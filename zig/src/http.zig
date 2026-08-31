//! One JSON round-trip, for the providers that talk to a vault over HTTP.
//!
//! std ships both an HTTP client and TLS (std.crypto.tls), so this port
//! needs neither a third-party crate nor a hand-rolled protocol: the whole
//! file is a thin, opinionated wrapper that turns std.http.Client into the
//! `{status, body}` pair every port's `fetchjson` returns.
//!
//! Opinionated in three ways, all of them the canonical's:
//!
//!   - A redirect is never followed. A vault API does not legitimately
//!     redirect, and a followed one would carry X-Vault-Token to the
//!     redirect's host (and could downgrade https to http), which
//!     `checkaddr` - it only ever sees the CONFIGURED address - cannot see.
//!   - A network failure is an ERROR, never a miss: an unreachable store is
//!     a store that could not answer.
//!   - A 200 whose body is not JSON is an error too. The status promised
//!     JSON; treating an incoherent answer as a miss would fall through to
//!     a weaker store. Error statuses may carry any body, so they are
//!     decided on status alone.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Header = std.http.Header;

/// How long connecting to a vault may take before it is treated as
/// unreachable. Ports carry the same bound.
///
/// Applied to the SOCKET, because std will not apply it for us.
///
/// `ConnectTcpOptions` has a `timeout` field and `connectTcpOptions` never
/// reads it: in Zig 0.16 the whole of `std/http/Client.zig` mentions
/// `timeout` exactly once, at the field's own declaration, and the body
/// calls `host.connect(io, port, .{ .mode = .stream })` without it. Passing
/// it did nothing. This port therefore had NO bound of any kind while its
/// code and its README both said it had one - measured: still blocked at
/// 35s against a server that accepted and went silent, where every other
/// port gave up at 10.
///
/// So the bound is set with SO_RCVTIMEO / SO_SNDTIMEO on the connection's
/// own socket, which does hold. Being a socket option it bounds each read
/// and each write, not the request as a whole - the same shape as every
/// port here except Go, whose deadline is total. A server dribbling one
/// byte at a time can still outlast it; a server that says nothing cannot.
pub const CONNECT_TIMEOUT_MS = 10_000;

/// How much of a response body will be read before the store is treated as
/// having answered incoherently. Ports carry the same bound.
///
/// Far above anything real - the largest legitimate payload this library
/// fetches is Doppler's whole-config download, measured in kilobytes.
///
/// This port needs the bound most. It advertises gzip and deflate and
/// decompresses transparently (see readerDecompressing below), so a hostile
/// endpoint does not have to SEND gigabytes: a few hundred kilobytes of
/// zeros expands to gigabytes in this process's heap, and the watchdog only
/// bounds the time, not the allocation.
const MAXBODY: u64 = 8 * 1024 * 1024;

/// Bounds one request by shutting its socket down if it outlasts
/// CONNECT_TIMEOUT_MS.
///
/// A thread per request is a real cost, and it buys the only bound this
/// port can have: see CONNECT_TIMEOUT_MS for why the socket option and the
/// std timeout field are both unavailable. The wait is in short steps so a
/// request that finishes early is not held up by its own watchdog.
const Watchdog = struct {
    stream: std.Io.net.Stream,
    io: std.Io,
    done: std.atomic.Value(bool) = .init(false),

    const STEP_MS = 50;

    fn run(self: *Watchdog) void {
        var waited: u64 = 0;
        while (waited < CONNECT_TIMEOUT_MS) : (waited += STEP_MS) {
            if (self.done.load(.acquire)) return;
            self.io.sleep(.fromMilliseconds(STEP_MS), .awake) catch return;
        }

        if (self.done.load(.acquire)) return;

        // Ends the pending read the way a closed connection does. Errors are
        // ignored: the socket may already have closed under us, which is the
        // case this is racing and the harmless outcome.
        self.stream.shutdown(self.io, .both) catch {};
    }
};

/// What one round-trip returns. `body` is null when the response carried no
/// JSON - only possible for a non-200, which is decided on status alone.
pub const Response = struct {
    status: u16,
    body: ?std.json.Value,
};

/// The result of a round-trip, or the message of a failure.
pub const Result = union(enum) {
    ok: Response,
    err: []const u8,
};

/// The part of a URL a failure message may show. A query string can carry a
/// vault path or a filter, so messages name the URL without it.
pub fn nakedurl(url: []const u8) []const u8 {
    const cut = std.mem.indexOfScalar(u8, url, '?') orelse return url;
    return url[0..cut];
}

/// One JSON round-trip.
pub fn fetchjson(
    alloc: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    headers: []const Header,
    body: ?[]const u8,
) Allocator.Error!Result {
    var client: std.http.Client = .{ .allocator = alloc, .io = io };
    defer client.deinit();

    const uri = std.Uri.parse(url) catch {
        return .{ .err = try std.fmt.allocPrint(
            alloc,
            "sekreto: cannot reach {s}: not a valid url",
            .{nakedurl(url)},
        ) };
    };

    var text: std.Io.Writer.Allocating = .init(alloc);

    const status = roundtrip(&client, io, method, uri, headers, body, &text) catch |err| {
        // An endless body has its own message: "cannot reach" would be
        // wrong, since the store was reached and answered - just not with
        // anything this library will hold in memory.
        if (error.OversizedResponse == err) {
            return .{ .err = try std.fmt.allocPrint(
                alloc,
                "sekreto: oversized response from {s}",
                .{nakedurl(url)},
            ) };
        }

        return .{ .err = try std.fmt.allocPrint(
            alloc,
            "sekreto: cannot reach {s}: {s}",
            .{ nakedurl(url), @errorName(err) },
        ) };
    };

    const raw = text.writer.buffered();

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, raw, .{}) catch {
        // A success status promised JSON; a body that does not parse means
        // the store could not answer coherently.
        if (200 == status) {
            return .{ .err = try std.fmt.allocPrint(
                alloc,
                "sekreto: malformed response from {s}",
                .{nakedurl(url)},
            ) };
        }
        return .{ .ok = .{ .status = status, .body = null } };
    };

    return .{ .ok = .{ .status = status, .body = parsed.value } };
}

// The request itself. Separated so that every way it can fail collapses
// into one "cannot reach" message, the way `fetch`'s error union would.
fn roundtrip(
    client: *std.http.Client,
    io: std.Io,
    method: std.http.Method,
    uri: std.Uri,
    headers: []const Header,
    body: ?[]const u8,
    text: *std.Io.Writer.Allocating,
) !u16 {
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.UnsupportedScheme;
    const port = uri.port orelse @as(u16, if (.tls == protocol) 443 else 80);

    var hostbuf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = try uri.getHost(&hostbuf);

    if (.tls == protocol) {
        // std.http.Client scans the system trust store inside `request`, but
        // ONLY on the path where it opens the connection itself. This
        // request pre-connects - the one place std lets a timeout in - so
        // the handshake would otherwise read an unset trust store and
        // crash. Loading it here is what makes https work at all, which is
        // in turn why this port needs no TLS dependency.
        const now = std.Io.Clock.real.now(io);
        client.ca_bundle.rescan(client.allocator, io, now) catch
            return error.CertificateBundleLoadFailure;
        client.now = now;
    }

    const connection = try client.connectTcpOptions(.{
        .host = host,
        .port = port,
        .protocol = protocol,
    });

    // The bound std would not apply. See CONNECT_TIMEOUT_MS: the `timeout`
    // field on ConnectTcpOptions is declared and never read, so this port
    // had none at all.
    //
    // Enforced with a watchdog rather than SO_RCVTIMEO. The socket option
    // is the obvious move and it is wrong here: it makes recv return EAGAIN,
    // and `Io.Threaded` treats EAGAIN on a socket read as a programmer bug
    // and PANICS. That turns a hung vault into a crash, which is not an
    // improvement. Shutting the socket down instead makes the pending read
    // end the way a closed connection does, which the reader already
    // handles, so a wedged vault surfaces as the ordinary "cannot reach"
    // error every other port gives.
    var watch: Watchdog = .{
        .stream = connection.stream_reader.stream,
        .io = io,
    };
    const watcher = std.Thread.spawn(.{}, Watchdog.run, .{&watch}) catch null;
    defer if (watcher) |thread| {
        watch.done.store(true, .release);
        thread.join();
    };

    var req = try client.request(method, uri, .{
        .connection = connection,
        .keep_alive = false,
        // Never follow a redirect: see the note at the top of this file.
        .redirect_behavior = .unhandled,
        .extra_headers = headers,
    });
    defer req.deinit();

    if (body) |payload| {
        req.transfer_encoding = .{ .content_length = payload.len };
        var writer = try req.sendBodyUnflushed(&.{});
        try writer.writer.writeAll(payload);
        try writer.end();
        try req.connection.?.flush();
    } else {
        try req.sendBodiless();
    }

    var response = try req.receiveHead(&.{});

    var transfer: [1024]u8 = undefined;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.http.Decompress = undefined;

    // The client advertises gzip and deflate, so a server is entitled to
    // use them; decoding is not optional.
    const reader = response.readerDecompressing(&transfer, &decompress, &window);

    // Bounded, not streamRemaining: an endless body would otherwise be
    // accumulated until the watchdog fires, and a decompressing reader turns
    // a small one into a large one. An endless body is a store that could
    // not answer, so this is an error, never a miss.
    var total: u64 = 0;
    while (true) {
        const got = reader.stream(&text.writer, .limited(64 * 1024)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return response.bodyErr().?,
            else => |rest| return rest,
        };

        total += got;
        if (MAXBODY < total) {
            return error.OversizedResponse;
        }
    }

    return @intFromEnum(response.head.status);
}

/// A map field of a JSON body, or null when anything on the way is absent
/// or not a map. The vault protocols nest their answers, and a chain of
/// `orelse return null` at every level is the same check written ten times.
pub fn jget(value: ?std.json.Value, key: []const u8) ?std.json.Value {
    const entry = value orelse return null;
    return switch (entry) {
        .object => |map| map.get(key),
        else => null,
    };
}

/// A JSON string field, or null when it is absent or not a string.
pub fn jstr(value: ?std.json.Value) ?[]const u8 {
    const entry = value orelse return null;
    return switch (entry) {
        .string => |found| found,
        else => null,
    };
}

/// A JSON number field as an integer, whatever shape it arrived in. Lease
/// and expiry durations are the only numbers these protocols carry, and
/// servers disagree about whether they are integers or strings.
pub fn jnum(value: ?std.json.Value) ?i64 {
    const entry = value orelse return null;
    return switch (entry) {
        .integer => |found| found,
        .float => |found| @intFromFloat(found),
        .number_string, .string => |found| std.fmt.parseInt(i64, found, 10) catch null,
        else => null,
    };
}
