//! RUN: make test
//! RUN-SOME: ./build/sekretotest envkey
//!
//! The sekreto conformance suite. Every port runs these same fourteen
//! groups, from the same spec/sekreto.json, through its own voxgig/omni
//! runner.
//!
//! No third-party test framework: a failing omni check returns a message,
//! which this harness reports.
//!
//! Only this file names omni. The library and the CLI never do, so a
//! checkout with no omni beside it still builds both (omni register 4.13).

const std = @import("std");
const omni = @import("omni");
const sekreto = @import("sekreto");

const Json = omni.Json;
const ProviderSpec = sekreto.ProviderSpec;

// Zig has no closures, so a subject is a bare function pointer: what it
// needs from the run lives here. The suite is one process, one arena.
var ALLOC: std.mem.Allocator = undefined;
var CONFIG: sekreto.Config = undefined;
var ONLY: ?[]const u8 = null;
var PASSCOUNT: usize = 0;
var FAILCOUNT: usize = 0;

// Find the shared spec directory by walking up from the working directory.
fn specfile(alloc: std.mem.Allocator, io: std.Io, name: []const u8) ![]const u8 {
    var dir: []const u8 = ".";

    var step: usize = 0;
    while (step < 8) : (step += 1) {
        const cand = try std.fmt.allocPrint(alloc, "{s}/spec/{s}", .{ dir, name });
        const file = std.Io.Dir.cwd().openFile(io, cand, .{}) catch {
            dir = try std.fmt.allocPrint(alloc, "{s}/..", .{dir});
            continue;
        };
        file.close(io);
        return cand;
    }

    return error.SpecNotFound;
}

// ---- spec to library -------------------------------------------------

fn text(value: omni.Maybe) []const u8 {
    return omni.asstr(value) orelse "";
}

fn field(value: omni.Maybe, key: []const u8) []const u8 {
    return text(omni.jget(value, key));
}

// The spec describes a provider chain as plain JSON; this is the shortest
// honest route from omni's value model to the library's typed specs.
fn specof(entry: omni.Maybe) !ProviderSpec {
    var out = ProviderSpec{ .kind = field(entry, "kind") };

    out.name = field(entry, "name");
    out.prefix = field(entry, "prefix");
    out.file = field(entry, "file");
    out.dir = field(entry, "dir");
    out.addr = field(entry, "addr");
    out.token = field(entry, "token");
    out.mount = field(entry, "mount");
    out.vaultnamespace = field(entry, "vaultnamespace");
    out.command = field(entry, "command");
    out.profile = field(entry, "profile");
    out.backend = field(entry, "backend");
    out.reason = field(entry, "reason");
    out.namespace = field(entry, "namespace");
    out.home = field(entry, "home");
    out.region = field(entry, "region");
    out.keyid = field(entry, "keyid");
    out.secret = field(entry, "secret");
    out.session = field(entry, "session");
    out.project = field(entry, "project");
    out.vault = field(entry, "vault");
    out.tenant = field(entry, "tenant");
    out.clientid = field(entry, "clientid");
    out.clientsecret = field(entry, "clientsecret");
    out.loginaddr = field(entry, "loginaddr");
    out.imdsaddr = field(entry, "imdsaddr");
    out.metadataaddr = field(entry, "metadataaddr");
    out.apiversion = field(entry, "apiversion");
    out.config = field(entry, "config");
    out.environment = field(entry, "environment");
    out.path = field(entry, "path");

    if (omni.asnum(omni.jget(entry, "kv"))) |kv| {
        out.kv = @intFromFloat(kv);
    }

    if (omni.jget(entry, "values")) |values| {
        if (.object == values) {
            var pairs: std.ArrayList(sekreto.providers.KeyValue) = .empty;
            var it = values.object.iterator();
            while (it.next()) |pair| {
                try pairs.append(ALLOC, .{
                    .key = pair.key_ptr.*,
                    .value = omni.asstr(pair.value_ptr.*) orelse "",
                });
            }
            out.values = pairs.items;
        }
    }

    if (omni.jget(entry, "auth")) |auth| {
        if (.object == auth) {
            out.auth = .{
                .method = field(auth, "method"),
                .mount = field(auth, "mount"),
                .role = field(auth, "role"),
                .jwt = omni.asstr(omni.jget(auth, "jwt")),
                .jwtfile = field(auth, "jwtfile"),
                .roleid = field(auth, "roleid"),
                .secretid = field(auth, "secretid"),
            };
        }
    }

    return out;
}

const Chain = union(enum) {
    ok: *sekreto.Sekreto,
    err: []const u8,
};

fn chainof(args: []const Json) !Chain {
    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    var specs: std.ArrayList(ProviderSpec) = .empty;

    if (omni.jget(entry, "chain")) |chain| {
        if (.array == chain) {
            for (chain.array.items) |item| {
                try specs.append(ALLOC, try specof(item));
            }
        }
    }

    return switch (try sekreto.Sekreto.init(ALLOC, CONFIG, specs.items, true)) {
        .err => |message| .{ .err = message },
        .ok => |made| .{ .ok = made },
    };
}

/// A list of strings as omni sees it.
fn jstrlist(list: []const []const u8) !Json {
    var out = std.json.Array.init(ALLOC);
    for (list) |item| {
        try out.append(omni.jstr(item));
    }
    return .{ .array = out };
}

// ---- subjects --------------------------------------------------------

fn callValidname(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const name: omni.Maybe = if (0 < args.len) args[0] else null;

    // The spec says JSON true/false, so the boolean is adapted HERE - the
    // library keeps handing back a Zig bool.
    return .{ .ok = omni.jbool(sekreto.validname(omni.asstr(name) orelse "")) };
}

fn callEnvkey(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (sekreto.envkey(ALLOC, field(entry, "name"), field(entry, "prefix")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        .ok => |value| .{ .ok = omni.jstr(value) },
    };
}

fn callVaultref(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const name: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (sekreto.vaultref(ALLOC, omni.asstr(name) orelse "") catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        // omni compares against the spec's JSON, so answer in that shape.
        .ok => |ref| .{ .ok = omni.jmap(ALLOC, &.{
            .{ "path", omni.jstr(ref.path) },
            .{ "field", omni.jstr(ref.field) },
        }) catch return .{ .err = "sekreto: out of memory" } },
    };
}

fn callFlatname(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (sekreto.flatname(ALLOC, field(entry, "name"), field(entry, "sep")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        .ok => |value| .{ .ok = omni.jstr(value) },
    };
}

fn callAwsparam(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (sekreto.awsparam(ALLOC, field(entry, "name"), field(entry, "prefix")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        .ok => |value| .{ .ok = omni.jstr(value) },
    };
}

fn callParsedotenv(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const raw: omni.Maybe = if (0 < args.len) args[0] else null;

    const parsed = sekreto.parsedotenv(ALLOC, omni.asstr(raw) orelse "") catch
        return .{ .err = "sekreto: out of memory" };

    var out: std.json.ObjectMap = .{};
    for (parsed.keys, 0..) |key, at| {
        out.put(ALLOC, key, omni.jstr(parsed.values[at])) catch
            return .{ .err = "sekreto: out of memory" };
    }

    return .{ .ok = .{ .object = out } };
}

fn callRedact(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    var values: std.ArrayList([]const u8) = .empty;

    if (omni.jget(entry, "values")) |list| {
        if (.array == list) {
            for (list.array.items) |item| {
                values.append(ALLOC, omni.asstr(item) orelse "") catch
                    return .{ .err = "sekreto: out of memory" };
            }
        }
    }

    const out = sekreto.redact(ALLOC, field(entry, "text"), values.items) catch
        return .{ .err = "sekreto: out of memory" };

    return .{ .ok = omni.jstr(out) };
}

fn callSigv4(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    var headers: std.ArrayList(sekreto.sigv4.Pair) = .empty;

    if (omni.jget(entry, "headers")) |given| {
        if (.object == given) {
            var it = given.object.iterator();
            while (it.next()) |pair| {
                headers.append(ALLOC, .{
                    .name = pair.key_ptr.*,
                    .value = omni.asstr(pair.value_ptr.*) orelse "",
                }) catch return .{ .err = "sekreto: out of memory" };
            }
        }
    }

    const signed = sekreto.sigv4.sign(ALLOC, .{
        .method = field(entry, "method"),
        .url = field(entry, "url"),
        .headers = headers.items,
        .body = field(entry, "body"),
        .service = field(entry, "service"),
        .region = field(entry, "region"),
        .keyid = field(entry, "keyid"),
        .secret = field(entry, "secret"),
        .session = field(entry, "session"),
        .datetime = field(entry, "datetime"),
    }) catch return .{ .err = "sekreto: out of memory" };

    var out: std.json.ObjectMap = .{};
    for (signed) |header| {
        out.put(ALLOC, header.name, omni.jstr(header.value)) catch
            return .{ .err = "sekreto: out of memory" };
    }

    return .{ .ok = .{ .object = out } };
}

fn callResolve(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const secrets = switch (chainof(args) catch return .{ .err = "sekreto: out of memory" }) {
        .err => |message| return .{ .err = message },
        .ok => |made| made,
    };

    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (secrets.get(field(entry, "name")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        .ok => |value| .{ .ok = omni.jstr(value) },
    };
}

fn callTrysecret(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const secrets = switch (chainof(args) catch return .{ .err = "sekreto: out of memory" }) {
        .err => |message| return .{ .err = message },
        .ok => |made| made,
    };

    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (secrets.trysecret(field(entry, "name")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        // A miss is a JSON null, which the runner's null-normalisation turns
        // into the spec's __NULL__ - never an empty string, which is a
        // perfectly good secret.
        .ok => |found| .{ .ok = if (found) |value| omni.jstr(value) else Json{ .null = {} } },
    };
}

fn callGetfrom(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const secrets = switch (chainof(args) catch return .{ .err = "sekreto: out of memory" }) {
        .err => |message| return .{ .err = message },
        .ok => |made| made,
    };

    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (secrets.getfrom(field(entry, "store"), field(entry, "name")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        .ok => |value| .{ .ok = omni.jstr(value) },
    };
}

fn callTryfrom(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const secrets = switch (chainof(args) catch return .{ .err = "sekreto: out of memory" }) {
        .err => |message| return .{ .err = message },
        .ok => |made| made,
    };

    const entry: omni.Maybe = if (0 < args.len) args[0] else null;

    return switch (secrets.tryfrom(field(entry, "store"), field(entry, "name")) catch
        return .{ .err = "sekreto: out of memory" }) {
        .err => |message| .{ .err = message },
        .ok => |found| .{ .ok = if (found) |value| omni.jstr(value) else Json{ .null = {} } },
    };
}

fn callSources(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const secrets = switch (chainof(args) catch return .{ .err = "sekreto: out of memory" }) {
        .err => |message| return .{ .err = message },
        .ok => |made| made,
    };

    const list = secrets.sources(ALLOC) catch return .{ .err = "sekreto: out of memory" };
    return .{ .ok = jstrlist(list) catch return .{ .err = "sekreto: out of memory" } };
}

fn callStores(_: *const omni.Subject, args: []const Json) omni.SubjectResult {
    const secrets = switch (chainof(args) catch return .{ .err = "sekreto: out of memory" }) {
        .err => |message| return .{ .err = message },
        .ok => |made| made,
    };

    const list = secrets.stores(ALLOC) catch return .{ .err = "sekreto: out of memory" };
    return .{ .ok = jstrlist(list) catch return .{ .err = "sekreto: out of memory" } };
}

const VALIDNAME = omni.Subject{ .call = callValidname };
const ENVKEY = omni.Subject{ .call = callEnvkey };
const VAULTREF = omni.Subject{ .call = callVaultref };
const FLATNAME = omni.Subject{ .call = callFlatname };
const AWSPARAM = omni.Subject{ .call = callAwsparam };
const PARSEDOTENV = omni.Subject{ .call = callParsedotenv };
const REDACT = omni.Subject{ .call = callRedact };
const SIGV4 = omni.Subject{ .call = callSigv4 };
const RESOLVE = omni.Subject{ .call = callResolve };
const TRYSECRET = omni.Subject{ .call = callTrysecret };
const GETFROM = omni.Subject{ .call = callGetfrom };
const TRYFROM = omni.Subject{ .call = callTryfrom };
const SOURCES = omni.Subject{ .call = callSources };
const STORES = omni.Subject{ .call = callStores };

// ---- harness ---------------------------------------------------------

fn report(name: []const u8, failure: ?[]const u8) void {
    if (failure) |message| {
        FAILCOUNT += 1;
        std.debug.print("FAIL - {s}\n{s}\n", .{ name, message });
    } else {
        PASSCOUNT += 1;
        std.debug.print("ok   - {s}\n", .{name});
    }
}

fn wanted(name: []const u8) bool {
    const only = ONLY orelse return true;
    return std.mem.eql(u8, only, name);
}

fn rungroup(
    pack: *const omni.RunPack,
    name: []const u8,
    subject: *const omni.Subject,
    flags: omni.Flags,
) !void {
    if (!wanted(name)) {
        return;
    }
    report(name, try pack.runsetflags(pack.set(name), flags, subject));
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    ALLOC = arena.allocator();
    CONFIG = .{ .io = init.io, .env = init.environ_map };

    var argit = std.process.Args.Iterator.init(init.minimal.args);
    _ = argit.skip();
    if (argit.next()) |first| {
        ONLY = first;
    }

    const path = try specfile(ALLOC, init.io, "sekreto.json");

    const provider = try ALLOC.create(omni.Provider);
    provider.* = .{};

    const runner = try omni.makeRunner(ALLOC, init.io, path, provider);
    const pack = try runner.runner("sekreto", null);

    // All fourteen groups the spec defines, in the order every port lists
    // them.
    try rungroup(&pack, "validname", &VALIDNAME, omni.Flags.nonull());
    try rungroup(&pack, "envkey", &ENVKEY, .{});
    try rungroup(&pack, "vaultref", &VAULTREF, .{});
    try rungroup(&pack, "flatname", &FLATNAME, .{});
    try rungroup(&pack, "awsparam", &AWSPARAM, .{});
    try rungroup(&pack, "parsedotenv", &PARSEDOTENV, .{});
    try rungroup(&pack, "resolve", &RESOLVE, .{});
    try rungroup(&pack, "trysecret", &TRYSECRET, .{});
    try rungroup(&pack, "sources", &SOURCES, .{});
    try rungroup(&pack, "stores", &STORES, .{});
    try rungroup(&pack, "getfrom", &GETFROM, .{});
    try rungroup(&pack, "tryfrom", &TRYFROM, .{});
    try rungroup(&pack, "sigv4", &SIGV4, .{});
    try rungroup(&pack, "redact", &REDACT, .{});

    std.debug.print("\n{d} passed, {d} failed\n", .{ PASSCOUNT, FAILCOUNT });

    std.process.exit(if (0 == FAILCOUNT) 0 else 1);
}
