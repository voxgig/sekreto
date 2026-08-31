//! The providers a Sekreto chains together.
//!
//! A provider answers one question: "do you have this secret?" It returns
//! the value, or null to mean "ask the next one". Nothing else about a
//! provider is visible to the caller - which is the point: an app reads
//! `api.token` and never learns whether it came from the environment, a
//! .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//!
//! Two failure shapes, and they are never interchangeable. A store that
//! does not hold the secret is a MISS (`.ok = null`) - the chain carries
//! on. A store that could not answer - bad credentials, unreachable host,
//! missing configuration - is an ERROR (`.err`): falling through there
//! would quietly reach for a weaker store.
//!
//! Zig has no interfaces, so `Provider` is a tagged union of the fourteen
//! concrete kinds. A union rather than a vtable because the set is closed
//! and named by `ProviderSpec.kind`: an unknown kind must fail loudly, and
//! a union makes the exhaustive switch the compiler's problem.

const std = @import("std");

const sekreto = @import("sekreto.zig");
const sigv4 = @import("sigv4.zig");
const http = @import("http.zig");

const Allocator = std.mem.Allocator;
const Answer = sekreto.Answer;
const Found = sekreto.Found;

/// What the library needs from the process it runs in.
///
/// Passed in rather than reached for, because Zig 0.16 hands both to `main`
/// and because a library that samples global state cannot be tested. The
/// environment is read by the `env` provider and by every store that
/// follows its own ecosystem's convention (AWS_*, GCE_METADATA_HOST); `io`
/// is what opens sockets, reads files and runs the boru binary.
pub const Config = struct {
    io: std.Io,
    env: *const std.process.Environ.Map,
};

/// One literal secret, for the `memory` provider. A list rather than a map
/// because the spec pins the whole map and randomised iteration would make
/// that comparison depend on the run.
pub const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

/// Logging in for a token instead of being handed one.
pub const Auth = struct {
    /// `kubernetes` or `approle`.
    method: []const u8 = "",
    /// The auth mount, defaulting to the method name.
    mount: []const u8 = "",
    /// kubernetes: the Vault role to log in as.
    role: []const u8 = "",
    /// kubernetes: the service-account JWT itself (tests).
    jwt: ?[]const u8 = null,
    /// kubernetes: where the JWT lives; the conventional pod path by default.
    jwtfile: []const u8 = "",
    /// approle: the role and secret ids.
    roleid: []const u8 = "",
    secretid: []const u8 = "",
};

/// The declarative form of a provider, as used in config and in the shared
/// spec.
///
/// Every string defaults to empty rather than being optional: "not
/// configured" and "configured empty" mean the same thing for every field
/// here, and one representation is one fewer thing to get wrong.
///
/// The strings are BORROWED. A provider keeps the spec's slices rather than
/// copying them - configuration is read once at startup and outlives the
/// chain in every real caller - so whatever owns them must outlive the
/// Sekreto built from them.
pub const ProviderSpec = struct {
    kind: []const u8,
    /// The store name `Sekreto.getfrom` addresses. Defaults to `kind`.
    name: []const u8 = "",
    prefix: []const u8 = "",
    /// dotenv: the file to read.
    file: []const u8 = "",
    /// memory: literal values, keyed like environment variables.
    values: []const KeyValue = &.{},
    /// file: the directory of one-secret-per-file entries.
    dir: []const u8 = "",
    /// hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the
    /// base URL.
    addr: []const u8 = "",
    /// hashicorp / boru (wire) / gcp / azure / 1password / doppler /
    /// infisical: the access token.
    token: []const u8 = "",
    /// hashicorp / boru (wire): the KV mount (default `secret`).
    mount: []const u8 = "",
    /// hashicorp: KV engine version, 1 or 2 (default 2). Zero means unset.
    kv: i64 = 0,
    /// hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
    vaultnamespace: []const u8 = "",
    /// hashicorp: log in for a token instead of being handed one.
    auth: ?Auth = null,
    /// boru / secretspec: the executable to run (default: the kind's own
    /// name).
    command: []const u8 = "",
    /// secretspec: the profile to read (`--profile`).
    profile: []const u8 = "",
    /// secretspec: which of ITS backends to read from (`--provider`), e.g.
    /// `keyring` or `dotenv://.env`. Named `backend` here because
    /// `provider` already means a sekreto provider.
    backend: []const u8 = "",
    /// secretspec: the audit reason recorded for the read (`--reason`).
    /// SecretSpec refuses to read without one.
    reason: []const u8 = "",
    /// boru: the namespace qualifying the alias.
    namespace: []const u8 = "",
    /// boru: the vault home, passed as BORU_HOME.
    home: []const u8 = "",
    /// aws: region and credentials; the standard AWS_* environment
    /// variables fill whichever are not given.
    region: []const u8 = "",
    keyid: []const u8 = "",
    secret: []const u8 = "",
    session: []const u8 = "",
    /// gcp / doppler / infisical: the project (GCP project id, Doppler
    /// project slug, Infisical workspace id).
    project: []const u8 = "",
    /// azure: the Key Vault name or full URL. 1password: the vault name or id.
    vault: []const u8 = "",
    /// azure: client-credential login. infisical: universal-auth login
    /// (tenant is Azure-only).
    tenant: []const u8 = "",
    clientid: []const u8 = "",
    clientsecret: []const u8 = "",
    /// azure: where to log in / where IMDS answers. gcp: where the metadata
    /// server answers.
    loginaddr: []const u8 = "",
    imdsaddr: []const u8 = "",
    metadataaddr: []const u8 = "",
    /// azure: the Key Vault API version (default 7.4).
    apiversion: []const u8 = "",
    /// doppler: the config slug (with `project`).
    config: []const u8 = "",
    /// infisical: the environment slug and secret path.
    environment: []const u8 = "",
    path: []const u8 = "",
};

/// Refuse to send a secret-bearing credential in the clear.
///
/// A vault API is HTTPS in any real deployment; plaintext is a dev-mode
/// convenience. Sending a token over http to anything but the local machine
/// puts both the token and the secret it fetches on the wire for anyone on
/// the path, so sekreto will not do it. Loopback stays allowed: that is
/// `vault server -dev`, `boru vault serve`, and this repo's own harness.
///
/// The address is read by hand, in the same handful of steps in every port,
/// rather than by each platform's URL parser. That is deliberate. Twelve
/// parsers disagree about malformed input - where userinfo ends, whether
/// `0177.0.0.1` is loopback, what an unclosed bracket means - and a check
/// that answers differently in different ports is not a check.
///
/// The rule this parse obeys, and the reason it can be trusted: it is never
/// more permissive than the HTTP client that will dial the address. It ends
/// the authority at `/`, `?` or `#` only, so a client that also breaks on
/// `\` (WHATWG does) can only ever see a SHORTER host than this does. It
/// refuses userinfo outright rather than locating its end. It compares the
/// host literally, so a numeric form no parser here agrees on is refused
/// rather than guessed at.
pub fn checkaddr(alloc: Allocator, addr: []const u8) Allocator.Error!Answer(void) {
    const scheme = if (std.mem.startsWith(u8, addr, "https://"))
        "https://"
    else if (std.mem.startsWith(u8, addr, "http://"))
        "http://"
    else
        return .{ .err = try sekreto.fail(alloc, "sekreto: not an http(s) address: {s}", .{addr}) };

    const rest = addr[scheme.len..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..authority_end];

    // Userinfo is refused outright rather than parsed around, and on https as
    // well as http. No store this library speaks authenticates by userinfo -
    // they take a token or a signature - so an address carrying one is a
    // mistake at best. At worst it is the attack this whole function exists
    // to stop: `http://localhost:8200@evil.example.com/` is a request to
    // evil.example.com that reads, to anything that splits the authority on
    // ':', as loopback.
    if (null != std.mem.indexOfScalar(u8, authority, '@')) {
        return .{ .err = try sekreto.fail(
            alloc,
            "sekreto: refusing an address with embedded credentials: {s}",
            .{addr},
        ) };
    }

    // An opening bracket with no closing one is not an address at all.
    if (0 != authority.len and '[' == authority[0] and
        null == std.mem.indexOfScalar(u8, authority, ']'))
    {
        return .{ .err = try sekreto.fail(
            alloc,
            "sekreto: not a valid http(s) address: {s}",
            .{addr},
        ) };
    }

    if (std.mem.eql(u8, "https://", scheme)) {
        return .{ .ok = {} };
    }

    // A bracketed IPv6 literal keeps its brackets. Splitting the authority on
    // the first colon yields `[`, so `http://[::1]:8200` could never match -
    // which made the `[::1]` entry below unreachable, and refused a
    // legitimate local vault.
    const raw = if (0 != authority.len and '[' == authority[0]) blk: {
        // The closing bracket is known to be there: the check above returned
        // for an authority that opens one without closing it.
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse authority.len - 1;
        break :blk authority[0 .. close + 1];
    } else blk: {
        const colon = std.mem.indexOfScalar(u8, authority, ':') orelse authority.len;
        break :blk authority[0..colon];
    };

    const host = try std.ascii.allocLowerString(alloc, raw);
    defer alloc.free(host);

    for ([_][]const u8{ "localhost", "127.0.0.1", "::1", "[::1]" }) |allowed| {
        if (std.mem.eql(u8, allowed, host)) {
            return .{ .ok = {} };
        }
    }

    return .{ .err = try sekreto.fail(
        alloc,
        "sekreto: refusing to send a token in plaintext to {s} (use https)",
        .{addr},
    ) };
}

/// A base URL with one trailing slash removed, so paths join cleanly.
fn trimslash(addr: []const u8) []const u8 {
    if (0 != addr.len and '/' == addr[addr.len - 1]) {
        return addr[0 .. addr.len - 1];
    }
    return addr;
}

/// The configured value, or the first non-empty of the named environment
/// variables. Those names are the ecosystem's own convention, so a pod or a
/// CI job that already has them set should just work.
fn firstof(config: Config, given: []const u8, names: []const []const u8) []const u8 {
    if (0 != given.len) {
        return given;
    }

    for (names) |name| {
        if (config.env.get(name)) |value| {
            if (0 != value.len) {
                return value;
            }
        }
    }

    return "";
}

/// Now, in milliseconds since the epoch. Token expiry is the only clock
/// this library reads.
fn nowms(io: std.Io) i64 {
    const stamp = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(stamp.nanoseconds, std.time.ns_per_ms));
}

/// Never: a configured token is kept for the life of the process.
const NEVER: i64 = std.math.maxInt(i64);

/// When a lease of `seconds` should be renewed - a minute early, because a
/// long-running process must not keep presenting a token the vault already
/// expired.
fn renewafter(io: std.Io, seconds: ?i64) i64 {
    const lease = seconds orelse return NEVER;
    if (0 >= lease) {
        return NEVER;
    }
    return nowms(io) + 1000 * @max(lease - 60, 1);
}

/// Percent-escape one query-string value.
fn escape(alloc: Allocator, text: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;

    for (text) |ch| {
        const plain = ('A' <= ch and 'Z' >= ch) or ('a' <= ch and 'z' >= ch) or
            ('0' <= ch and '9' >= ch) or '-' == ch or '_' == ch or '.' == ch or '~' == ch;

        if (plain) {
            try out.append(alloc, ch);
        } else {
            try out.appendSlice(alloc, try std.fmt.allocPrint(alloc, "%{X:0>2}", .{ch}));
        }
    }

    return out.items;
}

/// Decode standard base64 - GCP payloads and AWS binary secrets.
fn unbase64(alloc: Allocator, text: []const u8) Allocator.Error!?[]const u8 {
    const decoder = std.base64.standard.Decoder;

    const size = decoder.calcSizeForSlice(text) catch return null;
    const out = try alloc.alloc(u8, size);
    decoder.decode(out, text) catch return null;

    return out;
}

// ---- env -------------------------------------------------------------

/// Environment variables: `api.token` from `API_TOKEN`.
pub const EnvProvider = struct {
    config: Config,
    prefix: []const u8,

    pub fn lookup(self: *EnvProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const key = switch (try sekreto.envkey(alloc, name, self.prefix)) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        return .{ .ok = self.config.env.get(key) };
    }

    pub fn describe(self: *EnvProvider, alloc: Allocator) Allocator.Error![]const u8 {
        if (0 == self.prefix.len) {
            return alloc.dupe(u8, "env");
        }
        return std.fmt.allocPrint(alloc, "env:{s}", .{self.prefix});
    }

    pub fn deinit(_: *EnvProvider, _: Allocator) void {}
};

// ---- dotenv ----------------------------------------------------------

/// A `.env` file, read once, keyed exactly like the environment.
pub const DotenvProvider = struct {
    alloc: Allocator,
    config: Config,
    file: []const u8,
    prefix: []const u8,
    // Loaded once and kept, so the file is read once per process. Its own
    // arena because the parse hands back a mix of borrowed slices and
    // unescaped copies; one free covers both.
    state: std.heap.ArenaAllocator,
    values: ?sekreto.Dotenv,

    fn load(self: *DotenvProvider, alloc: Allocator) Allocator.Error!Answer(sekreto.Dotenv) {
        if (self.values) |values| {
            return .{ .ok = values };
        }

        const keep = self.state.allocator();

        const text = std.Io.Dir.cwd().readFileAlloc(
            self.config.io,
            self.file,
            keep,
            .unlimited,
        ) catch |err| switch (err) {
            // An absent file - or an absent directory - means "no secrets
            // here", exactly like fileprovider. Anything else (permission
            // denied, an unreadable mount) is a store that could not answer,
            // and swallowing it would fall through to a weaker store.
            error.FileNotFound, error.NotDir => "",
            else => return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: dotenv provider cannot read {s}: {s}",
                .{ self.file, @errorName(err) },
            ) },
        };

        const values = try sekreto.parsedotenv(keep, text);
        self.values = values;

        return .{ .ok = values };
    }

    pub fn lookup(self: *DotenvProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const key = switch (try sekreto.envkey(alloc, name, self.prefix)) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        const values = switch (try self.load(alloc)) {
            .err => |message| return .{ .err = message },
            .ok => |loaded| loaded,
        };

        return .{ .ok = values.get(key) };
    }

    pub fn describe(self: *DotenvProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "dotenv:{s}", .{self.file});
    }

    pub fn deinit(self: *DotenvProvider, _: Allocator) void {
        self.state.deinit();
    }
};

// ---- memory ----------------------------------------------------------

/// Literal values, keyed like environment variables. The spec uses this to
/// test chain behaviour without touching the outside world.
pub const MemoryProvider = struct {
    values: []const KeyValue,
    prefix: []const u8,

    pub fn lookup(self: *MemoryProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const key = switch (try sekreto.envkey(alloc, name, self.prefix)) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        for (self.values) |entry| {
            if (std.mem.eql(u8, entry.key, key)) {
                return .{ .ok = entry.value };
            }
        }

        return .{ .ok = null };
    }

    pub fn describe(self: *MemoryProvider, alloc: Allocator) Allocator.Error![]const u8 {
        if (0 == self.prefix.len) {
            return alloc.dupe(u8, "memory");
        }
        return std.fmt.allocPrint(alloc, "memory:{s}", .{self.prefix});
    }

    pub fn deinit(_: *MemoryProvider, _: Allocator) void {}
};

// ---- file ------------------------------------------------------------

/// A directory of one-secret-per-file entries, keyed like the environment:
/// `api.token` reads `<dir>/API_TOKEN`.
///
/// This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
/// secret, and a systemd credentials directory, so those all work with no
/// further configuration. One trailing newline is stripped - tools that
/// write these files disagree about it, and a newline is never part of a
/// secret on purpose.
pub const FileProvider = struct {
    config: Config,
    dir: []const u8,
    prefix: []const u8,

    pub fn lookup(self: *FileProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const key = switch (try sekreto.envkey(alloc, name, self.prefix)) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        const path = try std.fs.path.join(alloc, &.{ self.dir, key });

        const text = std.Io.Dir.cwd().readFileAlloc(
            self.config.io,
            path,
            alloc,
            .unlimited,
        ) catch |err| switch (err) {
            // An absent file - or an absent directory - means "no secrets
            // here", exactly like a missing .env. Anything else (permission
            // denied, an unreadable mount) is a store that could not answer.
            error.FileNotFound, error.NotDir => return .{ .ok = null },
            else => return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: file provider cannot read {s}: {s}",
                .{ path, @errorName(err) },
            ) },
        };

        var value: []const u8 = text;
        if (0 != value.len and '\n' == value[value.len - 1]) {
            value = value[0 .. value.len - 1];
            if (0 != value.len and '\r' == value[value.len - 1]) {
                value = value[0 .. value.len - 1];
            }
        }

        return .{ .ok = value };
    }

    pub fn describe(self: *FileProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "file:{s}", .{self.dir});
    }

    pub fn deinit(_: *FileProvider, _: Allocator) void {}
};

// ---- hashicorp -------------------------------------------------------

/// HashiCorp Vault.
///
/// KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
/// takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
/// `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
/// here" - a miss - so a vault can sit in a chain with fallbacks.
///
/// A Vault Enterprise namespace rides the X-Vault-Namespace header, on
/// logins as well as reads.
///
/// Instead of being handed a token, the provider can log in: Kubernetes
/// auth (the pod's service-account JWT, from its conventional path) or
/// AppRole. A failed login is an error, never a miss - it means this store
/// could not answer at all.
pub const HashicorpProvider = struct {
    alloc: Allocator,
    config: Config,
    addr: []const u8,
    token: []const u8,
    mount: []const u8,
    kv: i64,
    vaultnamespace: []const u8,
    auth: ?Auth,
    // The working token: a configured token is kept forever, a logged-in
    // token is renewed shortly before its lease runs out.
    livetoken: ?[]const u8,
    renewat: i64,

    fn baseheaders(self: *HashicorpProvider, alloc: Allocator) Allocator.Error!std.ArrayList(http.Header) {
        var headers: std.ArrayList(http.Header) = .empty;
        if (0 != self.vaultnamespace.len) {
            try headers.append(alloc, .{ .name = "X-Vault-Namespace", .value = self.vaultnamespace });
        }
        return headers;
    }

    fn login(self: *HashicorpProvider, alloc: Allocator) Allocator.Error!Answer([]const u8) {
        const auth = self.auth orelse {
            return .{ .err = try sekreto.fail(alloc, "sekreto: hashicorp: no token and no auth method", .{}) };
        };

        const mount = if (0 != auth.mount.len) auth.mount else auth.method;
        const url = try std.fmt.allocPrint(
            alloc,
            "{s}/v1/auth/{s}/login",
            .{ trimslash(self.addr), mount },
        );

        var body: []const u8 = undefined;

        if (std.mem.eql(u8, "kubernetes", auth.method)) {
            const jwt = auth.jwt orelse blk: {
                const file = if (0 != auth.jwtfile.len)
                    auth.jwtfile
                else
                    "/var/run/secrets/kubernetes.io/serviceaccount/token";

                const text = std.Io.Dir.cwd().readFileAlloc(
                    self.config.io,
                    file,
                    alloc,
                    .unlimited,
                ) catch {
                    return .{ .err = try sekreto.fail(
                        alloc,
                        "sekreto: hashicorp: cannot read jwt file {s}",
                        .{file},
                    ) };
                };

                break :blk std.mem.trim(u8, text, " \t\r\n");
            };

            body = try jsonobject(alloc, &.{
                .{ .key = "role", .value = auth.role },
                .{ .key = "jwt", .value = jwt },
            });
        } else if (std.mem.eql(u8, "approle", auth.method)) {
            body = try jsonobject(alloc, &.{
                .{ .key = "role_id", .value = auth.roleid },
                .{ .key = "secret_id", .value = auth.secretid },
            });
        } else {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: hashicorp: unknown auth method: {s}",
                .{auth.method},
            ) };
        }

        var headers = try self.baseheaders(alloc);
        try headers.append(alloc, .{ .name = "content-type", .value = "application/json" });

        const res = switch (try http.fetchjson(alloc, self.config.io, .POST, url, headers.items, body)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const clienttoken = http.jstr(http.jget(http.jget(res.body, "auth"), "client_token"));

        if (200 != res.status or null == clienttoken) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: hashicorp login failed: {d}: {s}",
                .{ res.status, url },
            ) };
        }

        self.renewat = renewafter(
            self.config.io,
            http.jnum(http.jget(http.jget(res.body, "auth"), "lease_duration")),
        );

        return .{ .ok = clienttoken.? };
    }

    pub fn lookup(self: *HashicorpProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        switch (try checkaddr(alloc, self.addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        if (null == self.livetoken or nowms(self.config.io) >= self.renewat) {
            const fresh = switch (try self.login(alloc)) {
                .err => |message| return .{ .err = message },
                .ok => |got| got,
            };
            try self.settoken(fresh);
        }

        const ref = switch (try sekreto.vaultref(alloc, name)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const url = if (1 == self.kv)
            try std.fmt.allocPrint(alloc, "{s}/v1/{s}/{s}", .{ trimslash(self.addr), self.mount, ref.path })
        else
            try std.fmt.allocPrint(alloc, "{s}/v1/{s}/data/{s}", .{ trimslash(self.addr), self.mount, ref.path });

        var headers = try self.baseheaders(alloc);
        try headers.append(alloc, .{ .name = "X-Vault-Token", .value = self.livetoken.? });

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, headers.items, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (404 == res.status) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: hashicorp error: {d}: {s}",
                .{ res.status, url },
            ) };
        }

        const data = if (1 == self.kv)
            http.jget(res.body, "data")
        else
            http.jget(http.jget(res.body, "data"), "data");

        return .{ .ok = http.jstr(http.jget(data, ref.field)) };
    }

    // The live token outlives one lookup, so it cannot live in the lookup's
    // scratch arena; the previous one is freed as it is replaced.
    fn settoken(self: *HashicorpProvider, token: []const u8) Allocator.Error!void {
        if (self.livetoken) |old| {
            self.alloc.free(old);
        }
        self.livetoken = try self.alloc.dupe(u8, token);
    }

    pub fn describe(self: *HashicorpProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "hashicorp:{s}/{s}", .{ self.addr, self.mount });
    }

    pub fn deinit(self: *HashicorpProvider, alloc: Allocator) void {
        if (self.livetoken) |token| {
            alloc.free(token);
        }
    }
};

// ---- boru ------------------------------------------------------------

/// A boru vault (https://github.com/boru-lang/boru).
///
/// Two ways in, both boru's own.
///
/// With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
/// secret on stdout and nothing else. The passphrase is read by boru itself
/// from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config and
/// never puts it on a command line, where it would show up in the process
/// table.
///
/// With an `addr`, boru's wire protocol: `boru vault serve` publishes a
/// read-only, HashiCorp-shaped provision API, authenticated by a capability
/// token from `boru vault grant`. A sekreto name is already a valid boru
/// alias, and boru aliases keep their dots, so `api.token` is the single
/// path segment `api.token` - not the `api`/`token` split a HashiCorp KV
/// gets. The value is the `value` field. A 404 is a miss; anything else the
/// server refuses (a revoked capability, a sealed vault) is an error.
///
/// boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
/// credential *broker*, built precisely so the caller never receives the
/// credential. `vault serve` is the provision endpoint, built to hand the
/// value back - that is the one sekreto uses.
pub const BoruProvider = struct {
    alloc: Allocator,
    config: Config,
    command: []const u8,
    namespace: []const u8,
    home: []const u8,
    addr: []const u8,
    token: []const u8,
    mount: []const u8,

    pub fn lookup(self: *BoruProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        switch (try sekreto.checkname(alloc, name)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        if (0 != self.addr.len) {
            return self.lookupwire(alloc, name);
        }

        return self.lookupcli(alloc, name);
    }

    fn lookupwire(self: *BoruProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const addr = trimslash(self.addr);

        switch (try checkaddr(alloc, addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        const alias = if (0 != self.namespace.len)
            try std.fmt.allocPrint(alloc, "{s}/{s}", .{ self.namespace, name })
        else
            name;

        const url = try std.fmt.allocPrint(alloc, "{s}/v1/{s}/data/{s}", .{ addr, self.mount, alias });

        const headers = [_]http.Header{.{ .name = "X-Vault-Token", .value = self.token }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (404 == res.status) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: boru serve error: {d}: {s}",
                .{ res.status, url },
            ) };
        }

        const data = http.jget(http.jget(res.body, "data"), "data");
        return .{ .ok = http.jstr(http.jget(data, "value")) };
    }

    fn lookupcli(self: *BoruProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const alias = if (0 != self.namespace.len)
            try std.fmt.allocPrint(alloc, "{s}:{s}", .{ self.namespace, name })
        else
            name;

        // BORU_HOME is added to a copy of the environment, never to the
        // command line: the passphrase boru reads from the environment must
        // not end up in the process table beside it.
        var environ = try self.config.env.clone(alloc);
        defer environ.deinit();

        if (0 != self.home.len) {
            try environ.put("BORU_HOME", self.home);
        }

        const run = std.process.run(alloc, self.config.io, .{
            .argv = &.{ self.command, "vault", "get", "--reveal", alias },
            .environ_map = &environ,
        }) catch |err| {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: cannot run {s}: {s}",
                .{ self.command, @errorName(err) },
            ) };
        };

        const exited = switch (run.term) {
            .exited => |code| code,
            else => 1,
        };

        if (0 == exited) {
            // boru prints the value and one newline, and nothing else.
            var value: []const u8 = run.stdout;
            if (0 != value.len and '\n' == value[value.len - 1]) {
                value = value[0 .. value.len - 1];
            }
            return .{ .ok = value };
        }

        const why = std.mem.trim(u8, run.stderr, " \t\r\n");

        // "no alias named" is boru saying it does not hold this secret,
        // which is a miss: the chain carries on to the next provider. A
        // locked vault or a wrong passphrase is not a miss - treating it as
        // one would fall through to a weaker store without saying so.
        if (null != std.mem.indexOf(u8, why, "no alias named")) {
            return .{ .ok = null };
        }

        if (0 != why.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: boru vault error: {s}", .{why}) };
        }

        return .{ .err = try sekreto.fail(alloc, "sekreto: boru vault error: exit {d}", .{exited}) };
    }

    pub fn describe(self: *BoruProvider, alloc: Allocator) Allocator.Error![]const u8 {
        if (0 != self.addr.len) {
            return std.fmt.allocPrint(alloc, "boru:{s}", .{trimslash(self.addr)});
        }
        if (0 != self.namespace.len) {
            return std.fmt.allocPrint(alloc, "boru:{s}", .{self.namespace});
        }
        return alloc.dupe(u8, "boru");
    }

    pub fn deinit(_: *BoruProvider, _: Allocator) void {}
};

// ---- secretspec ------------------------------------------------------

/// SecretSpec (https://secretspec.dev).
///
/// SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
/// project needs - plus a chain of its own backends to satisfy them from.
/// That makes it the same shape as sekreto one level down, and the reason
/// to support it is the same reason sekreto exists: a project that has
/// already declared its secrets there should not have to declare them
/// again here.
///
/// Read through its CLI, as boru is, because that is the interface it
/// offers a program in another language: `secretspec get API_TOKEN` prints
/// the value on stdout and nothing else. A sekreto name maps to a
/// SecretSpec key exactly as it maps to an environment variable -
/// `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
/// examples use.
///
/// `backend` selects one of SecretSpec's backends (`--provider`, e.g.
/// `keyring` or `dotenv://.env`) and is called `backend` here only because
/// `provider` already means something else in this library.
///
/// A reason is required, not optional: SecretSpec records every read in an
/// audit log and refuses to read at all without one. sekreto sends
/// `sekreto` unless told otherwise, so the audit trail says which tool
/// asked.
pub const SecretspecProvider = struct {
    config: Config,
    command: []const u8,
    file: []const u8,
    profile: []const u8,
    backend: []const u8,
    reason: []const u8,
    prefix: []const u8,

    pub fn lookup(self: *SecretspecProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const key = switch (try sekreto.envkey(alloc, name, self.prefix)) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(alloc, self.command);

        if (0 != self.file.len) {
            try argv.append(alloc, "--file");
            try argv.append(alloc, self.file);
        }

        try argv.append(alloc, "get");
        try argv.append(alloc, key);

        if (0 != self.backend.len) {
            try argv.append(alloc, "--provider");
            try argv.append(alloc, self.backend);
        }
        if (0 != self.profile.len) {
            try argv.append(alloc, "--profile");
            try argv.append(alloc, self.profile);
        }

        try argv.append(alloc, "--reason");
        try argv.append(alloc, if (0 != self.reason.len) self.reason else "sekreto");

        const run = std.process.run(alloc, self.config.io, .{
            .argv = argv.items,
            .environ_map = self.config.env,
        }) catch |err| {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: cannot run {s}: {s}",
                .{ self.command, @errorName(err) },
            ) };
        };

        const exited = switch (run.term) {
            .exited => |code| code,
            else => 1,
        };

        if (0 == exited) {
            // The value and one newline, and nothing else.
            var value: []const u8 = run.stdout;
            if (0 != value.len and '\n' == value[value.len - 1]) {
                value = value[0 .. value.len - 1];
            }
            return .{ .ok = value };
        }

        const why = std.mem.trim(u8, run.stderr, " \t\r\n");

        if (try secretspecmiss(alloc, why, key)) {
            return .{ .ok = null };
        }

        if (0 != why.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: secretspec error: {s}", .{why}) };
        }

        return .{ .err = try sekreto.fail(alloc, "sekreto: secretspec error: exit {d}", .{exited}) };
    }

    pub fn describe(self: *SecretspecProvider, alloc: Allocator) Allocator.Error![]const u8 {
        if (0 == self.backend.len) {
            return alloc.dupe(u8, "secretspec");
        }
        return std.fmt.allocPrint(alloc, "secretspec:{s}", .{self.backend});
    }

    pub fn deinit(_: *SecretspecProvider, _: Allocator) void {}
};

/// Does this SecretSpec failure mean "no such secret" rather than "I could
/// not answer"?
///
/// SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
/// not declare and one declared with no value, and both are misses: this
/// store does not hold it, so the chain carries on.
///
/// MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
/// `Provider backend 'keyring' not found`, which is a store that could not
/// answer at all - and reading that as a miss is the worst failure this
/// library has, because the chain then falls through to a weaker store
/// without saying so. The key is required to appear, so the two cannot be
/// confused.
fn secretspecmiss(alloc: Allocator, why: []const u8, key: []const u8) Allocator.Error!bool {
    const phrase = try std.fmt.allocPrint(alloc, "Secret '{s}' not found", .{key});
    return null != std.mem.indexOf(u8, why, phrase);
}

// ---- aws -------------------------------------------------------------

/// Region and credentials, from config first and the standard AWS_*
/// environment variables second. Missing either is an error: an AWS store
/// with no credentials could not answer.
const AwsAuth = struct {
    region: []const u8,
    keyid: []const u8,
    secret: []const u8,
    session: []const u8,
};

/// The common half of both AWS providers.
const Aws = struct {
    config: Config,
    region: []const u8,
    keyid: []const u8,
    secret: []const u8,
    session: []const u8,
    addr: []const u8,
    prefix: []const u8,

    fn auth(self: Aws, alloc: Allocator) Allocator.Error!Answer(AwsAuth) {
        const region = firstof(self.config, self.region, &.{ "AWS_REGION", "AWS_DEFAULT_REGION" });
        const keyid = firstof(self.config, self.keyid, &.{"AWS_ACCESS_KEY_ID"});
        const secret = firstof(self.config, self.secret, &.{"AWS_SECRET_ACCESS_KEY"});
        const session = firstof(self.config, self.session, &.{"AWS_SESSION_TOKEN"});

        if (0 == region.len) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: aws: no region (set region or AWS_REGION)",
                .{},
            ) };
        }

        if (0 == keyid.len or 0 == secret.len) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: aws: no credentials (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)",
                .{},
            ) };
        }

        return .{ .ok = .{ .region = region, .keyid = keyid, .secret = secret, .session = session } };
    }

    /// One signed call to an AWS JSON-1.1 API.
    fn call(
        self: Aws,
        alloc: Allocator,
        service: []const u8,
        target: []const u8,
        payload: []const u8,
    ) Allocator.Error!http.Result {
        const credentials = switch (try self.auth(alloc)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        // The China partition lives under its own suffix; every other
        // commercial region is plain amazonaws.com.
        const suffix: []const u8 = if (std.mem.startsWith(u8, credentials.region, "cn-"))
            ".amazonaws.com.cn"
        else
            ".amazonaws.com";

        const addr = if (0 != self.addr.len)
            self.addr
        else
            try std.fmt.allocPrint(alloc, "https://{s}.{s}{s}", .{ service, credentials.region, suffix });

        switch (try checkaddr(alloc, addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        const url = try std.fmt.allocPrint(alloc, "{s}/", .{trimslash(addr)});

        const unsigned = [_]sigv4.Pair{
            .{ .name = "content-type", .value = "application/x-amz-json-1.1" },
            .{ .name = "x-amz-target", .value = target },
        };

        const signed = try sigv4.sign(alloc, .{
            .method = "POST",
            .url = url,
            .headers = &unsigned,
            .body = payload,
            .service = service,
            .region = credentials.region,
            .keyid = credentials.keyid,
            .secret = credentials.secret,
            .session = credentials.session,
            .datetime = try awsnow(alloc, self.config.io),
        });

        var headers: std.ArrayList(http.Header) = .empty;
        for (unsigned) |header| {
            try headers.append(alloc, .{ .name = header.name, .value = header.value });
        }
        for (signed) |header| {
            try headers.append(alloc, .{ .name = header.name, .value = header.value });
        }

        return http.fetchjson(alloc, self.config.io, .POST, url, headers.items, payload);
    }
};

/// The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.
fn awsnow(alloc: Allocator, io: std.Io) Allocator.Error![]const u8 {
    const seconds: u64 = @intCast(@divTrunc(nowms(io), 1000));

    const day = std.time.epoch.EpochSeconds{ .secs = seconds };
    const yearday = day.getEpochDay().calculateYearDay();
    const monthday = yearday.calculateMonthDay();
    const clock = day.getDaySeconds();

    return std.fmt.allocPrint(alloc, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yearday.year,
        monthday.month.numeric(),
        monthday.day_index + 1,
        clock.getHoursIntoDay(),
        clock.getMinutesIntoHour(),
        clock.getSecondsIntoMinute(),
    });
}

/// Does this AWS error body name one of the not-found types? Those are a
/// miss; every other failure is a store that could not answer.
fn awsmiss(body: ?std.json.Value, want: []const u8) bool {
    const errtype = http.jstr(http.jget(body, "__type")) orelse return false;
    return null != std.mem.indexOf(u8, errtype, want);
}

/// AWS Secrets Manager.
///
/// `api.token` reads the secret named `api` (the vaultref path, so
/// `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
/// SecretString - the AWS idiom of one JSON map per secret. A SecretString
/// that is not JSON is the value itself, under the conventional field
/// `value`. Requests are SigV4-signed in-tree; see sigv4.zig.
pub const AwsSecretsProvider = struct {
    aws: Aws,

    pub fn lookup(self: *AwsSecretsProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const ref = switch (try sekreto.vaultref(alloc, name)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const payload = try jsonobject(alloc, &.{.{ .key = "SecretId", .value = ref.path }});

        const res = switch (try self.aws.call(alloc, "secretsmanager", "secretsmanager.GetSecretValue", payload)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (400 == res.status and awsmiss(res.body, "ResourceNotFoundException")) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: aws secretsmanager error: {d}",
                .{res.status},
            ) };
        }

        const text = http.jstr(http.jget(res.body, "SecretString")) orelse {
            // A binary secret has no fields to address; only the
            // conventional `value` field can mean "the bytes themselves".
            const binary = http.jstr(http.jget(res.body, "SecretBinary")) orelse return .{ .ok = null };
            if (!std.mem.eql(u8, "value", ref.field)) {
                return .{ .ok = null };
            }
            return .{ .ok = try unbase64(alloc, binary) };
        };

        const parsed = std.json.parseFromSlice(std.json.Value, alloc, text, .{}) catch {
            // A plain-string secret is the whole value; it has no named
            // fields.
            return .{ .ok = if (std.mem.eql(u8, "value", ref.field)) text else null };
        };

        if (.object == parsed.value) {
            return .{ .ok = http.jstr(http.jget(parsed.value, ref.field)) };
        }

        return .{ .ok = if (std.mem.eql(u8, "value", ref.field)) text else null };
    }

    pub fn describe(self: *AwsSecretsProvider, alloc: Allocator) Allocator.Error![]const u8 {
        // Config only, never the environment: describe() feeds the spec's
        // sources group, which must answer the same everywhere.
        return std.fmt.allocPrint(alloc, "awssecrets:{s}", .{self.aws.region});
    }

    pub fn deinit(_: *AwsSecretsProvider, _: Allocator) void {}
};

/// AWS SSM Parameter Store.
///
/// `db.pass.main` reads the parameter `/db/pass/main` (under an optional
/// prefix path), decrypted. Parameter Store carries flat strings, so there
/// is no field indirection.
pub const AwsParamsProvider = struct {
    aws: Aws,

    pub fn lookup(self: *AwsParamsProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const param = switch (try sekreto.awsparam(alloc, name, self.aws.prefix)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const payload = try std.fmt.allocPrint(
            alloc,
            "{{\"Name\":{s},\"WithDecryption\":true}}",
            .{try jsonstring(alloc, param)},
        );

        const res = switch (try self.aws.call(alloc, "ssm", "AmazonSSM.GetParameter", payload)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (400 == res.status and awsmiss(res.body, "ParameterNotFound")) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: aws ssm error: {d}", .{res.status}) };
        }

        return .{ .ok = http.jstr(http.jget(http.jget(res.body, "Parameter"), "Value")) };
    }

    pub fn describe(self: *AwsParamsProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "awsparams:{s}{s}", .{ self.aws.region, self.aws.prefix });
    }

    pub fn deinit(_: *AwsParamsProvider, _: Allocator) void {}
};

// ---- gcp -------------------------------------------------------------

/// GCP Secret Manager.
///
/// `api.token` reads secret `api_token` (dots flattened to `_`; Secret
/// Manager ids have no hierarchy and reject dots), latest version. The token
/// comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE/GKE
/// metadata server - so on Google's own platform no credential
/// configuration is needed at all.
///
/// The metadata call itself is plain http to a link-local host by platform
/// design; no credential rides on it, so `checkaddr` guards the Secret
/// Manager address instead.
pub const GcpSecretsProvider = struct {
    alloc: Allocator,
    config: Config,
    project: []const u8,
    token: []const u8,
    addr: []const u8,
    metadataaddr: []const u8,
    livetoken: ?[]const u8,
    renewat: i64,

    fn metadata(self: *GcpSecretsProvider, alloc: Allocator) Allocator.Error![]const u8 {
        if (0 != self.metadataaddr.len) {
            return self.metadataaddr;
        }

        if (self.config.env.get("GCE_METADATA_HOST")) |host| {
            if (0 != host.len) {
                return std.fmt.allocPrint(alloc, "http://{s}", .{host});
            }
        }

        return "http://metadata.google.internal";
    }

    fn login(self: *GcpSecretsProvider, alloc: Allocator) Allocator.Error!Answer([]const u8) {
        const configured = firstof(self.config, self.token, &.{"GOOGLE_OAUTH_ACCESS_TOKEN"});
        if (0 != configured.len) {
            return .{ .ok = configured };
        }

        const url = try std.fmt.allocPrint(
            alloc,
            "{s}/computeMetadata/v1/instance/service-accounts/default/token",
            .{trimslash(try self.metadata(alloc))},
        );

        const headers = [_]http.Header{.{ .name = "Metadata-Flavor", .value = "Google" }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const access = http.jstr(http.jget(res.body, "access_token"));

        if (200 != res.status or null == access) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: gcp: no token and metadata server did not answer",
                .{},
            ) };
        }

        self.renewat = renewafter(self.config.io, http.jnum(http.jget(res.body, "expires_in")));

        return .{ .ok = access.? };
    }

    pub fn lookup(self: *GcpSecretsProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        if (0 == self.project.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: gcp: no project", .{}) };
        }

        const addr = if (0 != self.addr.len) self.addr else "https://secretmanager.googleapis.com";

        switch (try checkaddr(alloc, addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        if (null == self.livetoken or nowms(self.config.io) >= self.renewat) {
            const fresh = switch (try self.login(alloc)) {
                .err => |message| return .{ .err = message },
                .ok => |got| got,
            };
            if (self.livetoken) |old| {
                self.alloc.free(old);
            }
            self.livetoken = try self.alloc.dupe(u8, fresh);
        }

        const flat = switch (try sekreto.flatname(alloc, name, "_")) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const url = try std.fmt.allocPrint(
            alloc,
            "{s}/v1/projects/{s}/secrets/{s}/versions/latest:access",
            .{ trimslash(addr), self.project, flat },
        );

        const bearer = try std.fmt.allocPrint(alloc, "Bearer {s}", .{self.livetoken.?});
        const headers = [_]http.Header{.{ .name = "authorization", .value = bearer }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (404 == res.status) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: gcp error: {d}: {s}", .{ res.status, url }) };
        }

        const data = http.jstr(http.jget(http.jget(res.body, "payload"), "data")) orelse
            return .{ .ok = null };

        return .{ .ok = try unbase64(alloc, data) };
    }

    pub fn describe(self: *GcpSecretsProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "gcpsecrets:{s}", .{self.project});
    }

    pub fn deinit(self: *GcpSecretsProvider, alloc: Allocator) void {
        if (self.livetoken) |token| {
            alloc.free(token);
        }
    }
};

// ---- azure -----------------------------------------------------------

/// Azure Key Vault.
///
/// `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
/// names allow nothing else), current version. The token comes from config,
/// then a client-credentials login when tenant/clientid/clientsecret are
/// given, then the IMDS managed-identity endpoint - so on Azure's own
/// platform no credential configuration is needed.
///
/// As with GCP, the IMDS call is plain http to a link-local host by platform
/// design and carries no credential; the login and vault addresses are
/// `checkaddr`-guarded.
pub const AzureSecretsProvider = struct {
    alloc: Allocator,
    config: Config,
    vault: []const u8,
    token: []const u8,
    tenant: []const u8,
    clientid: []const u8,
    clientsecret: []const u8,
    loginaddr: []const u8,
    imdsaddr: []const u8,
    apiversion: []const u8,
    livetoken: ?[]const u8,
    renewat: i64,

    const RESOURCE = "https://vault.azure.net";

    fn login(self: *AzureSecretsProvider, alloc: Allocator) Allocator.Error!Answer([]const u8) {
        if (0 != self.token.len) {
            return .{ .ok = self.token };
        }

        if (0 != self.tenant.len and 0 != self.clientid.len and 0 != self.clientsecret.len) {
            const loginaddr = if (0 != self.loginaddr.len)
                self.loginaddr
            else
                "https://login.microsoftonline.com";

            switch (try checkaddr(alloc, loginaddr)) {
                .err => |message| return .{ .err = message },
                .ok => {},
            }

            const url = try std.fmt.allocPrint(
                alloc,
                "{s}/{s}/oauth2/v2.0/token",
                .{ trimslash(loginaddr), self.tenant },
            );

            const form = try std.fmt.allocPrint(
                alloc,
                "grant_type=client_credentials&client_id={s}&client_secret={s}&scope={s}",
                .{
                    try escape(alloc, self.clientid),
                    try escape(alloc, self.clientsecret),
                    try escape(alloc, RESOURCE ++ "/.default"),
                },
            );

            const headers = [_]http.Header{
                .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
            };

            const res = switch (try http.fetchjson(alloc, self.config.io, .POST, url, &headers, form)) {
                .err => |message| return .{ .err = message },
                .ok => |got| got,
            };

            const access = http.jstr(http.jget(res.body, "access_token"));

            if (200 != res.status or null == access) {
                return .{ .err = try sekreto.fail(
                    alloc,
                    "sekreto: azure login failed: {d}",
                    .{res.status},
                ) };
            }

            self.renewat = renewafter(self.config.io, http.jnum(http.jget(res.body, "expires_in")));
            return .{ .ok = access.? };
        }

        const imds = if (0 != self.imdsaddr.len) self.imdsaddr else "http://169.254.169.254";

        const url = try std.fmt.allocPrint(
            alloc,
            "{s}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={s}",
            .{ trimslash(imds), try escape(alloc, RESOURCE) },
        );

        const headers = [_]http.Header{.{ .name = "Metadata", .value = "true" }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const access = http.jstr(http.jget(res.body, "access_token"));

        if (200 != res.status or null == access) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: azure: no token, no client credentials, and IMDS did not answer",
                .{},
            ) };
        }

        self.renewat = renewafter(self.config.io, http.jnum(http.jget(res.body, "expires_in")));
        return .{ .ok = access.? };
    }

    pub fn lookup(self: *AzureSecretsProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        if (0 == self.vault.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: azure: no vault", .{}) };
        }

        // Only an explicit scheme is a URL; a vault NAMED httpvault must
        // still become https://httpvault.vault.azure.net.
        const vaulturl = if (std.mem.startsWith(u8, self.vault, "http://") or
            std.mem.startsWith(u8, self.vault, "https://"))
            self.vault
        else
            try std.fmt.allocPrint(alloc, "https://{s}.vault.azure.net", .{self.vault});

        switch (try checkaddr(alloc, vaulturl)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        if (null == self.livetoken or nowms(self.config.io) >= self.renewat) {
            const fresh = switch (try self.login(alloc)) {
                .err => |message| return .{ .err = message },
                .ok => |got| got,
            };
            if (self.livetoken) |old| {
                self.alloc.free(old);
            }
            self.livetoken = try self.alloc.dupe(u8, fresh);
        }

        const flat = switch (try sekreto.flatname(alloc, name, "-")) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const version = if (0 != self.apiversion.len) self.apiversion else "7.4";

        const url = try std.fmt.allocPrint(
            alloc,
            "{s}/secrets/{s}?api-version={s}",
            .{ trimslash(vaulturl), flat, version },
        );

        const bearer = try std.fmt.allocPrint(alloc, "Bearer {s}", .{self.livetoken.?});
        const headers = [_]http.Header{.{ .name = "authorization", .value = bearer }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (404 == res.status) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: azure error: {d}: {s}",
                .{ res.status, http.nakedurl(url) },
            ) };
        }

        return .{ .ok = http.jstr(http.jget(res.body, "value")) };
    }

    pub fn describe(self: *AzureSecretsProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "azuresecrets:{s}", .{self.vault});
    }

    pub fn deinit(self: *AzureSecretsProvider, alloc: Allocator) void {
        if (self.livetoken) |token| {
            alloc.free(token);
        }
    }
};

// ---- 1password -------------------------------------------------------

/// 1Password, through a Connect server.
///
/// The item titled `api.token` (titles keep their dots), in the named vault.
/// The value is the field with purpose PASSWORD, or the field labelled
/// `value`. A vault that cannot be found is an error - config names it, so
/// its absence is a broken store, not a missing secret.
pub const OnePasswordProvider = struct {
    alloc: Allocator,
    config: Config,
    addr: []const u8,
    token: []const u8,
    vault: []const u8,
    vaultid: ?[]const u8,

    fn authheader(self: *OnePasswordProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "Bearer {s}", .{self.token});
    }

    fn resolvevault(self: *OnePasswordProvider, alloc: Allocator, addr: []const u8) Allocator.Error!Answer([]const u8) {
        if (0 == self.vault.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: onepassword: no vault", .{}) };
        }

        const url = try std.fmt.allocPrint(alloc, "{s}/v1/vaults", .{addr});
        const headers = [_]http.Header{
            .{ .name = "authorization", .value = try self.authheader(alloc) },
        };

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const list = res.body orelse std.json.Value{ .null = {} };

        if (200 != res.status or .array != list) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: onepassword error: {d}: listing vaults",
                .{res.status},
            ) };
        }

        for (list.array.items) |entry| {
            const id = http.jstr(http.jget(entry, "id"));
            const named = http.jstr(http.jget(entry, "name"));

            const hit = (null != id and std.mem.eql(u8, self.vault, id.?)) or
                (null != named and std.mem.eql(u8, self.vault, named.?));

            if (hit and null != id) {
                return .{ .ok = id.? };
            }
        }

        return .{ .err = try sekreto.fail(
            alloc,
            "sekreto: onepassword: no vault named {s}",
            .{self.vault},
        ) };
    }

    pub fn lookup(self: *OnePasswordProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        switch (try sekreto.checkname(alloc, name)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        const addr = trimslash(self.addr);
        if (0 == addr.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: onepassword: no addr", .{}) };
        }

        switch (try checkaddr(alloc, addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        if (null == self.vaultid) {
            const found = switch (try self.resolvevault(alloc, addr)) {
                .err => |message| return .{ .err = message },
                .ok => |got| got,
            };
            self.vaultid = try self.alloc.dupe(u8, found);
        }

        const filter = try escape(alloc, try std.fmt.allocPrint(alloc, "title eq \"{s}\"", .{name}));

        const findurl = try std.fmt.allocPrint(
            alloc,
            "{s}/v1/vaults/{s}/items?filter={s}",
            .{ addr, self.vaultid.?, filter },
        );

        const headers = [_]http.Header{
            .{ .name = "authorization", .value = try self.authheader(alloc) },
        };

        const found = switch (try http.fetchjson(alloc, self.config.io, .GET, findurl, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const list = found.body orelse std.json.Value{ .null = {} };

        if (200 != found.status or .array != list) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: onepassword error: {d}: finding {s}",
                .{ found.status, name },
            ) };
        }

        if (0 == list.array.items.len) {
            return .{ .ok = null };
        }

        const itemid = http.jstr(http.jget(list.array.items[0], "id")) orelse "";

        const itemurl = try std.fmt.allocPrint(
            alloc,
            "{s}/v1/vaults/{s}/items/{s}",
            .{ addr, self.vaultid.?, itemid },
        );

        const item = switch (try http.fetchjson(alloc, self.config.io, .GET, itemurl, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (200 != item.status) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: onepassword error: {d}: reading {s}",
                .{ item.status, name },
            ) };
        }

        const fields = http.jget(item.body, "fields") orelse return .{ .ok = null };
        if (.array != fields) {
            return .{ .ok = null };
        }

        for (fields.array.items) |field| {
            if (http.jstr(http.jget(field, "purpose"))) |purpose| {
                if (std.mem.eql(u8, "PASSWORD", purpose)) {
                    return .{ .ok = http.jstr(http.jget(field, "value")) };
                }
            }
        }

        for (fields.array.items) |field| {
            if (http.jstr(http.jget(field, "label"))) |label| {
                if (std.mem.eql(u8, "value", label)) {
                    return .{ .ok = http.jstr(http.jget(field, "value")) };
                }
            }
        }

        return .{ .ok = null };
    }

    pub fn describe(self: *OnePasswordProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "onepassword:{s}", .{self.vault});
    }

    pub fn deinit(self: *OnePasswordProvider, alloc: Allocator) void {
        if (self.vaultid) |id| {
            alloc.free(id);
        }
    }
};

// ---- doppler ---------------------------------------------------------

/// Doppler.
///
/// The whole config is downloaded once - Doppler's own bulk endpoint - and
/// answered from memory, like a remote .env: `api.token` is the `API_TOKEN`
/// entry. A service token is config-scoped, so project and config are only
/// needed with broader tokens.
pub const DopplerProvider = struct {
    alloc: Allocator,
    config: Config,
    token: []const u8,
    project: []const u8,
    dopplerconfig: []const u8,
    addr: []const u8,
    state: std.heap.ArenaAllocator,
    values: ?[]const KeyValue,

    fn load(self: *DopplerProvider, alloc: Allocator) Allocator.Error!Answer([]const KeyValue) {
        if (self.values) |values| {
            return .{ .ok = values };
        }

        const addr = trimslash(if (0 != self.addr.len) self.addr else "https://api.doppler.com");

        switch (try checkaddr(alloc, addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        var url: std.ArrayList(u8) = .empty;
        try url.appendSlice(alloc, addr);
        try url.appendSlice(alloc, "/v3/configs/config/secrets/download?format=json");

        if (0 != self.project.len) {
            try url.appendSlice(alloc, "&project=");
            try url.appendSlice(alloc, try escape(alloc, self.project));
        }
        if (0 != self.dopplerconfig.len) {
            try url.appendSlice(alloc, "&config=");
            try url.appendSlice(alloc, try escape(alloc, self.dopplerconfig));
        }

        const bearer = try std.fmt.allocPrint(alloc, "Bearer {s}", .{self.token});
        const headers = [_]http.Header{.{ .name = "authorization", .value = bearer }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url.items, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const body = res.body orelse std.json.Value{ .null = {} };

        if (200 != res.status or .object != body) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: doppler error: {d}", .{res.status}) };
        }

        // Loaded once, so it outlives the lookup's scratch arena.
        const keep = self.state.allocator();
        var values: std.ArrayList(KeyValue) = .empty;

        var it = body.object.iterator();
        while (it.next()) |field| {
            const value = http.jstr(field.value_ptr.*) orelse continue;
            try values.append(keep, .{
                .key = try keep.dupe(u8, field.key_ptr.*),
                .value = try keep.dupe(u8, value),
            });
        }

        self.values = values.items;
        return .{ .ok = values.items };
    }

    pub fn lookup(self: *DopplerProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const key = switch (try sekreto.envkey(alloc, name, "")) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        const values = switch (try self.load(alloc)) {
            .err => |message| return .{ .err = message },
            .ok => |loaded| loaded,
        };

        for (values) |entry| {
            if (std.mem.eql(u8, entry.key, key)) {
                return .{ .ok = entry.value };
            }
        }

        return .{ .ok = null };
    }

    pub fn describe(self: *DopplerProvider, alloc: Allocator) Allocator.Error![]const u8 {
        if (0 == self.project.len) {
            return alloc.dupe(u8, "doppler");
        }
        return std.fmt.allocPrint(alloc, "doppler:{s}/{s}", .{ self.project, self.dopplerconfig });
    }

    pub fn deinit(self: *DopplerProvider, _: Allocator) void {
        self.state.deinit();
    }
};

// ---- infisical -------------------------------------------------------

/// Infisical.
///
/// `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
/// convention is environment-style keys) at a secret path in one environment
/// of a project. Auth is a token, or a universal-auth (machine identity)
/// login with clientid/clientsecret.
pub const InfisicalProvider = struct {
    alloc: Allocator,
    config: Config,
    addr: []const u8,
    token: []const u8,
    clientid: []const u8,
    clientsecret: []const u8,
    project: []const u8,
    environment: []const u8,
    path: []const u8,
    livetoken: ?[]const u8,
    renewat: i64,

    fn login(self: *InfisicalProvider, alloc: Allocator, addr: []const u8) Allocator.Error!Answer([]const u8) {
        if (0 != self.token.len) {
            return .{ .ok = self.token };
        }

        if (0 == self.clientid.len or 0 == self.clientsecret.len) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: infisical: no token and no client credentials",
                .{},
            ) };
        }

        const url = try std.fmt.allocPrint(alloc, "{s}/api/v1/auth/universal-auth/login", .{addr});

        const body = try jsonobject(alloc, &.{
            .{ .key = "clientId", .value = self.clientid },
            .{ .key = "clientSecret", .value = self.clientsecret },
        });

        const headers = [_]http.Header{
            .{ .name = "content-type", .value = "application/json" },
        };

        const res = switch (try http.fetchjson(alloc, self.config.io, .POST, url, &headers, body)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        const access = http.jstr(http.jget(res.body, "accessToken"));

        if (200 != res.status or null == access) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: infisical login failed: {d}",
                .{res.status},
            ) };
        }

        self.renewat = renewafter(self.config.io, http.jnum(http.jget(res.body, "expiresIn")));

        return .{ .ok = access.? };
    }

    pub fn lookup(self: *InfisicalProvider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const addr = trimslash(if (0 != self.addr.len) self.addr else "https://app.infisical.com");

        switch (try checkaddr(alloc, addr)) {
            .err => |message| return .{ .err = message },
            .ok => {},
        }

        if (0 == self.project.len or 0 == self.environment.len) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: infisical: no project/environment", .{}) };
        }

        if (null == self.livetoken or nowms(self.config.io) >= self.renewat) {
            const fresh = switch (try self.login(alloc, addr)) {
                .err => |message| return .{ .err = message },
                .ok => |got| got,
            };
            if (self.livetoken) |old| {
                self.alloc.free(old);
            }
            self.livetoken = try self.alloc.dupe(u8, fresh);
        }

        const key = switch (try sekreto.envkey(alloc, name, "")) {
            .err => |message| return .{ .err = message },
            .ok => |made| made,
        };

        const url = try std.fmt.allocPrint(
            alloc,
            "{s}/api/v3/secrets/raw/{s}?workspaceId={s}&environment={s}&secretPath={s}",
            .{
                addr,
                key,
                try escape(alloc, self.project),
                try escape(alloc, self.environment),
                try escape(alloc, if (0 != self.path.len) self.path else "/"),
            },
        );

        const bearer = try std.fmt.allocPrint(alloc, "Bearer {s}", .{self.livetoken.?});
        const headers = [_]http.Header{.{ .name = "authorization", .value = bearer }};

        const res = switch (try http.fetchjson(alloc, self.config.io, .GET, url, &headers, null)) {
            .err => |message| return .{ .err = message },
            .ok => |got| got,
        };

        if (404 == res.status) {
            return .{ .ok = null };
        }

        if (200 != res.status) {
            return .{ .err = try sekreto.fail(alloc, "sekreto: infisical error: {d}", .{res.status}) };
        }

        return .{ .ok = http.jstr(http.jget(http.jget(res.body, "secret"), "secretValue")) };
    }

    pub fn describe(self: *InfisicalProvider, alloc: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(alloc, "infisical:{s}/{s}", .{ self.project, self.environment });
    }

    pub fn deinit(self: *InfisicalProvider, alloc: Allocator) void {
        if (self.livetoken) |token| {
            alloc.free(token);
        }
    }
};

// ---- JSON writing ----------------------------------------------------

/// One JSON string literal. The bodies this library sends are flat maps of
/// strings, so a full writer would be more machinery than the job needs.
fn jsonstring(alloc: Allocator, text: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(alloc, '"');

    for (text) |ch| {
        switch (ch) {
            '"' => try out.appendSlice(alloc, "\\\""),
            '\\' => try out.appendSlice(alloc, "\\\\"),
            '\n' => try out.appendSlice(alloc, "\\n"),
            '\r' => try out.appendSlice(alloc, "\\r"),
            '\t' => try out.appendSlice(alloc, "\\t"),
            else => {
                if (0x20 > ch) {
                    try out.appendSlice(alloc, try std.fmt.allocPrint(alloc, "\\u{x:0>4}", .{ch}));
                } else {
                    try out.append(alloc, ch);
                }
            },
        }
    }

    try out.append(alloc, '"');
    return out.items;
}

/// A flat JSON object of string fields.
fn jsonobject(alloc: Allocator, fields: []const KeyValue) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(alloc, '{');

    for (fields, 0..) |field, at| {
        if (0 < at) {
            try out.append(alloc, ',');
        }
        try out.appendSlice(alloc, try jsonstring(alloc, field.key));
        try out.append(alloc, ':');
        try out.appendSlice(alloc, try jsonstring(alloc, field.value));
    }

    try out.append(alloc, '}');
    return out.items;
}

// ---- the union -------------------------------------------------------

/// One provider, of one of the fourteen kinds.
///
/// Every kind is behind a pointer because several carry state that must
/// outlive one lookup - a logged-in token, a downloaded config, a resolved
/// vault id - and a union held by value in the chain would hand each lookup
/// its own copy of that state.
pub const Provider = union(enum) {
    env: *EnvProvider,
    dotenv: *DotenvProvider,
    memory: *MemoryProvider,
    file: *FileProvider,
    hashicorp: *HashicorpProvider,
    boru: *BoruProvider,
    awssecrets: *AwsSecretsProvider,
    awsparams: *AwsParamsProvider,
    gcpsecrets: *GcpSecretsProvider,
    azuresecrets: *AzureSecretsProvider,
    onepassword: *OnePasswordProvider,
    doppler: *DopplerProvider,
    infisical: *InfisicalProvider,
    secretspec: *SecretspecProvider,

    /// The value, null if this provider does not have it, or the message of
    /// a failure. `alloc` is scratch for one lookup: what the provider keeps
    /// between lookups it allocates from its own allocator instead.
    pub fn lookup(self: Provider, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        return switch (self) {
            inline else => |provider| provider.lookup(alloc, name),
        };
    }

    /// A short description, shown by `Sekreto.sources()`. It must lead with
    /// the kind: everything before the first `:` is the default store name.
    ///
    /// ALWAYS allocated, even for the kinds whose description is a constant:
    /// a caller that sometimes gets a literal and sometimes gets an
    /// allocation cannot free either one safely.
    pub fn describe(self: Provider, alloc: Allocator) Allocator.Error![]const u8 {
        return switch (self) {
            inline else => |provider| provider.describe(alloc),
        };
    }

    pub fn deinit(self: Provider, alloc: Allocator) void {
        switch (self) {
            inline else => |provider| {
                provider.deinit(alloc);
                alloc.destroy(provider);
            },
        }
    }
};

fn make(alloc: Allocator, comptime T: type, value: T) Allocator.Error!*T {
    const out = try alloc.create(T);
    out.* = value;
    return out;
}

/// Build a provider from its declarative form.
pub fn makeprovider(alloc: Allocator, config: Config, spec: ProviderSpec) Allocator.Error!Answer(Provider) {
    const kind = spec.kind;

    if (std.mem.eql(u8, "env", kind)) {
        return .{ .ok = .{ .env = try make(alloc, EnvProvider, .{
            .config = config,
            .prefix = spec.prefix,
        }) } };
    }

    if (std.mem.eql(u8, "dotenv", kind)) {
        return .{ .ok = .{ .dotenv = try make(alloc, DotenvProvider, .{
            .alloc = alloc,
            .config = config,
            .file = if (0 != spec.file.len) spec.file else ".env",
            .prefix = spec.prefix,
            .state = std.heap.ArenaAllocator.init(alloc),
            .values = null,
        }) } };
    }

    if (std.mem.eql(u8, "memory", kind)) {
        return .{ .ok = .{ .memory = try make(alloc, MemoryProvider, .{
            .values = spec.values,
            .prefix = spec.prefix,
        }) } };
    }

    if (std.mem.eql(u8, "file", kind)) {
        return .{ .ok = .{ .file = try make(alloc, FileProvider, .{
            .config = config,
            .dir = spec.dir,
            .prefix = spec.prefix,
        }) } };
    }

    if (std.mem.eql(u8, "hashicorp", kind)) {
        const kv: i64 = if (0 == spec.kv) 2 else spec.kv;

        // A version typo like kv: 3 must not quietly behave as v2 and turn
        // its 404s into misses; there is nothing safe to assume it meant.
        if (1 != kv and 2 != kv) {
            return .{ .err = try sekreto.fail(
                alloc,
                "sekreto: hashicorp: unsupported kv version: {d}",
                .{kv},
            ) };
        }

        return .{
            .ok = .{
                .hashicorp = try make(alloc, HashicorpProvider, .{
                    .alloc = alloc,
                    .config = config,
                    .addr = spec.addr,
                    .token = spec.token,
                    .mount = if (0 != spec.mount.len) spec.mount else "secret",
                    .kv = kv,
                    .vaultnamespace = spec.vaultnamespace,
                    .auth = spec.auth,
                    // A configured token is the live token, and is kept forever.
                    .livetoken = if (0 == spec.token.len) null else try alloc.dupe(u8, spec.token),
                    .renewat = NEVER,
                }),
            },
        };
    }

    if (std.mem.eql(u8, "boru", kind)) {
        return .{ .ok = .{ .boru = try make(alloc, BoruProvider, .{
            .alloc = alloc,
            .config = config,
            .command = if (0 != spec.command.len) spec.command else "boru",
            .namespace = spec.namespace,
            .home = spec.home,
            .addr = spec.addr,
            .token = spec.token,
            .mount = if (0 != spec.mount.len) spec.mount else "secret",
        }) } };
    }

    if (std.mem.eql(u8, "awssecrets", kind)) {
        return .{ .ok = .{ .awssecrets = try make(alloc, AwsSecretsProvider, .{
            .aws = awsof(config, spec),
        }) } };
    }

    if (std.mem.eql(u8, "awsparams", kind)) {
        return .{ .ok = .{ .awsparams = try make(alloc, AwsParamsProvider, .{
            .aws = awsof(config, spec),
        }) } };
    }

    if (std.mem.eql(u8, "gcpsecrets", kind)) {
        return .{ .ok = .{ .gcpsecrets = try make(alloc, GcpSecretsProvider, .{
            .alloc = alloc,
            .config = config,
            .project = spec.project,
            .token = spec.token,
            .addr = spec.addr,
            .metadataaddr = spec.metadataaddr,
            .livetoken = null,
            .renewat = NEVER,
        }) } };
    }

    if (std.mem.eql(u8, "azuresecrets", kind)) {
        return .{ .ok = .{ .azuresecrets = try make(alloc, AzureSecretsProvider, .{
            .alloc = alloc,
            .config = config,
            .vault = spec.vault,
            .token = spec.token,
            .tenant = spec.tenant,
            .clientid = spec.clientid,
            .clientsecret = spec.clientsecret,
            .loginaddr = spec.loginaddr,
            .imdsaddr = spec.imdsaddr,
            .apiversion = spec.apiversion,
            .livetoken = null,
            .renewat = NEVER,
        }) } };
    }

    if (std.mem.eql(u8, "onepassword", kind)) {
        return .{ .ok = .{ .onepassword = try make(alloc, OnePasswordProvider, .{
            .alloc = alloc,
            .config = config,
            .addr = spec.addr,
            .token = spec.token,
            .vault = spec.vault,
            .vaultid = null,
        }) } };
    }

    if (std.mem.eql(u8, "doppler", kind)) {
        return .{ .ok = .{ .doppler = try make(alloc, DopplerProvider, .{
            .alloc = alloc,
            .config = config,
            .token = spec.token,
            .project = spec.project,
            .dopplerconfig = spec.config,
            .addr = spec.addr,
            .state = std.heap.ArenaAllocator.init(alloc),
            .values = null,
        }) } };
    }

    if (std.mem.eql(u8, "infisical", kind)) {
        return .{ .ok = .{ .infisical = try make(alloc, InfisicalProvider, .{
            .alloc = alloc,
            .config = config,
            .addr = spec.addr,
            .token = spec.token,
            .clientid = spec.clientid,
            .clientsecret = spec.clientsecret,
            .project = spec.project,
            .environment = spec.environment,
            .path = spec.path,
            .livetoken = null,
            .renewat = NEVER,
        }) } };
    }

    if (std.mem.eql(u8, "secretspec", kind)) {
        return .{ .ok = .{ .secretspec = try make(alloc, SecretspecProvider, .{
            .config = config,
            .command = if (0 != spec.command.len) spec.command else "secretspec",
            .file = spec.file,
            .profile = spec.profile,
            .backend = spec.backend,
            .reason = spec.reason,
            .prefix = spec.prefix,
        }) } };
    }

    return .{ .err = try sekreto.fail(alloc, "sekreto: unknown provider kind: {s}", .{kind}) };
}

fn awsof(config: Config, spec: ProviderSpec) Aws {
    return .{
        .config = config,
        .region = spec.region,
        .keyid = spec.keyid,
        .secret = spec.secret,
        .session = spec.session,
        .addr = spec.addr,
        .prefix = spec.prefix,
    };
}
