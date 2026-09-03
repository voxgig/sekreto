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
//!
//! After the fourteen groups comes the plugin seam - what the spec cannot
//! see, pinned here as the other ports pin it in their own suites: the
//! built-ins need no plugin, an unloaded kind is refused by name, the full
//! set holds every kind, a refusal comes back out of the host as itself.

const std = @import("std");
const omni = @import("omni");
const sekreto = @import("sekreto");
const plugins = @import("sekretoplugins");

const plugin = sekreto.plugin;
const pv = plugin.value;

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
            var pairs: std.ArrayList(sekreto.KeyValue) = .empty;
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

    // Every plugin, to every chain the spec builds: the spec names kinds
    // freely, and which are built in is not its concern.
    return switch (try sekreto.Sekreto.init(ALLOC, CONFIG, .{
        .providers = specs.items,
        .plugins = &plugins.ALL,
    })) {
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

    var headers: std.ArrayList(plugins.sigv4.Pair) = .empty;

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

    const signed = plugins.sigv4.sign(ALLOC, .{
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

// ---- the plugin seam -------------------------------------------------
//
// Not omni groups: the spec runs the same in every port, and these are
// about what THIS port links and refuses. Each check answers null, or the
// reason it failed. The same eight the go and python suites pin.

const Allocator = std.mem.Allocator;
const Provider = sekreto.Provider;
const Found = sekreto.Found;
const KeyValue = sekreto.KeyValue;

fn build(options: sekreto.Options) !sekreto.Answer(*sekreto.Sekreto) {
    return sekreto.Sekreto.init(ALLOC, CONFIG, options);
}

fn joined(list: []const []const u8) ![]const u8 {
    return std.mem.join(ALLOC, " ", list);
}

/// Every instance ref on the host, sorted, space-joined - how the other
/// ports read `host.list()` in their seam tests.
fn refs(secrets: *sekreto.Sekreto) ![]const u8 {
    return joined(pv.keys(plugin.host.list(secrets.host)));
}

/// Is every instance on the host live?
fn alllive(secrets: *sekreto.Sekreto) bool {
    const list = plugin.host.list(secrets.host);
    for (pv.keys(list)) |ref| {
        if (!std.mem.eql(u8, "live", pv.asStr(pv.get(list, ref)))) {
            return false;
        }
    }
    return true;
}

fn names(secrets: *sekreto.Sekreto) ![]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (pv.items(secrets.catalog.names())) |name| {
        try out.append(ALLOC, pv.asStr(name));
    }
    return joined(out.items);
}

fn mismatch(comptime what: []const u8, want: []const u8, got: []const u8) ![]const u8 {
    return std.fmt.allocPrint(ALLOC, what ++ ": want `{s}`, got `{s}`", .{ want, got });
}

/// A chain of the four built-ins, with no plugin passed in: it builds,
/// it answers, and the host and the catalog hold exactly those four.
fn seamBuiltins() !?[]const u8 {
    const secrets = switch (try build(.{ .providers = &.{
        .{ .kind = "memory", .values = &.{.{ .key = "API_TOKEN", .value = "tok01" }} },
        .{ .kind = "env" },
        .{ .kind = "dotenv", .file = "/nonexistent-sekreto-test/.env" },
        .{ .kind = "file", .dir = "/nonexistent-sekreto-test" },
    } })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    switch (try secrets.get("api.token")) {
        .err => |message| return message,
        .ok => |value| if (!std.mem.eql(u8, "tok01", value)) return try mismatch("get", "tok01", value),
    }

    const stores = try joined(try secrets.stores(ALLOC));
    if (!std.mem.eql(u8, "memory env dotenv file", stores)) return try mismatch("stores", "memory env dotenv file", stores);

    const catalog = try names(secrets);
    if (!std.mem.eql(u8, "dotenv env file memory", catalog)) return try mismatch("catalog", "dotenv env file memory", catalog);

    const list = try refs(secrets);
    if (!std.mem.eql(u8, "dotenv env file memory", list)) return try mismatch("host", "dotenv env file memory", list);
    if (!alllive(secrets)) return "an instance is not live";

    return null;
}

/// A plugin kind that was not passed in is refused, naming the fix; a
/// kind nobody ships is a typo and gets no hint.
fn seamUnknownKind() !?[]const u8 {
    const want = "sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)" ++
        " - hashicorp is a sekreto plugin, not built in: pass it in the plugins option";
    switch (try build(.{ .providers = &.{.{ .kind = "hashicorp", .addr = "https://v", .token = "t" }} })) {
        .err => |message| if (!std.mem.eql(u8, want, message)) return try mismatch("unknown kind", want, message),
        .ok => |made| {
            made.deinit();
            return "an unloaded kind was accepted";
        },
    }

    const typo = "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)";
    switch (try build(.{ .providers = &.{.{ .kind = "vualt" }} })) {
        .err => |message| if (!std.mem.eql(u8, typo, message)) return try mismatch("typo", typo, message),
        .ok => |made| {
            made.deinit();
            return "a typo was accepted";
        },
    }

    return null;
}

/// Two providers MAY share a store name - a directed read walks both, and
/// the spec pins it - but an instance ref may not, so the second gets a
/// numbered tag from the host and keeps its store name. And a store name
/// must be a valid plugin tag.
fn seamStoreNames() !?[]const u8 {
    const secrets = switch (try build(.{ .providers = &.{
        .{ .kind = "memory" },
        .{ .kind = "memory", .values = &.{.{ .key = "API_TOKEN", .value = "second" }} },
        .{ .kind = "memory", .name = "pair" },
        .{ .kind = "memory", .name = "pair", .values = &.{.{ .key = "API_TOKEN", .value = "pair2" }} },
    } })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    const stores = try joined(try secrets.stores(ALLOC));
    if (!std.mem.eql(u8, "memory pair", stores)) return try mismatch("stores", "memory pair", stores);

    const list = try refs(secrets);
    if (!std.mem.eql(u8, "memory memory$1 memory$2 memory$pair", list)) return try mismatch("refs", "memory memory$1 memory$2 memory$pair", list);

    switch (try secrets.getfrom("memory", "api.token")) {
        .err => |message| return message,
        .ok => |value| if (!std.mem.eql(u8, "second", value)) return try mismatch("memory", "second", value),
    }
    switch (try secrets.getfrom("pair", "api.token")) {
        .err => |message| return message,
        .ok => |value| if (!std.mem.eql(u8, "pair2", value)) return try mismatch("pair", "pair2", value),
    }

    const want = "sekreto: invalid store name: my store";
    switch (try build(.{ .providers = &.{.{ .kind = "memory", .name = "my store" }} })) {
        .err => |message| if (!std.mem.eql(u8, want, message)) return try mismatch("store name", want, message),
        .ok => |made| {
            made.deinit();
            return "an invalid store name was accepted";
        },
    }

    return null;
}

const PLUGIN_KINDS = [_][]const u8{
    "awsparams",  "awssecrets", "azuresecrets", "boru",        "doppler",
    "gcpsecrets", "hashicorp",  "infisical",    "onepassword", "secretspec",
};

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// The full set holds every kind, and every kind - built in or plugin -
/// builds from a spec. Naming a kind is not enough: a kind can be in the
/// catalog and still fail to build, and construction is what the CLI does
/// before any network.
fn seamFullSet() !?[]const u8 {
    var got: std.ArrayList([]const u8) = .empty;
    for (plugins.ALL) |definition| {
        try got.append(ALLOC, definition.name);
    }
    std.mem.sort([]const u8, got.items, {}, lessStr);
    const shipped = try joined(got.items);
    const want = try joined(&PLUGIN_KINDS);
    if (!std.mem.eql(u8, want, shipped)) return try mismatch("full set", want, shipped);

    var kinds: std.ArrayList([]const u8) = .empty;
    try kinds.appendSlice(ALLOC, &sekreto.KINDS.builtin);
    try kinds.appendSlice(ALLOC, &sekreto.KINDS.plugin);
    std.mem.sort([]const u8, kinds.items, {}, lessStr);
    const all = try joined(kinds.items);
    const fourteen = "awsparams awssecrets azuresecrets boru doppler dotenv env file gcpsecrets hashicorp infisical memory onepassword secretspec";
    if (!std.mem.eql(u8, fourteen, all)) return try mismatch("KINDS", fourteen, all);

    var chain: std.ArrayList(ProviderSpec) = .empty;
    for (kinds.items) |kind| {
        try chain.append(ALLOC, .{
            .kind = kind,
            .addr = "http://127.0.0.1:8200",
            .token = "t",
            .dir = "/tmp",
            .file = "/tmp/.env",
        });
    }

    const secrets = switch (try build(.{ .providers = chain.items, .plugins = &plugins.ALL })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    const stores = try joined(try secrets.stores(ALLOC));
    if (!std.mem.eql(u8, all, stores)) return try mismatch("stores", all, stores);
    if (!alllive(secrets)) return "an instance is not live";

    return null;
}

/// One plugin is enough for a chain that names only it - and a kind that
/// was not passed in is refused, naming the fix.
fn seamOnePlugin() !?[]const u8 {
    const secrets = switch (try build(.{
        .plugins = &.{plugins.hashicorp},
        .providers = &.{
            .{ .kind = "memory", .values = &.{.{ .key = "API_TOKEN", .value = "tok01" }} },
            .{ .kind = "hashicorp", .name = "prod", .addr = "https://vault.example.com", .token = "t" },
        },
    })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    const stores = try joined(try secrets.stores(ALLOC));
    if (!std.mem.eql(u8, "memory prod", stores)) return try mismatch("stores", "memory prod", stores);

    const sources = try joined(try secrets.sources(ALLOC));
    if (!std.mem.eql(u8, "memory hashicorp:https://vault.example.com/secret", sources)) {
        return try mismatch("sources", "memory hashicorp:https://vault.example.com/secret", sources);
    }

    switch (try secrets.get("api.token")) {
        .err => |message| return message,
        .ok => |value| if (!std.mem.eql(u8, "tok01", value)) return try mismatch("get", "tok01", value),
    }

    // The plugin host is what the chain is made of, and it reads like
    // the chain: the kind, or kind$store for a named store.
    const list = try refs(secrets);
    if (!std.mem.eql(u8, "hashicorp$prod memory", list)) return try mismatch("host", "hashicorp$prod memory", list);
    if (!alllive(secrets)) return "an instance is not live";

    const catalog = try names(secrets);
    if (!std.mem.eql(u8, "dotenv env file hashicorp memory", catalog)) return try mismatch("catalog", "dotenv env file hashicorp memory", catalog);

    const want = "sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)" ++
        " - doppler is a sekreto plugin, not built in: pass it in the plugins option";
    switch (try build(.{ .plugins = &.{plugins.hashicorp}, .providers = &.{.{ .kind = "doppler", .token = "t" }} })) {
        .err => |message| if (!std.mem.eql(u8, want, message)) return try mismatch("unknown kind", want, message),
        .ok => |made| {
            made.deinit();
            return "an unloaded kind was accepted";
        },
    }

    return null;
}

/// A custom kind is one `providerplugin` call: a provider that answers to
/// SHOUTED names, and refuses a spec with no values.
const Shouty = struct {
    values: []const KeyValue,

    pub fn lookup(self: *Shouty, alloc: Allocator, name: []const u8) Allocator.Error!Found {
        const loud = try std.ascii.allocUpperString(alloc, name);
        for (self.values) |pair| {
            if (std.mem.eql(u8, pair.key, loud)) {
                return .{ .ok = pair.value };
            }
        }
        return .{ .ok = null };
    }

    pub fn describe(_: *Shouty, alloc: Allocator) Allocator.Error![]const u8 {
        return alloc.dupe(u8, "shouty");
    }

    pub fn deinit(_: *Shouty, _: Allocator) void {}
};

fn makeshouty(alloc: Allocator, config: sekreto.Config, spec: ProviderSpec) Allocator.Error!sekreto.Answer(Provider) {
    _ = config;
    if (0 == spec.values.len) {
        return .{ .err = try sekreto.fail(alloc, "sekreto: shouty: no values", .{}) };
    }
    return .{ .ok = try sekreto.provide(alloc, Shouty, .{ .values = spec.values }) };
}

const SHOUTY = sekreto.providerplugin("shouty", makeshouty);
const LOUDMEMORY = sekreto.providerplugin("memory", makeshouty);

/// A provider that refuses its own configuration answers with a message
/// from inside the plugin's `define`. The spec pins that message byte for
/// byte, so it must come back out of the host as itself - not wrapped as
/// plugin_define_failed, and not as the host's wording of it. Both for a
/// shipped kind and for a custom one.
fn seamRefusal() !?[]const u8 {
    const kv = "sekreto: hashicorp: unsupported kv version: 3";
    switch (try build(.{ .plugins = &plugins.ALL, .providers = &.{.{ .kind = "hashicorp", .addr = "https://v", .token = "t", .kv = 3 }} })) {
        .err => |message| if (!std.mem.eql(u8, kv, message)) return try mismatch("kv", kv, message),
        .ok => |made| {
            made.deinit();
            return "kv: 3 was accepted";
        },
    }

    const secrets = switch (try build(.{
        .plugins = &.{SHOUTY},
        .providers = &.{.{ .kind = "shouty", .values = &.{.{ .key = "API.TOKEN", .value = "loud" }} }},
    })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    switch (try secrets.get("api.token")) {
        .err => |message| return message,
        .ok => |value| if (!std.mem.eql(u8, "loud", value)) return try mismatch("shouty", "loud", value),
    }

    const want = "sekreto: shouty: no values";
    switch (try build(.{ .plugins = &.{SHOUTY}, .providers = &.{.{ .kind = "shouty" }} })) {
        .err => |message| if (!std.mem.eql(u8, want, message)) return try mismatch("refusal", want, message),
        .ok => |made| {
            made.deinit();
            return "a refusal was accepted";
        },
    }

    return null;
}

/// `close` tears the chain down - the host empties, every read reports
/// the secret unknown - and keeps redaction, which must outlive the chain
/// because the log it protects does.
fn seamClose() !?[]const u8 {
    const secrets = switch (try build(.{ .providers = &.{
        .{ .kind = "memory", .values = &.{.{ .key = "API_TOKEN", .value = "tok01secret" }} },
    } })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    switch (try secrets.get("api.token")) {
        .err => |message| return message,
        .ok => {},
    }

    secrets.close();

    const list = try refs(secrets);
    if (0 != list.len) return try mismatch("host after close", "", list);

    switch (try secrets.get("api.token")) {
        .err => |message| if (!std.mem.eql(u8, "sekreto: unknown secret: api.token", message)) return try mismatch("get after close", "sekreto: unknown secret: api.token", message),
        .ok => return "a closed chain answered",
    }

    const redacted = try secrets.redactText(ALLOC, "token=tok01secret");
    if (!std.mem.eql(u8, "token=[redacted]", redacted)) return try mismatch("redact after close", "token=[redacted]", redacted);

    return null;
}

/// A plugin that names a built-in kind replaces it - how a host
/// substitutes an implementation, and never an accident.
fn seamReplace() !?[]const u8 {
    const secrets = switch (try build(.{
        .plugins = &.{LOUDMEMORY},
        .providers = &.{.{ .kind = "memory", .values = &.{.{ .key = "API.TOKEN", .value = "replaced" }} }},
    })) {
        .err => |message| return message,
        .ok => |made| made,
    };
    defer secrets.deinit();

    switch (try secrets.get("api.token")) {
        .err => |message| return message,
        .ok => |value| if (!std.mem.eql(u8, "replaced", value)) return try mismatch("replaced memory", "replaced", value),
    }

    const catalog = try names(secrets);
    if (!std.mem.eql(u8, "dotenv env file memory", catalog)) return try mismatch("catalog", "dotenv env file memory", catalog);

    return null;
}

const Seam = struct { name: []const u8, check: *const fn () anyerror!?[]const u8 };

const SEAMS = [_]Seam{
    .{ .name = "plugins/builtins", .check = seamBuiltins },
    .{ .name = "plugins/unknownkind", .check = seamUnknownKind },
    .{ .name = "plugins/storenames", .check = seamStoreNames },
    .{ .name = "plugins/fullset", .check = seamFullSet },
    .{ .name = "plugins/oneplugin", .check = seamOnePlugin },
    .{ .name = "plugins/refusal", .check = seamRefusal },
    .{ .name = "plugins/close", .check = seamClose },
    .{ .name = "plugins/replace", .check = seamReplace },
};

fn runseams() void {
    for (SEAMS) |seam| {
        if (!wanted(seam.name)) {
            continue;
        }
        const failure = seam.check() catch |err| @errorName(err);
        report(seam.name, failure);
    }
}

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

    // ...and the plugin seam, which is this port's own.
    runseams();

    std.debug.print("\n{d} passed, {d} failed\n", .{ PASSCOUNT, FAILCOUNT });

    std.process.exit(if (0 == FAILCOUNT) 0 else 1);
}
