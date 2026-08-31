//! A tiny app that needs a secret.
//!
//! It asks sekreto for `api.token` and calls the token-protected API with
//! it. Every port ships this same CLI, and test/integration.sh runs all of
//! them against the same server from every secret source - which is what
//! proves the library, rather than the spec alone.
//!
//! Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
//!
//! Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//!          gcpsecrets azuresecrets onepassword doppler infisical
//!          secretspec chain
//!
//! Each source's configuration arrives in the environment variables its own
//! ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
//! chainfor below.

const std = @import("std");
const sekreto = @import("sekreto");

const ProviderSpec = sekreto.ProviderSpec;

const LANG = "zig";

fn get(env: *const std.process.Environ.Map, name: []const u8) []const u8 {
    return env.get(name) orelse "";
}

/// The provider chain one `--source` names.
fn chainfor(
    alloc: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    source: []const u8,
) std.mem.Allocator.Error![]const ProviderSpec {
    const envspec = ProviderSpec{ .kind = "env", .prefix = get(env, "SEKRETO_PREFIX") };

    const dotenvspec = ProviderSpec{
        .kind = "dotenv",
        .file = if (0 != get(env, "SEKRETO_DOTENV").len) get(env, "SEKRETO_DOTENV") else ".env",
    };

    const filespec = ProviderSpec{
        .kind = "file",
        .dir = if (0 != get(env, "SEKRETO_FILEDIR").len) get(env, "SEKRETO_FILEDIR") else "/run/secrets",
    };

    const auth: ?sekreto.providers.Auth = if (0 == get(env, "VAULT_AUTH").len) null else .{
        .method = get(env, "VAULT_AUTH"),
        .role = get(env, "VAULT_ROLE"),
        .jwtfile = get(env, "VAULT_JWT_FILE"),
        .roleid = get(env, "VAULT_ROLE_ID"),
        .secretid = get(env, "VAULT_SECRET_ID"),
    };

    const hashicorpspec = ProviderSpec{
        .kind = "hashicorp",
        .addr = get(env, "VAULT_ADDR"),
        .token = get(env, "VAULT_TOKEN"),
        .mount = get(env, "VAULT_MOUNT"),
        .kv = std.fmt.parseInt(i64, get(env, "VAULT_KV"), 10) catch 0,
        .vaultnamespace = get(env, "VAULT_NAMESPACE"),
        .auth = auth,
    };

    const boruspec = ProviderSpec{
        .kind = "boru",
        .command = if (0 != get(env, "BORU_COMMAND").len) get(env, "BORU_COMMAND") else "boru",
        .namespace = get(env, "BORU_NAMESPACE"),
        .home = get(env, "BORU_HOME"),
    };

    // The same vault over its wire protocol (`boru vault serve`) instead of
    // the CLI: an address plus a capability token from `vault grant`.
    const boruwirespec = ProviderSpec{
        .kind = "boru",
        .addr = get(env, "BORU_ADDR"),
        .token = get(env, "BORU_TOKEN"),
        .namespace = get(env, "BORU_NAMESPACE"),
    };

    const awssecretsspec = ProviderSpec{
        .kind = "awssecrets",
        .region = get(env, "AWS_REGION"),
        .addr = get(env, "AWS_ENDPOINT"),
    };

    const awsparamsspec = ProviderSpec{
        .kind = "awsparams",
        .region = get(env, "AWS_REGION"),
        .addr = get(env, "AWS_ENDPOINT"),
        .prefix = get(env, "AWS_PARAM_PREFIX"),
    };

    const gcpspec = ProviderSpec{
        .kind = "gcpsecrets",
        .project = get(env, "GCP_PROJECT"),
        .addr = get(env, "GCP_ADDR"),
        .metadataaddr = get(env, "GCP_METADATA_ADDR"),
    };

    const azurespec = ProviderSpec{
        .kind = "azuresecrets",
        .vault = get(env, "AZURE_VAULT"),
        .token = get(env, "AZURE_TOKEN"),
        .tenant = get(env, "AZURE_TENANT"),
        .clientid = get(env, "AZURE_CLIENT_ID"),
        .clientsecret = get(env, "AZURE_CLIENT_SECRET"),
        .loginaddr = get(env, "AZURE_LOGIN_ADDR"),
        .imdsaddr = get(env, "AZURE_IMDS_ADDR"),
    };

    const onepasswordspec = ProviderSpec{
        .kind = "onepassword",
        .addr = get(env, "OP_CONNECT_HOST"),
        .token = get(env, "OP_CONNECT_TOKEN"),
        .vault = get(env, "OP_VAULT"),
    };

    const dopplerspec = ProviderSpec{
        .kind = "doppler",
        .token = get(env, "DOPPLER_TOKEN"),
        .project = get(env, "DOPPLER_PROJECT"),
        .config = get(env, "DOPPLER_CONFIG"),
        .addr = get(env, "DOPPLER_ADDR"),
    };

    // SecretSpec's own environment variables where it has them
    // (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
    // secretspec CLI itself), so a shell already set up for secretspec
    // needs nothing further.
    const secretspecspec = ProviderSpec{
        .kind = "secretspec",
        .command = if (0 != get(env, "SECRETSPEC_COMMAND").len) get(env, "SECRETSPEC_COMMAND") else "secretspec",
        .file = get(env, "SECRETSPEC_FILE"),
        .profile = get(env, "SECRETSPEC_PROFILE"),
        .backend = get(env, "SECRETSPEC_PROVIDER"),
        .reason = get(env, "SECRETSPEC_REASON"),
    };

    const infisicalspec = ProviderSpec{
        .kind = "infisical",
        .addr = get(env, "INFISICAL_ADDR"),
        .token = get(env, "INFISICAL_TOKEN"),
        .clientid = get(env, "INFISICAL_CLIENT_ID"),
        .clientsecret = get(env, "INFISICAL_CLIENT_SECRET"),
        .project = get(env, "INFISICAL_PROJECT"),
        .environment = get(env, "INFISICAL_ENV"),
        .path = get(env, "INFISICAL_PATH"),
    };

    const bysource = [_]struct { []const u8, ProviderSpec }{
        .{ "env", envspec },
        .{ "dotenv", dotenvspec },
        .{ "file", filespec },
        .{ "hashicorp", hashicorpspec },
        .{ "boru", boruspec },
        .{ "boruwire", boruwirespec },
        .{ "awssecrets", awssecretsspec },
        .{ "awsparams", awsparamsspec },
        .{ "gcpsecrets", gcpspec },
        .{ "azuresecrets", azurespec },
        .{ "onepassword", onepasswordspec },
        .{ "doppler", dopplerspec },
        .{ "infisical", infisicalspec },
        .{ "secretspec", secretspecspec },
    };

    for (bysource) |entry| {
        if (std.mem.eql(u8, entry[0], source)) {
            return alloc.dupe(ProviderSpec, &.{entry[1]});
        }
    }

    // The default: the chain an app would actually ship with - local
    // overrides first, shared vaults last.
    return alloc.dupe(ProviderSpec, &.{ envspec, dotenvspec, hashicorpspec, boruspec });
}

/// The value of a `--flag value` pair, or "" when the flag is absent.
fn flagof(args: []const []const u8, flag: []const u8) []const u8 {
    for (args, 0..) |arg, at| {
        if (std.mem.eql(u8, flag, arg) and at + 1 < args.len) {
            return args[at + 1];
        }
    }
    return "";
}

/// One JSON string literal, for the single line this CLI prints.
fn quote(alloc: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
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

fn complain(io: std.Io, message: []const u8) void {
    var buffer: [4096]u8 = undefined;
    var stderr = std.Io.File.stderr().writer(io, &buffer);
    stderr.interface.print("sekreto-cli: {s}\n", .{message}) catch return;
    stderr.interface.flush() catch return;
}

fn run(init: std.process.Init) !u8 {
    const alloc = init.arena.allocator();
    const io = init.io;

    var argv: std.ArrayList([]const u8) = .empty;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip();
    while (args.next()) |arg| {
        try argv.append(alloc, arg);
    }

    const url = if (0 < argv.items.len and !std.mem.startsWith(u8, argv.items[0], "--"))
        argv.items[0]
    else
        "http://127.0.0.1:8099/whoami";

    const flagged = flagof(argv.items, "--source");
    const source = if (0 == flagged.len) "chain" else flagged;

    // --store names a store outright: the secret must come from that one,
    // not from whichever provider happens to answer first.
    const store = flagof(argv.items, "--store");

    const config = sekreto.Config{ .io = io, .env = init.environ_map };
    const specs = try chainfor(alloc, init.environ_map, source);

    var secrets = switch (try sekreto.Sekreto.init(alloc, config, specs, true)) {
        .err => |message| {
            complain(io, message);
            return 2;
        },
        .ok => |made| made,
    };
    defer secrets.deinit();

    const found = if (0 != store.len)
        try secrets.getfrom(store, "api.token")
    else
        try secrets.get("api.token");

    const token = switch (found) {
        .err => |message| {
            complain(io, message);
            return 2;
        },
        .ok => |value| value,
    };

    const bearer = try std.fmt.allocPrint(alloc, "Bearer {s}", .{token});

    const res = switch (try sekreto.http.fetchjson(alloc, io, .GET, url, &.{
        .{ .name = "authorization", .value = bearer },
        .{ .name = "x-sekreto-lang", .value = LANG },
    }, null)) {
        .err => |message| {
            complain(io, message);
            return 2;
        },
        .ok => |got| got,
    };

    if (200 != res.status) {
        // Never print the token itself, even when the call fails - the
        // server is entitled to echo whatever it was sent.
        const why = try std.fmt.allocPrint(alloc, "{f}", .{
            std.json.fmt(res.body orelse std.json.Value{ .null = {} }, .{}),
        });
        complain(io, try secrets.redactText(alloc, why));
        return 1;
    }

    const caller = sekreto.http.jstr(sekreto.http.jget(res.body, "caller")) orelse "unknown";

    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buffer);

    try stdout.interface.print(
        "{{\"ok\":true,\"lang\":{s},\"source\":{s},\"store\":{s},\"caller\":{s}}}\n",
        .{
            try quote(alloc, LANG),
            try quote(alloc, source),
            try quote(alloc, store),
            try quote(alloc, caller),
        },
    );
    try stdout.interface.flush();

    return 0;
}

pub fn main(init: std.process.Init) !void {
    std.process.exit(try run(init));
}
