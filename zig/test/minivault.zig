//! RUN: make seam
//! RUN-SOME: ./build/minivaulttest restricted
//!
//! The mini vault, from both sides: the store a chain reads, and the
//! programmatic API a plugin definition can publish beside it.
//!
//! The vault is not in spec/sekreto.json and cannot be until every port
//! ships the kind. The spec runs against all twenty-three of them, so an
//! entry naming `minivault` would fail the ports that have no such
//! provider. What the shared corpus would have carried is here instead,
//! plus the one thing it could not carry either way: a file written by
//! this port and read by another, pinned by test/fixture/*.skmv.
//!
//! It names no omni, so it builds and runs with no omni checkout at all -
//! unlike run.zig, which is the conformance runner.
//!
//! A port of typescript/test/minivault.test.ts.

const std = @import("std");

const sekreto = @import("sekreto");
// ROOTED AT plugins/minivault.zig, not at plugins/all.zig. That is the
// lean-consumer path the README describes - zig analyses only what a
// root reaches, so this binary carries the mini vault and nothing else,
// no HTTP client and no request signer - and running the suite that way
// is what keeps the path honest.
const mv = @import("sekretoplugins");

const Allocator = std.mem.Allocator;
const ProviderSpec = sekreto.ProviderSpec;
const Sekreto = sekreto.Sekreto;

const MASTER = "master-passphrase";

/// The rounds every test here uses. The library default is 210000, which
/// is the point of PBKDF2 and the wrong thing to pay per assertion.
const ROUNDS: u32 = 1000;

// Zig has no closures, so a test is a bare function pointer and what it
// needs from the run lives here. One process, one arena.
var ALLOC: Allocator = undefined;
var CONFIG: sekreto.Config = undefined;
var WORK: []const u8 = undefined;
var ONLY: ?[]const u8 = null;
var PASSCOUNT: usize = 0;
var FAILCOUNT: usize = 0;
var COUNT: usize = 0;

const Failure = error{Refused};

fn say(comptime format: []const u8, args: anytype) []const u8 {
    return std.fmt.allocPrint(ALLOC, format, args) catch "out of memory";
}

fn same(want: []const u8, got: []const u8, what: []const u8) !void {
    if (!std.mem.eql(u8, want, got)) {
        LAST = say("{s}:\n  want: {s}\n  got:  {s}", .{ what, want, got });
        return error.Refused;
    }
}

fn is(want: bool, got: bool, what: []const u8) !void {
    if (want != got) {
        LAST = say("{s}: want {}, got {}", .{ what, want, got });
        return error.Refused;
    }
}

fn holds(got: []const u8, want: []const u8, what: []const u8) !void {
    if (null == std.mem.indexOf(u8, got, want)) {
        LAST = say("{s}:\n  want to contain: {s}\n  got: {s}", .{ what, want, got });
        return error.Refused;
    }
}

/// The message of the last refusal, since a zig error carries no payload.
var LAST: []const u8 = "";

fn raise(message: []const u8) Failure {
    LAST = message;
    return error.Refused;
}

fn joined(list: []const []const u8) []const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (list, 0..) |item, at| {
        if (0 != at) {
            out.append(ALLOC, ' ') catch return "out of memory";
        }
        out.appendSlice(ALLOC, item) catch return "out of memory";
    }
    return out.items;
}

// --- the vault under test ---------------------------------------------

fn vaultpath() []const u8 {
    COUNT += 1;
    return say("{s}/vault{d}.skmv", .{ WORK, COUNT });
}

/// The value, or the refusal turned into one.
fn ok(comptime T: type, answer: sekreto.Answer(T)) !T {
    return switch (answer) {
        .err => |message| raise(message),
        .ok => |given| given,
    };
}

/// The message a refusal refused with, or a failure if it did not refuse.
fn refused(comptime T: type, answer: sekreto.Answer(T)) ![]const u8 {
    return switch (answer) {
        .err => |message| message,
        .ok => raise("nothing refused"),
    };
}

fn fresh() !*mv.Vault {
    return ok(*mv.Vault, try mv.createvault(ALLOC, CONFIG.io, .{
        .file = vaultpath(),
        .passphrase = MASTER,
        .iterations = ROUNDS,
    }));
}

fn openas(file: []const u8, key: []const u8, phrase: []const u8) !*mv.Vault {
    return ok(*mv.Vault, try mv.openvault(ALLOC, CONFIG.io, .{
        .file = file,
        .key = key,
        .passphrase = phrase,
        .iterations = ROUNDS,
    }));
}

fn value(vault: *mv.Vault, name: []const u8) !?[]const u8 {
    return ok(?[]const u8, try vault.get(ALLOC, name));
}

/// Where the committed vaults live, found by walking up.
fn fixturedir() ![]const u8 {
    var dir: []const u8 = ".";

    var step: usize = 0;
    while (step < 8) : (step += 1) {
        const cand = say("{s}/test/fixture", .{dir});
        const probe = say("{s}/minivault.skmv", .{cand});
        std.Io.Dir.cwd().access(CONFIG.io, probe, .{}) catch {
            dir = say("{s}/..", .{dir});
            continue;
        };
        return cand;
    }

    return raise("sekreto: fixture directory not found");
}

/// EVERY committed vault, read off disk rather than listed here. A
/// hard-coded list is one more place to edit when a port lands, and the
/// edit that gets forgotten is the one that makes this suite stop
/// checking the port that just arrived.
fn fixtures() ![]const []const u8 {
    const where = try fixturedir();

    var dir = std.Io.Dir.cwd().openDir(CONFIG.io, where, .{ .iterate = true }) catch {
        return raise("sekreto: fixture directory not readable");
    };
    defer dir.close(CONFIG.io);

    var out: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();

    while (it.next(CONFIG.io) catch null) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".skmv")) {
            try out.append(ALLOC, try ALLOC.dupe(u8, entry.name));
        }
    }

    std.mem.sort([]const u8, out.items, {}, lessStr);

    return out.items;
}

fn lessStr(_: void, left: []const u8, right: []const u8) bool {
    return .lt == std.mem.order(u8, left, right);
}

/// A committed vault, copied so that a test which writes cannot edit the
/// bytes the format contract is made of.
fn fixture(name: []const u8) ![]const u8 {
    const from = say("{s}/{s}", .{ try fixturedir(), name });
    const mine = vaultpath();

    const raw = std.Io.Dir.cwd().readFileAlloc(CONFIG.io, from, ALLOC, .unlimited) catch {
        return raise(say("sekreto: cannot read {s}", .{from}));
    };

    std.Io.Dir.cwd().writeFile(CONFIG.io, .{ .sub_path = mine, .data = raw }) catch {
        return raise(say("sekreto: cannot write {s}", .{mine}));
    };

    return mine;
}

fn thechain(providers: []const ProviderSpec) !*Sekreto {
    return ok(*Sekreto, try Sekreto.init(ALLOC, CONFIG, .{
        .providers = providers,
        .plugins = &.{mv.minivault},
        .cache = false,
    }));
}

// --- the file ---------------------------------------------------------

fn anewvaultholdsnothing() !void {
    const vault = try fresh();
    defer vault.deinit();

    try same("", joined(try ok([]const []const u8, try vault.list(ALLOC))), "list");
    try same("master", vault.vaultkey(), "key");

    const info = try ok(mv.KeyInfo, try vault.open(ALLOC));
    try is(true, info.master, "master");
    try is(true, info.write, "write");
    try same("", joined(info.grants), "grants");
}

fn awrittensecretcomesback() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.set(ALLOC, "db.pass", "hunter2"));

    try same("tok01", (try value(vault, "api.token")).?, "get");
    try same("api.token db.pass", joined(try ok([]const []const u8, try vault.list(ALLOC))), "list");
    try is(true, try ok(bool, try vault.has(ALLOC, "api.token")), "has");
    try is(false, try ok(bool, try vault.has(ALLOC, "nope")), "has nope");

    if (null != try value(vault, "nope")) {
        return raise("an unknown name answered");
    }

    // A SECOND HANDLE on the same file, so the assertion is about the
    // bytes rather than about what this handle happens to remember.
    const again = try openas(vault.vaultfile(), "", MASTER);
    defer again.deinit();
    try same("tok01", (try value(again, "api.token")).?, "a new handle");
}

fn thefileisbinary() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));

    const raw = std.Io.Dir.cwd().readFileAlloc(CONFIG.io, vault.vaultfile(), ALLOC, .unlimited) catch {
        return raise("cannot read the vault back");
    };

    try same("SKMV", raw[0..4], "magic");

    // NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
    // the secret's name and its value are not, and neither is the
    // passphrase that unwrapped them.
    for ([_][]const u8{ "api.token", "tok01", MASTER }) |secret| {
        if (null != std.mem.indexOf(u8, raw, secret)) {
            return raise(say("{s} is in the file", .{secret}));
        }
    }

    if (null == std.mem.indexOf(u8, raw, "master")) {
        return raise("the key id is not in the file");
    }
}

fn rewritinganamereplacesit() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "first"));
    _ = try ok(void, try vault.set(ALLOC, "api.token", "second"));

    try same("second", (try value(vault, "api.token")).?, "get");
    try same("api.token", joined(try ok([]const []const u8, try vault.list(ALLOC))), "one entry");
}

fn removedropsaname() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.set(ALLOC, "db.pass", "hunter2"));
    _ = try ok(void, try vault.remove(ALLOC, "api.token"));

    try same("db.pass", joined(try ok([]const []const u8, try vault.list(ALLOC))), "list");
    if (null != try value(vault, "api.token")) {
        return raise("a removed name answered");
    }

    try holds(try refused(void, try vault.remove(ALLOC, "api.token")), "no such secret: api.token", "remove again");
}

fn abadnameisrefused() !void {
    const vault = try fresh();
    defer vault.deinit();

    try holds(try refused(void, try vault.set(ALLOC, "API.TOKEN", "x")), "invalid name", "set");
    try holds(try refused(?[]const u8, try vault.get(ALLOC, "api..token")), "invalid name", "get");
    try holds(try refused(void, try vault.remove(ALLOC, "")), "invalid name", "remove");
}

// --- keys -------------------------------------------------------------

fn arestrictedkeyreadsitsgrants() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.set(ALLOC, "db.pass", "hunter2"));

    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();

    try same("tok01", (try value(ci, "api.token")).?, "granted");

    // THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and
    // this key cannot derive its key, so the answer is the one a stranger
    // gets: a miss.
    if (null != try value(ci, "db.pass")) {
        return raise("an ungranted name answered");
    }

    try same("api.token", joined(try ok([]const []const u8, try ci.list(ALLOC))), "list");

    const info = try ok(mv.KeyInfo, try ci.open(ALLOC));
    try is(false, info.master, "master");
    try is(false, info.write, "write");
    try same("api.token", joined(info.grants), "grants");
}

fn areadonlykeyrefusestowrite() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));

    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "reader",
        .passphrase = "reader-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "writer",
        .passphrase = "writer-passphrase",
        .names = &.{"api.token"},
        .write = true,
        .iterations = ROUNDS,
    }));

    const reader = try openas(vault.vaultfile(), "reader", "reader-passphrase");
    defer reader.deinit();
    try holds(try refused(void, try reader.set(ALLOC, "api.token", "x")), "key reader is read-only", "read-only");

    const writer = try openas(vault.vaultfile(), "writer", "writer-passphrase");
    defer writer.deinit();
    _ = try ok(void, try writer.set(ALLOC, "api.token", "rewritten"));

    try same("rewritten", (try value(vault, "api.token")).?, "the master sees it");
}

fn arestrictedkeycannotwriteanungrantedname() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .write = true,
        .iterations = ROUNDS,
    }));

    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();

    try holds(
        try refused(void, try ci.set(ALLOC, "db.pass", "x")),
        "key ci was not granted db.pass",
        "ungranted",
    );
}

fn agrantednamethatdoesnotexistyet() !void {
    const vault = try fresh();
    defer vault.deinit();

    // Granted BEFORE the name exists, which is the point: a deploy key is
    // minted from a list of what a service will need.
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();

    try same("", joined(try ok([]const []const u8, try ci.list(ALLOC))), "nothing yet");
    if (null != try value(ci, "api.token")) {
        return raise("a name that does not exist answered");
    }

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));

    try same("tok01", (try value(ci, "api.token")).?, "once written");
    try same("api.token", joined(try ok([]const []const u8, try ci.list(ALLOC))), "list");
}

fn themasterlistseverykey() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{ "db.pass", "api.token" },
        .write = true,
        .iterations = ROUNDS,
    }));

    const keys = try ok([]const mv.KeyInfo, try vault.keys(ALLOC));
    if (2 != keys.len) {
        return raise(say("want 2 keys, got {d}", .{keys.len}));
    }

    try same("master", keys[0].key, "the master");
    try is(true, keys[0].master, "master is master");
    try same("", joined(keys[0].grants), "a master is granted nothing");

    try same("ci", keys[1].key, "the restricted key");
    try is(false, keys[1].master, "ci is not master");
    try is(true, keys[1].write, "ci may write");
    // SORTED, so the record reads the same however the grant was spelled.
    try same("api.token db.pass", joined(keys[1].grants), "grants");
}

fn themasteronlymethodsrefusearestrictedkey() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .write = true,
        .iterations = ROUNDS,
    }));

    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();

    try holds(try refused([]const mv.KeyInfo, try ci.keys(ALLOC)), "listing the keys needs a master key", "keys");
    try holds(try refused(void, try ci.grant(ALLOC, .{ .key = "x", .passphrase = "y" })), "granting a key needs a master key", "grant");
    try holds(try refused(void, try ci.revoke(ALLOC, "master")), "revoking a key needs a master key", "revoke");
    try holds(try refused(void, try ci.rotate(ALLOC)), "rotating the vault needs a master key", "rotate");
    try holds(try refused(void, try ci.remove(ALLOC, "api.token")), "removing a secret needs a master key", "remove");
}

fn arepeatedkeyidisrefused() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.grant(ALLOC, .{ .key = "ci", .passphrase = "p", .iterations = ROUNDS }));

    try holds(
        try refused(void, try vault.grant(ALLOC, .{ .key = "ci", .passphrase = "q", .iterations = ROUNDS })),
        "key already exists: ci",
        "repeated",
    );
    try holds(
        try refused(void, try vault.grant(ALLOC, .{ .key = "", .passphrase = "p" })),
        "a grant needs a key id",
        "no id",
    );
    try holds(
        try refused(void, try vault.grant(ALLOC, .{ .key = "x", .passphrase = "" })),
        "a grant needs a passphrase",
        "no passphrase",
    );
}

fn revokedropsakey() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    _ = try ok(void, try vault.revoke(ALLOC, "ci"));

    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();
    try holds(try refused(?[]const u8, try ci.get(ALLOC, "api.token")), "no such key: ci", "revoked");

    try holds(try refused(void, try vault.revoke(ALLOC, "ci")), "no such key: ci", "revoke again");
    try holds(try refused(void, try vault.revoke(ALLOC, "master")), "a key cannot revoke itself", "itself");

    // THE SECRET IS UNTOUCHED: revoking bars a key, not a value.
    try same("tok01", (try value(vault, "api.token")).?, "the secret stays");
}

fn rotatekeepsthesecrets() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.set(ALLOC, "db.pass", "hunter2"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    _ = try ok(void, try vault.rotate(ALLOC));

    try same("tok01", (try value(vault, "api.token")).?, "api.token survives");
    try same("hunter2", (try value(vault, "db.pass")).?, "db.pass survives");
    try same("api.token db.pass", joined(try ok([]const []const u8, try vault.list(ALLOC))), "list");

    const keys = try ok([]const mv.KeyInfo, try vault.keys(ALLOC));
    if (1 != keys.len) {
        return raise(say("want 1 key after rotate, got {d}", .{keys.len}));
    }
    try same("master", keys[0].key, "the only key");

    // EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
    // rings were sealed under passphrases this process does not have.
    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();
    try holds(try refused(?[]const u8, try ci.get(ALLOC, "api.token")), "no such key: ci", "ci is gone");
}

// --- refusals ---------------------------------------------------------

fn awrongpassphraseandamissingfile() !void {
    const vault = try fresh();
    defer vault.deinit();
    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));

    const wrong = try openas(vault.vaultfile(), "", "not-the-passphrase");
    defer wrong.deinit();
    try holds(
        try refused(?[]const u8, try wrong.get(ALLOC, "api.token")),
        "wrong passphrase for key master, or a damaged vault",
        "wrong passphrase",
    );

    const unknown = try openas(vault.vaultfile(), "nope", MASTER);
    defer unknown.deinit();
    try holds(try refused(?[]const u8, try unknown.get(ALLOC, "api.token")), "no such key: nope", "unknown key");

    const missing = try openas(say("{s}/not-there.skmv", .{WORK}), "", MASTER);
    defer missing.deinit();
    try holds(try refused(?[]const u8, try missing.get(ALLOC, "api.token")), "no vault file", "missing file");
}

fn adamagedfileisrefused() !void {
    const vault = try fresh();
    defer vault.deinit();
    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));

    const raw = std.Io.Dir.cwd().readFileAlloc(CONFIG.io, vault.vaultfile(), ALLOC, .unlimited) catch {
        return raise("cannot read the vault back");
    };

    // Not a vault at all.
    const notone = vaultpath();
    std.Io.Dir.cwd().writeFile(CONFIG.io, .{ .sub_path = notone, .data = "nonsense" }) catch {
        return raise("cannot write");
    };
    const first = try openas(notone, "", MASTER);
    defer first.deinit();
    try holds(try refused(?[]const u8, try first.get(ALLOC, "api.token")), "not a vault file", "not a vault");

    // Cut off part way through.
    const short = vaultpath();
    std.Io.Dir.cwd().writeFile(CONFIG.io, .{ .sub_path = short, .data = raw[0 .. raw.len - 20] }) catch {
        return raise("cannot write");
    };
    const second = try openas(short, "", MASTER);
    defer second.deinit();
    try holds(try refused(?[]const u8, try second.get(ALLOC, "api.token")), "truncated", "truncated");

    // One byte of ciphertext flipped, which the GCM tag catches.
    const bent = try ALLOC.dupe(u8, raw);
    bent[bent.len - 1] ^= 0xff;
    const flipped = vaultpath();
    std.Io.Dir.cwd().writeFile(CONFIG.io, .{ .sub_path = flipped, .data = bent }) catch {
        return raise("cannot write");
    };
    const third = try openas(flipped, "", MASTER);
    defer third.deinit();
    try holds(try refused(?[]const u8, try third.get(ALLOC, "api.token")), "damaged", "flipped");

    // Trailing bytes, which a reader that stopped at the last record
    // would have accepted.
    const extra = try std.mem.concat(ALLOC, u8, &.{ raw, "junk" });
    const longer = vaultpath();
    std.Io.Dir.cwd().writeFile(CONFIG.io, .{ .sub_path = longer, .data = extra }) catch {
        return raise("cannot write");
    };
    const fourth = try openas(longer, "", MASTER);
    defer fourth.deinit();
    try holds(try refused(?[]const u8, try fourth.get(ALLOC, "api.token")), "trailing bytes", "trailing");
}

fn creatingoveranexistingvaultisrefused() !void {
    const vault = try fresh();
    defer vault.deinit();

    try holds(
        try refused(*mv.Vault, try mv.createvault(ALLOC, CONFIG.io, .{
            .file = vault.vaultfile(),
            .passphrase = MASTER,
            .iterations = ROUNDS,
        })),
        "vault file already exists",
        "create over",
    );
}

fn avaultneedsafileandapassphrase() !void {
    try holds(
        try refused(*mv.Vault, try mv.openvault(ALLOC, CONFIG.io, .{ .file = "", .passphrase = "p" })),
        "a vault needs a file",
        "no file",
    );
    try holds(
        try refused(*mv.Vault, try mv.openvault(ALLOC, CONFIG.io, .{ .file = "v.skmv", .passphrase = "" })),
        "a vault needs a passphrase",
        "no passphrase",
    );
}

fn createmakesthefileonlywhenasked() !void {
    const where = vaultpath();

    const off = try openas(where, "", MASTER);
    defer off.deinit();
    try holds(try refused(?[]const u8, try off.get(ALLOC, "api.token")), "no vault file", "create off");

    const on = try ok(*mv.Vault, try mv.openvault(ALLOC, CONFIG.io, .{
        .file = where,
        .passphrase = MASTER,
        .iterations = ROUNDS,
        .create = true,
    }));
    defer on.deinit();

    if (null != try value(on, "api.token")) {
        return raise("a new vault answered");
    }
    _ = try ok(void, try on.set(ALLOC, "api.token", "tok01"));
    try same("tok01", (try value(on, "api.token")).?, "written");

    // The file is there now, so the handle that refused reads it.
    const again = try openas(where, "", MASTER);
    defer again.deinit();
    try same("tok01", (try value(again, "api.token")).?, "the same file");
}

fn akeyidlongerthantheformatallows() !void {
    const vault = try fresh();
    defer vault.deinit();

    const long = try ALLOC.alloc(u8, 300);
    @memset(long, 'k');

    try holds(
        try refused(void, try vault.grant(ALLOC, .{ .key = long, .passphrase = "p", .iterations = ROUNDS })),
        "key id is longer than 255 bytes",
        "grant",
    );
    try holds(
        try refused(*mv.Vault, try mv.openvault(ALLOC, CONFIG.io, .{
            .file = vault.vaultfile(),
            .key = long,
            .passphrase = "p",
        })),
        "key id is longer than 255 bytes",
        "open",
    );

    // AND THE VAULT IS UNHARMED: the refusal came before the write, so a
    // 300-character id did not shift every field after it.
    const keys = try ok([]const mv.KeyInfo, try vault.keys(ALLOC));
    if (1 != keys.len) {
        return raise(say("want 1 key, got {d}", .{keys.len}));
    }
}

fn theinfoacallergetscannotchangewhatthekeymaydo() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "reader",
        .passphrase = "reader-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    const reader = try openas(vault.vaultfile(), "reader", "reader-passphrase");
    defer reader.deinit();

    var info = try ok(mv.KeyInfo, try reader.open(ALLOC));
    try is(false, info.write, "read-only");

    // A VALUE, not a handle on the vault's own record. Flipping the bit
    // edits this copy and nothing the vault reads - which is the defect
    // the review round found in the canonical, and cannot happen here.
    info.write = true;

    try holds(try refused(void, try reader.set(ALLOC, "api.token", "x")), "key reader is read-only", "still refused");
}

fn arevokedkeystopsreading() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    // OPEN AND READING FIRST, so the handle holds its derived keys.
    const ci = try openas(vault.vaultfile(), "ci", "ci-passphrase");
    defer ci.deinit();
    try same("tok01", (try value(ci, "api.token")).?, "before");

    _ = try ok(void, try vault.revoke(ALLOC, "ci"));

    // The live file no longer holds the key, and a handle that answered
    // from memory here would make `revoke` a suggestion.
    try holds(try refused(?[]const u8, try ci.get(ALLOC, "api.token")), "no such key: ci", "after");
}

fn aregrantedkeyid() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "first-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    const ci = try openas(vault.vaultfile(), "ci", "first-passphrase");
    defer ci.deinit();
    try same("tok01", (try value(ci, "api.token")).?, "before");

    _ = try ok(void, try vault.revoke(ALLOC, "ci"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "second-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    // SAME ID, DIFFERENT KEY. The handle re-derives because the sealed
    // ring changed, and the old passphrase does not unwrap the new one.
    try holds(
        try refused(?[]const u8, try ci.get(ALLOC, "api.token")),
        "wrong passphrase for key ci, or a damaged vault",
        "the old passphrase",
    );

    const second = try openas(vault.vaultfile(), "ci", "second-passphrase");
    defer second.deinit();
    try same("tok01", (try value(second, "api.token")).?, "the new passphrase");
}

fn closeforgetsthederivedkeys() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));
    try same("tok01", (try value(vault, "api.token")).?, "before");

    vault.close();

    try same("tok01", (try value(vault, "api.token")).?, "after");
}

// --- the committed files ----------------------------------------------

/// Every port's vault holds the same keys and the same secrets, so the
/// assertions do not vary with which file this is.
fn readsfixture(name: []const u8) !void {
    const file = try fixture(name);

    const master = try openas(file, "", "fixture-master");
    defer master.deinit();

    try same(
        "api.token db.pass deep.nested.name",
        joined(try ok([]const []const u8, try master.list(ALLOC))),
        "list",
    );
    try same("fixture-token", (try value(master, "api.token")).?, "api.token");
    try same("fixture-pass", (try value(master, "db.pass")).?, "db.pass");
    try same("fixture-deep", (try value(master, "deep.nested.name")).?, "deep.nested.name");

    const keys = try ok([]const mv.KeyInfo, try master.keys(ALLOC));
    var ids: std.ArrayList([]const u8) = .empty;
    for (keys) |info| {
        try ids.append(ALLOC, info.key);
    }
    std.mem.sort([]const u8, ids.items, {}, lessStr);
    try same("master reader writer", joined(ids.items), "keys");

    const reader = try openas(file, "reader", "fixture-reader");
    defer reader.deinit();
    try same("api.token", joined(try ok([]const []const u8, try reader.list(ALLOC))), "reader list");
    try same("fixture-token", (try value(reader, "api.token")).?, "reader reads");
    if (null != try value(reader, "db.pass")) {
        return raise("the reader key read db.pass");
    }
    try holds(try refused(void, try reader.set(ALLOC, "api.token", "x")), "read-only", "reader writes");

    const writer = try openas(file, "writer", "fixture-writer");
    defer writer.deinit();
    try same("db.pass", joined(try ok([]const []const u8, try writer.list(ALLOC))), "writer list");
    try same("fixture-pass", (try value(writer, "db.pass")).?, "writer reads");

    // The copy is this test's own, so writing it proves the round trip
    // without touching the committed bytes.
    _ = try ok(void, try writer.set(ALLOC, "db.pass", "rewritten"));
    try same("rewritten", (try value(master, "db.pass")).?, "the master sees it");
}

// --- the chain --------------------------------------------------------

fn avaultisonestoreinachain() !void {
    const vault = try fresh();
    defer vault.deinit();
    _ = try ok(void, try vault.set(ALLOC, "api.token", "from the vault"));

    const secrets = try thechain(&.{
        .{ .kind = "minivault", .file = vault.vaultfile(), .passphrase = MASTER },
        .{ .kind = "memory", .values = &.{.{ .key = "DB_PASS", .value = "from memory" }} },
    });
    defer secrets.deinit();

    try same("minivault memory", joined(try secrets.stores(ALLOC)), "stores");
    try same(
        say("minivault:{s} memory", .{vault.vaultfile()}),
        joined(try secrets.sources(ALLOC)),
        "sources",
    );
    try same("from the vault", try ok([]const u8, try secrets.get("api.token")), "the vault");
    try same("from memory", try ok([]const u8, try secrets.get("db.pass")), "memory");
}

fn arestrictedkeyinachainfallsthrough() !void {
    const vault = try fresh();
    defer vault.deinit();

    _ = try ok(void, try vault.set(ALLOC, "api.token", "from the vault"));
    _ = try ok(void, try vault.set(ALLOC, "db.pass", "also in the vault"));
    _ = try ok(void, try vault.grant(ALLOC, .{
        .key = "ci",
        .passphrase = "ci-passphrase",
        .names = &.{"api.token"},
        .iterations = ROUNDS,
    }));

    const secrets = try thechain(&.{
        .{ .kind = "minivault", .file = vault.vaultfile(), .vaultkey = "ci", .passphrase = "ci-passphrase" },
        .{ .kind = "memory", .values = &.{.{ .key = "DB_PASS", .value = "from memory" }} },
    });
    defer secrets.deinit();

    try same("from the vault", try ok([]const u8, try secrets.get("api.token")), "the grant");
    // A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
    // than stopping at a store that holds the name but not for this key.
    try same("from memory", try ok([]const u8, try secrets.get("db.pass")), "falls through");
}

fn thevaultbehindastoreisreachable() !void {
    const vault = try fresh();
    defer vault.deinit();
    _ = try ok(void, try vault.set(ALLOC, "api.token", "tok01"));

    const secrets = try thechain(&.{
        .{ .kind = "minivault", .file = vault.vaultfile(), .passphrase = MASTER },
    });
    defer secrets.deinit();

    const api = try ok(*mv.Vault, try mv.vaultof(ALLOC, secrets, ""));
    try same("api.token", joined(try ok([]const []const u8, try api.list(ALLOC))), "list");

    // A CHAIN READS; the API writes. Both see the same file.
    _ = try ok(void, try api.set(ALLOC, "db.pass", "written through the api"));
    try same("written through the api", try ok([]const u8, try secrets.get("db.pass")), "the chain");
}

fn anamedstoreisreachedbyname() !void {
    const first = try fresh();
    defer first.deinit();
    _ = try ok(void, try first.set(ALLOC, "api.token", "first"));

    const second = try fresh();
    defer second.deinit();
    _ = try ok(void, try second.set(ALLOC, "api.token", "second"));

    const secrets = try thechain(&.{
        .{ .kind = "minivault", .name = "app", .file = first.vaultfile(), .passphrase = MASTER },
        .{ .kind = "minivault", .name = "ops", .file = second.vaultfile(), .passphrase = MASTER },
    });
    defer secrets.deinit();

    try same("app ops", joined(try secrets.stores(ALLOC)), "stores");

    const app = try ok(*mv.Vault, try mv.vaultof(ALLOC, secrets, "app"));
    try same(first.vaultfile(), app.vaultfile(), "app");

    const ops = try ok(*mv.Vault, try mv.vaultof(ALLOC, secrets, "ops"));
    try same(second.vaultfile(), ops.vaultfile(), "ops");

    // TWO VAULTS, SO THE ALIAS CANNOT ANSWER: picking one would be a
    // guess, and the guess writes.
    try holds(
        try refused(*mv.Vault, try mv.vaultof(ALLOC, secrets, "nope")),
        "no minivault store named nope in this chain",
        "a store that is not there",
    );
}

fn achainwithnovaultsaysso() !void {
    const secrets = try thechain(&.{
        .{ .kind = "memory", .values = &.{.{ .key = "API_TOKEN", .value = "tok01" }} },
    });
    defer secrets.deinit();

    try holds(
        try refused(*mv.Vault, try mv.vaultof(ALLOC, secrets, "")),
        "no minivault store in this chain",
        "no vault",
    );
}

fn achainmissingthefileisrefused() !void {
    try holds(
        try refused(*Sekreto, try Sekreto.init(ALLOC, CONFIG, .{
            .providers = &.{.{ .kind = "minivault", .passphrase = "p" }},
            .plugins = &.{mv.minivault},
        })),
        "a vault needs a file",
        "no file",
    );
    try holds(
        try refused(*Sekreto, try Sekreto.init(ALLOC, CONFIG, .{
            .providers = &.{.{ .kind = "minivault", .file = "v.skmv" }},
            .plugins = &.{mv.minivault},
        })),
        "a vault needs a passphrase",
        "no passphrase",
    );
}

fn thefileisreachedatthefirstlookup() !void {
    // The file does not exist, and building the chain still succeeds:
    // the handle is lazy, so a chain costs no PBKDF2 until a secret is
    // actually wanted.
    const secrets = try thechain(&.{
        .{ .kind = "minivault", .file = say("{s}/never.skmv", .{WORK}), .passphrase = MASTER },
    });
    defer secrets.deinit();

    try holds(try refused([]const u8, try secrets.get("api.token")), "no vault file", "at the first lookup");
}

// --- the spec across the plugin boundary ------------------------------

/// Every ProviderSpec field survives `optionsof` and `specof`.
///
/// The two are written out field by field, so a field added to one and
/// forgotten in the other would be lost in silence - and `vaultkey`,
/// `passphrase`, `iterations` and `create` are four that arrived together.
/// Driven by `std.meta.fields` rather than by a list here, so a field
/// added tomorrow is checked without this test being edited.
fn thespecroundtrips() !void {
    var spec = ProviderSpec{ .kind = "minivault" };

    inline for (std.meta.fields(ProviderSpec)) |f| {
        if ([]const u8 == f.type) {
            @field(spec, f.name) = f.name;
        } else if (i64 == f.type) {
            @field(spec, f.name) = 7;
        } else if (bool == f.type) {
            @field(spec, f.name) = true;
        }
    }
    spec.kind = "minivault";
    spec.auth = .{ .method = "kubernetes", .role = "app", .jwt = "j" };
    spec.values = &.{.{ .key = "API_TOKEN", .value = "tok01" }};

    const back = sekreto.provider.specof(sekreto.provider.optionsof(spec));

    inline for (std.meta.fields(ProviderSpec)) |f| {
        const want = @field(spec, f.name);
        const got = @field(back, f.name);

        if ([]const u8 == f.type) {
            try same(want, got, f.name);
        } else if (i64 == f.type) {
            try is(want == got, true, f.name);
        } else if (bool == f.type) {
            try is(want, got, f.name);
        }
    }

    try same("kubernetes", back.auth.?.method, "auth.method");
    try same("j", back.auth.?.jwt.?, "auth.jwt");
    try same("tok01", back.values[0].value, "values");
}

// --- the run ----------------------------------------------------------

const Case = struct { name: []const u8, check: *const fn () anyerror!void };

const CASES = [_]Case{
    .{ .name = "newvault", .check = anewvaultholdsnothing },
    .{ .name = "written", .check = awrittensecretcomesback },
    .{ .name = "binary", .check = thefileisbinary },
    .{ .name = "rewrite", .check = rewritinganamereplacesit },
    .{ .name = "remove", .check = removedropsaname },
    .{ .name = "badname", .check = abadnameisrefused },
    .{ .name = "restricted", .check = arestrictedkeyreadsitsgrants },
    .{ .name = "readonly", .check = areadonlykeyrefusestowrite },
    .{ .name = "ungranted", .check = arestrictedkeycannotwriteanungrantedname },
    .{ .name = "laternamed", .check = agrantednamethatdoesnotexistyet },
    .{ .name = "keys", .check = themasterlistseverykey },
    .{ .name = "masteronly", .check = themasteronlymethodsrefusearestrictedkey },
    .{ .name = "repeatedid", .check = arepeatedkeyidisrefused },
    .{ .name = "revoke", .check = revokedropsakey },
    .{ .name = "rotate", .check = rotatekeepsthesecrets },
    .{ .name = "wrongphrase", .check = awrongpassphraseandamissingfile },
    .{ .name = "damaged", .check = adamagedfileisrefused },
    .{ .name = "createover", .check = creatingoveranexistingvaultisrefused },
    .{ .name = "needsfile", .check = avaultneedsafileandapassphrase },
    .{ .name = "createflag", .check = createmakesthefileonlywhenasked },
    .{ .name = "longkeyid", .check = akeyidlongerthantheformatallows },
    .{ .name = "infocopy", .check = theinfoacallergetscannotchangewhatthekeymaydo },
    .{ .name = "revokedcached", .check = arevokedkeystopsreading },
    .{ .name = "regranted", .check = aregrantedkeyid },
    .{ .name = "close", .check = closeforgetsthederivedkeys },
    .{ .name = "chain", .check = avaultisonestoreinachain },
    .{ .name = "chainfallthrough", .check = arestrictedkeyinachainfallsthrough },
    .{ .name = "api", .check = thevaultbehindastoreisreachable },
    .{ .name = "namedstore", .check = anamedstoreisreachedbyname },
    .{ .name = "novault", .check = achainwithnovaultsaysso },
    .{ .name = "badconfig", .check = achainmissingthefileisrefused },
    .{ .name = "lazy", .check = thefileisreachedatthefirstlookup },
    .{ .name = "roundtrip", .check = thespecroundtrips },
};

fn wanted(name: []const u8) bool {
    const only = ONLY orelse return true;
    return std.mem.eql(u8, only, name);
}

fn run(name: []const u8, check: *const fn () anyerror!void) void {
    if (!wanted(name)) {
        return;
    }

    LAST = "";

    check() catch |err| {
        FAILCOUNT += 1;
        const why = if (0 != LAST.len) LAST else @errorName(err);
        std.debug.print("FAIL - {s}\n  {s}\n", .{ name, why });
        return;
    };

    PASSCOUNT += 1;
    std.debug.print("ok   - {s}\n", .{name});
}

/// The fixture under test, since a case takes no argument.
var FIXTURE: []const u8 = "";

fn readsthefixture() !void {
    return readsfixture(FIXTURE);
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

    var seed: [8]u8 = undefined;
    init.io.random(&seed);
    WORK = try std.fmt.allocPrint(ALLOC, "/tmp/sekreto-minivault-{x}", .{seed});
    try std.Io.Dir.cwd().createDirPath(init.io, WORK);
    defer std.Io.Dir.cwd().deleteTree(init.io, WORK) catch {};

    for (CASES) |case| {
        run(case.name, case.check);
    }

    for (try fixtures()) |name| {
        FIXTURE = name;
        run(try std.fmt.allocPrint(ALLOC, "fixture:{s}", .{name}), readsthefixture);
    }

    std.debug.print("\n{d} passed, {d} failed\n", .{ PASSCOUNT, FAILCOUNT });

    std.process.exit(if (0 == FAILCOUNT) 0 else 1);
}
