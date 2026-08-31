//! sekreto: one interface for secrets, wherever they live.
//!
//! A Sekreto is an ordered chain of providers. `get` asks each in turn and
//! returns the first hit, so an app can be configured from environment
//! variables in development and a vault in production without changing a
//! line of its own code.
//!
//! This is the Zig port. The CANONICAL implementation is
//! ../../typescript/src/Sekreto.ts, and ../../spec/sekreto.json is the
//! behavioural contract every port runs.
//!
//! Zig has no exceptions, and its error values carry no payload, so a
//! failure is RETURNED as a message - the shape voxgig/omni's own Zig port
//! uses. That also keeps the distinction this library cares about most
//! structural rather than conventional:
//!
//!   Answer(?[]const u8){ .ok = "value" }   a hit
//!   Answer(?[]const u8){ .ok = null }      a MISS - the chain carries on
//!   Answer(?[]const u8){ .err = message }  a FAILURE - the chain stops
//!
//! Memory: every function that can allocate takes the allocator first, and
//! what it returns (value or message) comes from that allocator. `Sekreto`
//! owns one allocator for what outlives a lookup (the cache, the redaction
//! list, the last failure message) and runs each lookup inside an arena it
//! resets afterwards, so repeated lookups do not grow the heap.

const std = @import("std");

pub const providers = @import("providers.zig");
pub const sigv4 = @import("sigv4.zig");
pub const http = @import("http.zig");

pub const Provider = providers.Provider;
pub const ProviderSpec = providers.ProviderSpec;
pub const Config = providers.Config;
pub const checkaddr = providers.checkaddr;

const Allocator = std.mem.Allocator;

/// What a fallible call returns: the value, or the message of a failure.
///
/// A provider lookup is `Answer(?[]const u8)`, where `.ok = null` is a miss.
/// A miss and a failure are therefore different cases of different depth,
/// and no caller can confuse one for the other by accident.
pub fn Answer(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: []const u8,
    };
}

/// A secret, or a miss.
pub const Found = Answer(?[]const u8);

/// A secret name: dot-separated lowercase segments, e.g. `api.token`.
pub const Name = []const u8;

/// The message of anything sekreto refuses to do: a bad name, a missing
/// secret, a provider that could not be reached.
pub fn fail(alloc: Allocator, comptime format: []const u8, args: anytype) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(alloc, format, args);
}

/// Is this a well-formed secret name? Dot-separated segments of `[a-z0-9_]`.
pub fn validname(name: Name) bool {
    if (0 == name.len) {
        return false;
    }

    var parts = std.mem.splitScalar(u8, name, '.');

    while (parts.next()) |part| {
        if (0 == part.len) {
            return false;
        }
        for (part) |ch| {
            const ok = ('a' <= ch and 'z' >= ch) or ('0' <= ch and '9' >= ch) or '_' == ch;
            if (!ok) {
                return false;
            }
        }
    }

    return true;
}

/// The name itself, or the message that says why it is not one.
pub fn checkname(alloc: Allocator, name: Name) Allocator.Error!Answer(Name) {
    if (!validname(name)) {
        return .{ .err = try fail(alloc, "sekreto: invalid name: {s}", .{name}) };
    }
    return .{ .ok = name };
}

/// The environment-variable key for a name: `api.token` -> `API_TOKEN`.
pub fn envkey(alloc: Allocator, name: Name, prefix: []const u8) Allocator.Error!Answer([]const u8) {
    switch (try checkname(alloc, name)) {
        .err => |message| return .{ .err = message },
        .ok => {},
    }

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(alloc, prefix);

    for (name) |ch| {
        try out.append(alloc, if ('.' == ch) '_' else std.ascii.toUpper(ch));
    }

    return .{ .ok = out.items };
}

/// Where a name lives in a KV vault: `api.token` -> `api` / `token`.
///
/// A single-segment name has no path of its own, so it becomes a secret of
/// that name with the conventional field `value`.
pub const VaultRef = struct {
    path: []const u8,
    field: []const u8,
};

pub fn vaultref(alloc: Allocator, name: Name) Allocator.Error!Answer(VaultRef) {
    switch (try checkname(alloc, name)) {
        .err => |message| return .{ .err = message },
        .ok => {},
    }

    const cut = std.mem.lastIndexOfScalar(u8, name, '.') orelse {
        return .{ .ok = .{ .path = name, .field = "value" } };
    };

    var path: std.ArrayList(u8) = .empty;
    for (name[0..cut]) |ch| {
        try path.append(alloc, if ('.' == ch) '/' else ch);
    }

    return .{ .ok = .{ .path = path.items, .field = name[cut + 1 ..] } };
}

/// A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
/// Manager, `_`) or `api-token` (Azure Key Vault, `-`).
///
/// Those stores have no path hierarchy and reject dots in ids, so the dots
/// become the store's conventional separator. With `-` as the separator,
/// underscores flatten too: Azure Key Vault's alphabet is letters, digits
/// and hyphens only, and a valid sekreto name like `with_underscore` must
/// still be representable there.
pub fn flatname(alloc: Allocator, name: Name, sep: []const u8) Allocator.Error!Answer([]const u8) {
    switch (try checkname(alloc, name)) {
        .err => |message| return .{ .err = message },
        .ok => {},
    }

    const hyphen = std.mem.eql(u8, "-", sep);

    var out: std.ArrayList(u8) = .empty;
    for (name) |ch| {
        if ('.' == ch) {
            try out.appendSlice(alloc, sep);
        } else if (hyphen and '_' == ch) {
            try out.append(alloc, '-');
        } else {
            try out.append(alloc, ch);
        }
    }

    return .{ .ok = out.items };
}

/// The AWS SSM Parameter Store name for a name: dots become the path
/// hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
/// `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
pub fn awsparam(alloc: Allocator, name: Name, prefix: []const u8) Allocator.Error!Answer([]const u8) {
    switch (try checkname(alloc, name)) {
        .err => |message| return .{ .err = message },
        .ok => {},
    }

    var base = prefix;
    var out: std.ArrayList(u8) = .empty;

    if (0 != base.len and '/' != base[0]) {
        try out.append(alloc, '/');
    }
    if (0 != base.len and '/' == base[base.len - 1]) {
        base = base[0 .. base.len - 1];
    }

    try out.appendSlice(alloc, base);
    try out.append(alloc, '/');

    for (name) |ch| {
        try out.append(alloc, if ('.' == ch) '/' else ch);
    }

    return .{ .ok = out.items };
}

/// A parsed `.env`: raw keys to values, in the order the file gave them.
///
/// An ordered list rather than a hash map, because the spec compares the
/// whole map and a randomised iteration order would make that comparison
/// depend on the run.
pub const Dotenv = struct {
    keys: [][]const u8,
    values: [][]const u8,

    pub fn get(self: Dotenv, key: []const u8) ?[]const u8 {
        for (self.keys, 0..) |candidate, at| {
            if (std.mem.eql(u8, candidate, key)) {
                return self.values[at];
            }
        }
        return null;
    }
};

/// Parse `.env` text into raw keys and values.
///
/// Deliberately small: `KEY=value`, optional `export`, `#` comments on their
/// own line, and single- or double-quoted values (double quotes also
/// unescape `\n`, `\r`, `\t` and `\\`). A line with no `=` is skipped.
pub fn parsedotenv(alloc: Allocator, text: []const u8) Allocator.Error!Dotenv {
    var keys: std.ArrayList([]const u8) = .empty;
    var values: std.ArrayList([]const u8) = .empty;

    var lines = std.mem.splitScalar(u8, text, '\n');

    while (lines.next()) |rawline| {
        var line = rawline;
        if (0 != line.len and '\r' == line[line.len - 1]) {
            line = line[0 .. line.len - 1];
        }
        line = std.mem.trim(u8, line, " \t");

        if (0 == line.len or '#' == line[0]) {
            continue;
        }

        const body = if (std.mem.startsWith(u8, line, "export "))
            std.mem.trim(u8, line[7..], " \t")
        else
            line;

        const eq = std.mem.indexOfScalar(u8, body, '=') orelse continue;
        if (0 == eq) {
            continue;
        }

        const key = std.mem.trim(u8, body[0..eq], " \t");
        var value = std.mem.trim(u8, body[eq + 1 ..], " \t");

        if (2 <= value.len and '"' == value[0] and '"' == value[value.len - 1]) {
            value = try unescape(alloc, value[1 .. value.len - 1]);
        } else if (2 <= value.len and '\'' == value[0] and '\'' == value[value.len - 1]) {
            value = value[1 .. value.len - 1];
        }

        // A repeated key takes the later value, as an assignment does.
        var replaced = false;
        for (keys.items, 0..) |candidate, at| {
            if (std.mem.eql(u8, candidate, key)) {
                values.items[at] = value;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            try keys.append(alloc, key);
            try values.append(alloc, value);
        }
    }

    return .{ .keys = keys.items, .values = values.items };
}

fn unescape(alloc: Allocator, text: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;

    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        if ('\\' == text[index] and index + 1 < text.len) {
            const next = text[index + 1];
            index += 1;
            switch (next) {
                'n' => try out.append(alloc, '\n'),
                'r' => try out.append(alloc, '\r'),
                't' => try out.append(alloc, '\t'),
                '\\' => try out.append(alloc, '\\'),
                '"' => try out.append(alloc, '"'),
                else => {
                    try out.append(alloc, '\\');
                    try out.append(alloc, next);
                },
            }
        } else {
            try out.append(alloc, text[index]);
        }
    }

    return out.items;
}

/// Replace known secret values in text with `[redacted]`.
///
/// Only values of four characters or more are replaced: shorter ones are
/// too likely to appear in ordinary text, and redacting them would make
/// logs unreadable without making them safer.
pub fn redact(alloc: Allocator, text: []const u8, values: []const []const u8) Allocator.Error![]const u8 {
    var out: []const u8 = text;

    // Longest first: a shorter secret that prefixes a longer one used to eat
    // the prefix and leave the rest in the log. Copied first, so the
    // caller's slice is not reordered.
    const usable = try alloc.alloc([]const u8, values.len);
    defer alloc.free(usable);

    var count: usize = 0;
    for (values) |value| {
        if (4 <= value.len) {
            usable[count] = value;
            count += 1;
        }
    }

    const longest = struct {
        fn before(_: void, left: []const u8, right: []const u8) bool {
            return left.len > right.len;
        }
    }.before;
    std.mem.sort([]const u8, usable[0..count], {}, longest);

    for (usable[0..count]) |value| {
        out = try replaceall(alloc, out, value, "[redacted]");
    }

    return out;
}

fn replaceall(
    alloc: Allocator,
    text: []const u8,
    from: []const u8,
    to: []const u8,
) Allocator.Error![]const u8 {
    if (null == std.mem.indexOf(u8, text, from)) {
        return text;
    }

    var out: std.ArrayList(u8) = .empty;
    var rest = text;

    while (std.mem.indexOf(u8, rest, from)) |at| {
        try out.appendSlice(alloc, rest[0..at]);
        try out.appendSlice(alloc, to);
        rest = rest[at + from.len ..];
    }

    try out.appendSlice(alloc, rest);
    return out.items;
}

/// One provider in the chain, under the store name it answers to.
const Entry = struct {
    store: []const u8,
    provider: Provider,
};

/// One resolved value, under the store the CALLER named ("" for a
/// transparent `get`). Kept as a list rather than a map so that the store
/// stays attached, and so redaction order is stable.
///
/// `store` and `name` are copies: they arrive from the caller and must not
/// outlive it. `value` is not - it points at the copy `seen` already owns,
/// so a cached secret is stored once and freed once.
const Cached = struct {
    store: []const u8,
    name: []const u8,
    value: []const u8,
};

/// The store name a provider answers to when its spec does not say.
///
/// `describe()` opens with the provider's kind - `hashicorp:...`,
/// `dotenv:...`, plain `env` - so the kind is the natural default, and a
/// custom provider gets a sensible name without implementing anything extra.
fn storename(alloc: Allocator, provider: Provider, spec: ProviderSpec) Allocator.Error![]const u8 {
    if (0 != spec.name.len) {
        return alloc.dupe(u8, spec.name);
    }

    // describe() may or may not have allocated - `env` and `memory` answer
    // with a literal - so the store name is copied out and the description
    // released through the same allocator that could have made it.
    const described = try provider.describe(alloc);
    defer alloc.free(described);

    const cut = std.mem.indexOfScalar(u8, described, ':') orelse described.len;
    return alloc.dupe(u8, described[0..cut]);
}

/// Free a partly-built chain: the providers made so far, their store names,
/// and the list itself.
fn release(alloc: Allocator, entries: *std.ArrayList(Entry)) void {
    for (entries.items) |entry| {
        entry.provider.deinit(alloc);
        alloc.free(entry.store);
    }
    entries.deinit(alloc);
}

/// The secrets facade: a chain of providers plus a cache.
///
/// Two ways to read. `get` is transparent - it walks the chain and takes the
/// first hit, and the caller never learns which store answered. `getfrom` is
/// directed - it names the store, and only that store is asked. Use the
/// first for ordinary configuration, the second when *which* store holds a
/// secret is part of what you mean.
pub const Sekreto = struct {
    alloc: Allocator,
    entries: []Entry,
    docache: bool,
    cache: std.ArrayList(Cached),
    // Every value ever resolved, for redact(). Kept independently of the
    // read cache so that redaction still works when caching is off -
    // otherwise `cache: false` would silently disable redact() and leak
    // secrets to logs. It also owns every value string the cache points at.
    seen: std.ArrayList([]const u8),
    // Scratch for one lookup: URLs, request bodies, parsed responses. Reset
    // after every lookup, so a long-running process that reads the same
    // secrets over and over does not grow.
    scratch: std.heap.ArenaAllocator,
    // The most recent failure message, owned here so that a caller need not
    // free it and a retry loop cannot accumulate them.
    lasterr: ?[]const u8,

    /// Build a chain from declarative provider specs.
    ///
    /// Heap-allocated, not returned by value: the scratch arena hands out an
    /// allocator that points at its own address, so a Sekreto that moved
    /// after construction would hand every lookup a dangling one.
    ///
    /// A failure here hands back a message the CALLER owns - there is no
    /// Sekreto yet to own it. Once there is one, every message a lookup
    /// returns belongs to the Sekreto and is freed by `deinit`.
    pub fn init(
        alloc: Allocator,
        config: Config,
        specs: []const ProviderSpec,
        docache: bool,
    ) Allocator.Error!Answer(*Sekreto) {
        var entries: std.ArrayList(Entry) = .empty;

        // A chain that cannot be built is not left half-built. `errdefer`
        // covers running out of memory; the `.err` arm covers a spec this
        // library refuses (an unknown kind, an unsupported kv version),
        // which is a returned value rather than a Zig error and so is not
        // an errdefer's business.
        errdefer release(alloc, &entries);

        for (specs) |spec| {
            const provider = switch (try providers.makeprovider(alloc, config, spec)) {
                .err => |message| {
                    release(alloc, &entries);
                    return .{ .err = message };
                },
                .ok => |made| made,
            };
            try entries.append(alloc, .{
                .store = try storename(alloc, provider, spec),
                .provider = provider,
            });
        }

        const self = try alloc.create(Sekreto);
        self.* = .{
            .alloc = alloc,
            .entries = try entries.toOwnedSlice(alloc),
            .docache = docache,
            .cache = .empty,
            .seen = .empty,
            .scratch = std.heap.ArenaAllocator.init(alloc),
            .lasterr = null,
        };

        return .{ .ok = self };
    }

    pub fn deinit(self: *Sekreto) void {
        for (self.entries) |entry| {
            entry.provider.deinit(self.alloc);
            self.alloc.free(entry.store);
        }
        self.alloc.free(self.entries);

        for (self.seen.items) |value| {
            self.alloc.free(value);
        }
        self.seen.deinit(self.alloc);

        for (self.cache.items) |entry| {
            self.alloc.free(entry.store);
            self.alloc.free(entry.name);
        }
        self.cache.deinit(self.alloc);

        if (self.lasterr) |message| {
            self.alloc.free(message);
        }

        self.scratch.deinit();
        self.alloc.destroy(self);
    }

    /// The secret, or a failure if no provider has it.
    pub fn get(self: *Sekreto, name: Name) Allocator.Error!Answer([]const u8) {
        switch (try self.trysecret(name)) {
            .err => |message| return .{ .err = message },
            .ok => |found| {
                const value = found orelse
                    return .{ .err = try self.keep("sekreto: unknown secret: {s}", .{name}) };
                return .{ .ok = value };
            },
        }
    }

    /// The secret, or null if no provider has it.
    ///
    /// Named `trysecret` because `try` is a Zig keyword; every port names
    /// this the closest thing its language allows.
    pub fn trysecret(self: *Sekreto, name: Name) Allocator.Error!Found {
        return self.resolve("", name, self.entries);
    }

    /// The secret from one named store, or a failure if that store does not
    /// have it.
    pub fn getfrom(self: *Sekreto, store: []const u8, name: Name) Allocator.Error!Answer([]const u8) {
        switch (try self.tryfrom(store, name)) {
            .err => |message| return .{ .err = message },
            .ok => |found| {
                const value = found orelse return .{
                    .err = try self.keep("sekreto: unknown secret: {s}:{s}", .{ store, name }),
                };
                return .{ .ok = value };
            },
        }
    }

    /// The secret from one named store, or null if that store does not have
    /// it.
    ///
    /// Naming a store that is not in the chain is an error, not a miss:
    /// `try` already means "this store may not have it", so it cannot also
    /// mean "this store may not exist" without hiding a typo.
    pub fn tryfrom(self: *Sekreto, store: []const u8, name: Name) Allocator.Error!Found {
        var matching: std.ArrayList(Entry) = .empty;
        defer matching.deinit(self.alloc);

        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.store, store)) {
                try matching.append(self.alloc, entry);
            }
        }

        if (0 == matching.items.len) {
            return .{ .err = try self.keep("sekreto: unknown store: {s}", .{store}) };
        }

        return self.resolve(store, name, matching.items);
    }

    fn resolve(self: *Sekreto, store: []const u8, name: Name, entries: []const Entry) Allocator.Error!Found {
        const work = self.scratch.allocator();
        // The scratch arena holds only what this lookup needs; anything that
        // outlives it is copied into self.alloc before the reset.
        defer _ = self.scratch.reset(.retain_capacity);

        switch (try checkname(work, name)) {
            .err => |message| return .{ .err = try self.keepraw(message) },
            .ok => {},
        }

        if (self.docache) {
            for (self.cache.items) |entry| {
                if (std.mem.eql(u8, entry.store, store) and std.mem.eql(u8, entry.name, name)) {
                    return .{ .ok = entry.value };
                }
            }
        }

        for (entries) |entry| {
            switch (try entry.provider.lookup(work, name)) {
                .err => |message| return .{ .err = try self.keepraw(message) },
                .ok => |found| {
                    const value = found orelse continue;

                    // `seen` owns every resolved value; the cache points at
                    // the same bytes, so nothing is stored twice or freed
                    // twice.
                    const kept = try self.alloc.dupe(u8, value);
                    try self.seen.append(self.alloc, kept);

                    if (self.docache) {
                        // Keyed by the store the CALLER named - the empty
                        // string for a transparent `get` - not by whichever
                        // provider answered. A transparent read and a
                        // directed one are different questions, and a cache
                        // keyed by the answering provider would never
                        // satisfy the first of them.
                        try self.cache.append(self.alloc, .{
                            .store = try self.alloc.dupe(u8, store),
                            .name = try self.alloc.dupe(u8, name),
                            .value = kept,
                        });
                    }

                    return .{ .ok = kept };
                },
            }
        }

        return .{ .ok = null };
    }

    /// Does any provider have this secret?
    pub fn has(self: *Sekreto, name: Name) Allocator.Error!Answer(bool) {
        switch (try self.trysecret(name)) {
            .err => |message| return .{ .err = message },
            .ok => |found| return .{ .ok = null != found },
        }
    }

    /// Does this named store have this secret?
    pub fn hasin(self: *Sekreto, store: []const u8, name: Name) Allocator.Error!Answer(bool) {
        switch (try self.tryfrom(store, name)) {
            .err => |message| return .{ .err = message },
            .ok => |found| return .{ .ok = null != found },
        }
    }

    /// Every named secret at once. Missing ones are a failure.
    ///
    /// The values are the Sekreto's own; the returned list comes from
    /// `alloc`.
    pub fn all(
        self: *Sekreto,
        alloc: Allocator,
        names: []const Name,
    ) Allocator.Error!Answer([]const []const u8) {
        var out: std.ArrayList([]const u8) = .empty;

        for (names) |name| {
            switch (try self.get(name)) {
                .err => |message| return .{ .err = message },
                .ok => |value| try out.append(alloc, value),
            }
        }

        return .{ .ok = out.items };
    }

    /// A description of each provider, in resolution order.
    pub fn sources(self: *const Sekreto, alloc: Allocator) Allocator.Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;

        for (self.entries) |entry| {
            try out.append(alloc, try entry.provider.describe(alloc));
        }

        return out.items;
    }

    /// The name of each store that can be named by `getfrom`, in resolution
    /// order and without repeats.
    pub fn stores(self: *const Sekreto, alloc: Allocator) Allocator.Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;

        for (self.entries) |entry| {
            var seen = false;
            for (out.items) |candidate| {
                if (std.mem.eql(u8, candidate, entry.store)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                try out.append(alloc, entry.store);
            }
        }

        return out.items;
    }

    /// Replace every value this Sekreto has resolved with `[redacted]`.
    ///
    /// Works whether or not caching is enabled: the redaction list is kept
    /// independently of the read cache.
    pub fn redactText(
        self: *const Sekreto,
        alloc: Allocator,
        text: []const u8,
    ) Allocator.Error![]const u8 {
        return redact(alloc, text, self.seen.items);
    }

    /// Drop cached values, so the next `get` asks the providers again.
    pub fn refresh(self: *Sekreto) void {
        for (self.cache.items) |entry| {
            self.alloc.free(entry.store);
            self.alloc.free(entry.name);
        }
        self.cache.clearRetainingCapacity();
    }

    // One failure message, owned by the Sekreto so that a caller never has
    // to free it and a retry loop cannot pile them up.
    fn keep(self: *Sekreto, comptime format: []const u8, args: anytype) Allocator.Error![]const u8 {
        if (self.lasterr) |old| {
            self.alloc.free(old);
            self.lasterr = null;
        }

        const message = try std.fmt.allocPrint(self.alloc, format, args);
        self.lasterr = message;
        return message;
    }

    // The same, for a message built in the scratch arena: it must be copied
    // out before the arena is reset.
    fn keepraw(self: *Sekreto, message: []const u8) Allocator.Error![]const u8 {
        return self.keep("{s}", .{message});
    }
};
