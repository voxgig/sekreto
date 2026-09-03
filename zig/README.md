# sekreto — Zig

The Zig port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, and the plugin seam
```

Built and tested on **Zig 0.16.0**.

Zig has no exceptions, and its error values carry no payload, so where the
canonical port throws, this one **returns** the message:

```zig
pub fn Answer(comptime T: type) type {
    return union(enum) { ok: T, err: []const u8 };
}
```

A provider lookup is `Answer(?[]const u8)`. That makes the distinction the
library cares about most a matter of *shape* rather than convention:

| | |
|---|---|
| `.ok = "value"` | a hit |
| `.ok = null` | a **miss** — this store does not hold it, the chain carries on |
| `.err = message` | a **failure** — this store could not answer, and nothing falls through |

A caller cannot reach the value without naming which of the three it got,
so no chain can silently drop to a weaker store.

## Built in, or a plugin

The `sekreto` module carries the chain and the four kinds that read at
most a local file: `env`, `memory`, `dotenv`, `file`. It reaches no HTTP
client, no crypto and no child process. Every other kind is a plugin
under `plugins/`, a [voxgig/plugin](https://github.com/voxgig/plugin)
definition the calling project passes in — and a plugin a build does not
name is not compiled, because zig analyses only what a root reaches:

```zig
const sekreto = @import("sekreto");
const plugins = @import("sekretoplugins");

var secrets = switch (try sekreto.Sekreto.init(alloc, config, .{
    .plugins = &.{ plugins.hashicorp, plugins.awssecrets },
    .providers = &.{
        .{ .kind = "env" },
        .{ .kind = "dotenv", .file = ".env" },
        .{ .kind = "hashicorp", .name = "prod", .addr = addr, .token = token },
    },
})) {
    .err => |message| return fail(message),
    .ok => |made| made,
};
defer secrets.deinit();

// The plugin host reads like the chain:
// sekreto.plugin.host.list(secrets.host) -> { dotenv: "live", env: "live", "hashicorp$prod": "live" }
```

`sekretoplugins` is whatever the build roots it at: `plugins/all.zig`
for the full set (`plugins.ALL` — the CLI and the suite), or one plugin
file — `-Msekretoplugins=plugins/hashicorp.zig` compiles hashicorp and
the shared `httpjson.zig` and nothing else. Either way `plugins.hashicorp`
is the definition.

| | | |
|---|---|---|
| the core | module `sekreto`, rooted at `src/sekreto.zig` | `Sekreto`, `Options`, the name helpers, the four built-ins, `providerplugin`, `provide`, `checkaddr` |
| one plugin | module `sekretoplugins`, rooted at `plugins/<kind>.zig` | the definition, named as the kind (`aws.zig` has `awssecrets` and `awsparams`) |
| every plugin | module `sekretoplugins`, rooted at `plugins/all.zig` | `ALL`, plus `httpjson` and `sigv4` for whoever writes a plugin |
| the dependency | module `plugin`, rooted at `<checkout>/zig/src/plugin.zig` | voxgig/plugin's zig port; `sekreto.plugin` re-exports it |

A kind that was not passed in is refused by name, with the plugin to pass.
A custom store is one comptime call, `sekreto.providerplugin(kind, make)`,
where `make` answers `sekreto.provide(alloc, MyStore, .{ ... })` or the
message of its refusal. See [DOCS.md](../DOCS.md#plugins).

**The core cannot reach the plugins even by mistake.** A zig module's
imports are confined to its root's directory; `src/` is the `sekreto`
module's root and `plugins/` is outside it, so `@import("../plugins/…")`
is a compile error. What the compiler cannot see — an HTTP client, a
hash, a child process — `make check-core` greps for, and `make test`
runs it first.

## One dependency, and how it arrives

voxgig/plugin's zig port is the dependency, and the library needs it,
not only the tests. Zig has no package registry, so it is a **checkout**,
found the way every port here finds omni — `$PLUGIN_HOME`, then a sibling
`plugin`, then the `../.plugin` that `make deps` fetches when nothing
else is there — and named on the command line as the module `plugin`.
The whole module graph, for every binary the Makefile builds:

```sh
zig build-exe -femit-bin=build/sekreto-cli \
  --dep sekreto --dep sekretoplugins -Mroot=cli/sekreto-cli.zig \
  --dep plugin -Msekreto=src/sekreto.zig \
  --dep sekreto --dep plugin -Msekretoplugins=plugins/all.zig \
  -Mplugin=$PLUGIN/zig/src/plugin.zig
```

plugin's zig port was written for zig 0.13 and its own CI still runs
there; it now builds on 0.16 as well, through one comptime switch on the
compiler version, which is what lets this port compile it. Its
`zig/src/plugin.zig` is the consumer root: a host reaches `host`,
`value`, `types`, `catalog` and `ref` through that one file, because
three module roots in one directory is something zig refuses.

Everything else is std, TLS included — unlike the Rust port, no
dependency exception is required:

| | |
|---|---|
| HTTP and HTTPS | `std.http.Client`, with real TLS from `std.crypto.tls` — in `plugins/httpjson.zig`, never in the core |
| trust roots | `std.crypto.Certificate.Bundle`, scanned from the system store |
| JSON | `std.json` for parsing (responses are written by hand — they are flat maps of strings) |
| SigV4 | `std.crypto.hash.sha2.Sha256` and `std.crypto.auth.hmac.Hmac` — in `plugins/sigv4.zig`, beside the AWS plugin that needs it |
| base64 | `std.base64`, for the GCP payload and AWS binary secrets |
| the boru and secretspec CLIs | `std.process.run` — in their plugins |

`build.zig.zon` does not exist here, deliberately: there is nothing it
could declare.

## Memory

Every function that can allocate takes the allocator **first** and returns
what it allocated from it. `Sekreto` owns one allocator for what outlives a
lookup — the cache, the redaction list, the last failure message, the
providers — and runs each lookup inside an arena it resets afterwards, so
a long-running process that reads the same secrets over and over does not
grow. `deinit` frees everything, providers included.

What the plugin host holds — the definitions, the instances, each spec as
an options map — lives in voxgig/plugin's own arena, which that port
never frees (its design: every value lives in one arena, so nothing can
be double-freed). Construction is paid for once per chain; a process
that builds chains in a loop should know that the plugin arena grows
with each one. The spec's strings are **copied** into it on the way in,
so a caller's `ProviderSpec` need not outlive the chain.

Two consequences worth knowing:

- `Sekreto.init` returns a `*Sekreto`, not a value. The scratch arena hands
  out an allocator that points at its own address, so a Sekreto that moved
  after construction would give every lookup a dangling one.
- `describe()` **always** allocates, even for the kinds whose description is
  a constant (`env`, `memory`, `boru`, `doppler`, `secretspec`). A caller that sometimes
  gets a literal and sometimes gets an allocation cannot free either safely.

## Layout

| | |
|---|---|
| `src/sekreto.zig` | the facade on a voxgig/plugin host, the name helpers, `parsedotenv`, `redact` |
| `src/provider.zig` | `Provider` (a vtable), `ProviderSpec`, the spec ↔ options bridge, `providerplugin` |
| `src/builtins.zig` | the four built-in providers, `BUILTINS`, `KINDS` |
| `src/addr.zig` | `checkaddr` |
| `plugins/<kind>.zig` | one plugin each: hashicorp, boru, aws (two kinds), gcpsecrets, azuresecrets, onepassword, doppler, infisical, secretspec |
| `plugins/httpjson.zig` | one JSON round-trip over `std.http.Client`, and the helpers a plugin shares |
| `plugins/sigv4.zig` | AWS Signature Version 4 |
| `plugins/all.zig` | `ALL` |
| `test/run.zig` | the conformance suite, and the plugin seam |
| `cli/sekreto-cli.zig` | the app that needs a secret |

Only `test/run.zig` names omni. `make build` does not read `$OMNI_HOME` at
all, so the library and the CLI compile on a machine with no omni checkout
(omni register 4.13); `make build-clean` is the target that proves it.

## Notes on the translation

- **`try` is a keyword**, so `Sekreto.try` is `trysecret` and `Sekreto.redact`
  is `redactText` (the free function keeps the name `redact`).
- **`Provider` is a vtable**, not the tagged union it used to be. A union
  names every kind, and a core that names every kind links every kind;
  the set is open now, so the core holds a pointer and three function
  pointers. `sekreto.provide(alloc, T, value)` puts any struct with
  `lookup`, `describe` and `deinit` behind it.
- **A definition is comptime.** Zig has no closures, so
  `providerplugin(kind, make)` takes both as comptime arguments and
  generates the `define` callback that reads the spec off the instance,
  calls `make`, and exports the result. The plugin value model carries
  numbers and strings, not pointers, so what it exports is the **index**
  of the provider in the list `Sekreto.init` is building, and the
  allocator and process config `make` needs travel through a
  module-global set for the duration of `init` — the shape plugin's zig
  port uses for its error slot. Neither claims thread safety.
- **The spec crosses as a map.** `optionsof` writes each set field of a
  `ProviderSpec` under its own name; `specof` reads it back. Both walk
  the struct's fields at comptime, so a new field is one declaration.
- **A refusal comes back out as itself.** A provider that refuses its
  configuration answers `make` with a message; `define` raises it under
  the code `sekreto_error` with the message as `cause`, the host keeps a
  coded error as it is, and `Sekreto.init` hands back exactly that
  `cause` — byte for byte, because the spec pins those messages.
- **The environment and `std.Io` are passed in**, as `Config`, rather than
  reached for. Zig 0.16 hands both to `main`, and a library that samples
  global state cannot be tested.
- **The cache is a list**, not a map, so redaction order is stable between
  runs — the same reason Go and Rust keep insertion order explicitly.
- **The HTTP timeout is applied twice by hand, because `std` will not apply
  it at all.** `ConnectTcpOptions` has a `timeout` field and
  `connectTcpOptions` never reads it — in 0.16 the whole of
  `std/http/Client.zig` mentions `timeout` exactly once, at the field's own
  declaration. This README previously claimed the connect was bounded at
  10s on the strength of passing that field; it was not, and the port had
  no bound at all. Measured: still blocked at 35s against a server that
  accepted and went silent, where every other port gave up at 10.

  The two halves of a request need different machinery, because until the
  connect returns there is no socket to bound:

  - **The connect** is raced against a 10s sleep, and the loser cancelled
    (`dial` in `plugins/httpjson.zig`). `Io.Threaded` signals a thread
    blocked in a cancelable syscall, so the cancel genuinely unblocks a
    stuck connect.
  - **Everything after it** is bounded by a watchdog thread that shuts the
    socket down once 10s have passed.

  Shutting the socket down is deliberate, and `SO_RCVTIMEO` is the obvious
  move that is wrong here: it makes `recv` return `EAGAIN`, which
  `Io.Threaded` treats as a programmer bug and **panics** on — turning a
  hung vault into a crash. A shutdown ends the pending read the way a
  closed connection does, which the reader already handles.

  The watchdog's bound is **total**: wall-clock from the moment the
  connection is up, not a per-read timer that a trickle of bytes resets.
  That makes this port and Go the only two of the twelve that cut a server
  which answers 200 and then dribbles its body one byte at a time —
  measured at 10.05s here, against 30s-and-still-going for the other ten.

  The request is still built by hand rather than through `Client.fetch`,
  which gives no access to the connection at all.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Zig
[voxgig/omni](https://github.com/voxgig/omni) runner, covering all fourteen
groups. Set `OMNI_HOME` if your omni checkout is not a sibling of this
repository.

```sh
make test                       # every group, then the plugin seam
./build/sekretotest envkey      # just one
./build/sekretotest plugins/oneplugin
```

After the fourteen groups come eight checks the spec cannot express,
because they are about what *this* port links and refuses — the same
eight the go and python suites pin: the built-ins need no plugin, an
unloaded kind is refused naming the fix, a repeated store name numbers
the instance and an invalid one is refused, the full set holds every
kind and every kind builds, one plugin is enough, a refusal comes back
out of the host as itself, `close` tears the chain down and keeps
redaction, and a plugin may replace a built-in kind.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh zig     # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers plus a real boru vault, then runs
this port's CLI against them from each secret source in turn:

```sh
make build
build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

`make fmt-check` is the style gate; the compiler is Zig's static analyser,
so there is no separate linter.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Zig is listed under "Notes on the translation" above.
