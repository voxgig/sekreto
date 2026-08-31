# sekreto — Zig

The Zig port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
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

## Zero dependencies, TLS included

std carries everything this port needs, so — unlike the Rust port — **no
dependency exception is required**:

| | |
|---|---|
| HTTP and HTTPS | `std.http.Client`, with real TLS from `std.crypto.tls` |
| trust roots | `std.crypto.Certificate.Bundle`, scanned from the system store |
| JSON | `std.json` for parsing (responses are written by hand — they are flat maps of strings) |
| SigV4 | `std.crypto.hash.sha2.Sha256` and `std.crypto.auth.hmac.Hmac` |
| base64 | `std.base64`, for the GCP payload and AWS binary secrets |
| the boru and secretspec CLIs | `std.process.run` |

`build.zig.zon` does not exist here, deliberately: there is nothing to
declare.

## Memory

Every function that can allocate takes the allocator **first** and returns
what it allocated from it. `Sekreto` owns one allocator for what outlives a
lookup — the cache, the redaction list, the last failure message — and runs
each lookup inside an arena it resets afterwards, so a long-running process
that reads the same secrets over and over does not grow. `deinit` frees
everything, providers included; a leak check over 10,000 lookups (hits,
misses, unknown stores, invalid names, `refresh`) reports clean.

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
| `src/sekreto.zig` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/providers.zig` | all fourteen providers, and `checkaddr` |
| `src/sigv4.zig` | AWS Signature Version 4 |
| `src/http.zig` | one JSON round-trip over `std.http.Client` |
| `test/run.zig` | the conformance suite |
| `cli/sekreto-cli.zig` | the app that needs a secret |

Zig 0.16 needs cross-directory imports declared as named modules, so the
Makefile builds with `--dep`/`-M` rather than a `build.zig`:

```sh
zig build-exe -femit-bin=build/sekreto-cli \
  --dep sekreto -Mroot=cli/sekreto-cli.zig -Msekreto=src/sekreto.zig
```

Only `test/run.zig` names omni. `make build` does not read `$OMNI_HOME` at
all, so the library and the CLI compile on a machine with no omni checkout
(omni register 4.13); `make build-clean` is the target that proves it.

## Notes on the translation

- **`try` is a keyword**, so `Sekreto.try` is `trysecret` and `Sekreto.redact`
  is `redactText` (the free function keeps the name `redact`).
- **`Provider` is a tagged union**, not a vtable. The set of kinds is closed
  and named by `ProviderSpec.kind`, so an exhaustive switch is the
  compiler's problem and an unknown kind fails loudly.
- **The environment and `std.Io` are passed in**, as `Config`, rather than
  reached for. Zig 0.16 hands both to `main`, and a library that samples
  global state cannot be tested.
- **The cache is a list**, not a map, so redaction order is stable between
  runs — the same reason Go and Rust keep insertion order explicitly.
- **The HTTP timeout is set on the socket, because `std` will not set it.**
  `ConnectTcpOptions` has a `timeout` field and `connectTcpOptions` never
  reads it — in 0.16 the whole of `std/http/Client.zig` mentions `timeout`
  exactly once, at the field's own declaration. This README previously
  claimed the connect was bounded at 10s on the strength of passing that
  field; it was not, and the port had no bound at all. Measured: still
  blocked at 35s against a server that accepted and went silent, where
  every other port gave up at 10.

  `src/http.zig` now sets `SO_RCVTIMEO` / `SO_SNDTIMEO` on the connection's
  own socket, which does hold. Being a socket option it bounds each read
  and each write rather than the request as a whole — the same shape as
  every port here except Go, whose deadline is total. A server dribbling
  one byte at a time can still outlast it; a server that says nothing
  cannot. The request is still built by hand rather than through
  `Client.fetch`, which gives no access to the connection at all.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Zig
[voxgig/omni](https://github.com/voxgig/omni) runner, covering all fourteen
groups. Set `OMNI_HOME` if your omni checkout is not a sibling of this
repository.

```sh
make test                       # every group
./build/sekretotest envkey      # just one
```

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
