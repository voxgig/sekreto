# sekreto — Swift

The Swift port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make build                    # the three modules, then the CLI
make test                     # the conformance suite and the plugin seam
make check-core               # the core reaches no plugin
make lean                     # each plugin, built the way a lean app builds it
```

The library and the CLI depend on the Swift toolchain and on
[voxgig/plugin](https://github.com/voxgig/plugin), which is what the
provider catalog is built on and which itself takes nothing. `Json.swift`
is sekreto's own, `plugins/Crypto.swift` carries SHA-256 and HMAC-SHA256,
and HTTP is Foundation's `URLSession`. There is no `Package.swift`:
`swiftc` is called directly, because a SwiftPM manifest in the shipped
tree would be a manifest for a library that resolves nothing — so
voxgig/plugin is found the way voxgig/omni is (`PLUGIN_HOME`, a sibling
checkout, then the shallow clone `make deps` fetches) and compiled into
`build/` here. Nothing is written inside that checkout.

The build leaves a static archive and a `.swiftmodule` per module in
`build/`, and the CLI, the conformance suite and the seam suite all link
that one build. Only the conformance suite needs voxgig/omni, and only on
its link line.

The optional lookup is `tryget`, since `try` is a Swift keyword. A
provider answers `String?`, where `nil` is the miss that sends the chain
on to the next store. Every reading entry point is `throws`, so a store
that could not answer is a thrown `SekretoError` and cannot be mistaken
for a store that simply does not hold the secret.

Maps that the shared spec compares whole — a memory provider's `values`,
a `.env` file's contents, the SigV4 output headers — are carried in
`Ordered`, a pair list, because a Swift `Dictionary` is unordered and a
signed payload's field order is part of what was signed.

## Use

```swift
import Sekreto
import SekretoPlugins   // only for the kinds beyond the four built in

let secrets = try makesekreto([
  ProviderSpec(kind: "env"),
  ProviderSpec(kind: "dotenv", file: ".env"),
  ProviderSpec(kind: "hashicorp", addr: vaultaddr, token: vaulttoken),
], plugins: [hashicorp])

let token = try secrets.get("api.token")                  // the chain answers
let same = try secrets.getfrom("hashicorp", "api.token")  // one named store
```

`ProviderSpec` is a struct with a default for every field but `kind`, so a
chain reads as configuration and the compiler checks every name.
`Sekreto(providers:names:cache:)` takes live `Provider` instances instead,
for a provider of your own.

`plugins:` is the argument that decides what can be built. `env`, `memory`, `dotenv` and
`file` are built in and need nothing passed; every other kind must be
handed in, and one that was not is refused by name with the fix in the
message:

    sekreto: unknown provider kind: doppler (available: dotenv, env, file,
    hashicorp, memory) - doppler is a sekreto plugin, not built in: pass
    it in the plugins option

`allplugins` is the whole set, for a caller that wants all ten — the CLI
passes it.

## Layout

Three modules, and the middle one is the boundary.

| module | from | holds |
|---|---|---|
| `VoxgigPlugin` | the plugin checkout | the host the catalog is built on |
| `Sekreto` | `src/*.swift` | the core |
| `SekretoPlugins` | `plugins/*.swift` | the ten kinds that reach the world |

| | |
|---|---|
| `src/Sekreto.swift` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.swift` | `ProviderSpec`, the four built-in kinds, `providerplugin` |
| `src/Addr.swift` | `checkaddr`: no credential in the clear |
| `src/Json.swift` | the JSON value model, reader and writer |
| `src/Provider.swift` | the two-method protocol a provider implements |
| `plugins/<Kind>.swift` | one provider kind, one definition |
| `plugins/All.swift` | `allplugins`, the whole set |
| `plugins/Httpjson.swift` | the shared round-trip, percent-encoding, base64 |
| `plugins/Proc.swift` | the shared child process |
| `plugins/Sigv4.swift` | AWS request signing |
| `plugins/Crypto.swift` | SHA-256, HMAC-SHA256, hex |
| `test/SekretoTest.swift` | the conformance suite |
| `test/PluginTest.swift` | the plugin seam, from both sides |
| `cli/Cli.swift` | the app that needs a secret |

## The split

The four kinds that read at most a local file are built in. Every kind
that opens a socket, signs a request or spawns a process is a
voxgig/plugin definition under `plugins/`, and a `Sekreto` can build only
the kinds its initialiser was handed.

**The boundary is the swift module, and the compiler holds it.** `Sekreto`
is compiled from `src/*.swift` alone, so an `import SekretoPlugins` in a
core source names a module that is not there — and once it is there, it is
a cycle, because every plugin imports `Sekreto`:

```
src/Provider.swift:14:8: error: circular dependency between modules
'Sekreto' and 'SekretoPlugins'
```

What the compiler cannot see is everything else: `URLSession`, `Process`
and a hash function are one `import Foundation` away in any core file —
and so are `socket`, `connect` and `posix_spawn`, because that same import
re-exports Glibc, which is a socket and a child process with no import to
name. `make check-core` greps for all of them, and `nm -u
build/libSekreto.a` is the same claim read off the artifact rather than
the source — the core's undefined symbols name no `URLSession`, no
`Process`, no POSIX socket or spawn, and nothing from `SekretoPlugins`.

**A swift module is compiled whole**, which is the one place this port
differs from go and rust: linking `libSekretoPlugins.a` links all ten
kinds whether or not `allplugins` is named, because there is no
per-definition granularity to strip. A lean consumer therefore builds a
smaller module rather than reaching for a smaller name, which is what a
plugin's own build line looks like:

```sh
swiftc -I build -emit-module -emit-library -static \
  -module-name SekretoPlugins plugins/Hashicorp.swift plugins/Httpjson.swift
```

`make lean` does that for every kind, and it is a test as much as an
example: files in one module see each other with no import to give it
away, so a plugin that reached into its neighbour unremarked fails there and
nowhere else. It found two on the first run — `unbase64` and `uriescape`,
both of which had been sitting in `Crypto.swift` and `Sigv4.swift` and
were needed by plugins that sign nothing.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Swift
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`SekretoTest.swift` carries the bridge between the two value models: omni
has an `enum Json` with an `absent` case, and this port takes plain Swift
values and typed specs, so absent, null, and value stay distinct across the
boundary. Both modules export a type called `Json`, so omni's is spelled
`J` throughout the suite and the ambiguity is resolved once rather than at
every use.

`PluginTest.swift` is the other half, and the conformance suite cannot see
any of it: that suite hands every plugin to every chain it builds, so it
can never notice a missing one. The seam suite pins what a consumer
actually depends on — that the full set holds every kind, that every kind
builds from a spec, that a kind nobody passed in is refused naming the
fix, that a refusal from inside `define` comes back out as the
`SekretoError` it went in as, and that the core reaches no plugin. It
needs no omni, so a checkout with none beside it can still run it:

```sh
make build && ./build/sekreto-plugintest
```

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration             # every port
./test/integration.sh swift  # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **No SwiftNIO, no swift-crypto, no SwiftPM manifest.** `Json.swift` is
  an `enum` plus a small parser. `Json.parse` answers `nil` for text that
  is not JSON and `.null` for the literal `null`, which is the distinction
  the plugins' round-trip needs: only the first means the store could not
  answer. The
  same reads are offered on `Json?` as extension methods, so a provider
  can walk a response body without unwrapping at every step.
  `JSONSerialization` is deliberately unused — it hands back an unordered
  dictionary, and it bridges numbers through `NSNumber`, where `true` and
  `1` are not reliably distinguishable.
- **SHA-256 and HMAC-SHA256 are written in-tree, in the plugins.**
  CryptoKit ships only on Apple platforms and swift-crypto is a package,
  so `plugins/Crypto.swift` carries both — on the plugin side of the line,
  because the core of no port imports a hash function. The rule that permits a TLS binding covers cryptographic
  *transport*; a SigV4 signature is not transport. Correctness is not
  asserted in comments — it is proved by the five known-answer signing
  vectors in the shared spec, since a signature is a chain of these two
  functions and one wrong bit anywhere fails there.
- **Redirects are refused, not followed.** `URLSession` follows them by
  default, and a followed redirect would carry `X-Vault-Token` to a host
  `checkaddr` never saw, or downgrade https to http.
  `willPerformHTTPRedirection` answers its completion handler with `nil`,
  which hands the redirect response itself back as the result — a non-200
  the provider then reports as the refusal it is. The body is counted as
  it arrives and the task cancelled one byte over 8 MiB, so an endless
  body is refused rather than accumulated until the deadline.
- **HTTP/1.1 needs no pinning here.** Foundation's Linux `URLSession` is
  libcurl underneath, which speaks HTTP/1.1 over cleartext and never
  attempts the h2c upgrade that made the JVM ports send a declared
  `Content-Length` with no body.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault. It refuses embedded credentials on https as
  well as http, which is what closes
  `http://localhost:8200@evil.example.com/`.
- **A miss is not a failure.** A 404 from HashiCorp, boru's `no alias
  named`, SecretSpec's `Secret '<KEY>' not found`, an absent `.env` and an
  absent secret file all mean *this store does not hold it*, so the chain
  carries on. A locked vault, a rejected token, an unreachable host, a
  permission error and `Provider backend '<name>' not found` all raise.
- **Uppercasing is an explicit ASCII map.** `String.uppercased()` is
  locale-sensitive, and under a Turkish locale `i` becomes `İ` — which
  would turn `api.token` into a key no environment holds.
- **A command is resolved along `PATH` before it is run.** `Process` takes
  a path rather than a name, and going through `/usr/bin/env` instead
  would turn "this binary is not installed" into a non-zero exit that the
  miss detection would then have to reason about. It stays
  `sekreto: cannot run <command>: <err>`.
- **A scoped import keeps two `Json`s apart.** voxgig/plugin exports a
  `Json` of its own — its value model — and so does this port, so a plugin
  file that imported both whole could not name either. Each writes
  `import struct VoxgigPlugin.Definition`, which is the only name it wants
  from there. The core needs no such care: a declaration in the current
  module wins over an imported one, and the core declares `Json` itself.
  It does write `VoxgigPlugin.Host` in full, because Foundation ships a
  `Host` too.
- **`swiftc -static` appends to an archive it finds.** A file that moves
  out of a module leaves its object behind, and the core kept a
  `Crypto-1.o` that nothing in `src/` compiles any more — which is exactly
  what would make `nm` report a boundary that is not there. `make build`
  removes the archives first.
- **TLS verification is on, and `SEKRETO_CA_BUNDLE` is not honoured.**
  `URLSession` verifies the chain and the hostname by default and nothing
  here weakens that, but Linux Foundation exposes no server-trust hook and
  no additive trust store, so there is no way for this port to add a
  private CA without replacing the system roots — which the cross-port
  semantics forbid. The port therefore takes the documented
  `noted_skip` on the private-CA check rather than pretending to a trust
  variable it cannot implement additively.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Swift is listed there.
