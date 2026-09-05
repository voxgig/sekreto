# sekreto — Lean

The Lean port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find or fetch voxgig/plugin
make test                     # the conformance suite, and the plugin seam
make check-core               # what the core actually links
```

## The core, and the plugins

Four provider kinds are **built in** — `env`, `memory`, `dotenv` and
`file` — and what makes them built in is that they read at most a local
file. Every kind that opens a socket, signs a request, or spawns a process
is a [voxgig/plugin](https://github.com/voxgig/plugin) definition under
`plugins/`, and a `Sekreto` can build exactly the kinds its constructor
was handed:

```lean
import Sekreto
import SekretoPlugins.Hashicorp

open Sekreto

def main : IO Unit := do
  let secrets ← sekreto {
    plugins := [hashicorp],
    providers := [
      { kind := "memory", values := local },
      { kind := "hashicorp", addr := vaultaddr, token := vaulttoken }] }
```

Loading is explicit and never a side effect of importing: the set of
stores an app can reach is decided where the chain is written, and a kind
that was not passed in is refused with a message that names the fix.
`SekretoPlugins` is the whole set in one import, for a caller that wants
all ten — the CLI does, because `--source` is a run-time argument.

**Lean's own module resolution is the boundary.** A module name's first
component resolves to one directory on `LEAN_PATH` and every submodule
under that same directory, so the core is compiled with `build/lib` on its
path and the plugin tree left off it. A core module that imports a plugin
does not compile at all, which is why the plugins are `SekretoPlugins.*`
rather than `Sekreto.Plugins.*`; the namespace inside them is still
`Sekreto`, so the names a consumer writes are unchanged.

`make check-core` reads that fact back off the compiled objects. `lean`
emits one `initialize_<Module>` symbol per import and one undefined
reference per `@[extern]`, so the undefined symbols of an object are its
import graph and its platform reach, in full names:

```sh
$ make check-core
== the control: every forbidden name exists, on the plugin side
  initialize_SekretoPlugins_Hashicorp
  ...
  l_IO_Process_output
  sekreto_curl_fetch
  sekreto_epoch_seconds
== the core objects reference none of them
== and no plugin module is linked into build/sekreto-core
== the core reaches outside Lean's own naming for floor and nothing else
  plugin: sekreto_curl_fetch
  plugin: sekreto_epoch_seconds
  core:   floor
== and spawns nothing, by either name
== and imports Init, voxgig/plugin and its own modules, and nothing else
== one plugin reaches only the shared support it dials
  SekretoPlugins.Hashicorp -> initialize_SekretoPlugins_Httpjson
  SekretoPlugins.Secretspec -> initialize_SekretoPlugins_Proc
core: a chain of built-ins needs no plugin
```

The second claim is worth nothing without the first, so the first is
checked too: every forbidden name has to be found on the plugin side, or
the target fails for proving nothing.

A list of names could still miss a socket opened under a name nobody
thought to list, so three of those claims need no list, and each of the
three is a prefix rather than an enumerated API. The first: an `@[extern]`
written here shows up as an undefined symbol outside Lean's own
`l_`/`lean_`/`initialize_` naming, and the core is allowed exactly one,
the C math library's `floor`, which is what `Float` arithmetic compiles
to.

The other two exist because that first one proves less than it reads.
Lean's own runtime bindings are `lean_*` too, so `IO.Process.spawn`
compiles to an undefined `lean_io_process_spawn` that the naming test
skips, needs no `@[extern]` here, and needs no import either, since
`Init` is always in scope. An audit built a core that ran `/bin/sh -c id`
and watched the target pass. So the second claim denies both spellings —
`l_IO_Process_` for the compiled Lean function and `lean_io_process_` for
the runtime binding under it — whichever the compiler picks. The third
reads the import graph instead of the platform reach: every
`initialize_` symbol the core wants has to name `Init`, voxgig/plugin or
one of its own modules. That is what stops a core reaching `Std.Time` for
a wall clock, or a future `Std.Internal.UV.TCP` for a socket, both of
which arrive under `lean_*` names as well.

`build/sekreto-core` is the last piece — a real program, linked from the
core objects and voxgig/plugin with no `ffi/` object file and no
`-lcurl -lssl -lcrypto` on the command line. `sekreto_curl_fetch` and
`sekreto_epoch_seconds` are the only symbols the C files define, so a core
module that reached for either would fail that link instead of producing a
binary. It then runs a chain of the four built-in kinds, which is what
such a chain can do with no plugin loaded.

`sigv4` travels with the AWS plugin and `Crypto.lean` with it: the core of
no port imports a hash function. `Httpjson` and `Proc` are the shared
support the dialing plugins and the two CLI-reading plugins take — the
`secretspec` plugin takes `Proc` alone, so it links no TLS anywhere.

## voxgig/plugin, and libcurl

voxgig/plugin is a dependency of the **library**, not of the tests: every
provider kind is a plugin definition and every chain is a plugin host.
Lean has no package registry, so the Makefile finds a checkout the way
every port finds omni — `$PLUGIN_HOME`, a sibling, the usual places — and
`make deps` fetches a shallow clone when there is none. The library itself
searches nothing.

It is compiled here, from its source, with this port's pinned toolchain. A
`.olean` carries the exact compiler that wrote it and is refused by any
other, so taking that repository's build artifacts would pin both
repositories to one Lean release.

Beyond the toolchain and voxgig/plugin there is one thing more:
**libcurl**, bound in-tree by `ffi/sekreto_curl.c`, because Lean has no
sockets, no TLS, and no HTTP of its own. That is the repository's
cryptographic-transport rule — where a port's standard library has TLS it
uses it, and where it does not it binds the platform's audited library.
The audit surface is libcurl **plus whichever TLS backend it was built
against**, which this port does not choose. Everything else a standard
library would supply is written here: JSON, SHA-256, HMAC-SHA256, base64
and the SigV4 signer. Only the conformance suite needs voxgig/omni, and
only on its own module path.

There is no lakefile. `lean` and `leanc` are called directly from the
`Makefile`, which is what keeps the library's build inputs to `src/`,
voxgig/plugin and the toolchain while still linking a C stub, putting omni
in front of the suite alone, and compiling `src/` with `plugins/` out of
reach. The swift port ships no `Package.swift` for the same reason.

The optional lookup is `tryget`, since `try` is a Lean keyword, and the
facade's redaction is `redactText`, since the module-level `redact` keeps
its own name. A provider answers `IO (Option String)`, where `none` is the
miss that sends the chain on to the next store. The two spec fields whose
names are Lean keywords, `prefix` and `namespace`, keep those names
through Lean's `«…»` quoting rather than being renamed.

## Layout

| | |
|---|---|
| `src/Sekreto.lean` | the core's public surface, in one import |
| `src/Sekreto/Core.lean` | the name helpers, `parsedotenv`, `redact` |
| `src/Sekreto/Chain.lean` | the facade: the chain, the cache, the host |
| `src/Sekreto/Provider.lean` | `Provider`, `ProviderSpec`, `providerplugin` |
| `src/Sekreto/Builtin.lean` | the four built-in kinds |
| `src/Sekreto/Json.lean` | the JSON value model, reader and writer |
| `src/Sekreto/Addr.lean` | `checkaddr` and `safeaddr` |
| `src/Sekreto/Text.lean` | the string helpers Lean's standard library lacks |
| `plugins/SekretoPlugins.lean` | `allplugins`, the whole set in one import |
| `plugins/SekretoPlugins/Httpjson.lean` | `fetchjson`, base64, escaping, renewal |
| `plugins/SekretoPlugins/Proc.lean` | `runcmd`, for the two CLI-read kinds |
| `plugins/SekretoPlugins/Crypto.lean` | SHA-256 and HMAC-SHA256 |
| `plugins/SekretoPlugins/Clock.lean` | the wall clock SigV4 stamps |
| `plugins/SekretoPlugins/Sigv4.lean` | AWS request signing |
| `plugins/SekretoPlugins/Hashicorp.lean` | one file per kind, and nine more beside it |
| `ffi/sekreto_curl.c` | the TLS transport binding |
| `ffi/sekreto_clock.c` | `time()`, and nothing else |
| `test/SekretoTest.lean` | the conformance suite, and the plugin seam |
| `test/CoreOnly.lean` | the program `check-core` links without libcurl |
| `cli/Cli.lean` | the app that needs a secret |

## Use

```lean
import Sekreto
import SekretoPlugins.Hashicorp

open Sekreto

def main : IO Unit := do
  let secrets ← sekreto {
    plugins := [hashicorp],
    providers := [
      { kind := "env" },
      { kind := "dotenv", file := ".env" },
      { kind := "hashicorp", addr := vaultaddr, token := vaulttoken }] }

  let token ← secrets.get "api.token"                    -- the chain answers
  let same ← secrets.getfrom "hashicorp" "api.token"     -- one named store
```

`Options` and `ProviderSpec` are structures whose every field has a
default, so a chain reads as configuration and the compiler checks every
field. A provider kind of your own is one call — `providerplugin kind
make`, where `make` turns a `ProviderSpec` into a `Provider` — and a
definition naming one of the four built-in kinds replaces it.
`Sekreto.make providers names cache` takes live `Provider` records
instead, for a chain assembled without specs at all.

`Sekreto` itself is unprintable, and deliberately so: most of its fields
are `IO.Ref`, which has no `Repr` in Lean at all, so the hazard the other
ports answer with a hand-written print hook — `print(sekreto)` emitting
every resolved secret — cannot arise. `Sekreto.inspect` reports the store
names for the ports that agree on that shape, and `Sekreto.instances`
reports each plugin instance and its status.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Lean
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
make test GROUP=envkey            # one named group
make test GROUP=plugins/oneplugin # one seam check
```

omni's runner is compiled here too, and for the same reason voxgig/plugin
is: compiling `Omni.lean` into `build/omni` costs two seconds and nothing
the library builds ever reaches it.

`SekretoTest.lean` carries two bridges. The first is between the value
models: omni has `Option Lean.Json`, where `none` is absent and
`some .null` is a JSON null, and this port has its own `Sekreto.Json` and
typed specs, so absent, null and value stay distinct across the boundary.
The second is between the monads — omni's `Subject` is pure, because Lean
is, and the library is in `IO`, because reading a vault is. `runio` is the
join, and it is the only unsafe thing in the port.

After the fourteen groups come eleven seam checks, named `plugins/…`,
which the spec cannot see: it hands every plugin to every chain it builds,
so it can never notice a consumer passing the wrong ones. They pin the
full set against the core's list of what ships as a plugin, that every
kind builds from a spec, that the CLI passes all ten, that one plugin is
enough for a chain naming only it, how a repeated store name is numbered,
that a refusal raised inside `define` comes back byte for byte, and which
modules each file imports.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration             # every port
./test/integration.sh lean   # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **A definition cannot hand back a closure.** voxgig/plugin's value model
  carries numbers, strings, lists and maps, and no pointers, so a
  definition's `define` parks the `Provider` it built in a module-global
  slot and exports the slot number; `sekreto` reads the number back off
  the host and takes the provider out. The zig port does the same thing
  for the same reason. The table is set for no longer than one
  construction, and a chain that fails part-way drops whatever it left
  behind, so two threads building chains at once would race it — which
  this port, like the plugin port under it, does not claim to support.
- **The constructor of the error decides whose it is.** `SekretoError` is
  `IO.userError` and nothing else is, so a `userError` raised inside
  `define` is a provider refusing its own configuration and travels out
  under the code `sekreto_error` with its message byte for byte, which is
  what the spec pins. Every other `IO.Error` surfaces as the host reports
  it, naming the instance and the cause.
- **The binding is one file.** `ffi/sekreto_curl.c` is the only place this
  port names a library outside the toolchain, and
  `plugins/SekretoPlugins/Httpjson.lean` the only module that calls into
  it. It verifies the chain against the system store
  (`CURLOPT_SSL_VERIFYPEER`), verifies the **hostname**
  (`CURLOPT_SSL_VERIFYHOST` at 2, never 0 or 1 — a separate check from the
  chain, and the half people forget), lets libcurl send SNI for a name and
  omit it for an IP literal, and honours `SEKRETO_CA_BUNDLE` through
  `CURLOPT_SSL_CTX_FUNCTION` so that extra roots **add** to the system
  store. `CURLOPT_CAINFO` would replace it, which is why it is untouched.
  Redirects are off, proxies are off, HTTP/1.1 is pinned, TLS 1.2 is the
  floor, the round-trip is bounded at ten seconds and the body at 8 MiB.
- **`-lssl -lcrypto` is for one call.** `SSL_CTX_load_verify_locations`,
  which is trust configuration and therefore transport. SHA-256 and
  HMAC-SHA256 are hand-rolled in `plugins/SekretoPlugins/Crypto.lean`,
  because the exception covers transport and nothing else — the same line
  the rust port draws against `ring`.
- **No `Lean.Data.Json`.** Its objects are keyed by name, so field order is
  the sorted order and not the authored one — and a SigV4-signed body is
  signed in the order it was written. `Json.parse` answers `none` for text
  that is not JSON and `some .null` for the literal `null`, which is the
  distinction `fetchjson` needs: only the first means the store could not
  answer coherently. The same reads are offered on `Option Json` in the
  `OptJson` namespace, so a provider walks a response body without
  unwrapping at every step. The parser refuses past 128 levels of nesting,
  because a body arrives before any trust check has been made of it.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault. Userinfo is refused outright, on https as well
  as http, which is what closes
  `http://localhost:8200@evil.example.com/`. It stays in the core, because
  every kind that dials anything calls it before opening a connection.
- **A miss is not a failure.** A 404 from HashiCorp, boru's "no alias
  named", SecretSpec's `Secret 'KEY' not found` and an absent file or
  directory mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token, an unreachable host or an undecodable
  payload raises. Absence of a file is asked of the DIRECTORY, not through
  an existence predicate, which answers false for a permission error and
  would turn a locked mount into a miss.
- **Names are split with `String.splitOn "."`,** which keeps trailing
  empties, so `a.` is two segments and not a valid one-segment name. Each
  segment is matched by a character scan rather than a pattern: `$` in
  several regex engines also matches before a final newline, and
  `api.token\n` is a spec case. `envkey` uppercases through
  `Char.toUpper`, which in Lean maps `a`-`z` and nothing else, so the
  Turkish-locale hazard cannot arise.
- **The clock is bound, the calendar is not.** Lean has `IO.monoMsNow` —
  which is what token renewal wants, and uses — but no wall clock, so
  `ffi/sekreto_clock.c` is two lines of `time()` and
  `plugins/SekretoPlugins/Clock.lean` does the civil-date arithmetic in
  Lean, where it can be read. Both are plugin-side: SigV4 is the only
  thing here that reads a calendar.

## An open question this port does not settle

Whether Lean belongs here at all is still its own question: struct's Lean
port makes sense as a data structure library that Lean proofs can reason
about, and a secrets client that opens sockets is a different kind of
thing. The question left open is whether Lean should be a full port at all, or whether local providers only
— `env`, `dotenv`, `file`, `memory` and boru-via-CLI — is the destination
here rather than a staging post.

The core/plugin split narrows that question without answering it. A Lean
consumer that wants the four built-in kinds now links no libcurl, no
OpenSSL and no child process, and `make check-core` is what says so; the
ten kinds that do are there for the consumer that asks for one by name.
What this port is **for** is still worth someone stating, and nothing here
should be read as having settled it.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Lean is listed there.
