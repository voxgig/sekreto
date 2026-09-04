# sekreto — Lean

The Lean port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library depends on the Lean toolchain and one thing more: **libcurl**,
bound in-tree by `ffi/sekreto_curl.c`, because Lean has no sockets, no TLS
and no HTTP of its own. That is the repository's cryptographic-transport
rule — where a port's standard library has TLS it uses it, and where it
does not it binds the platform's audited library, which for Lean means the
libcurl its own HTTP clients already bind. Everything else a standard
library would supply is written here: JSON, SHA-256, HMAC-SHA256, base64
and the SigV4 signer. The audit surface is libcurl **plus whichever TLS
backend it was built against**, which this port does not choose. Only the
conformance suite needs voxgig/omni, and only on its own module path.

There is no lakefile. `lean` and `leanc` are called directly from the
`Makefile`, which is what keeps the library's build inputs to `src/` and
the toolchain while still linking a C stub and putting omni in front of
the suite alone. The swift port ships no `Package.swift` for the same
reason.

The optional lookup is `tryget`, since `try` is a Lean keyword, and the
facade's redaction is `redactText`, since the module-level `redact` keeps
its own name. A provider answers `IO (Option String)`, where `none` is the
miss that sends the chain on to the next store. The two spec fields whose
names are Lean keywords, `prefix` and `namespace`, keep those names
through Lean's `«…»` quoting rather than being renamed.

## Layout

| | |
|---|---|
| `src/Sekreto.lean` | the public surface, in one import |
| `src/Sekreto/Core.lean` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Sekreto/Providers.lean` | the fourteen provider kinds and `ProviderSpec` |
| `src/Sekreto/Sigv4.lean` | AWS request signing |
| `src/Sekreto/Crypto.lean` | SHA-256, HMAC-SHA256 and strict base64 |
| `src/Sekreto/Json.lean` | the JSON value model, reader and writer |
| `src/Sekreto/Addr.lean` | `checkaddr` and `safeaddr` |
| `src/Sekreto/Curl.lean` | `fetchjson`, over the binding |
| `src/Sekreto/Clock.lean` | the wall clock and token renewal |
| `src/Sekreto/Text.lean` | the string helpers Lean's standard library lacks |
| `src/Sekreto/Provider.lean` | the two-field record a provider implements |
| `ffi/sekreto_curl.c` | the TLS transport binding |
| `ffi/sekreto_clock.c` | `time()`, and nothing else |
| `test/SekretoTest.lean` | the conformance suite |
| `cli/Cli.lean` | the app that needs a secret |

## Use

```lean
import Sekreto
open Sekreto

def main : IO Unit := do
  let secrets ← sekreto [
    { kind := "env" },
    { kind := "dotenv", file := ".env" },
    { kind := "hashicorp", addr := vaultaddr, token := vaulttoken }]

  let token ← secrets.get "api.token"                    -- the chain answers
  let same ← secrets.getfrom "hashicorp" "api.token"     -- one named store
```

`ProviderSpec` is a structure whose every field has a default, so a chain
reads as configuration and the compiler checks every field.
`Sekreto.make providers names cache` takes live `Provider` records instead,
for a provider of your own; `makeprovider` is public, so a mixed chain is
built by turning the specs into providers first and handing the whole list
to `Sekreto.make`.

`Sekreto` itself is unprintable, and deliberately so: three of its four
fields are `IO.Ref`, which has no `Repr` in Lean at all, so the hazard the
other ports answer with a hand-written print hook — `print(sekreto)`
emitting every resolved secret — cannot arise. `Sekreto.inspect` reports
the store names for the ports that agree on that shape.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Lean
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
make test GROUP=envkey       # one named group
```

omni's runner is compiled here, from its source, with this port's pinned
toolchain. A `.olean` carries the exact compiler that wrote it and is
refused by any other, so linking omni's own build artifacts would pin both
repositories to one Lean release; compiling `Omni.lean` into `build/omni`
costs two seconds and nothing the library builds ever reaches it.

`SekretoTest.lean` carries two bridges. The first is between the value
models: omni has `Option Lean.Json`, where `none` is absent and
`some .null` is a JSON null, and this port has its own `Sekreto.Json` and
typed specs, so absent, null and value stay distinct across the boundary.
The second is between the monads — omni's `Subject` is pure, because Lean
is, and the library is in `IO`, because reading a vault is. `runio` is the
join, and it is the only unsafe thing in the port.

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

- **The binding is one file.** `ffi/sekreto_curl.c` is the only place this
  port names a library outside the toolchain, and `src/Sekreto/Curl.lean`
  the only module that calls into it. It verifies the chain against the
  system store (`CURLOPT_SSL_VERIFYPEER`), verifies the **hostname**
  (`CURLOPT_SSL_VERIFYHOST` at 2, never 0 or 1 — a separate check from the
  chain, and the half people forget), lets libcurl send SNI for a name and
  omit it for an IP literal, and honours `SEKRETO_CA_BUNDLE` through
  `CURLOPT_SSL_CTX_FUNCTION` so that extra roots **add** to the system
  store. `CURLOPT_CAINFO` would replace it, which is why it is untouched.
  Redirects are off, proxies are off, HTTP/1.1 is pinned, TLS 1.2 is the
  floor, the round-trip is bounded at ten seconds and the body at 8 MiB.
- **`-lssl -lcrypto` is for one call.** `SSL_CTX_load_verify_locations`,
  which is trust configuration and therefore transport. SHA-256 and
  HMAC-SHA256 are hand-rolled in `src/Sekreto/Crypto.lean`, because the
  exception covers transport and nothing else — the same line the rust
  port draws against `ring`.
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
  `http://localhost:8200@evil.example.com/`.
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
- **The clock is bound, the calendar is not.** Lean 4.16 has
  `IO.monoMsNow` — which is what token renewal wants, and uses — but no
  wall clock, so `ffi/sekreto_clock.c` is two lines of `time()` and
  `src/Sekreto/Clock.lean` does the civil-date arithmetic in Lean, where
  it can be read.

## An open question this port does not settle

[`doc/design/more-ports.md`](../doc/design/more-ports.md) records that Lean
is "still its own question": struct's Lean port makes sense as a data
structure library that Lean proofs can reason about, and a secrets client
that opens sockets is a different kind of thing. That document leaves open
whether Lean should be a full port at all, or whether local providers only
— `env`, `dotenv`, `file`, `memory` and boru-via-CLI — is the destination
here rather than a staging post.

This port answers the *how* and not the *whether*: all fourteen kinds work,
over real sockets, with the four TLS obligations met. What it is **for** is
still worth someone stating, and nothing here should be read as having
settled it.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Lean is listed there.
