# sekreto — Swift

The Swift port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but the Swift toolchain —
`Json.swift` is sekreto's own, `Crypto.swift` carries SHA-256 and
HMAC-SHA256, and HTTP is Foundation's `URLSession`. There is no
`Package.swift`: `swiftc` is called directly, because a SwiftPM manifest
in the shipped tree would be a manifest for a library that resolves
nothing. The build leaves a static archive and a `.swiftmodule` in
`build/`, and both the CLI and the conformance suite link that one build.
Only the conformance suite needs voxgig/omni, and only on its link line.

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
let secrets = try makesekreto([
  ProviderSpec(kind: "env"),
  ProviderSpec(kind: "dotenv", file: ".env"),
  ProviderSpec(kind: "hashicorp", addr: vaultaddr, token: vaulttoken),
])

let token = try secrets.get("api.token")                  // the chain answers
let same = try secrets.getfrom("hashicorp", "api.token")  // one named store
```

`ProviderSpec` is a struct with a default for every field but `kind`, so a
chain reads as configuration and the compiler checks every name.
`Sekreto(providers:names:cache:)` takes live `Provider` instances instead,
for a provider of your own.

## Layout

| | |
|---|---|
| `src/Sekreto.swift` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.swift` | the provider kinds and `ProviderSpec` |
| `src/Sigv4.swift` | AWS request signing |
| `src/Crypto.swift` | SHA-256, HMAC-SHA256, hex and base64 |
| `src/Json.swift` | the JSON value model, reader and writer |
| `src/Provider.swift` | the two-method protocol a provider implements |
| `test/SekretoTest.swift` | the conformance suite |
| `cli/Cli.swift` | the app that needs a secret |

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
  `fetchjson` needs: only the first means the store could not answer. The
  same reads are offered on `Json?` as extension methods, so a provider
  can walk a response body without unwrapping at every step.
  `JSONSerialization` is deliberately unused — it hands back an unordered
  dictionary, and it bridges numbers through `NSNumber`, where `true` and
  `1` are not reliably distinguishable.
- **SHA-256 and HMAC-SHA256 are written in-tree.** CryptoKit ships only
  on Apple platforms and swift-crypto is a package, so `Crypto.swift`
  carries both. The rule that permits a TLS binding covers cryptographic
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
