# sekreto — Dart

The Dart port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but the Dart SDK, and nothing
may be added: `pubspec.yaml` declares no dependencies, so `dart pub get`
is never run and no lock file is resolved. `json.dart` is sekreto's own
value model over `dart:convert`, and `crypto.dart` is a hand-rolled
SHA-256 and HMAC-SHA256, because the SDK has no cryptography and
`package:crypto` is a third-party package. HTTP and TLS are `dart:io`'s
`HttpClient`. Only the conformance suite needs voxgig/omni, and it
reaches it through a package map the Makefile writes into `build/` —
nothing a consumer resolves names omni.

The optional lookup is `tryget`, since `try` is a Dart keyword. A
provider answers `String?`, where `null` is the miss that sends the chain
on to the next store, and the empty string is a hit.

A read answers `FutureOr<String>`, not `Future<String>`, and the
distinction is load-bearing rather than an optimisation. A chain of local
stores — the environment, a `.env` file, a secrets directory, a child
process — completes without yielding, and answers with a plain value; the
first provider that opens a socket answers with a future, and the chain
returns one in turn. `await` reads either, so a caller writes `await
secrets.get('api.token')` once and never has to know which providers are
in the chain. What this buys is that a refusal raised before any I/O — an
address `checkaddr` will not dial, a KV version that does not exist —
arrives synchronously, at the call, rather than inside a future the
caller has not looked at yet.

Ordering is never left to a default: Dart maps are insertion-ordered
(`LinkedHashMap`), which is what `parsedotenv`, a `memory` provider's
values, a signed request body and the SigV4 output all need.

## Layout

| | |
|---|---|
| `src/sekreto.dart` | the facade, the name helpers, `redact` |
| `src/providers.dart` | the provider kinds, `ProviderSpec`, `checkaddr` |
| `src/sigv4.dart` | AWS request signing |
| `src/crypto.dart` | SHA-256 and HMAC-SHA256 |
| `src/json.dart` | the JSON value model, reader and writer |
| `src/provider.dart` | the two-method interface a provider implements |
| `test/sekreto_test.dart` | the conformance suite |
| `cli/cli.dart` | the app that needs a secret |

## Use

```dart
final secrets = sekreto([
  ProviderSpec(kind: 'env'),
  ProviderSpec(kind: 'dotenv', file: '.env'),
  ProviderSpec(kind: 'hashicorp', addr: vaultaddr, token: vaulttoken),
]);

// the chain answers
final token = await secrets.get('api.token');

// one named store
final same = await secrets.getfrom('hashicorp', 'api.token');
```

`ProviderSpec` takes named arguments, so a chain reads as configuration
and the compiler checks every field. `Sekreto(providers: ..., names:
..., cache: ...)` takes live `Provider` instances instead, for a provider
of your own.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Dart
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`sekreto_test.dart` carries the bridge between the two value models: omni
answers plain Dart values with an `Absent` marker for a key that is not
there, and this port takes typed specs, so absent, null and value stay
distinct across the boundary. It also holds the one adaptation the corpus
needs, `validname` returning a JSON boolean, which belongs in the test
rather than in the library.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration             # every port
./test/integration.sh dart   # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli \
  http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **No package:crypto, no package:http, no package:json.** `json.dart` is
  a sealed class plus a reader and a writer over `dart:convert`.
  `jsonparse` answers `null` for text that is not JSON and a `JsonNull`
  for the literal `null`, which is the distinction `fetchjson` needs:
  only the first means the store could not answer. It also does what
  `jsonDecode` alone does not — bounds nesting at 128, refuses a number
  that decodes to infinity, and renders an integral number as `1` rather
  than Dart's `1.0`, so this port's output matches every other port's
  byte for byte.
- **SHA-256 and HMAC are hand-rolled.** The SDK has none and the
  dependency rule admits none, so `crypto.dart` writes out FIPS 180-4 and
  RFC 2104. Nothing asserts the digests directly: a SigV4 signature is a
  chain of both primitives, so the five known-answer vectors in the
  shared spec — AWS's own published `get-vanilla` among them — fail on
  one wrong bit anywhere.
- **The signed `host` is split by hand, not by `Uri`.** AWS signs the
  WHATWG host: lowercased, userinfo stripped, and the port present only
  when it is not the scheme's default. A signature over a host the
  service reconstructs differently is refused with no useful diagnostic.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault — and would read
  `http://localhost:8200@evil.example.com/` as loopback.
- **A miss is not a failure.** A 404 from HashiCorp, boru's `no alias
  named`, SecretSpec's `Secret '<KEY>' not found` and an absent file or
  directory all mean *this store does not hold it*, so the chain carries
  on. A locked vault, a rejected token, an unreachable host, a directory
  read as a file and SecretSpec's `Provider backend '<name>' not found`
  all raise. Absence is told from failure by errno — `ENOENT` and
  `ENOTDIR` only — rather than by an `exists()` predicate, which answers
  false for a permission error and would turn a locked mount into a miss.
- **HTTP/1.1 needs no pinning here.** `dart:io`'s `HttpClient` speaks
  only HTTP/1.1, so the h2c upgrade that makes the JVM ports declare a
  `Content-Length` with no body cannot arise. Redirects are switched off
  and the proxy resolver is fixed to `DIRECT`, both explicitly: a
  followed redirect would carry `X-Vault-Token` to a host `checkaddr`
  never saw, and an `http_proxy` in the environment has sent a Vault
  token in the clear before now.
- **TLS is `dart:io`'s, and `SEKRETO_CA_BUNDLE` is additive.** The
  context is built `withTrustedRoots: true` and the bundle is *added* to
  those roots, never substituted for them, so a private CA can be trusted
  without losing the public ones. It fails open and silently: an
  unreadable file, or one holding no certificate, adds no roots and
  raises nothing. Chain verification and host verification are both the
  platform's, and the second matters as much as the first — the only
  HTTPS endpoint either suite offers is an IP literal, which is matched
  against an `iPAddress` name and not a DNS one.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Dart is listed there.
