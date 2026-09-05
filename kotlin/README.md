# sekreto — Kotlin

The Kotlin port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but the JDK and the Kotlin
standard library — `Json.kt` is sekreto's own, and HTTP is
`java.net.http.HttpClient`, pinned to HTTP/1.1. Only the conformance suite
needs voxgig/omni, and only on its classpath.

The optional lookup is `tryget`, since `try` is a keyword; `` `try` ``
delegates to it for callers translating from the canonical TypeScript.

## Layout

| | |
|---|---|
| `src/Sekreto.kt` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.kt` | the provider kinds and `ProviderSpec` |
| `src/Sigv4.kt` | AWS request signing |
| `src/Json.kt` | the JSON value model, reader and writer |
| `src/Provider.kt` | the one-method interface a provider implements |
| `test/SekretoTest.kt` | the conformance suite |
| `cli/Cli.kt` | the app that needs a secret |

## Use

```kotlin
val secrets = sekreto(
    listOf(
        ProviderSpec(kind = "env"),
        ProviderSpec(kind = "dotenv", file = ".env"),
        ProviderSpec(kind = "hashicorp", addr = vaultaddr, token = vaulttoken),
    ),
)

val token = secrets.get("api.token")          // the chain answers
val same = secrets.getfrom("hashicorp", "api.token")  // one named store
```

`ProviderSpec` is a data class, so a chain reads as configuration and the
compiler checks every field. `Sekreto(providers, names, cache)` takes live
`Provider` instances instead, for a provider of your own.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Kotlin
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`SekretoTest.kt` carries the bridge between the two value models: omni has
a sealed `Json` with an `Absent` variant, and this port takes plain Kotlin
values and typed specs, so absent, null, and value stay distinct across the
boundary.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh kotlin  # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
java -cp build/sekreto-cli.jar sekreto.Cli \
  http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **No kotlinx.serialization, no Gson.** `Json.kt` is a sealed class plus a
  small parser. `Json.parse` answers `null` for text that is not JSON and
  `Json.Null` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer.
- **HTTP/1.1, explicitly.** `java.net.http` defaults to HTTP/2, and over
  cleartext that means an h2c upgrade that sends a declared
  `Content-Length` with no body. Fastify — which Infisical is — refuses
  that outright. See the comment on `CLIENT` in `Providers.kt`.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault.
- **A miss is not a failure.** A 404 from HashiCorp and boru's "no alias
  named" mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token or an unreachable host raises.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Kotlin is listed there.
