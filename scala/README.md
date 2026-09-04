# sekreto — Scala

The Scala port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but the JDK and the Scala
standard library — `Json.scala` is sekreto's own, and HTTP is
`java.net.http.HttpClient`, pinned to HTTP/1.1. There is no sbt and no
mill: `scalac` is called directly, and the two runtime jars are folded into
`build/sekreto-cli.jar` so the CLI runs under a bare `java -cp`. Only the
conformance suite needs voxgig/omni, and only on its classpath.

The optional lookup is `tryget`, since `try` is a keyword. A provider
answers `Option[String]`, where `None` is the miss that sends the chain on
to the next store.

## Layout

| | |
|---|---|
| `src/Sekreto.scala` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.scala` | the provider kinds and `ProviderSpec` |
| `src/Sigv4.scala` | AWS request signing |
| `src/Json.scala` | the JSON value model, reader and writer |
| `src/Provider.scala` | the one-method trait a provider implements |
| `test/SekretoTest.scala` | the conformance suite |
| `cli/Cli.scala` | the app that needs a secret |

## Use

```scala
val secrets = sekreto(
  List(
    ProviderSpec(kind = "env"),
    ProviderSpec(kind = "dotenv", file = Some(".env")),
    ProviderSpec(kind = "hashicorp", addr = Some(vaultaddr), token = Some(vaulttoken)),
  ),
)

val token = secrets.get("api.token")                  // the chain answers
val same = secrets.getfrom("hashicorp", "api.token")  // one named store
```

`ProviderSpec` is a case class, so a chain reads as configuration and the
compiler checks every field. `Sekreto(providers, names, cache)` takes live
`Provider` instances instead, for a provider of your own.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Scala
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`SekretoTest.scala` carries the bridge between the two value models: omni
has an `enum Json` with an `Absent` case, and this port takes plain Scala
values and typed specs, so absent, null and value stay distinct across the
boundary.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration             # every port
./test/integration.sh scala  # just this one
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

- **No circe, no upickle.** `Json.scala` is an `enum` plus a small parser.
  `Json.parse` answers `None` for text that is not JSON and
  `Some(Json.Null)` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer. The
  same reads are offered on `Option[Json]` as extension methods, so a
  provider can walk a response body without unwrapping at every step.
- **HTTP/1.1, explicitly.** `java.net.http` defaults to HTTP/2, and over
  cleartext that means an h2c upgrade that sends a declared
  `Content-Length` with no body. Fastify — which Infisical is — refuses
  that outright. See the comment on `CLIENT` in `Providers.scala`.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault.
- **A miss is not a failure.** A 404 from HashiCorp and boru's "no alias
  named" mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token or an unreachable host raises.
- **A name is split with `split("\\.", -1)`.** Scala's default drops
  trailing empty segments, which would make `a.` a valid one-segment name;
  the spec says it is not. Segment matching uses `Regex.matches` rather
  than an anchored find, because `$` in `java.util.regex` also matches
  before a final newline — and `api.token\n` is a spec case.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Scala is listed there.
