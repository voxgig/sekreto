# sekreto — Java

The Java port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but the JDK — `Json.java` is
sekreto's own, and HTTP is `java.net.http.HttpClient` (JDK 11+). Only the
conformance suite needs voxgig/omni, and only on its classpath.

The optional lookup is `tryget`, since `try` is a keyword.

## Layout

| | |
|---|---|
| `src/com/voxgig/sekreto/Sekreto.java` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/com/voxgig/sekreto/Providers.java` | the five providers |
| `src/com/voxgig/sekreto/Json.java` | the JSON reader and writer |
| `test/SekretoTest.java` | the conformance suite |
| `cli/Cli.java` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Java
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh java    # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
make build
java -cp build/classes sekreto.Cli http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Java is listed there.
