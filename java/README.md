# sekreto — Java

The Java port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, and the plugin seam
```

`Json.java` is sekreto's own and HTTP is `java.net.http.HttpClient`
(JDK 11+), so the only thing this port depends on is
[voxgig/plugin](https://github.com/voxgig/plugin) — the provider kinds
are its definitions. There is **no Maven and no Gradle**: `javac` and
`java` over a source tree, driven from the Makefile, which is also what
makes the split below a boundary rather than a convention. Only the
conformance suite needs voxgig/omni, and only on its classpath.

The optional lookup is `tryget`, since `try` is a keyword.

## Built in, or a plugin

The core carries the chain and the four kinds that read at most a local
file: `env`, `memory`, `dotenv`, `file`. It reaches no HTTP client, no
hash function and no child process. Every other kind is a plugin under
`plugins/` — a voxgig/plugin definition the calling project passes in:

```java
Sekreto secrets = new Sekreto(new Sekreto.Options()
    .plugins(List.of(Hashicorp.PLUGIN))
    .providers(List.of(
        Map.of("kind", "env"),
        Map.of("kind", "hashicorp", "name", "prod", "addr", addr, "token", token))));

// The plugin host reads like the chain:
// secrets.host().list() -> { env=live, hashicorp$prod=live }
```

A kind that was not passed in is refused by name, with the plugin to
pass. `Plugins.ALL` is the full set, for a caller that genuinely wants
all ten kinds — the CLI, the conformance suite — and naming it links
every one of them, which is the cost the split exists to remove.

A custom store is one call:

```java
Definition mystore = Support.providerplugin(
    "mystore", spec -> new MyStore(Support.text(spec.get("addr"))));
```

**The boundary is the one `javac` draws.** `plugins/` is a source root of its own, and
`make core` compiles `src/` with voxgig/plugin on the classpath and
nothing else, so an import of a plugin from the core does not compile.
`make check-core` then reads the compiled classes back with `jdeps` and
fails on any reference to the plugins package — or to an HTTP client, a
hash function or a child process.

## Layout

| | |
|---|---|
| `src/com/voxgig/sekreto/Sekreto.java` | the facade, the chain, the name helpers, `parsedotenv`, `redact` |
| `src/com/voxgig/sekreto/Support.java` | `providerplugin` — how a kind becomes a plugin definition |
| `src/com/voxgig/sekreto/Builtins.java` | the four built-in kinds, and the names of the ten that are not |
| `src/com/voxgig/sekreto/Addr.java` | `checkaddr`, the guard every network plugin runs first |
| `src/com/voxgig/sekreto/Json.java` | the JSON reader and writer |
| `plugins/com/voxgig/sekreto/plugins/` | the ten plugin kinds, `Httpjson`, `Proc`, `Sigv4`, and `Plugins.ALL` |
| `test/SekretoTest.java` | the conformance suite |
| `test/PluginsTest.java` | the plugin seam, which the conformance suite cannot see |
| `cli/Cli.java` | the app that needs a secret |

`make build` compiles those into three trees — `build/core`,
`build/plugins` and voxgig/plugin's `build/plugin` — and then assembles
`build/classes`, which is the one directory `test/integration.sh` runs
the CLI from. A lean consumer takes `build/core` and the plugin classes
it named, and nothing else.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Java
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository, and `PLUGIN_HOME`
for voxgig/plugin; `make deps` fetches a shallow clone of the latter when
there is none.

The suite hands every plugin to every chain it builds, so it can never
notice a missing one. `PluginsTest` is what pins that half: the full set,
the unknown-kind message, the `sekreto_error` bridge, and the boundary
itself — read off a class loader that holds `build/core` alone, and off
the compiled class files.

What proves this port can actually *fetch* a secret is the integration
run, from the repository root:

```sh
make integration              # every port
./test/integration.sh java    # just this one
```

It starts a token-protected API and stand-in vaults, then runs this
port's CLI against them from each secret source in turn:

```sh
make build
java -cp build/classes sekreto.Cli http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Java is listed there.
