# sekreto — Kotlin

The Kotlin port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find (or fetch) voxgig/plugin
make test                     # the conformance suite, and the seam
make check-core               # the core, with the plugins absent
```

The library and the CLI depend on nothing but the JDK, the Kotlin standard
library and [voxgig/plugin](https://github.com/voxgig/plugin) — `Json.kt`
is sekreto's own, and HTTP is `java.net.http.HttpClient`, pinned to
HTTP/1.1. Only the conformance suite needs voxgig/omni, and only on its
classpath.

**No gradle, no maven.** `kotlinc` driven from the `Makefile` over a file
list is the whole build system, as it is for the `java` port's `javac`.
voxgig/plugin is therefore a checkout rather than a coordinate: the
`Makefile` finds it the way every port finds omni — `PLUGIN_HOME`, then a
sibling checkout, then the usual places — and `make deps` fetches a
shallow clone into `../.plugin` when there is none.

The optional lookup is `tryget`, since `try` is a keyword; `` `try` ``
delegates to it for callers translating from the canonical TypeScript.

## Layout

Four kinds are built in; the other ten are plugins
([`docs/design/plugin-providers.md`](../docs/design/plugin-providers.md)).
What makes a kind built in is that it reads **at most a local file** —
`env`, `memory`, `dotenv`, `file`. Everything that opens a socket, signs a
request or spawns a process lives under `plugins/`, and `src/` links none
of it.

| `src/` — the core | |
|---|---|
| `Sekreto.kt` | the facade, the name helpers, `parsedotenv`, `redact` |
| `Providers.kt` | the four built-in kinds, `checkaddr`, `BUILTINS`, `KINDS` |
| `Spec.kt` | `ProviderSpec` and `AuthSpec` |
| `Support.kt` | `providerplugin`, and the spec across the plugin boundary |
| `Json.kt` | the JSON value model, reader and writer |
| `Provider.kt` | the one-method interface a provider implements |

| `plugins/` — one file per kind | |
|---|---|
| `Hashicorp.kt` `Boru.kt` `Aws.kt` `Gcpsecrets.kt` `Azuresecrets.kt` `Onepassword.kt` `Doppler.kt` `Infisical.kt` `Secretspec.kt` | the ten plugin kinds, each a `val` a consumer imports |
| `Sigv4.kt` | AWS request signing, which travels with `Aws.kt` |
| `Httpjson.kt` | the shared HTTP-JSON transport and the child-process runner |
| `Plugins.kt` | `Plugins.ALL`, the full set |

| | |
|---|---|
| `test/SekretoTest.kt` | the conformance suite |
| `test/PluginsTest.kt` | the plugin seam, which the conformance suite cannot see |
| `test/CoreOnly.kt` | the core, run with `plugins/` off the classpath |
| `cli/Cli.kt` | the app that needs a secret |

### Three jars, and why

`make build` produces `build/sekreto.jar` (the core), then
`build/sekreto-plugins.jar` compiled against it, then
`build/sekreto-cli.jar`, which is self-contained because `test/checks.sh`
runs the CLI from one jar.

Two library jars rather than one is the point of the split. Folding the
plugins into `sekreto.jar` would make it nominal: an app whose chain is
`[dotenv, env]` would still carry AWS request signing and seven HTTP vault
clients on its classpath. The core jar is compiled with `plugins/` nowhere
on the classpath, so a core file that reached for a plugin would not
compile, and `make check-core` greps the finished jar for a plugin, a
socket, a cipher and a child process.

## Use

```kotlin
import com.voxgig.sekreto.plugins.hashicorp

val secrets = sekreto(
    listOf(
        ProviderSpec(kind = "env"),
        ProviderSpec(kind = "dotenv", file = ".env"),
        ProviderSpec(kind = "hashicorp", addr = vaultaddr, token = vaulttoken),
    ),
    listOf(hashicorp),
)

val token = secrets.get("api.token")          // the chain answers
val same = secrets.getfrom("hashicorp", "api.token")  // one named store

secrets.close()                               // tear the chain down
```

`ProviderSpec` is a data class, so a chain reads as configuration and the
compiler checks every field.

**Loading is a list handed to the constructor, never a side effect of
importing.** The second argument is the provider kinds beyond the four
built-in ones that the chain may name: `listOf(hashicorp)` for one,
`Plugins.ALL` for the lot. A kind that was not passed in is refused with a
message that names the fix:

```
sekreto: unknown provider kind: doppler (available: dotenv, env, file, memory)
 - doppler is a sekreto plugin, not built in: pass it in the plugins option
```

A configured provider is a plugin instance on `secrets.host`, addressed by
name and tag — `hashicorp` for a store named after its kind,
`hashicorp$prod` otherwise — so `secrets.host.list()` reads like the chain.

`Sekreto(providers, plugins, names, docache)` takes live `Provider`
instances in `providers` as well, for a provider of your own; `names` gives
their store names positionally. A custom KIND is one call:

```kotlin
val mystore = providerplugin("mystore") { spec -> Mystore(spec.addr) }
```

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
values and typed specs, so absent, null and value stay distinct across the
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

What neither suite can see is the seam itself — the conformance suite
hands every plugin to every chain it builds, so it can never notice a
missing one. `make seam` pins that half: the full set holds every kind,
every kind builds, the CLI passes the full set, a kind that was not passed
in is refused, a `SekretoError` raised in `define` comes back out as
itself, and the core jar does not reach a plugin.

## Notes

- **No kotlinx.serialization, no Gson.** `Json.kt` is a sealed class plus a
  small parser. `Json.parse` answers `null` for text that is not JSON and
  `Json.Null` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer.
- **A `SekretoError` crosses the plugin boundary under the code
  `sekreto_error`** and comes back out as itself. The spec pins those
  messages byte for byte, and voxgig/plugin wraps a code-less error raised
  in `define` as `plugin_define_failed`. `providerplugin` puts the code on;
  `Sekreto` takes it off. Nowhere else catches and rewraps.
- **The spec crosses the boundary as plugin's own value model**, written
  out field by field in `Support.kt` rather than reflected over — `Sekreto`
  hands `optionsof(spec)` to `host.load`, and a definition's `define` reads
  `specof(inst.options)` back. A field added to one and forgotten in the
  other would be lost in silence, so `PluginsTest` round-trips a spec with
  every field set.
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
