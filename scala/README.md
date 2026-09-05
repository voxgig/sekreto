# sekreto — Scala

The Scala port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find (or fetch) voxgig/plugin
make test                     # the conformance suite, and the seam
make check-core               # the core, with the plugins absent
```

The library and the CLI depend on nothing but the JDK, the Scala standard
library and [voxgig/plugin](https://github.com/voxgig/plugin) —
`Json.scala` is sekreto's own, and HTTP is `java.net.http.HttpClient`,
pinned to HTTP/1.1. Only the conformance suite needs voxgig/omni, and only
on its classpath.

**No sbt, no mill, no `libraryDependencies`.** `scalac` driven from the
`Makefile` over a file list is the whole build system, as it is for
voxgig/plugin's own Scala port. voxgig/plugin is therefore a checkout
rather than a coordinate: the `Makefile` finds it the way every port finds
omni — `PLUGIN_HOME`, then a sibling checkout, then the usual places — and
`make deps` fetches a shallow clone into `../.plugin` when there is none.

The optional lookup is `tryget`, since `try` is a keyword. A provider
answers `Option[String]`, where `None` is the miss that sends the chain on
to the next store.

## Layout

Four kinds are built in; the other ten are plugins.
What makes a kind built in is that it reads **at most a local file** —
`env`, `memory`, `dotenv`, `file`. Everything that opens a socket, signs a
request or spawns a process lives under `plugins/`, and `src/` links none
of it.

| `src/` — the core | |
|---|---|
| `Sekreto.scala` | the facade, the name helpers, `parsedotenv`, `redact` |
| `Providers.scala` | the four built-in kinds, `checkaddr`, `BUILTINS`, `KINDS` |
| `Spec.scala` | `ProviderSpec` and `AuthSpec` |
| `Support.scala` | `providerplugin`, and the spec across the plugin boundary |
| `Json.scala` | the JSON value model, reader and writer |
| `Provider.scala` | the one-method trait a provider implements |

| `plugins/` — one file per kind | |
|---|---|
| `Hashicorp.scala` `Boru.scala` `Aws.scala` `Gcpsecrets.scala` `Azuresecrets.scala` `Onepassword.scala` `Doppler.scala` `Infisical.scala` `Secretspec.scala` | the ten plugin kinds, each a `val` a consumer imports |
| `Sigv4.scala` | AWS request signing, which travels with `Aws.scala` |
| `Httpjson.scala` | the shared HTTP-JSON transport and the child-process runner |
| `Plugins.scala` | `Plugins.ALL`, the full set |

| | |
|---|---|
| `test/SekretoTest.scala` | the conformance suite |
| `test/PluginsTest.scala` | the plugin seam, which the conformance suite cannot see |
| `test/CoreOnly.scala` | the core, run with `plugins/` off the classpath |
| `cli/Cli.scala` | the app that needs a secret |

### Four jars, and why

`make build` produces `build/voxgigplugin.jar`, then `build/sekreto.jar`
(the core), then `build/sekreto-plugins.jar` compiled against it, then
`build/sekreto-cli.jar`, which is self-contained — the two Scala runtime
jars folded in — because `test/checks.sh` runs the CLI from one jar under
a bare `java -cp`.

Two library jars rather than one is the point of the split. Folding the
plugins into `sekreto.jar` would make it nominal: an app whose chain is
`[dotenv, env]` would still carry AWS request signing and seven HTTP vault
clients on its classpath. The core jar is compiled with `plugins/` nowhere
on the classpath, so a core file that reached for a plugin would not
compile, and `make check-core` reads the finished jar back three ways —
`jdeps -verbose:class` for what it actually references, `test/CoreOnly.scala`
run with the plugins jar absent, and a grep of every entry (`.tasty`
included, which `jdeps` cannot see) for a plugin, a socket, a cipher and a
child process.

## Use

```scala
import com.voxgig.sekreto.plugins.hashicorp

val secrets = sekreto(
  List(
    ProviderSpec(kind = "env"),
    ProviderSpec(kind = "dotenv", file = Some(".env")),
    ProviderSpec(kind = "hashicorp", addr = Some(vaultaddr), token = Some(vaulttoken)),
  ),
  List(hashicorp),
)

val token = secrets.get("api.token")                  // the chain answers
val same = secrets.getfrom("hashicorp", "api.token")  // one named store

secrets.close()                                       // tear the chain down
```

`ProviderSpec` is a case class, so a chain reads as configuration and the
compiler checks every field.

**Loading is a list handed to the constructor, never a side effect of
importing.** The second argument is the provider kinds beyond the four
built-in ones that the chain may name: `List(hashicorp)` for one,
`Plugins.ALL` for the lot. A kind that was not passed in is refused with a
message that names the fix:

```
sekreto: unknown provider kind: doppler (available: dotenv, env, file, memory)
 - doppler is a sekreto plugin, not built in: pass it in the plugins option
```

A configured provider is a plugin instance on `secrets.host`, addressed by
name and tag — `hashicorp` for a store named after its kind,
`hashicorp$prod` otherwise — so `secrets.host.list` reads like the chain.

`Sekreto(providers, plugins, names, docache)` takes live `Provider`
instances in `providers` as well, for a provider of your own; `names` gives
their store names positionally. The parameter is typed
`List[Provider | ProviderSpec]`, a **union**, so the two shapes a chain
entry may have are the two the compiler admits — from Scala. The JVM
erases the union, so the constructor's bytecode signature is
`List<Object>` and a caller in another JVM language, or one behind an
unchecked cast, can pass anything; that gets `sekreto: not a provider or
a provider spec`. A custom KIND is one call:

```scala
val mystore = providerplugin("mystore", spec => Mystore(spec.addr))
```

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
values and typed specs, so absent, null, and value stay distinct across the
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

What neither suite can see is the seam itself — the conformance suite
hands every plugin to every chain it builds, so it can never notice a
missing one. `make seam` pins that half: the full set holds every kind,
every kind builds, the CLI passes the full set, a kind that was not passed
in is refused, a `SekretoError` raised in `define` comes back out as
itself, one plugin loads only itself, and the core jar does not reach a
plugin.

## Notes

- **No circe, no upickle.** `Json.scala` is an `enum` plus a small parser.
  `Json.parse` answers `None` for text that is not JSON and
  `Some(Json.Null)` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer. The
  same reads are offered on `Option[Json]` as extension methods, so a
  provider can walk a response body without unwrapping at every step.
- **A provider crosses the plugin boundary as a `VOpaque`.**
  voxgig/plugin's Scala port models values as a sealed hierarchy rather
  than as `Any`, and a live provider is not data; `VOpaque` is that port's
  own escape hatch for exactly this, so `define` exports the provider and
  `Sekreto` reads it back and pattern-matches it. A definition whose
  `define` exported none is refused by name rather than leaving a hole in
  the chain.
- **A `SekretoError` crosses the plugin boundary under the code
  `sekreto_error`** and comes back out as itself. The spec pins those
  messages byte for byte, and voxgig/plugin wraps a code-less error raised
  in `define` as `plugin_define_failed`. `providerplugin` puts the code on;
  `Sekreto` takes it off. Nowhere else catches and rewraps.
- **The spec crosses the boundary as plugin's own value model**, written
  out field by field in `Support.scala` rather than reflected over —
  `Sekreto` hands `optionsof(spec)` to `host.load`, and a definition's
  `define` reads `specof(inst.options)` back. A field added to one and
  forgotten in the other would be lost in silence, so `PluginsTest`
  round-trips a spec with every field set.
- **A top-level definition lives in a `<File>$package` class.** That is
  what makes "one plugin loads only itself" true and checkable here: `val
  hashicorp` is a static member of `Hashicorp$package`, so a consumer that
  imports it links that one class, and `PluginsTest` watches a class loader
  to say so.
- **HTTP/1.1, explicitly.** `java.net.http` defaults to HTTP/2, and over
  cleartext that means an h2c upgrade that sends a declared
  `Content-Length` with no body. Fastify — which Infisical is — refuses
  that outright. See the comment on `CLIENT` in `plugins/Httpjson.scala`.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault. It stays in the core although every caller is
  a plugin: the rule an address is held to must not vary with which vault
  client happens to be loaded, and it reads a string and opens nothing.
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
