# sekreto — Clojure

The Clojure port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, and the plugin seam
```

The library depends on the JDK, Clojure itself and
[voxgig/plugin](https://github.com/voxgig/plugin), and on nothing else —
`json.clj` is sekreto's own, and HTTP is `java.net.http.HttpClient`, pinned
to HTTP/1.1. `deps.edn` declares no `:deps` at all: there is no
`data.json`, no `cheshire` and no `clj-http`. The CLI is AOT-compiled into
`build/sekreto-cli.jar` with the Clojure runtime folded in, so it runs under
a bare `java -cp` — which is what the integration suite needs, since it runs
every port's CLI from an empty directory.

Three names differ from the shared API. The optional lookup is `tryget`,
since `try` is a special form. The Sekreto's own redaction is `redactall`
(as in the Perl port), because `redact` is already the pure two-argument
function and both take two arguments here. And `get` shadows
`clojure.core/get`, so the namespace excludes it — a consumer requiring
`voxgig.sekreto` with an alias, which is the ordinary way, is unaffected. A
provider answers a value or `nil`, where `nil` is the miss that sends the
chain on to the next store.

## Built in, or a plugin

`voxgig.sekreto` carries the chain and the four kinds that read at most a
local file: `env`, `memory`, `dotenv`, `file`. Requiring it loads the core,
those four and voxgig/plugin, and nothing under `plugins/` — which means no
`java.net.http`, no `MessageDigest` and no `ProcessBuilder`. Every other
kind is a plugin namespace there, a voxgig/plugin definition the calling
project requires and passes in:

```clojure
(require '[voxgig.sekreto :as sekreto]
         '[voxgig.sekreto.plugins.hashicorp :refer [hashicorp]]
         '[voxgig.sekreto.plugins.aws :refer [awssecrets]])

(def secrets
  (sekreto/sekreto
   [{:kind "env"}
    {:kind "dotenv" :file ".env"}
    {:kind "hashicorp" :name "prod" :addr vaultaddr :token vaulttoken}
    {:kind "awssecrets" :region "eu-west-1"}]
   {:plugins [hashicorp awssecrets]}))

(sekreto/get secrets "api.token")             ; the chain answers
(sekreto/getfrom secrets "prod" "api.token")  ; one named store

(voxgig.plugin.host/list (:host secrets))
;; {"env" "live", "dotenv" "live", "hashicorp$prod" "live", "awssecrets" "live"}

(sekreto/close secrets)  ; every store deactivated and unloaded, in reverse
```

| | require | holds |
|---|---|---|
| the core | `voxgig.sekreto` | the chain, the name helpers, the four built-in kinds, `providerplugin`, `checkaddr` |
| one plugin | `voxgig.sekreto.plugins.<name>` | the definition (`hashicorp`, `awssecrets` + `awsparams` + `sigv4`, …) and its provider record |
| every plugin | `voxgig.sekreto.plugins` | `ALL` |

Requiring one plugin loads only that plugin — Clojure has no package
initializer to run, so a directory of namespaces gets that for free. The
trap Clojure has instead is the container: a namespace is not a definition,
and neither is a symbol naming one. Both are refused by name, saying what to
pass, as is a definition that exports no provider.

A chain is data — a vector of maps, the same shape the shared spec and an
app's config file use — so it can be read from EDN or JSON without a
translation layer. `sekreto/make` is the same constructor and also takes
live providers, for a provider of your own: anything satisfying the
`Provider` protocol. A kind that was not passed in is refused by name, with
the plugin to pass. A custom store is `(providerplugin kind make)`; see
[DOCS.md](../DOCS.md#plugins).

voxgig/plugin has no published Clojure artifact and ships no `deps.edn` of
its own, so it is not even a `:local/root`: the Makefile finds a checkout —
`PLUGIN_HOME`, then the usual places — and puts its source directory on the
classpath, and `make deps` fetches a shallow clone into `../.plugin` when
there is none. The library itself searches no path.

## Layout

| | |
|---|---|
| `src/voxgig/sekreto.clj` | the one namespace a consumer requires |
| `src/voxgig/sekreto/chain.clj` | the chain, on a voxgig/plugin host |
| `src/voxgig/sekreto/providers.clj` | `providerplugin`, `BUILTINS`, `KINDS`, and the four built-in kinds |
| `src/voxgig/sekreto/core.clj` | the names, the errors, `parsedotenv`, `redact` |
| `src/voxgig/sekreto/addr.clj` | `checkaddr`, the plaintext-address guard — pure, and on the spec |
| `src/voxgig/sekreto/provider.clj` | the two-method protocol a provider implements |
| `src/voxgig/sekreto/json.clj` | the JSON reader, writer and reads |
| `plugins/voxgig/sekreto/plugins/<name>.clj` | one plugin each; `aws.clj` carries `sigv4.clj` beside it |
| `plugins/voxgig/sekreto/plugins/httpjson.clj` | the bounded, redirect-refusing HTTP round-trip every wire plugin shares |
| `plugins/voxgig/sekreto/plugins/proc.clj` | the two-stream child run boru and secretspec share |
| `plugins/voxgig/sekreto/plugins.clj` | the full set |
| `test/voxgig/sekreto/test/main.clj` | the conformance suite |
| `test/voxgig/sekreto/test/plugins.clj` | the plugin seam, from both sides |
| `cli/sekreto/cli.clj` | the app that needs a secret |

## Use

```clojure
(require '[voxgig.sekreto :as sekreto])

(def secrets
  (sekreto/sekreto [{:kind "env"}
                    {:kind "dotenv" :file ".env"}]))

(sekreto/get secrets "api.token")
```

A chain of the four built-in kinds needs no plugin at all.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Clojure
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository, and `PLUGIN_HOME`
likewise for voxgig/plugin.

```sh
OMNI_HOME=/path/to/omni make test
```

`main.clj` carries the bridge between the two value models: the runner
hands over the spec's own JSON, keyed by string with numbers as doubles and
a marker for a key that is not there, while a provider spec here is a map
keyed by keyword. It converts field by field, so absent, null, and value
stay distinct across the boundary.

`test/voxgig/sekreto/test/plugins.clj` is the other half, and the
conformance suite cannot see any of it: that suite hands every plugin to
every chain it builds, so it can never notice a missing one. The seam tests
pin what a consumer gets — the full set holds every kind, an unloaded kind
is refused naming the fix, a sekreto error crosses the boundary and comes
back as itself — and then measure the boundary itself in a fresh JVM:
`loaded-libs` after each require, and a classpath that is this one minus
`plugins/`, on which the core still answers and a plugin namespace cannot
be found at all.

`make check-core` is the same rule read off the compiled classes. It
AOT-compiles `src` against the Clojure runtime and voxgig/plugin and
nothing else, then runs `jdeps` over the result: a plugin reached through a
type hint, an interop call or an inlined constant would show up as a class
reference whatever the require graph said, and so would an HTTP client, a
hash function or a child process.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration               # every port
./test/integration.sh clojure  # just this one
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

- **The namespace split is load order, not taste.** The provider kinds need
  the name helpers, so the namespace that defines those cannot also be the
  one that builds a chain out of kinds: a namespace cycle is a load error in
  Clojure, not a warning. `voxgig.sekreto` republishes the parts — with
  their docstrings and argument lists — so a consumer requires one thing.
- **The classpath is written out by hand**, in the Makefile, rather than
  computed by `clojure -M`. voxgig/plugin has no coordinate `deps.edn` could
  name; more to the point, the split this port keeps *is* a classpath split,
  and writing `CORECP` and `LIBCP` out is what makes it readable.
- **A sekreto error crosses the plugin boundary under the code
  `sekreto_error`** and comes back out as itself. The spec pins those
  messages byte for byte, and voxgig/plugin wraps a code-less error raised
  in `define` as `plugin_define_failed`, so `providerplugin` puts the code
  on and the chain takes it off. Any other error is not sekreto's to
  rewrite, and surfaces as the host reports it.
- **No `data.json`.** `json.clj` is a reader plus a writer, and it adds one
  value to Clojure's own: `NONE`, for "there is no value here". `parse`
  answers `NONE` for text that is not JSON and `nil` for the literal `null`,
  which is the distinction `fetchjson` needs — only the first means the
  store could not answer. `dig` walks a response body and answers `NONE` the
  moment a step is missing, so a provider never checks each step.
- **Ordered maps are built, not grown.** `array-map` keeps insertion order
  only until `assoc` grows it past eight entries, after which it promotes to
  a hash map with an order of its own. `json/omap` builds one from its pairs
  in a single step, which is what keeps a signed payload's field order and
  redaction order the same on every run.
- **HTTP/1.1, explicitly.** `java.net.http` defaults to HTTP/2, and over
  cleartext that means an h2c upgrade that sends a declared
  `Content-Length` with no body. Fastify — which Infisical is — refuses
  that outright. See the comment on `CLIENT` in `plugins/…/httpjson.clj`.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse a
  legitimate local vault.
- **A miss is not a failure.** A 404 from HashiCorp and boru's "no alias
  named" mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token or an unreachable host raises.
- **A name is split with a limit of -1**, keeping trailing empties. The
  default drops them, which would make `a.` a valid one-segment name; the
  spec says it is not. Segment matching uses `re-matches` rather than an
  anchored find, because `$` in `java.util.regex` also matches before a
  final newline — and `api.token\n` is a spec case.
- **One error type.** Every refusal is an `ex-info` carrying `:sekreto true`
  and the message the spec pins; `sekretoerror?` asks about one without
  catching by class.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Clojure is listed there.
