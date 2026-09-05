# sekreto — Clojure

The Clojure port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but the JDK and Clojure itself —
`json.clj` is sekreto's own, and HTTP is `java.net.http.HttpClient`, pinned
to HTTP/1.1. `deps.edn` declares no `:deps` at all: there is no
`data.json`, no `cheshire` and no `clj-http`. The CLI is AOT-compiled into
`build/sekreto-cli.jar` with the Clojure runtime folded in, so it runs under
a bare `java -cp` — which is what the integration suite needs, since it runs
every port's CLI from an empty directory. Only the conformance suite needs
voxgig/omni, and only on its classpath.

Three names differ from the shared API. The optional lookup is `tryget`,
since `try` is a special form. The Sekreto's own redaction is `redactall`
(as in the Perl port), because `redact` is already the pure two-argument
function and both take two arguments here. And `get` shadows
`clojure.core/get`, so the namespace excludes it — a consumer requiring
`voxgig.sekreto` with an alias, which is the ordinary way, is unaffected. A
provider answers a value or `nil`, where `nil` is the miss that sends the
chain on to the next store.

## Layout

| | |
|---|---|
| `src/voxgig/sekreto.clj` | the one namespace a consumer requires |
| `src/voxgig/sekreto/core.clj` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/voxgig/sekreto/providers.clj` | the fourteen provider kinds and `makeprovider` |
| `src/voxgig/sekreto/sigv4.clj` | AWS request signing |
| `src/voxgig/sekreto/json.clj` | the JSON reader, writer and reads |
| `src/voxgig/sekreto/provider.clj` | the two-method protocol a provider implements |
| `test/voxgig/sekreto/test/main.clj` | the conformance suite |
| `cli/sekreto/cli.clj` | the app that needs a secret |

## Use

```clojure
(require '[voxgig.sekreto :as sekreto])

(def secrets
  (sekreto/sekreto
   [{:kind "env"}
    {:kind "dotenv" :file ".env"}
    {:kind "hashicorp" :addr vaultaddr :token vaulttoken}]))

(sekreto/get secrets "api.token")                  ; the chain answers
(sekreto/getfrom secrets "hashicorp" "api.token")  ; one named store
```

A chain is data — a vector of maps, the same shape the shared spec and an
app's config file use — so it can be read from EDN or JSON without a
translation layer. `sekreto/make` takes live providers instead, for a
provider of your own: anything that satisfies the `Provider` protocol.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Clojure
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`main.clj` carries the bridge between the two value models: the runner
hands over the spec's own JSON, keyed by string with numbers as doubles and
a marker for a key that is not there, while a provider spec here is a map
keyed by keyword. It converts field by field, so absent, null, and value
stay distinct across the boundary.

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
  Clojure, not a warning. `voxgig.sekreto` republishes both halves — with
  their docstrings and argument lists — so a consumer requires one thing.
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
  that outright. See the comment on `CLIENT` in `providers.clj`.
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
