# sekreto — Haskell

The Haskell port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find or fetch voxgig/plugin
make test                     # the conformance suite, and the plugin seam
make check-core               # what the core binary actually contains
```

The library and the CLI depend on GHC's boot libraries, on
[voxgig/plugin](https://github.com/voxgig/plugin) and on the system
OpenSSL, and on nothing else — there is no `.cabal` file, no `stack.yaml`
and no Hackage package, so `make build` never touches a package index.
`ghc --make` is called directly and `plugins/tls.c` is compiled in beside
the Haskell. Only the conformance suite needs voxgig/omni, and only on its
own include path.

## The core, and the plugins

Four provider kinds are **built in** — `env`, `memory`, `dotenv` and
`file` — and what makes them built in is that they read at most a local
file. Everything that opens a socket, signs a request, or spawns a
process is a voxgig/plugin definition in its own module under `plugins/`,
and a `Sekreto` can build exactly the kinds its constructor was handed:

```haskell
import Hashicorp (hashicorp)
import Sekreto (Options (..), emptyoptions, sekreto)

secrets <-
  sekreto
    emptyoptions
      { optplugins = [hashicorp],
        optproviders =
          [ emptyspec {speckind = "memory", specvalues = local},
            emptyspec {speckind = "hashicorp", specaddr = addr, spectoken = token}
          ]
      }
```

Loading is explicit and never a side effect of importing: a list handed to
a constructor cannot be erased by a compiler, and the set of stores an app
can reach is not something to discover at run time. A kind that was not
passed in is refused with a message that names the fix. `AllPlugins`
carries the ten as `allplugins` for a caller that genuinely wants them
all, and importing it links every one.

**GHC's include path is the boundary.** `src/` is compiled with plugin's
sources and nothing else, so `plugins/` is not reachable from the core and
an import of it there is a compile error rather than a convention. That is
the same shape the Zig port gets from module roots, and it means the four
built-in kinds work with no plugin compiled at all.

**`make check-core` reads the built binary rather than the source.** It
compiles `test/CoreOnly.hs` — a whole working chain of the four built-in
kinds — and then reads `build/sekreto-core` with `nm` and `ldd`, by exact
symbol name:

```
the core, as built: 33 modules, 55957 symbols
  A  no plugin module of 17 (all 17 are in the CLI)
  B  none of 21 socket, exec and TLS entry points (the CLI has 8)
  C  no libssl, no libcrypto (the CLI loads both)
  D  build/sekreto-one links Hashicorp and none of the other 8 kind modules
```

Every claim there carries a control that fails if the check read nothing:
the same extraction over `build/sekreto-cli` has to find all seventeen
plugin modules and all seven network and exec entry points, because a
check that cannot see a plugin when one is linked is a check that always
passes. `A` compares Z-encoded module names as sets — `Azuresecrets` is
`Azzuresecrets` in a GHC symbol table, which is the sort of near-miss a
substring match gets wrong.

OpenSSL is here because GHC's boot libraries have **no networking at all
— not even a socket**, and because cryptographic transport is the one
thing this repository does not hand-roll. `network` would answer the first
half of that and is neither a boot library nor cryptographic transport, so
it is not taken. The audit surface is `-lssl -lcrypto`: the
distribution's OpenSSL, reached through `plugins/tls.c`, which is the only
file in the port that names it or names a socket. Everything else a
standard library would have given is in-tree — JSON, HTTP/1.1 framing,
SHA-256, HMAC-SHA256, hex, base64 — and all of it is under `plugins/`,
`sigv4` with it, because the core of no port imports a hash function.

## voxgig/plugin, and omni

voxgig/plugin has no Hackage release and there is no manifest to name one
from, so the Makefile finds a checkout and puts it on GHC's include path:
`$PLUGIN_HOME`, a sibling, or the shallow clone `make deps` fetches when
there is none. The library itself searches nothing.

The conformance suite finds voxgig/omni the same way, under `$OMNI_HOME`,
and omni never appears on the library's, the plugins' or the CLI's path.

## Layout

| | |
|---|---|
| `src/Sekreto.hs` | the facade, the plugin host, `redact` |
| `src/Providers.hs` | `ProviderSpec`, the four built-ins, `providerplugin` |
| `src/Names.hs` | the secret name, each store's spelling of it, `parsedotenv` |
| `src/Provider.hs` | the two-function record a provider is, and `SekretoError` |
| `src/Bytes.hs` | UTF-8, hex, and strict base64 decoding |
| `plugins/<Kind>.hs` | one module per plugin kind; `Aws` carries both AWS kinds |
| `plugins/AllPlugins.hs` | the full set, for a caller that wants all ten |
| `plugins/Httpjson.hs` | the HTTP-JSON round trip, and the token clock |
| `plugins/Subproc.hs` | running a child process, for `boru` and `secretspec` |
| `plugins/Http.hs` | HTTP/1.1 framing, in-tree |
| `plugins/Tls.hs`, `plugins/tls.c` | the FFI declarations, the sockets and OpenSSL |
| `plugins/Sigv4.hs`, `plugins/Crypto.hs` | AWS request signing, SHA-256 and HMAC-SHA256 |
| `plugins/Json.hs` | the JSON value model, parser and writer |
| `test/SekretoTest.hs` | the conformance suite |
| `test/PluginTest.hs` | the plugin seam, from both sides |
| `test/checkcore.py` | the split, read out of the built binaries |
| `cli/Main.hs` | the app that needs a secret |

## Use

```haskell
secrets <-
  sekreto
    emptyoptions
      { optplugins = allplugins,
        optproviders =
          [ emptyspec {speckind = "env"},
            emptyspec {speckind = "dotenv", specfile = ".env"},
            emptyspec {speckind = "hashicorp", specaddr = vaultaddr, spectoken = vaulttoken}
          ]
      }

token <- get secrets "api.token"                  -- the chain answers
same <- getfrom secrets "hashicorp" "api.token"   -- one named store
close secrets                                     -- the chain goes down
```

`ProviderSpec` is a record with an empty value for every field, so a chain
reads as configuration and record-update syntax names only what is set.
`emptyoptions` works the same way, and `optcache = False` asks the
providers afresh every time. Every configured provider is a plugin
instance on `host secrets`, named `kind` or `kind$store`, so the host
reads like the chain.

`makechain providers names cache` takes live `Provider` values instead,
for a provider of your own: a `Provider` is a record of two functions, not
a class, so the provider set stays open to a type the library has never
seen. A kind worth naming is one `providerplugin` call.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Haskell
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

That suite hands **every** plugin to every chain it builds, so it can
never notice a missing one. `test/PluginTest.hs` is the suite that can:
seventeen entries covering the full set, the CLI's own list, the
`sekreto_error` bridge, a repeated store name, a custom kind, and the
three claims `test/checkcore.py` reads out of the built binaries.

```sh
make test-plugins             # the seam alone
./build/sekreto-plugins "a store name must be a valid tag"
```

`SekretoTest.hs` carries the bridge between the two value models: omni has
a `Json` type with an `Absent` case, and this port takes plain Haskell
strings and a typed spec, so absent, null, and value stay distinct across
the boundary. It also forces every answer that a pure name function
produced, so that a refusal raised lazily inside one arrives as a subject
failure rather than somewhere later.

Those suites prove this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration               # every port
./test/integration.sh haskell  # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **A provider crosses the plugin boundary as a slot number.** plugin's
  value model carries JSON, and a `Provider` is a record of two functions,
  so a definition's `define` exports the slot it put the provider in and
  the constructor reads it back — the shape plugin's own Zig port uses for
  its error slot. The table is not a registry of kinds: importing a module
  puts nothing in it, a slot is filled by `define` and emptied as soon as
  the chain holds the provider, and construction is not claimed to be
  thread-safe across two `Sekreto` values at once.
- **`src/Names.hs` exists because Haskell has no import cycles.**
  `Providers` needs the name functions and `Sekreto` needs `Providers`, so
  the names moved down a level. The same reason puts `SekretoError` in
  `src/Provider.hs`. `Sekreto` re-exports both, so a caller reads them
  where the other ports put them.
- **No aeson.** `plugins/Json.hs` is a six-case value model plus a small
  parser. `parse` answers `Nothing` for text that is not JSON and
  `Just JNull` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer.
  Nesting is capped at 128, since a response body arrives before any trust
  check.
- **HTTP/1.1 is framed in-tree.** The TLS exception covers cryptographic
  transport only, so `plugins/Http.hs` writes the request line and reads
  the status line, the headers and the chunked body itself. A chunk is
  sliced as bytes, never as text: a chunk boundary can fall inside a
  multibyte character, and a secret with any non-ASCII character in it
  would otherwise come back broken.
- **The TLS binding verifies four things, and its own test proves each.**
  The chain, against the system trust store; the **host name**, which is a
  separate step and the half people forget — by `dNSName` with
  `SSL_set1_host`, or by `iPAddress` SAN with
  `X509_VERIFY_PARAM_set1_ip_asc`, because a name check will never match
  an address; SNI, sent for a name and never for an address, which RFC
  6066 forbids; and `SEKRETO_CA_BUNDLE`, which **adds** roots rather than
  replacing them and fails open, so a wrong path weakens nothing.
- **The digests are hand-rolled even though libcrypto is linked in.**
  `EVP_Digest` and `HMAC` are a call away in a library the plugin side
  already loads, and using them would be a rule violation rather than a
  shortcut: the exception is for transport. `plugins/Crypto.hs` is FIPS
  180-4 and RFC 2104, proved by the spec's SigV4 known-answer vectors.
- **`checkaddr` stays in the core**, because deciding whether an address
  may carry a token is a decision about configuration rather than a
  socket. It parses the address; it does not split the authority on `:`,
  which would read `[` as the host of `http://[::1]:8200` and refuse a
  legitimate local vault.
- **A miss is not a failure.** A 404 from HashiCorp and boru's `no alias
  named` mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token, an unreachable host or SecretSpec's
  `Provider backend '<name>' not found` raises.
- **A name is checked by scanning its characters**, not by matching
  `^[a-z0-9_]+$`: in four of this library's target languages `$` also
  matches before a final newline, and `api.token\n` is a spec case. The
  split keeps empty segments, so `a.` is not a valid one-segment name.
- **Laziness is forced where the moment matters.** The pure name functions
  raise with `throw`, and a thrown value inside a lazy structure surfaces
  wherever it is finally demanded — possibly outside the handler meant to
  catch it. `Provider.forced` pins each one to the point the contract
  names, so `resolve` really does validate the name before it reads the
  cache.
- **An insertion-ordered map is an association list throughout** —
  `Data.Map` orders by key, and the spec compares whole maps: a `.env`
  file's order, a `memory` provider's values and a signed request's
  headers all have to come back in the order they went in.
- The optional lookup is `tryget`, since `try` is
  [`Control.Exception.try`](https://hackage.haskell.org/package/base/docs/Control-Exception.html);
  the method form of `redact` is `redactall`, since the module-level
  `redact` keeps its name, and `all` is `getall` for the same reason. A
  provider answers `IO (Maybe String)`, where `Nothing` is the miss that
  sends the chain on to the next store.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Haskell is listed there.
