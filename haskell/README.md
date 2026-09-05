# sekreto — Haskell

The Haskell port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on GHC's boot libraries and on the
system OpenSSL, and on nothing else — there is no `.cabal` file, no
`stack.yaml` and no Hackage package, so `make build` never touches a
package index. `ghc --make` is called directly and `src/tls.c` is compiled
in beside the Haskell. Only the conformance suite needs voxgig/omni, and
only on its own include path.

OpenSSL is here because GHC's boot libraries have **no networking at all
— not even a socket**, and because cryptographic transport is the one
thing this repository does not hand-roll. `network` would answer the first
half of that and is neither a boot library nor cryptographic transport, so
it is not taken. The audit surface is `-lssl -lcrypto`: the
distribution's OpenSSL, reached through `src/tls.c`, which is the only
file in the port that names it or names a socket. Everything else a
standard library would have given is in-tree — JSON, HTTP/1.1 framing,
SHA-256, HMAC-SHA256, hex, base64.

The optional lookup is `tryget`, since `try` is
[`Control.Exception.try`](https://hackage.haskell.org/package/base/docs/Control-Exception.html);
the method form of `redact` is `redactall`, since the module-level
`redact` keeps its name, and `all` is `getall` for the same reason. A
provider answers `IO (Maybe String)`, where `Nothing` is the miss that
sends the chain on to the next store.

An insertion-ordered map is an association list throughout — `Data.Map`
orders by key, and the spec compares whole maps: a `.env` file's order, a
`memory` provider's values and a signed request's headers all have to come
back in the order they went in.

## Layout

| | |
|---|---|
| `src/Sekreto.hs` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.hs` | the provider kinds and `ProviderSpec` |
| `src/Sigv4.hs` | AWS request signing |
| `src/Json.hs` | the JSON value model, parser and writer |
| `src/Http.hs` | HTTP/1.1 framing, in-tree |
| `src/Tls.hs` | the FFI declarations, and a connection |
| `src/tls.c` | the transport binding: sockets, and OpenSSL |
| `src/Crypto.hs` | SHA-256 and HMAC-SHA256 |
| `src/Bytes.hs` | UTF-8, hex, and strict base64 decoding |
| `src/Provider.hs` | the two-function record a provider is |
| `test/SekretoTest.hs` | the conformance suite |
| `cli/Main.hs` | the app that needs a secret |

## Use

```haskell
secrets <-
  sekreto
    [ emptyspec {speckind = "env"},
      emptyspec {speckind = "dotenv", specfile = ".env"},
      emptyspec {speckind = "hashicorp", specaddr = vaultaddr, spectoken = vaulttoken}
    ]
    True

token <- get secrets "api.token"                  -- the chain answers
same <- getfrom secrets "hashicorp" "api.token"   -- one named store
```

`ProviderSpec` is a record with an empty value for every field, so a chain
reads as configuration and record-update syntax names only what is set.
`makechain providers names cache` takes live `Provider` values instead, for
a provider of your own: a `Provider` is a record of two functions, not a
class, so the provider set stays open to a type the library has never seen.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Haskell
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`SekretoTest.hs` carries the bridge between the two value models: omni has
a `Json` type with an `Absent` case, and this port takes plain Haskell
strings and a typed spec, so absent, null, and value stay distinct across
the boundary. It also forces every answer that a pure name function
produced, so that a refusal raised lazily inside one arrives as a subject
failure rather than somewhere later.

That suite proves this port computes the same answers as the others. What
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

- **No aeson.** `Json.hs` is a six-case value model plus a small parser.
  `parse` answers `Nothing` for text that is not JSON and `Just JNull` for
  the literal `null`, which is the distinction `fetchjson` needs: only the
  first means the store could not answer. Nesting is capped at 128, since
  a response body arrives before any trust check.
- **HTTP/1.1 is framed in-tree.** The TLS exception covers cryptographic
  transport only, so `src/Http.hs` writes the request line and reads the
  status line, the headers and the chunked body itself. A chunk is sliced
  as bytes, never as text: a chunk boundary can fall inside a multibyte
  character, and a secret with any non-ASCII character in it would
  otherwise come back broken.
- **The TLS binding verifies four things, and its own test proves each.**
  The chain, against the system trust store; the **host name**, which is a
  separate step and the half people forget — by `dNSName` with
  `SSL_set1_host`, or by `iPAddress` SAN with
  `X509_VERIFY_PARAM_set1_ip_asc`, because a name check will never match
  an address; SNI, sent for a name and never for an address, which RFC
  6066 forbids; and `SEKRETO_CA_BUNDLE`, which **adds** roots rather than
  replacing them and fails open, so a wrong path weakens nothing.
- **The digests are hand-rolled even though libcrypto is linked in.**
  `EVP_Digest` and `HMAC` are a call away in a library this port already
  loads, and using them would be a rule violation rather than a shortcut:
  the exception is for transport. `src/Crypto.hs` is FIPS 180-4 and RFC
  2104, proved by the spec's SigV4 known-answer vectors.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault.
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

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Haskell is listed there.
