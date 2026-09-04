# sekreto — OCaml

The OCaml port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on the OCaml distribution and on one thing
more: **OpenSSL, for TLS and for nothing else**. OCaml has sockets in
`Unix` and no TLS at all, and TLS is the one thing this repository has
decided must not be hand-rolled — so `src/tls_stubs.c` binds `libssl` and
the `libcrypto` beneath it, exactly as ocaml-ssl and conduit do. That
binding is the whole of the port's third-party surface, and the audit
surface is the distribution's OpenSSL, not the direct edge. Everything
else a standard library lacks is written in-tree: JSON, HTTP/1.1 framing,
base64, SHA-256 and HMAC. Reaching into the already-linked `libcrypto` for
a digest would widen "cryptographic transport is not hand-rolled" into
"cryptography is not hand-rolled", which is not the rule.

There is no dune, no ocamlfind and no opam. `ocamlopt` is driven directly
from the Makefile — the same shape the sibling voxgig/plugin OCaml port
takes — which is what keeps a consumer of this library free of a package
manager, and what settles the choice between C stubs and the `ocaml-ssl`
opam package in favour of the stubs. Only the conformance suite needs
voxgig/omni, and only on its own compile line.

The optional lookup is `tryget`, since `try` is a keyword, and the chain's
own redaction is `redacttext`, since the free `redact` it delegates to
lives in the same module. Everything else keeps its canonical name. A
provider answers `string option`, where `None` is the miss that sends the
chain on to the next store, and the chain's reads are functions over a
`Sekreto.t` rather than methods. `Providers.sekreto` builds a chain from
specs; it lives beside the kind table rather than beside the facade because
OCaml compiles a module before anything that uses it, and the facade cannot
name the kind table without the kind table naming the facade back.

## Built in

All fourteen provider kinds are in `src/providers.ml` and dispatched by a
match on `spec.kind`. The plugin split is pending, as it is for the other
monolithic ports.

## Use

```ocaml
let secrets =
  Providers.sekreto
    [
      { Providers.nospec with kind = "env" };
      { Providers.nospec with kind = "dotenv"; file = ".env" };
      { Providers.nospec with kind = "hashicorp"; addr = vaultaddr; token = vaulttoken };
    ]

let token = Sekreto.get secrets "api.token"                  (* the chain answers *)
let same = Sekreto.getfrom secrets "hashicorp" "api.token"   (* one named store *)
```

`Providers.nospec` is the record with every field at its default, so a
chain reads as configuration and the compiler checks every field name.
String fields default to the empty string rather than to an option, because
"not configured" and "configured empty" mean the same thing everywhere in
this library. `Sekreto.make ~names ~cache providers` takes live providers
instead, for a provider of your own: it is a record of two functions,
`lookup` and `describe`, so the provider set stays open.

## Layout

| | |
|---|---|
| `src/sekreto.ml` | the facade, the provider record, the name helpers, `parsedotenv`, `redact` |
| `src/providers.ml` | the fourteen provider kinds, `spec`, `checkaddr`, `fetchjson`, the subprocess runner |
| `src/sigv4.ml` | AWS request signing |
| `src/crypto.ml` | SHA-256 and HMAC-SHA256 |
| `src/json.ml` | the JSON value model, reader and writer |
| `src/http.ml` | HTTP/1.1 framing over a socket, and strict base64 |
| `src/tls.ml` | the OCaml side of the TLS binding |
| `src/tls_stubs.c` | the OpenSSL binding itself, and the port's only dependency |
| `test/sekreto_test.ml` | the conformance suite |
| `test/behaviour.ml` | what the corpus cannot reach |
| `test/tlsproof.sh` | the TLS binding, against a real handshake |
| `cli/cli.ml` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the OCaml
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`test/sekreto_test.ml` carries the bridge between the two value models:
omni has a `json` type with an `Absent` case, and this port takes plain
strings and a typed `spec` record, so absent, null and value stay distinct
across the boundary. A chain is built inside each subject, never outside
it, so that a constructor refusal — `unsupported kv version` is the one the
corpus pins — reaches omni as a subject failure.

`make test` runs two more suites beside it, because **a port that passes
the corpus is not a port**. No case in `spec/sekreto.json` opens a socket,
so a port with no transport at all could pass all fourteen groups.
`test/behaviour.ml` covers what the corpus never reaches — the whole
`checkaddr` decision table, strict base64, a miss that is not a failure on
a real file, the cache and redaction lifecycle. `test/tlsproof.sh` covers
the handshake, and is described below.

That leaves what proves this port can actually *fetch* a secret, which is
the integration run, from the repository root:

```sh
make integration             # every port
./test/integration.sh ocaml  # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## The TLS proof

A TLS binding that connects but does not *verify* is worse than no TLS,
because it looks like it works — and nothing else in this repository can
catch that here. `make test` never opens a socket, `make integration`
speaks only plaintext loopback, and `make realstores` has a happy path and
an untrusted path but no negative hostname case. So `make tlscheck` (which
`make test` also runs) issues its own certificates, starts a real TLS
server on the loopback interface and proves all four obligations, negative
cases included:

```sh
make tlscheck
```

| | proved by |
|---|---|
| the chain is verified against the system trust store | an untrusted CA is refused, `certificate verify failed: unable to get local issuer certificate` |
| the **host name** is verified | a certificate for `wrong.example.com` is refused for `127.0.0.1` with `IP address mismatch` and for `localhost` with `hostname mismatch`, though the same CA signed it |
| SNI is sent, and only for a name | the server records exactly one server name, `localhost`; the IP-literal connections sent none |
| `SEKRETO_CA_BUNDLE` adds roots | our CA alone is trusted, an unrelated CA alone is not, a file holding both is, and a path that does not exist fails open in silence |

It needs `node` and the `openssl` command line, and says so and skips if
either is missing rather than passing quietly.

## Notes

- **No yojson, no ezjsonm.** `src/json.ml` is a variant plus a small
  parser. `Json.parse` answers `None` for text that is not JSON and
  `Some Json.Null` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer. The
  same reads are offered on `Json.t option` as `odig`, `otext` and
  friends, so a provider walks a response body without unwrapping at every
  step. Objects are association lists, not maps, because a payload's field
  order is signed. The parser caps nesting at 128: a response body arrives
  before any trust check, and `[[[[…` must not recurse until the stack
  gives out.
- **HTTP/1.1 is framed in-tree**, over a `Unix` socket, which is why the
  binding is `libssl` and not `libcurl` — libcurl is an HTTP client, and
  the framing has to stay here. No redirects, ever: a followed redirect
  would carry `X-Vault-Token` to a host `checkaddr` never saw, and could
  downgrade https to http. No proxies: nothing reads `http_proxy`, because
  the GCP and Azure metadata endpoints are not loopback and a proxy
  variable has sent a Vault token in the clear before.
- **One connect deadline for all of a name's addresses.** A name commonly
  resolves to several, and giving each the full ten seconds makes the real
  bound ten seconds times however many addresses the name cares to return
  — which is not a bound when the name is the attacker's.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse a
  legitimate local vault, and which reads
  `http://localhost:8200@evil.example.com/` as loopback. Userinfo is
  refused outright, on https as well as http, and every refusal routes its
  address through `safeaddr` — one of them fires precisely because the
  address carries a password that `redact` has never seen and never will.
- **A miss is not a failure.** A 404 from HashiCorp, boru's `no alias
  named`, SecretSpec's `Secret '<KEY>' not found`, AWS's
  `ResourceNotFoundException` and an absent file all mean *this store does
  not hold it*, so the chain carries on. A locked vault, a rejected token,
  an unreachable host, a permission error and SecretSpec's
  `Provider backend '<name>' not found` all raise. The empty string is a
  hit.
- **A segment is scanned, not matched.** `^[a-z0-9_]+$` is not the check it
  looks like — in several regex dialects `$` also matches before a final
  newline, and four ports accepted `api.token\n` because of it. The corpus
  pins that case, and `api\n.token` and `api.token\r` with it.
- **The subprocess runner drains both streams through one `select` loop.**
  Reading stdout to EOF and only then reading stderr deadlocks the moment
  the child writes more than one 64 KiB pipe buffer to stderr, and
  SecretSpec's box-drawn diagnostics reach that size. The child's stdin is
  closed, so a CLI that prompts for a passphrase sees EOF instead of
  waiting forever. A command that is not there is resolved before the fork,
  because `Unix.create_process` execs in the child and a failed exec would
  otherwise be indistinguishable from a command that ran and failed.
- **Ordered data is carried as association lists.** `Hashtbl` and `Map`
  answer in an order that is not the insertion order, and the spec compares
  `values`, `parsedotenv` output and the SigV4 header set as whole maps.
- **`Sekreto_error` registers a printer.** omni reads a subject's failure
  with `Printexc.to_string`, and the corpus pins refusal messages byte for
  byte; without the printer the message would arrive as
  `Sekreto.Sekreto_error("…")`.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
OCaml is listed there.
