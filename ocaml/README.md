# sekreto — OCaml

The OCaml port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find or fetch voxgig/plugin
make test                     # the conformance suite, and the plugin seam
make coreproof                # what a chain of built-ins actually links
```

The library and the CLI depend on the OCaml distribution, on
[voxgig/plugin](https://github.com/voxgig/plugin), and on one thing more:
**OpenSSL, for TLS and for nothing else**. OCaml has sockets in `Unix` and
no TLS at all, and TLS is the one thing this repository has decided must
not be hand-rolled, so `plugins/tls_stubs.c` binds `libssl` and the
`libcrypto` beneath it, exactly as ocaml-ssl and conduit do. That binding
is the whole of the port's third-party surface, and the audit surface is
the distribution's OpenSSL rather than the direct edge. Everything else a
standard library lacks is written in-tree: JSON, HTTP/1.1 framing, base64,
SHA-256 and HMAC. Reaching into the already-linked `libcrypto` for a
digest would widen "cryptographic transport is not hand-rolled" into
"cryptography is not hand-rolled", which is not the rule.

There is no dune, no ocamlfind, and no opam. `ocamlopt` is driven directly
from the Makefile — the same shape the sibling voxgig/plugin OCaml port
takes — which is what keeps a consumer of this library free of a package
manager, and what settles the choice between C stubs and the `ocaml-ssl`
opam package in favour of the stubs. voxgig/plugin has no opam release
either, so the Makefile finds a checkout the way every port finds its
sibling repositories and compiles its modules into `build/plugin.cmxa`;
`make deps` fetches a shallow clone when there is none. Only the
conformance suite needs voxgig/omni, and only on its own compile line.

The optional lookup is `tryget`, since `try` is a keyword, and the chain's
own redaction is `redacttext`, since the free `redact` it delegates to
lives in the same module. Everything else keeps its canonical name. A
provider answers `string option`, where `None` is the miss that sends the
chain on to the next store, and the chain's reads are functions over a
`Sekreto.t` rather than methods. `Sekreto.sekreto` builds a chain from
specs, `Sekreto.make` from providers you built yourself.

## The core, and the plugins

Four provider kinds are **built in** — `env`, `memory`, `dotenv` and
`file` — and what makes them built in is that they read at most a local
file. Everything that opens a socket, signs a request, or spawns a process
is a [voxgig/plugin](https://github.com/voxgig/plugin) definition in its
own module under `plugins/`, and a chain can build exactly the kinds its
constructor was handed:

```ocaml
let secrets =
  Sekreto.sekreto
    ~plugins:[ Hashicorp.plugin () ]
    [
      { Provider.nospec with kind = "memory"; values = local };
      { Provider.nospec with kind = "hashicorp"; name = "prod"; addr; token };
    ]
```

Loading is explicit and never a side effect of compiling a module: a list
handed to a constructor cannot be erased, and the set of stores an app can
reach is not something to discover at run time. A kind that was not passed
in is refused with a message that names the fix. Each configured provider
is an instance on `Sekreto.host secrets`, addressed by name and tag —
`hashicorp` for a store named after its kind and `hashicorp$prod`
otherwise — so `Host.list` reads like the chain.

**The linker is the boundary here, and it is checkable.** The core is
compiled against `build/core`, a staging directory holding the core's own
interfaces and voxgig/plugin's and not one interface from `plugins/`, so a
core module that named a plugin would not compile. `make coreproof` then
reads the built artifacts back:

```
$ make coreproof
== the compilation units in build/coreonly
... Catalog Defs Export Host Json Order Point Provider Ref Secret Sekreto ...
== what each binary links beside the C runtime
  coreonly    libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6
  coreonly    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
  sekreto-cli libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3
  sekreto-cli libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3
```

`build/coreonly` is a whole program whose chain is the four built-ins.
Every compilation unit it links has one `caml<Unit>__entry` symbol, and
not one of them is `Http`, `Tls`, `Sigv4`, `Crypto` or a provider kind. So
a consumer whose chain is `[dotenv; env]` links no TLS, no HTTP client and
no request signing, and loads no OpenSSL at all. `test/plugins.ml` pins
both readings, unit by unit and by exact name, with the same extraction
run over the CLI as a control.

`sigv4` travels with the AWS plugin and `crypto.ml` with it: the core of
no port imports a hash function. `plugins/secretspec.ml` reads its store
through a child process rather than a socket, so it reaches no transport
either, which `test/plugins.ml` also pins.

A plugin value carries numbers, strings, lists and maps, never a closure,
so a definition's `define` exports the HANDLE of the provider it built and
the facade reads it back — the shape the Zig port takes for the same
reason. The instance's options map is the spec itself, under the spec's
own key names, so the map a config document would carry is the map an
instance carries.

## Use

```ocaml
let secrets =
  Sekreto.sekreto
    ~plugins:[ Hashicorp.plugin () ]
    [
      { Provider.nospec with kind = "env" };
      { Provider.nospec with kind = "dotenv"; file = ".env" };
      { Provider.nospec with kind = "hashicorp"; addr = vaultaddr; token = vaulttoken };
    ]

let token = Sekreto.get secrets "api.token"                  (* the chain answers *)
let same = Sekreto.getfrom secrets "hashicorp" "api.token"   (* one named store *)
```

`Provider.nospec` is the record with every field at its default, so a
chain reads as configuration and the compiler checks every field name.
String fields default to the empty string rather than to an option, because
"not configured" and "configured empty" mean the same thing everywhere in
this library. `Sekreto.make ~names ~cache providers` takes live providers
instead, for a provider of your own: it is a record of two functions,
`lookup` and `describe`, so the provider set stays open. A custom kind is
one call to `Provider.providerplugin`, which is what every built-in and
every shipped plugin is made of.

`Allplugins.all ()` is every kind at once, for a caller that wants all ten
— the CLI takes it, because a source named on the command line is not
known until the command line is read. An app that ships one chain names
the kinds that chain configures and links those.

## Layout

| | |
|---|---|
| `src/secret.ml` | the error, the provider record, the name helpers, `parsedotenv`, `redact` |
| `src/provider.ml` | `spec`, the four built-in kinds, `checkaddr`, `providerplugin` |
| `src/sekreto.ml` | the facade over the plugin host, and the core surface under its canonical names |
| `src/json.ml` | the JSON value model, reader and writer |
| `plugins/<kind>.ml` | one module per plugin kind; `aws.ml` carries both AWS kinds |
| `plugins/allplugins.ml` | the full set |
| `plugins/httpjson.ml` | one JSON round-trip, and the reads a response body needs |
| `plugins/http.ml` | HTTP/1.1 framing over a socket, and strict base64 |
| `plugins/tls.ml` | the OCaml side of the TLS binding |
| `plugins/tls_stubs.c` | the OpenSSL binding itself, and the port's only third-party edge |
| `plugins/sigv4.ml` | AWS request signing |
| `plugins/crypto.ml` | SHA-256 and HMAC-SHA256 |
| `plugins/runcmd.ml` | the subprocess runner |
| `test/sekreto_test.ml` | the conformance suite |
| `test/behaviour.ml` | what the corpus cannot reach |
| `test/plugins.ml` | the plugin seam, from both sides |
| `test/coreonly.ml` | a chain of built-ins as a whole program, for the link proof |
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
strings and a typed `spec` record, so absent, null, and value stay distinct
across the boundary. A chain is built inside each subject, never outside
it, so that a constructor refusal — `unsupported kv version` is the one the
corpus pins — reaches omni as a subject failure.

`make test` runs three more suites beside it, because **a port that passes
the corpus is not a port**. No case in `spec/sekreto.json` opens a socket,
so a port with no transport at all could pass all fourteen groups.
`test/behaviour.ml` covers what the corpus never reaches — the whole
`checkaddr` decision table, strict base64, a miss that is not a failure on
a real file, the cache, and redaction lifecycle.

`test/plugins.ml` covers the plugin seam. The conformance suite hands the
full set to every chain it builds, so it can never see a chain that is
missing a kind, a kind that was not passed in, or a consumer whose list is
wrong; a CLI passing one plugin instead of ten leaves all fourteen groups
green and fails nine integration checks. That suite therefore pins the
call site in `cli/cli.ml` by exact text, closing bracket included, and
reads `build/coreonly` and `build/sekreto-cli` back with `nm`, `ldd` and
`ocamlobjinfo`. Every reading carries a control: a check whose input came
back empty would otherwise pass over an unread binary.

`test/tlsproof.sh` covers the handshake, and is described below.

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
| `SEKRETO_CA_BUNDLE` adds roots | the test CA alone is trusted, an unrelated CA alone is not, a file holding both is, and a path that does not exist fails open in silence |

It needs `node` and the `openssl` command line, and says so and skips if
either is missing rather than passing silently.

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
  closed, so a CLI that prompts for a passphrase reads EOF instead of
  waiting forever. A command that is not there is resolved before the fork,
  because `Unix.create_process` execs in the child and a failed exec would
  otherwise be indistinguishable from a command that ran and failed.
- **Ordered data is carried as association lists.** `Hashtbl` and `Map`
  answer in an order that is not the insertion order, and the spec compares
  `values`, `parsedotenv` output and the SigV4 header set as whole maps.
- **`Sekreto_error` registers a printer.** omni reads a subject's failure
  with `Printexc.to_string`, and the corpus pins refusal messages byte for
  byte; without the printer the message would arrive as
  `Secret.Sekreto_error("…")`. A plugin error gets one too, so a host that
  catches what a definition raised reads the diagnostic rather than the
  constructor.
- **Three modules where canonical has one.** OCaml compiles a module
  before anything that uses it, and the facade needs the four built-in
  kinds, which need the name functions and the error. So `src/secret.ml`
  holds the floor, `src/provider.ml` the kinds, and `src/sekreto.ml` the
  facade — which re-exports every name from the first two, so a caller
  writes `Sekreto.envkey` and never has to know.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
OCaml is listed there.
