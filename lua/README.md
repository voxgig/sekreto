# sekreto — Lua

The Lua port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, the plugin seam, the TLS check
```

Lua 5.4's whole standard library is basic, coroutine, package, string,
utf8, table, math, io, os and debug. There are no sockets of any kind, no
TLS, and `io.popen` is unidirectional and goes through a shell — so this
port carries one C program, `native/sekretonet.c`, compiled by its own
Makefile. That program links `-lssl -lcrypto`, and the distribution's
OpenSSL is the whole audit surface. Nothing else is linked beyond libc,
and there is no luarocks dependency: LuaSec and LuaSocket are both
absent, and LuaSocket would not have been covered by the rule in any
case, since a socket library is not cryptographic transport.

Everything the rule leaves in-tree is in-tree. The JSON, the HTTP/1.1
framing, SHA-256, HMAC-SHA256, hex and base64 are Lua, in
`src/sekreto/plugins/`. In particular the digests SigV4 signs with are
**not** taken from the libcrypto that is already linked: the exception
covers transport and nothing else, which is the decision the rust port
took with `ring` already inside rustls's closure. Only the conformance
suite needs voxgig/omni, and only on its own `package.path`.

The one dependency the library itself takes is
[voxgig/plugin](https://github.com/voxgig/plugin), which takes nothing:
the provider kinds are its definitions and a chain is its host. It is
required by the plain module name `plugin`, so whatever is already on the
caller's `package.path` wins; this checkout finds a sibling the way every
port finds omni, and `make deps` fetches a shallow clone when there is
none.

The optional lookup is `tryget`, since `try` cannot be written as a field
name in Lua without quoting at every call site; `secrets.try` is kept as
an alias for callers translating from canonical. A provider answers `nil`
for the miss that sends the chain on to the next store, and raises for a
store that could not answer.

Lua tables have no insertion order, so anything whose order is contract is
carried as an array of `{name, value}` pairs rather than as a table:
request headers, the JSON object writer, and the ordered map `sigv4`
answers. `parsedotenv` returns its values table and the key order
separately, for the same reason.

## Four built in, ten plugins

**The line is "reads at most a local file".** `env`, `memory`, `dotenv`
and `file` are built in and live in `src/sekreto/providers.lua`. The ten
kinds that open a socket, sign a request or spawn a process are
voxgig/plugin definitions under `src/sekreto/plugins/`, one module each,
and a `Sekreto` can build one only if the calling project handed it in:

```lua
local sekreto = require('sekreto')
local hashicorp = require('sekreto.plugins.hashicorp').hashicorp

local secrets = sekreto.sekreto({
  plugins = { hashicorp },
  providers = { { kind = 'env' }, { kind = 'hashicorp', addr = a, token = t } },
})
```

`require('sekreto.plugins').allplugins` is all ten at once, for the CLI
and for an app whose chain is decided at run time. Reaching it loads
every network client and the crypto behind them, which is the cost the
split exists to remove — an app requires the kinds it configures.

**Requiring `sekreto` loads five modules and no plugin**, so no HTTP
client, no SHA-256, and not `sekreto.plugins.net` — which means a chain
of built-in kinds never needs `build/sekreto-net`, this port's only
compiled artifact, to exist at all. Lua has no link step, so that
boundary is the module graph, and `test/test_plugins.lua` reads it out of
`package.loaded` in a fresh interpreter:

```sh
lua5.4 -e "package.path=[[src/?.lua;$PLUGIN_HOME/lua/src/?.lua;]]..package.path
  require[[sekreto]]
  local m={} for k in pairs(package.loaded) do
    if [[sekreto]]==k:sub(1,7) then m[#m+1]=k end end
  table.sort(m) print(table.concat(m,' '))"
# sekreto sekreto.addr sekreto.err sekreto.name sekreto.providers
```

A kind that was not passed in is refused with the fix in the message:

```
sekreto: unknown provider kind: doppler (available: dotenv, env, file, memory)
 - doppler is a sekreto plugin, not built in: pass it in the plugins option
```

A custom kind is one `sekreto.providerplugin(kind, make)` call, which is
also how a plugin substitutes one of the four built-ins.

## Use

```lua
local sekreto = require('sekreto')
local hashicorp = require('sekreto.plugins.hashicorp').hashicorp

local secrets = sekreto.sekreto({
  plugins = { hashicorp },
  providers = {
    sekreto.spec{ kind = 'env' },
    sekreto.spec{ kind = 'dotenv', file = '.env' },
    sekreto.spec{ kind = 'hashicorp', addr = vaultaddr, token = vaulttoken },
  },
})

local token = secrets:get('api.token')                   -- the chain answers
local same = secrets:getfrom('hashicorp', 'api.token')   -- one named store
```

`sekreto.spec` tags a plain table, so a chain reads as configuration and
prints without its credentials. A `providers` element that already has a
callable `lookup` is taken as a live provider instead, for a provider of
your own: anything with a callable `lookup` and a `describe` will do,
since providers are duck-typed rather than typed. `secrets.host` and
`secrets.catalog` are the voxgig/plugin host and catalog underneath —
`host:list()` names each store's ref and status, and reading either
advances nothing.

## Layout

| | |
|---|---|
| **the core** — five modules, and requiring `sekreto` loads exactly these | |
| `src/sekreto.lua` | the facade, the catalog and host, and the whole public surface |
| `src/sekreto/name.lua` | `validname`, `envkey`, `vaultref`, `flatname`, `awsparam`, `parsedotenv`, `redact` |
| `src/sekreto/providers.lua` | the four built-in kinds, `providerplugin` and `ProviderSpec` |
| `src/sekreto/addr.lua` | `checkaddr` and `safeaddr` |
| `src/sekreto/err.lua` | `SekretoError` |
| **the plugins** — required only by a program that names one | |
| `src/sekreto/plugins.lua` | `allplugins`, the full set, and the only file that names all ten |
| `src/sekreto/plugins/<kind>.lua` | one module per kind; `aws.lua` holds both AWS kinds |
| `src/sekreto/plugins/sigv4.lua` | AWS request signing, reached from `aws.lua` alone |
| `src/sekreto/plugins/crypto.lua` | SHA-256, HMAC-SHA256, hex, strict base64 |
| `src/sekreto/plugins/json.lua` | the JSON value model, parser and writer |
| `src/sekreto/plugins/httpjson.lua` | HTTP/1.1 framing and the one JSON round-trip |
| `src/sekreto/plugins/net.lua` | the bridge to the transport helper, and child processes |
| `src/sekreto/plugins/support.lua` | the pure helpers the store clients share; requires nothing |
| `native/sekretonet.c` | the socket, the TLS binding, and child processes |
| **the rest** | |
| `test/sekreto_test.lua` | the conformance suite |
| `test/test_plugins.lua` | the plugin seam, from both sides |
| `test/pluginhome.lua` | where voxgig/plugin is, for the tests and the CLI |
| `test/tlscheck.sh` | the TLS obligations, against `openssl s_server` |
| `cli/sekreto-cli.lua` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Lua
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
make conformance GROUP=envkey                        # one group
make plugins SEAM='the core requires no plugin'      # one seam test
```

`test/sekreto_test.lua` carries the bridge between the two value models:
omni tags every container with a metatable and carries explicit `NULL`
and `ABSENT` sentinels, because a Lua table can hold neither a `nil` nor
an ordering, while this port takes plain Lua values and plain spec
tables. Absent, null and value stay distinct across the boundary.

That suite proves this port computes the same answers as the others. It
does not prove it can fetch anything: no corpus case opens a socket, so a
build with no transport at all would pass all fourteen groups. It also
hands every plugin to every chain it builds, so it can never see a
consumer that passes the wrong set — measured here: truncating the CLI's
list to one plugin left all fourteen groups green and failed nine
integration checks. Three things answer that. `make plugins`, which
`make test` also runs, pins the seam from both sides — the full set, the
CLI's call site, the refusal of an unloaded kind, and the module graph
of the core. `make tlscheck`, which `make test` also runs, stands up
`openssl s_server` and proves the TLS binding verifies rather than merely
connects — including the negative hostname case neither shared suite has.
And the integration run, from the repository root:

```sh
make integration            # every port
./test/integration.sh lua   # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
lua5.4 cli/sekreto-cli.lua \
  http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **One dependency, and it is transport.** `native/sekretonet.c` opens
  the socket, speaks TLS through OpenSSL, and runs child processes. It
  knows nothing about HTTP: the request line, the headers, the
  length-counted and chunked bodies are framed in
  `src/sekreto/plugins/httpjson.lua`, so the binding is exactly as narrow
  as the rule allows. It is also entirely on the plugin side: the core
  never requires `src/sekreto/plugins/net.lua`, so a chain of built-in
  kinds runs on a checkout where the helper was never compiled.
- **The binding verifies, it does not merely connect.** The chain against
  the system trust store (`SSL_CTX_set_default_verify_paths` plus
  `SSL_VERIFY_PEER` with a null callback, and `SSL_get_verify_result`
  read back afterwards); the hostname, which is a separate step and a
  *different call* for an address — `X509_VERIFY_PARAM_set1_ip_asc`, not
  `SSL_set1_host`, since a DNS-name check never matches an `iPAddress`
  SAN; SNI, and not for an IP literal, which RFC 6066 forbids; and
  `SEKRETO_CA_BUNDLE`, loaded in addition to the default roots and never
  in place of them, failing open and silently on a path that does not
  read.
- **The digests are not libcrypto's.** `src/sekreto/plugins/crypto.lua` carries
  FIPS 180-4 and RFC 2104 in Lua even though libcrypto is already linked,
  because the exception is cryptographic transport and nothing else. Both
  are proved by the five SigV4 known-answer vectors in the corpus: a
  signature is a chain of these primitives, so one wrong bit anywhere
  fails there.
- **The transport request goes through a file, not a command line.**
  `io.popen` is unidirectional, so a request cannot be written to a child
  and its answer read back through the same handle. A vault token rides
  in the request headers and the process table is world readable, so the
  request is handed over in an `os.tmpname` file — `mkstemp`, and so
  already 0600 — which the helper unlinks before reading a byte of it.
- **Child processes are not `io.popen`.** That would mean a shell, a
  quoted command line, and no way to read stderr apart from stdout — and
  the miss detection for both boru and secretspec reads stderr. The
  helper forks and `execvp`s an argv array, closes the child's stdin on
  `/dev/null`, and drains both streams through one `poll`. Draining them
  in series deadlocks permanently once the child writes more than one
  64 KiB pipe buffer to stderr, which secretspec's box-drawn diagnostics
  reach easily. A failed exec is reported through a close-on-exec status
  pipe rather than guessed from an exit code, since a real child is
  equally free to exit 127.
- **No JSON library.** `src/sekreto/plugins/json.lua` is a value model plus a
  parser. `parse` answers `nil` for text that is not JSON and the `NULL`
  sentinel for the literal `null`, which is the distinction `fetchjson`
  needs: only the first means the store could not answer. Object keys
  keep their insertion order, because an AWS payload's field order is
  signed, and the parser caps recursion at 128 levels, because a response
  body arrives before any trust check has been made.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault, and it refuses userinfo outright on https as
  well as http, which is what closes
  `http://localhost:8200@evil.example.com/`.
- **A miss is not a failure.** A 404 from HashiCorp, boru's
  `no alias named`, secretspec's `Secret '<KEY>' not found`, AWS's
  `ResourceNotFoundException` and an absent file or directory all mean
  *this store does not hold it*, so the chain carries on. A locked vault,
  a rejected token, an unreachable host and secretspec's
  `Provider backend '<x>' not found` all raise. The last of those is why
  the secretspec phrase is matched whole and never on a bare `not found`.
- **A name is scanned, not matched.** `^[a-z0-9_]+$` is not the check it
  looks like: in several languages `$` also matches before a final
  newline, and four ports accepted `api.token\n`. `validname` walks the
  bytes, and `string.upper` is likewise spelled out as an ASCII map,
  since the C library's `toupper` follows the machine's locale and a
  Turkish `i` would change every key this library computes.
- **`first()` walks its arguments with `select`, never `ipairs`.** A
  `nil` argument leaves a hole in a packed table and `ipairs` stops dead
  at the first one, so `first(nil, os.getenv('AWS_ACCESS_KEY_ID'))` would
  answer empty with the variable plainly set. The same trap caught
  `test/pluginhome.lua` during the plugin conversion, from the other
  end: `$PLUGIN_HOME` was the first entry of a table constructor, an
  unset variable is a `nil`, and the whole search was skipped exactly
  when the environment was wiped — which is how `test/checks.sh` runs
  the CLI. `make test` stayed green; fifteen of the nineteen integration
  checks failed. There is a seam test for it now.
- **The 8 MiB bound is on the whole response**, headers included, rather
  than on the body alone — a few hundred bytes stricter than the ports
  that bound the body, and the difference is not reachable by anything
  real.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Lua is listed there.
