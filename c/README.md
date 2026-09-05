# sekreto — C

The C port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, the seam, the boundary
```

**Four provider kinds are built in and ten are plugins.** `env`,
`memory`, `dotenv` and `file` read at most a local file and live in
`src/`; every kind that opens a socket, signs a request or spawns a
child — the vault clients, the cloud stores, the two CLIs, and SigV4
signing with them — is a [voxgig/plugin](https://github.com/voxgig/plugin)
definition under `plugins/`, and a `sek_sekreto` can build only the kinds
its options were handed. See [Plugins](#plugins) below.

Two dependencies, and each belongs to one layer. The core depends on
**voxgig/plugin**, whose C port is the host the chain is built on; C has
no package manager, so the Makefile finds a checkout the way it finds
omni (`PLUGIN_HOME`, the usual sibling paths, or a shallow clone `make
deps` fetches) and compiles it into `build/`. The plugins depend on the
transport: `-lssl -lcrypto`. C has no TLS
and a secrets library must not hand-roll it, so this port binds the
platform's audited OpenSSL — the same library the whole C ecosystem
binds — and the audit surface is the distribution's own build, pinned to
no version, vendored nowhere, patched nowhere. `ldd build/sekreto-cli`
names libssl, libcrypto and libc, and nothing else — while a binary that
links the core alone names **libc alone**, which is what the split is
for. Everything the standard library lacks is still written in-tree:
JSON, HTTP/1.1 framing, SHA-256, HMAC-SHA256, hex, base64 and PEM.
**`libcrypto` is linked for the handshake and is never called for a
digest** — `make check-tls` runs `nm` over both archives and fails if any
object but `tls.o` reaches an OpenSSL symbol. Only the conformance suite
needs voxgig/omni, and only on its own compile line.

There is no garbage collector, so ownership is settled by not having any:
every allocation comes from one `sek_pool` arena and `sek_pool_free`
releases the lot. There is no `free` anywhere else in the port, which is
what removes the double-free, the use-after-free and the leak on the
error arm — the arm a C library gets wrong. voxgig/plugin's C port makes
the same trade, with one difference that matters: its arena is
**process-global**, so `sek_pool_free` deliberately does not reset it —
doing so would free the instance options of every other live chain in the
process. What a construction declares is held until exit.

C has no exceptions either, so a fallible call returns `sek_err` — a
pool-owned message, or `NULL` for success — and writes its result through
an out-parameter. A **miss** is `*out == NULL` with no error; a
**failure** is a message. The optional lookup is `sek_try`, and `sek_get`
is that plus a miss check.

## Layout

Three archives, and the middle one is the boundary. Nothing under `src/`
includes a header under `plugins/` or names a symbol defined there, so
`build/libsekreto.a` records no undefined symbol from either.

| | |
|---|---|
| `src/sekreto.h` | the public API, the ownership rule and the failure rule |
| `src/sekreto.c` | the facade, the chain on a plugin host, the name helpers, `parsedotenv`, `redact` |
| `src/providers.c` | the four built-in kinds, `sek_spec`, `sek_providerplugin`, `checkaddr` |
| `src/json.c` | the JSON value model, parser and writer |
| `src/util.c` | the arena, the buffer, the ordered map and list, the local-file read |
| `src/internal.h` | what the library's files share and a consumer never sees |
| `plugins/sekretoplugins.h` | the ten definitions, the full set, the transport and SigV4 |
| `plugins/support.h` | what the plugins share and the core must never link |
| `plugins/hashicorp.c` … | one translation unit per kind; `aws.c` carries both AWS kinds |
| `plugins/all.c` | `sek_allplugins`, and the only object that names all ten |
| `plugins/httpjson.c` | sockets, HTTP/1.1 framing, `sek_fetch` |
| `plugins/tls.c` | the OpenSSL binding, the only file that names it, and the PEM reader |
| `plugins/sha256.c` | SHA-256, HMAC-SHA256, hex — pulled in by `aws.c` and nothing else |
| `plugins/encode.c` | strict base64 and RFC 3986 escaping, with the transport not the signer |
| `plugins/sigv4.c` | AWS request signing |
| `plugins/proc.c` | the subprocess runner: the only object that forks |
| `plugins/clock.c` | the deadline clock, token renewal, the SigV4 timestamp |
| `test/sekretotest.c` | the conformance suite |
| `test/plugintest.c` | the plugin seam, from both sides |
| `test/checkcore.sh` | the boundary proof: `nm`, the link line, and the controls |
| `test/tlscheck.sh` | the TLS obligations, proved against a real server |
| `cli/cli.c` | the app that needs a secret |

## Use

```c
#include "sekreto.h"
#include "sekretoplugins.h"          /* only for the kinds you configure */

sek_pool *pool = sek_pool_new();
sek_spec chain[3];
Definition *plugins[1] = {sek_plugin_hashicorp()};
sek_options options;
sek_sekreto *secrets = NULL;
char *token = NULL;

chain[0] = sek_spec_new("env");
chain[1] = sek_spec_new("dotenv");
chain[1].file = ".env";
chain[2] = sek_spec_new("hashicorp");
chain[2].addr = vaultaddr;
chain[2].token = vaulttoken;

memset(&options, 0, sizeof(options));
options.providers = chain;
options.count = 3;
options.plugins = plugins;                 /* the kinds beyond the built-ins */
options.plugincount = 1;

sek_err err = sek_new(pool, &options, &secrets);
if (NULL == err) {
  err = sek_get(secrets, "api.token", &token);          /* the chain answers */
}
```

A zeroed `sek_options` is an empty chain, the four built-in kinds and
caching on. `sek_spec` is a flat struct whose every field defaults to
`NULL`, so `sek_spec_new(kind)` plus the two or three fields a kind cares
about reads as configuration. `sek_getfrom(secrets, "hashicorp",
"api.token", &token)` asks one named store instead, and a spec carrying a
live `sek_provider` in its `provider` field joins the chain as it is —
the interface is two function pointers, `lookup` and `describe`, and
`sek_provider_new` fills them in.

`sek_host(secrets)` is the voxgig/plugin host every spec'd provider is an
instance of: `host_list` names each store's ref and status, and nothing
on it advances the chain. `sek_catalog(secrets)` is what this chain can
build.

## Plugins

The calling project links the plugin objects it needs and hands their
definitions to the constructor. There is no registry and nothing is
discovered: a kind that was not passed in is unknown to that `sek_sekreto`,
and the refusal says which of the two things went wrong.

```
sekreto: unknown provider kind: doppler (available: dotenv, env, file,
memory) - doppler is a sekreto plugin, not built in: pass it in the
plugins option
```

A kind sekreto has never heard of gets no such hint, because that one is
a typo. Collapsing the two was the first thing that made the split
confusing to use.

The ten are `hashicorp`, `boru`, `awssecrets`, `awsparams`,
`gcpsecrets`, `azuresecrets`, `onepassword`, `doppler`, `infisical` and
`secretspec`; `sek_allplugins` hands back all of them at once, for a
consumer that genuinely wants all ten — the CLI, the conformance suite,
an app whose chain is decided at run time. **It is also the object to
avoid if size matters**: naming it pulls every plugin, every HTTP client,
the TLS binding, the child-process launcher and AWS request signing into
the link.

A custom kind is one call. `sek_providerplugin(slot, kind, make)` fills a
`sek_providerkind` the caller owns and answers the definition to pass:

```c
static sek_err mystore_make(sek_pool *pool, const sek_spec *spec, sek_provider **out) {
  if (sek_empty(spec->addr)) {
    return "sekreto: mystore: no addr";         /* a refusal, byte for byte */
  }
  *out = sek_provider_new(pool, mystore_lookup, mystore_describe, data);
  return NULL;
}

static sek_providerkind MYSTORE;
Definition *mystore(void) { return sek_providerplugin(&MYSTORE, "mystore", mystore_make); }
```

A `make` that refuses its own configuration answers a `sek_err`, and that
message comes back out of `sek_new` unchanged — it crosses the host under
the code `sekreto_error` and is unwrapped on the other side, because the
shared spec pins those messages byte for byte. Any other error a
hand-written `define` raises is the host's to report, not sekreto's to
rewrite. A plugin naming a **built-in** kind replaces it: that is how a
host substitutes an implementation, and never an accident, because the
four names are documented.

`sek_close` is voxgig/plugin's teardown: every instance is deactivated
and unloaded in reverse, releasing whatever a provider acquired at
activation. Afterwards nothing answers, and `sek_redact_text` still knows
every value ever resolved.

### The boundary, and how it is proved

C has no module system, so the boundary is made out of translation units,
archives and the link line — and a grep of source text proves nothing
here, because `socket`, `connect`, `fork` and `posix_spawn` are reachable
from any file with a declaration and no `#include` at all. So
`make check-core` reads the artifacts:

```sh
make check-core
```

- A binary that links `libsekreto.a` and the plugin host **and nothing
  else** compiles, runs and resolves a secret. No plugins archive on the
  command line, no `-lssl`; `ldd` on it names libc.
- `nm -u` on the core archive, matched against **exact** undefined symbol
  names — never substrings, because `connect` is a substring of
  `disconnect` and no library name a grep list carries spells `socket`.
- A **control** on that read: the core needs libc for memory and strings,
  so a symbol list with none of `malloc`/`calloc`/`free`/`memcpy`/
  `memset`/`strlen` in it is a list that was not parsed, and its empty
  intersection with the forbidden set would mean nothing.
- `ar t` on the core archive, so a Makefile edit that slips a plugin
  object in is caught even if that object needs nothing new.
- One link per kind, with the negative control that gives it teeth: a
  store that signs nothing carries no SHA-256 and a store that runs no
  child carries no launcher, **and** the aws link does carry the digest.
- A grep for the one thing a symbol table cannot see: a core file that
  `#include`s a plugins header. A preprocessor line is code, not prose.

Every archive is deleted before it is written, because `ar r` appends to
one it finds — and a stale member is exactly what would make `nm` report
a boundary that is not there.

What none of this covers, stated rather than glossed: a hash function
written out **inline** in a core file is arithmetic with no external
symbol, so neither `nm` nor any grep would see it. The rule is that the
core does not *import* a hash function, and inline arithmetic does not
violate it.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the C
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`sekretotest.c` carries the bridge between the two value models: omni has
an `omni_json` whose ABSENT case is distinct from null, and this port
takes plain C strings and a flat `sek_spec`, so absent, null, and value
stay distinct across the boundary. That is also where `sek_validname`'s C
`int` becomes the JSON boolean the spec compares — the adaptation belongs
in the test, never in the library.

That suite proves this port computes the same answers as the others. It
hands **every** plugin to every chain it builds, so it can never see a
consumer that passes the wrong list — a CLI passing one plugin instead of
ten leaves all fourteen groups green and fails nine integration checks.
`test/plugintest.c` is where that is pinned, along with the rest of the
seam: the full set holds every kind, every kind builds, a kind that was
not passed in is refused, a repeated store name numbers the instance, a
refusal crosses the host unchanged, and the core archive needs nothing
from a plugin.

```sh
make seam                    # the nineteen seam cases
./build/sekretoseam cli      # just one of them
```

What proves the library can actually *fetch* a secret is the integration
run, from the repository root:

```sh
make integration             # every port
./test/integration.sh c      # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli \
  http://127.0.0.1:8099/whoami --source hashicorp
```

Neither suite reaches a TLS handshake — `make integration` contains no
`https://` URL at all, and no case in the shared spec opens a socket. So
the binding has a gate of its own:

```sh
make tlscheck                # the four TLS obligations
```

It raises a private CA, signs one certificate that names this machine and
one that names somebody else, and drives a real handshake at each. Every
obligation is made to fail before it is made to pass.

## Notes

- **No JSON library.** `json.c` is a six-case value model, a
  recursive-descent parser and a compact writer. `sek_json_parse` answers
  `NULL` for text that is not JSON and a `SEK_JSON_NULL` node for the
  literal `null`, which is the distinction `fetchjson` needs: only the
  first means the store could not answer. Objects are insertion-ordered,
  because an AWS payload's field order is signed and the spec compares
  whole maps. The parser caps nesting at 128 — a response body arrives
  before any trust check, and `[[[[…` must not overflow the stack.
- **HTTP/1.1 is framed in-tree, and that is why the binding is OpenSSL
  and not libcurl.** libcurl is an HTTP client; taking it would carry the
  framing across the line the dependency rule draws. The client follows
  no redirects — a followed one carries `X-Vault-Token` to a host
  `checkaddr` never saw, and can downgrade https to http — reads no proxy
  variables, bounds the whole round-trip at ten seconds and the body at 8
  MiB, and dechunks over **bytes**, because a chunk boundary may fall
  inside a multibyte character.
- **The connect deadline is shared across every resolved address, not
  handed out per address.** A dual-stack name answers with both an A and
  an AAAA; ten seconds each is not a bound when the name is the
  attacker's. `connect` is started non-blocking and `poll` carries
  whatever is left of the one deadline.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault — and would read
  `http://localhost:8200@evil.example.com/` as loopback, which is the
  attack the function exists to stop.
- **A miss is not a failure.** A 404 from HashiCorp, boru's `no alias
  named`, SecretSpec's `Secret '<KEY>' not found`, an absent file or an
  absent directory all mean *this store does not hold it*, so the chain
  carries on. A locked vault, a rejected token, an unreachable host, a
  permission error and SecretSpec's `Provider backend '<x>' not found`
  all raise. The two are separate returns, never one value: a miss is
  `*out == NULL` with no error.
- **`toupper` is not used anywhere.** It follows the machine's locale,
  and in a Turkish one `i` uppercases to a character that is not `I` —
  which would give `envkey` a different answer on one machine than on
  every other. The name check is a character scan for the same family of
  reason: `^[a-z0-9_]+$` is not the check it looks like in a regex engine
  where `$` also matches before a final newline, and `api.token\n` is a
  spec case.
- **SHA-256 and HMAC are hand-rolled beside a linked libcrypto**, which
  is the rule and not an oversight: the dependency exception covers
  cryptographic *transport*. Both are proved by the SigV4 known-answer
  vectors — a signature is a chain of these primitives, so one wrong bit
  fails there. The digest is streaming rather than one-shot, so HMAC over
  an 8 MiB body needs no 8 MiB buffer.
- **The digest is its own translation unit, and so are the two
  encoders.** A static archive is pulled in an object at a time, so where
  a function lives decides what a link carries. `sha256.c` holds only the
  primitives, and `aws.c` is the only thing in the library that names
  them; `encode.c` holds base64 and percent-encoding, which four stores
  that hash nothing need to build their URLs and read their payloads. Put
  either encoder beside the signer and every one of those four would link
  SHA-256. `make check-core` links each kind on its own and reads the
  result rather than trusting the intent.
- **A provider crosses the plugin boundary as an index, not a pointer.**
  voxgig/plugin's value model carries numbers and strings, and its
  `Definition` carries no context, so a kind's `define` exports the index
  of the provider it built and `sek_new` reads it back; the pool travels
  the same way, through a file-scope slot held for the duration of one
  construction. That is the shape the zig port arrived at and the shape
  plugin's own C port uses for its pending error, and it is why `sek_new`
  is not reentrant and says so.
- **The shared `define` finds its kind through the catalog.** A
  `Definition` has no user data, so the one `define` every kind shares
  asks the host's catalog for the definition registered under this
  instance's name and casts it back to the `sek_providerkind` it is the
  first member of. That is why `def` is first in that struct, and it is
  what makes a definition data rather than a generated function per kind.
  A definition this port did not make never reaches it, and `sek_new`
  refuses it by name when it exports no provider.
- **voxgig/plugin is compiled with its own flags.** It is C11 at `-O1`;
  at this port's `-O2` gcc's `-Wclobbered` fires on three of its
  `setjmp` frames. Turning a warning off — or `-Werror` off — to make a
  checkout this port does not own compile under these flags would weaken
  the gate to suit the dependency, so the dependency is built the way its
  own build builds it and this port's flags stay as they are.
- **The TLS binding verifies four things, and each has a failing test.**
  The chain against the system trust store
  (`SSL_CTX_set_default_verify_paths` plus `SSL_VERIFY_PEER` with a
  `NULL` callback, so a bad chain aborts the handshake rather than
  waiting to be asked about). The **hostname**, which is a separate check
  and the half people forget — `SSL_set1_host` for a DNS name and
  `X509_VERIFY_PARAM_set1_ip_asc` for an IP literal, because
  `SSL_set1_host` does DNS-name matching and will not match an
  `iPAddress` SAN. **SNI**, sent for a name and withheld for an IP
  literal, which RFC 6066 forbids. And **`SEKRETO_CA_BUNDLE`**, which
  adds roots to the default store rather than replacing it, parses its
  PEM in-tree, and fails open in silence: a wrong path adds no roots and
  raises nothing.
- **`sek_show` is the print hook.** `cache` and `seen` are ordinary
  fields, so the obvious debug print of a chain would emit every resolved
  secret; this one reaches only the store names. `sek_spec_show` and
  `sek_authspec_show` do the same for a chain that will not build, which
  is exactly when someone prints one — a credential field reports
  `[set]` or `[unset]`, never its value.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
C is listed there.
