# sekreto — C

The C port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

One dependency, and it is the transport: `-lssl -lcrypto`. C has no TLS
and a secrets library must not hand-roll it, so this port binds the
platform's audited OpenSSL — the same library the whole C ecosystem
binds — and the audit surface is the distribution's own build, pinned to
no version, vendored nowhere, patched nowhere. `ldd build/sekreto-cli`
names libssl, libcrypto and libc, and nothing else. Everything the
standard library lacks is still written in-tree: JSON, HTTP/1.1 framing,
SHA-256, HMAC-SHA256, hex, base64 and PEM. **`libcrypto` is linked for
the handshake and is never called for a digest** — `make check-tls` runs
`nm` over the archive and fails if any object but `tls.o` reaches an
OpenSSL symbol. Only the conformance suite needs voxgig/omni, and only on
its own compile line.

There is no garbage collector, so ownership is settled by not having any:
every allocation comes from one `sek_pool` arena and `sek_pool_free`
releases the lot. There is no `free` anywhere else in the port, which is
what removes the double-free, the use-after-free and the leak on the
error arm — the arm a C library gets wrong.

C has no exceptions either, so a fallible call returns `sek_err` — a
pool-owned message, or `NULL` for success — and writes its result through
an out-parameter. A **miss** is `*out == NULL` with no error; a
**failure** is a message. The optional lookup is `sek_try`, and `sek_get`
is that plus a miss check.

## Layout

| | |
|---|---|
| `src/sekreto.h` | the public API, the ownership rule and the failure rule |
| `src/sekreto.c` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/providers.c` | the fourteen provider kinds, `sek_spec`, `checkaddr` |
| `src/sigv4.c` | AWS request signing |
| `src/json.c` | the JSON value model, parser and writer |
| `src/crypto.c` | SHA-256, HMAC-SHA256, hex, strict base64, PEM |
| `src/http.c` | sockets and HTTP/1.1 framing |
| `src/tls.c` | the OpenSSL binding, and the only file that names it |
| `src/proc.c` | the subprocess runner and the two clocks |
| `src/util.c` | the arena, the buffer, the ordered map and list |
| `src/internal.h` | what the library's files share and a consumer never sees |
| `test/sekretotest.c` | the conformance suite |
| `test/tlscheck.sh` | the TLS obligations, proved against a real server |
| `cli/cli.c` | the app that needs a secret |

## Use

```c
sek_pool *pool = sek_pool_new();
sek_spec chain[3];
sek_sekreto *secrets = NULL;
char *token = NULL;

chain[0] = sek_spec_new("env");
chain[1] = sek_spec_new("dotenv");
chain[1].file = ".env";
chain[2] = sek_spec_new("hashicorp");
chain[2].addr = vaultaddr;
chain[2].token = vaulttoken;

sek_err err = sek_sekreto_of(pool, chain, 3, 1, &secrets);
if (NULL == err) {
  err = sek_get(secrets, "api.token", &token);          /* the chain answers */
}
```

`sek_spec` is a flat struct whose every field defaults to `NULL`, so
`sek_spec_new(kind)` plus the two or three fields a kind cares about
reads as configuration. `sek_getfrom(secrets, "hashicorp", "api.token",
&token)` asks one named store instead, and `sek_new(pool, providers,
names, count, cache)` takes live `sek_provider` values for a provider of
your own — the interface is two function pointers, `lookup` and
`describe`.

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
takes plain C strings and a flat `sek_spec`, so absent, null and value
stay distinct across the boundary. That is also where `sek_validname`'s C
`int` becomes the JSON boolean the spec compares — the adaptation belongs
in the test, never in the library.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

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
