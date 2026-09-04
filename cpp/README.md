# sekreto — C++

The C++ port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on the C++17 standard library and one
linked library, OpenSSL — `-lssl -lcrypto`, and the distribution's OpenSSL
is the audit surface. C++ has no TLS, and cryptographic transport is the
one thing this repository does not hand-roll, so this port binds the same
library every C++ program that speaks https binds. It is bound directly
rather than through Boost.Asio's SSL stream or cpp-httplib, because those
are HTTP frameworks and the framing has to stay in-tree. Everything else a
standard library lacks is written here: JSON, HTTP/1.1, SHA-256, HMAC,
base64 and PEM. Only the conformance suite needs voxgig/omni, and only on
its own include path.

The optional lookup is `tryget`, since `try` is a keyword. A provider
answers `std::optional<std::string>`, where `std::nullopt` is the miss that
sends the chain on to the next store, and a thrown `SekretoError` is a
store that could not answer at all.

## Built in

Every ordered map is a `std::vector<std::pair<...>>` rather than a
`std::map`, which orders by key: the shared spec compares whole maps, and a
signed AWS payload's field order is part of what was signed.

## Layout

| | |
|---|---|
| `src/Sekreto.cpp` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.cpp` | the fourteen provider kinds and `ProviderSpec` |
| `src/Sigv4.cpp` | AWS request signing |
| `src/Json.cpp` | the JSON value model, parser and writer |
| `src/Crypto.cpp` | SHA-256, HMAC-SHA256, hex and strict base64 |
| `src/Http.cpp` | HTTP/1.1 framing over a POSIX socket |
| `src/Tls.cpp` | the OpenSSL binding, and the only file that names it |
| `src/Provider.hpp` | the two-method interface a provider implements |
| `test/SekretoTest.cpp` | the conformance suite |
| `test/TlsTest.cpp` | the certificate checks no other suite reaches |
| `cli/Cli.cpp` | the app that needs a secret |

## Use

```cpp
sekreto::ProviderSpec fromenv;
fromenv.kind = "env";

sekreto::ProviderSpec fromfile;
fromfile.kind = "dotenv";
fromfile.file = ".env";

sekreto::ProviderSpec fromvault;
fromvault.kind = "hashicorp";
fromvault.addr = vaultaddr;
fromvault.token = vaulttoken;

sekreto::Sekreto secrets = sekreto::makesekreto({fromenv, fromfile, fromvault});

std::string token = secrets.get("api.token");                  // the chain answers
std::string same = secrets.getfrom("hashicorp", "api.token");  // one named store
```

`ProviderSpec` is a plain aggregate, so a chain reads as configuration and
the compiler checks every field. String fields default to the empty string
rather than to an optional, because "not configured" and "configured
empty" mean the same thing everywhere in this library.
`Sekreto(providers, names, cache)` takes live `Provider` instances
instead, for a provider of your own.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the C++
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`SekretoTest.cpp` carries the bridge between the two value models: omni's
`Json` has an `Absent` case, this port's has not, and the conversion is
written out so that absent, null and value stay distinct across the
boundary. `specof` maps a spec entry onto a `ProviderSpec`, and every chain
is built inside the subject, so a constructor refusal — `unsupported kv
version` — reaches omni as a subject error rather than aborting the run.

`make test` also runs `test/TlsTest.cpp`, which mints a certificate,
serves it, and asserts what a green corpus cannot: that an untrusted
certificate is refused, and that a *trusted* certificate issued for
another host is refused too.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration            # every port
./test/integration.sh cpp   # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
./build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **No nlohmann/json, no RapidJSON.** `Json.cpp` is a six-case value model
  and a small parser. `Json::parse` answers `false` for text that is not
  JSON and `true` with a `Null` for the literal `null`, which is the
  distinction `fetchjson` needs: only the first means the store could not
  answer. The parser caps nesting at 128, because a response body arrives
  before anything about it has been trusted.
- **The TLS binding is four obligations, not one.** `src/Tls.cpp` verifies
  the chain against the system trust store, verifies the *hostname*
  separately — `SSL_set1_host` for a name, `X509_VERIFY_PARAM_set1_ip_asc`
  for an address, which is a different call and the one people forget —
  sends SNI for a name and not for an address, and adds the roots in
  `SEKRETO_CA_BUNDLE` on top of the system ones. The bundle is additive
  and fails open: a path naming nothing adds no roots and raises nothing.
- **libcrypto's digests are not used for SigV4.** The exception that
  permits the link covers transport only, so `Crypto.cpp` carries SHA-256
  and HMAC in-tree — the same line `rust/src/crypto.rs` holds beside
  rustls.
- **HTTP/1.1 is written by hand**, with no redirects and no proxies. A
  followed redirect would carry `X-Vault-Token` to a host `checkaddr`
  never saw and could downgrade https to http; a proxy in the environment
  has sent a Vault token in the clear before, and the GCP and Azure
  metadata endpoints are not loopback.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault — and would read
  `http://localhost:8200@evil.example.com/` as loopback.
- **A miss is not a failure.** A 404 from HashiCorp and boru's `no alias
  named` mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token or an unreachable host raises. The
  subprocess kinds drain stdout and stderr concurrently for the same
  reason: a child that writes more than one pipe buffer of diagnostics
  would otherwise deadlock for ever, and `get()` would simply never
  return.
- **A name is scanned, not matched against `^[a-z0-9_]+$`.** In most regex
  dialects `$` also matches before a final newline, and `api.token\n` is a
  spec case. Uppercasing is an explicit ASCII map for the same kind of
  reason: `toupper` is locale-sensitive, and `envkey` must answer the same
  everywhere.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
C++ is listed there.
