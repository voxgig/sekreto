# sekreto — Elixir

The Elixir port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

The library and the CLI depend on nothing but Elixir and OTP — `json.ex`
is sekreto's own, and the HTTP/1.1 framing in `http.ex` is written here,
over `:gen_tcp` and `:ssl`. `:crypto` supplies SHA-256 and HMAC, `:ssl`
supplies TLS, and nothing else is reached for. There is no mix project, so
there is no manifest a resolver could ever read a dependency out of:
`elixirc` is called directly and `:escript.create/2` packs the result,
with Elixir's own `ebin` alongside it, into `build/sekreto-cli`. That
escript runs from any working directory with nothing beside it. Only the
conformance suite needs voxgig/omni, and only on its code path.

The optional lookup is `tryget`, since `try` is a special form. A provider
answers a string, or `nil` — the miss that sends the chain on to the next
store; the empty string is a value, not a miss. The facade's redaction is
`redactall/2`, because the module-level `redact/2` — the pure function
over an explicit list of values — takes two arguments too.

Anything whose order is part of its meaning is carried as an ordered list
of `{key, value}` pairs rather than as a map: `parsedotenv/1`, a memory
provider's `values`, a JSON object, and the headers SigV4 signs. Elixir
maps have no order at all once they grow past a handful of keys, and a
payload's field order is signed.

## Layout

| | |
|---|---|
| `src/sekreto.ex` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/providers.ex` | the provider kinds, `ProviderSpec` and `checkaddr` |
| `src/http.ex` | the HTTP/1.1 client, and the TLS binding |
| `src/sigv4.ex` | AWS request signing |
| `src/json.ex` | the JSON value model, reader and writer |
| `src/provider.ex` | the provider shape, and the cell a provider keeps state in |
| `test/sekreto_test.exs` | the conformance suite |
| `tool/escript.exs` | packs the compiled modules into the escript |
| `cli/cli.ex` | the app that needs a secret |

## Use

```elixir
secrets =
  Sekreto.new([
    %Sekreto.ProviderSpec{kind: "env"},
    %Sekreto.ProviderSpec{kind: "dotenv", file: ".env"},
    %Sekreto.ProviderSpec{kind: "hashicorp", addr: vaultaddr, token: vaulttoken}
  ])

token = Sekreto.get(secrets, "api.token")                  # the chain answers
same = Sekreto.getfrom(secrets, "hashicorp", "api.token")  # one named store
```

`ProviderSpec` is a struct, so a chain reads as configuration and every
field has a name. `Sekreto.new/2` takes live providers instead, or a mix
of the two: anything that is a map with a one-argument `lookup` is a
provider, so a caller's own three-line map counts.

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Elixir
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

```sh
OMNI_HOME=/path/to/omni make test
```

`sekreto_test.exs` carries the bridge between the two value models: omni's
are plain Elixir values with absence marked by an atom of its own, and
this port takes typed specs, ordered pair lists and `nil` for a miss, so
absent, null and value stay distinct across the boundary. The chain is
built inside each subject rather than beside it, because four corpus
entries expect a refusal the constructor raises.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh elixir  # just this one
```

It starts a token-protected API and stand-in HashiCorp, AWS, GCP, Azure,
1Password, Doppler and Infisical servers (plus a real boru vault), then
runs this port's CLI against them from each secret source in turn:

```sh
make build
build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## Notes

- **No Jason, no Poison.** `json.ex` is a tagged-tuple value model plus a
  small parser. `Json.parse` answers `:error` for text that is not JSON
  and `{:ok, :null}` for the literal `null`, which is the distinction
  `fetchjson` needs: only the first means the store could not answer. OTP
  27 ships `:json` and Elixir 1.18 a `JSON` module; neither is used, and
  neither is reached for conditionally, because the OTP 25 that Ubuntu
  24.04 packages has neither — a port that used one where it found one
  would behave differently on two releases of the same runtime.
- **The HTTP framing is in-tree, and `:httpc` is not used.** Three of this
  library's rules are not expressible through it: the 8 MiB body bound
  (httpc buffers the whole body before the caller receives a byte), the single
  ten-second deadline across connect, send and read, and the rule
  that no proxy is consulted — httpc's proxy, redirect and cookie settings
  live on a shared profile a host application may already have configured.
  Response headers are still decoded by OTP's `{:packet, :http_bin}` mode,
  which is the runtime's, not a dependency's.
- **TLS is `:ssl`, and it is the audit surface.** Cryptographic transport
  is never hand-rolled. The binding lives in one file and does all four of
  the things a binding must: `verify: :verify_peer` against
  `:public_key.cacerts_get/0`; hostname verification through
  `pkix_verify_hostname_match_fun(:https)`, and for an IP literal an
  explicit `pkix_verify_hostname` against the certificate's `iPAddress`
  name, which DNS-name matching would never make; SNI, sent for a name and
  never for an address, which RFC 6066 forbids; and `SEKRETO_CA_BUNDLE`
  parsed with `:public_key.pem_decode/1` and **added** to the platform
  roots, failing open in silence when the file is unreadable.
- **`checkaddr` parses the address**; it does not split the authority on
  `:`, which would read `[` as the host of `http://[::1]:8200` and refuse
  a legitimate local vault — and would read
  `http://localhost:8200@evil.example.com/` as loopback.
- **A miss is not a failure.** A 404 from HashiCorp and boru's "no alias
  named" mean *this store does not hold it*, so the chain carries on. A
  locked vault, a rejected token or an unreachable host raises. SecretSpec
  is matched on the whole phrase `Secret '<KEY>' not found`, never on
  "not found", because it words a missing backend the same way and that is
  a store which could not answer at all.
- **A child process is started through `sh`, and its stderr goes to a
  file.** The BEAM's ports cannot hand a parent the child's stderr on a
  channel of its own, and boru's and SecretSpec's miss detection is a
  phrase they print there. Redirecting it also delivers the other two
  obligations: `</dev/null` gives a CLI that prompts for a passphrase an
  EOF instead of a hang, and a child writing megabytes to stderr cannot
  deadlock, because no pipe is being drained. The arguments travel as
  `$0` and `$@` and the redirect target arrives in the environment, so
  nothing is ever parsed by the shell.
- **A name is scanned byte by byte**, not matched against
  `^[a-z0-9_]+$`. In four of the regex flavours these ports use, `$` also
  matches before a final newline — and `api.token\n` is a spec case.
- **Provider state lives in a process.** Nothing on the BEAM is mutable,
  so a memoised `.env`, a logged-in token and a resolved 1Password vault
  id are held in a `Sekreto.Cell` — an Agent, linked to whoever built the
  provider. No I/O runs inside it: a read that took the full transport
  bound would outlive the Agent's own call timeout.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Elixir is listed there.
