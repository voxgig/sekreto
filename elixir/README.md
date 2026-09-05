# sekreto — Elixir

The Elixir port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # both suites
make check-core               # the core reaches no plugin
```

The library and the CLI depend on nothing but Elixir, OTP and
[voxgig/plugin](https://github.com/voxgig/plugin) — `json.ex` is sekreto's
own, and the HTTP/1.1 framing in `plugins/http.ex` is written here, over
`:gen_tcp` and `:ssl`. `:crypto` supplies SHA-256 and HMAC, `:ssl` supplies
TLS, and nothing else is reached for. There is no mix project, so there is
no manifest a resolver could ever read a dependency out of: `elixirc` is
called directly and `:escript.create/2` packs the result, with Elixir's own
`ebin` and voxgig/plugin's beams alongside it, into `build/sekreto-cli`.
That escript runs from any working directory with nothing beside it. Only
the conformance suite needs voxgig/omni, and only on its code path.

voxgig/plugin has no registry to be declared in, so the Makefile finds a
checkout the way every port finds omni — `$PLUGIN_HOME`, then a sibling,
then the usual places — and `make deps` fetches a shallow clone when there
is none. The library itself searches no path.

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

Four provider kinds are **built in** — `env`, `memory`, `dotenv` and
`file`, the ones that read at most a local file. Every other kind opens a
socket, signs a request or spawns a process, and is a voxgig/plugin
definition under `plugins/` that the calling project hands to the
constructor. Nothing under `src/` names anything under `plugins/`.

| | |
|---|---|
| `src/sekreto.ex` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/providers.ex` | the four built-in kinds, `providerplugin`, `ProviderSpec` and `checkaddr` |
| `src/json.ex` | the JSON value model, reader and writer |
| `src/provider.ex` | the provider shape, and the cell a provider keeps state in |
| `plugins/<kind>.ex` | one plugin kind each: `hashicorp`, `boru`, `gcpsecrets`, `azuresecrets`, `onepassword`, `doppler`, `infisical`, `secretspec` — and `aws`, which holds both AWS stores because they share a signer |
| `plugins/plugins.ex` | `Sekreto.Plugins.all/0`, the full set |
| `plugins/http.ex` | the HTTP/1.1 client, the TLS binding, and the URL functions |
| `plugins/httpjson.ex` | one JSON round-trip, and token renewal |
| `plugins/sigv4.ex` | AWS request signing |
| `plugins/proc.ex` | the child process the two CLI-backed kinds run |
| `test/sekreto_test.exs` | the conformance suite |
| `test/plugins_test.exs` | the plugin seam, which the conformance suite cannot see |
| `tool/escript.exs` | packs the compiled modules into the escript |
| `tool/checkcore.exs` | compiles `src/` alone, and reads the beams back |
| `cli/cli.ex` | the app that needs a secret |

## Use

```elixir
secrets =
  Sekreto.new(
    [
      %Sekreto.ProviderSpec{kind: "env"},
      %Sekreto.ProviderSpec{kind: "dotenv", file: ".env"},
      %Sekreto.ProviderSpec{
        kind: "hashicorp",
        addr: vaultaddr,
        token: vaulttoken
      }
    ],
    plugins: [Sekreto.Plugins.Hashicorp.hashicorp()]
  )

token = Sekreto.get(secrets, "api.token")                  # the chain answers
same = Sekreto.getfrom(secrets, "hashicorp", "api.token")  # one named store
```

`ProviderSpec` is a struct, so a chain reads as configuration and every
field has a name. `Sekreto.new/2` takes live providers instead, or a mix
of the two: anything that is a map with a one-argument `lookup` is a
provider, so a caller's own three-line map counts. It also accepts one
options list, which is how every other port spells it and what
[DOCS.md](../DOCS.md) documents — `Sekreto.new(plugins: …, providers: …)`.

`plugins` is the set of kinds beyond the four built-ins this chain may
name. A kind that was not passed in cannot be built, and naming one says
so:

    sekreto: unknown provider kind: doppler (available: dotenv, env, file,
    hashicorp, memory) - doppler is a sekreto plugin, not built in: pass
    it in the plugins option

`Sekreto.Plugins.all/0` is every shipped kind at once, for the CLI, the
conformance suite, and an app whose chain is decided at run time. Reaching
it reaches every network client, AWS request signing and the TLS binding
under them, which is the cost the split exists to remove — so an app names
the kinds it configures.

A custom kind is one call:

```elixir
mystore =
  Sekreto.providerplugin("mystore", fn spec ->
    %{lookup: fn name -> ... end, describe: fn -> "mystore:" <> spec.addr end}
  end)
```

Each store built from a spec is an instance on `secrets.host`, the
voxgig/plugin host, addressed `kind` or `kind$store`; `secrets.catalog`
holds the definitions this chain can build. Nothing is contacted by
construction, and `Sekreto.close/1` deactivates and unloads every instance
in reverse.

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

`make test` runs a second suite, `plugins_test.exs`, for what the first
cannot see. The conformance suite hands every plugin to every chain it
builds, so it can never notice a kind that was not passed in, nor a
consumer that passed the wrong ones — a CLI passing one plugin instead of
ten leaves all fourteen groups green and fails nine integration checks.
Seventeen tests pin the seam: the full set, that every kind builds, the
CLI's own call, the refusals, the numbered tags, the `sekreto_error`
bridge, the boundary itself — and the one pair of opposite answers to a
single call, `Integer.to_string(n, 16)`, which `src/json.ex` lowercases
and `plugins/http.ex` must not. Flipping either passes all fourteen
conformance groups and all nineteen integration checks, so a comment in
each file was all that held them apart; now the whole control range and
every byte are pinned.

`make check-core` is the boundary, proved twice. `src/` is compiled ALONE,
with only voxgig/plugin on the code path: a core module that so much as
named `Sekreto.Plugins.Hashicorp` would fail there, because `elixirc`
warns on a call into a module that is not available and this port compiles
with `--warnings-as-errors`. Then every beam it produced is read back
through its `imports` chunk — the exact `{module, function, arity}` of
every remote call the compiler emitted, which is this runtime's link map —
and refused if it names a plugin module, a socket, a hash function or a
child process.

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
- **Loading is explicit, and the BEAM makes it cheap.** A module is loaded
  the first time something calls into it, so `Sekreto.Plugins.Hashicorp`
  never brings the other nine with it, and even the full set loads no HTTP
  client until a lookup makes one. That laziness is the runtime's, not this
  port's — what this port decides is which kinds a chain may name, and that
  is the list handed to the constructor. There is no registry, and nothing
  is loaded by name.
- **Provider state lives in a process.** Nothing on the BEAM is mutable,
  so a memoised `.env`, a logged-in token and a resolved 1Password vault
  id are held in a `Sekreto.Cell` — an Agent, linked to whoever built the
  provider. No I/O runs inside it: a read that took the full transport
  bound would outlive the Agent's own call timeout.

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Elixir is listed there.
