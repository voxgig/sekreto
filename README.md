# sekreto

**One interface for secrets, wherever they live.**

An app asks for `api.token`. It never learns whether that value came from
an environment variable, a `.env` file, HashiCorp Vault or a boru vault —
and it does not have to change when the answer changes. Moving from
`.env` in development to a vault in production is a config change, not a
code change.

The same library is available in twelve languages, all behaving
identically, because they all run the same shared test spec through
[voxgig/omni](https://github.com/voxgig/omni).

```ts
import { Sekreto } from '@voxgig/sekreto'
import { hashicorp } from '@voxgig/sekreto/plugins/hashicorp'
import { boru } from '@voxgig/sekreto/plugins/boru'

const secrets = new Sekreto({
  plugins: [hashicorp, boru],                              // the stores this app can reach
  providers: [
    { kind: 'env' },                                       // local overrides
    { kind: 'dotenv', file: '.env' },                      // developer machines
    { kind: 'hashicorp', addr: VAULT_ADDR, token: ... },   // production
    { kind: 'boru' },                                      // a local boru vault
  ],
})

// Transparent: the first store that has it wins, and the app never learns
// which one answered.
const token = await secrets.get('api.token')

// Directed: name the store, and only that store is asked.
const staging = await secrets.getfrom('hashicorp', 'api.token')
```

**Transparent** is the default, and the reason the library exists: one chain
covers every environment the app runs in, and moving a secret between stores
changes no code.

**Directed** is for when *which* store holds a secret is part of what you
mean - promoting a value between environments, checking that a secret really
landed in the vault, or reading two stores that both hold `api.token` and
meaning a particular one. `stores()` lists what can be named. Naming a store
that is not in the chain raises rather than missing: `try` already means
"this store may not have it", so it cannot also mean "this store may not
exist" without hiding a typo.

## Built in, or a plugin

Every port has the same **four built-in provider kinds** — the ones that
read at most a local file, and need no socket, no TLS, no crypto and no
child process:

| kind | reads |
|---|---|
| `memory` | literal values, given as options — for tests and defaults |
| `env` | environment variables |
| `dotenv` | a plaintext `.env` file |
| `file` | a directory of one-secret-per-file entries — a mounted Kubernetes or Docker secret |

A chain of those works with nothing else loaded. **Everything that opens
a socket, signs a request or spawns a process is a plugin**: each store
client is a [voxgig/plugin](https://github.com/voxgig/plugin) definition
in the port's `plugins/` folder, and the calling project hands the ones
it needs to `Sekreto` at construction — statically, in code, so a build
carries exactly the store clients it configures and a chain of `[dotenv,
env]` carries no AWS request signing and no HTTP vault client at all.

| plugin | kinds | needs |
|---|---|---|
| `hashicorp` | `hashicorp` | HTTPS (and the filesystem, for a kubernetes JWT) |
| `boru` | `boru` | a child process, or HTTPS in wire mode |
| `aws` | `awssecrets`, `awsparams` | HTTPS and HMAC-SHA256 — the one crypto dependency, kept out of the core |
| `gcpsecrets` | `gcpsecrets` | HTTPS |
| `azuresecrets` | `azuresecrets` | HTTPS |
| `onepassword` | `onepassword` | HTTPS |
| `doppler` | `doppler` | HTTPS |
| `infisical` | `infisical` | HTTPS |
| `secretspec` | `secretspec` | a child process |

The plugin mechanism is voxgig/plugin's, not sekreto's own: a provider
kind is a plugin *definition*, a configured store is an *instance*
addressed by name and tag (`hashicorp$prod`), and `secrets.host` is the
plugin host they live on. The design, and what each port owes it, is
[`docs/design/plugin-providers.md`](docs/design/plugin-providers.md).

### Per language

A port adopts the plugin architecture once voxgig/plugin has a port of
its language to stand on. Until then it ships every kind in one module
behind a `kind` switch, with the same four built-ins and the same ten
plugin kinds — the *set* is identical everywhere; only how the store
clients are loaded differs.

| | plugin architecture | plugins live in | voxgig/plugin port |
|---|---|---|---|
| [typescript](typescript/) *(canonical)* | ✅ | `typescript/plugins/` | `@voxgig/plugin` |
| [go](go/) | ✅ | `go/plugins/<kind>/` | `github.com/voxgig/plugin/go` |
| [python](python/) | ✅ | `python/voxgig_sekreto/plugins/` | `voxgig-plugin` (from git) |
| [javascript](javascript/) | switch — pending | | exists |
| [ruby](ruby/) | switch — pending | | exists |
| [php](php/) | switch — pending | | exists |
| [perl](perl/) | switch — pending | | exists |
| [rust](rust/) | switch — pending | | exists |
| [java](java/) | switch — pending | | exists |
| [csharp](csharp/) | switch — pending | | exists |
| [kotlin](kotlin/) | switch — pending | | exists |
| [zig](zig/) | switch — **no plugin port yet** | | not yet — check again |

**typescript** — one import per plugin, or the full set from
`@voxgig/sekreto/plugins`:

```ts
import { Sekreto } from '@voxgig/sekreto'
import { hashicorp } from '@voxgig/sekreto/plugins/hashicorp'
import { awssecrets } from '@voxgig/sekreto/plugins/aws'

const secrets = new Sekreto({
  plugins: [hashicorp, awssecrets],
  providers: [
    { kind: 'env' },
    { kind: 'hashicorp', name: 'prod', addr: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN },
    { kind: 'awssecrets', region: 'eu-west-1' },
  ],
})

const token = await secrets.get('api.token')     // the chain answers
const prod = await secrets.getfrom('prod', 'api.token')   // one store answers
secrets.host.list()   // { env: 'live', 'hashicorp$prod': 'live', awssecrets: 'live' }
```

**go** — one package per plugin, linked only when imported, or all of
them from `plugins`:

```go
import (
    plugin "github.com/voxgig/plugin/go/plugin"

    "github.com/voxgig/sekreto/go/plugins/aws"
    "github.com/voxgig/sekreto/go/plugins/hashicorp"
    "github.com/voxgig/sekreto/go/sekreto"
)

secrets, err := sekreto.New(&sekreto.Options{
    Plugins: []plugin.Definition{hashicorp.Plugin, aws.Secrets},
    Providers: []*sekreto.ProviderSpec{
        {Kind: "env"},
        {Kind: "hashicorp", Name: "prod", Addr: os.Getenv("VAULT_ADDR"), Token: os.Getenv("VAULT_TOKEN")},
        {Kind: "awssecrets", Region: "eu-west-1"},
    },
})

token, err := secrets.Get("api.token")
prod, err := secrets.GetFrom("prod", "api.token")
secrets.Host().List()   // map[env:live hashicorp$prod:live awssecrets:live]
```

**python** — one module per plugin, or `ALL` from
`voxgig_sekreto.plugins`:

```python
from voxgig_sekreto import Sekreto
from voxgig_sekreto.plugins.hashicorp import hashicorp
from voxgig_sekreto.plugins.aws import awssecrets

secrets = Sekreto({
    'plugins': [hashicorp, awssecrets],
    'providers': [
        {'kind': 'env'},
        {'kind': 'hashicorp', 'name': 'prod', 'addr': os.environ['VAULT_ADDR'], 'token': os.environ['VAULT_TOKEN']},
        {'kind': 'awssecrets', 'region': 'eu-west-1'},
    ],
})

token = secrets.get('api.token')
prod = secrets.getfrom('prod', 'api.token')
secrets.host.list()   # {'env': 'live', 'hashicorp$prod': 'live', 'awssecrets': 'live'}
```

A kind that was not passed in is refused by name, and the message says
what to pass:

```
sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)
 - doppler is a sekreto plugin, not built in: pass it in the plugins option
```

A custom store is one call — `providerplugin(kind, make)` in typescript
and python, `sekreto.ProviderPlugin` in go — and joins the chain like any
shipped plugin. See [DOCS.md](DOCS.md#plugins).

## Languages

| | conformance | CLI |
|---|---|---|
| [typescript](typescript/) *(canonical)* | ✅ | ✅ |
| [javascript](javascript/) | ✅ | ✅ |
| [python](python/) | ✅ | ✅ |
| [ruby](ruby/) | ✅ | ✅ |
| [php](php/) | ✅ | ✅ |
| [perl](perl/) | ✅ | ✅ |
| [go](go/) | ✅ | ✅ |
| [rust](rust/) | ✅ | ✅ |
| [java](java/) | ✅ | ✅ |
| [csharp](csharp/) | ✅ | ✅ |
| [zig](zig/) | ✅ | ✅ |
| [kotlin](kotlin/) | ✅ | ✅ |

Every port is tested three ways: the shared conformance spec, an
integration run against mock servers, and — on demand and weekly — the
same CLIs against the **real** stores in Docker
(`doc/design/real-stores.md`).

Every port has **zero third-party dependencies, with one deliberate
exception**: the Rust port takes `rustls` (with `webpki-roots` for the
trust anchors, which rustls deliberately does not ship) for TLS. Everywhere else, where a
standard library lacks something — JSON in Java and Rust, HTTP in Rust — the
port carries a small one of its own rather than taking on a package. TLS is
the line: hand-rolling it for a secrets library would be far worse than
depending on a well-audited crate.

The one **Voxgig** dependency is [voxgig/plugin](https://github.com/voxgig/plugin),
which itself has none: the ports that have adopted the plugin
architecture take its port of their language, and nothing else.

## Secret names

A name is dot-separated lowercase segments: `api.token`, `db.pass.main`.
One name, one secret, whichever provider answers:

| name | environment | vault path / field |
|---|---|---|
| `api.token` | `API_TOKEN` | `api` / `token` |
| `db.pass.main` | `DB_PASS_MAIN` | `db/pass` / `main` |
| `token` | `TOKEN` | `token` / `value` |

## Providers

| kind | | store name | reads |
|---|---|---|---|
| `env` | built in | `env` | environment variables, optionally prefixed |
| `dotenv` | built in | `dotenv` | a `.env` file, parsed once |
| `memory` | built in | `memory` | literal values — for tests and defaults |
| `file` | built in | `file` | a directory of one-secret-per-file entries — a mounted Kubernetes/Docker secret |
| `hashicorp` | plugin | `hashicorp` | HashiCorp Vault (and OpenBao), KV v2 or v1, namespaces, kubernetes/approle logins |
| `boru` | plugin | `boru` | a [boru](https://github.com/boru-lang/boru) vault — the `boru` CLI, or `boru vault serve` over its wire protocol |
| `awssecrets` | plugin `aws` | `awssecrets` | AWS Secrets Manager, SigV4-signed in-tree |
| `awsparams` | plugin `aws` | `awsparams` | AWS SSM Parameter Store, SigV4-signed in-tree |
| `gcpsecrets` | plugin | `gcpsecrets` | GCP Secret Manager; on-platform auth via the metadata server |
| `azuresecrets` | plugin | `azuresecrets` | Azure Key Vault; client-credential or managed-identity auth |
| `onepassword` | plugin | `onepassword` | 1Password, through a Connect server |
| `doppler` | plugin | `doppler` | Doppler, one bulk download per config |
| `infisical` | plugin | `infisical` | Infisical, token or universal-auth machine identity |
| `secretspec` | plugin | `secretspec` | [SecretSpec](https://secretspec.dev), through its CLI — whatever backend it is configured with |

The store name is what `getfrom` addresses. It defaults to the kind and can
be set with `name`, so two boru vaults can be `personal` and `team`.

Every networked provider observes the same plaintext guard: a token never
rides `http://` to anything but loopback (the platform metadata endpoints,
which carry no credential outbound, are the one principled exception).
Cloud credentials resolve from config first and each ecosystem's own
environment convention second (`AWS_*`, `GOOGLE_OAUTH_ACCESS_TOKEN`,
metadata/IMDS on-platform), so a pod or CI job that is already set up for
its cloud just works.

### AWS, and the signature

The AWS providers sign requests with an in-tree implementation of
Signature V4 — `sigv4` is a pure function (the timestamp is an argument),
so the shared spec carries known-answer cases, including a vector from
AWS's own published SigV4 test suite, that every port must reproduce
byte-for-byte. The integration mock re-derives the signature of every
request server-side and refuses mismatches, so a port that signs wrongly
fails the way it would against real AWS.

`api.token` reads Secrets Manager secret `api`, field `token` of its JSON
`SecretString` (the AWS idiom), or SSM parameter `/api/token`, decrypted.
GCP flattens dots to `_` (`api_token`), Azure to `-` (`api-token`) — those
stores reject dots in ids.

A store that does not hold a secret is a **miss** — the chain carries on. A
store that *could not answer* (a locked vault, a wrong passphrase, an
unreachable host) is an **error**: falling through there would quietly reach
for a weaker store.

### HashiCorp Vault

Vault publishes a wire protocol, so this provider talks to the real thing:
`GET {addr}/v1/{mount}/data/{path}` with an `X-Vault-Token` header, reading
the field out of `data.data`, with 404 as a miss.

The secret does cross a network, so **sekreto refuses to send a token in
plaintext to anything but loopback**. `http://` to a remote host raises
before a socket is opened; use `https://`. Loopback stays allowed for
`vault server -dev` and for this repo's test harness. Vault's own answer to
the same problem is TLS plus short-lived, policy-scoped tokens, response
wrapping and audit devices — this guard just stops the easy mistake.

Every port verifies the server certificate and host name over https. For an
internal CA, `SEKRETO_CA_BUNDLE` names a PEM bundle of extra trust roots in
the Rust port; the others use their platform trust store.

### boru

[boru](https://github.com/boru-lang/boru) keeps secrets in a local encrypted
keyring. sekreto reads them two ways, both boru's own.

**Through the CLI** (the default): `boru vault get --reveal <alias>` prints
the secret on stdout, and a sekreto name is already a valid boru alias, so
`api.token` crosses over unchanged. The passphrase comes from
`BORU_VAULT_PASSPHRASE` in the environment: never config, never a command
line, where the process table would show it.

**Over the wire** (`addr` + `token` config): boru's `vault serve` publishes
a read-only, HashiCorp-shaped **provision protocol** (boru's
`design/VAULT-WIRE-PROTOCOL.0.md`), authenticated by capability tokens from
`boru vault grant` — one alias, or a whole namespace with
`vault grant 'ns:*'`. boru aliases keep their dots, so `api.token` is the
single path segment `api.token`, field `value`.

> **The broker stays out of bounds.** boru's `vault proxy` and `vault mcp`
> are a *credential broker* — they inject the real secret into an outbound
> request and forward it, so an agent can call an API without ever holding
> the credential. Handing a value back is the one thing a broker is built
> not to do, and sekreto still does not ask it to. `vault serve` is the
> opposite tool: a provision endpoint built precisely to hand the value
> back, under capability tokens, and that is the one sekreto speaks to.
>
> The distinction matters: an app calling `secrets.get()` necessarily
> *holds* the secret. If the caller is untrusted, boru's broker is the
> better tool and sekreto is the wrong layer.

The other direction works with no sekreto code at all: `boru vault exec
api.token=API_TOKEN -- yourapp` puts the secret in the child's environment,
where sekreto's `env` provider picks it up.

## Testing

Two suites, and both matter:

```sh
make test         # every port computes the same answers
make integration  # every port can actually fetch a secret and use it
make all          # both
make spec         # recompile spec/sekreto.json from the aontu sources
```

**`make test`** runs [`spec/sekreto.json`](spec/sekreto.json) — fourteen
groups covering name validation, the environment, vault, flat and
parameter-path mappings, `.env` parsing, SigV4 signing (with AWS's own
published test vector), chain resolution, directed access, store naming,
provider description and redaction — through each port's own voxgig/omni
runner. Every port runs the same file. A port that disagrees with the spec
is the thing that is wrong.

The spec is written in [aontu](https://github.com/voxgig/aontu):
[`spec/sekreto.aon`](spec/sekreto.aon) plus the case files in
[`spec/def/`](spec/def) are the source of truth, and `sekreto.json` is
compiled from them by **`make spec`** and committed, so that no port needs a
Node toolchain to run its tests. Edit the aontu, never the JSON.

**`make integration`** starts a Fastify API that rejects any request without
the right bearer token, plus stand-ins for every published wire protocol —
HashiCorp Vault (twice: plain, and enterprise-style demanding a namespace
and kubernetes/approle logins), AWS (verifying every SigV4 signature
server-side), GCP (metadata server included), Azure (client-credential
login), 1Password Connect, Doppler and Infisical (universal-auth login) —
and, when the `boru` binary is available, a real boru vault, read both
through the CLI and over `boru vault serve` with a granted capability
token. Each CLI runs twenty-two times: once per secret source, once for the
full chain, twice for directed access, and the refusals — an unknown store,
no secret at all, the wrong secret, and an AWS request signed with the
wrong key — without printing the real token while failing.

boru is skipped, not faked, when the binary is absent: its CLI and its
serve endpoint are exercised against the real thing or not at all.

That second half is the point. A spec can only prove a library computes
the right strings; only a real call to a real server proves it can fetch a
secret and use it.

## Documentation

- [DOCS.md](DOCS.md) — the full API, provider by provider
- [AGENTS.md](AGENTS.md) — how to work in this repository
- each port's own `README.md` for language-specific notes

## License

MIT
