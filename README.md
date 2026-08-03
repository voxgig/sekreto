# sekreto

**One interface for secrets, wherever they live.**

An app asks for `api.token`. It never learns whether that value came from
an environment variable, a `.env` file, HashiCorp Vault or a boru vault —
and it does not have to change when the answer changes. Moving from
`.env` in development to a vault in production is a config change, not a
code change.

The same library is available in ten languages, all behaving identically,
because they all run the same shared test spec through
[voxgig/omni](https://github.com/voxgig/omni).

```js
const { Sekreto } = require('@voxgig/sekreto-js')

const secrets = new Sekreto({
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

Every port has **zero third-party dependencies**. Where a language's
standard library lacks something — JSON in Java and Rust, HTTP in Rust —
the port carries a small one of its own rather than taking on a package.

## Secret names

A name is dot-separated lowercase segments: `api.token`, `db.pass.main`.
One name, one secret, whichever provider answers:

| name | environment | vault path / field |
|---|---|---|
| `api.token` | `API_TOKEN` | `api` / `token` |
| `db.pass.main` | `DB_PASS_MAIN` | `db/pass` / `main` |
| `token` | `TOKEN` | `token` / `value` |

## Providers

| kind | store name | reads |
|---|---|---|
| `env` | `env` | environment variables, optionally prefixed |
| `dotenv` | `dotenv` | a `.env` file, parsed once |
| `memory` | `memory` | literal values — for tests and defaults |
| `hashicorp` | `hashicorp` | HashiCorp Vault, KV v2, over its published HTTP API |
| `boru` | `boru` | a [boru](https://github.com/boru-lang/boru) vault, through the `boru` CLI |

The store name is what `getfrom` addresses. It defaults to the kind and can
be set with `name`, so two boru vaults can be `personal` and `team`.

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

### boru

[boru](https://github.com/boru-lang/boru) keeps secrets in a local encrypted
keyring. sekreto reads them the way boru itself does — by running
`boru vault get --reveal <alias>` — and a sekreto name is already a valid
boru alias, so `api.token` crosses over unchanged. The passphrase comes from
`BORU_VAULT_PASSPHRASE` in the environment: never config, never a command
line, where the process table would show it.

> **There is deliberately no HTTP read.** boru's `vault proxy` and
> `vault mcp` are a *credential broker* — they inject the real secret into an
> outbound request and forward it, so an agent can call an API without ever
> holding the credential. Handing a value back is the one thing that broker
> is built not to do, so sekreto does not ask it to.
>
> That is a stronger posture than sekreto's own: an app calling
> `secrets.get()` necessarily *holds* the secret. If the caller is untrusted,
> boru's broker is the better tool and sekreto is the wrong layer.

The other direction works with no sekreto code at all: `boru vault exec
api.token=API_TOKEN -- yourapp` puts the secret in the child's environment,
where sekreto's `env` provider picks it up.

## Testing

Two suites, and both matter:

```sh
make test         # every port computes the same answers
make integration  # every port can actually fetch a secret and use it
make all          # both
```

**`make test`** runs [`spec/sekreto.json`](spec/sekreto.json) — eleven
groups covering name validation, the environment and vault mappings, `.env`
parsing, chain resolution, directed access, store naming, provider
description and redaction — through each port's own voxgig/omni runner.
Every port runs the same file. A port that disagrees with the spec is the
thing that is wrong.

**`make integration`** starts a Fastify API that rejects any request without
the right bearer token, plus a stand-in HashiCorp Vault and — when the
`boru` binary is available — a real boru vault. Each CLI runs ten times:
once per secret source, once for the full chain, twice for directed access
(including one run where the *wrong* token sits in the environment and
`--store boru` must still fetch the right one), and three times where it
must be *refused* — an unknown store, no secret at all, and the wrong one —
without printing the real token while failing.

boru is skipped, not faked, when the binary is absent: it has no wire
protocol to imitate.

That second half is the point. A spec can only prove a library computes
the right strings; only a real call to a real server proves it can fetch a
secret and use it.

## Documentation

- [DOCS.md](DOCS.md) — the full API, provider by provider
- [AGENTS.md](AGENTS.md) — how to work in this repository
- each port's own `README.md` for language-specific notes

## License

MIT
