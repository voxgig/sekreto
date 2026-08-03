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
    { kind: 'env' },                                  // local overrides
    { kind: 'dotenv', file: '.env' },                 // developer machines
    { kind: 'vault', addr: VAULT_ADDR, token: ... },  // production
    { kind: 'boru', addr: BORU_ADDR, token: ... },
  ],
})

const token = await secrets.get('api.token')
```

The first provider that has the secret wins. A provider that does not have
it says so and the next one is asked, so one chain covers every
environment the app runs in.

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

| kind | reads |
|---|---|
| `env` | environment variables, optionally prefixed |
| `dotenv` | a `.env` file, parsed once |
| `memory` | literal values — for tests and defaults |
| `vault` | HashiCorp Vault, KV v2 |
| `boru` | a boru vault |

A vault answering 404 is a **miss**, not an error, so a vault can sit in a
chain with fallbacks behind it.

> **Note on the boru vault protocol.** sekreto speaks
> `GET {addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
> expecting `{"ok":true,"value":"..."}`. This is the contract sekreto
> assumes and what `test/mockvault.js` implements. If the real boru vault
> differs, `boruprovider` is the single function to change — callers never
> see it.

## Testing

Two suites, and both matter:

```sh
make test         # every port computes the same answers
make integration  # every port can actually fetch a secret and use it
make all          # both
```

**`make test`** runs [`spec/sekreto.json`](spec/sekreto.json) — eight
groups covering name validation, the environment and vault mappings,
`.env` parsing, chain resolution, provider description and redaction —
through each port's own voxgig/omni runner. Every port runs the same file.
A port that disagrees with the spec is the thing that is wrong.

**`make integration`** starts a Fastify API that rejects any request
without the right bearer token, plus stand-in HashiCorp and boru vaults,
then runs every port's CLI against them. Each CLI runs seven times: once
per secret source, once for the full chain, and twice where it must be
*refused* — with no secret at all, and with the wrong one — and must not
print the real token while failing.

That second half is the point. A spec can only prove a library computes
the right strings; only a real call to a real server proves it can fetch a
secret and use it.

## Documentation

- [DOCS.md](DOCS.md) — the full API, provider by provider
- [AGENTS.md](AGENTS.md) — how to work in this repository
- each port's own `README.md` for language-specific notes

## License

MIT
