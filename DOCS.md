# sekreto API

Every port exposes the same API, spelled the way its language spells
things. The TypeScript signatures below are canonical; the table at the
end of each section gives the per-language names where they differ.

---

## Names

A secret name is one or more dot-separated segments, each matching
`[a-z0-9_]+`. `api.token` and `db.pass.main` are names; `API.Token`,
`a-b`, `a..b` and `""` are not.

### `validname(name): boolean`

Is this a well-formed secret name? Never throws — it is the predicate the
rest of the API checks with.

### `envkey(name, prefix?): string`

The environment-variable key for a name. Segments are joined with `_` and
upper-cased, after an optional prefix.

```
envkey('api.token')            // 'API_TOKEN'
envkey('db.pass.main')         // 'DB_PASS_MAIN'
envkey('api.token', 'APP_')    // 'APP_API_TOKEN'
```

### `vaultref(name): {path, field}`

Where a name lives in a KV vault. All but the last segment form the path;
the last is the field.

```
vaultref('api.token')          // { path: 'api',     field: 'token' }
vaultref('db.pass.main')       // { path: 'db/pass', field: 'main'  }
vaultref('token')              // { path: 'token',   field: 'value' }
```

A single-segment name has no path of its own, so it becomes a secret of
that name with the conventional field `value`.

Both `envkey` and `vaultref` raise `sekreto: invalid name: <name>` for a
name that is not well-formed.

---

## `parsedotenv(text): Record<string,string>`

Parse `.env` text into raw keys and values. Deliberately small:

- `KEY=value`, with surrounding whitespace trimmed
- an optional `export ` prefix
- `#` comments, on their own line only — a `#` after a value is part of it
- `'single'` quotes, taken literally
- `"double"` quotes, which also unescape `\n`, `\r`, `\t`, `\\` and `\"`
- a line with no `=`, or with `=` first, is skipped

Keys are used verbatim, so a `.env` file is keyed exactly like the
environment: `API_TOKEN=...`, not `api.token=...`.

---

## `redact(text, values): string`

Replace each of `values` in `text` with `[redacted]`.

Only values of **four characters or more** are replaced. Shorter ones are
too likely to appear in ordinary text, and redacting them would make logs
unreadable without making them safer.

---

## `Sekreto`

The facade: an ordered chain of providers plus a cache of what has been
resolved.

```ts
new Sekreto({
  providers: (Provider | ProviderSpec)[],  // resolution order
  cache?: boolean,                         // default true
})
```

A `providers` entry is either a live provider or its declarative form —
the same shape used in `spec/sekreto.json` and in an app's config file.

### Transparent — the chain answers

| method | answers |
|---|---|
| `get(name)` | the secret, or raises `sekreto: unknown secret: <name>` |
| `try(name)` | the secret, or nothing if no provider has it |
| `has(name)` | whether any provider has it |
| `all(names)` | every named secret at once; a missing one is an error |

### Directed — one named store answers

| method | answers |
|---|---|
| `getfrom(store, name)` | the secret from that store, or raises `sekreto: unknown secret: <store>:<name>` |
| `tryfrom(store, name)` | the secret from that store, or nothing if it does not have it |
| `hasin(store, name)` | whether that store has it |
| `stores()` | every store name that can be named, in order, without repeats |

A store name defaults to the provider's kind and can be set with `name` in
the spec, so a chain can hold `personal` and `team` boru vaults and address
each. Several providers may share a name; a directed read walks all of them,
in chain order.

Naming a store that is not in the chain raises
`sekreto: unknown store: <store>` — from `tryfrom` as well as `getfrom`.
`try` already means "this store may not have it"; letting it also mean "this
store may not exist" would swallow a typo.

The cache is keyed by store *and* name, so a directed read and a transparent
one never alias.

### Everything else

| method | answers |
|---|---|
| `sources()` | a description of each provider, in resolution order |
| `redact(text)` | `text` with every value *this* Sekreto resolved hidden |
| `refresh()` | drop cached values, so the next `get` asks again |

`get` and `try` raise `sekreto: invalid name: <name>` before asking any
provider, so a typo fails the same way whether or not a vault is reachable.

### Per-language names

| | optional lookup | directed | redact-resolved |
|---|---|---|---|
| typescript, javascript | `try` | `getfrom` / `tryfrom` | `redact` |
| python | `try_` | `getfrom` / `tryfrom` | `redact` |
| ruby | `try` | `getfrom` / `tryfrom` | `redact` |
| php | `try` | `getfrom` / `tryfrom` | `redact` |
| perl | `try` | `getfrom` / `tryfrom` | `redactall` |
| go | `Try` → `(value, found, err)` | `GetFrom` / `TryFrom` | `Redact` |
| rust | `trysecret` → `Option` | `getfrom` / `tryfrom` | `redact` |
| java | `tryget` | `getfrom` / `tryfrom` | `redact` |
| csharp | `TryGet` | `GetFrom` / `TryFrom` | `Redact` |

`try` is a keyword in Java and Python needs to avoid shadowing the
statement, hence `tryget` and `try_`. Go and Rust have no exceptions, so
they answer with `(value, found, error)` and `Result<Option<..>>`
respectively rather than throwing.

---

## Providers

A provider answers one question: *do you have this secret?* It returns the
value, or nothing to mean "ask the next one". That is the whole interface —
which is what lets an app read `api.token` without knowing where it lives.

```ts
type Provider = {
  lookup: (name: string) => string | undefined | Promise<string | undefined>
  describe: () => string
}
```

### `env`

Environment variables, via `envkey`.

```ts
{ kind: 'env', prefix?: string }
```

`describe()` → `env` or `env:<prefix>`

### `dotenv`

A `.env` file, read once on first use and keyed exactly like the
environment. **A missing file is not an error** — it means "no secrets
here", so a chain works unchanged on a machine that has no `.env`.

```ts
{ kind: 'dotenv', file?: string, prefix?: string }   // file defaults to '.env'
```

`describe()` → `dotenv:<file>`

### `memory`

Literal values, keyed like environment variables. Used by the shared spec
to test chain behaviour without touching the outside world, and useful for
defaults in an app.

```ts
{ kind: 'memory', values: Record<string,string>, prefix?: string }
```

`describe()` → `memory` or `memory:<prefix>`

### `hashicorp` — HashiCorp Vault, KV v2

```ts
{ kind: 'hashicorp', addr: string, token: string, mount?: string }  // mount: 'secret'
```

`api.token` reads `{addr}/v1/{mount}/data/api` with an `X-Vault-Token`
header and takes the `token` field of `data.data`. This is Vault's published
HTTP API, so the provider talks to a real Vault unmodified.

- **404 → a miss**, so a vault can sit in a chain with fallbacks behind it
- any other non-200 raises `sekreto: hashicorp error: <status>: <url>`
- a plaintext `addr` pointing anywhere but loopback raises before any socket
  is opened — see below

`describe()` → `hashicorp:<addr>/<mount>`

**On sending secrets over a network.** Vault's own defences are TLS,
short-lived policy-scoped tokens, response wrapping (a single-use token you
unwrap once, so interception is detectable), dynamic secrets minted per use,
and audit devices. sekreto adds one guard of its own, because the easy
mistake is `VAULT_ADDR=http://vault.internal:8200`:

| addr | result |
|---|---|
| `https://…` | allowed |
| `http://127.0.0.1`, `localhost`, `::1` | allowed — `vault server -dev`, test harnesses |
| `http://` anything else | `sekreto: refusing to send a token in plaintext to <addr> (use https)` |
| anything not http(s) | `sekreto: not an http(s) address: <addr>` |

The Rust port is narrower still: its in-tree HTTP client has no TLS, so it
can reach a Vault on loopback and nowhere else. That is stated loudly in
`rust/src/http.rs` rather than silently downgraded.

### `boru` — a boru vault

```ts
{ kind: 'boru', command?: string, namespace?: string, home?: string }
```

- `command` — the executable to run, default `boru`
- `namespace` — qualifies the alias as boru writes it, `<namespace>:<name>`
- `home` — passed as `BORU_HOME`, for a vault outside `~`

`api.token` runs `boru vault get --reveal api.token`, which prints the
secret on stdout and nothing else. A sekreto name is already a valid boru
alias — boru allows letters, digits, dot, dash and underscore in a segment —
so names cross over unchanged.

- **`no alias named …` → a miss**, and the chain carries on
- anything else (locked vault, wrong passphrase) raises
  `sekreto: boru vault error: <why>`; treating it as a miss would fall
  through to a weaker store without saying so
- the binary not being runnable raises `sekreto: cannot run <command>: <why>`

`describe()` → `boru`, or `boru:<namespace>`

The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`. sekreto
never takes it as config and never puts it on a command line, where the
process table would show it.

> **Why there is no HTTP read.** boru's `vault proxy` and `vault mcp` are a
> *credential broker*: they inject the real secret into an outbound request
> and forward it, so a caller can use a credential without ever holding it.
> Handing the value back is the one thing that design refuses. sekreto's
> interface is the opposite — `get` means "give me the secret" — so it reads
> the vault the way boru itself does, through the CLI.
>
> If your caller is untrusted (an agent, a plugin), boru's broker is the
> better tool and sekreto is the wrong layer. Use both in the other
> direction instead: `boru vault exec api.token=API_TOKEN -- yourapp` puts
> the secret in the child's environment, where sekreto's `env` provider
> finds it with no sekreto configuration at all.

---

## Errors

Every failure is a `SekretoError` (Go: a `*SekretoError` value; Rust: a
`SekretoError` in a `Result`), with a message that is byte-identical in
every port:

| message | when |
|---|---|
| `sekreto: invalid name: <name>` | a name that is not well-formed |
| `sekreto: unknown secret: <name>` | no provider had it |
| `sekreto: unknown secret: <store>:<name>` | a directed read, and that store did not have it |
| `sekreto: unknown store: <store>` | a directed read naming a store not in the chain |
| `sekreto: unknown provider kind: <kind>` | a spec naming no known provider |
| `sekreto: hashicorp error: <status>: <url>` | Vault answered neither 200 nor 404 |
| `sekreto: refusing to send a token in plaintext to <addr> (use https)` | a remote plaintext Vault address |
| `sekreto: not an http(s) address: <addr>` | a Vault address of some other scheme |
| `sekreto: boru vault error: <why>` | boru failed for a reason other than a missing alias |
| `sekreto: cannot run <command>: <why>` | the boru binary could not be started |
| `sekreto: cannot reach <url>: <why>` | the vault could not be contacted |

Those messages are pinned by `spec/sekreto.json`, so they cannot drift
between ports without a test going red.

---

## The shared spec

[`spec/sekreto.json`](spec/sekreto.json) is the contract. It is plain
JSON, run by every port through its own
[voxgig/omni](https://github.com/voxgig/omni) runner:

| group | subject |
|---|---|
| `validname` | `validname` |
| `envkey` | `envkey` |
| `vaultref` | `vaultref` |
| `parsedotenv` | `parsedotenv` |
| `resolve` | `Sekreto.get` over a chain of `memory` providers |
| `trysecret` | `Sekreto.try` |
| `sources` | `Sekreto.sources` |
| `stores` | `Sekreto.stores` |
| `getfrom` | `Sekreto.getfrom` |
| `tryfrom` | `Sekreto.tryfrom` |
| `redact` | `redact` |

The chain groups use `memory` providers so the spec stays hermetic — it runs
the same on a machine with no network. The `hashicorp` and `boru` providers
appear in it only where nothing has to be contacted: their `describe()`
strings, and the plaintext-address guard, which raises before a socket is
opened.

Actually *fetching* from them is proved instead by `test/integration.sh`,
which talks to a stand-in Vault over a real socket and to a real boru vault
through the real binary. That split is deliberate: the spec pins behaviour,
the integration run pins reality.
