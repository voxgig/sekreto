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

| method | answers |
|---|---|
| `get(name)` | the secret, or raises `sekreto: unknown secret: <name>` |
| `try(name)` | the secret, or nothing if no provider has it |
| `has(name)` | whether any provider has it |
| `all(names)` | every named secret at once; a missing one is an error |
| `sources()` | a description of each provider, in resolution order |
| `redact(text)` | `text` with every value *this* Sekreto resolved hidden |
| `refresh()` | drop cached values, so the next `get` asks again |

`get` and `try` raise `sekreto: invalid name: <name>` before asking any
provider, so a typo fails the same way whether or not a vault is reachable.

### Per-language names

| | optional lookup | redact-resolved |
|---|---|---|
| typescript, javascript | `try` | `redact` |
| python | `try_` | `redact` |
| ruby | `try` | `redact` |
| php | `try` | `redact` |
| perl | `try` | `redactall` |
| go | `Try` → `(value, found, err)` | `Redact` |
| rust | `trysecret` → `Option` | `redact` |
| java | `tryget` | `redact` |
| csharp | `TryGet` | `Redact` |

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

### `vault` — HashiCorp Vault, KV v2

```ts
{ kind: 'vault', addr: string, token: string, mount?: string }  // mount: 'secret'
```

`api.token` reads `{addr}/v1/{mount}/data/api` with an `X-Vault-Token`
header and takes the `token` field of `data.data`.

- **404 → a miss**, so a vault can sit in a chain with fallbacks behind it
- any other non-200 raises `sekreto: vault error: <status>: <url>`

`describe()` → `vault:<addr>/<mount>`

### `boru` — a boru vault

```ts
{ kind: 'boru', addr: string, token: string }
```

`api.token` reads `{addr}/vault/api?field=token` with an `X-Boru-Token`
header, expecting `{"ok":true,"value":"..."}`.

- **404, or `ok` not `true` → a miss**
- any other non-200 raises `sekreto: boru vault error: <status>: <url>`

`describe()` → `boru:<addr>`

> This is the protocol sekreto *assumes*, and what `test/mockvault.js`
> implements. If the real boru vault differs, `boruprovider` is the one
> function to change — nothing above it sees the wire format.

---

## Errors

Every failure is a `SekretoError` (Go: a `*SekretoError` value; Rust: a
`SekretoError` in a `Result`), with a message that is byte-identical in
every port:

| message | when |
|---|---|
| `sekreto: invalid name: <name>` | a name that is not well-formed |
| `sekreto: unknown secret: <name>` | no provider had it |
| `sekreto: unknown provider kind: <kind>` | a spec naming no known provider |
| `sekreto: vault error: <status>: <url>` | a vault answered neither 200 nor 404 |
| `sekreto: boru vault error: <status>: <url>` | likewise, for a boru vault |
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
| `redact` | `redact` |

The chain groups use `memory` providers so the spec stays hermetic — it
runs the same on a machine with no network. The `vault` and `boru`
providers are proved instead by `test/integration.sh`, which talks to a
real server over a real socket. That split is deliberate: the spec pins
behaviour, the integration run pins reality.
