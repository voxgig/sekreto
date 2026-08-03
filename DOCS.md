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

### `flatname(name, sep): string`

A name flattened to one segment, for stores whose ids have no hierarchy
and reject dots: GCP Secret Manager (`_`) and Azure Key Vault (`-`).

```
flatname('api.token', '_')     // 'api_token'   (GCP)
flatname('api.token', '-')     // 'api-token'   (Azure)
```

### `awsparam(name, prefix?): string`

The SSM Parameter Store path for a name: dots become the parameter
hierarchy, rooted at `/`, under an optional prefix.

```
awsparam('db.pass.main')          // '/db/pass/main'
awsparam('api.token', '/app')     // '/app/api/token'
```

All of `envkey`, `vaultref`, `flatname` and `awsparam` raise
`sekreto: invalid name: <name>` for a name that is not well-formed.

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

## `sigv4(input): headers`

AWS Signature V4, in-tree, pure: the caller passes the timestamp
(`datetime: 'YYYYMMDDTHHMMSSZ'`), so the same input signs identically in
every port. Input: `method`, `url`, `headers?`, `body?`, `service`,
`region`, `keyid`, `secret`, `session?`, `datetime`. Output: the headers
to attach — `authorization`, `x-amz-date`, and `x-amz-security-token`
when a session token was given.

The spec pins known-answer cases, including a vector from AWS's own
published SigV4 test suite, so a port that signs wrongly in any byte goes
red. The AWS providers call this; apps normally never need it directly.

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

### `file` — a mounted-secret directory

One secret per file, keyed like the environment: `api.token` reads
`<dir>/API_TOKEN`. That is the shape of a mounted Kubernetes Secret, a
Docker/Swarm secret and a systemd credentials directory, so those work
with no further configuration. One trailing newline is stripped — the
tools that write these files disagree about it.

```ts
{ kind: 'file', dir: string, prefix?: string }
```

- an absent file **or absent directory** is a miss, like a missing `.env`
- any other read failure (permissions, an unreadable mount) raises

`describe()` → `file:<dir>`

### `hashicorp` — HashiCorp Vault

```ts
{
  kind: 'hashicorp',
  addr: string,
  token: string,            // or log in via `auth`
  mount?: string,           // default 'secret'
  kv?: 1 | 2,               // default 2
  vaultnamespace?: string,  // Vault Enterprise X-Vault-Namespace
  auth?: {                  // used when token is empty
    method: 'kubernetes' | 'approle'
    mount?: string          // auth mount, default = method
    role?: string           // kubernetes: the Vault role
    jwt?: string            // kubernetes: the JWT itself (tests)
    jwtfile?: string        // kubernetes: default = the conventional pod path
    roleid?: string         // approle
    secretid?: string
  }
}
```

KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` with
an `X-Vault-Token` header and takes the `token` field of `data.data`.
KV v1 (`kv: 1`) reads `{addr}/v1/{mount}/api` and takes the field of
`data`. This is Vault's published HTTP API, so the provider talks to a
real Vault — or an [OpenBao](https://openbao.org) — unmodified.

A `vaultnamespace` rides the `X-Vault-Namespace` header on every request,
logins included. With an empty `token` and an `auth` block, the provider
logs in once (Kubernetes auth with the pod's service-account JWT, or
AppRole) and reuses the returned client token.

- **404 → a miss**, so a vault can sit in a chain with fallbacks behind it
- any other non-200 raises `sekreto: hashicorp error: <status>: <url>`
- a failed login raises `sekreto: hashicorp login failed: <status>: <url>`
  — an error, never a miss: this store could not answer at all
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

Over https every port verifies the server certificate **and** the host name;
neither is optional and there is no "skip verify" switch. The Rust port
trusts the Mozilla root set via `rustls`, and `SEKRETO_CA_BUNDLE` names a PEM
bundle of extra roots for an internal CA — additive, so a wrong path weakens
nothing, it just adds no roots.

### `boru` — a boru vault

```ts
{
  kind: 'boru',
  command?: string,     // CLI mode: the executable, default 'boru'
  namespace?: string,   // the boru namespace qualifying the alias
  home?: string,        // CLI mode: passed as BORU_HOME
  addr?: string,        // wire mode: the `boru vault serve` address
  token?: string,       // wire mode: a capability token from `vault grant`
  mount?: string,       // wire mode: default 'secret'
}
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

`describe()` → `boru`, or `boru:<namespace>` (CLI mode); `boru:<addr>`
(wire mode)

The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`. sekreto
never takes it as config and never puts it on a command line, where the
process table would show it.

**Wire mode.** With an `addr`, the provider speaks boru's provision
protocol instead of running the CLI: `boru vault serve` publishes a
read-only, HashiCorp-shaped API (boru's `design/VAULT-WIRE-PROTOCOL.0.md`),
authenticated by capability tokens from `boru vault grant` — one alias, or
a whole namespace with `vault grant 'ns:*'`. boru aliases keep their dots,
so `api.token` is the single path segment `api.token` (under
`<namespace>/` when one is set), field `value`. A 404 is a miss; anything
else the server refuses — a revoked capability, a sealed vault — raises
`sekreto: boru serve error: <status>: <url>`. The plaintext-address guard
applies; `vault serve` binds loopback by default, which is exactly the
allowed case.

> **The broker stays out of bounds.** boru's `vault proxy` and `vault mcp`
> are a *credential broker*: they inject the real secret into an outbound
> request and forward it, so a caller can use a credential without ever
> holding it. Handing the value back is the one thing that design refuses,
> and sekreto still does not ask it to — `vault serve` is boru's provision
> endpoint, built for exactly this, under capability tokens.
>
> If your caller is untrusted (an agent, a plugin), boru's broker is the
> better tool and sekreto is the wrong layer. Use both in the other
> direction instead: `boru vault exec api.token=API_TOKEN -- yourapp` puts
> the secret in the child's environment, where sekreto's `env` provider
> finds it with no sekreto configuration at all.

### `awssecrets` / `awsparams` — AWS

```ts
{ kind: 'awssecrets', region?: string, keyid?: string, secret?: string,
  session?: string, addr?: string }
{ kind: 'awsparams',  ...same..., prefix?: string }
```

Region and credentials come from config first, then AWS's own environment
convention (`AWS_REGION`/`AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`); missing either raises.
Requests are SigV4-signed in-tree (see `sigv4` above).

`awssecrets`: `api.token` reads the secret named `api` (the `vaultref`
path) and takes the `token` field of its JSON `SecretString` — the AWS
idiom of one JSON map per secret. A plain-string secret is the value
itself, under the conventional field `value`. A
`ResourceNotFoundException` is a miss; any other failure raises.

`awsparams`: `db.pass.main` reads parameter `/db/pass/main` (under
`prefix`), decrypted. `ParameterNotFound` is a miss.

`describe()` → `awssecrets:<region>` / `awsparams:<region><prefix>`
(config values only, so the description is environment-independent)

### `gcpsecrets` — GCP Secret Manager

```ts
{ kind: 'gcpsecrets', project: string, token?: string, addr?: string,
  metadataaddr?: string }
```

`api.token` reads secret `api_token` (dots flattened, Secret Manager ids
reject them), latest version, base64-decoded. The token comes from
config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE/GKE metadata
server — on Google's platform no credential configuration is needed. A
404 is a miss.

`describe()` → `gcpsecrets:<project>`

### `azuresecrets` — Azure Key Vault

```ts
{ kind: 'azuresecrets', vault: string, token?: string, tenant?: string,
  clientid?: string, clientsecret?: string, loginaddr?: string,
  imdsaddr?: string, apiversion?: string }
```

`vault` is the Key Vault name (`corp` → `https://corp.vault.azure.net`)
or a full URL. `api.token` reads secret `api-token` (dots flattened, Key
Vault names allow nothing else). The token comes from config, then a
client-credentials login when tenant/clientid/clientsecret are given,
then the IMDS managed identity — on Azure's platform no credential
configuration is needed. A 404 is a miss.

`describe()` → `azuresecrets:<vault>`

### `onepassword` — 1Password, through a Connect server

```ts
{ kind: 'onepassword', addr: string, token: string, vault: string }
```

The item titled `api.token` (titles keep their dots) in the named vault;
the value is the field with purpose `PASSWORD`, or the field labelled
`value`. An item that is not there is a miss; a *vault* that is not
there raises — config names it, so its absence is a broken store.

`describe()` → `onepassword:<vault>`

### `doppler` — Doppler

```ts
{ kind: 'doppler', token: string, project?: string, config?: string,
  addr?: string }
```

The whole config is downloaded once — Doppler's own bulk endpoint — and
answered from memory, like a remote `.env`: `api.token` is the
`API_TOKEN` entry. A service token is config-scoped, so `project` and
`config` are only needed with broader tokens. A missing entry is a miss.

`describe()` → `doppler`, or `doppler:<project>/<config>`

### `infisical` — Infisical

```ts
{ kind: 'infisical', addr?: string, token?: string, clientid?: string,
  clientsecret?: string, project: string, environment: string,
  path?: string }
```

`api.token` reads the secret keyed `API_TOKEN` (Infisical's own
convention) at `path` (default `/`) in one environment of a project.
Auth is a token, or a universal-auth (machine identity) login with
clientid/clientsecret. A 404 is a miss.

`describe()` → `infisical:<project>/<environment>`

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
| `sekreto: boru serve error: <status>: <url>` | boru's wire protocol answered neither 200 nor 404 |
| `sekreto: hashicorp login failed: <status>: <url>` | a kubernetes/approle login was refused |
| `sekreto: aws: no region …` / `sekreto: aws: no credentials …` | an AWS store with nothing to sign with |
| `sekreto: aws secretsmanager error: <status>` / `sekreto: aws ssm error: <status>` | AWS answered with anything but success or not-found |
| `sekreto: gcp: no project` / `sekreto: gcp error: <status>: <url>` | a GCP store misconfigured, or answering badly |
| `sekreto: azure: no vault` / `sekreto: azure login failed: <status>` / `sekreto: azure error: <status>: <url>` | an Azure store misconfigured, refusing login, or answering badly |
| `sekreto: onepassword: no vault named <vault>` | config names a Connect vault that is not there |
| `sekreto: doppler error: <status>` | Doppler refused the download |
| `sekreto: infisical login failed: <status>` / `sekreto: infisical error: <status>` | Infisical refused login or answered badly |
| `sekreto: file provider cannot read <file>: <why>` | a secret file that exists but cannot be read |
| `sekreto: cannot reach <url>: <why>` | the store could not be contacted |

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
| `flatname` | `flatname` |
| `awsparam` | `awsparam` |
| `parsedotenv` | `parsedotenv` |
| `resolve` | `Sekreto.get` over a chain of `memory` providers |
| `trysecret` | `Sekreto.try` |
| `sources` | `Sekreto.sources` |
| `stores` | `Sekreto.stores` |
| `getfrom` | `Sekreto.getfrom` |
| `tryfrom` | `Sekreto.tryfrom` |
| `redact` | `redact` |
| `sigv4` | `sigv4` — known-answer signatures, incl. AWS's own published vector |

The chain groups use `memory` (and pathless `file`) providers so the spec
stays hermetic — it runs the same on a machine with no network. The
networked providers appear in it only where nothing has to be contacted:
their `describe()` strings, the name mappings, the SigV4 signatures, and
the plaintext-address guard, which raises before a socket is opened.

Actually *fetching* from them is proved instead by `test/integration.sh`,
which talks to stand-ins for every published wire protocol over real
sockets — HashiCorp (plain and enterprise-style), AWS with server-side
signature verification, GCP, Azure, 1Password Connect, Doppler, Infisical
— and to a real boru vault through the real binary, both CLI and
`vault serve`. That split is deliberate: the spec pins behaviour, the
integration run pins reality.
