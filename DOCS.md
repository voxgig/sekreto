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
flatname('api.token', '_')       // 'api_token'       (GCP)
flatname('api.token', '-')       // 'api-token'       (Azure)
flatname('with_underscore', '-') // 'with-underscore' (Azure has no '_')
```

With `-` as the separator, underscores flatten too — Azure Key Vault's
alphabet is letters, digits and hyphens only, so a valid name like
`with_underscore` must still be representable. The resulting `.`/`_`
collision mirrors `envkey`, where both already map to `_`.

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
every port. It lives with the `aws` plugin — `@voxgig/sekreto/plugins/aws`,
`plugins/aws` in go, `voxgig_sekreto.plugins.aws` in python — because it
is the one place the library needs HMAC-SHA256, and the core never does.

Input: `method`, `url`, `headers?`, `body?`, `service`, `region`,
`keyid`, `secret`, `session?`, `datetime`. Output: the headers to attach
— `authorization`, `x-amz-date`, and `x-amz-security-token` when a
session token was given.

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
  plugins?: Definition[],                  // the kinds beyond the built-ins that providers may name
  cache?: boolean,                         // default true
})
```

A `providers` entry is either a live provider or its declarative form —
the same shape used in `spec/sekreto.json` and in an app's config file.
A spec names a `kind`: one of the four built-ins, or a plugin passed in
`plugins` (see [Plugins](#plugins)). A kind that was passed in neither
way raises `sekreto: unknown provider kind: <kind>` before anything is
built.

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
| `close()` | tear the chain down: every store's plugin instance is deactivated and unloaded, in reverse; afterwards nothing answers, and `redact` still knows every value ever resolved |
| `host` | the voxgig/plugin host the stores are instances of — `host.list()` names each store's ref and status; nothing on it advances the chain |
| `catalog` | the definitions this Sekreto can build: the built-ins plus `plugins` |

`get` and `try` raise `sekreto: invalid name: <name>` before asking any
provider, so a typo fails the same way whether or not a vault is reachable.

### Per-language names

| | optional lookup | directed | redact-resolved | construct |
|---|---|---|---|---|
| typescript, javascript | `try` | `getfrom` / `tryfrom` | `redact` | `new Sekreto({ plugins, providers })` |
| python | `try_` | `getfrom` / `tryfrom` | `redact` | `Sekreto({'plugins': …, 'providers': …})` |
| ruby | `try` | `getfrom` / `tryfrom` | `redact` | |
| php | `try` | `getfrom` / `tryfrom` | `redact` | |
| perl | `try` | `getfrom` / `tryfrom` | `redactall` | |
| go | `Try` → `(value, found, err)` | `GetFrom` / `TryFrom` | `Redact` | `New(&Options{Plugins, Providers}) (*Sekreto, error)` |
| rust | `trysecret` → `Option` | `getfrom` / `tryfrom` | `redact` | |
| java | `tryget` | `getfrom` / `tryfrom` | `redact` | |
| kotlin | `tryget`, and `` `try` `` | `getfrom` / `tryfrom` | `redact` | |
| scala | `tryget` → `Option` | `getfrom` / `tryfrom` | `redact` | |
| clojure | `tryget` | `getfrom` / `tryfrom` | `redactall` | |
| swift | `tryget` → `String?` | `getfrom` / `tryfrom` | `redact` | |
| dart | `tryget` → `FutureOr<String?>` | `getfrom` / `tryfrom` | `redact` | |
| elixir | `tryget` | `getfrom` / `tryfrom` | `redactall` | `Sekreto.new(plugins: …, providers: …)` |
| cpp | `tryget` → `std::optional` | `getfrom` / `tryfrom` | `redact` | |
| c | `sek_try` → `(err, *out)` | `sek_getfrom` / `sek_tryfrom` | `sek_redact_text` | `sek_new(&opts, &out)` |
| lua | `tryget` → `nil` on a miss | `getfrom` / `tryfrom` | `redact` | |
| ocaml | `tryget` → `string option` | `getfrom` / `tryfrom` | `redact` | |
| haskell | `tryget` → `IO (Maybe String)` | `getfrom` / `tryfrom` | `redact` | |
| lean | `tryget` → `IO (Option String)` | `getfrom` / `tryfrom` | `redact` | |
| csharp | `TryGet` | `GetFrom` / `TryFrom` | `Redact` | |

C prefixes everything `sek_` and answers every call with a `sek_err`,
writing the value through an out parameter, for the same reason Go
returns one: it has nothing to throw. It is the only port whose caller
also owns memory, which is why `sek_redact` takes a pool and the chain's
own redaction is `sek_redact_text`.

Go's `New` returns an error, because building a chain can fail — an
unknown kind, a store name that is not a valid tag, a provider refusing
its configuration — and Go has nothing to throw. Its `Options.Providers`
is a list of specs; a spec may carry a `Provider` already built, which is
how a custom provider that is not a plugin joins the chain.

`try` is a keyword in Java, Kotlin, and Scala, and a special form in
Clojure, and Python needs to avoid shadowing the statement, hence `tryget`
and `try_`. Kotlin can escape a
keyword with backticks, so it carries `` `try` `` as well. Go and Rust have no
exceptions, so they answer with `(value, found, error)` and
`Result<Option<..>>` respectively rather than throwing. Scala has
exceptions and throws like the other JVM ports, but its optional lookup
answers with `Option[String]`, which is what the language reaches for
where Java returns `Optional`. Clojure and Elixir carry `redactall` for the same
reason Perl does: `redact` is already the pure two-argument function, and
the method on a chain would take two arguments as well.

Dart answers `FutureOr` rather than `Future`, and the reason is the
conformance runner: `dart:io`'s `HttpClient` is async-only while omni's
Dart runner is synchronous, so an all-`Future` API could not be driven by
the shared suite at all. A chain of local stores completes without
yielding and hands back a plain value; the first provider that opens a
socket returns a future and the chain returns one in turn. `await` reads
either. It also keeps every pre-I/O refusal — `checkaddr`, an unsupported
`kv` version, missing AWS credentials — synchronous at the call.

---

## Plugins

Four provider kinds are **built in** to every port: `env`, `memory`,
`dotenv` and `file` — the ones that read at most a local file, and need
no socket, no TLS, no crypto, and no child process. Every other kind is a
**plugin**: a [voxgig/plugin](https://github.com/voxgig/plugin)
definition in the port's `plugins/` folder, which the calling project
hands to `Sekreto` at construction.

| plugin | kinds | needs | typescript *(canonical)* |
|---|---|---|---|
| `hashicorp` | `hashicorp` | HTTPS, the filesystem | `@voxgig/sekreto/plugins/hashicorp` → `hashicorp` |
| `boru` | `boru` | child process, or HTTPS | `…/plugins/boru` → `boru` |
| `aws` | `awssecrets`, `awsparams` | HTTPS, HMAC-SHA256 | `…/plugins/aws` → `awssecrets`, `awsparams` |
| `gcpsecrets` | `gcpsecrets` | HTTPS | `…/plugins/gcpsecrets` → `gcpsecrets` |
| `azuresecrets` | `azuresecrets` | HTTPS | `…/plugins/azuresecrets` → `azuresecrets` |
| `onepassword` | `onepassword` | HTTPS | `…/plugins/onepassword` → `onepassword` |
| `doppler` | `doppler` | HTTPS | `…/plugins/doppler` → `doppler` |
| `infisical` | `infisical` | HTTPS | `…/plugins/infisical` → `infisical` |
| `secretspec` | `secretspec` | child process | `…/plugins/secretspec` → `secretspec` |
| *the full set* | all ten | everything | `@voxgig/sekreto/plugins` → `allplugins` |

The full set is for the CLI, the conformance suite, and an app whose
chain is decided at run time. Reaching one plugin through it reaches
every other, which is the cost the split exists to remove: an app
imports the kinds it configures.

**Loading is static.** There is no dynamic discovery, no registry a
module adds itself to at import, and no module loaded by name: the
plugins a `Sekreto` can build are exactly the ones its constructor was
handed, so what a build carries is decided where a compiler can see it.
That is the same in a language with dynamic loading (typescript, python)
as in one without (go), on purpose — the set of stores an app can reach
is not something to discover at run time.

### What a plugin is

A sekreto plugin is a voxgig/plugin `Definition` whose `name` is the
provider `kind` and whose `define` builds the provider from the
instance's options (the spec) and exports it under the key `provider`.
Every built-in and every shipped plugin is made by one helper, and so is
a custom kind:

```ts
import { providerplugin } from '@voxgig/sekreto'

export const mystore = providerplugin('mystore', (spec) => ({
  lookup: async (name) => ...,
  describe: () => 'mystore:' + spec.addr,
}))
```

```go
var Plugin = sekreto.ProviderPlugin("mystore", func(spec *sekreto.ProviderSpec) (sekreto.Provider, error) {
    return &MyStore{Addr: spec.Addr}, nil
})
```

```python
mystore = providerplugin('mystore', lambda spec: MyStore(spec.get('addr')))
```

```zig
fn make(alloc: Allocator, config: sekreto.Config, spec: sekreto.ProviderSpec) Allocator.Error!sekreto.Answer(sekreto.Provider) {
    return .{ .ok = try sekreto.provide(alloc, MyStore, .{ .config = config, .addr = spec.addr }) };
}
pub const mystore = sekreto.providerplugin("mystore", make);
```

A plugin that names a built-in kind replaces it — how a host substitutes
an implementation, and never an accident, because the four names are
documented.

### What the host holds

Each chain entry built from a spec is an **instance** on `secrets.host`,
the voxgig/plugin host, and `host.list()` reads like the chain: the
instance is `kind` for a store named after its kind and `kind$store`
otherwise, so `{ kind: 'hashicorp', name: 'prod' }` is `hashicorp$prod`.
Two providers may share a store name — a directed read walks both — but
an instance ref may not, so a repeat gets a numbered tag from the host
(`memory`, then `memory$1`) and keeps its store name. A store name must
be a valid plugin tag (`[a-zA-Z0-9.~_-]+`), or construction raises
`sekreto: invalid store name: <name>`.

Nothing is contacted at construction: `define` builds the provider and
`activate` takes the instance live, and a provider opens nothing until
its first lookup. `close()` deactivates and unloads every instance in
reverse, which is where a provider that acquired a resource at
activation releases it.

A provider that refuses its own configuration — `kv: 3`, a missing
project — raises a `SekretoError` from inside `define`. voxgig/plugin
keeps an error that carries a code and wraps one that does not, so the
helper gives a `SekretoError` the code `sekreto_error` on the way in and
`Sekreto` turns it back into the same `SekretoError` on the way out,
byte for byte, because the spec pins those messages. Any other error a
`define` raises is the host's to report, as `plugin_define_failed`.

### Per language

| | plugins live in | the dependency | loading one | loading all |
|---|---|---|---|---|
| typescript | `typescript/plugins/` | `@voxgig/plugin` (npm) | `import { hashicorp } from '@voxgig/sekreto/plugins/hashicorp'` | `import { allplugins } from '@voxgig/sekreto/plugins'` |
| go | `go/plugins/<kind>/` | `github.com/voxgig/plugin/go` (module proxy) | `import ".../go/plugins/hashicorp"` → `hashicorp.Plugin` | `import ".../go/plugins"` → `plugins.All()` |
| python | `python/voxgig_sekreto/plugins/` | `voxgig-plugin` (from git, until it is on PyPI) | `from voxgig_sekreto.plugins.hashicorp import hashicorp` | `from voxgig_sekreto.plugins import ALL` (built on demand) |
| zig | `zig/plugins/` | plugin's zig port, a checkout named on the command line as the module `plugin` | `-Msekretoplugins=plugins/hashicorp.zig` → `plugins.hashicorp` | `-Msekretoplugins=plugins/all.zig` → `plugins.ALL` |
| javascript | `javascript/plugins/` | `@voxgig/plugin-js` (npm) | `require('@voxgig/sekreto/plugins/hashicorp')` | `require('@voxgig/sekreto/plugins')` → `allplugins` |
| ruby | `ruby/lib/voxgig_sekreto/plugins/` | a checkout | `require 'voxgig_sekreto/plugins/hashicorp'` | `require 'voxgig_sekreto/plugins'` → `ALL` |
| php | `php/plugins/` | a checkout | `Hashicorp::plugin()` | `Plugins::all()` |
| perl | `perl/plugins/` | a checkout | `VoxgigSekreto::Plugins::Hashicorp::plugin()` | `VoxgigSekreto::Plugins::all()` |
| rust | `rust/plugins/` | a checkout, a crate per plugin | `voxgig_sekreto_hashicorp::plugin()` | `voxgig_sekreto_plugins::all()` |
| java | `java/plugins/` | a checkout | `Hashicorp.PLUGIN` | `SekretoPlugins.all()` |
| csharp | `csharp/plugins/` | a checkout, its own assembly | `Hashicorp.Plugin` | `SekretoPlugins.All()` |
| kotlin | `kotlin/plugins/` | a checkout | `Hashicorp.plugin` | `allPlugins()` |
| scala | `scala/plugins/` | a checkout | `Hashicorp.hashicorp` | `Plugins.ALL` |
| clojure | `clojure/plugins/` | a checkout; the Makefile writes the classpaths | `voxgig.sekreto.plugins.hashicorp/hashicorp` | `voxgig.sekreto.plugins/ALL` |
| swift | `swift/plugins/` | a checkout, its own module | `import SekretoPlugins` → `hashicorp` | `allplugins` |
| dart | `dart/plugins/` | a checkout | `import '../plugins/hashicorp.dart'` | `import '../plugins/plugins.dart'` → `allplugins` |
| elixir | `elixir/plugins/` | a checkout | `Sekreto.Plugins.Hashicorp.hashicorp()` | `Sekreto.Plugins.all()` |
| cpp | `cpp/plugins/` | a checkout, compiled into `build/`, its own archive | `sekreto::hashicorp()` | `sekreto::allplugins()` |
| c | `c/plugins/` | a checkout, compiled into `build/`, one object per kind | `sek_hashicorp_plugin()` | `sek_allplugins(&out)` |
| lua | `lua/src/sekreto/plugins/` | a checkout | `require('sekreto.plugins.hashicorp').hashicorp` | `require('sekreto.plugins').ALL` |
| ocaml | `ocaml/plugins/` | a checkout, compiled into `build/` | `Hashicorp.hashicorp` | `Allplugins.all ()` |
| haskell | `haskell/plugins/` | a checkout, compiled into `build/` | `import Hashicorp` → `hashicorp` | `import AllPlugins` → `allplugins` |
| lean | `lean/plugins/` as `SekretoPlugins.*` | a checkout, compiled into `build/` | `import SekretoPlugins.Hashicorp` | `import SekretoPlugins` → `allplugins` |

In Go the split is a *linking* boundary: a plugin package not imported
is not in the binary, and the core package imports no `net/http`, no
`crypto` and no `os/exec`. In Zig it is the *compiler's* boundary: a
module's imports are confined to its root's directory, so the `sekreto`
module (rooted at `src/sekreto.zig`) cannot import `plugins/` at all,
and a plugins module rooted at one plugin file compiles that plugin and
the shared HTTP helper and nothing else. A custom kind is a comptime
`sekreto.providerplugin(kind, make)` where `make` answers
`sekreto.provide(alloc, MyStore, .{ ... })` or the message of its
refusal. In TypeScript it is a *bundling* one: the
core reaches no plugin module, so a bundler drops what a chain does not
name. In Python, where importing is neither, it governs which kinds a
`Sekreto` can name and what an import pulls in: `import voxgig_sekreto`
brings the core, the four built-ins and `voxgig_plugin`, and no module
under `plugins/`; importing one plugin brings that plugin alone, because
the package initializer imports none of them and `ALL` is assembled only
when read. (Each module is named after the definition it holds, so
`from voxgig_sekreto.plugins import hashicorp` is the module, not the
definition; `Sekreto` refuses a module by name and says what to import.)

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

### `env` — built in

Environment variables, via `envkey`.

```ts
{ kind: 'env', prefix?: string }
```

`describe()` → `env` or `env:<prefix>`

### `dotenv` — built in

A `.env` file, read once on first use, and keyed exactly like the
environment. **A missing file is not an error** — it means "no secrets
here", so a chain works unchanged on a machine that has no `.env`.

```ts
{ kind: 'dotenv', file?: string, prefix?: string }   // file defaults to '.env'
```

`describe()` → `dotenv:<file>`

### `memory` — built in

Literal values, keyed like environment variables. Used by the shared spec
to test chain behaviour without touching the outside world, and useful for
defaults in an app.

```ts
{ kind: 'memory', values: Record<string,string>, prefix?: string }
```

`describe()` → `memory` or `memory:<prefix>`

### `file` — a mounted-secret directory — built in

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

### `hashicorp` — HashiCorp Vault — plugin `hashicorp`

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
`data`. Any other `kv` value raises — a version typo must not silently
behave as v2 and turn its 404 responses into misses. This is Vault's published
HTTP API, so the provider talks to a real Vault — or an
[OpenBao](https://openbao.org) — unmodified.

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

| address | result |
|---|---|
| `https://…` | allowed |
| `http://127.0.0.1`, `localhost`, `::1` | allowed — `vault server -dev`, test harnesses |
| `http://` anything else | `sekreto: refusing to send a token in plaintext to <addr> (use https)` |
| anything but http or https | `sekreto: not an http(s) address: <addr>` |

Over https every port verifies the server certificate **and** the host name;
neither is optional and there is no "skip verify" switch. The Rust port
trusts the Mozilla root set via `rustls`, and `SEKRETO_CA_BUNDLE` names a PEM
bundle of extra roots for an internal CA — additive, so a wrong path weakens
nothing, it just adds no roots.

### `boru` — a boru vault — plugin `boru`

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

### `awssecrets` / `awsparams` — AWS — plugin `aws`

```ts
{ kind: 'awssecrets', region?: string, keyid?: string, secret?: string,
  session?: string, addr?: string }
{ kind: 'awsparams',  ...same..., prefix?: string }
```

Region and credentials come from config first, then AWS's own environment
convention (`AWS_REGION`/`AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`); missing either raises.
Requests are SigV4-signed in-tree (see `sigv4`, earlier on this page). Default endpoints
follow the region's partition: a `cn-*` region resolves under
`.amazonaws.com.cn`.

`awssecrets`: `api.token` reads the secret named `api` (the `vaultref`
path) and takes the `token` field of its JSON `SecretString` — the AWS
idiom of one JSON map per secret. A plain-string secret is the value
itself, under the conventional field `value`. A
`ResourceNotFoundException` is a miss; any other failure raises.

`awsparams`: `db.pass.main` reads parameter `/db/pass/main` (under
`prefix`), decrypted. `ParameterNotFound` is a miss.

`describe()` → `awssecrets:<region>` / `awsparams:<region><prefix>`
(config values only, so the description is environment-independent)

### `gcpsecrets` — GCP Secret Manager — plugin `gcpsecrets`

```ts
{ kind: 'gcpsecrets', project: string, token?: string, addr?: string,
  metadataaddr?: string }
```

`api.token` reads secret `api_token` (dots flattened, Secret Manager ids
reject them), latest version, base64-decoded. The token comes from
config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE/GKE metadata
server — on Google's platform no credential configuration is needed. A
metadata token is renewed shortly before its `expires_in` runs out, so a
long-running process keeps working past the first hour. A 404 is a miss.

`describe()` → `gcpsecrets:<project>`

### `azuresecrets` — Azure Key Vault — plugin `azuresecrets`

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
configuration is needed. Logged-in and IMDS tokens are renewed shortly
before their `expires_in` runs out. A 404 is a miss.

`describe()` → `azuresecrets:<vault>`

### `onepassword` — 1Password, through a Connect server — plugin `onepassword`

```ts
{ kind: 'onepassword', addr: string, token: string, vault: string }
```

The item titled `api.token` (titles keep their dots) in the named vault;
the value is the field with purpose `PASSWORD`, or the field labelled
`value`. An item that is not there is a miss; a *vault* that is not
there raises — config names it, so its absence is a broken store.

`describe()` → `onepassword:<vault>`

### `doppler` — Doppler — plugin `doppler`

```ts
{ kind: 'doppler', token: string, project?: string, config?: string,
  addr?: string }
```

The whole config is downloaded once — Doppler's own bulk endpoint — and
answered from memory, like a remote `.env`: `api.token` is the
`API_TOKEN` entry. A service token is config-scoped, so `project` and
`config` are only needed with broader tokens. A missing entry is a miss.

`describe()` → `doppler`, or `doppler:<project>/<config>`

### `infisical` — Infisical — plugin `infisical`

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

### `secretspec` — SecretSpec — plugin `secretspec`

```
{ kind: 'secretspec', command?: string, file?: string, profile?: string,
  backend?: string, reason?: string, prefix?: string }
```

[SecretSpec](https://secretspec.dev) is a declaration — a
`secretspec.toml` naming the secrets a project needs — plus a chain of
its own backends to satisfy them from. sekreto reads it through the
`secretspec` CLI, as it reads boru through the `boru` CLI, because that
is the interface SecretSpec offers a program in another language.

`api.token` is the SecretSpec key `API_TOKEN` — the same mapping
`envkey` makes, which is the convention SecretSpec's own examples use.

`backend` chooses one of SecretSpec's backends (its `--provider` flag,
e.g. `keyring` or `dotenv://.env`). It is called `backend` here only
because `provider` already means a sekreto provider.

`reason` is passed on every read, defaulting to `sekreto`: SecretSpec
records accesses in an audit log and refuses to read without one.

A secret SecretSpec does not hold — undeclared, or declared with no
value — is a **miss**, so the chain carries on. A backend that does not
exist, or a keyring that will not open, is an **error**.

The two are easy to confuse and expensive to get wrong, because
SecretSpec words both as "not found":

```
$ secretspec get API_TOKEN --provider env      # nothing in the environment
Secret 'API_TOKEN' not found                   # -> a miss, try the next store

$ secretspec get API_TOKEN --provider keyring  # a build without that backend
Provider backend 'keyring' not found           # -> an error, do NOT fall through
```

sekreto matches the whole phrase, key included, so the second cannot be
read as the first. Reading it as a miss would send the chain on to a
weaker store without saying so — and a secretspec built without a backend
compiled in, or a typo in `backend`, produces exactly that message.

`describe()` → `secretspec`, or `secretspec:<backend>`

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
| `sekreto: unknown provider kind: <kind> (available: …)` | a spec naming a kind that is neither built in nor in `plugins` — and, for a kind sekreto ships as a plugin, which plugin to pass |
| `sekreto: invalid store name: <name>` | a spec `name` that is not a valid plugin tag |
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
| `sekreto: secretspec error: <why>` | the `secretspec` CLI failed for a reason that is not a missing secret |
| `sekreto: file provider cannot read <file>: <why>` | a secret file that exists but cannot be read |
| `sekreto: cannot reach <url>: <why>` | the store could not be contacted |
| `sekreto: malformed response from <url>` | a store answered 200 with a body that is not JSON |
| `sekreto: hashicorp: unsupported kv version: <kv>` | a `kv` other than 1 or 2 |

Those messages are pinned by `spec/sekreto.json`, so they cannot drift
between ports without a test going red.

---

## The shared spec

[`spec/sekreto.json`](spec/sekreto.json) is the contract. It is plain
JSON, run by every port through its own
[voxgig/omni](https://github.com/voxgig/omni) runner.

That JSON is **generated**: the source of truth is
[`spec/sekreto.aon`](spec/sekreto.aon), which names the categories, and
the case files under [`spec/def/`](spec/def), written in
[aontu](https://github.com/voxgig/aontu). `make spec` compiles them, and the
result is committed so that no port needs a Node toolchain to run its tests.
Edit the aontu, never the JSON.

The spec declares omni **format version 1**, so every runner validates
each entry strictly — an unknown field, more than one of `in`/`args`/`ctx`,
`err` beside `out` or an empty set fails the suite rather than passing
silently — and `make spec` unifies every source with omni's spec-format
shape before the JSON is accepted.

The groups:

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
