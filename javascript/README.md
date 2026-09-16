# sekreto — JavaScript

The JavaScript port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
npm test                      # the conformance suite
```

A direct port of the TypeScript, minus the types. `get` and `try` are
async, because the vault providers are.

## Built in, or a plugin

The core — `@voxgig/sekreto-js` — carries the chain and the four kinds
that read at most a local file: `env`, `memory`, `dotenv`, `file`. Every
other kind is a plugin under `plugins/`, a
[voxgig/plugin](https://github.com/voxgig/plugin) definition the calling
project requires and passes in:

```js
const { Sekreto } = require('@voxgig/sekreto-js')
const { hashicorp } = require('@voxgig/sekreto-js/plugins/hashicorp')
const { awssecrets } = require('@voxgig/sekreto-js/plugins/aws')

const secrets = new Sekreto({
  plugins: [hashicorp, awssecrets],
  providers: [
    { kind: 'env' },
    { kind: 'dotenv', file: '.env' },
    { kind: 'hashicorp', name: 'prod', addr: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN },
    { kind: 'awssecrets', region: 'eu-west-1' },
  ],
})

const token = await secrets.get('api.token')
const prod = await secrets.getfrom('prod', 'api.token')

secrets.host.list()    // { env: 'live', dotenv: 'live', 'hashicorp$prod': 'live', awssecrets: 'live' }
secrets.close()        // every store deactivated and unloaded, in reverse
```

| | require | exports |
|---|---|---|
| the core | `@voxgig/sekreto-js` | `Sekreto`, the name helpers, the four built-in providers, `providerplugin`, `checkaddr` |
| one plugin | `@voxgig/sekreto-js/plugins/<name>` | the definition (`hashicorp`, `awssecrets` + `awsparams` + `sigv4`, …) and its provider factory |
| every plugin | `@voxgig/sekreto-js/plugins` | `allplugins`, and everything each module exports |

Destructure the definition — a bare `require` of a plugin hands back the
module, and a module passed as a plugin is refused by name. A kind that
was not passed in is refused by name too, with the plugin to pass.

A bundler carries only the plugins a chain requires: nothing under `src/`
reaches `plugins/`, and requiring one plugin reaches that plugin and the
shared HTTP helper, not the other nine. `test/plugins.test.js` proves
both from the module graph of a fresh process, and
`test/lazyload.test.js` proves the core surface exposes no plugin at all.
A custom store is `providerplugin(kind, make)`; see
[DOCS.md](../DOCS.md#plugins).

The one dependency is `@voxgig/plugin-js`, which itself has none.

`src/provider/support.js` requires `src/Sekreto.js` at the top, and
`Sekreto.js` reaches `src/provider/builtin.js` through a function — at
the one point a chain is built. CommonJS resolves the cycle that way
round; the other way, `support.js` would destructure a half-built module.

## The mini vault

`plugins/minivault.js` is a store this port owns outright rather than a
client for a server somebody else runs: every secret, encrypted, in one
binary file. It has a master key and restricted keys, and it is the port's
worked example of a definition publishing an API beside its provider.

```js
const { Sekreto } = require('@voxgig/sekreto-js')
const {
  createvault, minivault, vaultof,
} = require('@voxgig/sekreto-js/plugins/minivault')

const vault = createvault({ file: 'app.skmv', passphrase: MASTER })
vault.set('api.token', 'tok01')
vault.grant({ key: 'ci', passphrase: CI, names: ['api.token'] })

const secrets = new Sekreto({
  plugins: [minivault],
  providers: [{ kind: 'minivault', file: 'app.skmv', vaultkey: 'ci', passphrase: CI }],
})

await secrets.get('api.token')     // the chain reads
vaultof(secrets).list()            // ['api.token'] — as the `ci` key sees it
```

A chain reads; writing is a deliberate act with an API of its own, so the
definition exports `vault` beside `provider` and `vaultof` reads it back
off `secrets.host`. What each key may do, what the file holds, and what
the whole thing does and does not protect are in
[DOCS.md](../DOCS.md#minivault--a-local-mini-vault--plugin-minivault).

Ports carrying this kind read each other's files, which
`test/minivault.test.js` checks against every committed vault in
`test/fixture/`, including the one this port wrote.

## Layout

| | |
|---|---|
| `src/Sekreto.js` | the facade on a voxgig/plugin host, the name helpers, `parsedotenv`, `redact` |
| `src/provider/support.js` | `providerplugin` — how a kind becomes a definition — and the deferred `nodemod` |
| `src/provider/builtin.js` | the four built-in definitions, `BUILTINS`, and `KINDS` |
| `src/provider/{env,memory,dotenv,file}.js` | the built-in providers |
| `src/provider/addr.js` | `checkaddr`, the plaintext-address guard — pure, and on the spec |
| `plugins/<name>.js` | one plugin each; `plugins/aws.js` carries `sigv4.js` beside it |
| `plugins/httpjson.js` | the bounded, redirect-refusing HTTP round-trip every wire plugin shares |
| `plugins/minivault.js` | the mini vault: the format, the keys, the API, the definition |
| `plugins/index.js` | the full set |
| `test/sekreto.test.js` | the conformance suite, on `@voxgig/omni-js` from npm |
| `test/plugins.test.js`, `test/lazyload.test.js` | the plugin seam, from both sides |
| `test/minivault.test.js` | the mini vault, and the committed files every port reads |
| `cli/sekreto-cli.js` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the JavaScript
[voxgig/omni](https://github.com/voxgig/omni) runner, taken from npm as
the devDependency `@voxgig/omni-js`; `make test` runs `npm install`
first. A devDependency is omni's isolation device for Node: npm never
installs one transitively, so nothing that depends on this package can
acquire the runner through it.

voxgig/plugin comes from npm the same way, as the runtime dependency
`@voxgig/plugin-js`, so an ordinary build needs no checkout. For the two
cases npm cannot serve — a machine with no registry, and a plugin change
not yet published — the Makefile finds a checkout the way every port
finds omni (`PLUGIN_HOME`, then a sibling, then the usual places),
`make plugin-fetch` clones one when there is none, and `make build-local`
installs it over the published package. The library itself searches no
path.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh javascript# just this one
```

It starts a token-protected API and stand-in vaults, then runs this
port's CLI against them from each secret source in turn:

```sh
(nothing to build)
node cli/sekreto-cli.js http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
JavaScript is listed there.
