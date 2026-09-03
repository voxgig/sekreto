# sekreto — TypeScript

The TypeScript port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
npm test                      # the conformance suite
```

This port is **canonical**. `src/Sekreto.ts`, `src/provider/` and
`plugins/` define sekreto's behaviour; every other port is a translation
of them, and a change belongs here first.

`get` and `try` are async, because the vault providers are.

## Built in, or a plugin

The core — `@voxgig/sekreto` — carries the chain and the four kinds that
read at most a local file: `env`, `memory`, `dotenv`, `file`. Every other
kind is a plugin under `plugins/`, a [voxgig/plugin](https://github.com/voxgig/plugin)
definition the calling project imports and passes in:

```ts
import { Sekreto } from '@voxgig/sekreto'
import { hashicorp } from '@voxgig/sekreto/plugins/hashicorp'
import { awssecrets } from '@voxgig/sekreto/plugins/aws'

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

| | import | exports |
|---|---|---|
| the core | `@voxgig/sekreto` | `Sekreto`, the name helpers, the four built-in providers, `providerplugin`, `checkaddr` |
| one plugin | `@voxgig/sekreto/plugins/<name>` | the definition (`hashicorp`, `awssecrets` + `awsparams` + `sigv4`, …) and its provider factory |
| every plugin | `@voxgig/sekreto/plugins` | `allplugins`, and everything each module exports |

A kind that was not passed in is refused by name, with the plugin to pass.
A bundler carries only the plugins a chain imports: nothing under `src/`
reaches `plugins/`, and `test/lazyload.test.ts` proves it from both sides.
A custom store is `providerplugin(kind, make)`; see [DOCS.md](../DOCS.md#plugins).

The one dependency is `@voxgig/plugin`, which itself has none.

## Layout

| | |
|---|---|
| `src/Sekreto.ts` | the facade on a voxgig/plugin host, the name helpers, `parsedotenv`, `redact` |
| `src/provider/support.ts` | `Provider`, `ProviderSpec`, `providerplugin` — how a kind becomes a definition |
| `src/provider/builtin.ts` | the four built-in definitions, `BUILTINS`, and `KINDS` |
| `src/provider/{env,memory,dotenv,file}.ts` | the built-in providers |
| `src/provider/addr.ts` | `checkaddr`, the plaintext-address guard — pure, and on the spec |
| `plugins/<name>.ts` | one plugin each; `plugins/aws.ts` carries `sigv4.ts` beside it |
| `plugins/httpjson.ts` | the bounded, redirect-refusing HTTP round-trip every wire plugin shares |
| `plugins/index.ts` | the full set |
| `test/sekreto.test.ts` | the conformance suite, on `@voxgig/omni` from npm |
| `test/plugins.test.ts`, `test/lazyload.test.ts` | the plugin seam, from both sides |
| `cli/sekreto-cli.ts` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the TypeScript
[voxgig/omni](https://github.com/voxgig/omni) runner, taken from npm as
the devDependency `@voxgig/omni`. A devDependency is omni's isolation
device for Node: npm never installs one transitively, so nothing that
depends on this package can acquire the runner through it.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh typescript# just this one
```

It starts a token-protected API and stand-in vaults, then runs this
port's CLI against them from each secret source in turn:

```sh
npm run build
node dist/cli/sekreto-cli.js http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
TypeScript is listed there.
