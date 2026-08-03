# sekreto — JavaScript

The JavaScript port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
npm test                      # the conformance suite
```

A direct port of the TypeScript, minus the types. `get` and `try` are
async.

`Providers.js` imports `Sekreto.js` at the top, and `Sekreto.js` requires
`Providers.js` lazily — at the single point a provider is built. CommonJS
resolves the cycle that way round; the other way, `Providers` would see a
half-built module.

## Layout

| | |
|---|---|
| `src/Sekreto.js` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.js` | the five providers |
| `test/sekreto.test.js` | the conformance suite |
| `cli/sekreto-cli.js` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the JavaScript
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh javascript# just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
(nothing to build)
node cli/sekreto-cli.js http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
JavaScript is listed there.
