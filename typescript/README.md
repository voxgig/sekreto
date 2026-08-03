# sekreto — TypeScript

The TypeScript port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
npm test                      # the conformance suite
```

This port is **canonical**. `src/Sekreto.ts` and `src/Providers.ts`
define sekreto's behaviour; every other port is a translation of them, and
a change belongs here first.

`get` and `try` are async, because the vault providers are.

## Layout

| | |
|---|---|
| `src/Sekreto.ts` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/Providers.ts` | the five providers |
| `src/omnihome.ts` | finding the voxgig/omni checkout and the shared spec |
| `test/sekreto.test.ts` | the conformance suite |
| `cli/sekreto-cli.ts` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the TypeScript
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh typescript# just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
npm run build
node dist/cli/sekreto-cli.js http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
TypeScript is listed there.
