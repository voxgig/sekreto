# sekreto — Ruby

The Ruby port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

Synchronous, on `net/http` and `json` — both stdlib.

Provider specs are accepted with either string or symbol keys, so a chain
read from JSON and one written by hand both work.

## Layout

| | |
|---|---|
| `lib/voxgig_sekreto/sekreto.rb` | the facade, the name helpers, `parsedotenv`, `redact` |
| `lib/voxgig_sekreto/providers.rb` | the five providers |
| `test/test_sekreto.rb` | the conformance suite |
| `cli/sekreto_cli.rb` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Ruby
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh ruby    # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
(nothing to build)
ruby cli/sekreto_cli.rb http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Ruby is listed there.
