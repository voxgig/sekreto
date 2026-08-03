# sekreto — Python

The Python port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

Synchronous throughout — `urllib.request` blocks, and a secrets lookup
at startup has no reason not to.

The optional lookup is `try_`, since `try` is a statement. A miss is
`None`.

## Layout

| | |
|---|---|
| `voxgig_sekreto/sekreto.py` | the facade, the name helpers, `parsedotenv`, `redact` |
| `voxgig_sekreto/providers.py` | the five providers |
| `tests/test_sekreto.py` | the conformance suite |
| `cli/sekreto_cli.py` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Python
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh python  # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
(nothing to build)
python3 cli/sekreto_cli.py http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Python is listed there.
