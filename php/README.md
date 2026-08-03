# sekreto — PHP

The PHP port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

No Composer, no autoloader: `require_once` and nothing else, so the
library drops into any project.

HTTP goes through the stream wrapper with `ignore_errors` set, so a 404
from a vault is read as an answer rather than thrown away. That needs no
extension beyond a default PHP build — `curl` is not required.

## Layout

| | |
|---|---|
| `src/Sekreto.php` | the facade, `Name`, `parsedotenv`, `redact` |
| `src/Providers.php` | the five providers |
| `test/run.php` | the conformance suite |
| `cli/sekreto-cli.php` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the PHP
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh php     # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
(nothing to build)
php cli/sekreto-cli.php http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
PHP is listed there.
