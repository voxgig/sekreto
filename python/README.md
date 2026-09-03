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

## Built in, or a plugin

The package — `voxgig_sekreto` — carries the chain and the four kinds
that read at most a local file: `env`, `memory`, `dotenv`, `file`.
Importing it pulls in the core, those four and `voxgig_plugin`, and
nothing under `plugins/`. Every other kind is a plugin module there, a
[voxgig/plugin](https://github.com/voxgig/plugin) definition the calling
project imports and passes in:

```python
from voxgig_sekreto import Sekreto
from voxgig_sekreto.plugins.hashicorp import hashicorp
from voxgig_sekreto.plugins.aws import awssecrets

secrets = Sekreto({
    'plugins': [hashicorp, awssecrets],
    'providers': [
        {'kind': 'env'},
        {'kind': 'dotenv', 'file': '.env'},
        {'kind': 'hashicorp', 'name': 'prod', 'addr': os.environ['VAULT_ADDR'], 'token': os.environ['VAULT_TOKEN']},
        {'kind': 'awssecrets', 'region': 'eu-west-1'},
    ],
})

token = secrets.get('api.token')
prod = secrets.getfrom('prod', 'api.token')

secrets.host.list()    # {'env': 'live', 'dotenv': 'live', 'hashicorp$prod': 'live', 'awssecrets': 'live'}
secrets.close()        # every store deactivated and unloaded, in reverse
```

| | import | exports |
|---|---|---|
| the core | `voxgig_sekreto` | `Sekreto`, the name helpers, the four built-in providers, `providerplugin`, `checkaddr` |
| one plugin | `voxgig_sekreto.plugins.<name>` | the definition (`hashicorp`, `awssecrets` + `awsparams` + `sigv4`, …) and its provider class |
| every plugin | `voxgig_sekreto.plugins` | `ALL`, and everything each module exports |

A kind that was not passed in is refused by name, with the plugin to pass.
A custom store is `providerplugin(kind, make)`; see
[DOCS.md](../DOCS.md#plugins).

The one dependency is `voxgig-plugin`, which itself has none. It is not
on PyPI yet, so `pyproject.toml` declares it from git; a checkout that
has not pip-installed it finds a sibling `plugin` checkout the way the
tests find omni — `PLUGIN_HOME`, then the usual places
(`tests/pluginhome.py`) — for the tests and the CLI, and `make deps`
fetches a shallow clone into `../.plugin` when there is none, which is
what `npm install` and `go mod download` do for the other two ports.
The library itself searches no path.

## Layout

| | |
|---|---|
| `voxgig_sekreto/sekreto.py` | the facade on a voxgig/plugin host, the name helpers, `parsedotenv`, `redact` |
| `voxgig_sekreto/providers.py` | `Provider`, `providerplugin`, `BUILTINS`, and the four built-in providers |
| `voxgig_sekreto/addr.py` | `checkaddr`, the plaintext-address guard — pure, and on the spec |
| `voxgig_sekreto/plugins/<name>.py` | one plugin each; `aws.py` carries `sigv4.py` beside it |
| `voxgig_sekreto/plugins/httpjson.py` | the bounded, redirect-refusing HTTP round-trip every wire plugin shares |
| `voxgig_sekreto/plugins/__init__.py` | the full set |
| `tests/test_sekreto.py` | the conformance suite |
| `tests/test_plugins.py` | the plugin seam, from both sides |
| `cli/sekreto_cli.py` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Python
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository, and
`PLUGIN_HOME` likewise for voxgig/plugin.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh python  # just this one
```

It starts a token-protected API and stand-in vaults, then runs this
port's CLI against them from each secret source in turn:

```sh
(nothing to build)
python3 cli/sekreto_cli.py http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Python is listed there.
