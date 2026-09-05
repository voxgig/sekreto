# sekreto — PHP

The PHP port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find (or fetch) voxgig/plugin
make test                     # the conformance suite, then the plugin seam
make check-core               # what requiring the core pulls in
```

No Composer, no autoloader: `require_once` and nothing else, so the
library drops into any project.

## Four kinds are built in; the other ten are plugins

The core holds the chain, the cache, redaction, and the four provider kinds
that read at most a local file — `env`, `memory`, `dotenv`, `file`. Every
kind that opens a socket, signs a request or spawns a process is a
[voxgig/plugin](https://github.com/voxgig/plugin) definition in its own
file under `plugins/`, and a `Sekreto` can build only the kinds it was
handed:

```php
require_once __DIR__ . '/src/Sekreto.php';
require_once __DIR__ . '/plugins/hashicorp.php';

use Voxgig\Sekreto\Sekreto;
use function Voxgig\Sekreto\Plugins\hashicorp;

$secrets = new Sekreto([
    'plugins' => [hashicorp()],
    'providers' => [
        ['kind' => 'env'],
        ['kind' => 'hashicorp', 'addr' => $addr, 'token' => $token],
    ],
]);
```

A kind that was not passed in is refused, and the message names the fix.
For every kind at once — the CLI, the conformance suite, an app whose
chain is decided at run time — `allplugins()` from `plugins/plugins.php`.

The boundary is the require graph plus the namespace: `src/` is
`Voxgig\Sekreto`, `plugins/` is `Voxgig\Sekreto\Plugins`, and nothing in
the first requires or names anything in the second. `make check-core`
prints the core's include graph; `test/plugins.php` asserts it, together
with the fifteen other things the conformance suite cannot see.

voxgig/plugin is a dependency of the library itself, not only of the
tests. PHP here has no package manager — this port ships no Composer
manifest, and neither does plugin's own PHP port — so the dependency is a
checkout, found the way this port finds voxgig/omni: `PLUGIN_HOME`, then a
sibling checkout. `make deps` fetches a shallow clone when there is none.

HTTP goes through the stream wrapper with `ignore_errors` set, so a 404
from a vault is read as an answer rather than thrown away. That needs no
extension beyond a default PHP build — `curl` is not required.

## Layout

| | |
|---|---|
| `src/Sekreto.php` | the facade, `Name`, `parsedotenv`, `redact` |
| `src/Providers.php` | `Provider`, `providerplugin`, the four built-in kinds |
| `src/Addr.php` | `checkaddr`, `safeaddr` |
| `src/Plugin.php` | where voxgig/plugin is — the only path search in the library |
| `plugins/<kind>.php` | one plugin kind per file, `Voxgig\Sekreto\Plugins` |
| `plugins/httpjson.php` | the shared HTTP round-trip |
| `plugins/runcmd.php` | the shared child process |
| `plugins/sigv4.php` | AWS request signing — the only hashing in this port |
| `plugins/plugins.php` | `allplugins()`, the full set, built on demand |
| `test/run.php` | the conformance suite |
| `test/plugins.php` | the plugin seam |
| `test/included.php` | what one require costs, in a fresh interpreter |
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
