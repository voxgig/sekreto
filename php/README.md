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

## Four kinds are built in; the other eleven are plugins

The core holds the chain, the cache, redaction, and the four provider kinds
that read at most a local file — `env`, `memory`, `dotenv`, `file`. Every
kind that opens a socket, signs a request, spawns a process, or does
cryptography is a [voxgig/plugin](https://github.com/voxgig/plugin) definition in its own
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

## The mini vault

`plugins/minivault.php` is a store this port owns outright rather than a
client for a server somebody else runs: every secret, encrypted, in one
binary file. It has a master key and restricted keys, and it is the port's
worked example of a definition publishing an API beside its provider.

```php
require_once 'plugins/minivault.php';

use function Voxgig\Sekreto\Plugins\createvault;
use function Voxgig\Sekreto\Plugins\minivault;
use function Voxgig\Sekreto\Plugins\vaultof;

$vault = createvault(['file' => 'app.skmv', 'passphrase' => $master]);
$vault->set('api.token', 'tok01');
$vault->grant(['key' => 'ci', 'passphrase' => $ci, 'names' => ['api.token']]);

$secrets = new Sekreto([
    'plugins' => [minivault()],
    'providers' => [['kind' => 'minivault', 'file' => 'app.skmv',
                     'vaultkey' => 'ci', 'passphrase' => $ci]],
]);

$secrets->get('api.token');   // the chain reads
vaultof($secrets)->list();    // ['api.token'] — as the `ci` key sees it
```

A chain reads; writing is a deliberate act with an API of its own, so the
definition exports `vault` beside `provider` and `vaultof` reads it back
off `$secrets->host`. ext-openssl and ext-hash carry all four primitives,
so nothing here is hand-rolled. What each key may do, what the file holds,
and what the whole thing does and does not protect are in
[DOCS.md](../DOCS.md#minivault--a-local-mini-vault--plugin-minivault).

One thing this port has to say out loud: an empty `grants` is an OBJECT in
a key ring and an ARRAY in a meta record, and PHP's `[]` encodes as `[]`
for both. `mvjson` forces the ring's, because a ring that reads back as a
list is a key with no grants at all.

Ports carrying this kind read each other's files, which
`test/minivault.php` checks against every committed vault in
`test/fixture/`, including the one this port wrote.

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
| `plugins/minivault.php` | the mini vault: the format, the keys, the API, the definition |
| `plugins/plugins.php` | `allplugins()`, the full set, built on demand |
| `test/run.php` | the conformance suite |
| `test/plugins.php` | the plugin seam |
| `test/minivault.php` | the mini vault, and the committed files every port reads |
| `test/included.php` | what one require costs, in a fresh interpreter |
| `cli/sekreto-cli.php` | the app that needs a secret |

## Notes

- **`writejson`, not `json_encode`, for anything emitted.** `json_encode`
  escapes `/` as `\/` and every non-ASCII character as `\uXXXX` unless
  given `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`. The AWS plugin
  had passed the first flag alone since it signs the body it sends; with
  only the slashes turned off, a non-ASCII secret path still signed
  different bytes from every other port.

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
