# sekreto — Ruby

The Ruby port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, and the plugin seam
```

Synchronous, on `json` — and, in the plugins that speak to a store over
the wire, `net/http`. Both stdlib.

Provider specs are accepted with either string or symbol keys, so a chain
read from JSON and one written by hand both work.

## Built in, or a plugin

`voxgig_sekreto` carries the chain and the four kinds that read at most a
local file: `env`, `memory`, `dotenv`, `file`. Requiring it loads the
core, those four and `voxgig_plugin`, and nothing under `plugins/` —
which means no `net/http`, no `openssl` and no `open3`. Every other kind
is a plugin file there, a
[voxgig/plugin](https://github.com/voxgig/plugin) definition the calling
project requires and passes in:

```ruby
require 'voxgig_sekreto'
require 'voxgig_sekreto/plugins/hashicorp'
require 'voxgig_sekreto/plugins/aws'

secrets = VoxgigSekreto::Sekreto.new(
  'plugins' => [VoxgigSekreto::Plugins::HASHICORP, VoxgigSekreto::Plugins::AWSSECRETS],
  'providers' => [
    { 'kind' => 'env' },
    { 'kind' => 'dotenv', 'file' => '.env' },
    { 'kind' => 'hashicorp', 'name' => 'prod',
      'addr' => ENV['VAULT_ADDR'], 'token' => ENV['VAULT_TOKEN'] },
    { 'kind' => 'awssecrets', 'region' => 'eu-west-1' }
  ]
)

token = secrets.get('api.token')
prod = secrets.getfrom('prod', 'api.token')

secrets.host.list  # {"awssecrets"=>"live", "dotenv"=>"live", "env"=>"live", "hashicorp$prod"=>"live"}
secrets.close      # every store deactivated and unloaded, in reverse
```

| | require | holds |
|---|---|---|
| the core | `voxgig_sekreto` | `Sekreto`, the name helpers, the four built-in providers, `providerplugin`, `checkaddr` |
| one plugin | `voxgig_sekreto/plugins/<name>` | the definition (`Plugins::HASHICORP`, `Plugins::AWSSECRETS` + `Plugins::AWSPARAMS` + `sigv4`, …) and its provider class |
| every plugin | `voxgig_sekreto/plugins` | `Plugins::ALL` |

Requiring one plugin loads only that plugin — Ruby has no package
initializer to run, so a directory of files gets that for free. The trap
Ruby has instead is that the three things nearest to hand are all not
definitions: `require` returns `true`, a plugin file defines a *module*,
and the definition is one constant further on. `Sekreto` refuses all
three by name, saying what to pass.

A kind that was not passed in is refused by name, with the plugin to
pass. A custom store is `providerplugin(kind, make)`; see
[DOCS.md](../DOCS.md#plugins).

The one dependency is voxgig/plugin, which itself has none. There is no
gem yet, so the library requires it by name — an installed gem wins — and
a checkout finds the port the way the tests find omni: `PLUGIN_HOME`,
then the usual places (`test/pluginhome.rb`), for the tests and the CLI.
`make deps` fetches a shallow clone into `../.plugin` when there is none,
which is what `npm install` and `go mod download` do for the other ports.
The library itself searches no path.

## Layout

| | |
|---|---|
| `lib/voxgig_sekreto/sekreto.rb` | the facade on a voxgig/plugin host, the name helpers, `parsedotenv`, `redact` |
| `lib/voxgig_sekreto/providers.rb` | `providerplugin`, `BUILTINS`, `KINDS`, and the four built-in providers |
| `lib/voxgig_sekreto/addr.rb` | `checkaddr`, the plaintext-address guard — pure, and on the spec |
| `lib/voxgig_sekreto/plugins/<name>.rb` | one plugin each; `aws.rb` carries `sigv4.rb` beside it |
| `lib/voxgig_sekreto/plugins/httpjson.rb` | the bounded, redirect-refusing HTTP round-trip every wire plugin shares |
| `lib/voxgig_sekreto/plugins.rb` | the full set |
| `test/test_sekreto.rb` | the conformance suite |
| `test/test_plugins.rb` | the plugin seam, from both sides |
| `cli/sekreto_cli.rb` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Ruby
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository, and `PLUGIN_HOME`
likewise for voxgig/plugin.

`test/test_plugins.rb` is the other half, and the conformance suite
cannot see any of it: that suite hands every plugin to every chain it
builds, so it can never notice a missing one. The seam tests pin what a
consumer sees — the full set holds every kind, an unloaded kind is
refused naming the fix, a `SekretoError` crosses the boundary and comes
back as itself — and, in a fresh interpreter, what `$LOADED_FEATURES`
holds after each require. That last one is this port's version of a link
map: Ruby has no compile-time boundary, so the boundary is the import
graph, and it is measured rather than asserted.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh ruby    # just this one
```

It starts a token-protected API and stand-in vaults, then runs this
port's CLI against them from each secret source in turn:

```sh
(nothing to build)
ruby cli/sekreto_cli.rb http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Ruby is listed there.
