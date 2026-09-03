# sekreto — Go

The Go port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

Go has no exceptions, so where the canonical port throws, this one
returns a `*SekretoError`. A provider miss is a `(value, found, error)`
triple rather than a nil string, which keeps an empty-string secret
distinguishable from an absent one. `New` returns an error too, because
building a chain can fail — an unknown kind, a bad store name, a provider
refusing its configuration.

The cache keeps insertion order explicitly: map iteration is randomised,
and `Redact` must not vary between runs.

## Built in, or a plugin

The `sekreto` package carries the chain and the four kinds that read at
most a local file: `env`, `memory`, `dotenv`, `file`. It imports no
`net/http`, no `crypto` and no `os/exec`. Every other kind is a plugin
package under `plugins/`, a [voxgig/plugin](https://github.com/voxgig/plugin)
definition the calling project imports and passes in — and a package
that is not imported is not in the binary:

```go
import (
    plugin "github.com/voxgig/plugin/go/plugin"

    "github.com/voxgig/sekreto/go/plugins/aws"
    "github.com/voxgig/sekreto/go/plugins/hashicorp"
    "github.com/voxgig/sekreto/go/sekreto"
)

secrets, err := sekreto.New(&sekreto.Options{
    Plugins: []plugin.Definition{hashicorp.Plugin, aws.Secrets},
    Providers: []*sekreto.ProviderSpec{
        {Kind: "env"},
        {Kind: "dotenv", File: ".env"},
        {Kind: "hashicorp", Name: "prod", Addr: os.Getenv("VAULT_ADDR"), Token: os.Getenv("VAULT_TOKEN")},
        {Kind: "awssecrets", Region: "eu-west-1"},
    },
})

token, err := secrets.Get("api.token")
prod, err := secrets.GetFrom("prod", "api.token")

secrets.Host().List()   // map[awssecrets:live dotenv:live env:live hashicorp$prod:live]
secrets.Close()         // every store deactivated and unloaded, in reverse
```

| | import | exports |
|---|---|---|
| the core | `github.com/voxgig/sekreto/go/sekreto` | `Sekreto`, `New`, the name helpers, the four built-in providers, `Builtins()`, `ProviderPlugin`, `CheckAddr` |
| one plugin | `github.com/voxgig/sekreto/go/plugins/<kind>` | `Plugin` (`aws` has `Secrets`, `Params` and `SigV4`) and its `Provider` type |
| every plugin | `github.com/voxgig/sekreto/go/plugins` | `All()` |
| the shared HTTP helper | `github.com/voxgig/sekreto/go/plugins/httpjson` | `Call`, `Get`, `Dig`, … — for writing a plugin, never for the core |

A kind that was not passed in is refused by name, with the plugin to pass.
A custom store is `sekreto.ProviderPlugin(kind, make)`; a provider
already built joins the chain as `&ProviderSpec{Provider: p}`. See
[DOCS.md](../DOCS.md#plugins).

The one dependency is `github.com/voxgig/plugin/go`, which itself has
none, resolved from the module proxy like any other.

## Layout

| | |
|---|---|
| `sekreto/sekreto.go` | the facade on a voxgig/plugin host, the name helpers, `ParseDotenv`, `Redact` |
| `sekreto/providers.go` | `Provider`, `ProviderSpec`, `ProviderPlugin`, `Builtins`, and the four built-in providers |
| `sekreto/addr.go` | `CheckAddr`, the plaintext-address guard — pure, and on the spec |
| `plugins/<kind>/` | one package per plugin; `plugins/aws` carries `sigv4.go` |
| `plugins/httpjson/` | the bounded, redirect-refusing HTTP round-trip every wire plugin shares |
| `plugins/plugins.go` | the full set |
| `sekreto/plugin_test.go`, `plugins/plugins_test.go` | the plugin seam, from both sides |
| `testutil/sekreto_test.go` | the conformance suite |
| `cli/main.go` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Go
[voxgig/omni](https://github.com/voxgig/omni) runner, resolved from the
module proxy; no checkout is needed.

The suite lives in the nested `testutil` module, which requires omni by
its `go/vX.Y.Z` release tag from the module proxy and replaces the
library under test with `../` — a path relative to its own `go.mod`, so
nothing checked in works on only one machine and no `go.work` is needed.
`make build-clean` proves the library builds with no omni at all.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh go      # just this one
```

It starts a token-protected API and stand-in vaults, then runs this
port's CLI against them from each secret source in turn:

```sh
make build
build/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Go is listed there.
