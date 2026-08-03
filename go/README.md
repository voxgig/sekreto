# sekreto — Go

The Go port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

Go has no exceptions, so where the canonical port throws, this one
returns a `*SekretoError`. A provider miss is a `(value, found, error)`
triple rather than a nil string, which keeps an empty-string secret
distinguishable from an absent one.

The cache keeps insertion order explicitly: map iteration is randomised,
and `Redact` must not vary between runs.

`make test` generates a `go.work` pointing at the voxgig/omni checkout, so
`go.mod` carries no path that works on only one machine.

## Layout

| | |
|---|---|
| `sekreto/sekreto.go` | the facade, the name helpers, `ParseDotenv`, `Redact` |
| `sekreto/providers.go` | the five providers |
| `sekreto_test.go` | the conformance suite |
| `cli/main.go` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Go
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh go      # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
make build
build/sekreto-cli http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Go is listed there.
