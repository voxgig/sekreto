# sekreto — Rust

The Rust port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

std has no HTTP client and no JSON, and sekreto takes no crates, so
this port carries small ones of both.

`src/http.rs` speaks HTTP/1.1 over a `TcpStream`: a plaintext GET, a status
line, and a body delimited by `Content-Length` or by chunks. **There is no
TLS** — a vault reachable only over https needs a real client, and that
file is the one place to change.

Errors come back as `SekretoError` in a `Result`; a provider miss is
`Ok(None)`. The cache is a `Vec`, not a map, so redaction order is stable.

`make test` symlinks `vendor/omni` at the voxgig/omni checkout, so
`Cargo.toml` names a fixed path that resolves anywhere.

## Layout

| | |
|---|---|
| `src/sekreto.rs` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/providers.rs` | the five providers |
| `src/json.rs` | the JSON reader and writer |
| `src/http.rs` | the HTTP/1.1 client |
| `tests/sekreto.rs` | the conformance suite |
| `src/bin/sekreto-cli.rs` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Rust
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh rust    # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
make build
target/release/sekreto-cli http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Rust is listed there.
