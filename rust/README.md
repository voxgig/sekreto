# sekreto — Rust

The Rust port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # link voxgig/plugin
make test                     # the conformance suite, and the plugin seam
make check-core               # what the core actually links
```

## The core, and the plugins

Four provider kinds are **built in** — `env`, `memory`, `dotenv` and
`file` — and what makes them built in is that they read at most a local
file. Everything that opens a socket, signs a request or spawns a process
is a [voxgig/plugin](https://github.com/voxgig/plugin) definition in its
own crate under `plugins/`, and a `Sekreto` can build exactly the kinds
its constructor was handed:

```rust
use voxgig_sekreto::{Options, ProviderSpec, Sekreto};

let mut secrets = Sekreto::new(Options {
    plugins: vec![voxgig_sekreto_hashicorp::plugin()],
    providers: vec![
        ProviderSpec { values: local, ..ProviderSpec::of("memory") },
        ProviderSpec { addr, token, ..ProviderSpec::of("hashicorp") },
    ],
    ..Default::default()
})?;
```

Loading is explicit and never a side effect of importing: a list handed to
a constructor cannot be erased by a compiler, and the set of stores an app
can reach is not something to discover at run time. A kind that was not
passed in is refused with the message that names the fix.

**Cargo is the boundary, and it is checkable.** The core crate's whole
dependency list is `voxgig_plugin`; it does not name a TLS crate, and it
cannot name a plugin, because every plugin crate depends on it:

```sh
$ cargo tree -p voxgig_sekreto --edges normal
voxgig_sekreto v0.1.0
└── voxgig_plugin v0.1.6
```

So a consumer whose chain is `[dotenv, env]` compiles no TLS, no HTTP
client and no request signing. The TLS exception AGENTS.md rule 3 permits
has not gone away — it has moved to `plugins/httpjson`, which is where the
sockets are, and `plugins/secretspec` (a subprocess, no network) has no
TLS anywhere in its closure at all.

`plugins/httpjson/src/http.rs` speaks HTTP/1.1 over a `TcpStream`: a GET,
a status line, and a body delimited by `Content-Length`, by chunks, or by
the connection closing. https goes over **rustls**, verifying both the
server certificate and the host name, with `SEKRETO_CA_BUNDLE` adding
roots for an internal CA — which is how most private Vault deployments are
set up. std has no HTTP client and no JSON, so this port carries small
ones of both, next to each other and under `plugins/`.

`sigv4` travels with the AWS plugin, `crypto.rs` with it: the core of no
port imports a hash function.

Errors come back as `SekretoError` in a `Result`; a provider miss is
`Ok(None)`. Building a chain can also fail the host's way, so
`Sekreto::new` returns `ChainError` — `Sekreto` for sekreto's own refusals
(the spec pins those messages byte for byte) and `Plugin` for anything
else a definition raised, kept exactly as the host reported it. The cache
is a `Vec`, not a map, so redaction order is stable.

## voxgig/plugin, and omni

voxgig/plugin has no crates.io release, so Cargo takes it by path and
`make deps` makes that path: a gitignored `.plugin/rust` link to whichever
checkout it found — `$PLUGIN_HOME`, a sibling, or a shallow clone it
fetches. The library searches nothing; the Makefile does.

The conformance suite is its own package, `corpus/`, which takes omni as a
git dependency pinned to omni's `rust/vX.Y.Z` release tag; Cargo fetches
it, and no shipped manifest here ever names it.

## Layout

| | |
|---|---|
| `src/sekreto.rs` | the facade, the name helpers, `parsedotenv`, `redact` |
| `src/providers.rs` | `Provider`, `ProviderSpec`, the four built-ins, `providerplugin` |
| `src/addr.rs` | `checkaddr` — pure, so it stays in the core |
| `plugins/httpjson/` | the HTTP/1.1 client and the JSON reader — and the TLS |
| `plugins/<kind>/` | one crate per plugin kind; `aws` carries `sigv4` |
| `plugins/all/` | the full set, and the CLI that needs it |
| `tests/plugin.rs` | the plugin seam, from the core's side |
| `plugins/all/tests/plugins.rs` | the plugin seam, from the plugins' side |
| `corpus/tests/sekreto.rs` | the conformance suite |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Rust
[voxgig/omni](https://github.com/voxgig/omni) runner, pinned by tag; no
checkout is needed. It hands **every** plugin to every chain it builds, so
it can never notice a missing one — which is exactly why the two seam
suites above exist.

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
target/release/sekreto-cli http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Rust is listed there.
