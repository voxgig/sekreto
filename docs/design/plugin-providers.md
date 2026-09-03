# Provider plugins: sekreto on voxgig/plugin

**Status:** landed in typescript (canonical), go and python. Nine ports
pending; the order is at the end.

## Why

sekreto shipped thirteen provider kinds in one 1,279-line `Providers.ts`,
reachable from a `makeprovider` switch. Every consumer got all thirteen,
so an SDK whose chain was `[dotenv, env]` still carried AWS SigV4 request
signing, seven HTTP vault clients, and the `node:crypto` edge that comes
with them — in every language, because every port had the same switch.

`nodemod()` deferred the *platform module* to first use, and that was
worth doing — importing sekreto became safe on a runtime with no
`node:fs`. But it does not make the code absent, and its own comment
says so: a bundler still resolves a `require` it can see. Leanness needs
the provider to not be there at all.

The goal, stated by the consumer that forced it: **baseline sekreto has
no platform dependencies in any language port, and everything else is a
matter of choice or of what the app actually needs.**

## The shape

| layer | holds | needs |
|---|---|---|
| **core** | the chain (`get`/`try`/`getfrom`/`tryfrom`), cache, redaction, `Provider`, `SekretoError`, `checkaddr`, and the four **built-in** kinds `env` `memory` `dotenv` `file` | a local file, at most |
| **plugins** | `hashicorp` `boru` `aws` (`awssecrets` + `awsparams`, with `sigv4`) `gcpsecrets` `azuresecrets` `onepassword` `doppler` `infisical` `secretspec` | HTTPS; HMAC-SHA256 for aws; a child process for boru and secretspec |

**The line is "reads at most a local file".** An earlier draft kept only
`env` and `memory` in the core because only they *import* nothing; the
decision taken is broader and more useful: the four kinds an app needs
to define secrets as options, read the environment, read a plaintext
`.env` and read a mounted secret directory are built in everywhere, and
a chain of them works with no plugin loaded. Everything that needs a
socket, a signature or a subprocess is a plugin. Crypto is the sharpest
instance: `sigv4` moved into the aws plugin, and the core of no port
imports a hash function.

**The same set in every port.** Four built-ins and ten plugins, the same
names, the same `kind` strings, the same store names, whatever the
language. The spec already pins the behaviour; this document pins where
each kind lives.

## Providers are voxgig/plugin definitions

[`voxgig/plugin`](https://github.com/voxgig/plugin) is the general-purpose
plugin architecture for the stack — zero dependencies, one model across
every language. sekreto does not invent a second registry, and no longer
has one: the module-global `register()` of the first typescript draft is
gone.

- A **provider kind** is a plugin `Definition`, named after the kind. Its
  `define` reads the instance's options — the ProviderSpec — builds the
  provider, and exports it under the key `provider`. One helper makes
  every one of them, built-in or plugin, shipped or custom:
  `providerplugin(kind, make)` / `sekreto.ProviderPlugin`.
- A **configured provider** is a plugin instance on `Sekreto.host`,
  addressed by name+tag: `kind` for a store named after its kind,
  `kind$store` otherwise — `hashicorp$prod` and `hashicorp$test`
  coexist and `host.list()` reads like the chain. Two providers may
  share a store name (the spec says a directed read walks both), an
  instance ref may not, so a repeat takes a numbered tag from the host's
  `autotag` and keeps its store name. A store name must therefore be a
  valid plugin tag; one that is not is `sekreto: invalid store name`.
- **Lifecycle is plugin's:** `load` runs `define` (the provider is
  built), `activate` takes it live, `Sekreto.close()` deactivates and
  unloads in reverse. Nothing is contacted by any of it — a provider
  opens nothing until its first lookup — and a provider that does hold a
  resource acquires it in `activate` and lets the scope unwind it.
- **The catalog is built-ins first, then what the caller passed.** A
  plugin naming a built-in kind replaces it: a host substituting an
  implementation, never an accident, because the four names are
  documented.

## Loading is static, in every language

The calling project imports the plugins it needs and passes them to the
constructor — `plugins: [hashicorp, awssecrets]` — and a `Sekreto` can
build exactly those kinds and the four built-ins. No dynamic discovery,
no registry filled at import, no module loaded by name.

That is the same in a language with dynamic loading as in one without,
on purpose, for two reasons. The set of stores an app can reach is not
something to discover at run time. And a side effect of importing is a
thing a compiler can erase: the first typescript draft registered kinds
at import, the CLI's only import of the full set named a type, and every
kind but two failed in the integration suite while `make test` stayed
green. A list handed to a constructor cannot be erased.

Per language, the boundary the split enforces is the one the language
has:

| | plugins live in | boundary | dependency on voxgig/plugin |
|---|---|---|---|
| typescript | `typescript/plugins/`, one module per plugin, `index.ts` the full set (`allplugins`) | bundling: `src/` reaches nothing under `plugins/` | `@voxgig/plugin` from npm |
| go | `go/plugins/<kind>/`, one package per plugin, `plugins` the full set (`All()`) | linking: `sekreto/` imports no `net/http`, `crypto`, `os/exec`; an unimported package is not in the binary | `github.com/voxgig/plugin/go` from the module proxy |
| python | `python/voxgig_sekreto/plugins/`, one module per plugin, the package the full set (`ALL`) | importing: `import voxgig_sekreto` pulls in the core, the built-ins and `voxgig_plugin`, and no module under `plugins/` | `voxgig-plugin` from git, until it is on PyPI |

The shared HTTP helper — bounded, redirect-refusing, proxy-ignoring —
lives under `plugins/` too (`httpjson`), because a chain of built-ins
must never link it.

## The one seam that is NOT plugin's: async lookup

**voxgig/plugin has no async surface.** `compose()` is synchronous, and
the only mention of asynchrony in the library is a comment in `Point.ts`
explaining why the fan-out modes exist at all. That is deliberate — the
§18 portability budget spans twenty languages, many with no
async/await — and it is not a gap to be filled.

sekreto's `Provider.lookup` is inherently async: seven of the fourteen
kinds are HTTP clients.

So the boundary is:

- **plugin owns** the catalog, instances, name+tag addressing,
  lifecycle, and the options each instance was declared with.
- **sekreto owns** the walk. It reads each instance's exported provider
  off the host at construction and iterates them in its own language's
  idiom.

Two things this deliberately avoids:

1. **`bail` mode cannot express first-hit here.** `bail` stops at the
   first binding that returns a value; an async lookup returns a
   Promise, which is always a value, so every chain would stop at its
   first provider whether or not it found the secret.
2. **A `chain` point would work in TypeScript and mislead nine ports.**
   `compose` builds `fn(inner, ...args)`, which composes correctly when
   the bindings are async — *in JavaScript*, because promises compose.
   Relying on that would make the canonical port pass while giving the
   other ports a construct their languages do not have.

## Errors across the boundary

A provider that refuses its own configuration — `kv: 3`, a missing
project — raises a `SekretoError` from inside `define`, and the spec
pins that message byte for byte. voxgig/plugin keeps an error that
carries a code and wraps a code-less one as `plugin_define_failed`, and
in go it can only see a code on its own `*PluginError`. So the bridge is
the same in all three ports: `providerplugin` catches a `SekretoError`
and re-raises it as a plugin error with the code `sekreto_error` and the
message as `cause`; `Sekreto` unwraps exactly that code back into a
`SekretoError`. Any other error a `define` raises is not sekreto's to
rewrite and surfaces as the host reports it, naming the instance.

The unknown-kind message tells a typo from a plugin that was not passed:
`sekreto: unknown provider kind: doppler (available: dotenv, env, file,
memory) - doppler is a sekreto plugin, not built in: pass it in the
plugins option`. Collapsing the two was the first thing that made the
split confusing to use.

## Consequences accepted

- **Port coverage gates propagation.** plugin has seventeen ports;
  sekreto has twelve. Eleven overlap. zig has no plugin port and keeps
  the switch until one exists — checked again when plugin's P6 lands.
- **Python's dependency is from git.** voxgig/plugin's python port was
  not packaged at all; it now carries a `pyproject.toml`, and sekreto
  declares it from git until it is on PyPI. A checkout that has not
  pip-installed it finds a sibling `plugin` checkout the way every port
  finds omni (`PLUGIN_HOME`, `tests/pluginhome.py`), for the tests and
  the CLI only — the library does no path search.
- **Go's `New` returns an error**, because building a chain can now
  fail in ways the old `New` could not, and the Go port ships no
  package to stay compatible with. `Options.Providers` is a list of
  specs, and a spec may carry a `Provider` already built for the custom
  case.
- **The Go workspace needed two `replace` directives** for the phantom
  `v0.0.0` versions in `testutil/go.mod`; see AGENTS.md. Generated into
  the gitignored `go.work`, never checked in.
- **The spec did not change.** The chain groups build from `memory` and
  `file`, and the hashicorp cases fail before a socket; the conformance
  suites hand every plugin to every chain they build. What the suites
  cannot see — that the core reaches no plugin, that an unloaded kind is
  refused, that the full set holds every kind — is pinned per port by
  `lazyload.test.ts` + `plugins.test.ts`, `plugin_test.go` +
  `plugins/plugins_test.go`, and `test_plugins.py`.

## Propagation order

typescript (canonical) ✅ → go ✅, python ✅ → javascript, ruby, php,
perl, rust, java, csharp, kotlin (plugin ports exist; the same layout —
built-ins in the core, one plugin per module or package under
`plugins/`, a full set, a `plugins` option, the `sekreto_error` bridge,
and the three seam tests) → zig, when voxgig/plugin has it.
