# Working in this repository

sekreto is one library written ten times. The rules below exist so those
ten stay one.

## The three that matter

1. **TypeScript is canonical.** `typescript/src/Sekreto.ts`,
   `typescript/src/provider/` and `typescript/plugins/` define the
   behaviour. Every other port is a translation of them. Change canonical
   first, then propagate.

2. **`spec/sekreto.aon` is the contract.** It runs against every port. A
   port that disagrees with the spec is the thing that is wrong — not the
   spec. Changing the spec means changing ten ports, so change it
   deliberately.

   The cases live in `spec/def/*.aon`; `spec/sekreto.json` is **generated**
   from them by `make spec` and committed so that no port needs a Node
   toolchain to run its tests. Never hand-edit the JSON — edit the aontu,
   run `make spec`, commit both. CI's `spec-freshness` job rebuilds and
   fails on any drift.

3. **No third-party dependencies, with one narrow exception — and one
   Voxgig dependency.** (`tools/` is
   build machinery, not a port — it depends on `@voxgig/model`, and nothing
   at test time ever reaches it.) Where a
   standard library is missing something, the port carries a small one of
   its own: JSON in Java and Rust (C# uses the BCL's), HTTP in Rust. That is
   the cost of the rule and it is worth paying.

   The Voxgig dependency is [voxgig/plugin](https://github.com/voxgig/plugin),
   which itself takes nothing: a port that has adopted the plugin
   architecture (rule 4) depends on plugin's port of its language, the
   way that language takes a dependency — npm for typescript, the module
   proxy for go, git for python until it is on PyPI. That is the whole
   list. voxgig/omni is not on it: it drives the tests and no shipped
   manifest may name it (`tools/omni_isolation.py` proves that).

   The exception is **cryptographic transport**, and it is a principle
   rather than a list. Where a port's standard library has TLS, it uses it.
   Where it does not, it binds the platform's audited TLS library — the
   same one that language's own ecosystem binds. Hand-rolling TLS in a
   secrets library would be far worse than depending on an audited
   implementation, and no community these ports live in does otherwise.

   Rust is the instance you can already read: `rustls`, plus `webpki-roots`
   for the trust anchors, because rustls deliberately ships no root set and
   something has to supply one. (Perl is a quieter one: its HTTPS needs
   `IO::Socket::SSL`, which is not core — `HTTP::Tiny` picks it up when
   present, so nothing declares it, and a machine without it has a Perl
   port that cannot reach a real vault.)

   The exception is that narrow. Everything else a standard library lacks
   is still written in-tree — JSON, HTTP framing, PEM, base64, all of which
   these ports carry rather than taking a package. If you think you need a
   dependency for one of those, the answer is a small in-tree
   implementation.

   A binding that connects without **verifying** is worse than no TLS,
   because it looks like it works: verify the chain, verify the hostname
   (a separate step, and the one people forget), send SNI, and honour
   `SEKRETO_CA_BUNDLE` for extra roots. `test/realstores.sh` proves it both
   ways — the Azure emulator must be refused without its certificate and
   accepted with it. See `doc/design/more-ports.md`.

4. **Four kinds are built in; everything else is a plugin, in the port's
   `plugins/` folder, loaded statically by the calling project.** What
   makes a kind built in is that it reads at most a local file: `env`,
   `memory`, `dotenv`, `file`. Every kind that opens a socket, signs a
   request or spawns a process — the vault clients, the cloud stores,
   the two CLIs, and `sigv4` with them — is a voxgig/plugin definition
   under `plugins/`, and a `Sekreto` can build only the kinds its
   constructor was handed. The same four built-ins and the same ten
   plugin kinds in every port; only the loading mechanism follows the
   language.

   The rules that keep it true:

   - **The core imports no plugin, in any form.** Not the module, not
     the full set, not a type that the compiler would erase anyway. In
     Go that is a linking boundary (`sekreto/` imports no `net/http`,
     `crypto` or `os/exec`); in TypeScript a bundling one (nothing under
     `src/` reaches `plugins/`); in Python it decides what
     `import voxgig_sekreto` pulls in. `lazyload.test.ts`,
     `plugin_test.go` and `test_plugins.py` each pin their half.
   - **Loading is explicit, never a side effect of importing.** An
     earlier shape registered kinds at import into a module-global
     registry; the CLI's only import of the full set named a type,
     TypeScript erased it, and every kind but two failed in the
     integration suite while `make test` stayed green. A list handed to
     the constructor cannot be erased.
   - **A `SekretoError` crosses the plugin boundary under the code
     `sekreto_error`** and comes back out as itself. The spec pins those
     messages byte for byte, and voxgig/plugin wraps a code-less error
     raised in `define` as `plugin_define_failed`. `providerplugin` puts
     the code on; `Sekreto` takes it off. Do not catch and rewrap
     anywhere else.
   - **A port adopts the architecture only once voxgig/plugin has its
     language.** Until then it keeps the `kind` switch with the same
     fourteen kinds — javascript, ruby, php, perl, rust, java, csharp
     and kotlin can move now; zig waits for a plugin port. The
     propagation order, and what each port owes, is
     [`docs/design/plugin-providers.md`](./docs/design/plugin-providers.md).

   Deferring a builtin (`nodemod`) is not the same thing and does not
   replace it: deferring stops a Node module being EVALUATED at import,
   which is what lets the core's `dotenv` and `file` load `node:fs` at
   first lookup rather than at import. It does not remove code from a
   build; the split does that.

5. **Two ways to read, and they are not interchangeable.** `get` is
   transparent — the chain answers and the caller never learns which store
   did. `getfrom` is directed — one named store answers, or nothing. Adding
   a method to one half means adding its twin to the other.

## Both suites, every time

```sh
make test         # every port computes the same answers
make integration  # every port can actually fetch a secret and use it
make all          # both — run this before pushing
```

`make test` alone is not enough. It proves the pure functions and the
chain logic; it says nothing about whether a port can open a socket, speak
the vault protocol and come back with a secret. `test/integration.sh` is
what proves that, and it is the suite most likely to catch a real bug.

Run one port with `make test-go`, or one group with the `RUN-SOME:` line
at the top of each port's test file.

### And a third, when you have docker

```sh
make realstores   # the same CLIs against the REAL vaults, in containers
```

`test/integration.sh` runs against mocks, and a mock is a *claim* — "this
is what the real server does" — written by the same people who wrote the
client. `test/realstores.sh` checks the claim against HashiCorp Vault,
LocalStack, self-hosted Infisical, a Key Vault emulator and a real boru.

It is not part of `make all`: it needs docker, pulls images, and takes
minutes. CI runs it weekly and on demand
(`.github/workflows/real-stores.yml`), and a failure there means either a
port has a bug the mocks do not model or a mock has drifted from the
server it imitates.

It has already found both kinds. Read `doc/design/real-stores.md` before
changing it — in particular for which services are the vendor's own
server, which are emulators, and why AWS signing is still guarded by the
mock rather than by LocalStack.

Both suites share `test/checks.sh`: what a check is, how a port's CLI is
invoked, and what counts as a leak are defined once, because two suites
that disagree about what passing means are worse than one.

## Adding a port

A port is complete when it has all four:

- the library — the equivalent of `Sekreto`, the four built-in kinds in
  its core, and the ten plugin kinds in its `plugins/` folder where
  voxgig/plugin has its language (the `kind` switch over all fourteen
  where it does not yet)
- a conformance suite running `spec/sekreto.json` through that language's
  voxgig/omni runner, covering all fourteen groups
- a CLI at the path `test/integration.sh` expects, printing exactly
  `{"ok":true,"lang":"<lang>","source":"<source>","caller":"<lang>"}`
- `build`, `test`, `clean` and `inspect` targets in its `Makefile`

Then add it to `LANGS` in the top-level `Makefile` and to the two case
statements in `test/integration.sh`.

### Things that have bitten every port so far

- **Field order in the CLI's output.** Ports that print from a map get the
  language's key order, not the spec's: Go's `encoding/json` sorts keys,
  Perl hashes are unordered, Java's `HashMap` is neither. Print from an
  ordered structure, or assemble the line field by field.
- **Booleans.** `validname` returns whatever the language calls true. The
  spec says JSON `true`, so adapt in the *test*, not by making the library
  hand back JSON booleans.
- **Cache ordering.** `redact` walks the resolved values. If the cache is a
  hash map with randomised iteration, redaction output varies between runs.
  Go and Rust keep insertion order explicitly for this reason.
- **A missing `.env` is not an error.** It means "no secrets here". A port
  that raises there breaks every chain on a machine without one.
- **A miss and a failure are different.** 404 from HashiCorp, and boru's
  "no alias named", mean *this store does not hold it* — the chain carries
  on. A locked vault, a wrong passphrase or an unreachable host means *this
  store could not answer* — that must raise. Getting this backwards makes a
  chain silently fall through to a weaker store, which is the worst failure
  mode the library has.
- **Naming a store that does not exist raises, even from `tryfrom`.** `try`
  already means "may not have it"; letting it also mean "may not exist"
  swallows typos.
- **Store names come from `describe()`.** The default is everything before
  the first `:`, so a new provider gets a sensible store name for free —
  but it means `describe()` must keep leading with the kind. A spec'd
  store's name is decided before the provider exists — `name` or `kind`
  — and is also the plugin instance's tag, so it has to be a valid one.
- **A Go workspace does not resolve a phantom version.** `testutil/go.mod`
  requires omni and the library at `v0.0.0`, and `use` alone does not
  stop the module-graph loader fetching a go.mod at that version. It
  went unnoticed while the graph held only workspace modules; requiring
  voxgig/plugin from the proxy made every workspace-mode build fail on
  omni. The Makefile's `go.work` adds a `replace` pinned to the phantom
  version, and stays out of any checked-in file.

## voxgig/omni

The conformance suites need a [voxgig/omni](https://github.com/voxgig/omni)
checkout. Every port finds it the same way: `$OMNI_HOME`, then `../../omni`,
`../../../omni`, `/workspace/omni`, `/home/user/omni` — the first that has
`spec/fib.json`. Set `OMNI_HOME` if yours is elsewhere.

Compiled ports wire it in without putting a machine-specific path in a
checked-in file: Go generates a `go.work`, Rust symlinks `vendor/omni`,
C# passes `-p:OmniPath=`, Java puts it on the classpath. All four are
gitignored, and only the *test* depends on omni — the library and CLI
never do.

## The API server and the vaults

`test/integration.sh` stands up:

- `api/server.js` — Fastify, and the only thing it does is refuse any
  request without the right bearer token
- `test/mockhashicorp.js` — HashiCorp Vault, enough of it: KV v2 and v1,
  namespace enforcement, kubernetes/approle logins. Vault publishes its
  wire protocol, so imitating it is legitimate: the provider talks to this
  exactly as it would to a real Vault.
- `test/mockaws.js`, `test/mockgcp.js`, `test/mockazure.js`,
  `test/mockonepassword.js`, `test/mockdoppler.js`,
  `test/mockinfisical.js` — the other published wire protocols, same
  justification. The AWS mock re-derives every request's SigV4 signature
  and refuses mismatches, so wrong signing fails here the way it would
  against real AWS.
- a **real boru vault**, built by running `boru vault init` and
  `boru vault add` against the actual binary, found via `$BORU` or `PATH`
  — read through the CLI, and also over `boru vault serve` (its provision
  wire protocol) with a capability token from `vault grant`.

Neither suite will start a server on a port something else already holds.
`waitport` alone cannot tell a mock that bound from a squatter that was
already there — the mock dies in milliseconds while the squatter answers
the probe instantly — so the port is claimed first. A developer's own
`vault server -dev` on 8200 is exactly the case: without the guard every
HashiCorp check silently tests the wrong server.

**Neither is there a SecretSpec mock**, for the same reason and with the
same consequence: `secretspec` is read through its own CLI, so the thing
under test is whether a port reads what that program prints and tells its
two failure shapes apart. SecretSpec words both of them as "not found" —
`Secret 'API_TOKEN' not found` is a miss, `Provider backend 'keyring' not
found` is a store that could not answer — so a port that matches loosely
passes the easy check and silently falls through to a weaker store on the
hard one. `test/integration.sh` checks both, against the real binary,
found via `$SECRETSPEC` or `PATH`, and skips them when it is absent.

**There is still no boru mock, and there should not be one.** boru's wire
protocol ships inside the same binary the CLI does, so both boru paths are
exercised against the real thing; a mock would test the imitation. When
the binary is absent the boru checks are skipped, and the run says so. A
skipped check is honest; a faked one is not.

One boru boundary stays deliberate: the provider speaks `vault serve`
(the provision endpoint, built to hand a value back under capability
tokens) and never `vault proxy` or `vault mcp` — those are a credential
*broker*, built precisely so that a caller never receives the credential.
Read `design/VAULT-WIRE-PROTOCOL.0.md` in boru-lang/boru for the line
between the two.

## Release and publish

Ten ports, **two of which publish a package**:

| port | package | tag |
| --- | --- | --- |
| `typescript/` | npm `@voxgig/sekreto` | `typescript/v<version>` |
| `javascript/` | npm `@voxgig/sekreto-js` | `javascript/v<version>` |

The other eight (python, ruby, php, perl, go, rust, java, csharp) ship no
package and have no publish flow yet — they are consumed from this repository.

### Releasing

**Actions → release → Run workflow**, on `main`, choosing the `port`. Or push
a matching tag. The version comes from that port's own manifest, so **bump it
first in a reviewed PR**, then dispatch.

### `release.yml` is the only file that can publish, and it has three jobs

npm registers a trusted publisher against one owner, one repo, and a single
workflow **filename**, so the tag has to live in the same file as the publish.
They cannot be split across two files: a ref pushed with `GITHUB_TOKEN` starts
no further workflow run, so "tag in A, publish on the tag" publishes nothing,
silently. An unregistered workflow's OIDC token is refused as **404, not
403**, which reads as "the package does not exist".

Within that one file the work is split three ways, and the split is the
security shape of the file rather than tidiness:

| job | holds | runs |
| --- | --- | --- |
| `build` | `contents: read` | install, build, tests, packaging checks — all project code and every dependency lifecycle script. Uploads the tarball. |
| `publish` | `id-token: write`, `contents: read` | downloads that tarball and publishes it. **No checkout at all.** |
| `tag` | `contents: write` | git, and nothing else. |

The `publish` job's `contents: read` is belt-and-braces: it never checks out,
so nothing there reads the repository, and the grant could be dropped. It is
listed because a permissions table that omits a grant is worse than no table —
anyone auditing the OIDC isolation from it would conclude the job holds no
repository credential at all.

`id-token: write` is a **job-level** grant: it puts the OIDC request URL and
token in the environment of every process in the job, so a compromised
`postinstall` during `npm install` could mint a publish credential. Hence the
publish job never checks out the repository and never runs project code.

### Irreversible

**npm never allows republishing a version.** If a run publishes and then fails
before tagging, re-dispatch: the registry check skips the completed publish
and retries the tag. Never publish locally over a token — that bypasses OIDC
and its provenance attestation entirely.

The fullest write-up of this design is `voxgig/apidef`'s
`docs/how-to/release-and-tag.md`; the three-job shape here matches
`voxgig/omni`'s.


## Style

Match the surrounding code. Across ports that means: lowercase function
names in the dynamic languages, the language's own convention in the
compiled ones; comments that say *why*, not *what*; and constants on the
left of a comparison (`404 == status`), which is the house style
throughout voxgig.
