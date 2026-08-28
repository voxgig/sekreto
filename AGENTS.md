# Working in this repository

sekreto is one library written ten times. The rules below exist so those
ten stay one.

## The three that matter

1. **TypeScript is canonical.** `typescript/src/Sekreto.ts` and
   `typescript/src/Providers.ts` define the behaviour. Every other port is
   a translation of them. Change canonical first, then propagate.

2. **`spec/sekreto.aon` is the contract.** It runs against every port. A
   port that disagrees with the spec is the thing that is wrong — not the
   spec. Changing the spec means changing ten ports, so change it
   deliberately.

   The cases live in `spec/def/*.aon`; `spec/sekreto.json` is **generated**
   from them by `make spec` and committed so that no port needs a Node
   toolchain to run its tests. Never hand-edit the JSON — edit the aontu,
   run `make spec`, commit both. CI's `spec-freshness` job rebuilds and
   fails on any drift.

3. **No third-party dependencies, with exactly one exception.** (`tools/` is
   build machinery, not a port — it depends on `@voxgig/model`, and nothing
   at test time ever reaches it.) Where a
   standard library is missing something, the port carries a small one of
   its own: JSON in Java and Rust (C# uses the BCL's), HTTP in Rust. That is
   the cost of the rule and it is worth paying.

   The exception is **TLS in the Rust port**: `rustls`, plus `webpki-roots`
   for the trust anchors, because rustls deliberately ships no root set and
   something has to supply one. Two crates, one exception. That line is
   drawn deliberately: hand-rolling TLS in a secrets library would be far
   worse than depending on well-audited crates.

   Do not treat it as precedent for a third. If you think you need one, the
   answer is almost certainly a small in-tree implementation, as it was for
   JSON, HTTP, PEM and base64 — all of which this port carries rather than
   pulling in a crate.

4. **Two ways to read, and they are not interchangeable.** `get` is
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

## Adding a port

A port is complete when it has all four:

- the library — the equivalent of `Sekreto` and all thirteen provider
  kinds
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
  but it means `describe()` must keep leading with the kind.

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

## Style

Match the surrounding code. Across ports that means: lowercase function
names in the dynamic languages, the language's own convention in the
compiled ones; comments that say *why*, not *what*; and constants on the
left of a comparison (`404 == status`), which is the house style
throughout voxgig.
