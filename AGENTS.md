# Working in this repository

sekreto is one library written ten times. The rules below exist so those
ten stay one.

## The three that matter

1. **TypeScript is canonical.** `typescript/src/Sekreto.ts` and
   `typescript/src/Providers.ts` define the behaviour. Every other port is
   a translation of them. Change canonical first, then propagate.

2. **`spec/sekreto.json` is the contract.** It runs against every port. A
   port that disagrees with the spec is the thing that is wrong — not the
   spec. Changing the spec means changing ten ports, so change it
   deliberately.

3. **No third-party dependencies, in any port.** Where a standard library
   is missing something, the port carries a small one of its own: JSON in
   Java, Rust and C#(via the BCL), HTTP in Rust. That is the cost of the
   rule and it is worth paying.

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

- the library — the equivalent of `Sekreto` and the five providers
- a conformance suite running `spec/sekreto.json` through that language's
  voxgig/omni runner, covering all eight groups
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
- **404 from a vault is a miss, not an error.** Otherwise a vault cannot
  sit in a chain with anything behind it.

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

`test/integration.sh` starts three servers of its own:

- `api/server.js` — Fastify, and the only thing it does is refuse any
  request without the right bearer token
- `test/mockvault.js vault` — HashiCorp Vault KV v2, enough of it
- `test/mockvault.js boru` — a boru vault

The boru wire format there is the one sekreto assumes
(`GET {addr}/vault/{path}?field=...`, `X-Boru-Token`,
`{"ok":true,"value":...}`). If the real protocol differs, change
`boruprovider` in each port and `test/mockvault.js` to match — nothing
above the provider sees the wire format.

## Style

Match the surrounding code. Across ports that means: lowercase function
names in the dynamic languages, the language's own convention in the
compiled ones; comments that say *why*, not *what*; and constants on the
left of a comparison (`404 == status`), which is the house style
throughout voxgig.
