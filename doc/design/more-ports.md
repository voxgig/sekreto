# Bringing sekreto to the languages struct already has

[voxgig/struct](https://github.com/voxgig/struct) has twenty-three ports.
sekreto now has twelve — **zig** and **kotlin** landed with this document.
The remaining eleven are:

> c, clojure, cpp, dart, elixir, haskell, lean, lua, ocaml, scala, swift

Every one of them already has a [voxgig/omni](https://github.com/voxgig/omni)
runner, so the conformance half of a port has somewhere to plug in. The
gap is not the spec. It is that **sekreto does I/O and struct does not**.

struct manipulates JSON-shaped data in memory. Porting it needs a
language and nothing else. sekreto opens sockets, speaks seven vendors'
HTTP APIs, signs AWS requests with HMAC-SHA256, parses JSON responses,
decodes base64, and spawns the boru CLI. Against the rule that matters —
**zero third-party dependencies** — that is a much higher bar, and it is
a bar six of the thirteen cannot clear. The table below covers all
thirteen, zig and kotlin included, because the reason those two were
possible is the same reason the other six are not.

## What each language's standard library actually gives us

Measured against what the fourteen provider kinds need. "Hand-roll" is
the house answer and is not a problem in itself: the Java and Rust ports
already carry their own JSON, and Rust its own HTTP.

| | HTTP | TLS | JSON | SHA-256 / HMAC | subprocess |
|---|---|---|---|---|---|
| **zig** | `std.http.Client` | `std.crypto.tls` | `std.json` | `std.crypto` | `std.process.run` |
| **kotlin** | `java.net.http` | JSSE | hand-roll | `javax.crypto` | `ProcessBuilder` |
| **scala** | `java.net.http` | JSSE | hand-roll | `javax.crypto` | `ProcessBuilder` |
| **clojure** | `java.net.http` | JSSE | hand-roll | `javax.crypto` | `ProcessBuilder` |
| **dart** | `dart:io` | built in | `dart:convert` | hand-roll | `Process.run` |
| **swift** | `URLSession` | built in | `JSONSerialization` | hand-roll | `Foundation.Process` |
| **elixir** | `:httpc` | `:ssl` | hand-roll¹ | `:crypto` | `System.cmd` |
| **c** | POSIX sockets | **none** | hand-roll | hand-roll | POSIX |
| **cpp** | POSIX sockets | **none** | hand-roll | hand-roll | POSIX |
| **ocaml** | `Unix` sockets | **none** | hand-roll | hand-roll | `Unix` |
| **haskell** | **none**² | **none** | hand-roll | hand-roll | `process` |
| **lua** | **none**³ | **none** | hand-roll | hand-roll | `io.popen` only |
| **lean** | **none** | **none** | hand-roll | hand-roll | `IO.Process` |

¹ OTP 27 ships `:json` and Elixir 1.18 a `JSON` module; on the OTP 25
that Ubuntu 24.04 packages, neither exists, so the port hand-rolls one.
² GHC's boot libraries have no networking at all — not even a socket.
`network` is not a boot library.
³ Lua 5.4's whole library is basic, coroutine, package, string, utf8,
table, math, io, os, debug. There are no sockets of any kind. `io.popen`
is the only way out of the process, and it is unidirectional.

So the thirteen split cleanly in two, and the split was checked twice:
once per language against its standard library, and once adversarially
against that answer. Nothing in the second pass moved a language across
the line.

## Seven that can be complete ports today

**zig, kotlin, scala, clojure, dart, swift, elixir** — of which **zig and
kotlin are done**.

Each has HTTP with TLS in its standard library or platform library, and
everything else is either there or is the kind of small in-tree piece
this repository already writes by hand. No rule has to bend. These are
ordinary work — large, but ordinary — and they should be done in that
order, easiest first:

1. ~~**zig**~~ — **done.** The only one needing no hand-rolling at all:
   `std` has the HTTP client, TLS, JSON, SHA-256, HMAC, base64 and
   subprocess. It was also the best proof that the port shape survives a
   language with manual memory management and no exceptions.
2. **kotlin** (**done**)**, scala, clojure** — one platform, three
   languages. The JVM gives HTTP, TLS, HMAC and base64; only JSON is
   hand-rolled, and `java/src/com/voxgig/sekreto/Json.java` is the model
   at 299 lines. Writing that parser three times in three idioms is the
   point of the exercise rather than a waste of it.
   Note the HTTP/2 trap the Java port hit: `java.net.http` defaults to
   `HTTP_2` and its h2c upgrade sends a `Content-Length` with an empty
   body, which strict servers reject. Scala and Clojure inherit that
   default and must pin HTTP/1.1, as java and kotlin now do.
3. **dart, swift, elixir** — each has HTTP, TLS and (except Elixir on
   older OTP) JSON; each needs SHA-256 and HMAC hand-rolled, except
   Elixir, where OTP's `:crypto` has both.

## Six that cannot, without a decision that is not mine to make

**c, cpp, ocaml, haskell, lua, lean.**

For all six the blocker is the same and it is TLS. None has it in the
standard library, and there is no in-tree answer: TLS is the one thing
this repository has already decided must not be hand-rolled. AGENTS.md
is explicit —

> The exception is **TLS in the Rust port**: `rustls`, plus
> `webpki-roots` … hand-rolling TLS in a secrets library would be far
> worse than depending on well-audited crates. … Do not treat it as
> precedent for a third.

Haskell, Lua and Lean have a second problem underneath the first: no
sockets either, so even plaintext HTTP has nothing to build on. (Lua's
`io.popen` and Lean's `IO.Process` are process spawning, not networking.)

It is worth being precise about what this does *not* block, because the
precise version is stronger than the loose one.

**No case in `spec/sekreto.json` opens a socket.** Checked, not assumed:
the network kinds appear in four cases, and every one is rejected before
the transport is reached — `kv: 3` fails on the version, and
`http://vault.example.com` and `ftp://…` fail in `checkaddr`. The only
real I/O anywhere in the suite is the `file` provider reading a directory
that does not exist. So a Haskell or Lua port with no sockets at all
could pass all fourteen groups in full, having implemented `describe()`
and the validation and nothing else.

**A port that passes the spec is not a port**, and counting one would be
exactly the kind of vacuous green this repository goes out of its way to
refuse elsewhere. `test/integration.sh` is what would catch it — which is
the argument for not letting a port into `LANGS` until it passes that
too.

Four ways forward, and the choice belongs to whoever owns the
zero-dependency rule:

**A. One TLS dependency per port, as Rust already has.** OpenSSL for
C and C++, `ocaml-tls` for OCaml, `HsOpenSSL` or `crypton-x509` for
Haskell, `luasec` for Lua. Honest, conventional, and gives complete
ports. It also turns "one deliberate exception" into seven, which is a
different rule than the one written down.

**B. Plaintext only.** The ports compile, the local providers work, and
`checkaddr` already refuses plaintext to anything but loopback — so every
network provider becomes loopback-only. It would pass the integration
suite, which talks http to 127.0.0.1, while being unusable against a real
vault. This is the worst option precisely because it *looks* like it
works.

**C. Delegate transport to a subprocess.** There is a precedent: the boru
provider already shells out to the boru CLI. Extending it to "where a
port has no TLS, transport goes through `curl`" is coherent, and it keeps
the language's dependency manifest empty. Two costs: `curl` becomes a
runtime requirement, and — the part that must not be got wrong — the
vault token cannot go on the command line, where the process table would
publish it to every user on the machine. `curl -K -` reads its
configuration from stdin, so it is doable safely, but it is a design, not
a shortcut.

**D. Local providers only, and say so.** Ship `env`, `dotenv`, `file`,
`memory` and boru-via-CLI, and have every network provider raise
`sekreto: this port cannot reach a network vault` at construction. The
rule holds, nothing pretends, and the port is genuinely useful for the
configuration cases that do not need a vault. It is also, plainly, half a
sekreto.

**Recommendation: D as the default, A per language where someone
actually wants that port in production.** D keeps the rule and keeps the
honesty, and the failure is loud at the point of construction rather than
silent at the point of a fallback. A is then a per-language decision with
a named owner, taken because someone needs a C sekreto against a real
Vault — not taken six times over by default.

What should not happen is B, and what should not happen quietly is A.

## Lean is its own question

Lean 4 is in struct's list, and omni has a Lean runner
(`omni/lean/Omni.lean`, built with `lake`). Lean has no sockets, no TLS
and no HTTP, and reaching them means FFI to C. Before any of the above
is applied to it, someone should say what a Lean sekreto is *for* —
struct's Lean port makes sense as a data-structure library that Lean
proofs can reason about; a secrets client that opens sockets is a
different kind of thing. It may be that D is not a compromise there but
the right answer.

## What a port has to have

Unchanged from AGENTS.md, and worth repeating because the six-language
decision above is precisely about the first bullet:

- the library — `Sekreto` and all **fourteen** provider kinds
  (`secretspec` is the fourteenth)
- a conformance suite running `spec/sekreto.json` through that
  language's omni runner, covering every group
- a CLI at the path `test/checks.sh` expects, printing exactly
  `{"ok":true,"lang":"<lang>","source":"<source>","store":"<store>","caller":"<caller>"}`
- `build`, `test`, `clean` and `inspect` in its `Makefile`

then `LANGS` in the top-level `Makefile`, and `cli_cmd`/`cli_ready`/
`ALL_LANGS` in `test/checks.sh` — one place now rather than two, since
both suites share it.

## Toolchains

All thirteen can be installed on an Ubuntu runner. Where struct's
`.github/workflows/build.yml` already has a pinned setup action for a
language, use the same one rather than inventing a second way.

| | how |
|---|---|
| zig | `pip install ziglang` (no apt package; struct's CI does this too) |
| lua, ocaml, elixir, haskell, c, cpp | `apt-get install` |
| clojure | the official Clojure CLI installer — **not** Ubuntu's `clojure` package, which is the old wrapper and does not understand `-M`, so omni's runner cannot start under it |
| kotlin | the JetBrains release zip. Maven Central carries the compiler JAR but not the standalone distribution |
| scala | JVM plus `scala-cli` or a Scala 3 compiler |
| swift | `download.swift.org` tarball |
| dart | `storage.googleapis.com/dart-archive` |
| lean | `elan` |
