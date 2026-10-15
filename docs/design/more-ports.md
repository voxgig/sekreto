# Bringing sekreto to the languages struct already has

[voxgig/struct](https://github.com/voxgig/struct) has twenty-three ports.
**ALL OF THEM ARE DONE.** sekreto now has twenty-three ports, the same
set. **zig** and **kotlin** landed with this document; **scala**,
**clojure**, **swift**, **dart**, **elixir**, **cpp**, **c**, **lua**,
**ocaml**, **haskell** and **lean** landed after it. Nothing on the list
below is outstanding.

Two things this document predicted, and one it did not.

It said seven could be built today with no rule bent, and seven were. It
said six needed a TLS binding, and all six took one — **every one a full
port**, none falling back to the local-providers-only state offered as an
intermediate. What it did not anticipate is that the corpus would not be
the thing that caught the remaining bugs: three defects were found by
adversarial audit in code paths no spec entry reaches — an escape case,
a hand-built JSON string, and a credential field whose null value made
one port answer with a DIFFERENT field's secret. The spec pins behaviour
it describes; it cannot pin behaviour it does not.

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

~~**zig, kotlin, scala, clojure, dart, swift, elixir**~~ — **all seven
are done.** Every port this section said could be built today has been
built, and none needed a rule bent to do it.

Each has HTTP with TLS in its standard library or platform library, and
everything else is either there or is the kind of small in-tree piece
this repository already writes by hand. No rule has to bend. These are
ordinary work — large, but ordinary — and they should be done in that
order, easiest first:

1. ~~**zig**~~ — **done.** The only one needing no hand-rolling at all:
   `std` has the HTTP client, TLS, JSON, SHA-256, HMAC, base64 and
   subprocess. It was also the best proof that the port shape survives a
   language with manual memory management and no exceptions.
2. ~~**kotlin, scala, clojure**~~ — **all three done.** One platform,
   three languages. The JVM gives HTTP, TLS, HMAC and base64; only JSON is
   hand-rolled, and `java/src/com/voxgig/sekreto/Json.java` was the model
   at 299 lines. Writing that parser three times in three idioms was the
   point of the exercise rather than a waste of it, and the three came out
   at 299, 299 and 258 lines — close enough to the model to show the same
   work, far enough apart to show it was done again rather than copied.
   The HTTP/1.1 pin the java port needed is in all three.
   Note the HTTP/2 trap the Java port hit: `java.net.http` defaults to
   `HTTP_2` and its h2c upgrade sends a `Content-Length` with an empty
   body, which strict servers reject. Scala and Clojure inherit that
   default and must pin HTTP/1.1, as java and kotlin now do.
3. ~~**dart, swift, elixir**~~ — **all three done.** Each has HTTP and
   TLS; each needed SHA-256 and HMAC hand-rolled except Elixir, where
   OTP's `:crypto` has both.

   The JSON prediction held exactly. **Elixir was built on OTP 25** —
   what Ubuntu ships, and the floor this document named — where neither
   `:json` nor Elixir's `JSON` module exists, so its parser is
   hand-rolled and was proved against that OTP rather than a newer one.
   **swift and dart** could have used `JSONSerialization` and
   `dart:convert`; swift hand-rolls anyway and dart uses the platform
   one, which is the difference the rule allows.

   Two things this section did not predict. **swift ships no
   `Package.swift`** — the Makefile drives `swiftc` directly — which
   keeps SwiftPM out of a consumer's way entirely, and CryptoKit being
   Apple-only means `src/Crypto.swift` carries FIPS 180-4 in-tree.
   **dart answers `FutureOr`, not `Future`**, because `dart:io`'s client
   is async-only while omni's dart runner is synchronous: an all-`Future`
   API could not have been driven by the shared suite at all.

## Six that need a TLS binding — all six done

**c, cpp, ocaml, haskell, lua, lean**, and **every one landed as a FULL
port.** The intermediate state this document allows — local providers
working, network kinds raising "this build has no TLS backend" — was
offered to each and needed by none.

The decision below was taken here and is now implemented. What it cost,
measured rather than estimated: one binding per language, and OpenSSL
reached from exactly one file in each. c enforces that mechanically —
`make check-tls` runs `nm` over the archive and fails if any object but
`tls.o` names `SSL_*`, `X509_*`, `EVP_*` or `HMAC` — and cpp's audit
proved the same property by counting undefined symbols per object:
`Tls.o` 27, every other object 0.

The original analysis follows, unchanged.

For all six the obstacle is the same and it is TLS. None has it in the
standard library, and there is no in-tree answer: TLS is the one thing
this repository has already decided must not be hand-rolled. AGENTS.md
was explicit —

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

## The decision: bind the system TLS library

**Taken.** These six ports link the platform's audited TLS library
through a binding, exactly as every one of their communities already
does. The alternatives are recorded below, because a decision is worth
less without the ones it beat.

### Why this, and not the rule as written

The rule's instinct — *"hand-rolling TLS in a secrets library would be
far worse than depending on well-audited crates"* — is not sekreto's
peculiar caution. It is the settled conclusion of every one of these
communities:

| | what that community actually reaches for |
|---|---|
| C | OpenSSL, or libcurl above it; mbedTLS / BearSSL / wolfSSL in embedded work |
| C++ | the same OpenSSL, usually via Boost.Asio's SSL stream or cpp-httplib |
| Lua | [LuaSec](https://luarocks.org/modules/brunoos/luasec) on LuaSocket — an OpenSSL binding, effectively universal |
| Lean | FFI to **libcurl** — that is what the community HTTP clients are |
| OCaml | [`ocaml-tls`](https://github.com/mirleft/ocaml-tls) (pure OCaml) or [`ocaml-ssl`](https://github.com/savonet/ocaml-ssl) (OpenSSL); `conduit` defaults to OpenSSL |
| Haskell | [`http-client-tls`](https://hackage.haskell.org/package/http-client-tls) → the pure `tls` package, or [`http-client-openssl`](https://www.stackage.org/package/http-client-openssl) → HsOpenSSL |

Not one of them hand-rolls it. So this is not sekreto abandoning its
discipline; it is sekreto doing, in each language, the thing a program in
that language normally does.

**And "six more exceptions" overstates the cost.** For C, C++, Lua and
Lean the dependency is *the same artifact* — OpenSSL, or the libcurl that
links it. One well-audited C library reached four ways is a different
proposition from four unrelated supply chains, and should be counted that
way.

For OCaml and Haskell a pure-language TLS exists and is respectable. It
is not obviously the lighter choice: Haskell's `tls` pulls `crypton`,
`memory` and the whole `asn1-*` / `x509-*` family — ten-odd packages
against rustls's two. Either is defensible there; the OpenSSL binding
keeps the six uniform, which is worth something in a repository whose
whole premise is that the ports stay one library.

### What the rule becomes

`AGENTS.md` rule 3 lists one exception and says not to make a third. It
should state the principle instead, because the list was never the point:

> **Cryptographic transport is not hand-rolled.** Where a port's standard
> library has TLS, it uses it. Where it does not, it binds the platform's
> audited TLS library — the same one that language's own ecosystem binds.
> Everything else a standard library lacks is still written in-tree:
> JSON, HTTP framing, base64, PEM.

That reads on the existing ports unchanged — Rust's rustls becomes an
instance of the rule rather than an exception to it — and it settles the
next six without a fresh argument each time.

It also regularises something already true and undocumented: **the Perl
port's HTTPS depends on `IO::Socket::SSL`, which is not a core module.**
`HTTP::Tiny` is core and picks it up when present, so nothing declares
it, but a machine without it has a Perl port that cannot reach any real
vault. That is how `test/realstores.sh` found it. Under the rule above it
stops being an anomaly.

### What every binding must do, without exception

A TLS binding that connects but does not *verify* is worse than no TLS,
because it looks like it works. Each port must, and its integration
check must prove it:

- verify the chain against the system trust store —
  `SSL_CTX_set_default_verify_paths` and `SSL_VERIFY_PEER` in OpenSSL terms;
- verify the **hostname** — `SSL_set1_host`, which is separate from chain
  verification and is the half people forget;
- send SNI — `SSL_set_tlsext_host_name`;
- honour **`SEKRETO_CA_BUNDLE`** for extra roots. The Rust port already
  defines this variable; it should become the one cross-port way to add a
  private CA. The Zig port needs it too and does not have it: its
  `std.crypto.Certificate.Bundle` reads no environment variable, which is
  why `test/realstores.sh` skips zig's TLS check today.

`test/realstores.sh` already runs the proof: the Azure emulator is
refused without its certificate and accepted with it. A new port is not
finished until it passes both halves.

### The alternatives, and why they lost

**B. Plaintext only.** Compiles, passes the integration suite (which
talks http to 127.0.0.1), unusable against a real vault. Rejected: it is
the worst option precisely because it *looks* like it works.

**C. Delegate transport to `curl`.** Coherent, with precedent — the boru
and secretspec providers already run an external binary — and it is
literally what the Lean community does. Rejected as the general answer
because it makes `curl` a runtime requirement of a library and puts the
transport a process away from the error handling; kept as the sensible
shape for **Lean specifically**, where binding libcurl *is* the idiom.
Whichever is used, the vault token must never reach the command line,
where the process table publishes it: `curl -K -` reads its configuration
from stdin.

**D. Local providers only.** Ship `env`, `dotenv`, `file`, `memory` and
boru-via-CLI, and raise on every network provider. Honest, and half a
sekreto. Rejected as the destination, but it is the right *intermediate*
state: a port can land with its local providers working and the network
ones raising a clear "this build has no TLS backend", and gain them when
the binding is written. What must never ship is a port that raises
nothing and quietly reaches nowhere.

## Lean is still its own question

Lean 4 is in struct's list, and omni has a Lean runner
(`omni/lean/Omni.lean`, built with `lake`). Lean has no sockets, no TLS
and no HTTP, and reaching any of them means FFI to C — which is why the
decision above names libcurl for Lean rather than OpenSSL directly: that
is what the Lean HTTP clients that exist already are.

The open question is not how but whether. struct's Lean port makes sense
as a data-structure library that Lean proofs can reason about; a secrets
client that opens sockets is a different kind of thing, and worth someone
saying what it is *for* before it is built. It is the one port where
shipping local providers only might be the destination rather than a
staging post.

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
