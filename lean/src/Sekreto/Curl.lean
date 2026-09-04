/-
The one HTTP round-trip, over the libcurl binding.

This module and ffi/sekreto_curl.c are the whole of this port's contact
with the network. Everything above them - JSON, the fourteen provider
kinds, SigV4 - is in-tree Lean, and everything below them is libcurl.

What the binding guarantees, and why, is written out in
ffi/sekreto_curl.c: chain verification against the system store,
HOSTNAME verification (the separate half), SNI, and SEKRETO_CA_BUNDLE as
an ADDITIVE source of extra roots. What this file adds is the contract
the rest of the library depends on: a 10 s bound, an 8 MiB cap, no
redirects, no proxies, HTTP/1.1 - and the rule that a store that could
not answer RAISES rather than missing.
-/

import Sekreto.Text
import Sekreto.Json
import Sekreto.Core
import Sekreto.Addr

namespace Sekreto

/-- The libcurl round-trip. See the framing note in ffi/sekreto_curl.c:
one tag byte, four status bytes, then the payload.

`@&` on every string: the arguments are BORROWED, so the C side reads
them and does not release them. Without it Lean would hand ownership
over and the binding would have to drop each one by hand. -/
@[extern "sekreto_curl_fetch"]
opaque curlfetch (method : @& String) (url : @& String) (headers : @& String)
    (body : @& String) (hasbody : Bool) (cabundle : @& String) : IO ByteArray

/-- One JSON round-trip's result: the status, and the parsed body. -/
structure Answer where
  status : Nat
  body : Option Json
  deriving Inhabited

/-- A header value with CR and LF removed.

A vault token arrives from configuration and goes out in a header. One
containing a newline would end the header and start another, which is
request splitting; the two characters have no legitimate place in any
value this library sends. -/
private def headervalue (value : String) : String :=
  String.mk (value.toList.filter (fun ch => '\r' != ch && '\n' != ch))

/-- Extra trust roots, from the one variable every port in this
repository agrees on. Empty means unset, and an unreadable or unusable
file adds nothing and raises nothing - it fails OPEN, silently, exactly
as rust/src/http.rs does. -/
private def cabundle : IO String := do
  return ((← IO.getEnv "SEKRETO_CA_BUNDLE").getD "")

/-- One JSON round-trip.

Network failure is ALWAYS an error - an unreachable store is a store
that could not answer, and returning a miss there would fall through to
a weaker store on an attacker's cue. So is an oversized body, and so is
a 200 whose body does not parse. A non-200 with an unreadable body is
fine: error statuses are decided on status alone. -/
def fetchjson (method url : String) (headers : Pairs String := [])
    (body : Option String := none) : IO Answer := do
  let lines := String.intercalate "\n"
    (headers.map (fun kv => kv.1 ++ ": " ++ headervalue kv.2))

  let raw ← curlfetch method url lines (body.getD "") body.isSome (← cabundle)

  if 5 > raw.size then
    fail ("sekreto: cannot reach " ++ bareurl url ++ ": no answer")

  let tag := raw.get! 0
  let status :=
    (raw.get! 1).toNat * 16777216 + (raw.get! 2).toNat * 65536 +
    (raw.get! 3).toNat * 256 + (raw.get! 4).toNat
  let payload := raw.extract 5 raw.size

  if 'Z'.toNat.toUInt8 == tag then
    fail ("sekreto: oversized response from " ++ bareurl url)

  if 'E'.toNat.toUInt8 == tag then
    let why := (String.fromUTF8? payload).getD "transport failure"
    fail ("sekreto: cannot reach " ++ bareurl url ++ ": " ++ why)

  -- A body that is not UTF-8 cannot be JSON either, so it takes the same
  -- path a body that is text but not JSON takes.
  let parsed := (String.fromUTF8? payload).bind Json.parse

  if 200 == status && parsed.isNone then
    fail ("sekreto: malformed response from " ++ bareurl url)

  return { status := status, body := parsed }

end Sekreto
