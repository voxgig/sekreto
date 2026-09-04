/-
The wall clock, and the one timestamp sekreto formats.

Lean 4.16 has `IO.monoMsNow`, a monotonic millisecond counter - which is
exactly what token renewal wants, and what `renewat` uses. It has no wall
clock at all, and SigV4 signs a `YYYYMMDDTHHMMSSZ` stamp, so the seconds
since the epoch come through a two-line binding to libc's `time()` in
ffi/sekreto_clock.c.

The CALENDAR is computed here rather than delegated to `gmtime`, so that
the arithmetic is readable and testable in Lean: it is Howard Hinnant's
days-from-civil inverse, the same algorithm every implementation of this
conversion uses.
-/

import Sekreto.Text

namespace Sekreto

/-- Seconds since the Unix epoch, UTC. -/
@[extern "sekreto_epoch_seconds"]
opaque epochseconds : IO UInt64

/-- Zero-pad a number to `width` digits. -/
private def pad (value width : Nat) : String :=
  let text := toString value
  if text.length ≥ width then text else "".pushn '0' (width - text.length) ++ text

/-- The civil date for a day count since 1970-01-01, as (year, month,
day). Hinnant's `civil_from_days`, with the era shifted so that every
intermediate stays a natural number. -/
def civilfromdays (days : Nat) : Nat × Nat × Nat :=
  let z := days + 719468
  let era := z / 146097
  let doe := z % 146097
  let yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let year := yoe + era * 400
  let doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp := (5 * doy + 2) / 153
  let day := doy - (153 * mp + 2) / 5 + 1
  let month := if mp < 10 then mp + 3 else mp - 9
  (if month ≤ 2 then year + 1 else year, month, day)

/-- The `YYYYMMDDTHHMMSSZ` stamp SigV4 wants, for a given epoch second. -/
def awsstamp (epoch : Nat) : String :=
  let (year, month, day) := civilfromdays (epoch / 86400)
  let rest := epoch % 86400
  pad year 4 ++ pad month 2 ++ pad day 2 ++ "T" ++
    pad (rest / 3600) 2 ++ pad ((rest % 3600) / 60) 2 ++ pad (rest % 60) 2 ++ "Z"

/-- The `YYYYMMDDTHHMMSSZ` stamp SigV4 wants, for now. The only place in
this library that reads the wall clock; `sigv4` itself never does. -/
def awsnow : IO String := do
  return awsstamp (← epochseconds).toNat

/-- Never renew. -/
def NEVER : Nat := 0xffffffffffffffff

/-- When a logged-in token must be renewed, from its expiry in seconds:
now + max(seconds - 60, 1). A missing or zero expiry means never renew,
so a CONFIGURED token is kept for the life of the process.

Monotonic milliseconds, not the wall clock: a machine whose clock steps
backwards must not stop renewing. -/
def renewat (seconds : Float) : IO Nat := do
  if seconds.isNaN || 0.0 ≥ seconds then return NEVER
  let ahead := if seconds - 60.0 < 1.0 then 1.0 else seconds - 60.0
  return (← IO.monoMsNow) + (ahead * 1000.0).toUInt64.toNat

end Sekreto
