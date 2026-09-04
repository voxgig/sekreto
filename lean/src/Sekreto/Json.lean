/-
Minimal JSON support for sekreto.

sekreto adds no third-party dependencies, so it carries just enough JSON
to read a vault's answer and write the CLI's own line of output. It is
deliberately not a general-purpose library.

Lean does ship `Lean.Data.Json`, and this port does not use it. Two
reasons, and both are contract rather than taste. Its objects are an
`RBNode` keyed by name, so field order is the SORTED order and not the
authored one - and a SigV4-signed request body is signed in the order it
was written. And it lives in the `Lean` package, the compiler's own
library, which a shipped secrets library has no business importing.

An inductive rather than a bare value: a vault answering `null`, `false`,
`0` and "no such key" means four different things, and a closed value
model keeps them apart at compile time rather than by convention. `parse`
answers `Option Json`, where `none` means "this text is not JSON" and
`some Json.null` means "this text is the JSON literal null" - a
distinction fetchjson's callers need, since only the first is a
malformed response.

A port of typescript/src/Json.ts, which is canonical.
-/

import Sekreto.Text

namespace Sekreto

/-- An insertion-ordered association list. A JSON object's field order is
signed, so the whole library carries key/value data this way rather than
in a hash map. -/
abbrev Pairs (α : Type) : Type := List (String × α)

namespace Pairs

/-- The value under `key`, or none. -/
def find? {α : Type} (entries : Pairs α) (key : String) : Option α :=
  match entries with
  | [] => none
  | (name, value) :: rest => if name == key then some value else find? rest key

/-- Set `key`, in place if it is already there and appended if it is not,
so the order a caller wrote is the order that comes back. -/
def set {α : Type} (entries : Pairs α) (key : String) (value : α) : Pairs α :=
  match entries with
  | [] => [(key, value)]
  | (name, held) :: rest =>
    if name == key then (name, value) :: rest else (name, held) :: set rest key value

/-- The keys, in order. -/
def keys {α : Type} (entries : Pairs α) : List String := entries.map Prod.fst

end Pairs

/-- A JSON value. Numbers are `Float` only: there is no integer case
anywhere in this library, which is what keeps a payload read from one
store and written to another byte-identical. -/
inductive Json where
  | null
  | bool (value : Bool)
  | num (value : Float)
  | str (value : String)
  | arr (value : List Json)
  | obj (value : Pairs Json)
  deriving Inhabited

namespace Json

/-- Render a string as a JSON string literal, quotes included. Public,
because the CLI assembles its output line field by field. -/
def quote (text : String) : String :=
  let escape (ch : Char) : String :=
    if '"' == ch then "\\\""
    else if '\\' == ch then "\\\\"
    else if '\n' == ch then "\\n"
    else if '\r' == ch then "\\r"
    else if '\t' == ch then "\\t"
    else if ch.toNat < 0x20 then
      "\\u00" ++ hexbyte (UInt8.ofNat ch.toNat)
    else String.singleton ch
  "\"" ++ text.toList.foldl (fun out ch => out ++ escape ch) "" ++ "\""

/-- Render a value as compact JSON: no spaces, no newlines. -/
partial def stringify : Json → String
  | .null => "null"
  | .bool value => if value then "true" else "false"
  | .num value => numstr value
  | .str value => quote value
  | .arr entries => "[" ++ String.intercalate "," (entries.map stringify) ++ "]"
  | .obj entries =>
    "{" ++ String.intercalate ","
      (entries.map (fun kv => quote kv.1 ++ ":" ++ stringify kv.2)) ++ "}"

instance : ToString Json := ⟨stringify⟩

def asstr : Json → Option String
  | .str value => some value
  | _ => none

def asnum : Json → Option Float
  | .num value => some value
  | _ => none

def asbool : Json → Option Bool
  | .bool value => some value
  | _ => none

def asarr : Json → Option (List Json)
  | .arr value => some value
  | _ => none

def asobj : Json → Option (Pairs Json)
  | .obj value => some value
  | _ => none

/-- One step into an object; nothing for any other shape. -/
def get? (value : Json) (key : String) : Option Json :=
  match value with
  | .obj entries => entries.find? key
  | _ => none

/-- This value as the text a caller would print, or none when there is no
value at all. A JSON null is "no value": every provider here treats it as
a MISS rather than as the string "null". -/
def text : Json → Option String
  | .null => none
  | .str value => some value
  | .num value => some (numstr value)
  | .bool value => some (if value then "true" else "false")
  | other => some (stringify other)

/-- An object, in the order given: a payload's field order is signed. -/
def object (entries : Pairs Json) : Json := .obj entries

end Json

/-- The same reads on an optional value, so a provider can walk a
response body - which is `Option Json`, because a store may not have
answered with JSON at all - without unwrapping at every step. -/
namespace OptJson

/-- Walk nested objects; nothing the moment a step is not there. -/
def dig (value : Option Json) (keys : List String) : Option Json :=
  keys.foldl (fun at key => at.bind (fun held => held.get? key)) value

def text (value : Option Json) : Option String := value.bind Json.text
def asstr (value : Option Json) : Option String := value.bind Json.asstr
def asnum (value : Option Json) : Option Float := value.bind Json.asnum
def asarr (value : Option Json) : Option (List Json) := value.bind Json.asarr
def asobj (value : Option Json) : Option (Pairs Json) := value.bind Json.asobj

end OptJson

/-- Reader state: the remaining characters, and how deep the value model
is nested. -/
private structure Reader where
  rest : List Char
  depth : Nat

/-- The nesting a response body may reach before it is refused. A body
arrives before any trust check has been made of it, and `[[[[...` on a
recursive descent parser is a stack overflow - which is the process, not
an error. -/
private def MAXDEPTH : Nat := 128

private def skipws (reader : Reader) : Reader :=
  { reader with rest := reader.rest.dropWhile Char.isWhitespace }

private def isnumchar (ch : Char) : Bool :=
  ('0' ≤ ch && ch ≤ '9') || '-' == ch || '+' == ch || '.' == ch || 'e' == ch || 'E' == ch

/-- Read four hex digits as one UTF-16 code unit. No surrogate-pair
recombination, in this port or any other. -/
private def readhex4 (chars : List Char) : Option (Char × List Char) :=
  match chars with
  | a :: b :: c :: d :: rest => do
    let ha ← hexdigit a
    let hb ← hexdigit b
    let hc ← hexdigit c
    let hd ← hexdigit d
    let code := ((ha * 16 + hb) * 16 + hc) * 16 + hd
    if h : code.isValidChar then some (⟨UInt32.ofNat code, h⟩, rest) else some ('�', rest)
  | _ => none

private partial def readstr (chars : List Char) (out : String) : Option (String × List Char) :=
  match chars with
  | [] => none
  | '"' :: rest => some (out, rest)
  | '\\' :: escape :: rest =>
    if '"' == escape then readstr rest (out.push '"')
    else if '\\' == escape then readstr rest (out.push '\\')
    else if '/' == escape then readstr rest (out.push '/')
    else if 'b' == escape then readstr rest (out.push '\x08')
    else if 'f' == escape then readstr rest (out.push '\x0c')
    else if 'n' == escape then readstr rest (out.push '\n')
    else if 'r' == escape then readstr rest (out.push '\r')
    else if 't' == escape then readstr rest (out.push '\t')
    else if 'u' == escape then
      match readhex4 rest with
      | some (ch, more) => readstr more (out.push ch)
      | none => none
    else none
  | ch :: rest => readstr rest (out.push ch)

private def word (chars : List Char) (want : String) : Option (List Char) :=
  let wanted := want.toList
  if wanted.isPrefixOf chars then some (chars.drop wanted.length) else none

mutual

private partial def readvalue (reader : Reader) : Option (Json × Reader) :=
  if MAXDEPTH < reader.depth then none else
  let reader := skipws reader
  match reader.rest with
  | [] => none
  | '{' :: rest => readobj { reader with rest := rest, depth := reader.depth + 1 } []
  | '[' :: rest => readarr { reader with rest := rest, depth := reader.depth + 1 } []
  | '"' :: rest => do
    let (value, more) ← readstr rest ""
    some (.str value, { reader with rest := more })
  | 't' :: _ => (word reader.rest "true").map (fun more => (.bool true, { reader with rest := more }))
  | 'f' :: _ => (word reader.rest "false").map (fun more => (.bool false, { reader with rest := more }))
  | 'n' :: _ => (word reader.rest "null").map (fun more => (.null, { reader with rest := more }))
  | _ =>
    let span := reader.rest.takeWhile isnumchar
    if span.isEmpty then none
    else
      -- The platform's own float parser, then a finiteness check: `1e999`
      -- parses to infinity, JSON has no infinity, and an infinite expiry
      -- would later be arithmetic on a value that is not a number.
      match (String.mk span).toSubstring.toString.toFloat? with
      | none => none
      | some value =>
        if value.isNaN || value.isInf then none
        else some (.num value, { reader with rest := reader.rest.drop span.length })

private partial def readobj (reader : Reader) (out : Pairs Json) : Option (Json × Reader) :=
  let reader := skipws reader
  match reader.rest with
  | '}' :: rest => some (.obj out, { reader with rest := rest, depth := reader.depth - 1 })
  | '"' :: rest => do
    let (key, more) ← readstr rest ""
    let after := skipws { reader with rest := more }
    match after.rest with
    | ':' :: tail => do
      let (value, next) ← readvalue { after with rest := tail }
      let next := skipws next
      match next.rest with
      | ',' :: tail => readobj { next with rest := tail } (out ++ [(key, value)])
      | '}' :: tail => some (.obj (out ++ [(key, value)]), { next with rest := tail, depth := next.depth - 1 })
      | _ => none
    | _ => none
  | _ => none

private partial def readarr (reader : Reader) (out : List Json) : Option (Json × Reader) :=
  let reader := skipws reader
  match reader.rest with
  | ']' :: rest => some (.arr out, { reader with rest := rest, depth := reader.depth - 1 })
  | _ => do
    let (value, next) ← readvalue reader
    let next := skipws next
    match next.rest with
    | ',' :: tail => readarr { next with rest := tail } (out ++ [value])
    | ']' :: tail => some (.arr (out ++ [value]), { next with rest := tail, depth := next.depth - 1 })
    | _ => none

end

namespace Json

/-- Parse JSON text. Nothing for anything unreadable - which the caller
must tell apart from a literal `null` body, since only the first means
the store could not answer coherently. -/
def parse (text : String) : Option Json :=
  if text.isEmpty then none
  else
    match readvalue { rest := text.toList, depth := 0 } with
    | none => none
    | some (value, reader) =>
      -- Trailing content after the top-level value is not JSON.
      if (skipws reader).rest.isEmpty then some value else none

end Json

end Sekreto
