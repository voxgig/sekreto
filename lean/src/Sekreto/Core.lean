/-
sekreto: one interface for secrets, wherever they live.

A Sekreto is an ordered chain of providers. `get` asks each in turn and
returns the first hit, so an app can be configured from environment
variables in development and a vault in production without changing a
line of its own code.

Two shapes of failure, and they are never interchangeable. A store that
does not hold the secret is a MISS (`none`) and the chain carries on. A
store that could not ANSWER throws. Getting that backwards makes a chain
fall silently through to a weaker store, which is the worst failure this
library has.

Lean has no exception type of its own to subclass, and `SekretoError`
carries a message and nothing else in every port, so a refusal here is
`IO.userError message` - whose `toString` IS the message, byte for byte.
The pure functions that can refuse answer `Except String String`
instead, because Lean's are pure and a caller that has no `IO` to run in
still has to be able to ask.

A port of typescript/src/Sekreto.ts, which is canonical.
-/

import Sekreto.Text
import Sekreto.Json
import Sekreto.Provider

namespace Sekreto

/-- Anything sekreto refuses to do: a bad name, a missing secret, a
provider that could not be reached. The message is the whole contract -
no code, no fields, no cause. -/
def sekretoError (message : String) : IO.Error := IO.userError message

/-- Refuse, in `IO`. -/
def fail {α : Type} (message : String) : IO α := throw (sekretoError message)

/-- Carry a pure refusal into `IO` unchanged. -/
def ofResult {α : Type} : Except String α → IO α
  | .ok value => pure value
  | .error message => fail message

/-- Is this a well-formed secret name: dot-separated `[a-z0-9_]+`?

Never raises, whatever it is handed. The check is a character scan and
not a regex on purpose: in Python, PCRE, Perl and .NET `$` also matches
before a final newline, so `api.token\n` passed in four ports. The corpus
pins that case, and the two like it, as false. -/
def validname (name : String) : Bool :=
  !name.isEmpty && (segments name).all namepart

/-- The name, or a refusal. Every entry point checks its name here. -/
def checkname (name : String) : Except String String :=
  if validname name then .ok name else .error ("sekreto: invalid name: " ++ name)

/-- The environment-variable key for a name: `api.token` -> `API_TOKEN`.
The prefix is NOT uppercased - it is written as it is meant. -/
def envkey (name : String) (pre : String := "") : Except String String := do
  let checked ← checkname name
  return pre ++ asciiupper (String.intercalate "_" (segments checked))

/-- Where a name lives in a KV vault. -/
structure VaultRef where
  path : String
  field : String
  deriving Inhabited

/-- Where a name lives in a KV vault: `api.token` -> `api` / `token`.

A single-segment name has no path of its own, so it becomes a secret of
that name with the conventional field `value`. -/
def vaultref (name : String) : Except String VaultRef := do
  let parts := segments (← checkname name)
  match parts with
  | [only] => return { path := only, field := "value" }
  | _ =>
    let field := parts.getLast!
    return { path := String.intercalate "/" (parts.dropLast), field := field }

/-- A name flattened to one segment: `api.token` -> `api_token` (GCP
Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).

Those stores have no path hierarchy and reject dots in ids, so the dots
become the store's conventional separator. With `-` as the separator,
underscores flatten too: Azure Key Vault's alphabet is letters, digits
and hyphens only, and a valid sekreto name like `with_underscore` must
still be representable there. -/
def flatname (name : String) (sep : String) : Except String String := do
  let flat := String.intercalate sep (segments (← checkname name))
  return if "-" == sep then replaceAll flat "_" "-" else flat

/-- The AWS SSM Parameter Store name for a name: dots become the path
hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
`/db/pass/main`, or `/app/db/pass/main` under prefix `/app`. -/
def awsparam (name : String) (pre : String := "") : Except String String := do
  let checked ← checkname name
  let rooted := if !pre.isEmpty && !pre.startsWith "/" then "/" ++ pre else pre
  let base := dropsuffix rooted "/"
  return base ++ "/" ++ String.intercalate "/" (segments checked)

/-- Unescape a double-quoted `.env` value.

A scan, not a chain of replacements: `\n \r \t \\ \"` are the whole
alphabet, ANY OTHER escape is preserved as backslash plus character, and
a trailing backslash is literal. -/
private partial def unescape (chars : List Char) (out : String) : String :=
  match chars with
  | [] => out
  | '\\' :: next :: rest =>
    if 'n' == next then unescape rest (out.push '\n')
    else if 'r' == next then unescape rest (out.push '\r')
    else if 't' == next then unescape rest (out.push '\t')
    else if '\\' == next then unescape rest (out.push '\\')
    else if '"' == next then unescape rest (out.push '"')
    else unescape rest ((out.push '\\').push next)
  | ch :: rest => unescape rest (out.push ch)

private def unquote (value : String) : String :=
  if 2 ≤ value.length && value.startsWith "\"" && value.endsWith "\"" then
    unescape (value.drop 1 |>.dropRight 1 |>.toList) ""
  else if 2 ≤ value.length && value.startsWith "'" && value.endsWith "'" then
    value.drop 1 |>.dropRight 1
  else value

/-- Parse `.env` text into ordered raw keys and values.

There is no `.env` standard, so this function is the specification.
Deliberately small: `KEY=value`, an optional `export`, `#` comments on
their own line, and single- or double-quoted values (double quotes also
unescape). A line with no `=`, or with an empty key, is skipped SILENTLY
- it does not abort the lines after it. Never raises. -/
def parsedotenv (text : String) : Pairs String :=
  (text.splitOn "\n").foldl (fun out rawline =>
    let line := (dropsuffix rawline "\r").trim
    if line.isEmpty || line.startsWith "#" then out
    else
      let entry := if line.startsWith "export " then (line.drop 7).trim else line
      match indexOfChar entry '=' with
      | none => out
      -- `eq <= 0` skips both "no `=`" and "empty key".
      | some 0 => out
      | some eq =>
        let key := (entry.take eq).trim
        let value := (entry.drop (eq + 1)).trim
        Pairs.put out key (unquote value)) []

/-- Replace known secret values in text with `[redacted]`.

Only values of four characters or more are replaced: shorter ones are
too likely to appear in ordinary text, and redacting them would make
logs unreadable without making them safer.

LONGEST FIRST, always, and over a COPY of the caller's list - `values` is
`seen` when this is called through `Sekreto.redactText`, and reordering
it would reorder the live redaction history. The replacement is a literal
substring pass and not a pattern, so a secret full of metacharacters is
not interpreted. -/
def redact (text : String) (values : List String) : String :=
  let usable := values.filter (fun value => 4 ≤ value.length)
  let ordered := usable.mergeSort (fun left right => right.length ≤ left.length)
  ordered.foldl (fun out value => replaceAll out value "[redacted]") text

/-- The store name a provider answers to when nothing says otherwise.

`describe` opens with the provider's kind - `hashicorp:...`,
`dotenv:...`, plain `env` - so the kind is the natural default, and a
custom provider gets a sensible name without implementing anything
extra. -/
def storename (provider : Provider) : String :=
  takeWhile provider.describe (fun ch => ':' != ch)

/-- One provider in the chain, under the store name it answers to. -/
structure Entry where
  store : String
  provider : Provider

/-- One resolved value, with the store it came from. -/
structure Cached where
  store : String
  name : String
  value : String

end Sekreto

/-- The secrets facade: a chain of providers plus a cache.

Two ways to read. `get` is transparent - it walks the chain and takes the
first hit, and the caller never learns which store answered. `getfrom` is
directed - it names the store, and only that store is asked. Use the
first for ordinary configuration, the second when *which* store holds a
secret is part of what you mean.

There is no `Repr`, `ToString` or `deriving` anywhere on this structure,
and there cannot be one: three of its four fields are `IO.Ref`, which has
no printer in Lean at all. So the hazard every other port answers with a
hand-written print hook - `print(sekreto)` emitting every resolved secret
- does not exist here; `Sekreto.inspect` is offered because the ports
agree on the shape, not because anything would otherwise leak. -/
structure Sekreto where
  /-- The chain, in resolution order. A ref, so `close` can empty it. -/
  entries : IO.Ref (List Sekreto.Entry)
  /-- Resolved values, keyed by (store, name). A LIST, not a map: the
  store a value came from stays attached, and redaction order does not
  vary between runs. -/
  cache : IO.Ref (List Sekreto.Cached)
  /-- Every value ever resolved, for `redactText`. Kept independently of
  the read cache, so `cache := false` does not silently disable
  redaction; append-only for the object's life, so neither `refresh` nor
  `close` forgets a secret that has already been handed out. -/
  seen : IO.Ref (List String)
  docache : Bool

namespace Sekreto

/-- Build a chain from live providers. `names` is positional; an entry
left `none` or empty falls back to the provider's kind. -/
def make (providers : List Provider) (names : List (Option String) := [])
    (cache : Bool := true) : IO Sekreto := do
  let entries := (List.range providers.length).map (fun index =>
    let provider := providers.getD index { lookup := fun _ => pure none, describe := "" }
    let named := (names.get? index).join.filter (fun value => !value.isEmpty)
    ({ store := named.getD (storename provider), provider := provider } : Entry))
  return {
    entries := ← IO.mkRef entries,
    cache := ← IO.mkRef [],
    seen := ← IO.mkRef [],
    docache := cache }

/-- The single path both readers share.

The order matters and every step of it is pinned by the corpus: the name
is validated FIRST, before the cache and before the first provider; a
cache hit does NOT push to `seen`; the EMPTY STRING IS A HIT; misses are
never cached; and `seen` is appended to whether caching is on or off. A
provider that throws is not caught - the failure propagates out of
`get`. -/
private def resolve (self : Sekreto) (store name : String)
    (useentries : List Entry) : IO (Option String) := do
  let _ ← ofResult (checkname name)

  let held ← self.cache.get
  let hit := if self.docache then
      held.find? (fun entry => store == entry.store && name == entry.name)
    else none

  match hit with
  | some entry => return some entry.value
  | none =>
    let rec walk (rest : List Entry) : IO (Option String) := do
      match rest with
      | [] => return none
      | entry :: more =>
        match ← entry.provider.lookup name with
        | some value => return some value
        | none => walk more

    match ← walk useentries with
    | none => return none
    | some value =>
      if self.docache then
        self.cache.modify (fun held => held ++ [{ store := store, name := name, value := value }])
      self.seen.modify (fun held => held ++ [value])
      return some value

/-- The secret, or `none` if no provider has it. Named `tryget` because
`try` is a Lean keyword. -/
def tryget (self : Sekreto) (name : String) : IO (Option String) := do
  resolve self "" name (← self.entries.get)

/-- The secret, or a refusal if no provider has it. -/
def get (self : Sekreto) (name : String) : IO String := do
  match ← self.tryget name with
  | some value => return value
  | none => fail ("sekreto: unknown secret: " ++ name)

/-- The secret from one named store, or `none` if that store does not
have it.

Naming a store that is not in the chain is an error, not a miss, and it
is checked BEFORE the name: `tryget` already means "this store may not
have it", so it cannot also mean "this store may not exist" without
hiding a typo. Store names may repeat, and a directed read walks every
matching entry in chain order. -/
def tryfrom (self : Sekreto) (store name : String) : IO (Option String) := do
  let entries ← self.entries.get
  let matching := entries.filter (fun entry => store == entry.store)
  if matching.isEmpty then fail ("sekreto: unknown store: " ++ store)
  resolve self store name matching

/-- The secret from one named store, or a refusal if that store does not
have it. -/
def getfrom (self : Sekreto) (store name : String) : IO String := do
  match ← self.tryfrom store name with
  | some value => return value
  | none => fail ("sekreto: unknown secret: " ++ store ++ ":" ++ name)

/-- Does any provider have this secret? -/
def has (self : Sekreto) (name : String) : IO Bool := do
  return (← self.tryget name).isSome

/-- Does this named store have this secret? -/
def hasin (self : Sekreto) (store name : String) : IO Bool := do
  return (← self.tryfrom store name).isSome

/-- Every named secret at once, in the order asked. Missing ones are an
error, and the walk stops at the first. -/
def all (self : Sekreto) (names : List String) : IO (Pairs String) := do
  let mut out : Pairs String := []
  for name in names do
    out := out ++ [(name, ← self.get name)]
  return out

/-- A description of each provider, in resolution order, repeats kept. -/
def sources (self : Sekreto) : IO (List String) := do
  return (← self.entries.get).map (fun entry => entry.provider.describe)

/-- The name of each store `getfrom` can address, in resolution order and
without repeats. -/
def stores (self : Sekreto) : IO (List String) := do
  let entries ← self.entries.get
  return (entries.map (fun entry => entry.store)).eraseDups

/-- Replace every value this Sekreto has resolved with `[redacted]`.

Named `redactText` because the module-level `redact` this delegates to
keeps its own name; the zig port made the same split for the same
reason. Works whether or not caching is enabled. -/
def redactText (self : Sekreto) (text : String) : IO String := do
  return redact text (← self.seen.get)

/-- Drop cached values, so the next `get` asks the providers again.
`seen` is untouched: redaction must not forget a secret already handed
out. -/
def refresh (self : Sekreto) : IO Unit := self.cache.set []

/-- Tear the chain down. Afterwards `stores` and `sources` are empty,
`tryget` misses and `get` refuses - and `redactText` still knows every
value ever resolved. -/
def close (self : Sekreto) : IO Unit := do
  self.entries.set []
  self.cache.set []

/-- What a printer would be allowed to say. Never reaches a value. -/
def inspect (self : Sekreto) : IO String := do
  return "Sekreto { stores: [ " ++ String.intercalate ", " (← self.stores) ++ " ] }"

end Sekreto
