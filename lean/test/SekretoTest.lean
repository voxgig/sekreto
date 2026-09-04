/-
RUN: make test
RUN-SOME: make test GROUP=envkey

The sekreto conformance suite. Every port runs these same groups, from
the same spec/sekreto.json, through its own voxgig/omni runner.

No third-party test framework: a failing omni check comes back as
`Except.error message`, and the forty-line harness at the bottom reports
it.

TWO ADAPTATIONS HAPPEN HERE, and nowhere else.

The first is the value model. omni's is `Lean.Json` wrapped in
`Option` - `none` meaning ABSENT, as distinct from `some .null` meaning a
JSON null. The library's is its own `Sekreto.Json` and its own typed
`ProviderSpec`. The bridge below converts between them explicitly, so
nothing about absent, null and value is guessed. A miss comes back as
omni's `Json.null`, which omni's default flags rewrite to `"__NULL__"` on
both sides.

The second is the monad. omni's `Subject` is `List Val → Except String
Val`: PURE, because Lean is, and because every other omni port's checks
are. The library is in `IO`, because reading the environment, a file or a
vault is. `runio` is the join, and it is the only unsafe thing in this
port - confined to the test, never to the library, exactly as the
`validname` boolean adaptation is.

Note also what is NOT adapted here: the chain is built INSIDE each
subject, so that a constructor refusal - `unsupported kv version`, which
four entries expect - reaches omni as a subject error rather than
escaping the run.
-/

import Sekreto
import Omni

open Lean
open Omni
open Sekreto (ProviderSpec AuthSpec Signing)

/-- Run an `IO` action from a pure omni subject.

`unsafeIO` is the whole of it: Lean's `IO` is a state monad over a token
world, and running one outside `IO` is exactly what that function is for.
The `implemented_by`/`opaque` pair is the ordinary way to keep an unsafe
implementation behind a safe name. -/
unsafe def runioImpl {α : Type} (act : IO α) : Except String α :=
  match unsafeIO act with
  | .ok value => .ok value
  | .error err => .error (toString err)

@[implemented_by runioImpl]
opaque runio {α : Type} (act : IO α) : Except String α := .error "sekreto: io not run"

/-- Find the shared spec directory by walking up from the working dir. -/
partial def specfile (name : String) : IO String := do
  let rec search (dir : String) (step : Nat) : IO String := do
    if step ≥ 8 then
      throw (IO.userError s!"sekreto: spec not found: {name}")
    else
      let cand := s!"{dir}/spec/{name}"
      if ← System.FilePath.pathExists cand then pure cand else search s!"{dir}/.." (step + 1)
  search "." 0

-- ------------------------------------------------------------ the bridge

/-- A JSON string as text; anything else, including absence, as the empty
string. That is what the library's `String` entry points expect, and
`validname ""` is false, which is what the corpus's non-string cases
want. -/
def textof (value : Val) : String := (asstr value).getD ""

/-- The name a group's entry asks about. -/
def nameof (entry : Val) : String := textof (jget entry "name")

/-- The store a directed group's entry names. -/
def storeof (entry : Val) : String := textof (jget entry "store")

/-- An ordered map of strings, as the spec writes one. -/
def pairsof (value : Val) : Sekreto.Pairs String :=
  ((asmap value).getD []).map (fun kv => (kv.1, stringify (some kv.2)))

/-- An ordered map of strings, as omni compares one. -/
def toomni (pairs : Sekreto.Pairs String) : Json :=
  jmap (pairs.map (fun kv => (kv.1, jstr kv.2)))

/-- A list of strings, as omni compares them. -/
def textlist (values : List String) : Json := jlist (values.map jstr)

/-- A miss, as omni compares one: an explicit JSON null, which the
default flags rewrite to `__NULL__` on both sides. -/
def missing : Json := Json.null

/-- One provider spec, out of the spec's declarative chain description. -/
def specof (entry : Json) : ProviderSpec :=
  let here := some entry
  let field (key : String) : String := textof (jget here key)

  let auth : Option AuthSpec :=
    match asmap (jget here "auth") with
    | none => none
    | some _ =>
      let a := jget here "auth"
      let afield (key : String) : String := textof (jget a key)
      some {
        method := afield "method", mount := afield "mount", role := afield "role",
        jwt := afield "jwt", jwtfile := afield "jwtfile",
        roleid := afield "roleid", secretid := afield "secretid" }

  {
    kind := field "kind", name := field "name", «prefix» := field "prefix",
    file := field "file", values := pairsof (jget here "values"), dir := field "dir",
    addr := field "addr", token := field "token", mount := field "mount",
    kv := (asnum (jget here "kv")).map (fun value => value.toUInt64.toNat),
    vaultnamespace := field "vaultnamespace", auth := auth,
    command := field "command", profile := field "profile", backend := field "backend",
    reason := field "reason", «namespace» := field "namespace", home := field "home",
    region := field "region", keyid := field "keyid", secret := field "secret",
    session := field "session", project := field "project", vault := field "vault",
    tenant := field "tenant", clientid := field "clientid",
    clientsecret := field "clientsecret", loginaddr := field "loginaddr",
    imdsaddr := field "imdsaddr", metadataaddr := field "metadataaddr",
    apiversion := field "apiversion", config := field "config",
    environment := field "environment", path := field "path" }

/-- Build a Sekreto from the spec's declarative chain description.

Caching is OFF on every constructed chain, so no group can pass on a
value another group resolved. -/
def chainof (entry : Val) : IO Sekreto :=
  Sekreto.sekreto (((aslist (jget entry "chain")).getD #[]).toList.map specof) false

-- ----------------------------------------------------------- the subjects

-- `validname` answers whatever the language calls true; the spec says
-- JSON true, so the adaptation happens here rather than in the library.
def VALIDNAME : Subject := fun args =>
  .ok (some (jbool (Sekreto.validname (textof (args.getD 0 none)))))

def ENVKEY : Subject := fun args =>
  let entry := args.getD 0 none
  (Sekreto.envkey (nameof entry) (textof (jget entry "prefix"))).map (fun key => some (jstr key))

def VAULTREF : Subject := fun args =>
  (Sekreto.vaultref (textof (args.getD 0 none))).map (fun ref =>
    some (jmap [("path", jstr ref.path), ("field", jstr ref.field)]))

def FLATNAME : Subject := fun args =>
  let entry := args.getD 0 none
  (Sekreto.flatname (nameof entry) (textof (jget entry "sep"))).map (fun flat => some (jstr flat))

def AWSPARAM : Subject := fun args =>
  let entry := args.getD 0 none
  (Sekreto.awsparam (nameof entry) (textof (jget entry "prefix"))).map (fun path =>
    some (jstr path))

def PARSEDOTENV : Subject := fun args =>
  .ok (some (toomni (Sekreto.parsedotenv (textof (args.getD 0 none)))))

def RESOLVE : Subject := fun args =>
  let entry := args.getD 0 none
  (runio (do (← chainof entry).get (nameof entry))).map (fun value => some (jstr value))

def TRYSECRET : Subject := fun args =>
  let entry := args.getD 0 none
  (runio (do (← chainof entry).tryget (nameof entry))).map (fun value =>
    some (match value with | some held => jstr held | none => missing))

def SOURCES : Subject := fun args =>
  (runio (do (← chainof (args.getD 0 none)).sources)).map (fun found => some (textlist found))

def STORES : Subject := fun args =>
  (runio (do (← chainof (args.getD 0 none)).stores)).map (fun found => some (textlist found))

def GETFROM : Subject := fun args =>
  let entry := args.getD 0 none
  (runio (do (← chainof entry).getfrom (storeof entry) (nameof entry))).map (fun value =>
    some (jstr value))

def TRYFROM : Subject := fun args =>
  let entry := args.getD 0 none
  (runio (do (← chainof entry).tryfrom (storeof entry) (nameof entry))).map (fun value =>
    some (match value with | some held => jstr held | none => missing))

-- Answers the ordered output map itself, which omni compares as a JSON
-- object against the spec's known-answer signatures.
def SIGV4 : Subject := fun args =>
  let entry := args.getD 0 none
  let input : Signing := {
    method := textof (jget entry "method"),
    url := textof (jget entry "url"),
    service := textof (jget entry "service"),
    region := textof (jget entry "region"),
    keyid := textof (jget entry "keyid"),
    secret := textof (jget entry "secret"),
    datetime := textof (jget entry "datetime"),
    headers := pairsof (jget entry "headers"),
    body := textof (jget entry "body"),
    session := textof (jget entry "session") }
  .ok (some (toomni (Sekreto.sigv4 input)))

def REDACT : Subject := fun args =>
  let entry := args.getD 0 none
  let values := ((aslist (jget entry "values")).getD #[]).toList.map (fun held =>
    textof (some held))
  .ok (some (jstr (Sekreto.redact (textof (jget entry "text")) values)))

-- ------------------------------------------------------------ the runner

structure Counts where
  pass : Nat := 0
  fail : Nat := 0

def testcase (only : Option String) (counts : IO.Ref Counts) (name : String)
    (body : Except String Unit) : IO Unit := do
  match only with
  | some wanted => if wanted != name then return ()
  | none => pure ()

  match body with
  | .ok () =>
    counts.modify (fun held => { held with pass := held.pass + 1 })
    IO.println s!"ok   - {name}"
  | .error message =>
    counts.modify (fun held => { held with fail := held.fail + 1 })
    IO.println s!"FAIL - {name}"
    IO.println message

def main (argv : List String) : IO UInt32 := do
  let only := (argv.head?).filter (fun given => !given.isEmpty)
  let counts ← IO.mkRef ({} : Counts)
  let run := testcase only counts

  let R ← makeRunner (← specfile "sekreto.json") emptyProvider "sekreto"

  run "validname" (R.runsetflags (R.set "validname") Flags.nonull (some VALIDNAME))
  run "envkey" (R.runset (R.set "envkey") (some ENVKEY))
  run "vaultref" (R.runset (R.set "vaultref") (some VAULTREF))
  run "flatname" (R.runset (R.set "flatname") (some FLATNAME))
  run "awsparam" (R.runset (R.set "awsparam") (some AWSPARAM))
  run "parsedotenv" (R.runset (R.set "parsedotenv") (some PARSEDOTENV))
  run "resolve" (R.runset (R.set "resolve") (some RESOLVE))
  run "trysecret" (R.runset (R.set "trysecret") (some TRYSECRET))
  run "sources" (R.runset (R.set "sources") (some SOURCES))
  run "stores" (R.runset (R.set "stores") (some STORES))
  run "getfrom" (R.runset (R.set "getfrom") (some GETFROM))
  run "tryfrom" (R.runset (R.set "tryfrom") (some TRYFROM))
  run "sigv4" (R.runset (R.set "sigv4") (some SIGV4))
  run "redact" (R.runset (R.set "redact") (some REDACT))

  let final ← counts.get
  IO.println s!"\n{final.pass} passed, {final.fail} failed"

  return (if 0 == final.fail then 0 else 1)
