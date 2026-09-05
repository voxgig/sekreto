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

AFTER THE FOURTEEN GROUPS COMES THE PLUGIN SEAM, which the spec cannot
see. Every chain the corpus builds is handed every plugin, so the corpus
can never notice a consumer that passes the wrong ones, a kind that is
refused for the wrong reason, or a core that reaches into `plugins/`.
Those checks are at the bottom of this file, and the authoritative half
of the last one is `make check-core`, which reads the compiled objects.
-/

import Sekreto
import SekretoPlugins
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
  -- Every plugin, to every chain the spec builds: the spec names kinds
  -- from both halves and does not know the split exists.
  Sekreto.sekreto {
    plugins := Sekreto.allplugins,
    providers := ((aslist (jget entry "chain")).getD #[]).toList.map specof,
    cache := false }

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

-- -------------------------------------------------------- the plugin seam

-- `open Sekreto` for the seam and nothing else. The bridge above needs
-- omni's `Json`, and the library ships a `Sekreto.Json` of its own, so
-- opening the namespace for the whole file would make the two ambiguous.
section Seam
open Sekreto

/-- What a seam check answers: nothing, or what went wrong. -/
abbrev Fault := Option String

def wants (what wanted got : String) : Fault :=
  if wanted == got then none else
    some (what ++ "\n  wanted: " ++ wanted ++ "\n  got:    " ++ got)

/-- The first fault, or none. -/
def firstfault (faults : List Fault) : Fault :=
  faults.foldl (fun held next => held.orElse (fun _ => next)) none

/-- What a refusal said, or `<accepted>` when there was none. -/
def refusal {α : Type} (act : IO α) : IO String :=
  tryCatch (do let _ ← act; return "<accepted>") (fun err => return Sekreto.why err)

def joined (values : List String) : String := String.intercalate " " values

/-- Each plugin instance as `ref=status`, in the host's own order. -/
def refs (secrets : Sekreto) : IO String := do
  return joined ((← secrets.instances).map (fun entry => entry.1 ++ "=" ++ entry.2))

def sorted (values : List String) : List String :=
  values.mergeSort (fun left right => left ≤ right)

def PLUGINS : List String := [
  "awsparams", "awssecrets", "azuresecrets", "boru", "doppler", "gcpsecrets",
  "hashicorp", "infisical", "onepassword", "secretspec"]

def EVERY : List String :=
  sorted (["dotenv", "env", "file", "memory"] ++ PLUGINS)

/-- The import lines of one source file, in order. -/
def importsof (path : String) : IO (List String) := do
  let text ← IO.FS.readFile path
  return ((text.splitOn "\n").filter (fun line => line.startsWith "import ")).map
    (fun line => (line.drop 7).trim)

-- The full set holds every kind, and the core's own list of what ships as
-- a plugin says the same. That list is what tells a typo from a plugin
-- nobody passed in, so a kind added on one side and not the other would
-- give the wrong advice.
def seamFullSet : IO Fault := do
  return firstfault [
    wants "allplugins" (joined PLUGINS) (joined (sorted (allplugins.map (·.name)))),
    wants "PLUGINKINDS" (joined PLUGINS) (joined (sorted PLUGINKINDS)),
    wants "BUILTINS" (joined BUILTINKINDS) (joined (BUILTINS.map (·.name)))]

-- Naming a kind is not enough: a kind can be in the catalog and still
-- fail to build. Construction is what the CLI does before any network.
def seamEveryKind : IO Fault := do
  let secrets ← sekreto {
    plugins := allplugins,
    providers := EVERY.map (fun kind =>
      { kind := kind, addr := "http://127.0.0.1:8200", token := "t",
        dir := "/tmp", file := "/tmp/.env" }) }

  return firstfault [
    wants "stores" (joined EVERY) (joined (← secrets.stores)),
    wants "kinds" (joined EVERY) (joined (← secrets.kinds)),
    wants "instances" (joined (EVERY.map (fun kind => kind ++ "=live"))) (← refs secrets)]

-- THE CONSUMER'S LIST IS THE BLIND SPOT THE CORPUS CANNOT SEE: a CLI that
-- passes one plugin instead of ten leaves all fourteen groups green and
-- fails nine integration checks. Matched through the NEXT FIELD, so that
-- `plugins := allplugins.take 1` cannot satisfy a prefix of it.
def seamCli : IO Fault := do
  let source ← IO.FS.readFile "cli/Cli.lean"
  let lines := (source.splitOn "\n").map String.trim
  return firstfault [
    wants "cli imports the full set" "true" (toString (lines.contains "import SekretoPlugins")),
    wants "cli passes the full set" "true"
      (toString (hasText source "{ plugins := allplugins, providers := ← chainfor source }"))]

-- One plugin is enough for a chain that names only it - and a kind that
-- was not passed in is refused with a message that names the fix.
def seamOnePlugin : IO Fault := do
  let secrets ← sekreto {
    plugins := [hashicorp],
    providers := [
      { kind := "memory", values := [("API_TOKEN", "tok01")] },
      { kind := "hashicorp", name := "prod", addr := "https://vault.example.com", token := "t" }] }

  let notpassed ← refusal (sekreto {
    plugins := [hashicorp],
    providers := [{ kind := "doppler", token := "t" }] })

  -- A kind nobody ships is a typo, and gets no such hint.
  let typo ← refusal (sekreto { providers := [{ kind := "vualt" }] })

  return firstfault [
    wants "stores" "memory prod" (joined (← secrets.stores)),
    wants "sources" "memory hashicorp:https://vault.example.com/secret"
      (joined (← secrets.sources)),
    wants "get" "tok01" (← secrets.get "api.token"),
    wants "instances" "hashicorp$prod=live memory=live" (← refs secrets),
    wants "kinds" "dotenv env file hashicorp memory" (joined (← secrets.kinds)),
    wants "a kind nobody passed in"
      ("sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)"
        ++ " - doppler is a sekreto plugin, not built in: pass it in the plugins option")
      notpassed,
    wants "a typo"
      "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)"
      typo]

-- Two providers MAY share a store name - a directed read walks both, and
-- the spec pins it - but an instance ref may not, so the second gets a
-- numbered tag from the host and keeps its store name. A store name is
-- therefore also a plugin tag, and one that is not is refused.
def seamStoreNames : IO Fault := do
  let secrets ← sekreto { providers := [
    { kind := "memory" },
    { kind := "memory", values := [("API_TOKEN", "second")] },
    { kind := "memory", name := "pair" },
    { kind := "memory", name := "pair", values := [("API_TOKEN", "pair2")] }] }

  let bad ← refusal (sekreto { providers := [{ kind := "memory", name := "my store" }] })

  return firstfault [
    wants "stores" "memory pair" (joined (← secrets.stores)),
    wants "instances" "memory=live memory$1=live memory$2=live memory$pair=live"
      (← refs secrets),
    wants "getfrom memory" "second" (← secrets.getfrom "memory" "api.token"),
    wants "getfrom pair" "pair2" (← secrets.getfrom "pair" "api.token"),
    wants "an unusable store name" "sekreto: invalid store name: my store" bad]

-- A provider that refuses its own configuration raises a SekretoError
-- from inside the plugin's `define`. The spec pins that message byte for
-- byte, so it must come back out of the host as itself - not wrapped as
-- plugin_define_failed, and not as the host's wording of it.
def seamRefusal : IO Fault := do
  let kv ← refusal (sekreto {
    plugins := allplugins,
    providers := [{ kind := "hashicorp", addr := "https://v", token := "t", kv := some 3 }] })

  -- ...and any other error is not sekreto's to rewrite: it surfaces as
  -- the host reports it, naming the instance and the cause. A
  -- `SekretoError` is `IO.userError` and nothing else is, which is how
  -- the two are told apart.
  let broken := providerplugin "broken" (fun _ => throw (IO.Error.otherError 7 "boom"))
  let other ← refusal (sekreto {
    plugins := [broken],
    providers := [{ kind := "broken" }] })

  return firstfault [
    wants "a sekreto refusal" "sekreto: hashicorp: unsupported kv version: 3" kv,
    wants "any other error names the host's code" "true"
      (toString (hasText other "plugin_define_failed")),
    wants "any other error names the instance" "true" (toString (hasText other "broken")),
    wants "any other error keeps the cause" "true" (toString (hasText other "boom"))]

/-- A custom kind is one `providerplugin` call: a provider that answers to
SHOUTED names, and refuses a spec with no values. -/
def shouty : Plugin.Definition := providerplugin "shouty" (fun spec => do
  if spec.values.isEmpty then fail "sekreto: shouty: no values"
  return {
    lookup := fun name => pure (Pairs.find? spec.values (asciiupper name)),
    describe := "shouty" })

def seamCustom : IO Fault := do
  let secrets ← sekreto {
    plugins := [shouty],
    providers := [{ kind := "shouty", values := [("API.TOKEN", "loud")] }] }

  let empty ← refusal (sekreto { plugins := [shouty], providers := [{ kind := "shouty" }] })

  -- A definition Lean's types cannot reject - a name that is not a legal
  -- plugin name - is refused by the host rather than half-loaded. It is
  -- what the dynamic ports guard by refusing a module passed as a plugin.
  let unnamed ← refusal (sekreto { plugins := [providerplugin "" (fun _ => fail "never")] })

  return firstfault [
    wants "get" "loud" (← secrets.get "api.token"),
    wants "instances" "shouty=live" (← refs secrets),
    wants "a custom refusal" "sekreto: shouty: no values" empty,
    wants "an unusable definition name" "true"
      (toString (hasText unnamed "plugin_definition_name"))]

-- A plugin that names a built-in kind replaces it - how a host
-- substitutes an implementation, and never an accident, because the four
-- names are documented. The catalog still holds four kinds.
def loudmemory : Plugin.Definition := providerplugin "memory" (fun _ =>
  pure { lookup := fun _ => pure (some "replaced"), describe := "memory" })

def seamReplace : IO Fault := do
  let secrets ← sekreto {
    plugins := [loudmemory],
    providers := [{ kind := "memory", values := [("API_TOKEN", "original")] }] }

  -- ...and the replacement belongs to that chain alone: `allplugins` and
  -- BUILTINS are data, and each Sekreto copies them into a catalog of its
  -- own rather than sharing one.
  let plain ← sekreto { providers := [{ kind := "memory", values := [("API_TOKEN", "original")] }] }

  return firstfault [
    wants "replaced" "replaced" (← secrets.get "api.token"),
    wants "kinds" "dotenv env file memory" (joined (← secrets.kinds)),
    wants "the next chain is unaffected" "original" (← plain.get "api.token")]

-- `close` tears the chain down - the host empties, every read reports the
-- secret unknown - and keeps redaction, which must outlive the chain
-- because the log it protects does.
def seamClose : IO Fault := do
  let secrets ← sekreto {
    providers := [{ kind := "memory", values := [("API_TOKEN", "tok01secret")] }] }
  let before ← secrets.get "api.token"

  secrets.close

  return firstfault [
    wants "get" "tok01secret" before,
    wants "instances after close" "" (← refs secrets),
    wants "stores after close" "" (joined (← secrets.stores)),
    wants "tryget after close" "none" (toString (← secrets.tryget "api.token")),
    wants "get after close" "sekreto: unknown secret: api.token"
      (← refusal (secrets.get "api.token")),
    wants "redaction survives close" "token=[redacted]"
      (← secrets.redactText "token=tok01secret")]

-- THE CORE IMPORTS NO PLUGIN, and one plugin imports only itself.
--
-- This reads the sources, which fails faster and names the file. The
-- AUTHORITATIVE proof is `make check-core`, which reads the compiled
-- objects: `lean` emits one `initialize_<Module>` symbol per import, so
-- the core's import graph is in its object files under exact names, and
-- the core is linked there with no libcurl and no `ffi/` at all.
def COREFILES : List String := [
  "src/Sekreto.lean", "src/Sekreto/Text.lean", "src/Sekreto/Json.lean",
  "src/Sekreto/Core.lean", "src/Sekreto/Addr.lean", "src/Sekreto/Provider.lean",
  "src/Sekreto/Builtin.lean", "src/Sekreto/Chain.lean"]

def seamCoreImports : IO Fault := do
  let mut reached : List String := []
  for path in COREFILES do
    for named in ← importsof path do
      if named == "SekretoPlugins" || named.startsWith "SekretoPlugins." then
        reached := reached ++ [path ++ " -> " ++ named]
  return firstfault [
    wants "core files read" (toString COREFILES.length)
      (toString (← COREFILES.filterM (fun path =>
        System.FilePath.pathExists (System.FilePath.mk path))).length),
    wants "the core reaches no plugin" "" (joined reached)]

-- One plugin imports itself, the core it is built on, and - only if it
-- dials one - the shared HTTP client. It never imports another plugin
-- kind. secretspec reads its own CLI and nothing else, so it takes no
-- HTTP client and therefore no TLS anywhere in its closure; if that ever
-- stops being true it is a real change, not a tidy-up.
def seamPluginImports : IO Fault := do
  return firstfault [
    wants "hashicorp"
      "Sekreto.Text Sekreto.Json Sekreto.Core Sekreto.Provider Sekreto.Addr SekretoPlugins.Httpjson"
      (joined (← importsof "plugins/SekretoPlugins/Hashicorp.lean")),
    wants "secretspec"
      "Sekreto.Text Sekreto.Json Sekreto.Core Sekreto.Provider SekretoPlugins.Proc"
      (joined (← importsof "plugins/SekretoPlugins/Secretspec.lean")),
    wants "every kind has a module of its own" (joined (sorted PLUGINS))
      (joined (sorted (← PLUGINS.filterM (fun kind => do
        let module := if kind.startsWith "aws" then "Aws"
                      else asciiupper (kind.take 1) ++ kind.drop 1
        System.FilePath.pathExists
          (System.FilePath.mk ("plugins/SekretoPlugins/" ++ module ++ ".lean"))))))]

structure Seam where
  name : String
  check : IO Fault

def SEAMS : List Seam := [
  { name := "plugins/fullset", check := seamFullSet },
  { name := "plugins/everykind", check := seamEveryKind },
  { name := "plugins/cli", check := seamCli },
  { name := "plugins/oneplugin", check := seamOnePlugin },
  { name := "plugins/storenames", check := seamStoreNames },
  { name := "plugins/refusal", check := seamRefusal },
  { name := "plugins/custom", check := seamCustom },
  { name := "plugins/replace", check := seamReplace },
  { name := "plugins/close", check := seamClose },
  { name := "plugins/coreimports", check := seamCoreImports },
  { name := "plugins/pluginimports", check := seamPluginImports }]

end Seam


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

/-- One seam check, reported like a corpus group. A seam check that
raises is a failure, not a crash: the message is what it says. -/
def seamcase (only : Option String) (counts : IO.Ref Counts) (seam : Seam) : IO Unit := do
  match only with
  | some wanted => if wanted != seam.name then return ()
  | none => pure ()

  let outcome ← tryCatch seam.check (fun err => return some ("raised: " ++ Sekreto.why err))

  match outcome with
  | none =>
    counts.modify (fun held => { held with pass := held.pass + 1 })
    IO.println s!"ok   - {seam.name}"
  | some message =>
    counts.modify (fun held => { held with fail := held.fail + 1 })
    IO.println s!"FAIL - {seam.name}"
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

  -- ...and the plugin seam, which is this port's own.
  for seam in SEAMS do
    seamcase only counts seam

  let final ← counts.get
  IO.println s!"\n{final.pass} passed, {final.fail} failed"

  return (if 0 == final.fail then 0 else 1)
