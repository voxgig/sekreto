/-
RUN: make vaulttest
RUN-SOME: ./build/sekreto-vaulttest restricted

The mini vault, from both sides: the store a chain reads, and the
programmatic API a plugin definition can publish beside it.

The vault is not in spec/sekreto.json and cannot be until every port
ships the kind. The spec runs against all twenty-three of them, so an
entry naming `minivault` would fail the ports that have no such
provider. What the shared corpus would have carried is here instead,
plus the one thing it could not carry either way: a file written by this
port and read by another, pinned by the vaults in test/fixture.

Its own binary, and no omni: a checkout with no runner beside it can
still run this.

A port of typescript/test/minivault.test.ts.
-/

import Sekreto
import SekretoPlugins.Minivault

open Sekreto

/-- The master passphrase every case here opens with. -/
def master : String := "master-passphrase"

/-- The rounds every case here uses. The library default is 210000, which
is the point of PBKDF2 and the wrong thing to pay per assertion. -/
def rounds : Nat := 1000

initialize passcount : IO.Ref Nat ← IO.mkRef 0
initialize failcount : IO.Ref Nat ← IO.mkRef 0
initialize count : IO.Ref Nat ← IO.mkRef 0
initialize work : IO.Ref String ← IO.mkRef ""
initialize only : IO.Ref String ← IO.mkRef ""

-- ------------------------------------------------------------ the harness

/-- A failed assertion, raised the way a refusal is: this suite reports
one shape, and `testcase` tells them apart by nothing at all. -/
private def raisefail {α : Type} (why : String) : IO α := throw (IO.userError why)

def same (what want got : String) : IO Unit :=
  if want != got then
    raisefail (what ++ ":\n    want: " ++ want ++ "\n    got:  " ++ got)
  else pure ()

def samelist (what : String) (want got : List String) : IO Unit :=
  same what (String.intercalate " " want) (String.intercalate " " got)

def truth (what : String) (got : Bool) : IO Unit := if !got then raisefail what else pure ()

def holds (what want got : String) : IO Unit :=
  if (got.splitOn want).length < 2 then
    raisefail (what ++ ":\n    want to contain: " ++ want ++ "\n    got: " ++ got)
  else pure ()

/-- The refusal a call raises, or a failure when it did not refuse. -/
def refusal {α : Type} (what : String) (act : IO α) : IO String :=
  tryCatch (do let _ ← act; raisefail (what ++ ": nothing was refused"))
    (fun err => return why err)

def testcase (name : String) (body : IO Unit) : IO Unit := do
  if (← only.get).isEmpty || name == (← only.get) then
    match ← body.toBaseIO with
    | .ok _ =>
      passcount.modify (· + 1)
      IO.println ("ok   - " ++ name)
    | .error err =>
      failcount.modify (· + 1)
      IO.println ("FAIL - " ++ name ++ "\n       " ++ why err)

-- ------------------------------------------------------ the vault under test

def vaultpath : IO String := do
  count.modify (· + 1)
  return (← work.get) ++ "/vault" ++ toString (← count.get) ++ ".skmv"

def vaultopts (file key passphrase : String) : VaultOptions :=
  { file := file, key := key, passphrase := passphrase, iterations := rounds }

def fresh : IO Vault := do createvault (vaultopts (← vaultpath) "" master)

def openas (file key passphrase : String) : IO Vault :=
  openvault (vaultopts file key passphrase)

def grantof (key passphrase : String) (names : List String) (write : Bool) : GrantSpec :=
  { key := key, passphrase := passphrase, names := names, write := write,
    iterations := rounds }

/-- The value, or a word no secret here is, so a miss is an assertion
rather than an exception. -/
def valueof (v : Vault) (name : String) : IO String := do
  return (← vaultget v name).getD "(miss)"

/-- Where the committed vaults live, found by walking up. -/
def fixturedir : IO String := do
  let rec walk (dir : String) (left : Nat) : IO String := do
    if ← System.FilePath.pathExists (dir ++ "/test/fixture/minivault.skmv") then
      return dir ++ "/test/fixture"
    else match left with
      | 0 => raisefail "the fixture directory was not found"
      | next + 1 => walk (dir ++ "/..") next
  walk "." 8

/-- EVERY committed vault, read off disk rather than listed here. A
hard-coded list is one more place to edit when a port lands, and the edit
that gets forgotten is the one that makes this suite stop checking the
port that just arrived. -/
def fixtures : IO (List String) := do
  let held ← (System.FilePath.mk (← fixturedir)).readDir
  let names := held.toList.map (·.fileName) |>.filter (·.endsWith ".skmv")
  return names.mergeSort (· ≤ ·)

/-- A committed vault, copied so that a case which writes cannot edit the
bytes the format contract is made of. -/
def fixture (name : String) : IO String := do
  let mine ← vaultpath
  IO.FS.writeBinFile mine (← IO.FS.readBinFile ((← fixturedir) ++ "/" ++ name))
  return mine

/-- Does the raw file hold this text? BYTE-WISE, because a vault has NUL
bytes in it and a reader that stopped at the first one would report every
secret absent. -/
def holdsbytes (raw : ByteArray) (text : String) : Bool := Id.run do
  let want := text.toUTF8
  if raw.size < want.size then return false
  for start in [0 : raw.size - want.size + 1] do
    let mut found := true
    for step in [0 : want.size] do
      if raw[start + step]! != want[step]! then found := false
    if found then return true
  return false

def vaultspec (file key passphrase : String) : ProviderSpec :=
  { kind := "minivault", file := file, vaultkey := key, passphrase := passphrase }

def memoryspec (key value : String) : ProviderSpec :=
  { kind := "memory", values := [(key, value)] }

def thechain (specs : List ProviderSpec) : IO Sekreto :=
  sekreto { cache := false, plugins := [minivault], providers := specs }

-- ---------------------------------------------------------------- the file

def anewvaultholdsnothing : IO Unit := do
  let v ← fresh
  samelist "list" [] (← vaultlist v)
  same "key" "master" v.key

  let info ← vaultopen v
  truth "the master key is not master" info.master
  truth "the master key may not write" info.write
  samelist "grants" [] info.grants

def awrittensecretcomesback : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"

  same "get" "tok01" (← valueof v "api.token")
  samelist "list" ["api.token", "db.pass"] (← vaultlist v)
  truth "has said no" (← vaulthas v "api.token")
  truth "has said yes to an unknown name" !(← vaulthas v "nope")
  same "an unknown name answered" "(miss)" (← valueof v "nope")

  -- A SECOND HANDLE on the same file, so the assertion is about the bytes
  -- rather than about what this handle happens to remember.
  same "a new handle" "tok01" (← valueof (← openas v.file "" master) "api.token")

def thefileisbinary : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"

  let raw ← IO.FS.readBinFile v.file
  same "the magic is wrong" "SKMV" (String.fromUTF8! (raw.extract 0 4))

  -- NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
  -- the secret's name and its value are not, and neither is the passphrase
  -- that unwrapped them.
  for secret in ["api.token", "tok01", master] do
    if holdsbytes raw secret then raisefail (secret ++ " is in the file")

  truth "the key id is not in the file" (holdsbytes raw "master")

def rewritinganamereplacesit : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "first"
  vaultset v "api.token" "second"

  same "get" "second" (← valueof v "api.token")
  samelist "one entry" ["api.token"] (← vaultlist v)

def removedropsaname : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"
  vaultremove v "api.token"

  samelist "list" ["db.pass"] (← vaultlist v)
  same "a removed name answered" "(miss)" (← valueof v "api.token")
  holds "remove again" "no such secret: api.token"
    (← refusal "remove again" (vaultremove v "api.token"))

def abadnameisrefused : IO Unit := do
  let v ← fresh
  holds "set" "invalid name" (← refusal "set" (vaultset v "API.TOKEN" "x"))
  holds "get" "invalid name" (← refusal "get" (vaultget v "api..token"))
  holds "remove" "invalid name" (← refusal "remove" (vaultremove v ""))

-- ---------------------------------------------------------------- the keys

def arestrictedkeyreadsitsgrants : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] false)

  let ci ← openas v.file "ci" "ci-passphrase"
  same "granted" "tok01" (← valueof ci "api.token")

  -- THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and this
  -- key cannot derive its key, so the answer is the one a stranger gets: a
  -- miss.
  same "an ungranted name answered" "(miss)" (← valueof ci "db.pass")
  samelist "list" ["api.token"] (← vaultlist ci)

  let info ← vaultopen ci
  truth "a restricted key reports master" !info.master
  truth "a read-only key reports write" !info.write
  samelist "grants" ["api.token"] info.grants

def areadonlykeyrefusestowrite : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "reader" "reader-passphrase" ["api.token"] false)
  vaultgrant v (grantof "writer" "writer-passphrase" ["api.token"] true)

  let reader ← openas v.file "reader" "reader-passphrase"
  holds "read-only" "key reader is read-only"
    (← refusal "read-only" (vaultset reader "api.token" "x"))

  let writer ← openas v.file "writer" "writer-passphrase"
  vaultset writer "api.token" "rewritten"

  same "the master sees it" "rewritten" (← valueof v "api.token")

def arestrictedkeycannotwriteanungrantedname : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] true)

  let ci ← openas v.file "ci" "ci-passphrase"
  holds "ungranted" "key ci was not granted db.pass"
    (← refusal "ungranted" (vaultset ci "db.pass" "x"))

def agrantednamethatdoesnotexistyet : IO Unit := do
  let v ← fresh

  -- Granted BEFORE the name exists, which is the point: a deploy key is
  -- minted from a list of what a service will need.
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] false)

  let ci ← openas v.file "ci" "ci-passphrase"
  samelist "nothing yet" [] (← vaultlist ci)
  same "a name that does not exist answered" "(miss)" (← valueof ci "api.token")

  vaultset v "api.token" "tok01"

  same "once written" "tok01" (← valueof ci "api.token")
  samelist "list" ["api.token"] (← vaultlist ci)

def themasterlistseverykey : IO Unit := do
  let v ← fresh
  vaultgrant v (grantof "ci" "ci-passphrase" ["db.pass", "api.token"] true)

  let keys ← vaultkeys v
  same "key count" "2" (toString keys.length)

  let leading := keys[0]!
  same "the master" "master" leading.key
  truth "the master is not master" leading.master
  samelist "a master is granted nothing" [] leading.grants

  let second := keys[1]!
  same "the restricted key" "ci" second.key
  truth "ci reports master" !second.master
  truth "ci may not write" second.write
  -- SORTED, so the record reads the same however the grant was spelled.
  samelist "grants" ["api.token", "db.pass"] second.grants

def themasteronlymethodsrefusearestrictedkey : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] true)

  let ci ← openas v.file "ci" "ci-passphrase"

  holds "keys" "listing the keys needs a master key" (← refusal "keys" (vaultkeys ci))
  holds "grant" "granting a key needs a master key"
    (← refusal "grant" (vaultgrant ci (grantof "x" "y" [] false)))
  holds "revoke" "revoking a key needs a master key"
    (← refusal "revoke" (vaultrevoke ci "master"))
  holds "rotate" "rotating the vault needs a master key" (← refusal "rotate" (vaultrotate ci))
  holds "remove" "removing a secret needs a master key"
    (← refusal "remove" (vaultremove ci "api.token"))

def arepeatedkeyidisrefused : IO Unit := do
  let v ← fresh
  vaultgrant v (grantof "ci" "p" [] false)

  holds "repeated" "key already exists: ci"
    (← refusal "repeated" (vaultgrant v (grantof "ci" "q" [] false)))
  holds "no id" "a grant needs a key id"
    (← refusal "no id" (vaultgrant v (grantof "" "p" [] false)))
  holds "no passphrase" "a grant needs a passphrase"
    (← refusal "no passphrase" (vaultgrant v (grantof "x" "" [] false)))

def revokedropsakey : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] false)
  vaultrevoke v "ci"

  let ci ← openas v.file "ci" "ci-passphrase"
  holds "revoked" "no such key: ci" (← refusal "revoked" (vaultget ci "api.token"))
  holds "revoke again" "no such key: ci" (← refusal "revoke again" (vaultrevoke v "ci"))
  holds "itself" "a key cannot revoke itself" (← refusal "itself" (vaultrevoke v "master"))

  -- THE SECRET IS UNTOUCHED: revoking bars a key, not a value.
  same "the secret stays" "tok01" (← valueof v "api.token")

def rotatekeepsthesecrets : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] false)

  vaultrotate v

  same "api.token survives" "tok01" (← valueof v "api.token")
  same "db.pass survives" "hunter2" (← valueof v "db.pass")
  samelist "list" ["api.token", "db.pass"] (← vaultlist v)

  let keys ← vaultkeys v
  same "key count after rotate" "1" (toString keys.length)
  same "the only key" "master" keys[0]!.key

  -- EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
  -- rings were sealed under passphrases this process does not have.
  let ci ← openas v.file "ci" "ci-passphrase"
  holds "ci is gone" "no such key: ci" (← refusal "ci is gone" (vaultget ci "api.token"))

-- ------------------------------------------------------------ the refusals

def awrongpassphraseandamissingfile : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"

  let wrong ← openas v.file "" "not-the-passphrase"
  holds "wrong passphrase" "wrong passphrase for key master, or a damaged vault"
    (← refusal "wrong passphrase" (vaultget wrong "api.token"))

  let unknown ← openas v.file "nope" master
  holds "unknown key" "no such key: nope" (← refusal "unknown key" (vaultget unknown "api.token"))

  let missing ← openas ((← work.get) ++ "/not-there.skmv") "" master
  holds "missing file" "no vault file" (← refusal "missing file" (vaultget missing "api.token"))

def adamagedfileisrefused : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  let raw ← IO.FS.readBinFile v.file

  let refuses (what want : String) (made : ByteArray) : IO Unit := do
    let where' ← vaultpath
    IO.FS.writeBinFile where' made
    let held ← openas where' "" master
    holds what want (← refusal what (vaultget held "api.token"))

  -- Not a vault at all.
  refuses "not a vault" "not a vault file" "nonsense".toUTF8
  -- Cut off part way through.
  refuses "truncated" "truncated" (raw.extract 0 (raw.size - 20))
  -- One byte of ciphertext flipped, which the GCM tag catches.
  refuses "flipped" "damaged"
    ((raw.extract 0 (raw.size - 1)).push (raw[raw.size - 1]! ^^^ 0xff))
  -- Trailing bytes, which a reader that stopped at the last record would
  -- have accepted.
  refuses "trailing" "trailing bytes" (raw ++ "junk".toUTF8)

def creatingoveranexistingvaultisrefused : IO Unit := do
  let v ← fresh
  holds "create over" "vault file already exists"
    (← refusal "create over" (createvault (vaultopts v.file "" master)))

def avaultneedsafileandapassphrase : IO Unit := do
  holds "no file" "a vault needs a file"
    (← refusal "no file" (openvault (vaultopts "" "" "p")))
  holds "no passphrase" "a vault needs a passphrase"
    (← refusal "no passphrase" (openvault (vaultopts "v.skmv" "" "")))

/-- An EMPTY key is no key, so it means `master`. It is not a contrived
case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
expands to the empty string rather than to nothing at all. -/
def anemptykeymeansthemasterkey : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"

  let opened ← openas v.file "" master
  same "api.token" "tok01" (← valueof opened "api.token")
  same "key" "master" (← vaultopen opened).key

def createmakesthefileonlywhenasked : IO Unit := do
  let where' ← vaultpath

  let off ← openas where' "" master
  holds "create off" "no vault file" (← refusal "create off" (vaultget off "api.token"))

  let on ← openvault { vaultopts where' "" master with create := true }
  same "a new vault answered" "(miss)" (← valueof on "api.token")
  vaultset on "api.token" "tok01"
  same "written" "tok01" (← valueof on "api.token")

  -- The file is there now, so the handle that refused reads it.
  same "the same file" "tok01" (← valueof (← openas where' "" master) "api.token")

def akeyidlongerthantheformatallows : IO Unit := do
  let v ← fresh
  let big := String.ofList (List.replicate 300 'k')

  holds "grant" "key id is longer than 255 bytes"
    (← refusal "grant" (vaultgrant v (grantof big "p" [] false)))
  holds "open" "key id is longer than 255 bytes"
    (← refusal "open" (openvault (vaultopts v.file big "p")))

  -- AND THE VAULT IS UNHARMED: the refusal came before the write, so a
  -- 300-character id did not shift every field after it.
  same "key count" "1" (toString (← vaultkeys v).length)

def theinfoacallergetscannotchangewhatthekeymaydo : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "reader" "reader-passphrase" ["api.token"] false)

  let reader ← openas v.file "reader" "reader-passphrase"
  let info ← vaultopen reader
  truth "the reader key may write" !info.write

  -- NOTHING TO FLIP: a structure is a value here, so the defect the review
  -- round found in the canonical - a caller flipping its own `write` bit -
  -- does not compile. `with` makes a new value, and the vault reads its
  -- own.
  let copied := { info with write := true }
  truth "the copy did not take the change" copied.write

  holds "still refused" "key reader is read-only"
    (← refusal "still refused" (vaultset reader "api.token" "x"))

def arevokedkeystopsreading : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] false)

  -- OPEN AND READING FIRST, so the handle holds its derived keys.
  let ci ← openas v.file "ci" "ci-passphrase"
  same "before" "tok01" (← valueof ci "api.token")

  vaultrevoke v "ci"

  -- The live file no longer holds the key, and a handle that answered from
  -- memory here would make `revoke` a suggestion.
  holds "after" "no such key: ci" (← refusal "after" (vaultget ci "api.token"))

def aregrantedkeyid : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "first-passphrase" ["api.token"] false)

  let ci ← openas v.file "ci" "first-passphrase"
  same "before" "tok01" (← valueof ci "api.token")

  vaultrevoke v "ci"
  vaultgrant v (grantof "ci" "second-passphrase" ["api.token"] false)

  -- SAME ID, DIFFERENT KEY. The handle re-derives because the sealed ring
  -- changed, and the old passphrase does not unwrap the new one.
  holds "the old passphrase" "wrong passphrase for key ci, or a damaged vault"
    (← refusal "the old passphrase" (vaultget ci "api.token"))

  same "the new passphrase" "tok01"
    (← valueof (← openas v.file "ci" "second-passphrase") "api.token")

def closeforgetsthederivedkeys : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"
  same "before" "tok01" (← valueof v "api.token")

  vaultclose v

  same "after" "tok01" (← valueof v "api.token")

-- ------------------------------------------------------- the committed files

/-- Every port's vault holds the same keys and the same secrets, so the
assertions do not vary with which file this is. -/
def readsthefixture (name : String) : IO Unit := do
  let file ← fixture name
  let owner ← openas file "" "fixture-master"

  samelist "list" ["api.token", "db.pass", "deep.nested.name"] (← vaultlist owner)
  same "api.token" "fixture-token" (← valueof owner "api.token")
  same "db.pass" "fixture-pass" (← valueof owner "db.pass")
  same "deep.nested.name" "fixture-deep" (← valueof owner "deep.nested.name")

  samelist "keys" ["master", "reader", "writer"]
    (((← vaultkeys owner).map (·.key)).mergeSort (· ≤ ·))

  let reader ← openas file "reader" "fixture-reader"
  samelist "reader list" ["api.token"] (← vaultlist reader)
  same "reader reads" "fixture-token" (← valueof reader "api.token")
  same "the reader key read db.pass" "(miss)" (← valueof reader "db.pass")
  holds "reader writes" "read-only" (← refusal "reader writes" (vaultset reader "api.token" "x"))

  let writer ← openas file "writer" "fixture-writer"
  samelist "writer list" ["db.pass"] (← vaultlist writer)
  same "writer reads" "fixture-pass" (← valueof writer "db.pass")

  -- The copy is this case's own, so writing it proves the round trip
  -- without touching the committed bytes.
  vaultset writer "db.pass" "rewritten"
  same "the master sees it" "rewritten" (← valueof owner "db.pass")

-- --------------------------------------------------------------- the chain

def avaultisonestoreinachain : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "from the vault"

  let secrets ← thechain [vaultspec v.file "" master, memoryspec "DB_PASS" "from memory"]

  samelist "stores" ["minivault", "memory"] (← secrets.stores)
  samelist "sources" ["minivault:" ++ v.file, "memory"] (← secrets.sources)
  same "the vault" "from the vault" (← secrets.get "api.token")
  same "memory" "from memory" (← secrets.get "db.pass")

def arestrictedkeyinachainfallsthrough : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "from the vault"
  vaultset v "db.pass" "also in the vault"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] false)

  let secrets ← thechain
    [vaultspec v.file "ci" "ci-passphrase", memoryspec "DB_PASS" "from memory"]

  same "the grant" "from the vault" (← secrets.get "api.token")
  -- A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather than
  -- stopping at a store that holds the name but not for this key.
  same "falls through" "from memory" (← secrets.get "db.pass")

def thevaultbehindastoreisreachable : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"

  let secrets ← thechain [vaultspec v.file "" master]
  let api ← vaultof secrets

  samelist "list" ["api.token"] (← vaultlist api)

  -- A CHAIN READS; the API writes. Both see the same file.
  vaultset api "db.pass" "written through the api"
  same "the chain" "written through the api" (← secrets.get "db.pass")

def anamedstoreisreachedbyname : IO Unit := do
  let leading ← fresh
  vaultset leading "api.token" "first"
  let second ← fresh
  vaultset second "api.token" "second"

  let secrets ← thechain
    [{ vaultspec leading.file "" master with name := "app" },
     { vaultspec second.file "" master with name := "ops" }]

  samelist "stores" ["app", "ops"] (← secrets.stores)
  same "app" leading.file (← vaultof secrets "app").file
  same "ops" second.file (← vaultof secrets "ops").file

  -- A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in for
  -- it: picking one would be a guess, and the guess writes.
  holds "a store that is not there" "no minivault store named nope in this chain"
    (← refusal "a store that is not there" (vaultof secrets "nope"))

def achainwithnovaultsaysso : IO Unit := do
  let secrets ← thechain [memoryspec "API_TOKEN" "tok01"]
  holds "no vault" "no minivault store in this chain" (← refusal "no vault" (vaultof secrets))

def achainmissingthefileisrefused : IO Unit := do
  holds "no file" "a vault needs a file" (← refusal "no file" (thechain [vaultspec "" "" "p"]))
  holds "no passphrase" "a vault needs a passphrase"
    (← refusal "no passphrase" (thechain [vaultspec "v.skmv" "" ""]))

def thefileisreachedatthefirstlookup : IO Unit := do
  -- The file does not exist, and building the chain still succeeds: the
  -- handle is lazy, so a chain costs no PBKDF2 until a secret is actually
  -- wanted.
  let secrets ← thechain [vaultspec ((← work.get) ++ "/never.skmv") "" master]

  holds "at the first lookup" "no vault file"
    (← refusal "at the first lookup" (secrets.get "api.token"))

/-- A chain that is closed hands its vault back.

The definition's `close` drops the handle, as it does the provider's, so
a torn-down chain leaves the table where it found it - and `vaultof`
refuses rather than answering from a handle nothing holds. -/
def closehandsthevaultback : IO Unit := do
  let v ← fresh
  vaultset v "api.token" "tok01"

  let before ← heldvaults
  let secrets ← thechain [vaultspec v.file "" master]

  same "one vault while the chain is live" (toString (before + 1)) (toString (← heldvaults))

  secrets.close

  same "none after close" (toString before) (toString (← heldvaults))
  holds "vaultof after close" "no minivault store in this chain"
    (← refusal "vaultof after close" (vaultof secrets))

-- ----------------------------------------------------------------- the run

def main (args : List String) : IO UInt32 := do
  only.set (args.headD "")

  let here := "build/vaultwork"
  if ← System.FilePath.pathExists here then
    IO.FS.removeDirAll here
  IO.FS.createDirAll here
  work.set here

  testcase "newvault" anewvaultholdsnothing
  testcase "written" awrittensecretcomesback
  testcase "binary" thefileisbinary
  testcase "rewrite" rewritinganamereplacesit
  testcase "remove" removedropsaname
  testcase "badname" abadnameisrefused
  testcase "restricted" arestrictedkeyreadsitsgrants
  testcase "readonly" areadonlykeyrefusestowrite
  testcase "ungranted" arestrictedkeycannotwriteanungrantedname
  testcase "laternamed" agrantednamethatdoesnotexistyet
  testcase "keys" themasterlistseverykey
  testcase "masteronly" themasteronlymethodsrefusearestrictedkey
  testcase "repeatedid" arepeatedkeyidisrefused
  testcase "revoke" revokedropsakey
  testcase "rotate" rotatekeepsthesecrets
  testcase "wrongphrase" awrongpassphraseandamissingfile
  testcase "damaged" adamagedfileisrefused
  testcase "createover" creatingoveranexistingvaultisrefused
  testcase "needsfile" avaultneedsafileandapassphrase
  testcase "emptykey" anemptykeymeansthemasterkey
  testcase "createflag" createmakesthefileonlywhenasked
  testcase "longkeyid" akeyidlongerthantheformatallows
  testcase "infocopy" theinfoacallergetscannotchangewhatthekeymaydo
  testcase "revokedcached" arevokedkeystopsreading
  testcase "regranted" aregrantedkeyid
  testcase "close" closeforgetsthederivedkeys

  let files ← fixtures
  if files.isEmpty then
    failcount.modify (· + 1)
    IO.println "FAIL - fixtures\n       no committed vault was found"
  for name in files do
    testcase ("fixture:" ++ name) (readsthefixture name)

  testcase "chain" avaultisonestoreinachain
  testcase "chainfallthrough" arestrictedkeyinachainfallsthrough
  testcase "api" thevaultbehindastoreisreachable
  testcase "namedstore" anamedstoreisreachedbyname
  testcase "novault" achainwithnovaultsaysso
  testcase "badconfig" achainmissingthefileisrefused
  testcase "lazy" thefileisreachedatthefirstlookup
  testcase "closed" closehandsthevaultback

  IO.println ""
  IO.println (toString (← passcount.get) ++ " passed, " ++ toString (← failcount.get) ++ " failed")

  return (if 0 == (← failcount.get) then 0 else 1)
