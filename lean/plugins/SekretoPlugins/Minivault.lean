/-
A mini vault: every secret a project owns, encrypted, in ONE FILE.

The store to reach for before there is a vault server. There is nothing
to run and nothing to reach over a socket - the whole store is a single
binary file - and the same chain that reads it in development reads
HashiCorp or AWS in production by changing config, which is the reason
sekreto exists.

A PLUGIN, not a built-in: this kind needs crypto, which is the line the
four built-in kinds stay behind. Lean has no cryptography and the
no-new-package rule stands, so the four primitives come from the
libcrypto this port already links, through `ffi/sekreto_vault.c` - whose
header says why the dependency exception now reaches this far.

THE KEY DECIDES WHAT THE VAULT HOLDS. A master key reads and writes every
name and mints restricted keys. A restricted key reads the names it was
granted and CANNOT DERIVE ANY OTHER - the restriction is the cryptography
rather than a check this code performs, so a copy of the file plus a
restricted passphrase yields exactly what was granted and nothing else.
What that does and does not protect is set out in DOCS.md under "What the
mini vault protects".

THE FILE FORMAT, which is the contract between the ports:

    magic       4   'SKMV'
    version     1   format
    kdf         1   1 = PBKDF2-HMAC-SHA256
    cipher      1   1 = AES-256-GCM
    reserved    1   0
    keycount    4   uint32
    per key:
      id        1 + bytes      the key id, PLAINTEXT
      salt      1 + bytes
      iters     4              PBKDF2 rounds for this key
      ring      1 + iv, 4 + bytes    sealed under the passphrase
      meta      1 + iv, 4 + bytes    sealed under the vault's meta key
    entrycount  4   uint32
    per entry:
      id        1 + bytes      the blinded lookup id
      name      1 + iv, 4 + bytes    sealed under the vault's name key
      value     1 + iv, 4 + bytes    sealed under that secret's own key

Integers are big-endian and every length precedes its bytes, so the file
is written with the same two primitives it is read with.

NOTHING OUTSIDE A KEY RECORD IS PLAINTEXT. Secret names are sealed, and
an entry is addressed by a blinded id derived from its own key, so a
restricted key finds what it was granted without the file ever naming the
rest. What the file does show anyone is the key ids and how many secrets
there are.

A port of typescript/plugins/minivault.ts, which is canonical. The bytes
are pinned by the vaults in test/fixture rather than left to agreement
between implementations.
-/

import Std.Sync.Mutex

import Sekreto.Text
import Sekreto.Json
import Sekreto.Core
import Sekreto.Provider
import Sekreto.Chain

namespace Sekreto

-- ------------------------------------------------------- the primitives

/-- Fresh entropy from the platform's CSPRNG. Empty means the draw
failed, which is refused rather than papered over: a nonce repeated under
one AES-GCM key loses the confidentiality of both messages. -/
@[extern "sekreto_mv_random"]
opaque mvrandom (len : UInt32) : IO ByteArray

/-- HMAC-SHA256. Empty on failure, which a 32-byte mac never is. -/
@[extern "sekreto_mv_hmac"]
opaque mvhmac (key : @& ByteArray) (msg : @& ByteArray) : ByteArray

/-- PBKDF2-HMAC-SHA256. Empty on failure, including a round count below
one, which is what a damaged or hostile file records to make the
derivation free. -/
@[extern "sekreto_mv_pbkdf2"]
opaque mvpbkdf2 (pass : @& ByteArray) (salt : @& ByteArray) (iters : UInt32) : ByteArray

/-- AES-256-GCM, sealing: ciphertext followed by the 16-byte tag. Empty
on refusal, which a sealed blob never is - it always carries the tag. -/
@[extern "sekreto_mv_seal"]
opaque mvseal (key : @& ByteArray) (iv : @& ByteArray) (plain : @& ByteArray)
    (aad : @& ByteArray) : ByteArray

/-- AES-256-GCM, opening. Empty for a tag that fails to verify, and also
for a ciphertext that was empty to begin with: the caller tells the two
apart by the blob's own length, which it has. -/
@[extern "sekreto_mv_unseal"]
opaque mvunseal (key : @& ByteArray) (iv : @& ByteArray) (blob : @& ByteArray)
    (aad : @& ByteArray) : ByteArray

-- ---------------------------------------------------------- the format

private def MAGIC : ByteArray := "SKMV".toUTF8
private def FORMAT : Nat := 1
private def KDF_PBKDF2 : Nat := 1
private def CIPHER_AESGCM : Nat := 1

/-- AES-256-GCM: 32-byte keys, 12-byte nonces, 16-byte tags. -/
private def KEYLEN : Nat := 32
private def IVLEN : Nat := 12
private def TAGLEN : Nat := 16
private def SALTLEN : Nat := 16

/-- The PBKDF2-HMAC-SHA256 round count when a caller names none. -/
def VAULT_ITERATIONS : Nat := 210000

/-- The key id a vault gets when a caller names none. -/
def VAULT_MASTERKEY : String := "master"

/-- The export key the vault API is published under, beside the
`provider` key every kind publishes. -/
def VAULT_EXPORT : String := "vault"

/- Additional authenticated data. Every blob is bound to its PLACE in the
file, so no ciphertext can be moved: a restricted key's ring cannot be
relabelled as the master's, and one secret's value cannot be served under
a name it was never written for. -/
private def AAD_RING : String := "skmv1:ring:"
private def AAD_META : String := "skmv1:meta:"
private def AAD_NAME : String := "skmv1:name"
private def AAD_SECRET : String := "skmv1:secret:"

/- Everything a master reaches is derived from the root key, so rotating
is one new random value rather than a re-wrap of each part. -/
private def LABEL_NAMES : String := "skmv1:names"
private def LABEL_META : String := "skmv1:meta"
private def LABEL_ID : String := "skmv1:id"

/-- The largest key id the format can record.

A length is written in ONE byte. A longer id wrapped that byte and the
writer then appended the whole thing, so every field after it shifted: a
grant with a 300-character id replaced a working vault with an unreadable
one, and said nothing. Checked where an id is ACCEPTED, so the refusal
names the id rather than the file. -/
private def IDMAX : Nat := 255

private def mvfail {α : Type} (why : String) : IO α :=
  fail ("sekreto: minivault: " ++ why)

private def checkid (held what : String) : IO String := do
  if held.isEmpty then mvfail what
  if IDMAX < held.utf8ByteSize then
    mvfail ("key id is longer than " ++ toString IDMAX ++ " bytes: " ++
      held.take 32 ++ "...")
  return held

-- -------------------------------------------------------------- bytes

private def bytesof (text : String) : ByteArray := text.toUTF8

/-- The bytes as text. Every plaintext this is used on is a secret name
or a secret value, and both are text by the library's own rules. -/
private def textof (raw : ByteArray) : String := (String.fromUTF8? raw).getD ""

private def samebytes (left right : ByteArray) : Bool :=
  left.size == right.size && Id.run do
    let mut same := true
    for spot in [0 : left.size] do
      if left[spot]! != right[spot]! then same := false
    return same

private def lebytes (left right : ByteArray) : Bool := Id.run do
  let shorter := min left.size right.size
  for spot in [0 : shorter] do
    if left[spot]! < right[spot]! then return true
    if left[spot]! > right[spot]! then return false
  return left.size ≤ right.size

-- --------------------------------------------------------------- keys

private def mac (key : ByteArray) (text : String) : IO ByteArray := do
  let out := mvhmac key (bytesof text)
  if out.isEmpty then mvfail "cannot compute a mac"
  return out

/-- The key-encryption key a passphrase unwraps a ring with. -/
private def kek (passphrase : String) (salt : ByteArray) (iters : Nat) : IO ByteArray := do
  let out := mvpbkdf2 (bytesof passphrase) salt (UInt32.ofNat iters)
  if out.isEmpty then mvfail ("unusable round count: " ++ toString iters)
  return out

/-- The key one named secret's value is encrypted with.

DERIVED, never stored, for a master: it holds the root key and so reaches
every name, including ones written after it was made. A restricted key
holds the derived keys it was granted and nothing that produces another,
so every other name is ciphertext to it in exactly the way it is to a
stranger. -/
private def secretkey (root : ByteArray) (name : String) : IO ByteArray :=
  mac root (AAD_SECRET ++ name)

/-- Where a secret lives in the file, derived from its own key so that
finding it needs no plaintext name. One-way: an id yields nothing about
the key that produced it. -/
private def entryid (key : ByteArray) : IO ByteArray := mac key LABEL_ID

private def randombytes (len : Nat) : IO ByteArray := do
  let out ← mvrandom (UInt32.ofNat len)
  if out.size != len then mvfail "no randomness available"
  return out

-- ------------------------------------------------------------- sealing

structure Sealed where
  iv : ByteArray
  blob : ByteArray
  deriving Inhabited

private def sameseal (left right : Sealed) : Bool :=
  samebytes left.iv right.iv && samebytes left.blob right.blob

/-- The tag rides at the END of the blob, which is where every other
port's AEAD leaves it and therefore what the format records. -/
private def sealbox (key : ByteArray) (plain : ByteArray) (aad : String) : IO Sealed := do
  if KEYLEN != key.size then mvfail "bad key"
  let iv ← randombytes IVLEN
  let blob := mvseal key iv plain (bytesof aad)
  if blob.size != plain.size + TAGLEN then mvfail "cannot seal"
  return { iv := iv, blob := blob }

/-- The plaintext, or a refusal. A GCM tag that fails to verify is the
only evidence there is, and it cannot tell a wrong passphrase from a
damaged file, so `what` names the attempt and the message admits both. -/
private def unsealbox (key : ByteArray) (box : Sealed) (aad what : String) : IO ByteArray := do
  if box.blob.size < TAGLEN || IVLEN != box.iv.size then mvfail (what ++ ": truncated")
  if KEYLEN != key.size then mvfail "bad key"

  let out := mvunseal key box.iv box.blob (bytesof aad)

  -- An empty answer is a refusal UNLESS the ciphertext was empty too,
  -- which is the one case where nothing is a legitimate plaintext.
  if out.isEmpty && box.blob.size != TAGLEN then mvfail what

  return out

-- -------------------------------------------------------------- base64

/- Here rather than `Httpjson.unbase64`: importing that module would link
the libcurl binding into a program whose only store opens nothing, which
is the cost the core/plugin split exists to remove. -/
private def B64 : String := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

private def B64CHARS : List Char := B64.toList

private def b64char (value : Nat) : Char := B64CHARS[value]!

private def b64 (raw : ByteArray) : String := Id.run do
  let mut out := ""
  let mut spot := 0

  while spot < raw.size do
    let left := raw.size - spot
    let a := raw[spot]!.toNat
    let b := if 1 < left then raw[spot + 1]!.toNat else 0
    let c := if 2 < left then raw[spot + 2]!.toNat else 0
    let triple := a * 65536 + b * 256 + c

    out := out.push (b64char (triple / 262144 % 64))
    out := out.push (b64char (triple / 4096 % 64))
    out := out.push (if 1 < left then b64char (triple / 64 % 64) else '=')
    out := out.push (if 2 < left then b64char (triple % 64) else '=')

    spot := spot + 3

  return out

private def b64value (ch : Char) : Option Nat := B64CHARS.findIdx? (· == ch)

/-- STRICT. A lenient decoder hands back plausible bytes for a corrupted
payload, and those bytes are then used AS A KEY. -/
private def unb64 (text what : String) : IO ByteArray := do
  let missing : IO ByteArray := mvfail ("missing " ++ what)

  let chars := text.toList

  if chars.isEmpty || 0 != chars.length % 4 then missing else

  let body := chars.takeWhile (· != '=')
  let pad := chars.drop body.length

  if 2 < pad.length || !pad.all (· == '=') then missing else

  let mut out := ByteArray.empty
  let mut held := 0
  let mut bits := 0
  let mut ok := true

  for ch in body do
    match b64value ch with
    | none => ok := false
    | some value =>
      held := held * 64 + value
      bits := bits + 6
      if 8 ≤ bits then
        bits := bits - 8
        out := out.push (UInt8.ofNat (held / (2 ^ bits) % 256))

  if !ok then missing else return out

-- ------------------------------------------------------------ the file

structure KeyRecord where
  id : String
  salt : ByteArray
  iters : Nat
  ring : Sealed
  noted : Sealed
  deriving Inhabited

structure EntryRecord where
  id : ByteArray
  name : Sealed
  value : Sealed
  deriving Inhabited

structure VaultFile where
  keys : List KeyRecord := []
  entries : List EntryRecord := []
  deriving Inhabited

private def keyrecordof (file : VaultFile) (held : String) : Option KeyRecord :=
  file.keys.find? (·.id == held)

private def entryrecordof (file : VaultFile) (held : ByteArray) : Option EntryRecord :=
  file.entries.find? (samebytes held ·.id)

/-- A cursor, so that every length check is in one place: a truncated
vault is refused rather than read as a short one. -/
structure Cursor where
  raw : ByteArray
  spot : Nat := 0

/-- Reads `len` bytes, or refuses.

The bound is checked AGAINST WHAT IS LEFT, never by adding the length to
the cursor. Lean's `Nat` cannot wrap, so this is the one port where that
could not go wrong - the check reads the same in every port and is the
one that is right everywhere. -/
private def Cursor.take (cur : Cursor) (len : Nat) : IO (ByteArray × Cursor) := do
  if cur.raw.size - cur.spot < len then mvfail "the vault file is truncated"
  return (cur.raw.extract cur.spot (cur.spot + len), { cur with spot := cur.spot + len })

private def Cursor.u8 (cur : Cursor) : IO (Nat × Cursor) := do
  let (raw, next) ← cur.take 1
  return (raw[0]!.toNat, next)

private def Cursor.u32 (cur : Cursor) : IO (Nat × Cursor) := do
  let (raw, next) ← cur.take 4
  return (raw[0]!.toNat * 16777216 + raw[1]!.toNat * 65536 + raw[2]!.toNat * 256 +
    raw[3]!.toNat, next)

private def Cursor.small (cur : Cursor) : IO (ByteArray × Cursor) := do
  let (len, next) ← cur.u8
  next.take len

private def Cursor.large (cur : Cursor) : IO (ByteArray × Cursor) := do
  let (len, next) ← cur.u32
  next.take len

private def Cursor.sealed (cur : Cursor) : IO (Sealed × Cursor) := do
  let (iv, after) ← cur.small
  let (blob, next) ← after.large
  return ({ iv := iv, blob := blob }, next)

private partial def readkeys (cur : Cursor) (count : Nat)
    : IO (List KeyRecord × Cursor) := do
  if 0 == count then return ([], cur)
  let (held, c1) ← cur.small
  let (salt, c2) ← c1.small
  let (iters, c3) ← c2.u32
  let (ring, c4) ← c3.sealed
  let (noted, c5) ← c4.sealed
  let (rest, next) ← readkeys c5 (count - 1)
  return ({ id := textof held, salt := salt, iters := iters, ring := ring,
            noted := noted } :: rest, next)

private partial def readentries (cur : Cursor) (count : Nat)
    : IO (List EntryRecord × Cursor) := do
  if 0 == count then return ([], cur)
  let (held, c1) ← cur.small
  let (name, c2) ← c1.sealed
  let (value, c3) ← c2.sealed
  let (rest, next) ← readentries c3 (count - 1)
  return ({ id := held, name := name, value := value } :: rest, next)

def readfile (raw : ByteArray) : IO VaultFile := do
  let (found, c1) ← Cursor.take { raw := raw } 4
  if !samebytes MAGIC found then mvfail "not a vault file"

  let (version, c2) ← c1.u8
  if FORMAT != version then mvfail ("unsupported format version: " ++ toString version)

  let (kdf, c3) ← c2.u8
  let (cipher, c4) ← c3.u8
  if KDF_PBKDF2 != kdf || CIPHER_AESGCM != cipher then
    mvfail ("unsupported kdf or cipher: " ++ toString kdf ++ "/" ++ toString cipher)
  let (_, c5) ← c4.u8

  -- A COUNT IS BOUNDED BY WHAT IS LEFT. Each record carries at least a
  -- few bytes, so a file claiming four billion of them is damaged; the
  -- loop would find that out one truncation at a time.
  let (keycount, c6) ← c5.u32
  if raw.size - c6.spot < keycount then mvfail "the vault file is truncated"
  let (keys, c7) ← readkeys c6 keycount

  let (entrycount, c8) ← c7.u32
  if raw.size - c8.spot < entrycount then mvfail "the vault file is truncated"
  let (entries, c9) ← readentries c8 entrycount

  if c9.spot != raw.size then mvfail "the vault file has trailing bytes"

  return { keys := keys, entries := entries }

private def putu32 (value : Nat) : ByteArray :=
  ByteArray.empty
    |>.push (UInt8.ofNat (value / 16777216 % 256))
    |>.push (UInt8.ofNat (value / 65536 % 256))
    |>.push (UInt8.ofNat (value / 256 % 256))
    |>.push (UInt8.ofNat (value % 256))

private def putsmall (value : ByteArray) : ByteArray :=
  (ByteArray.empty.push (UInt8.ofNat (value.size % 256))).append value

private def putlarge (value : ByteArray) : ByteArray := (putu32 value.size).append value

private def putsealed (box : Sealed) : ByteArray :=
  (putsmall box.iv).append (putlarge box.blob)

def writefile (file : VaultFile) : ByteArray := Id.run do
  let mut out := MAGIC
  out := out.push (UInt8.ofNat FORMAT)
  out := out.push (UInt8.ofNat KDF_PBKDF2)
  out := out.push (UInt8.ofNat CIPHER_AESGCM)
  out := out.push 0

  out := out.append (putu32 file.keys.length)
  for record in file.keys do
    out := out.append (putsmall (bytesof record.id))
    out := out.append (putsmall record.salt)
    out := out.append (putu32 record.iters)
    out := out.append (putsealed record.ring)
    out := out.append (putsealed record.noted)

  -- SORTED BY ID, which is a blinded value: the file therefore records
  -- nothing about the order secrets were written in.
  let entries := file.entries.mergeSort (fun left right => lebytes left.id right.id)

  out := out.append (putu32 entries.length)
  for record in entries do
    out := out.append (putsmall record.id)
    out := out.append (putsealed record.name)
    out := out.append (putsealed record.value)

  return out

-- --------------------------------------------------- the file on disk

/-- Owner-only is NOT what this port can ask for, and neither is an
exclusive create: `IO.FS.writeBinFile` has neither a mode nor an
`O_EXCL`, and Lean offers no other way to make a file. So the two
guarantees the C and Go ports get from `O_EXCL | 0600` are arranged
differently here - `putnew` looks first and refuses a file that is there,
a check-then-write that two processes could both pass, and the file is
created under the umask a service normally runs with. A deployment that
needs 0600 on a shared host sets its umask, and the port says so rather
than implying a protection it cannot give. -/
private def spill (path : String) (raw : ByteArray) : IO Unit := do
  tryCatch (IO.FS.writeBinFile path raw)
    (fun _ => mvfail ("cannot write " ++ path))

private def hex (raw : ByteArray) : String := hexlower raw

-- ------------------------------------------------------------ the vault

/-- What a key may do. `grants` is empty for a master key, which reads
and writes every name there is.

A STRUCTURE OF IMMUTABLE FIELDS, so the defect the review round found in
the canonical - a caller flipping its own `write` bit on the record it
was handed - cannot be written at all. `{ info with write := true }`
makes a new value and changes nothing the vault reads. -/
structure VaultKeyInfo where
  key : String
  master : Bool := false
  write : Bool := false
  grants : List String := []
  deriving Inhabited

/-- How a vault file is opened as one key. -/
structure VaultOptions where
  /-- The vault file. -/
  file : String := ""
  /-- Which key to open with. Empty means `master`. -/
  key : String := ""
  /-- What unwraps that key. -/
  passphrase : String := ""
  /-- The PBKDF2 round count used when this handle CREATES a key. Reading
  uses what the file records for the key being opened. -/
  iterations : Nat := 0
  /-- Make the file, with this key as its master, if it is not there.

  Off by default. A missing vault is far more often a broken deployment
  than a new one, and a store that invents itself where a real vault was
  meant to be answers every read with a miss. -/
  create : Bool := false
  deriving Inhabited

/-- What mints a restricted key. -/
structure GrantSpec where
  /-- The id the new key answers to. -/
  key : String := ""
  /-- What unwraps it. Nothing else does, and no master can recover it -
  a lost restricted passphrase is re-granted, never read back. -/
  passphrase : String := ""
  /-- The names the key may read. A name that does not exist yet is
  allowed and means what it says: the key reads it once a master writes
  it. -/
  names : List String := []
  /-- Whether it may overwrite the values it can read. -/
  write : Bool := false
  /-- PBKDF2 rounds for this key, defaulting to the opening handle's. -/
  iterations : Nat := 0
  deriving Inhabited

/-- What a handle remembers between calls: this key's ring, unwrapped. -/
structure Opened where
  root : Option ByteArray
  grants : List (String × ByteArray)
  write : Bool
  /-- THE SEALED RING THIS WAS DERIVED FROM, kept so that every later call
  can check the file still says the same thing. A handle that cached its
  keys and never looked again kept reading a vault after its key was
  revoked, which is the one thing `vaultrevoke` promises. -/
  ring : Sealed
  deriving Inhabited

/-- A handle on one vault file, opened as ONE key.

Every call answers as that key: `vaultlist` shows the names it may read,
`vaultget` answers for those and misses on the rest, and the master-only
ones refuse for any other key. Nothing is read or derived until the first
call that needs the file, so putting a vault in a chain costs no key
derivation until a secret is actually wanted. -/
structure Vault where
  file : String
  key : String
  passphrase : String
  iterations : Nat
  create : Bool
  opened : IO.Ref (Option Opened)

/-- Forget the derived keys. The next call opens again. -/
def vaultclose (v : Vault) : IO Unit := v.opened.set none

/- A MASTER'S ring holds the root and no grants; a RESTRICTED key's holds
grants and no root, even when it was granted nothing. That asymmetry is
the format rather than a saving: a ring with a root reaches every name
there will ever be, so a grant list beside it would be a second answer to
the same question. -/
private def masterring (root : ByteArray) : String :=
  Json.stringify (.obj [("v", .num (Float.ofNat FORMAT)), ("write", .bool true),
    ("root", .str (b64 root))])

private def grantring (write : Bool) (grants : List (String × ByteArray)) : String :=
  Json.stringify (.obj [("v", .num (Float.ofNat FORMAT)), ("write", .bool write),
    ("grants", .obj (grants.map (fun pair => (pair.1, Json.str (b64 pair.2)))))])

private def metaof (master write : Bool) (names : List String) : String :=
  Json.stringify (.obj [("v", .num (Float.ofNat FORMAT)), ("master", .bool master),
    ("write", .bool write), ("grants", .arr (names.map Json.str))])

private def sealkey (root : ByteArray) (held passphrase : String) (iters : Nat)
    (ring noted : String) : IO KeyRecord := do
  let salt ← randombytes SALTLEN
  let wrapping ← kek passphrase salt iters
  let sealedring ← sealbox wrapping (bytesof ring) (AAD_RING ++ held)
  let metakey ← mac root LABEL_META
  let sealedmeta ← sealbox metakey (bytesof noted) (AAD_META ++ held)
  return { id := held, salt := salt, iters := iters, ring := sealedring,
           noted := sealedmeta }

/-- The one key record a new or rotated vault starts with: a master
holding the root, granted nothing because it needs nothing. -/
private def masterrecord (root : ByteArray) (held passphrase : String) (iters : Nat)
    : IO KeyRecord :=
  sealkey root held passphrase iters (masterring root) (metaof true true [])

private def newvault (held passphrase : String) (iters : Nat) : IO VaultFile := do
  let root ← randombytes KEYLEN
  let record ← masterrecord root held passphrase iters
  return { keys := [record], entries := [] }

/-- Writes a vault file that is not there yet, and REFUSES one that is.

A LOOK AND THEN A WRITE, which is two steps: see `spill` for why this
port cannot make it one. Two processes racing to create the same vault
can therefore both pass the look, and the second overwrites the first;
the C and Go ports refuse that in one syscall. -/
private def putnew (path : String) (made : VaultFile) : IO Unit := do
  match ← readmaybe path with
  | some _ => mvfail ("vault file already exists: " ++ path)
  | none => spill path (writefile made)

/-- Replaces the file rather than editing it in place. The rename is what
makes a concurrent reader see either the old file or the new one, so a
write interrupted halfway leaves a vault rather than wreckage.

THE TEMPORARY IS RANDOM, though it cannot be exclusive here: see `spill`.
`<vault>.<pid>.tmp` is a name anyone can predict, and the random suffix
is what stops that and what stops two writers colliding. -/
private def save (v : Vault) (made : VaultFile) : IO Unit := do
  let suffix ← randombytes 8
  let temp := v.file ++ "." ++ hex suffix ++ ".tmp"

  spill temp (writefile made)

  tryCatch (IO.FS.rename temp v.file)
    (fun _ => do
      -- The vault is unchanged either way, and the write error is what
      -- the caller needs to be told about.
      tryCatch (IO.FS.removeFile temp) (fun _ => pure ())
      mvfail ("cannot write " ++ v.file))

private def bytesofvault (v : Vault) : IO ByteArray := do
  match ← readmaybe v.file with
  | some raw => return raw
  | none =>
    -- A vault is configured deliberately, with a key. Its absence is a
    -- broken deployment and never "no secrets here": answering a miss
    -- would send the chain on to a weaker store, which is the failure
    -- mode this library most has to avoid. `create` is the caller saying
    -- the opposite, in writing.
    if !v.create then mvfail ("no vault file: " ++ v.file)
    putnew v.file (← newvault v.key v.passphrase v.iterations)
    match ← readmaybe v.file with
    | some raw => return raw
    | none => mvfail ("cannot read " ++ v.file)

private def jsontrue (held : Json) (key : String) : Bool :=
  match held.get? key with
  | some (.bool value) => value
  | _ => false

/-- The file as this key sees it: parsed every call - it is different
bytes every time - while the unwrapped ring is kept, because stretching a
passphrase once per lookup is the cost that caching exists to avoid. -/
private def load (v : Vault) : IO (VaultFile × Opened) := do
  let file ← readfile (← bytesofvault v)

  match keyrecordof file v.key with
  | none =>
    -- REVOKED, or never there. Either way this handle is finished, and
    -- dropping what it derived is what stops the next call answering from
    -- memory.
    vaultclose v
    mvfail ("no such key: " ++ v.key)
  | some record =>
    -- The file still holds this key, and holds the SAME ring: a key
    -- revoked and re-granted under another passphrase is a different key
    -- wearing the id, and re-deriving is what refuses it.
    match ← v.opened.get with
    | some held =>
      if sameseal held.ring record.ring then return (file, held)
      vaultclose v
      let made ← derive v record
      return (file, made)
    | none =>
      let made ← derive v record
      return (file, made)
where
  derive (v : Vault) (record : KeyRecord) : IO Opened := do
    let wrapping ← kek v.passphrase record.salt record.iters
    let plain ← unsealbox wrapping record.ring (AAD_RING ++ v.key)
      ("wrong passphrase for key " ++ v.key ++ ", or a damaged vault")

    let ring ← match Json.parse (textof plain) with
      | some held@(.obj _) => pure held
      | _ => mvfail ("unreadable key ring for " ++ v.key)

    let mut grants : List (String × ByteArray) := []
    match ring.get? "grants" with
    | some (.obj entries) =>
      for entry in entries do
        match entry.2 with
        | .str text => grants := grants ++ [(entry.1, ← unb64 text "a granted key")]
        | _ => mvfail "missing a granted key"
    | _ => pure ()

    let root ← match ring.get? "root" with
      | some (.str text) => pure (some (← unb64 text "the root key"))
      | _ => pure none

    let made : Opened :=
      { root := root, grants := grants,
        write := root.isSome || jsontrue ring "write", ring := record.ring }

    v.opened.set (some made)

    return made

/-- The root key, or a refusal naming what needed it. -/
private def rootof (v : Vault) (open' : Opened) (what : String) : IO ByteArray :=
  match open'.root with
  | some root => pure root
  | none => mvfail (what ++ " needs a master key, and " ++ v.key ++ " is restricted")

/-- The key for one name, or nothing when this key cannot reach it. -/
private def keyfor (open' : Opened) (name : String) : IO (Option ByteArray) :=
  match open'.root with
  | some root => do return some (← secretkey root name)
  | none => pure (Pairs.find? open'.grants name)

/-- Derive the key and read the file NOW rather than at first use. -/
def vaultopen (v : Vault) : IO VaultKeyInfo := do
  let (_, open') ← load v
  return { key := v.key, master := open'.root.isSome, write := open'.write,
           grants := (open'.grants.map Prod.fst).mergeSort (· ≤ ·) }

/-- The names this key can read, sorted. -/
def vaultlist (v : Vault) : IO (List String) := do
  let (file, open') ← load v

  let names ← match open'.root with
    | some root => do
      let namekey ← mac root LABEL_NAMES
      let mut held : List String := []
      for entry in file.entries do
        held := held ++ [textof (← unsealbox namekey entry.name AAD_NAME
          "a secret name is damaged")]
      pure held
    | none => do
      -- A restricted key has no name key, so it reports the grants it can
      -- actually find: the vault never tells it what else is there.
      let mut held : List String := []
      for grant in open'.grants do
        if (entryrecordof file (← entryid grant.2)).isSome then held := held ++ [grant.1]
      pure held

  return names.mergeSort (· ≤ ·)

/-- The value, or a MISS. A name the vault does not hold and a name this
key was not granted are both a miss. -/
def vaultget (v : Vault) (name : String) : IO (Option String) := do
  let _ ← ofResult (checkname name)
  let (file, open') ← load v

  -- OUTSIDE THE GRANT IS A MISS, deliberately. The vault answers as the
  -- key that opened it, so a name this key cannot read is a name this
  -- store does not hold for this caller - the same answer a stranger's
  -- vault gives, and the one that makes a restricted key in front of a
  -- broader store a workable chain.
  match ← keyfor open' name with
  | none => return none
  | some key =>
    match entryrecordof file (← entryid key) with
    | none => return none
    | some entry =>
      return some (textof (← unsealbox key entry.value (AAD_SECRET ++ name)
        ("the value of " ++ name ++ " is damaged")))

def vaulthas (v : Vault) (name : String) : IO Bool := do
  return (← vaultget v name).isSome

/-- The lock every handle on one file shares.

Each `Vault` is its own value, so two handles on one path did not
coordinate: both could finish `load` before either saved, and the second
rename then discarded the first one's change while reporting success.
Keyed by the path made absolute, so two handles spelled differently still
meet.

A guarantee WITHIN one process, which is what DOCS.md promises and what
the go port arranges the same way. Two processes still race, and the
format's answer to that is the exclusive create and the atomic rename: a
reader sees one whole vault or the other, never half of one. -/
initialize vaultlocks : IO.Ref (List (String × Std.BaseMutex)) ← IO.mkRef []

private def lockfor (file : String) : IO Std.BaseMutex := do
  let key ← tryCatch (do return (← IO.FS.realPath file).toString)
    (fun _ => pure file)

  match (← vaultlocks.get).find? (·.1 == key) with
  | some pair => return pair.2
  | none =>
    let one ← Std.BaseMutex.new
    -- The table is read and written under no lock of its own, so two
    -- threads racing to register the SAME path could each make a mutex
    -- and only one survive. `modifyGet` is one atomic step on the ref, so
    -- the loser takes the winner's rather than its own.
    vaultlocks.modifyGet (fun held =>
      match held.find? (·.1 == key) with
      | some pair => (pair.2, held)
      | none => (one, (key, one) :: held))

/-- Run a mutation with that lock held.

`BaseMutex` is NOT re-entrant, so the five mutating calls must not reach
one another while it is held - and none of them does: `vaultrotate` reads
through `vaultlist` and `vaultget`, and every one of them writes through
`save`, which takes no lock of its own. -/
private def locked {α : Type} (v : Vault) (body : IO α) : IO α := do
  let one ← lockfor v.file
  one.lock
  let out ← tryCatch (do return Except.ok (← body))
    (fun err => return Except.error err)
  one.unlock
  match out with
  | .ok value => return value
  | .error err => throw err

/-- Write a value. A master writes any name; a restricted key holding
`write` overwrites the names it was granted, and creates none. -/
def vaultset (v : Vault) (name value : String) : IO Unit := locked v do
  let _ ← ofResult (checkname name)
  let (file, open') ← load v

  if !open'.write then mvfail ("key " ++ v.key ++ " is read-only")

  match ← keyfor open' name with
  | none => mvfail ("key " ++ v.key ++ " was not granted " ++ name)
  | some key =>
    let box ← sealbox key (bytesof value) (AAD_SECRET ++ name)
    let held ← entryid key

    let entries ← match entryrecordof file held with
      | some _ =>
        pure (file.entries.map (fun entry =>
          if samebytes held entry.id then { entry with value := box } else entry))
      | none => do
        -- A NEW NAME NEEDS THE NAME KEY, which only a master holds. So a
        -- restricted key with `write` updates what it was granted and
        -- cannot grow the vault, which is what "restricted" has to mean
        -- for the grant list to stay the whole story.
        let root ← rootof v open' ("creating the secret " ++ name)
        let namekey ← mac root LABEL_NAMES
        let sealedname ← sealbox namekey (bytesof name) AAD_NAME
        pure (file.entries ++ [{ id := held, name := sealedname, value := box }])

    save v { file with entries := entries }

/-- Drop a name. Master only. -/
def vaultremove (v : Vault) (name : String) : IO Unit := locked v do
  let _ ← ofResult (checkname name)
  let (file, open') ← load v
  let root ← rootof v open' "removing a secret"
  let want ← entryid (← secretkey root name)

  match entryrecordof file want with
  | none => mvfail ("no such secret: " ++ name)
  | some _ =>
    save v { file with entries := file.entries.filter (!samebytes want ·.id) }

/-- Every key in the file, with what it may do. Master only. -/
def vaultkeys (v : Vault) : IO (List VaultKeyInfo) := do
  let (file, open') ← load v
  let metakey ← mac (← rootof v open' "listing the keys") LABEL_META

  let mut out : List VaultKeyInfo := []

  for record in file.keys do
    -- A record written under a root key this one has replaced is still in
    -- the file and still opens with its own passphrase, so it is reported
    -- rather than hidden - with what it can do unknown.
    let got ← tryCatch
      (do return some (← unsealbox metakey record.noted (AAD_META ++ record.id) "metadata"))
      (fun _ => pure none)

    match got with
    | none => out := out ++ [{ key := record.id }]
    | some plain =>
      match Json.parse (textof plain) with
      | some noted@(.obj _) =>
        let names := match noted.get? "grants" with
          | some (.arr items) => items.filterMap Json.asstr
          | _ => []
        out := out ++ [{ key := record.id, master := jsontrue noted "master",
                         write := jsontrue noted "write",
                         grants := names.mergeSort (· ≤ ·) }]
      | _ => mvfail ("unreadable metadata for key " ++ record.id)

  return out

/-- Mint a restricted key. Master only. -/
def vaultgrant (v : Vault) (spec : GrantSpec) : IO Unit := locked v do
  let (file, open') ← load v
  let root ← rootof v open' "granting a key"

  let _ ← checkid spec.key "a grant needs a key id"
  if spec.passphrase.isEmpty then mvfail "a grant needs a passphrase"
  if (keyrecordof file spec.key).isSome then
    mvfail ("key already exists: " ++ spec.key)

  let names := spec.names.mergeSort (· ≤ ·)

  let mut grants : List (String × ByteArray) := []
  for held in names do
    let _ ← ofResult (checkname held)
    grants := grants ++ [(held, ← secretkey root held)]

  let record ← sealkey root spec.key spec.passphrase
    (if 0 < spec.iterations then spec.iterations else v.iterations)
    (grantring spec.write grants)
    (metaof false spec.write names)

  save v { file with keys := file.keys ++ [record] }

/-- Drop a key. Master only.

Anyone who already copied the file keeps whatever that key could read, so
revoking bars future reads of the LIVE file and `vaultrotate` is what
takes a secret back. -/
def vaultrevoke (v : Vault) (held : String) : IO Unit := locked v do
  let (file, open') ← load v
  let _ ← rootof v open' "revoking a key"

  if held == v.key then mvfail ("a key cannot revoke itself: " ++ held)
  if (keyrecordof file held).isNone then mvfail ("no such key: " ++ held)

  save v { file with keys := file.keys.filter (·.id != held) }

/-- Take a new root key, re-encrypt every value under it, and DROP EVERY
OTHER KEY. Master only.

The other keys go because they must: their rings are sealed under
passphrases this process does not have, so there is no way to hand them
keys they can unwrap. Re-grant afterwards. -/
def vaultrotate (v : Vault) : IO Unit := locked v do
  let (file, open') ← load v
  let oldroot ← rootof v open' "rotating the vault"
  let iters := match keyrecordof file v.key with
    | some record => record.iters
    | none => v.iterations

  -- Read everything out under the old root before anything changes: once
  -- the root is replaced the old derived keys are unreachable.
  let oldnamekey ← mac oldroot LABEL_NAMES
  let mut held : List (String × String) := []

  for entry in file.entries do
    let name := textof (← unsealbox oldnamekey entry.name AAD_NAME "a secret name is damaged")
    let key ← secretkey oldroot name
    let value ← unsealbox key entry.value (AAD_SECRET ++ name)
      ("the value of " ++ name ++ " is damaged")
    held := held ++ [(name, textof value)]

  let root ← randombytes KEYLEN
  let namekey ← mac root LABEL_NAMES
  let mut entries : List EntryRecord := []

  for pair in held do
    let key ← secretkey root pair.1
    entries := entries ++ [{ id := ← entryid key,
                             name := ← sealbox namekey (bytesof pair.1) AAD_NAME,
                             value := ← sealbox key (bytesof pair.2) (AAD_SECRET ++ pair.1) }]

  let record ← masterrecord root v.key v.passphrase iters

  -- SAVE FIRST, adopt second. A handle holding the new root over a file
  -- that still holds the old one reads nothing and says the vault is
  -- damaged, which is the wrong story about a failed write.
  save v { keys := [record], entries := entries }

  -- Dropped rather than replaced: the next call re-derives from the file
  -- this one just wrote, which is the same rule every other change
  -- follows.
  vaultclose v

-- -------------------------------------------------- opening and creating

/-- Open a vault file as one key.

The handle is LAZY. Nothing is read, and no passphrase is stretched,
until a call needs the file - so a chain of ten providers costs ten
structures rather than ten PBKDF2 runs. -/
def openvault (options : VaultOptions) : IO Vault := do
  if options.file.isEmpty then mvfail "a vault needs a file"
  if options.passphrase.isEmpty then mvfail "a vault needs a passphrase"

  let held ← checkid
    (if options.key.isEmpty then VAULT_MASTERKEY else options.key)
    "a vault needs a key id"

  let opened ← IO.mkRef none

  return { file := options.file, key := held, passphrase := options.passphrase,
           iterations := if 0 < options.iterations then options.iterations
                         else VAULT_ITERATIONS,
           create := options.create, opened := opened }

/-- Make a vault file and answer a handle on its master key.

Refuses a file that is already there: a vault is created once, and
overwriting one discards every secret in it along with every key that
could read them. -/
def createvault (options : VaultOptions) : IO Vault := do
  let v ← openvault options
  putnew v.file (← newvault v.key v.passphrase v.iterations)
  return v

-- ----------------------------------------------------------- the provider

/-- The vaults this module has built.

voxgig/plugin's values carry numbers and strings, not pointers, so a
definition exports the SLOT of what it made and `vaultof` looks it up -
exactly as `providerplugin` exports one for the provider.

Unlike `slots`, this table is NOT emptied when the slot is read:
`vaultof` is called after construction, as often as an application likes.
`vaultdrop` is what the definition's `close` calls, so a chain that was
torn down and a chain whose construction was refused both hand their
vaults back; `heldvaults` reads the table, which is what makes that
checkable rather than merely intended. -/
initialize vaultslots : IO.Ref (List (Nat × Vault)) ← IO.mkRef []

initialize vaultseq : IO.Ref Nat ← IO.mkRef 0

def vaultput (v : Vault) : IO Nat := do
  let id ← vaultseq.modifyGet (fun held => (held, held + 1))
  vaultslots.modify (fun held => held ++ [(id, v)])
  return id

def vaultat (id : Nat) : IO (Option Vault) := do
  let held ← vaultslots.get
  return (held.find? (fun entry => id == entry.1)).map Prod.snd

def vaultdrop (id : Nat) : IO Unit :=
  vaultslots.modify (fun held => held.filter (fun entry => entry.1 != id))

/-- How many vaults the table is holding. A chain that has been closed
must leave this where it found it. -/
def heldvaults : IO Nat := do return (← vaultslots.get).length

/-- Reads a vault as one store in a chain.

The provider is the READ half and nothing more: a chain resolves secrets,
and writing one is a deliberate act with an API of its own. That API is
the same handle, reached with `vaultof` off a chain or built directly
with `openvault`. -/
def minivaultprovider (v : Vault) : Provider :=
  { lookup := fun name => vaultget v name
    describe := "minivault:" ++ v.file }

/-- The `minivault` provider kind, as a voxgig/plugin definition.

Written out rather than built by `providerplugin`, because this
definition publishes TWO exports: `provider`, the read half every kind
publishes, and `vault`, the programmatic API. voxgig/plugin's exports are
how a definition offers an application more than the host's own
vocabulary, and a store that can only be read is half a vault.

The `sekreto_error` wrapping is what `providerplugin` would have done:
plugin wraps a code-less error raised in `define` as
`plugin_define_failed` and keeps one that already carries a code, so a
refusal of this provider's own configuration travels under
`sekreto_error` and comes back out of the host as itself. -/
def minivault : Plugin.Definition := {
  name := "minivault"
  define := some (fun inst => do
    let options ← inst.getOptions
    let spec := specof options

    -- Configuration is refused HERE, so a mistyped chain fails at
    -- construction. Reaching the file is not configuration: the handle is
    -- lazy, and nothing is read or stretched until a lookup.
    let built ← (tryCatch (do return Except.ok (← openvault
        { file := spec.file, key := spec.vaultkey, passphrase := spec.passphrase,
          iterations := spec.iterations.getD 0, create := spec.create }))
      (fun (err : IO.Error) => return Except.error err) : IO _)

    match built with
    | .error (.userError message) =>
      Plugin.raise ERROR_CODE message
        ((Plugin.Value.vmap.set "ref" (.str inst.ref)).set "cause" (.str message))
    | .error other => Plugin.raise "plugin_bare" (why other)
    | .ok v =>
      let id ← slotput (minivaultprovider v)
      inst.exportValue PROVIDER_EXPORT (.num (Float.ofNat id))
      let vid ← vaultput v
      inst.exportValue VAULT_EXPORT (.num (Float.ofNat vid))

      -- THE SLOT IS KEPT IN THE INSTANCE'S STATE AS WELL, because `close`
      -- has to drop it and an instance cannot read its own exports back:
      -- `InstApi` offers `exportValue` and no getter. State is a ref on
      -- the host's entry, so what `define` puts there is what `close`
      -- finds.
      inst.setState ((Plugin.Value.vmap).set "vault" (.num (Float.ofNat vid))))
  close := some (fun inst => do
    match (← inst.getState).get "vault" with
    | .num slot => vaultdrop slot.toUInt64.toNat
    | _ => pure ()) }

/-- The vault behind a store in a chain, as its programmatic API.

`secrets.host` is the voxgig/plugin host the chain is made of, and a
definition's exports are readable off it by ref. This is the one call
that turns a store into an API, and it lives here rather than on
`Sekreto` because the core knows no plugin.

With no store named, the unqualified alias answers: one vault in the
chain resolves whatever it is called, and two refuse rather than picking
one. -/
def vaultof (secrets : Sekreto) (store : String := "") : IO Vault := do
  let held (ref why : String) : IO Vault := do
    match ← runplugin (Plugin.hostExports secrets.host (ref ++ "/" ++ VAULT_EXPORT)) with
    | some (.num slot) =>
      match ← vaultat slot.toUInt64.toNat with
      | some v => return v
      | none => mvfail why
    | _ => mvfail why

  if store.isEmpty then held "minivault" "no minivault store in this chain" else

  -- A NAMED STORE MUST EXIST, and the alias must not stand in for it.
  -- `hostExports` falls back to the alias when the exact ref misses, so
  -- asking for `minivault` in a chain whose only vault is named `app`
  -- used to hand back the `app` vault - and then write to it. Naming a
  -- store that is not there refuses, which is the rule the whole library
  -- follows: `trysecret` already means "may not have it", so it cannot
  -- also mean "may not exist".
  let missing := "no minivault store named " ++ store ++ " in this chain"
  let ref := if "minivault" == store then "minivault" else "minivault$" ++ store

  match ← runplugin (Plugin.hostInstance secrets.host ref) with
  | none => mvfail missing
  | some _ => held ref missing

end Sekreto
