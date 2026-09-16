/* Copyright (c) 2025 Voxgig Ltd, MIT License */

// A mini vault: every secret a project owns, encrypted, in ONE FILE.
//
// The store to reach for before there is a vault server. There is nothing
// to run and nothing to reach over a socket - the whole store is a single
// binary file - and the same chain that reads it in development reads
// HashiCorp or AWS in production by changing config, which is the reason
// sekreto exists.
//
// It is a plugin rather than a built-in kind because it needs crypto,
// which is the line the four built-ins stay behind
// (docs/design/plugin-providers.md).
//
// THE KEY DECIDES WHAT THE VAULT HOLDS. A master key reads and writes
// every name and mints restricted keys. A restricted key reads the names
// it was granted and CANNOT DERIVE ANY OTHER - the restriction is the
// cryptography rather than a check this code performs, so a copy of the
// file plus a restricted passphrase yields exactly what was granted and
// nothing else. What that does and does not protect is set out in
// DOCS.md under "What the mini vault protects", because a store
// described as more than it is gets deployed as more than it is.
//
// node:crypto and node:fs are loaded on first use, like every other
// platform module a plugin needs: a consumer that configured no
// minivault never evaluates them, and a runtime without them fails at
// the point of use, naming what it lacks.

import { PluginError } from '@voxgig/plugin'

import {
  Definition, ERROR_CODE, PROVIDER_EXPORT, Provider, ProviderSpec, SekretoError,
  checkname, nodemod,
} from '../src/provider/support'

type Crypto = typeof import('node:crypto')
type Fs = typeof import('node:fs')

function crypto(): Crypto {
  return nodemod<Crypto>('node:crypto')
}

function fs(): Fs {
  return nodemod<Fs>('node:fs')
}


// --- the format ------------------------------------------------------
//
//   magic       4   'SKMV'
//   version     1   FORMAT
//   kdf         1   1 = PBKDF2-HMAC-SHA256
//   cipher      1   1 = AES-256-GCM
//   reserved    1   0
//   keycount    4   uint32
//   per key:
//     id        1 + bytes      the key id, PLAINTEXT
//     salt      1 + bytes
//     iters     4              PBKDF2 rounds for this key
//     ring      1 + iv, 4 + bytes    sealed under the passphrase
//     meta      1 + iv, 4 + bytes    sealed under the vault's meta key
//   entrycount  4   uint32
//   per entry:
//     id        1 + bytes      the blinded lookup id
//     name      1 + iv, 4 + bytes    sealed under the vault's name key
//     value     1 + iv, 4 + bytes    sealed under that secret's own key
//
// Integers are big-endian, and every length precedes its bytes, so a
// port writes the file with the same two primitives it reads it with.
// A file one port writes is read by every other; `test/fixture` pins
// that with a committed vault rather than with agreement, because a
// format two implementations merely agree about is one that drifts.
//
// NOTHING OUTSIDE A KEY RECORD IS PLAINTEXT. Secret names are sealed,
// and an entry is addressed by a blinded id derived from its own key,
// so a restricted key finds the entries it was granted without the file
// ever naming the rest. What the file does show anyone is the key ids
// and how many secrets there are.

const MAGIC = 'SKMV'
const FORMAT = 1
const KDF_PBKDF2 = 1
const CIPHER_AESGCM = 1

/** AES-256-GCM: 32-byte keys, 12-byte nonces, 16-byte tags. */
const KEYLEN = 32
const IVLEN = 12
const TAGLEN = 16
const SALTLEN = 16

/** PBKDF2-HMAC-SHA256 rounds when a caller names none. */
export const ITERATIONS = 210000

/** The key id a vault gets when a caller names none. */
export const MASTERKEY = 'master'

// Additional authenticated data. Every blob is bound to its PLACE in the
// file, so no ciphertext can be moved: a restricted key's ring cannot be
// relabelled as the master's, and one secret's value cannot be served
// under a name it was never written for.
const AAD_RING = 'skmv1:ring:'
const AAD_META = 'skmv1:meta:'
const AAD_NAME = 'skmv1:name'
const AAD_SECRET = 'skmv1:secret:'

// Everything a master can reach is derived from the root key, so a
// rotation is one new random value rather than a re-wrap of each part.
const LABEL_NAMES = 'skmv1:names'
const LABEL_META = 'skmv1:meta'
const LABEL_ID = 'skmv1:id'


function fail(text: string): never {
  throw new SekretoError('sekreto: minivault: ' + text)
}

/** The largest key id the format can record.
 *
 * `small` writes a length in ONE byte. A longer id wrapped that byte and
 * the writer then appended the whole thing, so every field after it
 * shifted: a `grant` with a 300-character id replaced a working vault
 * with an unreadable one, and said nothing. Checked where an id is
 * ACCEPTED, so the refusal names the id rather than the file. */
const IDMAX = 255

function checkid(id: string, what: string): string {
  if ('string' !== typeof id || '' === id) {
    fail(what)
  }
  if (IDMAX < Buffer.byteLength(id, 'utf8')) {
    fail('key id is longer than ' + IDMAX + ' bytes: ' + id.substring(0, 32) + '...')
  }
  return id
}


// --- keys ------------------------------------------------------------

function hmac(key: Buffer, text: string): Buffer {
  return crypto().createHmac('sha256', key).update(text, 'utf8').digest()
}

/** The key-encryption key a passphrase unwraps a ring with. */
function kek(passphrase: string, salt: Buffer, iters: number): Buffer {
  return crypto().pbkdf2Sync(passphrase, salt, iters, KEYLEN, 'sha256')
}

/** The key one named secret's value is encrypted with.
 *
 * DERIVED, never stored, for a master: it holds the root key and so
 * reaches every name, including ones written after it was made. A
 * restricted key holds the derived keys it was granted and nothing that
 * produces another, so every other name is ciphertext to it in exactly
 * the way it is to a stranger. */
function secretkey(root: Buffer, name: string): Buffer {
  return hmac(root, AAD_SECRET + name)
}

/** Where a secret lives in the file, derived from its own key so that
 * finding it needs no plaintext name. One-way: an id yields nothing
 * about the key that produced it. */
function entryid(key: Buffer): Buffer {
  return hmac(key, LABEL_ID)
}

function random(len: number): Buffer {
  return crypto().randomBytes(len)
}


// --- sealing ---------------------------------------------------------

type Sealed = { iv: Buffer, blob: Buffer }

function seal(key: Buffer, plain: Buffer, aad: string): Sealed {
  const iv = random(IVLEN)
  const cipher = crypto().createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const body = Buffer.concat([cipher.update(plain), cipher.final()])
  return { iv, blob: Buffer.concat([body, cipher.getAuthTag()]) }
}

/** The plaintext, or a refusal. A GCM tag that fails to verify is the
 * only evidence there is, and it cannot tell a wrong passphrase from a
 * damaged file, so `what` names the attempt and the message admits
 * both. */
function unseal(key: Buffer, sealed: Sealed, aad: string, what: string): Buffer {
  if (sealed.blob.length < TAGLEN || IVLEN !== sealed.iv.length) {
    fail(what + ': truncated')
  }

  // The WHOLE round-trip is guarded, not only `final()`. A nonce or tag
  // of the wrong length makes the constructor itself raise, and a
  // damaged file reaching a caller as a raw RangeError is a refusal
  // nobody can act on.
  try {
    const decipher = crypto().createDecipheriv('aes-256-gcm', key, sealed.iv)
    decipher.setAAD(Buffer.from(aad, 'utf8'))
    decipher.setAuthTag(sealed.blob.subarray(sealed.blob.length - TAGLEN))

    return Buffer.concat([
      decipher.update(sealed.blob.subarray(0, sealed.blob.length - TAGLEN)),
      decipher.final(),
    ])
  } catch {
    fail(what)
  }
}

function jsonof(plain: Buffer, what: string): any {
  try {
    return JSON.parse(plain.toString('utf8'))
  } catch {
    return fail('unreadable ' + what)
  }
}

function b64(bytes: Buffer): string {
  return bytes.toString('base64')
}

function unb64(text: any, what: string): Buffer {
  if ('string' !== typeof text) {
    fail('missing ' + what)
  }
  return Buffer.from(text, 'base64')
}


// --- the file --------------------------------------------------------

type KeyRecord = { id: string, salt: Buffer, iters: number, ring: Sealed, meta: Sealed }
type EntryRecord = { id: Buffer, name: Sealed, value: Sealed }
type VaultFile = { keys: KeyRecord[], entries: EntryRecord[] }

/** A cursor, so that every length check is in one place: a truncated
 * vault is refused rather than read as a short one. */
function reader(bytes: Buffer) {
  let at = 0

  const take = (len: number): Buffer => {
    if (bytes.length < at + len) {
      fail('the vault file is truncated')
    }
    const out = Buffer.from(bytes.subarray(at, at + len))
    at += len
    return out
  }

  const u8 = (): number => take(1)[0]
  const u32 = (): number => take(4).readUInt32BE(0)
  const small = (): Buffer => take(u8())
  const large = (): Buffer => take(u32())

  return {
    u8, u32, small, large,
    magic: (): string => take(4).toString('latin1'),
    sealed: (): Sealed => ({ iv: small(), blob: large() }),
    done: (): boolean => at === bytes.length,
  }
}

function readfile(bytes: Buffer): VaultFile {
  const read = reader(bytes)

  if (MAGIC !== read.magic()) {
    fail('not a vault file')
  }

  const version = read.u8()
  if (FORMAT !== version) {
    fail('unsupported format version: ' + version)
  }

  const kdf = read.u8()
  const cipher = read.u8()
  if (KDF_PBKDF2 !== kdf || CIPHER_AESGCM !== cipher) {
    fail('unsupported kdf or cipher: ' + kdf + '/' + cipher)
  }
  read.u8()

  const keys: KeyRecord[] = []
  const keycount = read.u32()
  for (let index = 0; index < keycount; index++) {
    const id = read.small().toString('utf8')
    const salt = read.small()
    const iters = read.u32()
    keys.push({ id, salt, iters, ring: read.sealed(), meta: read.sealed() })
  }

  const entries: EntryRecord[] = []
  const entrycount = read.u32()
  for (let index = 0; index < entrycount; index++) {
    entries.push({ id: read.small(), name: read.sealed(), value: read.sealed() })
  }

  if (!read.done()) {
    fail('the vault file has trailing bytes')
  }

  return { keys, entries }
}

function writefile(vault: VaultFile): Buffer {
  const parts: Buffer[] = []

  const u8 = (value: number) => parts.push(Buffer.from([value]))
  const u32 = (value: number) => {
    const four = Buffer.alloc(4)
    four.writeUInt32BE(value, 0)
    parts.push(four)
  }
  const small = (bytes: Buffer) => { u8(bytes.length); parts.push(bytes) }
  const large = (bytes: Buffer) => { u32(bytes.length); parts.push(bytes) }
  const sealed = (value: Sealed) => { small(value.iv); large(value.blob) }

  parts.push(Buffer.from(MAGIC, 'latin1'))
  u8(FORMAT)
  u8(KDF_PBKDF2)
  u8(CIPHER_AESGCM)
  u8(0)

  u32(vault.keys.length)
  for (const key of vault.keys) {
    small(Buffer.from(key.id, 'utf8'))
    small(key.salt)
    u32(key.iters)
    sealed(key.ring)
    sealed(key.meta)
  }

  // SORTED BY ID, which is a blinded value: the file therefore records
  // nothing about the order secrets were written in.
  const entries = [...vault.entries].sort((left, right) => Buffer.compare(left.id, right.id))

  u32(entries.length)
  for (const entry of entries) {
    small(entry.id)
    sealed(entry.name)
    sealed(entry.value)
  }

  return Buffer.concat(parts)
}


// --- what a key is ---------------------------------------------------

/** A detached copy, so that what a caller is handed cannot become what
 * this vault believes. */
function copyinfo(info: VaultKeyInfo): VaultKeyInfo {
  return {
    key: info.key,
    master: info.master,
    write: info.write,
    grants: [...info.grants],
  }
}

/** What a key may do. `grants` is empty for a master key, which reads
 * and writes every name there is. */
export type VaultKeyInfo = {
  key: string
  master: boolean
  write: boolean
  grants: string[]
}

export type GrantSpec = {
  /** The id the new key answers to. */
  key: string
  /** Its passphrase. Nothing else unwraps it, and no master can recover
   * it - a lost restricted passphrase is re-granted, never read back. */
  passphrase: string
  /** The names it may read. A name that does not exist yet is allowed
   * and means what it says: the key reads it once a master writes it. */
  names: string[]
  /** May it overwrite the values it can read? Default false. */
  write?: boolean
  /** PBKDF2 rounds for this key, defaulting to the opening handle's. */
  iterations?: number
}

export type VaultOptions = {
  /** The vault file. */
  file: string
  /** Which key to open with. Default `master`. */
  key?: string
  passphrase: string
  /** PBKDF2 rounds used when this call CREATES a key. Reading uses what
   * the file records for the key being opened. */
  iterations?: number
  /** Make the file, with this key as its master, if it is not there.
   *
   * Off by default. A missing vault is far more often a broken
   * deployment than a new one, and a store that invents itself where a
   * real vault was meant to be answers every read with a miss. */
  create?: boolean
}

/** A handle on one vault file, opened as ONE key.
 *
 * Every method answers as that key: `list` shows the names it may read,
 * `get` answers for those and misses on the rest, and the master-only
 * methods refuse for any other key. Nothing is read or derived until the
 * first call that needs the file, so putting a vault in a chain costs no
 * key derivation until a secret is actually wanted. */
export type MiniVault = {
  /** The file this handle reads. */
  file: () => string
  /** The key id this handle opens with. */
  key: () => string
  /** Derive the key and read the file NOW rather than at first use. */
  open: () => VaultKeyInfo
  /** Forget the derived keys. The next call opens again. */
  close: () => void
  /** The names this key can read, sorted. */
  list: () => string[]
  has: (name: string) => boolean
  /** The value, or undefined when the vault does not hold that name or
   * this key was not granted it. */
  get: (name: string) => string | undefined
  /** Write a value. A master writes any name; a restricted key holding
   * `write` overwrites the names it was granted, and creates none. */
  set: (name: string, value: string) => void
  /** Drop a name. Master only. */
  remove: (name: string) => void
  /** Every key in the file, with what it may do. Master only. */
  keys: () => VaultKeyInfo[]
  /** Mint a restricted key. Master only. */
  grant: (spec: GrantSpec) => void
  /** Drop a key. Master only.
   *
   * Anyone who already copied the file keeps whatever that key could
   * read, so revoking bars future reads of the LIVE file and `rotate` is
   * what takes a secret back. */
  revoke: (key: string) => void
  /** A new root key, every value re-encrypted under it, and EVERY OTHER
   * KEY DROPPED. Master only.
   *
   * The other keys go because they must: their rings are sealed under
   * passphrases this process does not have, so there is no way to hand
   * them keys they can unwrap. Re-grant afterwards. */
  rotate: () => void
}


// --- creating --------------------------------------------------------

/** A new vault: one master key, no secrets. */
function newvault(keyid: string, passphrase: string, iterations: number): VaultFile {
  const root = random(KEYLEN)
  const salt = random(SALTLEN)

  const ring: Ring = { v: FORMAT, write: true, root: b64(root) }
  const meta: Meta = { v: FORMAT, master: true, write: true, grants: [] }

  return {
    keys: [{
      id: keyid,
      salt,
      iters: iterations,
      ring: seal(kek(passphrase, salt, iterations),
        Buffer.from(JSON.stringify(ring), 'utf8'), AAD_RING + keyid),
      meta: seal(hmac(root, LABEL_META),
        Buffer.from(JSON.stringify(meta), 'utf8'), AAD_META + keyid),
    }],
    entries: [],
  }
}

/** Write a vault file that is not there yet, and REFUSE one that is.
 *
 * Straight to the target under `wx` — `O_CREAT|O_EXCL` — rather than
 * through a temporary and a rename. `rename` REPLACES its destination,
 * so two processes creating the same vault both succeeded and the
 * second discarded the first one's secrets; `existsSync` beforehand
 * only narrows that window. There is nothing to lose by writing the
 * target directly here, because there is no file to damage: either this
 * call creates it or the call fails. */
function putnew(file: string, vault: VaultFile): void {
  try {
    fs().writeFileSync(file, writefile(vault), { mode: 0o600, flag: 'wx' })
  } catch (err: any) {
    if ('EEXIST' === err.code) {
      fail('vault file already exists: ' + file)
    }
    fail('cannot write ' + file + ': ' + err.message)
  }
}


// --- opening ---------------------------------------------------------

/** The ring, as stored: EITHER a root key (master) OR a fixed set of
 * derived per-secret keys (restricted). */
type Ring = { v: number, write: boolean, root?: string, grants?: Record<string, string> }

/** What a master recorded about a key when it minted it, sealed under
 * the vault's meta key so that `keys()` can answer without holding any
 * other key's passphrase. */
type Meta = { v: number, master: boolean, write: boolean, grants: string[] }

type Opened = {
  info: VaultKeyInfo
  /** Present for a master key only. */
  root?: Buffer
  /** The per-name keys this key was granted. Empty for a master, which
   * derives them from the root key instead. */
  grants: Record<string, Buffer>
  /** THE SEALED RING THIS WAS DERIVED FROM, kept so that every later
   * call can check the file still says the same thing. A handle that
   * cached its keys and never looked again kept reading a vault after
   * its key was revoked, which is the one thing `revoke` promises. */
  ring: Sealed
}

/** Is this the same sealed blob, byte for byte? */
function sameseal(left: Sealed, right: Sealed): boolean {
  return 0 === Buffer.compare(left.iv, right.iv) && 0 === Buffer.compare(left.blob, right.blob)
}

/** Open a vault file as one key.
 *
 * The handle is lazy. Nothing is read, and no passphrase is stretched,
 * until a method needs the file - so a chain of ten providers costs ten
 * objects rather than ten PBKDF2 runs. */
export function openvault(options: VaultOptions): MiniVault {
  const opts = options || ({} as VaultOptions)
  const file = opts.file
  const keyid = opts.key || MASTERKEY
  const passphrase = opts.passphrase
  const iterations = opts.iterations || ITERATIONS

  if ('string' !== typeof file || '' === file) {
    fail('a vault needs a file')
  }
  if ('string' !== typeof passphrase || '' === passphrase) {
    fail('a vault needs a passphrase')
  }
  checkid(keyid, 'a vault needs a key id')

  let opened: Opened | undefined

  const bytes = (): Buffer => {
    try {
      return fs().readFileSync(file)
    } catch (err: any) {
      // A vault is configured deliberately, with a key. Its absence is a
      // broken deployment and never "no secrets here": answering a miss
      // would send the chain on to a weaker store, which is the failure
      // mode this library most has to avoid. `create` is the caller
      // saying the opposite, in writing.
      if ('ENOENT' === err.code) {
        if (true !== opts.create) {
          fail('no vault file: ' + file)
        }
        putnew(file, newvault(keyid, passphrase, iterations))
        return fs().readFileSync(file)
      }
      return fail('cannot read ' + file + ': ' + err.message)
    }
  }

  const load = (): { vault: VaultFile, open: Opened } => {
    const vault = readfile(bytes())

    const record = vault.keys.find((k) => k.id === keyid)
    if (undefined === record) {
      // REVOKED, or never there. Either way this handle is finished, and
      // dropping what it derived is what stops the next call answering
      // from memory.
      opened = undefined
      fail('no such key: ' + keyid)
    }

    // The file still holds this key, and holds the SAME ring: a key
    // revoked and re-granted under another passphrase is a different key
    // wearing the id, and re-deriving is what refuses it.
    if (undefined !== opened && sameseal(opened.ring, record.ring)) {
      return { vault, open: opened }
    }
    opened = undefined

    const plain = unseal(kek(passphrase, record.salt, record.iters), record.ring,
      AAD_RING + keyid, 'wrong passphrase for key ' + keyid + ', or a damaged vault')

    const ring: Ring = jsonof(plain, 'key ring for ' + keyid)

    const grants: Record<string, Buffer> = {}
    for (const [name, key] of Object.entries(ring.grants || {})) {
      grants[name] = unb64(key, 'a granted key')
    }

    opened = {
      info: {
        key: keyid,
        master: undefined !== ring.root,
        write: undefined !== ring.root || true === ring.write,
        grants: Object.keys(grants).sort(),
      },
      root: undefined === ring.root ? undefined : unb64(ring.root, 'the root key'),
      grants,
      ring: record.ring,
    }

    return { vault, open: opened }
  }

  const rootof = (open: Opened, what: string): Buffer => {
    if (undefined === open.root) {
      fail(what + ' needs a master key, and ' + open.info.key + ' is restricted')
    }
    return open.root
  }

  /** The key for one name, or undefined when this key cannot reach it. */
  const keyfor = (open: Opened, name: string): Buffer | undefined => {
    if (undefined !== open.root) {
      return secretkey(open.root, name)
    }
    return open.grants[name]
  }

  const findentry = (vault: VaultFile, key: Buffer): EntryRecord | undefined => {
    const id = entryid(key)
    return vault.entries.find((entry) => 0 === Buffer.compare(entry.id, id))
  }

  const metaof = (open: Opened, record: KeyRecord): Meta | undefined => {
    const root = rootof(open, 'reading key metadata')
    try {
      return jsonof(unseal(hmac(root, LABEL_META), record.meta, AAD_META + record.id,
        'metadata for key ' + record.id), 'metadata for key ' + record.id)
    } catch {
      // A record written under a root key this one has replaced. The key
      // is still in the file and still opens with its own passphrase, so
      // it is reported rather than hidden - with what it can do unknown.
      return undefined
    }
  }

  const sealkey = (
    root: Buffer, id: string, phrase: string, iters: number, ring: Ring, meta: Meta,
  ): KeyRecord => {
    const salt = random(SALTLEN)
    return {
      id,
      salt,
      iters,
      ring: seal(kek(phrase, salt, iters), Buffer.from(JSON.stringify(ring), 'utf8'), AAD_RING + id),
      meta: seal(hmac(root, LABEL_META), Buffer.from(JSON.stringify(meta), 'utf8'), AAD_META + id),
    }
  }

  /** Read, change, and REPLACE - never edit in place. The rename is what
   * makes a concurrent reader see either the old file or the new one, so
   * a write interrupted halfway leaves a vault rather than wreckage.
   *
   * THE TEMPORARY IS RANDOM AND EXCLUSIVE. `<vault>.<pid>.tmp` is a name
   * anyone can predict, so anyone who can write the vault's directory
   * could put a symlink there and have the next save truncate whatever
   * it pointed at. `wx` is `O_CREAT|O_EXCL`, which POSIX refuses on a
   * symlink, and the random suffix stops two writers in one process
   * colliding on the path. */
  const save = (vault: VaultFile): void => {
    const node = fs()
    const temp = file + '.' + random(8).toString('hex') + '.tmp'

    try {
      node.writeFileSync(temp, writefile(vault), { mode: 0o600, flag: 'wx' })
      node.renameSync(temp, file)
    } catch (err: any) {
      try {
        node.unlinkSync(temp)
      } catch {
        // The vault is unchanged either way, and the write error is what
        // the caller needs to be told about.
      }
      fail('cannot write ' + file + ': ' + err.message)
    }
  }

  const self: MiniVault = {
    file: () => file,
    key: () => keyid,

    // A COPY. `set` reads `info.write` to decide whether this key may
    // write, so handing the caller the object itself let it flip its own
    // permission: `vault.open().write = true` turned a read-only key
    // into a writing one. Authorization state does not leave this
    // closure.
    open: () => copyinfo(load().open.info),

    close: () => { opened = undefined },

    list: () => {
      const { vault, open } = load()

      if (undefined !== open.root) {
        const namekey = hmac(open.root, LABEL_NAMES)
        return vault.entries
          .map((entry) => unseal(namekey, entry.name, AAD_NAME, 'a secret name is damaged')
            .toString('utf8'))
          .sort()
      }

      // A restricted key has no name key, so it reports the grants it can
      // actually find: the vault never tells it what else is in there.
      return open.info.grants
        .filter((name) => undefined !== findentry(vault, open.grants[name]))
        .sort()
    },

    has: (name: string) => undefined !== self.get(name),

    get: (name: string) => {
      checkname(name)
      const { vault, open } = load()

      const key = keyfor(open, name)
      if (undefined === key) {
        // OUTSIDE THE GRANT IS A MISS, deliberately. The vault answers as
        // the key that opened it, so a name this key cannot read is a
        // name this store does not hold for this caller - the same answer
        // a stranger's vault gives, and the one that makes a restricted
        // key in front of a broader store a workable chain.
        return undefined
      }

      const entry = findentry(vault, key)
      if (undefined === entry) {
        return undefined
      }

      return unseal(key, entry.value, AAD_SECRET + name,
        'the value of ' + name + ' is damaged').toString('utf8')
    },

    set: (name: string, value: string) => {
      checkname(name)
      if ('string' !== typeof value) {
        fail('a secret value must be text: ' + name)
      }

      const { vault, open } = load()

      if (!open.info.write) {
        fail('key ' + open.info.key + ' is read-only')
      }

      const key = keyfor(open, name)
      if (undefined === key) {
        fail('key ' + open.info.key + ' was not granted ' + name)
      }

      const sealedvalue = seal(key, Buffer.from(value, 'utf8'), AAD_SECRET + name)
      const id = entryid(key)
      const at = vault.entries.findIndex((entry) => 0 === Buffer.compare(entry.id, id))

      if (-1 !== at) {
        vault.entries[at] = { id: vault.entries[at].id, name: vault.entries[at].name, value: sealedvalue }
      } else {
        // A NEW NAME NEEDS THE NAME KEY, which only a master holds. So a
        // restricted key with `write` updates what it was granted and
        // cannot grow the vault, which is what "restricted" has to mean
        // for the grant list to stay the whole story.
        const root = rootof(open, 'creating the secret ' + name)
        vault.entries.push({
          id,
          name: seal(hmac(root, LABEL_NAMES), Buffer.from(name, 'utf8'), AAD_NAME),
          value: sealedvalue,
        })
      }

      save(vault)
    },

    remove: (name: string) => {
      checkname(name)
      const { vault, open } = load()
      const root = rootof(open, 'removing a secret')

      const at = vault.entries.findIndex(
        (entry) => 0 === Buffer.compare(entry.id, entryid(secretkey(root, name))))
      if (-1 === at) {
        fail('no such secret: ' + name)
      }

      vault.entries.splice(at, 1)
      save(vault)
    },

    keys: () => {
      const { vault, open } = load()
      rootof(open, 'listing the keys')

      return vault.keys.map((record) => {
        const meta = metaof(open, record)
        if (undefined === meta) {
          return { key: record.id, master: false, write: false, grants: [] }
        }
        return {
          key: record.id,
          master: true === meta.master,
          write: true === meta.write,
          grants: [...(meta.grants || [])].sort(),
        }
      })
    },

    grant: (spec: GrantSpec) => {
      const { vault, open } = load()
      const root = rootof(open, 'granting a key')

      checkid(null == spec ? '' : spec.key, 'a grant needs a key id')
      if ('string' !== typeof spec.passphrase || '' === spec.passphrase) {
        fail('a grant needs a passphrase')
      }
      if (undefined !== vault.keys.find((k) => k.id === spec.key)) {
        fail('key already exists: ' + spec.key)
      }

      const names = [...(spec.names || [])].sort()
      const grants: Record<string, string> = {}
      for (const name of names) {
        checkname(name)
        grants[name] = b64(secretkey(root, name))
      }

      const write = true === spec.write
      vault.keys.push(sealkey(root, spec.key, spec.passphrase, spec.iterations || iterations,
        { v: FORMAT, write, grants },
        { v: FORMAT, master: false, write, grants: names }))

      save(vault)
    },

    revoke: (key: string) => {
      const { vault, open } = load()
      rootof(open, 'revoking a key')

      if (key === open.info.key) {
        fail('a key cannot revoke itself: ' + key)
      }

      const at = vault.keys.findIndex((k) => k.id === key)
      if (-1 === at) {
        fail('no such key: ' + key)
      }

      vault.keys.splice(at, 1)
      save(vault)
    },

    rotate: () => {
      const { vault, open } = load()
      rootof(open, 'rotating the vault')

      // Read everything out under the old root before anything changes:
      // once the root is replaced the old derived keys are unreachable.
      const plain = self.list().map((name) => ({ name, value: self.get(name) as string }))

      const root = random(KEYLEN)
      const namekey = hmac(root, LABEL_NAMES)

      const entries: EntryRecord[] = plain.map((secret) => {
        const key = secretkey(root, secret.name)
        return {
          id: entryid(key),
          name: seal(namekey, Buffer.from(secret.name, 'utf8'), AAD_NAME),
          value: seal(key, Buffer.from(secret.value, 'utf8'), AAD_SECRET + secret.name),
        }
      })

      const record = vault.keys.find((k) => k.id === keyid) as KeyRecord

      const fresh = sealkey(root, keyid, passphrase, record.iters,
        { v: FORMAT, write: true, root: b64(root) },
        { v: FORMAT, master: true, write: true, grants: [] })

      // SAVE FIRST, adopt second. A handle holding the new root over a
      // file that still holds the old one reads nothing and says the
      // vault is damaged, which is the wrong story about a failed write.
      save({ keys: [fresh], entries })

      opened = {
        info: { key: keyid, master: true, write: true, grants: [] },
        root,
        grants: {},
        ring: fresh.ring,
      }
    },
  }

  return self
}

/** Make a vault file and return a handle on its master key.
 *
 * Refuses a file that is already there: a vault is created once, and
 * overwriting one discards every secret in it along with every key that
 * could read them. */
export function createvault(options: VaultOptions): MiniVault {
  const opts = options || ({} as VaultOptions)

  if ('string' !== typeof opts.file || '' === opts.file) {
    fail('a vault needs a file')
  }
  if ('string' !== typeof opts.passphrase || '' === opts.passphrase) {
    fail('a vault needs a passphrase')
  }
  checkid(opts.key || MASTERKEY, 'a vault needs a key id')

  // No `existsSync` first: the check and the write would be two steps,
  // and `putnew` refuses an existing file in ONE, which is what makes
  // two processes racing to create a vault leave one vault.
  putnew(opts.file, newvault(opts.key || MASTERKEY, opts.passphrase, opts.iterations || ITERATIONS))

  return openvault(opts)
}


// --- the provider ----------------------------------------------------

/** Read a vault as one store in a chain.
 *
 * The provider is the READ half and nothing more: a chain resolves
 * secrets, and writing one is a deliberate act with an API of its own.
 * That API is the same handle, reached with `vaultof` off a chain or
 * built directly with `openvault`. */
export function providerof(vault: MiniVault): Provider {
  return {
    lookup: (name: string) => vault.get(name),
    describe: () => 'minivault:' + vault.file(),
  }
}

/** A vault provider from options, for a chain built by hand. */
export function minivaultprovider(options: VaultOptions): Provider {
  return providerof(openvault(options))
}

/** The vault options a provider spec describes. */
function vaultoptions(spec: ProviderSpec): VaultOptions {
  return {
    file: spec.file || '',
    key: spec.vaultkey,
    passphrase: spec.passphrase || '',
    iterations: spec.iterations,
    create: true === spec.create,
  }
}


// --- the plugin ------------------------------------------------------

/** The export key the vault API is published under, beside the
 * `provider` key every kind publishes. */
export const VAULT_EXPORT = 'vault'

/** The `minivault` provider kind.
 *
 * Written out rather than built by `providerplugin`, because this
 * definition publishes TWO exports: `provider`, the read half every kind
 * publishes, and `vault`, the programmatic API. voxgig/plugin's exports
 * are how a definition offers an application more than the host's own
 * vocabulary, and a store that can only be read is half a vault.
 *
 * The SekretoError wrapping is what `providerplugin` would have done:
 * plugin wraps a code-less error raised in `define` as
 * `plugin_define_failed`, and keeps one that already carries a code, so
 * a refusal of this provider's own configuration travels under
 * `sekreto_error` and comes back out of the host as itself. */
export const minivault: Definition = {
  name: 'minivault',
  define: (inst: any) => {
    const options = vaultoptions(inst.options as ProviderSpec)

    try {
      // `openvault` refuses bad configuration HERE, so a mistyped chain
      // fails at construction. Reaching the FILE is not configuration:
      // the handle is lazy, and nothing is read or stretched until a
      // lookup.
      const vault = openvault(options)

      inst.export(PROVIDER_EXPORT, providerof(vault))
      inst.export(VAULT_EXPORT, vault)
    } catch (err: any) {
      if (err instanceof SekretoError) {
        throw new PluginError(ERROR_CODE, err.message, { ref: inst.ref, cause: err.message })
      }
      throw err
    }
  },
}

/** The vault behind a store in a chain, as its programmatic API.
 *
 * `secrets.host` is the voxgig/plugin host the chain is made of, and a
 * definition's exports are readable off it by ref. This is the one line
 * that turns a store into an API, and it lives here rather than on
 * `Sekreto` because the core knows no plugin.
 *
 * With no store named, the unqualified alias answers: one vault in the
 * chain resolves whatever it is called, and two raise rather than
 * picking one. */
export function vaultof(secrets: { host: any }, store?: string): MiniVault {
  if (undefined === store) {
    const found = secrets.host.exports('minivault/' + VAULT_EXPORT)
    if (undefined === found) {
      fail('no minivault store in this chain')
    }
    return found as MiniVault
  }

  // A NAMED STORE MUST EXIST, and the alias must not stand in for it.
  // `host.exports` falls back to the alias when the exact ref misses, so
  // asking for `minivault` in a chain whose only vault is named `app`
  // used to hand back the `app` vault - and then write to it. Naming a
  // store that is not there raises, which is the rule the whole library
  // follows: `try` already means "may not have it", so it cannot also
  // mean "may not exist".
  const ref = 'minivault' === store ? 'minivault' : 'minivault$' + store

  if (undefined === secrets.host.instance(ref)) {
    fail('no minivault store named ' + store + ' in this chain')
  }

  return secrets.host.exports(ref + '/' + VAULT_EXPORT) as MiniVault
}
