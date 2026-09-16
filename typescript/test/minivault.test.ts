// RUN: npm test
//
// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail twenty-one ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by
// this port and read by another, pinned by test/fixture/minivault.skmv.

import { before, describe, test } from 'node:test'
import assert from 'node:assert'
import {
  copyFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Sekreto, SekretoError } from '../src'
import {
  MASTERKEY, MiniVault, createvault, minivault, openvault, vaultof,
} from '../plugins/minivault'

const MASTER = 'master-passphrase'

/** The rounds every test here uses. The library default is 210000, which
 * is the point of PBKDF2 and the wrong thing to pay per assertion. */
const ROUNDS = 1000

let work: string
let count = 0

function vaultpath(): string {
  count += 1
  return join(work, 'vault' + count + '.skmv')
}

function fresh(): MiniVault {
  return createvault({ file: vaultpath(), passphrase: MASTER, iterations: ROUNDS })
}

/** Where the committed vaults live, found by walking up. */
function fixturedir(): string {
  let dir = __dirname

  for (let step = 0; step < 8; step++) {
    const cand = join(dir, 'test', 'fixture')
    if (existsSync(cand)) {
      return cand
    }
    dir = join(dir, '..')
  }
  throw new Error('sekreto: fixture directory not found')
}

/** EVERY committed vault, read off disk rather than listed here.
 *
 * A hard-coded list is one more place to edit when a port lands, and the
 * edit that gets forgotten is the one that makes this suite stop
 * checking the port that just arrived. */
function fixtures(): string[] {
  return readdirSync(fixturedir()).filter((n) => n.endsWith('.skmv')).sort()
}

/** A committed vault, copied so that a test which writes cannot edit the
 * bytes the format contract is made of. */
function fixture(name: string): string {
  let dir = __dirname

  for (let step = 0; step < 8; step++) {
    const cand = join(dir, 'test', 'fixture', name)
    if (existsSync(cand)) {
      const mine = vaultpath()
      copyFileSync(cand, mine)
      return mine
    }
    dir = join(dir, '..')
  }

  throw new Error('sekreto: fixture vault not found: ' + name)
}

describe('minivault', () => {
  before(() => {
    work = mkdtempSync(join(tmpdir(), 'sekreto-minivault-'))
  })

  // --- one file, one key ---------------------------------------------

  test('a new vault holds nothing and answers as its master key', () => {
    const vault = fresh()

    assert.deepEqual(vault.open(),
      { key: MASTERKEY, master: true, write: true, grants: [] })
    assert.deepEqual(vault.list(), [])
    assert.equal(vault.get('api.token'), undefined)
    assert.equal(vault.has('api.token'), false)
  })

  test('a written secret comes back, and a new handle reads it', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.set('db.pass', 'hunter2')

    assert.deepEqual(vault.list(), ['api.token', 'db.pass'])
    assert.equal(vault.get('api.token'), 'tok01')
    assert.equal(vault.has('db.pass'), true)

    // A SECOND HANDLE, not the same object: what is being checked is the
    // file, and a handle that answered from memory would pass either way.
    const reopened = openvault({ file: vault.file(), passphrase: MASTER })
    assert.equal(reopened.get('db.pass'), 'hunter2')
  })

  test('the file is binary, and names nothing in plaintext', () => {
    const vault = fresh()
    vault.set('api.token', 'tok01')

    const bytes = readFileSync(vault.file())

    assert.equal(bytes.subarray(0, 4).toString('latin1'), 'SKMV')
    assert.equal(bytes[4], 1, 'format version')

    // The key ids are plaintext and documented as such; a secret name is
    // not, and neither is a value.
    const text = bytes.toString('latin1')
    assert.ok(text.includes(MASTERKEY), 'key ids are plaintext')
    assert.ok(!text.includes('api.token'), 'a secret name is in the clear')
    assert.ok(!text.includes('tok01'), 'a secret value is in the clear')
  })

  test('rewriting a name replaces it rather than adding one', () => {
    const vault = fresh()

    vault.set('api.token', 'first')
    vault.set('api.token', 'second')

    assert.deepEqual(vault.list(), ['api.token'])
    assert.equal(vault.get('api.token'), 'second')
  })

  test('remove drops a name, and refuses one that is not there', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.remove('api.token')

    assert.deepEqual(vault.list(), [])
    assert.throws(() => vault.remove('api.token'),
      { name: 'SekretoError', message: 'sekreto: minivault: no such secret: api.token' })
  })

  test('a name the library refuses is refused here too', () => {
    const vault = fresh()

    assert.throws(() => vault.set('Api.Token', 'x'),
      { name: 'SekretoError', message: 'sekreto: invalid name: Api.Token' })
    assert.throws(() => vault.get('api token'),
      { name: 'SekretoError', message: 'sekreto: invalid name: api token' })
  })

  // --- restricted keys -----------------------------------------------

  test('a restricted key reads its grants and MISSES on the rest', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.set('db.pass', 'hunter2')
    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })

    const ci = openvault({ file: vault.file(), key: 'ci', passphrase: 'ci-pass' })

    assert.deepEqual(ci.open(),
      { key: 'ci', master: false, write: false, grants: ['api.token'] })
    assert.equal(ci.get('api.token'), 'tok01')

    // Not an error: the vault answers as the key that opened it, so a
    // name outside the grant is a name this store does not hold.
    assert.equal(ci.get('db.pass'), undefined)
    assert.equal(ci.has('db.pass'), false)

    // And it is never told the name exists.
    assert.deepEqual(ci.list(), ['api.token'])
  })

  test('a read-only key refuses to write, and a write key updates', () => {
    const vault = fresh()

    vault.set('db.pass', 'hunter2')
    vault.grant({ key: 'ro', passphrase: 'ro-pass', names: ['db.pass'], iterations: ROUNDS })
    vault.grant({
      key: 'rw', passphrase: 'rw-pass', names: ['db.pass'], write: true, iterations: ROUNDS,
    })

    const readonly = openvault({ file: vault.file(), key: 'ro', passphrase: 'ro-pass' })
    assert.throws(() => readonly.set('db.pass', 'x'),
      { message: 'sekreto: minivault: key ro is read-only' })

    const writable = openvault({ file: vault.file(), key: 'rw', passphrase: 'rw-pass' })
    writable.set('db.pass', 'rotated')

    assert.equal(vault.get('db.pass'), 'rotated')
  })

  test('a restricted key cannot write a name it was not granted', () => {
    const vault = fresh()

    vault.grant({
      key: 'rw', passphrase: 'rw-pass', names: ['db.pass'], write: true, iterations: ROUNDS,
    })

    const writable = openvault({ file: vault.file(), key: 'rw', passphrase: 'rw-pass' })

    assert.throws(() => writable.set('api.token', 'x'),
      { message: 'sekreto: minivault: key rw was not granted api.token' })
  })

  // A GRANT CAN PRECEDE THE SECRET, because the key for a name is
  // derived from the name rather than stored against an entry. This is
  // also the one path on which a restricted key reaches `set` for a name
  // that has no entry yet - and is refused, because writing a NEW name
  // needs the master's name key.
  test('a granted name that does not exist yet reads once a master writes it', () => {
    const vault = fresh()

    vault.grant({
      key: 'rw', passphrase: 'rw-pass', names: ['later.value'], write: true, iterations: ROUNDS,
    })

    const writable = openvault({ file: vault.file(), key: 'rw', passphrase: 'rw-pass' })

    assert.deepEqual(writable.list(), [])
    assert.equal(writable.get('later.value'), undefined)
    assert.throws(() => writable.set('later.value', 'mine'),
      { message: 'sekreto: minivault: creating the secret later.value needs a master key, and rw is restricted' })

    vault.set('later.value', 'from the master')

    assert.deepEqual(writable.list(), ['later.value'])
    assert.equal(writable.get('later.value'), 'from the master')

    writable.set('later.value', 'now mine')
    assert.equal(vault.get('later.value'), 'now mine')
  })

  test('the master lists every key and what it may do', () => {
    const vault = fresh()

    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })
    vault.grant({
      key: 'ops', passphrase: 'ops-pass', names: ['db.pass', 'api.token'],
      write: true, iterations: ROUNDS,
    })

    assert.deepEqual(vault.keys(), [
      { key: MASTERKEY, master: true, write: true, grants: [] },
      { key: 'ci', master: false, write: false, grants: ['api.token'] },
      { key: 'ops', master: false, write: true, grants: ['api.token', 'db.pass'] },
    ])
  })

  test('the master-only methods refuse a restricted key', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })

    const ci = openvault({ file: vault.file(), key: 'ci', passphrase: 'ci-pass' })

    const restricted = ' needs a master key, and ci is restricted'
    assert.throws(() => ci.keys(), { message: 'sekreto: minivault: listing the keys' + restricted })
    assert.throws(() => ci.remove('api.token'),
      { message: 'sekreto: minivault: removing a secret' + restricted })
    assert.throws(() => ci.grant({ key: 'x', passphrase: 'p', names: [] }),
      { message: 'sekreto: minivault: granting a key' + restricted })
    assert.throws(() => ci.revoke(MASTERKEY),
      { message: 'sekreto: minivault: revoking a key' + restricted })
    assert.throws(() => ci.rotate(),
      { message: 'sekreto: minivault: rotating the vault' + restricted })
  })

  test('a repeated key id is refused rather than overwriting one', () => {
    const vault = fresh()

    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: [], iterations: ROUNDS })

    assert.throws(
      () => vault.grant({ key: 'ci', passphrase: 'other', names: [], iterations: ROUNDS }),
      { message: 'sekreto: minivault: key already exists: ci' })
  })

  test('revoke drops a key, and a key cannot revoke itself', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })
    vault.revoke('ci')

    assert.deepEqual(vault.keys().map((k) => k.key), [MASTERKEY])
    assert.throws(() => openvault({ file: vault.file(), key: 'ci', passphrase: 'ci-pass' }).list(),
      { message: 'sekreto: minivault: no such key: ci' })

    assert.throws(() => vault.revoke(MASTERKEY),
      { message: 'sekreto: minivault: a key cannot revoke itself: master' })
    assert.throws(() => vault.revoke('nobody'),
      { message: 'sekreto: minivault: no such key: nobody' })
  })

  // Revoking bars the LIVE file; anyone who copied it keeps what they
  // had. Rotating is what takes a secret back, and the cost is stated
  // rather than hidden: every other key goes with it.
  test('rotate keeps the secrets and drops every other key', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.set('db.pass', 'hunter2')
    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })

    const before = readFileSync(vault.file())

    vault.rotate()

    assert.deepEqual(vault.list(), ['api.token', 'db.pass'])
    assert.equal(vault.get('api.token'), 'tok01')
    assert.deepEqual(vault.keys().map((k) => k.key), [MASTERKEY])

    assert.throws(() => openvault({ file: vault.file(), key: 'ci', passphrase: 'ci-pass' }).list(),
      { message: 'sekreto: minivault: no such key: ci' })

    // The ciphertext changed, which is the part that makes a copy of the
    // old file useless for anything written after this point.
    assert.notDeepEqual(readFileSync(vault.file()), before)

    // The master passphrase is unchanged: rotating is not a password
    // change, and saying so is cheaper than a support question.
    assert.equal(openvault({ file: vault.file(), passphrase: MASTER }).get('db.pass'), 'hunter2')
  })

  // --- refusals ------------------------------------------------------

  test('a wrong passphrase, an unknown key and a missing file all refuse', () => {
    const vault = fresh()
    vault.set('api.token', 'tok01')

    assert.throws(
      () => openvault({ file: vault.file(), passphrase: 'not it' }).get('api.token'),
      { message: 'sekreto: minivault: wrong passphrase for key master, or a damaged vault' })

    assert.throws(
      () => openvault({ file: vault.file(), key: 'ghost', passphrase: MASTER }).get('api.token'),
      { message: 'sekreto: minivault: no such key: ghost' })

    const gone = join(work, 'not-there.skmv')
    assert.throws(() => openvault({ file: gone, passphrase: MASTER }).get('api.token'),
      { message: 'sekreto: minivault: no vault file: ' + gone })
  })

  test('a damaged file is refused rather than read as a short one', () => {
    const vault = fresh()
    vault.set('api.token', 'tok01')

    const bytes = readFileSync(vault.file())

    const cut = join(work, 'cut.skmv')
    writeFileSync(cut, bytes.subarray(0, bytes.length - 20))
    assert.throws(() => openvault({ file: cut, passphrase: MASTER }).get('api.token'),
      { message: /truncated/ })

    const extra = join(work, 'extra.skmv')
    writeFileSync(extra, Buffer.concat([bytes, Buffer.from([0])]))
    assert.throws(() => openvault({ file: extra, passphrase: MASTER }).get('api.token'),
      { message: 'sekreto: minivault: the vault file has trailing bytes' })

    const wrong = join(work, 'wrong.skmv')
    writeFileSync(wrong, Buffer.from('not a vault at all, but long enough', 'utf8'))
    assert.throws(() => openvault({ file: wrong, passphrase: MASTER }).get('api.token'),
      { message: 'sekreto: minivault: not a vault file' })

    // A FLIPPED BIT IN THE CIPHERTEXT, which is what a GCM tag is for: a
    // vault that decrypts to something plausible would be worse than one
    // that refuses.
    const bent = Buffer.from(bytes)
    bent[bent.length - 1] ^= 0xff
    const damaged = join(work, 'damaged.skmv')
    writeFileSync(damaged, bent)
    assert.throws(() => openvault({ file: damaged, passphrase: MASTER }).get('api.token'),
      { message: /damaged/ })
  })

  test('creating over an existing vault is refused', () => {
    const vault = fresh()

    assert.throws(
      () => createvault({ file: vault.file(), passphrase: 'other', iterations: ROUNDS }),
      { message: 'sekreto: minivault: vault file already exists: ' + vault.file() })
  })

  test('a vault needs a file and a passphrase', () => {
    assert.throws(() => openvault({ file: '', passphrase: MASTER }),
      { message: 'sekreto: minivault: a vault needs a file' })
    assert.throws(() => openvault({ file: vaultpath(), passphrase: '' }),
      { message: 'sekreto: minivault: a vault needs a passphrase' })
  })

  // An EMPTY key is no key, so it means `master`. It is not a contrived
  // case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
  // expands to the empty string rather than to nothing at all. A port
  // whose null-coalescing operator answers for null alone - PHP's `??`,
  // Java's `null ==`, C#'s `??`, Kotlin's `?:` - reads it as a key id of
  // its own and refuses the handle.
  test('an empty key means the master key', () => {
    const vault = fresh()
    vault.set('api.token', 'tok01')

    assert.equal(openvault({ file: vault.file(), key: '', passphrase: MASTER }).get('api.token'),
      'tok01')
    assert.equal(openvault({ file: vault.file(), key: '', passphrase: MASTER }).open().key,
      'master')
  })

  test('create makes the file, and only when asked', () => {
    const file = vaultpath()

    const made = openvault({ file, passphrase: MASTER, iterations: ROUNDS, create: true })
    made.set('api.token', 'tok01')

    assert.equal(openvault({ file, passphrase: MASTER }).get('api.token'), 'tok01')
  })

  // --- the format, across ports ---------------------------------------

  // EVERY COMMITTED VAULT, not only this port's. A suite that reads only
  // the vault its own port wrote proves the reader agrees with the
  // writer beside it — which a port whose serializer and parser share a
  // mistake satisfies perfectly. The others were written by other ports,
  // so reading them here is the canonical checking somebody else's
  // bytes.
  for (const name of fixtures()) {
  test('the committed fixture reads, key by key: ' + name, () => {
    const file = fixture(name)

    const master = openvault({ file, passphrase: 'fixture-master' })
    assert.deepEqual(master.list(), ['api.token', 'db.pass', 'deep.nested.name'])
    assert.equal(master.get('api.token'), 'fixture-token')
    assert.equal(master.get('db.pass'), 'fixture-pass')
    assert.equal(master.get('deep.nested.name'), 'fixture-deep')

    assert.deepEqual(master.keys(), [
      { key: MASTERKEY, master: true, write: true, grants: [] },
      { key: 'reader', master: false, write: false, grants: ['api.token'] },
      { key: 'writer', master: false, write: true, grants: ['db.pass'] },
    ])

    const reader = openvault({ file, key: 'reader', passphrase: 'fixture-reader' })
    assert.deepEqual(reader.list(), ['api.token'])
    assert.equal(reader.get('api.token'), 'fixture-token')
    assert.equal(reader.get('db.pass'), undefined)

    const writer = openvault({ file, key: 'writer', passphrase: 'fixture-writer' })
    writer.set('db.pass', 'written by this port')
    assert.equal(master.get('db.pass'), 'written by this port')
  })
  }

  // --- the chain ------------------------------------------------------

  test('a vault is one store in a chain', async () => {
    const vault = fresh()
    vault.set('api.token', 'from the vault')

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [
        { kind: 'memory', values: { DB_PASS: 'from memory' } },
        { kind: 'minivault', file: vault.file(), passphrase: MASTER },
      ],
    })

    assert.equal(await secrets.get('api.token'), 'from the vault')
    assert.equal(await secrets.get('db.pass'), 'from memory')
    assert.equal(await secrets.getfrom('minivault', 'api.token'), 'from the vault')
    assert.deepEqual(secrets.sources(), ['memory', 'minivault:' + vault.file()])
    assert.deepEqual(secrets.stores(), ['memory', 'minivault'])
    assert.deepEqual(secrets.host.list(), { memory: 'live', minivault: 'live' })
  })

  test('a restricted key in a chain falls through on what it cannot read', async () => {
    const vault = fresh()
    vault.set('api.token', 'from the vault')
    vault.set('db.pass', 'vault password')
    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [
        { kind: 'minivault', file: vault.file(), vaultkey: 'ci', passphrase: 'ci-pass' },
        { kind: 'memory', values: { DB_PASS: 'the fallback' } },
      ],
    })

    assert.equal(await secrets.get('api.token'), 'from the vault')
    assert.equal(await secrets.get('db.pass'), 'the fallback')
    assert.equal(await secrets.tryfrom('minivault', 'db.pass'), undefined)
  })

  test('two vaults are two stores, each addressable', async () => {
    const one = fresh()
    one.set('api.token', 'first')
    const two = fresh()
    two.set('api.token', 'second')

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [
        { kind: 'minivault', name: 'app', file: one.file(), passphrase: MASTER },
        { kind: 'minivault', name: 'ops', file: two.file(), passphrase: MASTER },
      ],
    })

    assert.deepEqual(secrets.stores(), ['app', 'ops'])
    assert.deepEqual(Object.keys(secrets.host.list()), ['minivault$app', 'minivault$ops'])
    assert.equal(await secrets.getfrom('app', 'api.token'), 'first')
    assert.equal(await secrets.getfrom('ops', 'api.token'), 'second')
  })

  // --- the programmatic API -------------------------------------------

  // THE POINT OF THE EXPORT. A chain reads; a vault is also written to,
  // and voxgig/plugin's exports are how a definition publishes an API of
  // its own beside the provider the host asked it for.
  test('the vault behind a store is reachable as an API', async () => {
    const vault = fresh()
    vault.set('api.token', 'first')

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [{ kind: 'minivault', file: vault.file(), passphrase: MASTER }],
    })

    const api = vaultof(secrets)

    assert.equal(api.file(), vault.file())
    assert.deepEqual(api.list(), ['api.token'])

    api.set('added.here', 'through the host')
    api.grant({ key: 'ci', passphrase: 'ci-pass', names: ['added.here'], iterations: ROUNDS })

    // The file is what changed, so a chain built afterwards sees it.
    const after = new Sekreto({
      plugins: [minivault],
      providers: [{ kind: 'minivault', file: vault.file(), vaultkey: 'ci', passphrase: 'ci-pass' }],
    })

    assert.equal(await after.get('added.here'), 'through the host')
  })

  test('a named store is reached by name, and the alias by itself', () => {
    const vault = fresh()
    vault.set('api.token', 'first')

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [{ kind: 'minivault', name: 'app', file: vault.file(), passphrase: MASTER }],
    })

    assert.equal(vaultof(secrets, 'app').file(), vault.file())

    // One vault in the chain, whatever it is called: the unqualified
    // alias resolves it, which is voxgig/plugin's own export rule.
    assert.equal(vaultof(secrets).file(), vault.file())
  })

  test('two vaults make the unqualified alias ambiguous rather than lucky', () => {
    const one = fresh()
    const two = fresh()

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [
        { kind: 'minivault', name: 'app', file: one.file(), passphrase: MASTER },
        { kind: 'minivault', name: 'ops', file: two.file(), passphrase: MASTER },
      ],
    })

    assert.throws(() => vaultof(secrets), { code: 'plugin_export_ambiguous' })
    assert.equal(vaultof(secrets, 'ops').file(), two.file())
  })

  // NAMING A STORE THAT IS NOT THERE RAISES, which is the rule the whole
  // library follows. `host.exports` falls back to the unqualified alias
  // when an exact ref misses, so asking for `minivault` in a chain whose
  // only vault is named `app` used to hand back the `app` vault — and
  // then write to it.
  test('an explicit store name must exist rather than falling back', () => {
    const vault = fresh()
    vault.set('api.token', 'first')

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [{ kind: 'minivault', name: 'app', file: vault.file(), passphrase: MASTER }],
    })

    assert.throws(() => vaultof(secrets, 'minivault'),
      {
        name: 'SekretoError',
        message: 'sekreto: minivault: no minivault store named minivault in this chain',
      })
    assert.throws(() => vaultof(secrets, 'nosuchstore'),
      { message: 'sekreto: minivault: no minivault store named nosuchstore in this chain' })

    // The omitted argument still uses the alias, which is the whole
    // point of having one.
    assert.equal(vaultof(secrets).file(), vault.file())
    assert.equal(vaultof(secrets, 'app').file(), vault.file())
  })

  test('a chain that has no vault says so', () => {
    const secrets = new Sekreto({ providers: [{ kind: 'memory', values: {} }] })

    assert.throws(() => vaultof(secrets),
      { name: 'SekretoError', message: 'sekreto: minivault: no minivault store in this chain' })
  })

  // --- configuration --------------------------------------------------

  // A provider that refuses its own configuration raises a SekretoError
  // from inside `define`, and it must come back out of the host as
  // itself rather than wrapped as plugin_define_failed. The definition
  // is written out by hand rather than built by `providerplugin`,
  // because it publishes two exports, so this is the half of
  // `providerplugin` it has to reproduce.
  test('a chain missing the file or the passphrase is refused at construction', () => {
    let caught: any
    try {
      new Sekreto({ plugins: [minivault], providers: [{ kind: 'minivault' }] })
    } catch (err: any) {
      caught = err
    }

    assert.ok(caught instanceof SekretoError, 'not a SekretoError: ' + caught)
    assert.equal(caught.message, 'sekreto: minivault: a vault needs a file')

    assert.throws(
      () => new Sekreto({
        plugins: [minivault],
        providers: [{ kind: 'minivault', file: vaultpath() }],
      }),
      { name: 'SekretoError', message: 'sekreto: minivault: a vault needs a passphrase' })
  })

  // Nothing is opened at construction, which is what makes a chain with
  // a vault in it cost no key derivation until a secret is wanted - and
  // also means a missing file surfaces at the first lookup.
  test('the file is reached at the first lookup, never at construction', async () => {
    const file = vaultpath()

    const secrets = new Sekreto({
      plugins: [minivault],
      providers: [{ kind: 'minivault', file, passphrase: MASTER }],
    })

    assert.deepEqual(secrets.host.list(), { minivault: 'live' })

    await assert.rejects(() => secrets.get('api.token'),
      { name: 'SekretoError', message: 'sekreto: minivault: no vault file: ' + file })
  })

  // --- what a handle must not let a caller do -------------------------

  // A READ-ONLY KEY MUST STAY READ-ONLY. `set` asks `info.write` whether
  // this key may write, so handing a caller the object that answer lives
  // in let it flip its own permission: `vault.open().write = true` and a
  // key minted without write overwrote a granted secret.
  test('the key information a caller gets cannot change what the key may do', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.grant({ key: 'ro', passphrase: 'ro-pass', names: ['api.token'], iterations: ROUNDS })

    const readonly = openvault({ file: vault.file(), key: 'ro', passphrase: 'ro-pass' })

    const info = readonly.open()
    assert.equal(info.write, false)

    info.write = true
    info.master = true
    info.grants.push('db.pass')

    assert.throws(() => readonly.set('api.token', 'escalated'),
      { message: 'sekreto: minivault: key ro is read-only' })
    assert.throws(() => readonly.keys(),
      { message: /needs a master key/ })
    assert.equal(vault.get('api.token'), 'tok01')

    // ...and the next reading of it is unaffected by what was done to the
    // last one.
    assert.deepEqual(readonly.open(),
      { key: 'ro', master: false, write: false, grants: ['api.token'] })
  })

  // REVOKING BARS THE LIVE FILE, which is what this library tells people
  // it does. A handle that derived its keys once and never looked at the
  // file again kept answering from memory, so the promise held only for
  // a handle opened after the revoke.
  test('a revoked key stops reading, even from a handle that already read', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.grant({ key: 'ci', passphrase: 'ci-pass', names: ['api.token'], iterations: ROUNDS })

    const ci = openvault({ file: vault.file(), key: 'ci', passphrase: 'ci-pass' })
    assert.equal(ci.get('api.token'), 'tok01')

    vault.revoke('ci')

    assert.throws(() => ci.get('api.token'),
      { message: 'sekreto: minivault: no such key: ci' })
    assert.throws(() => ci.list(),
      { message: 'sekreto: minivault: no such key: ci' })
  })

  // The same id, re-granted under a different passphrase, is a different
  // key wearing the name. A cached ring would have kept the old one
  // working; the file's ring is what decides.
  test('a re-granted key id does not keep the old passphrase working', () => {
    const vault = fresh()

    vault.set('api.token', 'tok01')
    vault.grant({ key: 'ci', passphrase: 'first', names: ['api.token'], iterations: ROUNDS })

    const ci = openvault({ file: vault.file(), key: 'ci', passphrase: 'first' })
    assert.equal(ci.get('api.token'), 'tok01')

    vault.revoke('ci')
    vault.grant({ key: 'ci', passphrase: 'second', names: ['api.token'], iterations: ROUNDS })

    assert.throws(() => ci.get('api.token'),
      { message: 'sekreto: minivault: wrong passphrase for key ci, or a damaged vault' })

    assert.equal(
      openvault({ file: vault.file(), key: 'ci', passphrase: 'second' }).get('api.token'), 'tok01')
  })

  // A length the format cannot record. `small` writes one byte, so a
  // longer id wrapped it and the writer appended the whole thing anyway:
  // every field after it shifted, and a `grant` replaced a working vault
  // with an unreadable one without saying so.
  test('a key id longer than the format allows is refused', () => {
    const long = 'k'.repeat(256)

    assert.throws(
      () => createvault({ file: vaultpath(), key: long, passphrase: MASTER, iterations: ROUNDS }),
      { message: /key id is longer than 255 bytes/ })

    const vault = fresh()
    vault.set('api.token', 'tok01')

    assert.throws(
      () => vault.grant({ key: long, passphrase: 'p', names: [], iterations: ROUNDS }),
      { message: /key id is longer than 255 bytes/ })

    // The vault it would have destroyed is untouched.
    assert.equal(vault.get('api.token'), 'tok01')

    // 255 bytes is the limit, not 255 characters: a multi-byte id counts
    // its bytes.
    assert.throws(
      () => vault.grant({ key: 'é'.repeat(128), passphrase: 'p', names: [], iterations: ROUNDS }),
      { message: /key id is longer than 255 bytes/ })
  })

  test('close forgets the derived keys and the next call opens again', () => {
    const vault = fresh()
    vault.set('api.token', 'tok01')

    vault.close()

    assert.equal(vault.get('api.token'), 'tok01')
  })
})
