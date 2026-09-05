// RUN: npm test
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.

const { existsSync } = require('node:fs')
const { dirname, join } = require('node:path')
const { before, describe, test } = require('node:test')

const {
  Sekreto,
  awsparam,
  envkey,
  flatname,
  parsedotenv,
  redact,
  validname,
  vaultref,
} = require('../src')

// THE CONFORMANCE SUITE LOADS EVERY PLUGIN, deliberately.
//
// `spec/sekreto.json` is the contract for the whole library and exercises
// all fourteen provider kinds, so this suite hands the full set to every
// Sekreto it builds. That is not a leak of the core/plugin split - it is
// the split working: a CONSUMER passes the kinds it configures and
// carries nothing else, while the suite that proves all fourteen behave
// has to have all fourteen. `lazyload.test.js` and `plugins.test.js` pin
// the other half, that the core surface reaches none of them.
//
// `sigv4` lives with the aws plugin - it is the crypto edge, and only
// the two aws kinds use it (docs/design/plugin-providers.md).
const { allplugins, sigv4 } = require('../plugins')

// Find the shared spec directory by walking up from this file.
function specfile(name) {
  let dir = __dirname
  for (let i = 0; i < 8; i++) {
    const cand = join(dir, 'spec', name)
    if (existsSync(cand)) {
      return cand
    }
    dir = dirname(dir)
  }
  throw new Error('sekreto: spec not found: ' + name)
}

// omni from npm, as a devDependency - which is omni's own isolation device
// for a Node consumer: npm never installs a devDependency transitively, so
// nothing that depends on @voxgig/sekreto-js can acquire the runner through
// it (omni register 4.13). The other ports take a checkout; see AGENTS.md.
const { makeRunner } = require('@voxgig/omni-js')

// Build a Sekreto from the spec's declarative chain description.
function chainof(spec) {
  return new Sekreto({ plugins: allplugins, providers: spec.chain, cache: false })
}

describe('sekreto', () => {
  let R

  before(async () => {
    const runner = await makeRunner(specfile('sekreto.json'))
    R = await runner('sekreto')
  })

  test('validname', async () => {
    await R.runsetflags(R.spec.validname, { null: false }, (name) => validname(name))
  })

  test('envkey', async () => {
    await R.runset(R.spec.envkey, (vin) => envkey(vin.name, vin.prefix))
  })

  test('vaultref', async () => {
    await R.runset(R.spec.vaultref, (name) => vaultref(name))
  })

  test('flatname', async () => {
    await R.runset(R.spec.flatname, (vin) => flatname(vin.name, vin.sep))
  })

  test('awsparam', async () => {
    await R.runset(R.spec.awsparam, (vin) => awsparam(vin.name, vin.prefix))
  })

  test('parsedotenv', async () => {
    await R.runset(R.spec.parsedotenv, (text) => parsedotenv(text))
  })

  test('resolve', async () => {
    await R.runset(R.spec.resolve, (vin) => chainof(vin).get(vin.name))
  })

  test('trysecret', async () => {
    await R.runset(R.spec.trysecret, (vin) => chainof(vin).try(vin.name))
  })

  test('sources', async () => {
    await R.runset(R.spec.sources, (vin) => chainof(vin).sources())
  })

  test('stores', async () => {
    await R.runset(R.spec.stores, (vin) => chainof(vin).stores())
  })

  test('getfrom', async () => {
    await R.runset(R.spec.getfrom, (vin) => chainof(vin).getfrom(vin.store, vin.name))
  })

  test('tryfrom', async () => {
    await R.runset(R.spec.tryfrom, (vin) => chainof(vin).tryfrom(vin.store, vin.name))
  })

  test('sigv4', async () => {
    await R.runset(R.spec.sigv4, (vin) => sigv4(vin))
  })

  test('redact', async () => {
    await R.runset(R.spec.redact, (vin) => redact(vin.text, vin.values))
  })
})
