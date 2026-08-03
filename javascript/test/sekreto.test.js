// RUN: npm test
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.

const { existsSync } = require('node:fs')
const { dirname, join } = require('node:path')
const { before, describe, test } = require('node:test')

const { Sekreto, envkey, parsedotenv, redact, validname, vaultref } = require('../src')

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

// omni is a sibling checkout, not a published package (yet), so it is
// required by path.
function omnihome() {
  const cands = [
    process.env.OMNI_HOME,
    join(__dirname, '..', '..', '..', 'omni'),
    join(__dirname, '..', '..', '..', '..', 'omni'),
    '/workspace/omni',
    '/home/user/omni',
  ]

  for (const cand of cands) {
    if (cand && existsSync(join(cand, 'spec', 'fib.json'))) {
      return cand
    }
  }

  throw new Error('sekreto: voxgig/omni not found - set OMNI_HOME')
}

const { makeRunner } = require(omnihome() + '/javascript/src')

// Build a Sekreto from the spec's declarative chain description.
function chainof(spec) {
  return new Sekreto({ providers: spec.chain, cache: false })
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

  test('redact', async () => {
    await R.runset(R.spec.redact, (vin) => redact(vin.text, vin.values))
  })
})
