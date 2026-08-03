// RUN: npm test
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.

import { before, describe, test } from 'node:test'

import { Sekreto, envkey, parsedotenv, redact, validname, vaultref } from '../src'
import { omnihome, specfile } from '../src/omnihome'

// omni is a sibling checkout, not a published package (yet), so it is
// required by path. The TypeScript port consumes omni's compiled output.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const omni = require(omnihome() + '/typescript/dist/src')

// Build a Sekreto from the spec's declarative chain description.
function chainof(spec: any): Sekreto {
  return new Sekreto({ providers: spec.chain, cache: false })
}

describe('sekreto', () => {
  let R: any

  before(async () => {
    const runner = await omni.makeRunner(specfile())
    R = await runner('sekreto')
  })

  test('validname', async () => {
    await R.runsetflags(R.spec.validname, { null: false }, (name: any) => validname(name))
  })

  test('envkey', async () => {
    await R.runset(R.spec.envkey, (vin: any) => envkey(vin.name, vin.prefix))
  })

  test('vaultref', async () => {
    await R.runset(R.spec.vaultref, (name: any) => vaultref(name))
  })

  test('parsedotenv', async () => {
    await R.runset(R.spec.parsedotenv, (text: any) => parsedotenv(text))
  })

  test('resolve', async () => {
    await R.runset(R.spec.resolve, (vin: any) => chainof(vin).get(vin.name))
  })

  test('trysecret', async () => {
    await R.runset(R.spec.trysecret, (vin: any) => chainof(vin).try(vin.name))
  })

  test('sources', async () => {
    await R.runset(R.spec.sources, (vin: any) => chainof(vin).sources())
  })

  test('redact', async () => {
    await R.runset(R.spec.redact, (vin: any) => redact(vin.text, vin.values))
  })
})
