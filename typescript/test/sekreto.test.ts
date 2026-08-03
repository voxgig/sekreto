// RUN: npm test
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.

import { before, describe, test } from 'node:test'

import { Sekreto, awsparam, envkey, flatname, parsedotenv, redact, sigv4, validname, vaultref } from '../src'
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

  test('flatname', async () => {
    await R.runset(R.spec.flatname, (vin: any) => flatname(vin.name, vin.sep))
  })

  test('awsparam', async () => {
    await R.runset(R.spec.awsparam, (vin: any) => awsparam(vin.name, vin.prefix))
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

  test('stores', async () => {
    await R.runset(R.spec.stores, (vin: any) => chainof(vin).stores())
  })

  test('getfrom', async () => {
    await R.runset(R.spec.getfrom, (vin: any) => chainof(vin).getfrom(vin.store, vin.name))
  })

  test('tryfrom', async () => {
    await R.runset(R.spec.tryfrom, (vin: any) => chainof(vin).tryfrom(vin.store, vin.name))
  })

  test('sigv4', async () => {
    await R.runset(R.spec.sigv4, (vin: any) => sigv4(vin))
  })

  test('redact', async () => {
    await R.runset(R.spec.redact, (vin: any) => redact(vin.text, vin.values))
  })
})
