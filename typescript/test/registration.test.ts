// WHAT THE CONFORMANCE SUITE CANNOT SEE.
//
// Splitting the providers into self-registering modules made a consumer's
// IMPORTS load-bearing: a kind nobody imports is not registered, and
// `makeprovider` rejects it. That is the intended behaviour, and it means a
// consumer can now be broken without a single unit test noticing.
//
// It happened immediately. The CLI's only reference to the barrel was
//
//     import { ProviderSpec } from '../src/Providers'
//
// which names a TYPE, so TypeScript erased it. The providers had been
// registered only because Sekreto.ts still reached the barrel itself;
// cutting that edge left the CLI with `env` and `memory` and failed 14 of
// the integration suite's 190 checks, in typescript alone, while
// `make test` stayed green.
//
// So these two tests guard the seam from both sides: the barrel registers
// everything, and the one consumer that needs everything imports it in a
// form the compiler keeps.

import { describe, test } from 'node:test'
import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import '../src/Providers'
import { kinds, makeprovider } from '../src/provider/Registry'

const KINDS = [
  'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'dotenv',
  'env', 'file', 'gcpsecrets', 'hashicorp', 'infisical', 'memory',
  'onepassword', 'secretspec',
]

describe('provider registration', () => {

  test('the full-set barrel registers every kind', () => {
    assert.deepEqual(kinds(), KINDS)
  })

  // Registration alone is not enough: a kind can be registered and still
  // fail to build. Construction is what the CLI does before any network.
  test('every registered kind constructs from a spec', () => {
    const failed: string[] = []
    for (const kind of KINDS) {
      try {
        makeprovider({
          kind, addr: 'http://127.0.0.1:8200', token: 't',
          dir: '/tmp', file: '/tmp/.env', values: {},
        } as any)
      }
      catch (err: any) {
        failed.push(kind + ': ' + err.message)
      }
    }
    assert.deepEqual(failed, [])
  })

  test('the CLI imports the barrel for its side effect, not as a type', () => {
    // This suite runs COMPILED, out of dist/test, so the package root is
    // two levels up — not one. Reading the TypeScript source is the point:
    // the defect being guarded is a type-only import, which exists in the
    // source and by definition is gone from the compiled output.
    const src = readFileSync(
      join(__dirname, '..', '..', 'cli', 'sekreto-cli.ts'), 'utf8')

    assert.ok(/^import '\.\.\/src\/Providers'$/m.test(src),
      "sekreto-cli.ts must carry a bare `import '../src/Providers'`. A " +
      'type-only import is erased by the compiler, so the CLI would ' +
      'register nothing and every kind but env and memory would fail')
  })
})
