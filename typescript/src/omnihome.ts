// Locate the sibling voxgig/omni checkout that drives the shared spec.
//
// sekreto's conformance tests are omni tests: the same spec/sekreto.json
// runs in every port. omni is not published yet, so the tests find it on
// disk - by $OMNI_HOME, or by looking where a checkout usually sits.

import { existsSync } from 'node:fs'
import { join } from 'node:path'

export function omnihome(marker = 'spec/fib.json'): string {
  const candidates = [
    process.env.OMNI_HOME,
    join(__dirname, '..', '..', '..', 'omni'),
    join(__dirname, '..', '..', '..', '..', 'omni'),
    '/workspace/omni',
    '/home/user/omni',
  ]

  for (const candidate of candidates) {
    if (candidate && existsSync(join(candidate, marker))) {
      return candidate
    }
  }

  throw new Error('sekreto: voxgig/omni not found - set OMNI_HOME')
}

export function specfile(name = 'sekreto.json'): string {
  let dir = __dirname

  for (let step = 0; step < 8; step++) {
    const cand = join(dir, 'spec', name)
    if (existsSync(cand)) {
      return cand
    }
    dir = join(dir, '..')
  }

  throw new Error('sekreto: spec not found: ' + name)
}
