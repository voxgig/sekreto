// Locate the shared spec, walking up from this file. Test-only: the
// library never reads a spec, and nothing here ships in the package.

import { existsSync } from 'node:fs'
import { join } from 'node:path'

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
