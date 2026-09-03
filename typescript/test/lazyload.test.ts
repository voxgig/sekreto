// RUN: npm test
//
// Importing sekreto must not drag Node builtins into the module graph.
//
// `child_process`, `fs`, `path` and `crypto` were top-level imports of
// Providers.ts and Sigv4.ts, and Sekreto.ts imports Providers for
// makeprovider — so merely importing the library evaluated all four, for a
// caller who only ever used a `memory` or `env` provider. Any runtime
// lacking them failed at import time rather than at the point of use.
//
// This is asserted by SPYING ON THE LOADER rather than by reading the
// source, because the property that matters is a runtime one: what is
// actually pulled in, through however many levels of re-export.

/* eslint-disable @typescript-eslint/no-require-imports --
 * This file exists to observe MODULE LOADING, so it must load sekreto
 * itself through require(): an `import` is hoisted above the loader spy
 * and would be evaluated before the hook is installed, measuring nothing.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert'
import Module from 'node:module'
import { join } from 'node:path'

// NOTE: sekreto itself is deliberately NOT imported at the top of this
// file. It has to be loaded inside the spy, after the hook is installed.

const GUARDED = /^node:(fs|path|child_process|crypto)$/

const SRC = join(__dirname, '..', 'src')

// The two built-ins that read a file defer node:fs to their first
// lookup, so importing the core evaluates no builtin at all. Everything
// that opens a socket or spawns a process is not in the core in any form
// - it is a plugin under plugins/, and importing the core cannot reach
// it. That is the point of the split: deferring the builtin stopped the
// module being EVALUATED, but the code was still in the build. See
// docs/design/plugin-providers.md.
const FILE_PROVIDER = join(__dirname, '..', 'src', 'provider', 'file')

// Record every module request made while `fn` runs, then restore.
function loadsDuring(fn: () => void): string[] {
  const seen: string[] = []
  const mod: any = Module
  const original = mod._load

  mod._load = function (request: string, ...rest: any[]) {
    seen.push(request)
    return original.call(this, request, ...rest)
  }

  try {
    fn()
  } finally {
    mod._load = original
  }

  return seen
}

// Drop sekreto's own modules from the cache so the next require really
// re-evaluates them. Node builtins are not cleared (and need not be — the
// spy records the REQUEST, whether or not it hits a cache).
function uncache(): void {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(join(__dirname, '..', 'src'))) {
      delete require.cache[key]
    }
  }
}

describe('lazy node builtins', () => {
  test('importing sekreto loads no guarded builtin', () => {
    uncache()

    const seen = loadsDuring(() => {
      require(SRC)
    })

    assert.deepEqual(
      seen.filter((name) => GUARDED.test(name)),
      [],
      'importing sekreto pulled in a Node builtin at module-evaluation time',
    )
  })

  test('the library still works without them', () => {
    uncache()

    // The two providers a browser or restricted runtime can actually use.
    const { Sekreto } = require(SRC)
    const sekreto = new Sekreto({
      providers: [{ kind: 'memory', values: { API_TOKEN: 'tok01' } }],
    })

    assert.ok(null != sekreto)
  })

  // THE SPLIT'S OWN INVARIANT, and the one that actually keeps SDKs lean.
  //
  // Deferring the builtin (the tests above) stops the module being
  // EVALUATED; it does not stop the code being in the build, because a
  // bundler still resolves a require it can see. So the core surface must
  // not reach a plugin AT ALL - if `hashicorpprovider` is exported from
  // the core index again, every consumer carries an HTTP vault client
  // whether or not they configured one, and every consumer of the aws
  // kinds carries request signing.
  test('the core surface exposes no plugin', () => {
    uncache()

    const core = require(SRC)

    const plugins = [
      'hashicorpprovider', 'boruprovider', 'awssecretsprovider',
      'awsparamsprovider', 'gcpsecretsprovider', 'azuresecretsprovider',
      'onepasswordprovider', 'dopplerprovider', 'infisicalprovider',
      'secretspecprovider', 'sigv4', 'fetchjson', 'allplugins',
    ]

    const leaked = plugins.filter((name) => undefined !== core[name])
    assert.deepEqual(leaked, [],
      'these are reachable from the core surface, so every consumer ' +
      'carries them: ' + leaked.join(', '))

    // The four built-ins stay: they read at most a local file, and a
    // chain with nowhere to read from is not usable.
    assert.equal('function', typeof core.envprovider)
    assert.equal('function', typeof core.memoryprovider)
    assert.equal('function', typeof core.dotenvprovider)
    assert.equal('function', typeof core.fileprovider)
    assert.deepEqual(core.BUILTINS.map((d: any) => d.name), ['env', 'memory', 'dotenv', 'file'])
  })

  // The core's catalog holds the built-ins and nothing else, so a chain
  // naming a plugin kind that was not handed in is refused - by name,
  // and saying what to do about it.
  test('a plugin kind that was not passed in is unknown to the core', () => {
    uncache()

    const { Sekreto } = require(SRC)

    assert.throws(
      () => new Sekreto({ providers: [{ kind: 'hashicorp', addr: 'https://v', token: 't' }] }),
      {
        message:
          'sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)' +
          ' - hashicorp is a sekreto plugin, not built in: pass it in the plugins option',
      },
    )
  })


  // The other half of the claim: deferred, not removed. A provider that
  // genuinely needs a builtin must still get it when it runs.
  test('a file provider loads node:fs when it is actually used', async () => {
    uncache()

    const { fileprovider } = require(FILE_PROVIDER)

    // Construction alone must not load it...
    const atbuild = loadsDuring(() => {
      fileprovider('/nonexistent-sekreto-test')
    })
    assert.deepEqual(
      atbuild.filter((name) => GUARDED.test(name)),
      [],
      'constructing a provider loaded a builtin; the load should be deferred to lookup',
    )

    // ...but a lookup must. A missing directory is a MISS, not an error,
    // so this exercises the load without needing a real file.
    const provider = fileprovider('/nonexistent-sekreto-test')
    const atlookup = loadsDuring(() => {
      provider.lookup('api.token')
    })

    assert.ok(
      atlookup.some((name) => 'node:fs' === name),
      'a file lookup did not load node:fs — is it still reachable at all?',
    )
  })

  test('a file provider lookup still behaves the same', async () => {
    uncache()

    const { fileprovider } = require(FILE_PROVIDER)
    const provider = fileprovider('/nonexistent-sekreto-test')

    // Synchronous return preserved: this is why the loader uses require()
    // rather than an async dynamic import.
    const out = provider.lookup('api.token')

    assert.equal(out, undefined)
    assert.ok(!(out instanceof Promise), 'lookup became asynchronous')
  })
})
