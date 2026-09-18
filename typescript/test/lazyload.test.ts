
/* eslint-disable @typescript-eslint/no-require-imports --
 * This file exists to observe MODULE LOADING, so it must load sekreto
 * itself through require(): an `import` is hoisted above the loader spy
 * and would be evaluated before the hook is installed, measuring nothing.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert'
import Module from 'node:module'
import { join } from 'node:path'


const GUARDED = /^node:(fs|path|child_process|crypto)$/

const SRC = join(__dirname, '..', 'src')

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

    const { Sekreto } = require(SRC)
    const sekreto = new Sekreto({
      providers: [{ kind: 'memory', values: { API_TOKEN: 'tok01' } }],
    })

    assert.ok(null != sekreto)
  })

  test('the core surface exposes no plugin', () => {
    uncache()

    const core = require(SRC)

    const plugins = [
      'hashicorpprovider', 'boruprovider', 'awssecretsprovider',
      'awsparamsprovider', 'gcpsecretsprovider', 'azuresecretsprovider',
      'onepasswordprovider', 'dopplerprovider', 'infisicalprovider',
      'secretspecprovider', 'sigv4', 'fetchjson', 'allplugins',
      'minivaultprovider', 'openvault', 'createvault', 'vaultof',
    ]

    const leaked = plugins.filter((name) => undefined !== core[name])
    assert.deepEqual(leaked, [],
      'these are reachable from the core surface, so every consumer ' +
      'carries them: ' + leaked.join(', '))

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

    const out = provider.lookup('api.token')

    assert.equal(out, undefined)
    assert.ok(!(out instanceof Promise), 'lookup became asynchronous')
  })
})
