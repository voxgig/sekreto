// RUN: npm test
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
// passed in is not in the catalog, and a chain naming it is refused.
// That is the intended behaviour, and it means a consumer can be broken
// without a single conformance test noticing - the conformance suite
// passes every plugin, so it can never see a missing one.
//
// It happened immediately, in the previous shape of this split: the
// CLI's only reference to the full set was a TYPE import, which the
// compiler erased, and every kind but env and memory failed in the
// integration suite while `make test` stayed green. So the full set is
// pinned here: it holds every kind, every kind builds, and the CLI
// passes it as a value.

import { describe, test } from 'node:test'
import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { Sekreto, SekretoError, BUILTINS, KINDS, providerplugin } from '../src'
import { allplugins, hashicorp } from '../plugins'

const PLUGINS = [
  'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'gcpsecrets',
  'hashicorp', 'infisical', 'onepassword', 'secretspec',
]

const ALL = ['dotenv', 'env', 'file', 'memory'].concat(PLUGINS).sort()

describe('plugins', () => {

  test('the full set holds every plugin kind, and the core the rest', () => {
    assert.deepEqual(allplugins.map((d) => d.name).sort(), PLUGINS)
    assert.deepEqual(BUILTINS.map((d) => d.name), KINDS.builtin)
    assert.deepEqual(PLUGINS, [...KINDS.plugin].sort())
  })

  // Naming a kind is not enough: a kind can be in the catalog and still
  // fail to build. Construction is what the CLI does before any network.
  test('every kind builds from a spec', () => {
    const chain = ALL.map((kind) => ({
      kind, addr: 'http://127.0.0.1:8200', token: 't',
      dir: '/tmp', file: '/tmp/.env', values: {},
    }))

    const secrets = new Sekreto({ plugins: allplugins, providers: chain as any })

    assert.deepEqual(secrets.stores(), ALL)
    assert.deepEqual(Object.keys(secrets.host.list()).sort(), ALL)
    for (const status of Object.values(secrets.host.list())) {
      assert.equal(status, 'live')
    }
  })

  test('the CLI passes the full set as a value, not a type', () => {
    // This suite runs COMPILED, out of dist/test, so the package root is
    // two levels up - not one. Reading the TypeScript source is the point:
    // the defect being guarded is a type-only import, which exists in the
    // source and by definition is gone from the compiled output.
    const src = readFileSync(
      join(__dirname, '..', '..', 'cli', 'sekreto-cli.ts'), 'utf8')

    assert.ok(/^import \{ allplugins \} from '\.\.\/plugins'$/m.test(src),
      "sekreto-cli.ts must import { allplugins } from '../plugins' as a value")
    assert.ok(/plugins: allplugins/.test(src),
      'sekreto-cli.ts must pass allplugins to Sekreto')
  })

  // --- what a consumer sees -------------------------------------------

  test('one plugin is enough for a chain that names only it', async () => {
    const secrets = new Sekreto({
      plugins: [hashicorp],
      providers: [
        { kind: 'memory', values: { API_TOKEN: 'tok01' } },
        { kind: 'hashicorp', name: 'prod', addr: 'https://vault.example.com', token: 't' },
      ],
    })

    assert.deepEqual(secrets.stores(), ['memory', 'prod'])
    assert.deepEqual(secrets.sources(), ['memory', 'hashicorp:https://vault.example.com/secret'])
    assert.equal(await secrets.get('api.token'), 'tok01')

    // The plugin host is what the chain is made of, and it reads like
    // the chain: the kind, or kind$store for a named store.
    assert.deepEqual(secrets.host.list(), { memory: 'live', hashicorp$prod: 'live' })
    assert.deepEqual(secrets.catalog.names(), ['dotenv', 'env', 'file', 'hashicorp', 'memory'])
  })

  test('a kind that was not passed in is refused, naming the fix', () => {
    assert.throws(
      () => new Sekreto({ plugins: [hashicorp], providers: [{ kind: 'doppler', token: 't' }] }),
      {
        name: 'SekretoError',
        message:
          'sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)' +
          ' - doppler is a sekreto plugin, not built in: pass it in the plugins option',
      },
    )

    // A kind nobody ships is a typo, and gets no such hint.
    assert.throws(
      () => new Sekreto({ providers: [{ kind: 'vualt' } as any] }),
      { message: 'sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)' },
    )
  })

  // Two providers MAY share a store name - a directed read walks both,
  // and the spec pins it - but an instance ref may not, so the second
  // gets a numbered tag from the host and keeps its store name.
  test('a repeated store name keeps the store and numbers the instance', async () => {
    const secrets = new Sekreto({
      providers: [
        { kind: 'memory', values: {} },
        { kind: 'memory', values: { API_TOKEN: 'second' } },
        { kind: 'memory', name: 'pair', values: {} },
        { kind: 'memory', name: 'pair', values: { API_TOKEN: 'pair2' } },
      ],
    })

    assert.deepEqual(secrets.stores(), ['memory', 'pair'])
    assert.deepEqual(Object.keys(secrets.host.list()), ['memory', 'memory$1', 'memory$2', 'memory$pair'])
    assert.equal(await secrets.getfrom('memory', 'api.token'), 'second')
    assert.equal(await secrets.getfrom('pair', 'api.token'), 'pair2')
  })

  test('a store name must be a valid tag', () => {
    assert.throws(
      () => new Sekreto({ providers: [{ kind: 'memory', name: 'my store', values: {} }] }),
      { name: 'SekretoError', message: 'sekreto: invalid store name: my store' },
    )
  })

  // A provider that refuses its own configuration raises a SekretoError
  // from inside the plugin's `define`. The spec pins that message byte
  // for byte, so it must come back out of the host as itself - not
  // wrapped as plugin_define_failed, and not as a PluginError.
  test('a SekretoError raised in define comes back out as itself', () => {
    let caught: any
    try {
      new Sekreto({
        plugins: [hashicorp],
        providers: [{ kind: 'hashicorp', addr: 'http://127.0.0.1:1', token: 't', kv: 3 }],
      })
    } catch (err: any) {
      caught = err
    }

    assert.ok(caught instanceof SekretoError, 'not a SekretoError: ' + caught)
    assert.equal(caught.message, 'sekreto: hashicorp: unsupported kv version: 3')
  })

  // ...and any other error is not sekreto's to rewrite: it surfaces as
  // the host reports it, naming the instance and the cause.
  test("any other error raised in define is the host's report of it", () => {
    const broken = providerplugin('broken', () => { throw new TypeError('boom') })

    assert.throws(
      () => new Sekreto({ plugins: [broken], providers: [{ kind: 'broken' }] }),
      (err: any) => 'plugin_define_failed' === err.code && /boom/.test(err.message),
    )
  })

  test('a custom kind is one providerplugin call', async () => {
    const shouty = providerplugin('shouty', (spec) => ({
      lookup: (name: string) => (spec.values || {})[name.toUpperCase()],
      describe: () => 'shouty',
    }))

    const secrets = new Sekreto({
      plugins: [shouty],
      providers: [{ kind: 'shouty', values: { 'API.TOKEN': 'loud' } }],
    })

    assert.equal(await secrets.get('api.token'), 'loud')
    assert.deepEqual(secrets.host.list(), { shouty: 'live' })
  })

  // A plugin that names a built-in kind replaces it: that is how a host
  // substitutes an implementation, and never an accident, because the
  // four names are documented.
  test('a plugin may replace a built-in kind', async () => {
    const memory = providerplugin('memory', () => ({
      lookup: () => 'replaced',
      describe: () => 'memory',
    }))

    const secrets = new Sekreto({
      plugins: [memory],
      providers: [{ kind: 'memory', values: { API_TOKEN: 'original' } }],
    })

    assert.equal(await secrets.get('api.token'), 'replaced')
  })

  test('close tears the chain down and keeps redaction', async () => {
    const secrets = new Sekreto({
      providers: [{ kind: 'memory', values: { API_TOKEN: 'tok01' } }],
    })

    assert.equal(await secrets.get('api.token'), 'tok01')

    secrets.close()

    assert.deepEqual(secrets.host.list(), {})
    assert.deepEqual(secrets.stores(), [])
    assert.equal(await secrets.try('api.token'), undefined)
    assert.equal(secrets.redact('token=tok01'), 'token=[redacted]')
  })
})
