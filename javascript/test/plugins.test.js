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
// canonical CLI's only reference to the full set was a TYPE import,
// which the compiler erased, and every kind but env and memory failed in
// the integration suite while `make test` stayed green. So the full set
// is pinned here: it holds every kind, every kind builds, and the CLI
// passes it as a value.
//
// A port of typescript/test/plugins.test.ts and python/tests/test_plugins.py.

const { describe, test } = require('node:test')
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const { readFileSync } = require('node:fs')
const { join, relative, sep } = require('node:path')

const { Sekreto, SekretoError, BUILTINS, KINDS, providerplugin } = require('../src')
const { allplugins } = require('../plugins')
const { hashicorp } = require('../plugins/hashicorp')

const PLUGINS = [
  'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'gcpsecrets',
  'hashicorp', 'infisical', 'onepassword', 'secretspec',
]

const ALL = ['dotenv', 'env', 'file', 'memory'].concat(PLUGINS).sort()

const PKG = join(__dirname, '..')

// What a require pulls in, measured in a FRESH process because this one
// has required everything above on purpose. The module graph is the real
// artifact in a language with no link step: `require.cache` is the list
// of files this program actually loaded.
function graph(code) {
  const out = execFileSync(
    process.execPath,
    ['-e', code + ';console.log(JSON.stringify(Object.keys(require.cache)))'],
    { cwd: PKG, encoding: 'utf8' },
  )

  return JSON.parse(out)
    .map((file) => relative(PKG, file))
    .filter((file) => !file.startsWith('..') && !file.startsWith('node_modules'))
    .map((file) => file.split(sep).join('/'))
    .sort()
}

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

    const secrets = new Sekreto({ plugins: allplugins, providers: chain })

    assert.deepEqual(secrets.stores(), ALL)
    assert.deepEqual(Object.keys(secrets.host.list()).sort(), ALL)
    for (const status of Object.values(secrets.host.list())) {
      assert.equal(status, 'live')
    }
  })

  test('the CLI passes the full set', () => {
    const src = readFileSync(join(PKG, 'cli', 'sekreto-cli.js'), 'utf8')

    assert.ok(/^const \{ allplugins \} = require\('\.\.\/plugins'\)$/m.test(src),
      "sekreto-cli.js must require { allplugins } from '../plugins'")
    assert.ok(/plugins: allplugins/.test(src),
      'sekreto-cli.js must pass allplugins to Sekreto')
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
      () => new Sekreto({ providers: [{ kind: 'vualt' }] }),
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
    assert.deepEqual(
      Object.keys(secrets.host.list()),
      ['memory', 'memory$1', 'memory$2', 'memory$pair'],
    )
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
    let caught
    try {
      new Sekreto({
        plugins: [hashicorp],
        providers: [{ kind: 'hashicorp', addr: 'http://127.0.0.1:1', token: 't', kv: 3 }],
      })
    } catch (err) {
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
      (err) => 'plugin_define_failed' === err.code && /boom/.test(err.message),
    )
  })

  test('a custom kind is one providerplugin call', async () => {
    const shouty = providerplugin('shouty', (spec) => ({
      lookup: (name) => (spec.values || {})[name.toUpperCase()],
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

  // --- the boundary, as the module graph sees it ------------------------

  // THE CORE REQUIRES NO PLUGIN. Not the module, not the full set, not a
  // name a bundler could follow: requiring the library loads the chain,
  // the built-ins and voxgig/plugin, and not one file under plugins/.
  test('the core requires no plugin', () => {
    const loaded = graph("require('./src')")

    assert.deepEqual(loaded, [
      'src/Sekreto.js',
      'src/index.js',
      'src/provider/addr.js',
      'src/provider/builtin.js',
      'src/provider/dotenv.js',
      'src/provider/env.js',
      'src/provider/file.js',
      'src/provider/memory.js',
      'src/provider/support.js',
    ])

    assert.deepEqual(loaded.filter((file) => file.startsWith('plugins/')), [],
      'requiring the core reached a plugin')
  })

  // ...and one plugin requires only itself. The full set is one file, and
  // a single-plugin require must not reach it: through the index, one
  // plugin makes every other reachable too - AWS request signing and
  // seven HTTP vault clients, for a consumer that named exactly one.
  test('one plugin requires only itself', () => {
    const loaded = graph("require('./plugins/hashicorp')")

    assert.deepEqual(loaded.filter((file) => file.startsWith('plugins/')),
      ['plugins/hashicorp.js', 'plugins/httpjson.js'])

    for (const other of ['index', 'aws', 'sigv4', 'boru', 'doppler', 'gcpsecrets',
                         'azuresecrets', 'onepassword', 'infisical', 'secretspec']) {
      assert.ok(!loaded.includes('plugins/' + other + '.js'),
        'requiring one plugin reached plugins/' + other + '.js')
    }
  })

  // The full set is built where it is asked for, and reaching it pulls in
  // everything - which is why it is a separate module and not the core's
  // business.
  test('the full set is built on demand', () => {
    const loaded = graph("require('./plugins')")

    for (const name of ['index', 'hashicorp', 'boru', 'aws', 'sigv4', 'gcpsecrets',
                        'azuresecrets', 'onepassword', 'doppler', 'infisical',
                        'secretspec', 'httpjson']) {
      assert.ok(loaded.includes('plugins/' + name + '.js'),
        'the full set did not pull in plugins/' + name + '.js')
    }
  })

  // `require('.../plugins/hashicorp')` is the MODULE, and in CommonJS the
  // module and the definition it holds are both plain objects - so a
  // module handed to `plugins` would fail deep inside voxgig/plugin with
  // a message about a definition name. Refused here, naming the
  // destructure that was meant.
  test('a module passed as a plugin is refused', () => {
    const module = require('../plugins/hashicorp')

    assert.equal(undefined, module.name)

    assert.throws(
      () => new Sekreto({ plugins: [module], providers: [] }),
      {
        name: 'SekretoError',
        message:
          'sekreto: not a plugin definition: a module holding hashicorp' +
          ' - destructure the definition it holds and pass that: plugins: [hashicorp]',
      },
    )

    // And anything that is not a definition at all says so plainly.
    assert.throws(
      () => new Sekreto({ plugins: ['hashicorp'], providers: [] }),
      { name: 'SekretoError', message: 'sekreto: not a plugin definition: hashicorp' },
    )
  })
})
