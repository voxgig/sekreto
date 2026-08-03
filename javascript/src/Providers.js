// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or undefined to mean "ask the next one". Nothing else about
// a provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault or a boru vault.
//
// A port of typescript/src/Providers.ts, which is canonical.

const { spawnSync } = require('node:child_process')
const { readFileSync } = require('node:fs')

// Sekreto.js requires this module lazily, so by the time any provider is
// built these names are all defined.
const { SekretoError, checkname, envkey, parsedotenv, vaultref } = require('./Sekreto')

/** Environment variables: `api.token` from `API_TOKEN`. */
function envprovider(prefix, source) {
  const env = source || process.env

  return {
    lookup: (name) => {
      const value = env[envkey(name, prefix)]
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'env' + (prefix ? ':' + prefix : ''),
  }
}

/** A `.env` file, read once, keyed exactly like the environment. */
function dotenvprovider(file, prefix) {
  let values

  const load = () => {
    if (undefined === values) {
      try {
        values = parsedotenv(readFileSync(file, 'utf8'))
      } catch (err) {
        // A missing .env file is not an error: it means "no secrets here".
        values = {}
      }
    }
    return values
  }

  return {
    lookup: (name) => load()[envkey(name, prefix)],
    describe: () => 'dotenv:' + file,
  }
}

/** Literal values, keyed like environment variables. The spec uses this
 * to test chain behaviour without touching the outside world. */
function memoryprovider(values, prefix) {
  return {
    lookup: (name) => values[envkey(name, prefix)],
    describe: () => 'memory' + (prefix ? ':' + prefix : ''),
  }
}

/** Refuse to send a Vault token in the clear.
 *
 * Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
 * convenience. Sending `X-Vault-Token` over http to anything but the local
 * machine puts both the token and the secret it fetches on the wire for
 * anyone on the path, so sekreto will not do it. Loopback stays allowed:
 * that is `vault server -dev` and this repo's own test harness. */
function checkaddr(addr) {
  if (addr.startsWith('https://')) {
    return
  }

  if (!addr.startsWith('http://')) {
    throw new SekretoError('sekreto: not an http(s) address: ' + addr)
  }

  const host = addr.slice('http://'.length).split('/')[0].split(':')[0]

  if ('localhost' === host || '127.0.0.1' === host || '::1' === host || '[::1]' === host) {
    return
  }

  throw new SekretoError('sekreto: refusing to send a token in plaintext to ' + addr + ' (use https)')
}

/** HashiCorp Vault, KV v2.
 *
 * `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
 * field of `data.data`. A 404 means "not here", which is a miss rather
 * than an error, so a vault can sit in a chain with fallbacks. */
function hashicorpprovider(addr, token, mount) {
  const usemount = mount || 'secret'

  return {
    lookup: async (name) => {
      checkaddr(addr)

      const ref = vaultref(name)
      const url = addr.replace(/\/$/, '') + '/v1/' + usemount + '/data/' + ref.path

      const res = await fetch(url, { headers: { 'X-Vault-Token': token } })

      if (404 === res.status) {
        return undefined
      }

      if (!res.ok) {
        throw new SekretoError('sekreto: hashicorp error: ' + res.status + ': ' + url)
      }

      const body = await res.json()
      const data = body && body.data && body.data.data

      const value = data ? data[ref.field] : undefined
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'hashicorp:' + addr + '/' + usemount,
  }
}

/** A boru vault (https://github.com/boru-lang/boru).
 *
 * boru keeps secrets in a local encrypted keyring and hands a value out
 * through its own CLI: `boru vault get --reveal <alias>` prints the secret
 * on stdout, and nothing else.
 *
 * There is deliberately no HTTP read here. boru's `vault proxy` and
 * `vault mcp` are a *credential broker*: they inject the real secret into
 * an outbound request and forward it, so an agent can call an API without
 * ever holding the credential. Handing a value back is the one thing that
 * broker is built not to do, so sekreto reads the vault the way boru
 * itself does - through the CLI.
 *
 * A sekreto name is already a valid boru alias, so `api.token` crosses over
 * unchanged. A `namespace` qualifies it the way boru writes it,
 * `<namespace>:<name>`.
 *
 * The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
 * sekreto never accepts it as config and never puts it on a command line,
 * where it would show up in the process table. */
function boruprovider(options) {
  const opts = options || {}
  const command = opts.command || 'boru'

  return {
    lookup: (name) => {
      checkname(name)

      const alias = opts.namespace ? opts.namespace + ':' + name : name
      const env = opts.home ? { ...process.env, BORU_HOME: opts.home } : process.env

      const run = spawnSync(command, ['vault', 'get', '--reveal', alias], {
        encoding: 'utf8',
        env,
      })

      if (run.error) {
        throw new SekretoError('sekreto: cannot run ' + command + ': ' + run.error.message)
      }

      if (0 === run.status) {
        // boru prints the value and one newline, and nothing else.
        return run.stdout.replace(/\n$/, '')
      }

      const why = (run.stderr || '').trim()

      // "no alias named" is boru saying it does not hold this secret, which
      // is a miss: the chain carries on to the next provider. A locked vault
      // or a wrong passphrase is not a miss - treating it as one would fall
      // through to a weaker store without saying so.
      if (borumiss(why)) {
        return undefined
      }

      throw new SekretoError('sekreto: boru vault error: ' + (why || 'exit ' + run.status))
    },
    describe: () => 'boru' + (opts.namespace ? ':' + opts.namespace : ''),
  }
}

/** Does this boru failure mean "no such secret" rather than "I could not
 * answer"? Matched on boru's own wording for a missing alias. */
function borumiss(why) {
  return /no alias named/.test(why)
}

/** Build a provider from its declarative form. */
function makeprovider(spec) {
  switch (spec.kind) {
    case 'env':
      return envprovider(spec.prefix)
    case 'dotenv':
      return dotenvprovider(spec.file || '.env', spec.prefix)
    case 'memory':
      return memoryprovider(spec.values || {}, spec.prefix)
    case 'hashicorp':
      return hashicorpprovider(spec.addr || '', spec.token || '', spec.mount)
    case 'boru':
      return boruprovider({
        command: spec.command,
        namespace: spec.namespace,
        home: spec.home,
      })
    default:
      throw new SekretoError('sekreto: unknown provider kind: ' + String(spec.kind))
  }
}

module.exports = {
  boruprovider,
  dotenvprovider,
  envprovider,
  makeprovider,
  memoryprovider,
  hashicorpprovider,
}
