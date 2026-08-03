// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or undefined to mean "ask the next one". Nothing else about
// a provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault or a boru vault.

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

import { SekretoError, checkname, envkey, parsedotenv, vaultref } from './Sekreto'

export type Provider = {
  /** The value, or undefined if this provider does not have it. */
  lookup: (name: string) => Promise<string | undefined> | string | undefined
  /** A short description, shown by `Sekreto.sources()`. */
  describe: () => string
}

/** The declarative form of a provider, as used in config and in the
 * shared spec. */
export type ProviderSpec = {
  kind: 'env' | 'dotenv' | 'memory' | 'hashicorp' | 'boru'
  /** The store name `Sekreto.getfrom` addresses. Defaults to `kind`. */
  name?: string
  prefix?: string
  /** dotenv: the file to read. */
  file?: string
  /** memory: literal values, keyed like environment variables. */
  values?: Record<string, string>
  /** hashicorp: the base URL, e.g. http://127.0.0.1:8200 */
  addr?: string
  /** hashicorp: the access token. */
  token?: string
  /** hashicorp: the KV mount (default `secret`). */
  mount?: string
  /** boru: the executable to run (default `boru`). */
  command?: string
  /** boru: the namespace qualifying the alias. */
  namespace?: string
  /** boru: the vault home, passed as BORU_HOME. */
  home?: string
}

/** Environment variables: `api.token` from `API_TOKEN`. */
export function envprovider(prefix?: string, source?: Record<string, any>): Provider {
  const env = source || process.env

  return {
    lookup: (name: string) => {
      const value = env[envkey(name, prefix)]
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'env' + (prefix ? ':' + prefix : ''),
  }
}

/** A `.env` file, read once, keyed exactly like the environment. */
export function dotenvprovider(file: string, prefix?: string): Provider {
  let values: Record<string, string> | undefined

  const load = () => {
    if (undefined === values) {
      try {
        values = parsedotenv(readFileSync(file, 'utf8'))
      } catch (err: any) {
        // A missing .env file is not an error: it means "no secrets here".
        values = {}
      }
    }
    return values
  }

  return {
    lookup: (name: string) => load()[envkey(name, prefix)],
    describe: () => 'dotenv:' + file,
  }
}

/** Literal values, keyed like environment variables. The spec uses this
 * to test chain behaviour without touching the outside world. */
export function memoryprovider(values: Record<string, string>, prefix?: string): Provider {
  return {
    lookup: (name: string) => values[envkey(name, prefix)],
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
export function checkaddr(addr: string): void {
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
export function hashicorpprovider(addr: string, token: string, mount?: string): Provider {
  const usemount = mount || 'secret'

  return {
    lookup: async (name: string) => {
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

      const body: any = await res.json()
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
 * A sekreto name is already a valid boru alias (a boru segment allows
 * letters, digits, dot, dash and underscore), so `api.token` crosses over
 * unchanged. A `namespace` qualifies it the way boru writes it,
 * `<namespace>:<name>`.
 *
 * The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
 * sekreto never accepts it as config and never puts it on a command line,
 * where it would show up in the process table. */
export function boruprovider(options?: {
  command?: string
  namespace?: string
  home?: string
}): Provider {
  const opts = options || {}
  const command = opts.command || 'boru'

  return {
    lookup: (name: string) => {
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
function borumiss(why: string): boolean {
  return /no alias named/.test(why)
}

/** Build a provider from its declarative form. */
export function makeprovider(spec: ProviderSpec): Provider {
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
      throw new SekretoError('sekreto: unknown provider kind: ' + String((spec as any).kind))
  }
}
