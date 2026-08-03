// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or undefined to mean "ask the next one". Nothing else about
// a provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault or a boru vault.

import { readFileSync } from 'node:fs'

import { SekretoError, envkey, parsedotenv, vaultref } from './Sekreto'

export type Provider = {
  /** The value, or undefined if this provider does not have it. */
  lookup: (name: string) => Promise<string | undefined> | string | undefined
  /** A short description, shown by `Sekreto.sources()`. */
  describe: () => string
}

/** The declarative form of a provider, as used in config and in the
 * shared spec. */
export type ProviderSpec = {
  kind: 'env' | 'dotenv' | 'memory' | 'vault' | 'boru'
  prefix?: string
  /** dotenv: the file to read. */
  file?: string
  /** memory: literal values, keyed like environment variables. */
  values?: Record<string, string>
  /** vault/boru: the base URL, e.g. http://127.0.0.1:8200 */
  addr?: string
  /** vault/boru: the access token. */
  token?: string
  /** vault: the KV mount (default `secret`). */
  mount?: string
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

/** HashiCorp Vault, KV v2.
 *
 * `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
 * field of `data.data`. A 404 means "not here", which is a miss rather
 * than an error, so a vault can sit in a chain with fallbacks. */
export function vaultprovider(addr: string, token: string, mount?: string): Provider {
  const usemount = mount || 'secret'

  return {
    lookup: async (name: string) => {
      const ref = vaultref(name)
      const url = addr.replace(/\/$/, '') + '/v1/' + usemount + '/data/' + ref.path

      const res = await fetch(url, { headers: { 'X-Vault-Token': token } })

      if (404 === res.status) {
        return undefined
      }

      if (!res.ok) {
        throw new SekretoError('sekreto: vault error: ' + res.status + ': ' + url)
      }

      const body: any = await res.json()
      const data = body && body.data && body.data.data

      const value = data ? data[ref.field] : undefined
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'vault:' + addr + '/' + usemount,
  }
}

/** A boru vault.
 *
 * The boru vault protocol as sekreto uses it: a GET of
 * `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
 * answering `{"ok":true,"value":"..."}` when the secret exists and
 * `{"ok":false}` (or 404) when it does not.
 *
 * NOTE: this is the contract sekreto assumes, and what test/mockvault.js
 * implements. If the real boru vault differs, this is the one function to
 * change - callers never see it. */
export function boruprovider(addr: string, token: string): Provider {
  return {
    lookup: async (name: string) => {
      const ref = vaultref(name)
      const url =
        addr.replace(/\/$/, '') + '/vault/' + ref.path + '?field=' + encodeURIComponent(ref.field)

      const res = await fetch(url, { headers: { 'X-Boru-Token': token } })

      if (404 === res.status) {
        return undefined
      }

      if (!res.ok) {
        throw new SekretoError('sekreto: boru vault error: ' + res.status + ': ' + url)
      }

      const body: any = await res.json()

      if (!body || true !== body.ok) {
        return undefined
      }

      return undefined === body.value || null === body.value ? undefined : String(body.value)
    },
    describe: () => 'boru:' + addr,
  }
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
    case 'vault':
      return vaultprovider(spec.addr || '', spec.token || '', spec.mount)
    case 'boru':
      return boruprovider(spec.addr || '', spec.token || '')
    default:
      throw new SekretoError('sekreto: unknown provider kind: ' + String((spec as any).kind))
  }
}
