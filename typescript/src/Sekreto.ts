// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// This file is CANONICAL. Every other port is a translation of it, and
// spec/sekreto.json is the behavioural contract they all run.

import {
  Provider,
  ProviderSpec,
  makeprovider,
} from './Providers'

/** A secret name: dot-separated lowercase segments, e.g. `api.token`. */
export type Name = string

export type SekretoOptions = {
  /** The provider chain, in resolution order. */
  providers?: (Provider | ProviderSpec)[]
  /** Cache resolved values (default: true). */
  cache?: boolean
}

/** Anything sekreto refuses to do: a bad name, a missing secret, a
 * provider that could not be reached. */
export class SekretoError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SekretoError'
  }
}

const NAMEPART = /^[a-z0-9_]+$/

/** Is this a well-formed secret name? */
export function validname(name: any): boolean {
  if ('string' !== typeof name || 0 === name.length) {
    return false
  }

  const parts = name.split('.')

  for (const part of parts) {
    if (!NAMEPART.test(part)) {
      return false
    }
  }

  return true
}

export function checkname(name: any): string {
  if (!validname(name)) {
    throw new SekretoError('sekreto: invalid name: ' + String(null == name ? '' : name))
  }
  return name
}

/** The environment-variable key for a name: `api.token` -> `API_TOKEN`. */
export function envkey(name: Name, prefix?: string): string {
  checkname(name)
  return (prefix || '') + name.split('.').join('_').toUpperCase()
}

/** Where a name lives in a KV vault: `api.token` -> `api` / `token`.
 *
 * A single-segment name has no path of its own, so it becomes a secret of
 * that name with the conventional field `value`. */
export function vaultref(name: Name): { path: string; field: string } {
  checkname(name)

  const parts = name.split('.')

  if (1 === parts.length) {
    return { path: parts[0], field: 'value' }
  }

  return { path: parts.slice(0, -1).join('/'), field: parts[parts.length - 1] }
}

/** A name flattened to one segment: `api.token` -> `api_token` (GCP
 * Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).
 *
 * Those stores have no path hierarchy and reject dots in ids, so the
 * dots become the store's conventional separator. With `-` as the
 * separator, underscores flatten too: Azure Key Vault's alphabet is
 * letters, digits and hyphens only, and a valid sekreto name like
 * `with_underscore` must still be representable there. (The resulting
 * `.`/`_` collision mirrors the documented envkey behaviour, where
 * both already map to `_`.) */
export function flatname(name: Name, sep: string): string {
  checkname(name)
  const flat = name.split('.').join(sep)
  return '-' === sep ? flat.split('_').join('-') : flat
}

/** The AWS SSM Parameter Store name for a name: dots become the path
 * hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
 * `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`. */
export function awsparam(name: Name, prefix?: string): string {
  checkname(name)

  let base = prefix || ''
  if ('' !== base && !base.startsWith('/')) {
    base = '/' + base
  }
  base = base.replace(/\/$/, '')

  return base + '/' + name.split('.').join('/')
}

/** Parse `.env` text into a map of raw keys to values.
 *
 * Deliberately small: `KEY=value`, optional `export`, `#` comments on their
 * own line, and single- or double-quoted values (double quotes also
 * unescape `\n`, `\r`, `\t` and `\\`). A line with no `=` is skipped. */
export function parsedotenv(text: string): Record<string, string> {
  const out: Record<string, string> = {}

  if ('string' !== typeof text) {
    return out
  }

  for (const rawline of text.split('\n')) {
    const line = rawline.replace(/\r$/, '').trim()

    if (0 === line.length || line.startsWith('#')) {
      continue
    }

    const body = line.startsWith('export ') ? line.slice(7).trim() : line

    const eq = body.indexOf('=')
    if (0 >= eq) {
      continue
    }

    const key = body.slice(0, eq).trim()
    let value = body.slice(eq + 1).trim()

    if (2 <= value.length && value.startsWith('"') && value.endsWith('"')) {
      value = unescape(value.slice(1, -1))
    } else if (2 <= value.length && value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1)
    }

    out[key] = value
  }

  return out
}

function unescape(text: string): string {
  let out = ''

  for (let index = 0; index < text.length; index++) {
    if ('\\' === text[index] && index + 1 < text.length) {
      const next = text[index + 1]
      index++
      if ('n' === next) {
        out += '\n'
      } else if ('r' === next) {
        out += '\r'
      } else if ('t' === next) {
        out += '\t'
      } else if ('\\' === next) {
        out += '\\'
      } else if ('"' === next) {
        out += '"'
      } else {
        out += '\\' + next
      }
    } else {
      out += text[index]
    }
  }

  return out
}

/** Replace known secret values in text with `[redacted]`.
 *
 * Only values of four characters or more are replaced: shorter ones are
 * too likely to appear in ordinary text, and redacting them would make
 * logs unreadable without making them safer. */
export function redact(text: string, values: string[]): string {
  let out = 'string' === typeof text ? text : ''

  for (const value of values || []) {
    if ('string' !== typeof value || 4 > value.length) {
      continue
    }
    out = out.split(value).join('[redacted]')
  }

  return out
}

/** One provider in the chain, under the store name it answers to. */
type Entry = { store: string; provider: Provider }

/** One resolved value. Kept as a list rather than a map so that the store
 * a value came from stays attached, and so redaction order is stable. */
type Cached = { store: string; name: Name; value: string }

/** The store name a provider answers to when its spec does not say.
 *
 * `describe()` opens with the provider's kind - `vault:...`, `dotenv:...`,
 * plain `env` - so the kind is the natural default, and a custom provider
 * gets a sensible name without having to implement anything extra. */
function storename(provider: Provider, spec?: ProviderSpec): string {
  if (spec && spec.name) {
    return spec.name
  }
  return provider.describe().split(':')[0]
}

/** The secrets facade: a chain of providers plus a cache.
 *
 * Two ways to read. `get` is transparent - it walks the chain and takes
 * the first hit, and the caller never learns which store answered. `getfrom`
 * is directed - it names the store, and only that store is asked. Use the
 * first for ordinary configuration, the second when *which* store holds a
 * secret is part of what you mean. */
export class Sekreto {
  private entries: Entry[]
  private docache: boolean
  private cache: Cached[]
  // Every value ever resolved, for redact(). Kept independently of the
  // read cache so that redaction still works when cache is off - otherwise
  // `cache: false` would silently disable redact() and leak secrets to logs.
  private seen: string[]

  constructor(options?: SekretoOptions) {
    const opts = options || {}

    this.entries = (opts.providers || []).map((entry) => {
      if ('function' === typeof (entry as Provider).lookup) {
        const provider = entry as Provider
        return { store: storename(provider), provider }
      }

      const spec = entry as ProviderSpec
      const provider = makeprovider(spec)
      return { store: storename(provider, spec), provider }
    })

    this.docache = false === opts.cache ? false : true
    this.cache = []
    this.seen = []
  }

  /** The secret, or a SekretoError if no provider has it. */
  async get(name: Name): Promise<string> {
    const found = await this.try(name)

    if (undefined === found) {
      throw new SekretoError('sekreto: unknown secret: ' + name)
    }

    return found
  }

  /** The secret, or undefined if no provider has it. */
  async try(name: Name): Promise<string | undefined> {
    return this.resolve('', name, this.entries)
  }

  /** The secret from one named store, or a SekretoError if that store does
   * not have it. */
  async getfrom(store: string, name: Name): Promise<string> {
    const found = await this.tryfrom(store, name)

    if (undefined === found) {
      throw new SekretoError('sekreto: unknown secret: ' + store + ':' + name)
    }

    return found
  }

  /** The secret from one named store, or undefined if that store does not
   * have it.
   *
   * Naming a store that is not in the chain is an error, not a miss: `try`
   * already means "this store may not have it", so it cannot also mean
   * "this store may not exist" without hiding a typo. */
  async tryfrom(store: string, name: Name): Promise<string | undefined> {
    const matching = this.entries.filter((entry) => entry.store === store)

    if (0 === matching.length) {
      throw new SekretoError('sekreto: unknown store: ' + store)
    }

    return this.resolve(store, name, matching)
  }

  private async resolve(
    store: string,
    name: Name,
    entries: Entry[],
  ): Promise<string | undefined> {
    checkname(name)

    if (this.docache) {
      const hit = this.cache.find((entry) => entry.store === store && entry.name === name)
      if (undefined !== hit) {
        return hit.value
      }
    }

    for (const entry of entries) {
      const found = await entry.provider.lookup(name)

      if (undefined !== found && null !== found) {
        if (this.docache) {
          this.cache.push({ store, name, value: found })
        }
        this.seen.push(found)
        return found
      }
    }

    return undefined
  }

  /** Does any provider have this secret? */
  async has(name: Name): Promise<boolean> {
    return undefined !== (await this.try(name))
  }

  /** Does this named store have this secret? */
  async hasin(store: string, name: Name): Promise<boolean> {
    return undefined !== (await this.tryfrom(store, name))
  }

  /** Every named secret at once. Missing ones are an error. */
  async all(names: Name[]): Promise<Record<string, string>> {
    const out: Record<string, string> = {}

    for (const name of names) {
      out[name] = await this.get(name)
    }

    return out
  }

  /** A description of each provider, in resolution order. */
  sources(): string[] {
    return this.entries.map((entry) => entry.provider.describe())
  }

  /** The name of each store that can be named by `getfrom`, in resolution
   * order and without repeats. */
  stores(): string[] {
    const out: string[] = []

    for (const entry of this.entries) {
      if (!out.includes(entry.store)) {
        out.push(entry.store)
      }
    }

    return out
  }

  /** Replace every value this Sekreto has resolved with `[redacted]`.
   *
   * Works whether or not caching is enabled: the redaction list is kept
   * independently of the read cache. */
  redact(text: string): string {
    return redact(text, this.seen)
  }

  /** Drop cached values, so the next `get` asks the providers again. */
  refresh(): void {
    this.cache = []
  }
}

/** Make a Sekreto from options. */
export function sekreto(options?: SekretoOptions): Sekreto {
  return new Sekreto(options)
}
