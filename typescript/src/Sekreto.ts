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

function checkname(name: any): string {
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

/** The secrets facade: a chain of providers plus a cache. */
export class Sekreto {
  private providers: Provider[]
  private docache: boolean
  private cache: Map<string, string>

  constructor(options?: SekretoOptions) {
    const opts = options || {}
    this.providers = (opts.providers || []).map((entry) =>
      'function' === typeof (entry as Provider).lookup
        ? (entry as Provider)
        : makeprovider(entry as ProviderSpec),
    )
    this.docache = false === opts.cache ? false : true
    this.cache = new Map()
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
    checkname(name)

    if (this.docache && this.cache.has(name)) {
      return this.cache.get(name)
    }

    for (const provider of this.providers) {
      const found = await provider.lookup(name)

      if (undefined !== found && null !== found) {
        if (this.docache) {
          this.cache.set(name, found)
        }
        return found
      }
    }

    return undefined
  }

  /** Does any provider have this secret? */
  async has(name: Name): Promise<boolean> {
    return undefined !== (await this.try(name))
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
    return this.providers.map((provider) => provider.describe())
  }

  /** Replace every value this Sekreto has resolved with `[redacted]`. */
  redact(text: string): string {
    return redact(text, Array.from(this.cache.values()))
  }

  /** Drop cached values, so the next `get` asks the providers again. */
  refresh(): void {
    this.cache.clear()
  }
}

/** Make a Sekreto from options. */
export function sekreto(options?: SekretoOptions): Sekreto {
  return new Sekreto(options)
}
