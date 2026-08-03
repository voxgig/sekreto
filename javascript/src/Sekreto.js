// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

// Providers.js needs the name helpers below, so it is required lazily -
// at the one point a provider is actually built - rather than at load
// time, which would see a half-built module.
function makeprovider(spec) {
  return require('./Providers').makeprovider(spec)
}

/** Anything sekreto refuses to do: a bad name, a missing secret, a
 * provider that could not be reached. */
class SekretoError extends Error {
  constructor(message) {
    super(message)
    this.name = 'SekretoError'
  }
}

const NAMEPART = /^[a-z0-9_]+$/

/** Is this a well-formed secret name? */
function validname(name) {
  if ('string' !== typeof name || 0 === name.length) {
    return false
  }

  for (const part of name.split('.')) {
    if (!NAMEPART.test(part)) {
      return false
    }
  }

  return true
}

function checkname(name) {
  if (!validname(name)) {
    throw new SekretoError('sekreto: invalid name: ' + String(null == name ? '' : name))
  }
  return name
}

/** The environment-variable key for a name: `api.token` -> `API_TOKEN`. */
function envkey(name, prefix) {
  checkname(name)
  return (prefix || '') + name.split('.').join('_').toUpperCase()
}

/** Where a name lives in a KV vault: `api.token` -> `api` / `token`.
 *
 * A single-segment name has no path of its own, so it becomes a secret of
 * that name with the conventional field `value`. */
function vaultref(name) {
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
function flatname(name, sep) {
  checkname(name)
  const flat = name.split('.').join(sep)
  return '-' === sep ? flat.split('_').join('-') : flat
}

/** The AWS SSM Parameter Store name for a name: dots become the path
 * hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
 * `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`. */
function awsparam(name, prefix) {
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
function parsedotenv(text) {
  const out = {}

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

function unescape(text) {
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
function redact(text, values) {
  let out = 'string' === typeof text ? text : ''

  for (const value of values || []) {
    if ('string' !== typeof value || 4 > value.length) {
      continue
    }
    out = out.split(value).join('[redacted]')
  }

  return out
}

/** The store name a provider answers to when its spec does not say.
 *
 * `describe()` opens with the provider's kind - `vault:...`, `dotenv:...`,
 * plain `env` - so the kind is the natural default, and a custom provider
 * gets a sensible name without having to implement anything extra. */
function storename(provider, spec) {
  if (spec && spec.name) {
    return spec.name
  }
  return provider.describe().split(':')[0]
}

/** The secrets facade: a chain of providers plus a cache.
 *
 * Two ways to read. `get` is transparent - it walks the chain and takes the
 * first hit, and the caller never learns which store answered. `getfrom` is
 * directed - it names the store, and only that store is asked. */
class Sekreto {
  constructor(options) {
    const opts = options || {}

    this.entries = (opts.providers || []).map((entry) => {
      if ('function' === typeof entry.lookup) {
        return { store: storename(entry), provider: entry }
      }

      const provider = makeprovider(entry)
      return { store: storename(provider, entry), provider }
    })

    this.docache = false === opts.cache ? false : true

    // A list, not a map: the store a value came from stays attached, and
    // redaction order does not vary between runs.
    this.cache = []
  }

  /** The secret, or a SekretoError if no provider has it. */
  async get(name) {
    const found = await this.try(name)

    if (undefined === found) {
      throw new SekretoError('sekreto: unknown secret: ' + name)
    }

    return found
  }

  /** The secret, or undefined if no provider has it. */
  async try(name) {
    return this.resolve('', name, this.entries)
  }

  /** The secret from one named store, or a SekretoError if that store does
   * not have it. */
  async getfrom(store, name) {
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
  async tryfrom(store, name) {
    const matching = this.entries.filter((entry) => entry.store === store)

    if (0 === matching.length) {
      throw new SekretoError('sekreto: unknown store: ' + store)
    }

    return this.resolve(store, name, matching)
  }

  async resolve(store, name, entries) {
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
        return found
      }
    }

    return undefined
  }

  /** Does any provider have this secret? */
  async has(name) {
    return undefined !== (await this.try(name))
  }

  /** Does this named store have this secret? */
  async hasin(store, name) {
    return undefined !== (await this.tryfrom(store, name))
  }

  /** Every named secret at once. Missing ones are an error. */
  async all(names) {
    const out = {}

    for (const name of names) {
      out[name] = await this.get(name)
    }

    return out
  }

  /** A description of each provider, in resolution order. */
  sources() {
    return this.entries.map((entry) => entry.provider.describe())
  }

  /** The name of each store that can be named by `getfrom`, in resolution
   * order and without repeats. */
  stores() {
    const out = []

    for (const entry of this.entries) {
      if (!out.includes(entry.store)) {
        out.push(entry.store)
      }
    }

    return out
  }

  /** Replace every value this Sekreto has resolved with `[redacted]`. */
  redact(text) {
    return redact(
      text,
      this.cache.map((entry) => entry.value),
    )
  }

  /** Drop cached values, so the next `get` asks the providers again. */
  refresh() {
    this.cache = []
  }
}

/** Make a Sekreto from options. */
function sekreto(options) {
  return new Sekreto(options)
}

module.exports = {
  Sekreto,
  SekretoError,
  awsparam,
  checkname,
  envkey,
  flatname,
  parsedotenv,
  redact,
  sekreto,
  validname,
  vaultref,
}
