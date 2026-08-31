// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or undefined to mean "ask the next one". Nothing else about
// a provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that
// does not hold the secret is a MISS (undefined) - the chain carries on.
// A store that could not answer - bad credentials, unreachable host,
// missing configuration - is an ERROR: falling through there would
// quietly reach for a weaker store.

import {
  SekretoError,
  awsparam,
  checkname,
  envkey,
  flatname,
  parsedotenv,
  vaultref,
} from './Sekreto'
import { sigv4 } from './Sigv4'

// NODE BUILTINS, LOADED ON FIRST USE.
//
// These were top-level imports, which made them a side effect of importing
// sekreto AT ALL: `child_process`, `fs` and `path` entered the module graph
// for a caller who only ever used a `memory` or `env` provider, and any
// runtime lacking them failed at import time rather than at the point of
// use. Sekreto.ts imports makeprovider from this module, so the chain
// reached everything.
//
// A plain require(), not `await import()`: dotenvprovider, fileprovider and
// boruprovider all have SYNCHRONOUS lookups, and making them async to
// accommodate a dynamic import would change observable behaviour for anyone
// calling a provider directly. The package is CommonJS ("type":
// "commonjs"), so require is available and synchronous.
//
// What this buys and what it does not: the builtins are no longer evaluated
// at import time, so importing sekreto is safe in a runtime that lacks them
// and a bundler can drop an unreachable provider along with its edge. It is
// NOT by itself a complete browser story — a bundler still resolves a
// require it can see statically, so a browser build wants conditional
// exports ("browser" field) as well. That is a packaging change, tracked
// separately.
const nodemods: Record<string, any> = {}

function nodemod<T = any>(name: string): T {
  let mod = nodemods[name]

  if (undefined === mod) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      mod = nodemods[name] = require(name)
    } catch (err: any) {
      throw new SekretoError(
        'sekreto: this provider needs ' +
          name +
          ', which this runtime does not provide: ' +
          err.message,
      )
    }
  }

  return mod as T
}

export type Provider = {
  /** The value, or undefined if this provider does not have it. */
  lookup: (name: string) => Promise<string | undefined> | string | undefined
  /** A short description, shown by `Sekreto.sources()`. */
  describe: () => string
}

/** The declarative form of a provider, as used in config and in the
 * shared spec. */
export type ProviderSpec = {
  kind:
    | 'env'
    | 'dotenv'
    | 'memory'
    | 'file'
    | 'hashicorp'
    | 'boru'
    | 'awssecrets'
    | 'awsparams'
    | 'gcpsecrets'
    | 'azuresecrets'
    | 'onepassword'
    | 'doppler'
    | 'infisical'
    | 'secretspec'
  /** The store name `Sekreto.getfrom` addresses. Defaults to `kind`. */
  name?: string
  prefix?: string
  /** dotenv: the file to read. */
  file?: string
  /** memory: literal values, keyed like environment variables. */
  values?: Record<string, string>
  /** file: the directory of one-secret-per-file entries. */
  dir?: string
  /** hashicorp / boru (wire) / gcp / 1password / doppler / infisical:
   * the base URL. */
  addr?: string
  /** hashicorp / boru (wire) / gcp / azure / 1password / doppler /
   * infisical: the access token. */
  token?: string
  /** hashicorp / boru (wire): the KV mount (default `secret`). */
  mount?: string
  /** hashicorp: KV engine version, 1 or 2 (default 2). */
  kv?: number
  /** hashicorp: Vault Enterprise namespace (X-Vault-Namespace). */
  vaultnamespace?: string
  /** hashicorp: log in for a token instead of being handed one. */
  auth?: {
    method: 'kubernetes' | 'approle'
    /** The auth mount, defaulting to the method name. */
    mount?: string
    /** kubernetes: the Vault role to log in as. */
    role?: string
    /** kubernetes: the service-account JWT itself (tests). */
    jwt?: string
    /** kubernetes: where the JWT lives; the conventional pod path by
     * default. */
    jwtfile?: string
    /** approle: the role and secret ids. */
    roleid?: string
    secretid?: string
  }
  /** boru / secretspec: the executable to run (default: the kind's own
   * name). */
  command?: string
  /** secretspec: the profile to read (`--profile`). */
  profile?: string
  /** secretspec: which of ITS backends to read from (`--provider`), e.g.
   * `keyring` or `dotenv://.env`. Named `backend` here because
   * `provider` already means a sekreto provider. */
  backend?: string
  /** secretspec: the audit reason recorded for the read (`--reason`).
   * SecretSpec refuses to read without one. */
  reason?: string
  /** boru: the namespace qualifying the alias. */
  namespace?: string
  /** boru: the vault home, passed as BORU_HOME. */
  home?: string
  /** aws: region and credentials; the standard AWS_* environment
   * variables fill whichever are not given. */
  region?: string
  keyid?: string
  secret?: string
  session?: string
  /** gcp / doppler / infisical: the project (GCP project id, Doppler
   * project slug, Infisical workspace id). */
  project?: string
  /** azure: the Key Vault name or full URL. 1password: the vault name
   * or id. */
  vault?: string
  /** azure: client-credential login. infisical: universal-auth login
   * (tenant is Azure-only). */
  tenant?: string
  clientid?: string
  clientsecret?: string
  /** azure: where to log in / where IMDS answers. gcp: where the
   * metadata server answers. Overridable for tests and for clouds with
   * nonstandard endpoints. */
  loginaddr?: string
  imdsaddr?: string
  metadataaddr?: string
  /** azure: the Key Vault API version (default 7.4). */
  apiversion?: string
  /** doppler: the config slug (with `project`). */
  config?: string
  /** infisical: the environment slug and secret path. */
  environment?: string
  path?: string
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
        const { readFileSync } = nodemod<typeof import('node:fs')>('node:fs')
        values = parsedotenv(readFileSync(file, 'utf8'))
      } catch (err: any) {
        // An absent file - or an absent directory - means "no secrets
        // here", exactly like fileprovider. Anything else (permission
        // denied, an unreadable mount) is a store that could not answer,
        // and swallowing it would fall through to a weaker store.
        if ('ENOENT' === err.code || 'ENOTDIR' === err.code) {
          values = {}
        } else {
          throw new SekretoError(
            'sekreto: dotenv provider cannot read ' + file + ': ' + err.message,
          )
        }
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

/** A directory of one-secret-per-file entries, keyed like the
 * environment: `api.token` reads `<dir>/API_TOKEN`.
 *
 * This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
 * secret, and a systemd credentials directory, so those all work with no
 * further configuration. One trailing newline is stripped - tools that
 * write these files disagree about it, and a newline is never part of a
 * secret on purpose. */
export function fileprovider(dir: string, prefix?: string): Provider {
  return {
    lookup: (name: string) => {
      const { join } = nodemod<typeof import('node:path')>('node:path')
      const file = join(dir, envkey(name, prefix))

      let text: string
      try {
        const { readFileSync } = nodemod<typeof import('node:fs')>('node:fs')
        text = readFileSync(file, 'utf8')
      } catch (err: any) {
        // An absent file - or an absent directory - means "no secrets
        // here", exactly like a missing .env. Anything else (permission
        // denied, an unreadable mount) is a store that could not answer.
        if ('ENOENT' === err.code || 'ENOTDIR' === err.code) {
          return undefined
        }
        throw new SekretoError('sekreto: file provider cannot read ' + file + ': ' + err.message)
      }

      return text.replace(/\r?\n$/, '')
    },
    describe: () => 'file:' + dir,
  }
}

/** An address with any userinfo replaced by `[redacted]`, for messages.
 *
 * Every refusal below names the address it refused, and one of them fires
 * precisely because the address carries a credential — so printing it
 * verbatim wrote the password to stderr and into the logs. It cannot be
 * cleaned up afterwards either: that password was never resolved as a
 * secret, so `redact()` has never seen it and never will. The host is what
 * a reader needs to identify which chain entry is at fault; the userinfo
 * is not. */
export function safeaddr(addr: string): string {
  const mark = addr.indexOf('://')
  if (-1 === mark) {
    return addr
  }

  const rest = addr.slice(mark + 3)
  const end = rest.search(/[/?#]/)
  const authority = -1 === end ? rest : rest.slice(0, end)

  const at = authority.lastIndexOf('@')
  if (-1 === at) {
    return addr
  }

  return addr.slice(0, mark + 3) + '[redacted]' + addr.slice(mark + 3 + at)
}

/** Refuse to send a secret-bearing credential in the clear.
 *
 * A vault API is HTTPS in any real deployment; plaintext is a dev-mode
 * convenience. Sending a token over http to anything but the local
 * machine puts both the token and the secret it fetches on the wire for
 * anyone on the path, so sekreto will not do it. Loopback stays allowed:
 * that is `vault server -dev`, `boru vault serve`, and this repo's own
 * test harness.
 *
 * The address is read by hand, in the same handful of steps in every
 * port, rather than by each platform's URL parser. That is deliberate.
 * Twelve parsers disagree about malformed input — where userinfo ends,
 * whether `0177.0.0.1` is loopback, what an unclosed bracket means — and
 * a check that answers differently in different ports is not a check.
 *
 * The rule this parse obeys, and the reason it can be trusted: it is
 * never more permissive than the HTTP client that will dial the address.
 * It ends the authority at `/`, `?` or `#` only, so a client that also
 * breaks on `\` (WHATWG does) can only ever see a SHORTER host than this
 * does. It refuses userinfo outright rather than locating its end. It
 * compares the host literally, so a numeric form no parser here agrees on
 * is refused rather than guessed at. Each of those can refuse an address
 * that would in fact have been safe; none can allow one that is not. */
export function checkaddr(addr: string): void {
  const scheme = addr.startsWith('https://')
    ? 'https://'
    : addr.startsWith('http://')
      ? 'http://'
      : ''

  if ('' === scheme) {
    throw new SekretoError('sekreto: not an http(s) address: ' + safeaddr(addr))
  }

  const rest = addr.slice(scheme.length)
  const end = rest.search(/[/?#]/)
  const authority = -1 === end ? rest : rest.slice(0, end)

  // Userinfo is refused outright rather than parsed around, and on https
  // as well as http. No store this library speaks authenticates by
  // userinfo — they take a token or a signature — so an address carrying
  // one is a mistake at best. At worst it is the attack this whole
  // function exists to stop: `http://localhost:8200@evil.example.com/` is
  // a request to evil.example.com that reads, to anything that splits the
  // authority on ':', as loopback. Refusing the shape is a rule twelve
  // ports can apply identically; agreeing on where the userinfo ends is
  // not.
  if (authority.includes('@')) {
    throw new SekretoError(
      'sekreto: refusing an address with embedded credentials: ' + safeaddr(addr),
    )
  }

  // An opening bracket with no closing one is not an address at all, and
  // saying so is more use to whoever wrote the config than refusing it as
  // though it named a remote host.
  if (authority.startsWith('[') && !authority.includes(']')) {
    throw new SekretoError('sekreto: not a valid http(s) address: ' + safeaddr(addr))
  }

  if ('https://' === scheme) {
    return
  }

  // A bracketed IPv6 literal keeps its brackets. Splitting the authority
  // on the first colon yields '[', so `http://[::1]:8200` could never
  // match — which made the '[::1]' entry below unreachable, and refused a
  // legitimate local vault.
  const host = (
    authority.startsWith('[')
      ? authority.slice(0, authority.indexOf(']') + 1)
      : authority.split(':')[0]
  ).toLowerCase()

  if ('localhost' === host || '127.0.0.1' === host || '::1' === host || '[::1]' === host) {
    return
  }

  throw new SekretoError(
    'sekreto: refusing to send a token in plaintext to ' + safeaddr(addr) + ' (use https)',
  )
}

/** How long any single vault round-trip may take before it is treated as
 * unreachable. Ports carry the same bound. */
const HTTP_TIMEOUT_MS = 10000

/** One JSON round-trip. Network failure is always an error - an
 * unreachable store is a store that could not answer. */
async function fetchjson(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: string,
): Promise<{ status: number; body: any }> {
  let res: Response
  try {
    res = await fetch(url, {
      method,
      headers,
      body,
      // A vault API never legitimately redirects, and a followed redirect
      // carries X-Vault-Token to the redirect's host (and can downgrade
      // https to http), which checkaddr - it only validates the configured
      // address - cannot see. Refuse to follow one.
      redirect: 'error',
      // Bound the wait so an accepted-but-silent endpoint cannot hang the
      // caller (and the app's startup) forever.
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    })
  } catch (err: any) {
    throw new SekretoError('sekreto: cannot reach ' + url.split('?')[0] + ': ' + err.message)
  }

  let parsed: any = undefined
  try {
    parsed = await res.json()
  } catch (err: any) {
    // A success status promised JSON; a body that does not parse means
    // the store could not answer coherently, and treating it as a miss
    // would fall through to a weaker store. Error statuses may carry
    // any body - they are decided on status alone.
    if (200 === res.status) {
      throw new SekretoError('sekreto: malformed response from ' + url.split('?')[0])
    }
  }

  return { status: res.status, body: parsed }
}

/** HashiCorp Vault.
 *
 * KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api`
 * and takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
 * `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means
 * "not here" - a miss - so a vault can sit in a chain with fallbacks.
 *
 * A Vault Enterprise namespace rides the X-Vault-Namespace header, on
 * logins as well as reads.
 *
 * Instead of being handed a token, the provider can log in: Kubernetes
 * auth (the pod's service-account JWT, from its conventional path) or
 * AppRole. A failed login is an error, never a miss - it means this
 * store could not answer at all. */
export function hashicorpprovider(
  addr: string,
  token: string,
  options?: {
    mount?: string
    kv?: number
    vaultnamespace?: string
    auth?: ProviderSpec['auth']
  },
): Provider {
  const opts = options || {}
  const usemount = opts.mount || 'secret'
  const kv = opts.kv || 2

  // A version typo like kv: 3 must not quietly behave as v2 and turn
  // its 404s into misses; there is nothing safe to assume it meant.
  if (1 !== kv && 2 !== kv) {
    throw new SekretoError('sekreto: hashicorp: unsupported kv version: ' + String(kv))
  }

  // The working token: a configured token is kept forever, a logged-in
  // token is renewed shortly before its lease runs out - a long-running
  // process must not keep presenting a token the vault already expired.
  let livetoken: string | undefined = '' === token ? undefined : token
  let renewat = Infinity

  const baseheaders = (): Record<string, string> => {
    const headers: Record<string, string> = {}
    if (opts.vaultnamespace) {
      headers['X-Vault-Namespace'] = opts.vaultnamespace
    }
    return headers
  }

  const login = async (): Promise<string> => {
    const auth = opts.auth
    if (!auth) {
      throw new SekretoError('sekreto: hashicorp: no token and no auth method')
    }

    const mount = auth.mount || auth.method
    const url = addr.replace(/\/$/, '') + '/v1/auth/' + mount + '/login'

    let body: any
    if ('kubernetes' === auth.method) {
      let jwt = auth.jwt
      if (undefined === jwt) {
        const file = auth.jwtfile || '/var/run/secrets/kubernetes.io/serviceaccount/token'
        try {
          const { readFileSync } = nodemod<typeof import('node:fs')>('node:fs')
          jwt = readFileSync(file, 'utf8').trim()
        } catch (err: any) {
          throw new SekretoError('sekreto: hashicorp: cannot read jwt file ' + file)
        }
      }
      body = { role: auth.role || '', jwt }
    } else if ('approle' === auth.method) {
      body = { role_id: auth.roleid || '', secret_id: auth.secretid || '' }
    } else {
      throw new SekretoError('sekreto: hashicorp: unknown auth method: ' + String(auth.method))
    }

    const res = await fetchjson('POST', url, baseheaders(), JSON.stringify(body))

    const got = res.body && res.body.auth && res.body.auth.client_token
    if (200 !== res.status || !got) {
      throw new SekretoError('sekreto: hashicorp login failed: ' + res.status + ': ' + url)
    }

    const lease = Number(res.body.auth.lease_duration)
    renewat = 0 < lease ? Date.now() + Math.max(lease - 60, 1) * 1000 : Infinity

    return String(got)
  }

  return {
    lookup: async (name: string) => {
      checkaddr(addr)

      if (undefined === livetoken || Date.now() >= renewat) {
        livetoken = await login()
      }

      const ref = vaultref(name)
      const base = addr.replace(/\/$/, '') + '/v1/' + usemount
      const url = 1 === kv ? base + '/' + ref.path : base + '/data/' + ref.path

      const headers = baseheaders()
      headers['X-Vault-Token'] = livetoken

      const res = await fetchjson('GET', url, headers)

      if (404 === res.status) {
        return undefined
      }

      if (200 !== res.status) {
        throw new SekretoError('sekreto: hashicorp error: ' + res.status + ': ' + url)
      }

      const data =
        1 === kv ? res.body && res.body.data : res.body && res.body.data && res.body.data.data

      const value = data ? data[ref.field] : undefined
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'hashicorp:' + addr + '/' + usemount,
  }
}

/** A boru vault (https://github.com/boru-lang/boru).
 *
 * Two ways in, both boru's own.
 *
 * With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
 * secret on stdout and nothing else. The passphrase is read by boru
 * itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as
 * config and never puts it on a command line, where it would show up in
 * the process table.
 *
 * With an `addr`, boru's wire protocol: `boru vault serve` publishes a
 * read-only, HashiCorp-shaped provision API (boru's
 * design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
 * from `boru vault grant`. A sekreto name is already a valid boru
 * alias, and boru aliases keep their dots, so `api.token` is the single
 * path segment `api.token` - not the `api`/`token` split a HashiCorp KV
 * gets. The value is the `value` field. A 404 is a miss; anything else
 * the server refuses (a revoked capability, a sealed vault) is an
 * error.
 *
 * boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
 * credential *broker*, built precisely so the caller never receives the
 * credential. `vault serve` is the provision endpoint, built to hand
 * the value back - that is the one sekreto uses. */
export function boruprovider(options?: {
  command?: string
  namespace?: string
  home?: string
  addr?: string
  token?: string
  mount?: string
}): Provider {
  const opts = options || {}
  const command = opts.command || 'boru'

  if (opts.addr) {
    const addr = opts.addr.replace(/\/$/, '')
    const mount = opts.mount || 'secret'

    return {
      lookup: async (name: string) => {
        checkname(name)
        checkaddr(addr)

        const alias = opts.namespace ? opts.namespace + '/' + name : name
        const url = addr + '/v1/' + mount + '/data/' + alias

        const res = await fetchjson('GET', url, { 'X-Vault-Token': opts.token || '' })

        if (404 === res.status) {
          return undefined
        }

        if (200 !== res.status) {
          throw new SekretoError('sekreto: boru serve error: ' + res.status + ': ' + url)
        }

        const data = res.body && res.body.data && res.body.data.data
        const value = data ? data['value'] : undefined
        return undefined === value || null === value ? undefined : String(value)
      },
      describe: () => 'boru:' + addr,
    }
  }

  return {
    lookup: (name: string) => {
      checkname(name)

      const alias = opts.namespace ? opts.namespace + ':' + name : name
      const env = opts.home ? { ...process.env, BORU_HOME: opts.home } : process.env

      const { spawnSync } = nodemod<typeof import('node:child_process')>('node:child_process')
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

/** SecretSpec (https://secretspec.dev).
 *
 * SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
 * project needs - plus a chain of its own backends to satisfy them from.
 * That makes it the same shape as sekreto one level down, and the reason
 * to support it is the same reason sekreto exists: a project that has
 * already declared its secrets there should not have to declare them
 * again here.
 *
 * Read through its CLI, as boru is, because that is the interface it
 * offers a program in another language: `secretspec get API_TOKEN`
 * prints the value on stdout and nothing else. A sekreto name maps to a
 * SecretSpec key exactly as it maps to an environment variable -
 * `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
 * examples use.
 *
 * `backend` selects one of SecretSpec's backends (`--provider`, e.g.
 * `keyring` or `dotenv://.env`) and is called `backend` here only
 * because `provider` already means something else in this library.
 *
 * A reason is required, not optional: SecretSpec records every read in
 * an audit log and refuses to read at all without one. sekreto sends
 * `sekreto` unless told otherwise, so the audit trail says which tool
 * asked. */
export function secretspecprovider(options?: {
  command?: string
  file?: string
  profile?: string
  backend?: string
  reason?: string
  prefix?: string
}): Provider {
  const opts = options || {}
  const command = opts.command || 'secretspec'

  return {
    lookup: (name: string) => {
      const key = envkey(name, opts.prefix)

      const args: string[] = []
      if (opts.file) {
        args.push('--file', opts.file)
      }
      args.push('get', key)
      if (opts.backend) {
        args.push('--provider', opts.backend)
      }
      if (opts.profile) {
        args.push('--profile', opts.profile)
      }
      args.push('--reason', opts.reason || 'sekreto')

      const { spawnSync } = nodemod<typeof import('node:child_process')>('node:child_process')
      const run = spawnSync(command, args, { encoding: 'utf8' })

      if (run.error) {
        throw new SekretoError('sekreto: cannot run ' + command + ': ' + run.error.message)
      }

      if (0 === run.status) {
        // The value and one newline, and nothing else.
        return run.stdout.replace(/\n$/, '')
      }

      const why = (run.stderr || '').trim()

      if (secretspecmiss(why, key)) {
        return undefined
      }

      throw new SekretoError('sekreto: secretspec error: ' + (why || 'exit ' + run.status))
    },
    describe: () => 'secretspec' + (opts.backend ? ':' + opts.backend : ''),
  }
}

/** Does this SecretSpec failure mean "no such secret" rather than "I
 * could not answer"?
 *
 * SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
 * not declare and one declared with no value, and both are misses: this
 * store does not hold it, so the chain carries on.
 *
 * MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
 * `Provider backend 'keyring' not found`, which is a store that could
 * not answer at all - and reading that as a miss is the worst failure
 * this library has, because the chain then falls through to a weaker
 * store without saying so. The key is required to appear, so the two
 * cannot be confused. */
function secretspecmiss(why: string, key: string): boolean {
  return why.includes("Secret '" + key + "' not found")
}

/** The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. */
function awsnow(): string {
  return new Date()
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')
}

type Awsopts = {
  region?: string
  keyid?: string
  secret?: string
  session?: string
  addr?: string
  prefix?: string
}

/** Region and credentials, from config first and the standard AWS_*
 * environment variables second - those are AWS's own convention, and a
 * pod or CI job that has them set should just work. Missing either is
 * an error: an AWS store with no credentials could not answer. */
function awsauth(opts: Awsopts): {
  region: string
  keyid: string
  secret: string
  session?: string
} {
  const env = process.env

  const region = opts.region || env.AWS_REGION || env.AWS_DEFAULT_REGION || ''
  const keyid = opts.keyid || env.AWS_ACCESS_KEY_ID || ''
  const secret = opts.secret || env.AWS_SECRET_ACCESS_KEY || ''
  const session = opts.session || env.AWS_SESSION_TOKEN || undefined

  if ('' === region) {
    throw new SekretoError('sekreto: aws: no region (set region or AWS_REGION)')
  }
  if ('' === keyid || '' === secret) {
    throw new SekretoError(
      'sekreto: aws: no credentials (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)',
    )
  }

  return { region, keyid, secret, session }
}

/** One signed call to an AWS JSON-1.1 API. */
async function awscall(
  opts: Awsopts,
  service: string,
  target: string,
  payload: any,
): Promise<{ status: number; body: any }> {
  const auth = awsauth(opts)
  // The China partition lives under its own suffix; every other
  // commercial region is plain amazonaws.com.
  const suffix = auth.region.startsWith('cn-') ? '.amazonaws.com.cn' : '.amazonaws.com'
  const addr = opts.addr || 'https://' + service + '.' + auth.region + suffix
  checkaddr(addr)

  const url = addr.replace(/\/$/, '') + '/'
  const body = JSON.stringify(payload)
  const headers: Record<string, string> = {
    'content-type': 'application/x-amz-json-1.1',
    'x-amz-target': target,
  }

  const signed = sigv4({
    method: 'POST',
    url,
    headers,
    body,
    service,
    region: auth.region,
    keyid: auth.keyid,
    secret: auth.secret,
    session: auth.session,
    datetime: awsnow(),
  })

  return fetchjson('POST', url, { ...headers, ...signed }, body)
}

/** Does this AWS error body name one of the not-found types? Those are
 * a miss; every other failure is a store that could not answer. */
function awsmiss(body: any, types: string[]): boolean {
  const errtype = body && 'string' === typeof body.__type ? body.__type : ''
  return types.some((name) => errtype.includes(name))
}

/** AWS Secrets Manager.
 *
 * `api.token` reads the secret named `api` (the vaultref path, so
 * `db.pass.main` reads `db/pass`) and takes the `token` field of its
 * JSON SecretString - the AWS idiom of one JSON map per secret. A
 * SecretString that is not JSON is the value itself, under the
 * conventional field `value`. Requests are SigV4-signed in-tree; see
 * Sigv4.ts. */
export function awssecretsprovider(options?: Awsopts): Provider {
  const opts = options || {}

  return {
    lookup: async (name: string) => {
      const ref = vaultref(name)

      const res = await awscall(opts, 'secretsmanager', 'secretsmanager.GetSecretValue', {
        SecretId: ref.path,
      })

      if (400 === res.status && awsmiss(res.body, ['ResourceNotFoundException'])) {
        return undefined
      }

      if (200 !== res.status) {
        throw new SekretoError('sekreto: aws secretsmanager error: ' + res.status)
      }

      const text = res.body && res.body.SecretString

      if ('string' !== typeof text) {
        // A binary secret has no fields to address; only the conventional
        // `value` field can mean "the bytes themselves".
        const bin = res.body && res.body.SecretBinary
        if ('string' === typeof bin && 'value' === ref.field) {
          return Buffer.from(bin, 'base64').toString('utf8')
        }
        return undefined
      }

      let parsed: any
      try {
        parsed = JSON.parse(text)
      } catch (err: any) {
        parsed = undefined
      }

      if (parsed && 'object' === typeof parsed && !Array.isArray(parsed)) {
        const value = parsed[ref.field]
        return undefined === value || null === value ? undefined : String(value)
      }

      // A plain-string secret is the whole value; it has no named fields.
      return 'value' === ref.field ? text : undefined
    },
    // Config only, never the environment: describe() feeds the spec's
    // sources group, which must answer the same everywhere.
    describe: () => 'awssecrets:' + (opts.region || ''),
  }
}

/** AWS SSM Parameter Store.
 *
 * `db.pass.main` reads the parameter `/db/pass/main` (under an optional
 * prefix path), decrypted. Parameter Store carries flat strings, so
 * there is no field indirection. */
export function awsparamsprovider(options?: Awsopts): Provider {
  const opts = options || {}

  return {
    lookup: async (name: string) => {
      const res = await awscall(opts, 'ssm', 'AmazonSSM.GetParameter', {
        Name: awsparam(name, opts.prefix),
        WithDecryption: true,
      })

      if (400 === res.status && awsmiss(res.body, ['ParameterNotFound'])) {
        return undefined
      }

      if (200 !== res.status) {
        throw new SekretoError('sekreto: aws ssm error: ' + res.status)
      }

      const value = res.body && res.body.Parameter && res.body.Parameter.Value
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'awsparams:' + (opts.region || '') + (opts.prefix || ''),
  }
}

/** GCP Secret Manager.
 *
 * `api.token` reads secret `api_token` (dots flattened to `_`; Secret
 * Manager ids have no hierarchy and reject dots), latest version. The
 * token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
 * GCE/GKE metadata server - so on Google's own platform no credential
 * configuration is needed at all.
 *
 * The metadata call itself is plain http to a link-local host by
 * platform design; no credential rides on it, so `checkaddr` guards the
 * Secret Manager address instead. */
export function gcpsecretsprovider(options?: {
  project?: string
  token?: string
  addr?: string
  metadataaddr?: string
}): Provider {
  const opts = options || {}

  // A configured token is kept forever; a metadata-server token carries
  // expires_in and is renewed shortly before it runs out.
  let livetoken: string | undefined
  let renewat = Infinity

  const metadataaddr = (): string => {
    if (opts.metadataaddr) {
      return opts.metadataaddr
    }
    const host = process.env.GCE_METADATA_HOST
    return host ? 'http://' + host : 'http://metadata.google.internal'
  }

  const login = async (): Promise<string> => {
    const configured = opts.token || process.env.GOOGLE_OAUTH_ACCESS_TOKEN
    if (configured) {
      return configured
    }

    const url =
      metadataaddr().replace(/\/$/, '') +
      '/computeMetadata/v1/instance/service-accounts/default/token'

    const res = await fetchjson('GET', url, { 'Metadata-Flavor': 'Google' })

    const got = res.body && res.body.access_token
    if (200 !== res.status || !got) {
      throw new SekretoError('sekreto: gcp: no token and metadata server did not answer')
    }

    const expires = Number(res.body.expires_in)
    renewat = 0 < expires ? Date.now() + Math.max(expires - 60, 1) * 1000 : Infinity

    return String(got)
  }

  return {
    lookup: async (name: string) => {
      const project = opts.project || ''
      if ('' === project) {
        throw new SekretoError('sekreto: gcp: no project')
      }

      const addr = opts.addr || 'https://secretmanager.googleapis.com'
      checkaddr(addr)

      if (undefined === livetoken || Date.now() >= renewat) {
        livetoken = await login()
      }

      const url =
        addr.replace(/\/$/, '') +
        '/v1/projects/' +
        project +
        '/secrets/' +
        flatname(name, '_') +
        '/versions/latest:access'

      const res = await fetchjson('GET', url, { authorization: 'Bearer ' + livetoken })

      if (404 === res.status) {
        return undefined
      }

      if (200 !== res.status) {
        throw new SekretoError('sekreto: gcp error: ' + res.status + ': ' + url)
      }

      const data = res.body && res.body.payload && res.body.payload.data
      if ('string' !== typeof data) {
        return undefined
      }

      return Buffer.from(data, 'base64').toString('utf8')
    },
    describe: () => 'gcpsecrets:' + (opts.project || ''),
  }
}

/** Azure Key Vault.
 *
 * `api.token` reads secret `api-token` (dots flattened to `-`; Key
 * Vault names allow nothing else), current version. The token comes
 * from config, then a client-credentials login when tenant/clientid/
 * clientsecret are given, then the IMDS managed-identity endpoint - so
 * on Azure's own platform no credential configuration is needed.
 *
 * As with GCP, the IMDS call is plain http to a link-local host by
 * platform design and carries no credential; the login and vault
 * addresses are `checkaddr`-guarded. */
export function azuresecretsprovider(options?: {
  vault?: string
  token?: string
  tenant?: string
  clientid?: string
  clientsecret?: string
  loginaddr?: string
  imdsaddr?: string
  apiversion?: string
}): Provider {
  const opts = options || {}
  const resource = 'https://vault.azure.net'

  // A configured token is kept forever; logged-in and IMDS tokens carry
  // expires_in and are renewed shortly before they run out.
  let livetoken: string | undefined
  let renewat = Infinity

  const expiry = (expires: any): number => {
    const seconds = Number(expires)
    return 0 < seconds ? Date.now() + Math.max(seconds - 60, 1) * 1000 : Infinity
  }

  const login = async (): Promise<string> => {
    if (opts.token) {
      return opts.token
    }

    if (opts.tenant && opts.clientid && opts.clientsecret) {
      const loginaddr = opts.loginaddr || 'https://login.microsoftonline.com'
      checkaddr(loginaddr)

      const url = loginaddr.replace(/\/$/, '') + '/' + opts.tenant + '/oauth2/v2.0/token'
      const form =
        'grant_type=client_credentials&client_id=' +
        encodeURIComponent(opts.clientid) +
        '&client_secret=' +
        encodeURIComponent(opts.clientsecret) +
        '&scope=' +
        encodeURIComponent(resource + '/.default')

      const res = await fetchjson(
        'POST',
        url,
        { 'content-type': 'application/x-www-form-urlencoded' },
        form,
      )

      const got = res.body && res.body.access_token
      if (200 !== res.status || !got) {
        throw new SekretoError('sekreto: azure login failed: ' + res.status)
      }

      renewat = expiry(res.body.expires_in)
      return String(got)
    }

    const imds =
      (opts.imdsaddr || 'http://169.254.169.254').replace(/\/$/, '') +
      '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' +
      encodeURIComponent(resource)

    const res = await fetchjson('GET', imds, { Metadata: 'true' })

    const got = res.body && res.body.access_token
    if (200 !== res.status || !got) {
      throw new SekretoError(
        'sekreto: azure: no token, no client credentials, and IMDS did not answer',
      )
    }

    renewat = expiry(res.body.expires_in)
    return String(got)
  }

  return {
    lookup: async (name: string) => {
      const vault = opts.vault || ''
      if ('' === vault) {
        throw new SekretoError('sekreto: azure: no vault')
      }

      // Only an explicit scheme is a URL; a vault NAMED httpvault must
      // still become https://httpvault.vault.azure.net.
      const vaulturl =
        vault.startsWith('http://') || vault.startsWith('https://')
          ? vault
          : 'https://' + vault + '.vault.azure.net'
      checkaddr(vaulturl)

      if (undefined === livetoken || Date.now() >= renewat) {
        livetoken = await login()
      }

      const url =
        vaulturl.replace(/\/$/, '') +
        '/secrets/' +
        flatname(name, '-') +
        '?api-version=' +
        (opts.apiversion || '7.4')

      const res = await fetchjson('GET', url, { authorization: 'Bearer ' + livetoken })

      if (404 === res.status) {
        return undefined
      }

      if (200 !== res.status) {
        throw new SekretoError('sekreto: azure error: ' + res.status + ': ' + url.split('?')[0])
      }

      const value = res.body && res.body.value
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'azuresecrets:' + (opts.vault || ''),
  }
}

/** 1Password, through a Connect server.
 *
 * The item titled `api.token` (titles keep their dots), in the named
 * vault. The value is the field with purpose PASSWORD, or the field
 * labelled `value`. A vault that cannot be found is an error - config
 * names it, so its absence is a broken store, not a missing secret. */
export function onepasswordprovider(options?: {
  addr?: string
  token?: string
  vault?: string
}): Provider {
  const opts = options || {}

  let vaultid: string | undefined

  const auth = (): Record<string, string> => ({
    authorization: 'Bearer ' + (opts.token || ''),
  })

  const resolvevault = async (addr: string): Promise<string> => {
    const want = opts.vault || ''
    if ('' === want) {
      throw new SekretoError('sekreto: onepassword: no vault')
    }

    const res = await fetchjson('GET', addr + '/v1/vaults', auth())

    if (200 !== res.status || !Array.isArray(res.body)) {
      throw new SekretoError('sekreto: onepassword error: ' + res.status + ': listing vaults')
    }

    for (const entry of res.body) {
      if (entry && (want === entry.id || want === entry.name)) {
        return String(entry.id)
      }
    }

    throw new SekretoError('sekreto: onepassword: no vault named ' + want)
  }

  return {
    lookup: async (name: string) => {
      checkname(name)

      const addr = (opts.addr || '').replace(/\/$/, '')
      if ('' === addr) {
        throw new SekretoError('sekreto: onepassword: no addr')
      }
      checkaddr(addr)

      if (undefined === vaultid) {
        vaultid = await resolvevault(addr)
      }

      const filter = encodeURIComponent('title eq "' + name + '"')
      const found = await fetchjson(
        'GET',
        addr + '/v1/vaults/' + vaultid + '/items?filter=' + filter,
        auth(),
      )

      if (200 !== found.status || !Array.isArray(found.body)) {
        throw new SekretoError('sekreto: onepassword error: ' + found.status + ': finding ' + name)
      }

      if (0 === found.body.length) {
        return undefined
      }

      const item = await fetchjson(
        'GET',
        addr + '/v1/vaults/' + vaultid + '/items/' + found.body[0].id,
        auth(),
      )

      if (200 !== item.status) {
        throw new SekretoError('sekreto: onepassword error: ' + item.status + ': reading ' + name)
      }

      const fields = (item.body && item.body.fields) || []

      for (const field of fields) {
        if (field && 'PASSWORD' === field.purpose) {
          return undefined === field.value || null === field.value ? undefined : String(field.value)
        }
      }
      for (const field of fields) {
        if (field && 'value' === field.label) {
          return undefined === field.value || null === field.value ? undefined : String(field.value)
        }
      }

      return undefined
    },
    describe: () => 'onepassword:' + (opts.vault || ''),
  }
}

/** Doppler.
 *
 * The whole config is downloaded once - Doppler's own bulk endpoint -
 * and answered from memory, like a remote .env: `api.token` is the
 * `API_TOKEN` entry. A service token is config-scoped, so project and
 * config are only needed with broader tokens. */
export function dopplerprovider(options?: {
  token?: string
  project?: string
  config?: string
  addr?: string
}): Provider {
  const opts = options || {}

  let values: Record<string, string> | undefined

  const load = async (): Promise<Record<string, string>> => {
    if (undefined !== values) {
      return values
    }

    const addr = (opts.addr || 'https://api.doppler.com').replace(/\/$/, '')
    checkaddr(addr)

    let url = addr + '/v3/configs/config/secrets/download?format=json'
    if (opts.project) {
      url += '&project=' + encodeURIComponent(opts.project)
    }
    if (opts.config) {
      url += '&config=' + encodeURIComponent(opts.config)
    }

    const res = await fetchjson('GET', url, {
      authorization: 'Bearer ' + (opts.token || ''),
    })

    if (200 !== res.status || !res.body || 'object' !== typeof res.body) {
      throw new SekretoError('sekreto: doppler error: ' + res.status)
    }

    values = {}
    for (const [key, value] of Object.entries(res.body)) {
      if (null !== value && undefined !== value) {
        values[key] = String(value)
      }
    }

    return values
  }

  return {
    lookup: async (name: string) => (await load())[envkey(name)],
    describe: () =>
      'doppler' + (opts.project ? ':' + opts.project + '/' + (opts.config || '') : ''),
  }
}

/** Infisical.
 *
 * `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
 * convention is environment-style keys) at a secret path in one
 * environment of a project. Auth is a token, or a universal-auth
 * (machine identity) login with clientid/clientsecret. */
export function infisicalprovider(options?: {
  addr?: string
  token?: string
  clientid?: string
  clientsecret?: string
  project?: string
  environment?: string
  path?: string
}): Provider {
  const opts = options || {}

  // A configured token is kept forever; a universal-auth token carries
  // expiresIn and is renewed shortly before it runs out.
  let livetoken: string | undefined
  let renewat = Infinity

  const login = async (addr: string): Promise<string> => {
    if (opts.token) {
      return opts.token
    }

    if (!opts.clientid || !opts.clientsecret) {
      throw new SekretoError('sekreto: infisical: no token and no client credentials')
    }

    const res = await fetchjson(
      'POST',
      addr + '/api/v1/auth/universal-auth/login',
      { 'content-type': 'application/json' },
      JSON.stringify({ clientId: opts.clientid, clientSecret: opts.clientsecret }),
    )

    const got = res.body && res.body.accessToken
    if (200 !== res.status || !got) {
      throw new SekretoError('sekreto: infisical login failed: ' + res.status)
    }

    const expires = Number(res.body.expiresIn)
    renewat = 0 < expires ? Date.now() + Math.max(expires - 60, 1) * 1000 : Infinity

    return String(got)
  }

  return {
    lookup: async (name: string) => {
      const addr = (opts.addr || 'https://app.infisical.com').replace(/\/$/, '')
      checkaddr(addr)

      const project = opts.project || ''
      const environment = opts.environment || ''
      if ('' === project || '' === environment) {
        throw new SekretoError('sekreto: infisical: no project/environment')
      }

      if (undefined === livetoken || Date.now() >= renewat) {
        livetoken = await login(addr)
      }

      const url =
        addr +
        '/api/v3/secrets/raw/' +
        envkey(name) +
        '?workspaceId=' +
        encodeURIComponent(project) +
        '&environment=' +
        encodeURIComponent(environment) +
        '&secretPath=' +
        encodeURIComponent(opts.path || '/')

      const res = await fetchjson('GET', url, { authorization: 'Bearer ' + livetoken })

      if (404 === res.status) {
        return undefined
      }

      if (200 !== res.status) {
        throw new SekretoError('sekreto: infisical error: ' + res.status)
      }

      const value = res.body && res.body.secret && res.body.secret.secretValue
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'infisical:' + (opts.project || '') + '/' + (opts.environment || ''),
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
    case 'file':
      return fileprovider(spec.dir || '', spec.prefix)
    case 'hashicorp':
      return hashicorpprovider(spec.addr || '', spec.token || '', {
        mount: spec.mount,
        kv: spec.kv,
        vaultnamespace: spec.vaultnamespace,
        auth: spec.auth,
      })
    case 'boru':
      return boruprovider({
        command: spec.command,
        namespace: spec.namespace,
        home: spec.home,
        addr: spec.addr,
        token: spec.token,
        mount: spec.mount,
      })
    case 'awssecrets':
      return awssecretsprovider(spec)
    case 'awsparams':
      return awsparamsprovider(spec)
    case 'gcpsecrets':
      return gcpsecretsprovider(spec)
    case 'azuresecrets':
      return azuresecretsprovider(spec)
    case 'onepassword':
      return onepasswordprovider(spec)
    case 'doppler':
      return dopplerprovider(spec)
    case 'infisical':
      return infisicalprovider(spec)
    case 'secretspec':
      return secretspecprovider({
        command: spec.command,
        file: spec.file,
        profile: spec.profile,
        backend: spec.backend,
        reason: spec.reason,
        prefix: spec.prefix,
      })
    default:
      throw new SekretoError('sekreto: unknown provider kind: ' + String((spec as any).kind))
  }
}
