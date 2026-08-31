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
} from '../Sekreto'

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
  /** boru: the executable to run (default `boru`). */
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

export {
  SekretoError, awsparam, checkname, envkey, flatname, parsedotenv, vaultref,
}
export { nodemod }

/** Decode standard base64, or undefined when the text is not base64.
 *
 * `Buffer.from(text, 'base64')` is lenient: it skips anything outside the
 * alphabet and hands back whatever it managed, so a corrupted payload
 * became a plausible-looking string of bytes that the caller then returned
 * AS THE SECRET. The alphabet is checked first so that a store which
 * answered incoherently can be told apart from one that answered.
 *
 * A store that could not answer coherently is an ERROR, never a miss — the
 * same rule this code already applies to a 200 whose body is not JSON. */
export function unbase64(text: string): string | undefined {
  const trimmed = text.replace(/\s+/g, '')

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(trimmed) || 0 !== trimmed.length % 4) {
    return undefined
  }

  return Buffer.from(trimmed, 'base64').toString('utf8')
}
