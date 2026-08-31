/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { ProviderSpec, Provider, SekretoError, checkname, nodemod, vaultref } from './support'
import { checkaddr } from './addr'
import { fetchjson } from './http'

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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'hashicorp',
  needs: ['fetch', 'fs'],
  define: (spec: ProviderSpec) => hashicorpprovider(spec.addr || '', spec.token || '', {
    mount: spec.mount,
    kv: spec.kv,
    vaultnamespace: spec.vaultnamespace,
    auth: spec.auth,
  }),
})
