/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { SekretoError } from './support'
import { checkaddr } from './addr'

// Moved here with fetchjson, its only consumer.
const HTTP_TIMEOUT_MS = 10000

export async function fetchjson(
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
