/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { ProviderSpec, Provider, SekretoError, envkey } from './support'
import { checkaddr } from './addr'
import { fetchjson } from './http'

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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'doppler',
  needs: ['fetch'],
  define: (spec: ProviderSpec) => dopplerprovider(spec),
})
