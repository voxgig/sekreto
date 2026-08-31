/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import {
  ProviderSpec, Provider, SekretoError, checkname, vaultref,
} from './support'
import { checkaddr } from './addr'
import { fetchjson } from './http'

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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'onepassword',
  needs: ['fetch'],
  define: (spec: ProviderSpec) => onepasswordprovider(spec),
})
