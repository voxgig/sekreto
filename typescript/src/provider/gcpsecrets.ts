/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { ProviderSpec, Provider, SekretoError, flatname, nodemod, unbase64 } from './support'
import { checkaddr } from './addr'
import { fetchjson } from './http'

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

      const decoded = unbase64(data)
      if (undefined === decoded) {
        throw new SekretoError('sekreto: gcp: undecodable secret')
      }

      return decoded
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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'gcpsecrets',
  needs: ['fetch'],
  define: (spec: ProviderSpec) => gcpsecretsprovider(spec),
})
