/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { ProviderSpec, Provider, SekretoError, flatname } from './support'
import { checkaddr } from './addr'
import { fetchjson } from './http'

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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'azuresecrets',
  needs: ['fetch'],
  define: (spec: ProviderSpec) => azuresecretsprovider(spec),
})
