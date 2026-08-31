/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import {
  ProviderSpec, Provider, SekretoError, envkey, flatname, nodemod,
} from './support'

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

/** Refuse to send a secret-bearing credential in the clear.
 *
 * A vault API is HTTPS in any real deployment; plaintext is a dev-mode
 * convenience. Sending a token over http to anything but the local
 * machine puts both the token and the secret it fetches on the wire for
 * anyone on the path, so sekreto will not do it. Loopback stays allowed:
 * that is `vault server -dev`, `boru vault serve`, and this repo's own
 * test harness. */


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'file',
  needs: ['fs'],
  define: (spec: ProviderSpec) => fileprovider(spec.dir || '', spec.prefix),
})
