/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { ProviderSpec, Provider, envkey } from './support'

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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'env',
  needs: [],
  define: (spec: ProviderSpec) => envprovider(spec.prefix),
})
