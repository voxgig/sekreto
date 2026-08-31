/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { ProviderSpec, Provider, envkey } from './support'

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


// Registering at import is what makes this module's presence the only
// thing that decides whether the kind exists in a build.
import { register } from './Registry'

register({
  name: 'memory',
  needs: [],
  define: (spec: ProviderSpec) => memoryprovider(spec.values || {}, spec.prefix),
})
