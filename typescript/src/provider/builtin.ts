/* Copyright (c) 2025 Voxgig Ltd, MIT License */

// THE BUILT-IN PROVIDER KINDS - the same four in every port.
//
// What makes a kind built in is that it needs nothing of the platform
// beyond reading a local file: no socket, no TLS, no crypto, no child
// process. These four are the floor every chain stands on, and a chain
// that reads secrets from options, the environment, a plaintext `.env`
// and a mounted secret directory works with no plugin loaded at all.
// Everything else - the vault clients, the cloud stores, the CLIs - is a
// plugin, and lives under `plugins/` (docs/design/plugin-providers.md).

import { Definition, ProviderSpec, providerplugin } from './support'
import { envprovider } from './env'
import { memoryprovider } from './memory'
import { dotenvprovider } from './dotenv'
import { fileprovider } from './file'

export const BUILTINS: Definition[] = [
  providerplugin('env', (spec: ProviderSpec) => envprovider(spec.prefix)),
  providerplugin('memory', (spec: ProviderSpec) => memoryprovider(spec.values || {}, spec.prefix)),
  providerplugin('dotenv', (spec: ProviderSpec) => dotenvprovider(spec.file || '.env', spec.prefix)),
  providerplugin('file', (spec: ProviderSpec) => fileprovider(spec.dir || '', spec.prefix)),
]

/** Every kind this library ships, built in or as a plugin, so that an
 * unknown kind can be told from a plugin that was not loaded. */
export const KINDS = {
  builtin: ['env', 'memory', 'dotenv', 'file'],
  plugin: [
    'hashicorp', 'boru', 'awssecrets', 'awsparams', 'gcpsecrets',
    'azuresecrets', 'onepassword', 'doppler', 'infisical', 'secretspec',
  ],
}
