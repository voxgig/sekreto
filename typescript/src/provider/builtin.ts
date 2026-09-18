/* Copyright (c) 2025 Voxgig Ltd, MIT License */


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
    'minivault',
  ],
}
