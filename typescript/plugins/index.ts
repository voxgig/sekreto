// THE FULL SET - every plugin this library ships, in one import.
//
// It exists for the callers that genuinely want all ten kinds: the CLI,
// the conformance suite, an app whose chain is decided at run time.
//
//     import { allplugins } from '@voxgig/sekreto/plugins'
//     new Sekreto({ plugins: allplugins, providers: [...] })
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Reaching one
// plugin through this file makes every other reachable too - AWS request
// signing and seven HTTP vault clients included - which is the cost the
// core/plugin split exists to remove. A lean consumer imports the kinds
// it actually configures, each from its own module:
//
//     import { hashicorp } from '@voxgig/sekreto/plugins/hashicorp'
//
// See docs/design/plugin-providers.md.

import type { Definition } from '@voxgig/plugin'

import { hashicorp } from './hashicorp'
import { boru } from './boru'
import { awssecrets, awsparams } from './aws'
import { gcpsecrets } from './gcpsecrets'
import { azuresecrets } from './azuresecrets'
import { onepassword } from './onepassword'
import { doppler } from './doppler'
import { infisical } from './infisical'
import { secretspec } from './secretspec'
import { minivault } from './minivault'

export {
  hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
  onepassword, doppler, infisical, secretspec, minivault,
}

export const allplugins: Definition[] = [
  hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
  onepassword, doppler, infisical, secretspec, minivault,
]

export { hashicorpprovider } from './hashicorp'
export { boruprovider } from './boru'
export { awssecretsprovider, awsparamsprovider, sigv4 } from './aws'
export type { Sigv4Input, Sigv4Output } from './aws'
export { gcpsecretsprovider } from './gcpsecrets'
export { azuresecretsprovider } from './azuresecrets'
export { onepasswordprovider } from './onepassword'
export { dopplerprovider } from './doppler'
export { infisicalprovider } from './infisical'
export { secretspecprovider } from './secretspec'
export {
  ITERATIONS, MASTERKEY, VAULT_EXPORT, createvault, minivaultprovider, openvault,
  providerof, vaultof,
} from './minivault'
export type { GrantSpec, MiniVault, VaultKeyInfo, VaultOptions } from './minivault'
export { fetchjson } from './httpjson'
