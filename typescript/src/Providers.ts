/* Copyright (c) 2025 Voxgig Ltd, MIT License */

// THE FULL-SET BARREL — every provider kind, as this module always
// carried them.
//
// It exists for compatibility and for the callers that genuinely want
// all thirteen: importing it registers the lot, exactly as the old
// `makeprovider` switch made them all reachable. Nothing that used
// `from './Providers'` has to change.
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Reaching a kind
// through this file makes every other kind reachable too — AWS request
// signing and seven HTTP vault clients included — which is the cost the
// core/plugin split exists to remove. A lean consumer imports the core
// and the kinds it actually configures:
//
//     import { sekreto } from '@voxgig/sekreto'
//     import '@voxgig/sekreto/provider/dotenv'   // registers 'dotenv'
//
// See docs/design/plugin-providers.md.

export { envprovider } from './provider/env'
export { memoryprovider } from './provider/memory'
export { dotenvprovider } from './provider/dotenv'
export { fileprovider } from './provider/file'
export { hashicorpprovider } from './provider/hashicorp'
export { boruprovider } from './provider/boru'
export { awssecretsprovider, awsparamsprovider } from './provider/aws'
export { gcpsecretsprovider } from './provider/gcpsecrets'
export { azuresecretsprovider } from './provider/azuresecrets'
export { onepasswordprovider } from './provider/onepassword'
export { dopplerprovider } from './provider/doppler'
export { infisicalprovider } from './provider/infisical'
export { secretspecprovider } from './provider/secretspec'

export { checkaddr, safeaddr } from './provider/addr'
export { makeprovider, register, registered, kinds } from './provider/Registry'
export type { ProviderDefinition } from './provider/Registry'
export type { Provider, ProviderSpec } from './provider/support'

export { sigv4 } from './Sigv4'
export type { Sigv4Input, Sigv4Output } from './Sigv4'
