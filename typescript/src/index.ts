// @voxgig/sekreto - one interface for secrets, wherever they live.

export {
  Sekreto,
  SekretoError,
  awsparam,
  envkey,
  flatname,
  parsedotenv,
  redact,
  sekreto,
  validname,
  vaultref,
} from './Sekreto'

export type { Name, SekretoOptions } from './Sekreto'

// THE CORE SURFACE. Deliberately does NOT re-export the twelve provider
// kinds that need something of their runtime: pulling one through this
// file would make all of them reachable and put AWS request signing in
// every build, which is the thing the split removes.
//
// `env` and `memory` are here because they import nothing at all, and a
// chain with nowhere to read from is not usable or testable.
//
// Everything else registers itself when its module is imported:
//
//     import '@voxgig/sekreto/provider/dotenv'
//
// or, for the old all-in behaviour, `from '@voxgig/sekreto/Providers'`.
// See docs/design/plugin-providers.md.
export { envprovider } from './provider/env'
export { memoryprovider } from './provider/memory'

// A pure validator, no platform dependency - kept on the core surface
// because callers validate an address before configuring a provider.
export { checkaddr } from './provider/addr'

export { makeprovider, register, registered, kinds } from './provider/Registry'
export type { ProviderDefinition } from './provider/Registry'

export type { Provider, ProviderSpec } from './provider/support'

// `sigv4` is NOT on the core surface: it is the node:crypto edge, and
// only the two aws providers use it. Import it from the module that
// needs it - `@voxgig/sekreto/provider/aws` - or from the full-set
// barrel. Re-exporting it here would put request signing in every
// build again, which is the thing the split removes.
