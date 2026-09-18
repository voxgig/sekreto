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

export { envprovider } from './provider/env'
export { memoryprovider } from './provider/memory'
export { dotenvprovider } from './provider/dotenv'
export { fileprovider } from './provider/file'
export { BUILTINS, KINDS } from './provider/builtin'

// How a provider kind becomes a plugin definition - the one call a
// custom kind needs.
export { providerplugin, PROVIDER_EXPORT, ERROR_CODE } from './provider/support'

// A pure validator, no platform dependency - kept on the core surface
// because callers validate an address before configuring a provider.
export { checkaddr, safeaddr } from './provider/addr'

export type { Provider, ProviderSpec } from './provider/support'
export type { Definition } from '@voxgig/plugin'
