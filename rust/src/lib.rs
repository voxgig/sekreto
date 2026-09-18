
pub mod addr;
pub mod providers;
pub mod sekreto;

pub use crate::addr::{checkaddr, safeaddr};
pub use crate::providers::{
    builtins, optionsof, providerplugin, specof, AuthSpec, DotenvProvider, EnvProvider,
    FileProvider, MemoryProvider, Provider, ProviderSpec, BUILTIN_KINDS, ERROR_CODE, PLUGIN_KINDS,
    PROVIDER_EXPORT,
};
pub use crate::sekreto::{
    awsparam, checkname, envkey, flatname, parsedotenv, redact, storename, validname, vaultref,
    Answer, ChainError, Options, Sekreto, SekretoError, VaultRef,
};

/// voxgig/plugin, re-exported: a consumer builds a custom kind with
/// `providerplugin` and never needs to name the dependency itself.
pub use voxgig_plugin;
