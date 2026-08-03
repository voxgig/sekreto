//! sekreto: one interface for secrets, wherever they live.
//!
//! An app asks a `Sekreto` for `api.token` and never learns whether the
//! value came from the environment, a `.env` file, HashiCorp Vault or a
//! boru vault. Swapping the chain is a config change, not a code change.
//!
//! This port depends on nothing beyond the standard library: it carries its
//! own JSON reader and a small HTTP/1.1 client for the vault providers.

pub mod http;
pub mod json;
pub mod providers;
pub mod sekreto;

pub use crate::json::Json;
pub use crate::providers::{
    makechain, makeprovider, BoruProvider, DotenvProvider, EnvProvider, HashicorpProvider,
    MemoryProvider, Provider, ProviderSpec,
};
pub use crate::sekreto::{
    envkey, parsedotenv, redact, validname, vaultref, Answer, Sekreto, SekretoError, VaultRef,
};
