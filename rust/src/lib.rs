//! sekreto: one interface for secrets, wherever they live.
//!
//! An app asks a `Sekreto` for `api.token` and never learns whether the
//! value came from the environment, a `.env` file, HashiCorp Vault, AWS,
//! GCP, Azure or a boru vault. Swapping the chain is a config change, not
//! a code change.
//!
//! This port depends on nothing beyond the standard library (and rustls,
//! for TLS): it carries its own JSON reader, a small HTTP/1.1 client,
//! SHA-256/HMAC and SigV4 signing for the vault providers.

pub mod crypto;
pub mod http;
pub mod json;
pub mod providers;
pub mod sekreto;
pub mod sigv4;

pub use crate::json::Json;
pub use crate::providers::{
    makechain, makeprovider, AuthSpec, AwsParamsProvider, AwsSecretsProvider,
    AzureSecretsProvider, BoruProvider, DopplerProvider, DotenvProvider, EnvProvider,
    FileProvider, GcpSecretsProvider, HashicorpProvider, InfisicalProvider, MemoryProvider,
    OnePasswordProvider, Provider, ProviderSpec, SecretSpecProvider,
};
pub use crate::sekreto::{
    awsparam, envkey, flatname, parsedotenv, redact, validname, vaultref, Answer, Sekreto,
    SekretoError, VaultRef,
};
pub use crate::sigv4::{sigv4, Sigv4Input, Sigv4Output};
