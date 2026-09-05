//! The full set: every plugin this repository ships, in one call.
//!
//! ```ignore
//! let secrets = Sekreto::new(Options {
//!     plugins: voxgig_sekreto_plugins::all(),
//!     providers: chain,
//!     ..Default::default()
//! })?;
//! ```
//!
//! DEPENDING ON THIS CRATE LINKS ALL TEN, AWS request signing and seven
//! HTTP vault clients included, which is exactly the cost the core/plugin
//! split exists to remove. A lean consumer names the kinds it configures,
//! one crate each:
//!
//! ```ignore
//! plugins: vec![voxgig_sekreto_hashicorp::plugin()]
//! ```

use voxgig_plugin::catalog::Definition;

pub use voxgig_sekreto_aws as aws;
pub use voxgig_sekreto_azuresecrets as azuresecrets;
pub use voxgig_sekreto_boru as boru;
pub use voxgig_sekreto_doppler as doppler;
pub use voxgig_sekreto_gcpsecrets as gcpsecrets;
pub use voxgig_sekreto_hashicorp as hashicorp;
pub use voxgig_sekreto_httpjson as httpjson;
pub use voxgig_sekreto_infisical as infisical;
pub use voxgig_sekreto_onepassword as onepassword;
pub use voxgig_sekreto_secretspec as secretspec;

/// Every plugin definition this repository ships, in a fresh vector.
pub fn all() -> Vec<Definition> {
    vec![
        hashicorp::plugin(),
        boru::plugin(),
        aws::secrets(),
        aws::params(),
        gcpsecrets::plugin(),
        azuresecrets::plugin(),
        onepassword::plugin(),
        doppler::plugin(),
        infisical::plugin(),
        secretspec::plugin(),
    ]
}
