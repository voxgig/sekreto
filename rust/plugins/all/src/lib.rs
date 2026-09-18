
use voxgig_plugin::catalog::Definition;

pub use voxgig_sekreto_aws as aws;
pub use voxgig_sekreto_azuresecrets as azuresecrets;
pub use voxgig_sekreto_boru as boru;
pub use voxgig_sekreto_doppler as doppler;
pub use voxgig_sekreto_gcpsecrets as gcpsecrets;
pub use voxgig_sekreto_hashicorp as hashicorp;
pub use voxgig_sekreto_httpjson as httpjson;
pub use voxgig_sekreto_infisical as infisical;
pub use voxgig_sekreto_minivault as minivault;
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
        minivault::minivault(),
    ]
}
