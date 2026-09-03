//! THE FULL SET - every plugin this library ships, in one module.
//!
//! It exists for the callers that genuinely want all ten kinds: the CLI,
//! the conformance suite, an app whose chain is decided at run time.
//!
//!     const plugins = @import("sekretoplugins");
//!     const secrets = try sekreto.Sekreto.init(alloc, config, .{
//!         .plugins = &plugins.ALL,
//!         .providers = chain,
//!     });
//!
//! IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. A module rooted
//! here compiles every plugin - AWS request signing and seven HTTPS vault
//! clients included - which is the cost the core/plugin split exists to
//! remove. A lean consumer roots its plugins module at the one file it
//! needs instead: `-Msekretoplugins=plugins/hashicorp.zig` compiles
//! hashicorp and `httpjson.zig` and nothing else, because zig analyses
//! only what a root reaches. See docs/design/plugin-providers.md.
//!
//! Also here, for whoever writes a plugin or a CLI: the shared HTTP
//! helper and the SigV4 signer.

const sekreto = @import("sekreto");

pub const httpjson = @import("httpjson.zig");
pub const sigv4 = @import("sigv4.zig");

pub const hashicorp = @import("hashicorp.zig").hashicorp;
pub const boru = @import("boru.zig").boru;
pub const awssecrets = @import("aws.zig").awssecrets;
pub const awsparams = @import("aws.zig").awsparams;
pub const gcpsecrets = @import("gcpsecrets.zig").gcpsecrets;
pub const azuresecrets = @import("azuresecrets.zig").azuresecrets;
pub const onepassword = @import("onepassword.zig").onepassword;
pub const doppler = @import("doppler.zig").doppler;
pub const infisical = @import("infisical.zig").infisical;
pub const secretspec = @import("secretspec.zig").secretspec;

/// Every plugin definition this library ships.
pub const ALL = [_]sekreto.Definition{
    hashicorp,    boru,        awssecrets, awsparams, gcpsecrets,
    azuresecrets, onepassword, doppler,    infisical, secretspec,
};
