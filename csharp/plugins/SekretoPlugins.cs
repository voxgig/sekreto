// THE FULL SET - every plugin this library ships, in one name.
//
// It exists for the callers that genuinely want all ten kinds: the CLI,
// the conformance suite, an app whose chain is decided at run time.
//
//     var secrets = new Sekreto(new SekretoOptions
//     {
//         Plugins = SekretoPlugins.All(),
//         Providers = chain,
//     });
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Referencing this
// assembly links every plugin - AWS request signing and seven HTTP vault
// clients included - which is the cost the core/plugin split exists to
// remove. A lean consumer names the kinds it actually configures:
//
//     Plugins = new List<Definition> { Hashicorp.Plugin }
//
// See docs/design/plugin-providers.md.

using System.Collections.Generic;

using Definition = Voxgig.Plugin.Definition;

namespace Voxgig.Sekreto.Plugins
{
    /// <summary>Every plugin definition this library ships.</summary>
    public static class SekretoPlugins
    {
        /// <summary>
        /// The full set, in a fresh list, in the order the design doc
        /// lists them.
        /// </summary>
        public static List<Definition> All()
        {
            return new List<Definition>
            {
                Hashicorp.Plugin,
                Boru.Plugin,
                AwsPlugins.Secrets,
                AwsPlugins.Params,
                GcpSecrets.Plugin,
                AzureSecrets.Plugin,
                OnePassword.Plugin,
                Doppler.Plugin,
                Infisical.Plugin,
                SecretSpec.Plugin,
            };
        }
    }
}
