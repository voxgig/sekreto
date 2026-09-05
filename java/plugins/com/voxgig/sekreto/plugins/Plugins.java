// THE FULL SET - every plugin this library ships, in one class.
//
// It exists for the callers that genuinely want all ten kinds: the CLI,
// the conformance suite, an app whose chain is decided at run time.
//
//     new Sekreto(new Sekreto.Options()
//         .plugins(Plugins.ALL)
//         .providers(chain));
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Naming this class
// reaches every plugin - AWS request signing and seven HTTP vault clients
// included - which is the cost the core/plugin split exists to remove. A
// lean consumer names the kinds it actually configures, and javac links
// no more than those:
//
//     .plugins(List.of(Hashicorp.PLUGIN))
//
// See docs/design/plugin-providers.md.

package com.voxgig.sekreto.plugins;

import java.util.List;
import voxgig.plugin.Definition;

public final class Plugins {

  private Plugins() {}

  /** Every plugin definition this library ships. */
  public static final List<Definition> ALL = List.of(
      Hashicorp.PLUGIN, Boru.PLUGIN, Aws.SECRETS, Aws.PARAMS, Gcpsecrets.PLUGIN,
      Azuresecrets.PLUGIN, Onepassword.PLUGIN, Doppler.PLUGIN, Infisical.PLUGIN,
      Secretspec.PLUGIN);
}
