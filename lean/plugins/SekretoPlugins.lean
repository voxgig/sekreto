/-
THE FULL SET - every plugin this library ships, in one import.

It exists for the callers that genuinely want all ten kinds: the CLI, the
conformance suite, an app whose chain is decided at run time.

    import SekretoPlugins

    sekreto { plugins := allplugins, providers := [...] }

IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Importing this
module compiles and links every plugin - AWS request signing, the libcurl
binding and seven HTTP vault clients included - which is the cost the
core/plugin split exists to remove. A lean consumer imports the kinds it
actually configures, each from its own module:

    import SekretoPlugins.Hashicorp

The module names are `SekretoPlugins.*` and the namespace is still
`Sekreto`, which is not an accident of taste. Lean resolves a module
name's first component to one directory on `LEAN_PATH` and every
submodule under that same one, so a plugin named `Sekreto.Plugins.X`
could not be built into a tree the core's own compilation cannot see -
and that separation is the boundary this port enforces with. The names a
consumer writes are unchanged.

A port of typescript/plugins/index.ts, which is canonical.
-/

import SekretoPlugins.Httpjson
import SekretoPlugins.Proc
import SekretoPlugins.Crypto
import SekretoPlugins.Clock
import SekretoPlugins.Sigv4
import SekretoPlugins.Hashicorp
import SekretoPlugins.Boru
import SekretoPlugins.Secretspec
import SekretoPlugins.Aws
import SekretoPlugins.Gcpsecrets
import SekretoPlugins.Azuresecrets
import SekretoPlugins.Onepassword
import SekretoPlugins.Doppler
import SekretoPlugins.Infisical

namespace Sekreto

/-- Every kind this library ships as a plugin, in the order the design
lists them.

A definition is data, so this is an ordinary list and two Sekretos
handed it share nothing: `Options.plugins` is copied into each chain's
own catalog. -/
def allplugins : List Plugin.Definition := [
  hashicorp, boru, awssecrets, awsparams, gcpsecrets,
  azuresecrets, onepassword, doppler, infisical, secretspec]

end Sekreto
