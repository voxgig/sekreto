// THE FULL SET - every plugin this library ships, in one import.
//
// It exists for the callers that genuinely want all ten kinds: the CLI,
// the conformance suite, an app whose chain is decided at run time.
//
//	secrets, err := sekreto.New(&sekreto.Options{
//	    Plugins:   plugins.All(),
//	    Providers: chain,
//	})
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Importing this
// package links every plugin - AWS request signing and seven HTTP vault
// clients included - which is the cost the core/plugin split exists to
// remove. A lean consumer imports the kinds it actually configures, each
// from its own package:
//
//	import "github.com/voxgig/sekreto/go/plugins/hashicorp"
//	Plugins: []plugin.Definition{hashicorp.Plugin}
//
// See docs/design/plugin-providers.md.
package plugins

import (
	plugin "github.com/voxgig/plugin/go/plugin"

	"github.com/voxgig/sekreto/go/plugins/aws"
	"github.com/voxgig/sekreto/go/plugins/azuresecrets"
	"github.com/voxgig/sekreto/go/plugins/boru"
	"github.com/voxgig/sekreto/go/plugins/doppler"
	"github.com/voxgig/sekreto/go/plugins/gcpsecrets"
	"github.com/voxgig/sekreto/go/plugins/hashicorp"
	"github.com/voxgig/sekreto/go/plugins/infisical"
	"github.com/voxgig/sekreto/go/plugins/onepassword"
	"github.com/voxgig/sekreto/go/plugins/secretspec"
)

// All is every plugin definition this library ships, in a fresh slice.
func All() []plugin.Definition {
	return []plugin.Definition{
		hashicorp.Plugin, boru.Plugin, aws.Secrets, aws.Params, gcpsecrets.Plugin,
		azuresecrets.Plugin, onepassword.Plugin, doppler.Plugin, infisical.Plugin,
		secretspec.Plugin,
	}
}
