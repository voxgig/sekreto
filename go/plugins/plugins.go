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
	"github.com/voxgig/sekreto/go/plugins/minivault"
	"github.com/voxgig/sekreto/go/plugins/onepassword"
	"github.com/voxgig/sekreto/go/plugins/secretspec"
)

// All is every plugin definition this library ships, in a fresh slice.
func All() []plugin.Definition {
	return []plugin.Definition{
		hashicorp.Plugin, boru.Plugin, aws.Secrets, aws.Params, gcpsecrets.Plugin,
		azuresecrets.Plugin, onepassword.Plugin, doppler.Plugin, infisical.Plugin,
		secretspec.Plugin, minivault.Plugin,
	}
}
