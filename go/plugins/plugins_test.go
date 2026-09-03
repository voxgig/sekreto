// The plugin seam, from the plugins' side: the full set holds every kind,
// every kind builds from a spec, one plugin is enough for a chain that
// names only it, and a provider's refusal of its own configuration comes
// back out of the host as the SekretoError it went in as.

package plugins_test

import (
	"sort"
	"strings"
	"testing"

	plugin "github.com/voxgig/plugin/go/plugin"

	"github.com/voxgig/sekreto/go/plugins"
	"github.com/voxgig/sekreto/go/plugins/hashicorp"
	"github.com/voxgig/sekreto/go/sekreto"
)

var kinds = []string{
	"awsparams", "awssecrets", "azuresecrets", "boru", "doppler", "gcpsecrets",
	"hashicorp", "infisical", "onepassword", "secretspec",
}

func TestTheFullSetHoldsEveryKind(t *testing.T) {
	names := []string{}
	for _, def := range plugins.All() {
		names = append(names, def.Name)
	}
	sort.Strings(names)

	if strings.Join(kinds, " ") != strings.Join(names, " ") {
		t.Fatalf("plugins: %v", names)
	}

	shipped := append([]string{}, sekreto.Kinds.Plugin...)
	sort.Strings(shipped)
	if strings.Join(kinds, " ") != strings.Join(shipped, " ") {
		t.Fatalf("Kinds.Plugin: %v", shipped)
	}
}

// Naming a kind is not enough: a kind can be in the catalog and still
// fail to build. Construction is what the CLI does before any network.
func TestEveryKindBuildsFromASpec(t *testing.T) {
	all := append(append([]string{}, sekreto.Kinds.Builtin...), kinds...)
	sort.Strings(all)

	chain := []*sekreto.ProviderSpec{}
	for _, kind := range all {
		chain = append(chain, &sekreto.ProviderSpec{
			Kind: kind, Addr: "http://127.0.0.1:8200", Token: "t",
			Dir: "/tmp", File: "/tmp/.env", Values: map[string]string{},
		})
	}

	sek, err := sekreto.New(&sekreto.Options{Plugins: plugins.All(), Providers: chain})
	if nil != err {
		t.Fatal(err)
	}

	if strings.Join(all, " ") != strings.Join(sek.Stores(), " ") {
		t.Fatalf("stores: %v", sek.Stores())
	}
	for ref, status := range sek.Host().List() {
		if plugin.StatusLive != status {
			t.Fatalf("%s is %s", ref, status)
		}
	}
}

func TestOnePluginIsEnough(t *testing.T) {
	sek, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{hashicorp.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "memory", Values: map[string]string{"API_TOKEN": "tok01"}},
			{Kind: "hashicorp", Name: "prod", Addr: "https://vault.example.com", Token: "t"},
		},
	})
	if nil != err {
		t.Fatal(err)
	}

	if "memory prod" != strings.Join(sek.Stores(), " ") {
		t.Fatalf("stores: %v", sek.Stores())
	}
	if "memory hashicorp:https://vault.example.com/secret" != strings.Join(sek.Sources(), " ") {
		t.Fatalf("sources: %v", sek.Sources())
	}
	if value, _ := sek.Get("api.token"); "tok01" != value {
		t.Fatalf("got %q", value)
	}

	// The plugin host is what the chain is made of, and it reads like
	// the chain: the kind, or kind$store for a named store.
	list := sek.Host().List()
	if 2 != len(list) || plugin.StatusLive != list["memory"] || plugin.StatusLive != list["hashicorp$prod"] {
		t.Fatalf("list: %v", list)
	}
	if "dotenv env file hashicorp memory" != strings.Join(sek.Catalog().Names(), " ") {
		t.Fatalf("catalog: %v", sek.Catalog().Names())
	}

	// ...and a kind that was not passed in is refused, naming the fix.
	_, err = sekreto.New(&sekreto.Options{
		Plugins:   []plugin.Definition{hashicorp.Plugin},
		Providers: []*sekreto.ProviderSpec{{Kind: "doppler", Token: "t"}},
	})
	want := "sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)" +
		" - doppler is a sekreto plugin, not built in: pass it in the Plugins option"
	if nil == err || want != err.Error() {
		t.Fatalf("got %v", err)
	}
}

// A provider that refuses its own configuration returns a SekretoError
// from inside the plugin's Define. The spec pins that message byte for
// byte, so it must come back out of the host as itself - not wrapped as
// plugin_define_failed, and not as a PluginError.
func TestARefusalComesBackOutAsItself(t *testing.T) {
	_, err := sekreto.New(&sekreto.Options{
		Plugins:   []plugin.Definition{hashicorp.Plugin},
		Providers: []*sekreto.ProviderSpec{{Kind: "hashicorp", Addr: "http://127.0.0.1:1", Token: "t", KV: 3}},
	})

	if nil == err || "sekreto: hashicorp: unsupported kv version: 3" != err.Error() {
		t.Fatalf("got %v", err)
	}
	if _, is := err.(*sekreto.SekretoError); !is {
		t.Fatalf("not a SekretoError: %T", err)
	}
}
