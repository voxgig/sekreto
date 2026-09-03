// The plugin seam, from the core's side: what a chain of built-ins can
// do with no plugin loaded, how a kind that was not loaded is refused,
// and how a custom kind joins. The plugins themselves are exercised from
// their own side in plugins/plugins_test.go, because this package cannot
// import them - they import it.

package sekreto

import (
	"strings"
	"testing"

	plugin "github.com/voxgig/plugin/go/plugin"
)

func TestBuiltinsNeedNoPlugin(t *testing.T) {
	sek, err := New(&Options{Providers: []*ProviderSpec{
		{Kind: "memory", Values: map[string]string{"API_TOKEN": "tok01"}},
		{Kind: "env"},
		{Kind: "dotenv", File: "/nonexistent-sekreto-test/.env"},
		{Kind: "file", Dir: "/nonexistent-sekreto-test"},
	}})
	if nil != err {
		t.Fatal(err)
	}

	value, err := sek.Get("api.token")
	if nil != err || "tok01" != value {
		t.Fatalf("got %q, %v", value, err)
	}

	want := []string{"memory", "env", "dotenv", "file"}
	if strings.Join(want, " ") != strings.Join(sek.Stores(), " ") {
		t.Fatalf("stores: %v", sek.Stores())
	}

	names := sek.Catalog().Names()
	if "dotenv env file memory" != strings.Join(names, " ") {
		t.Fatalf("catalog: %v", names)
	}

	// The host reads like the chain, and every entry is live.
	for ref, status := range sek.Host().List() {
		if "live" != string(status) {
			t.Fatalf("%s is %s", ref, status)
		}
	}
}

func TestUnknownKindNamesTheFix(t *testing.T) {
	_, err := New(&Options{Providers: []*ProviderSpec{{Kind: "hashicorp", Addr: "https://v", Token: "t"}}})
	want := "sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)" +
		" - hashicorp is a sekreto plugin, not built in: pass it in the Plugins option"
	if nil == err || want != err.Error() {
		t.Fatalf("got %v", err)
	}
	if _, is := err.(*SekretoError); !is {
		t.Fatalf("not a SekretoError: %T", err)
	}

	// A kind nobody ships is a typo, and gets no such hint.
	_, err = New(&Options{Providers: []*ProviderSpec{{Kind: "vualt"}}})
	if nil == err || "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)" != err.Error() {
		t.Fatalf("got %v", err)
	}
}

// Two providers MAY share a store name - a directed read walks both, and
// the spec pins it - but an instance ref may not, so the second gets a
// numbered tag from the host and keeps its store name.
func TestRepeatedStoreNameNumbersTheInstance(t *testing.T) {
	sek, err := New(&Options{Providers: []*ProviderSpec{
		{Kind: "memory", Values: map[string]string{}},
		{Kind: "memory", Values: map[string]string{"API_TOKEN": "second"}},
		{Kind: "memory", Name: "pair", Values: map[string]string{}},
		{Kind: "memory", Name: "pair", Values: map[string]string{"API_TOKEN": "pair2"}},
	}})
	if nil != err {
		t.Fatal(err)
	}

	if "memory pair" != strings.Join(sek.Stores(), " ") {
		t.Fatalf("stores: %v", sek.Stores())
	}

	refs := []string{}
	for ref := range sek.Host().List() {
		refs = append(refs, ref)
	}
	sortstrings(refs)
	if "memory memory$1 memory$2 memory$pair" != strings.Join(refs, " ") {
		t.Fatalf("refs: %v", refs)
	}

	if value, _ := sek.GetFrom("memory", "api.token"); "second" != value {
		t.Fatalf("memory: %q", value)
	}
	if value, _ := sek.GetFrom("pair", "api.token"); "pair2" != value {
		t.Fatalf("pair: %q", value)
	}
}

func TestStoreNameMustBeATag(t *testing.T) {
	_, err := New(&Options{Providers: []*ProviderSpec{{Kind: "memory", Name: "my store"}}})
	if nil == err || "sekreto: invalid store name: my store" != err.Error() {
		t.Fatalf("got %v", err)
	}
}

type shouty struct{ values map[string]string }

func (provider *shouty) Lookup(name string) (string, bool, error) {
	value, has := provider.values[strings.ToUpper(name)]
	return value, has, nil
}

func (provider *shouty) Describe() string { return "shouty" }

// A custom kind is one ProviderPlugin call - and a provider that refuses
// its configuration returns a SekretoError from inside the plugin's
// Define, which must come back out of the host as itself, byte for byte,
// because the spec pins those messages.
func TestCustomKindAndItsRefusal(t *testing.T) {
	kind := ProviderPlugin("shouty", func(spec *ProviderSpec) (Provider, error) {
		if nil == spec.Values {
			return nil, Fail("sekreto: shouty: no values")
		}
		return &shouty{values: spec.Values}, nil
	})

	sek, err := New(&Options{
		Plugins:   []plugin.Definition{kind},
		Providers: []*ProviderSpec{{Kind: "shouty", Values: map[string]string{"API.TOKEN": "loud"}}},
	})
	if nil != err {
		t.Fatal(err)
	}
	if value, _ := sek.Get("api.token"); "loud" != value {
		t.Fatalf("got %q", value)
	}

	_, err = New(&Options{
		Plugins:   []plugin.Definition{kind},
		Providers: []*ProviderSpec{{Kind: "shouty"}},
	})
	if nil == err || "sekreto: shouty: no values" != err.Error() {
		t.Fatalf("got %v", err)
	}
	if _, is := err.(*SekretoError); !is {
		t.Fatalf("not a SekretoError: %T", err)
	}
}

// A provider already built joins the chain as it is, under its own
// store name, backed by no instance.
func TestLiveProviderJoinsTheChain(t *testing.T) {
	sek, err := New(&Options{Providers: []*ProviderSpec{
		{Provider: &shouty{values: map[string]string{"API.TOKEN": "loud"}}},
		{Provider: &shouty{values: map[string]string{}}, Name: "quiet"},
	}})
	if nil != err {
		t.Fatal(err)
	}
	if "shouty quiet" != strings.Join(sek.Stores(), " ") {
		t.Fatalf("stores: %v", sek.Stores())
	}
	if 0 != len(sek.Host().List()) {
		t.Fatalf("instances: %v", sek.Host().List())
	}
	if value, _ := sek.Get("api.token"); "loud" != value {
		t.Fatalf("got %q", value)
	}
}

func TestCloseTearsDownAndKeepsRedaction(t *testing.T) {
	sek, err := New(&Options{Providers: []*ProviderSpec{
		{Kind: "memory", Values: map[string]string{"API_TOKEN": "tok01"}},
	}})
	if nil != err {
		t.Fatal(err)
	}
	if _, err := sek.Get("api.token"); nil != err {
		t.Fatal(err)
	}

	if err := sek.Close(); nil != err {
		t.Fatal(err)
	}

	if 0 != len(sek.Host().List()) || 0 != len(sek.Stores()) {
		t.Fatalf("still open: %v %v", sek.Host().List(), sek.Stores())
	}
	if _, has, _ := sek.Try("api.token"); has {
		t.Fatal("still resolving after close")
	}
	if "token=[redacted]" != sek.Redact("token=tok01") {
		t.Fatal("redaction lost")
	}
}

func sortstrings(list []string) {
	for i := 1; i < len(list); i++ {
		for j := i; 0 < j && list[j] < list[j-1]; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}
