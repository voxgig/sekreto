// RUN: make test
// RUN-SOME: cd testutil && go test -run 'TestSekreto/envkey'
//
// The commands name this NESTED module deliberately. This suite lives
// outside the published module (register 4.13: nothing the library
// builds may name omni), so `go test ./...` from the port root skips it
// entirely and reports a green that ran no conformance at all.
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.

package sekreto_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	omni "github.com/voxgig/omni/go"
	"github.com/voxgig/sekreto/go/plugins"
	"github.com/voxgig/sekreto/go/plugins/aws"
	"github.com/voxgig/sekreto/go/sekreto"
)

// Find the shared spec directory by walking up from the working directory.
func specfile(t *testing.T, name string) string {
	t.Helper()

	dir, err := os.Getwd()
	if nil != err {
		t.Fatalf("sekreto: no working directory: %v", err)
	}

	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "spec", name)
		if _, err := os.Stat(cand); nil == err {
			return cand
		}
		dir = filepath.Dir(dir)
	}

	t.Fatalf("sekreto: spec not found: %s", name)
	return ""
}

// The spec describes a provider chain as plain JSON. Re-encoding is the
// shortest honest route from omni's `any` to the library's typed specs.
//
// THE CONFORMANCE SUITE LOADS EVERY PLUGIN, deliberately. The spec is the
// contract for the whole library and exercises all fourteen provider
// kinds, so this suite hands the full set to every Sekreto it builds.
// That is the split working, not a leak of it: a CONSUMER passes the
// kinds it configures and links nothing else, while the suite that
// proves all fourteen behave has to have all fourteen.
func chainof(value any) (*sekreto.Sekreto, error) {
	entry, is := value.(map[string]any)
	if !is {
		return nil, nil
	}

	text, err := json.Marshal(entry["chain"])
	if nil != err {
		return nil, err
	}

	var specs []*sekreto.ProviderSpec
	if err := json.Unmarshal(text, &specs); nil != err {
		return nil, err
	}

	return sekreto.New(&sekreto.Options{
		Plugins:   plugins.All(),
		Providers: specs,
		NoCache:   true,
	})
}

func text(value any) string {
	out, _ := value.(string)
	return out
}

// The subjects, adapted to the omni calling convention.
var (
	VALIDNAME = omni.Subject(func(args ...any) (any, error) {
		return sekreto.ValidName(args[0]), nil
	})

	ENVKEY = omni.Subject(func(args ...any) (any, error) {
		entry, _ := args[0].(map[string]any)
		return sekreto.EnvKey(text(entry["name"]), text(entry["prefix"]))
	})

	VAULTREF = omni.Subject(func(args ...any) (any, error) {
		ref, err := sekreto.NameVaultRef(text(args[0]))
		if nil != err {
			return nil, err
		}
		// omni compares against the spec's JSON, so answer in that shape.
		return map[string]any{"path": ref.Path, "field": ref.Field}, nil
	})

	FLATNAME = omni.Subject(func(args ...any) (any, error) {
		entry, _ := args[0].(map[string]any)
		return sekreto.FlatName(text(entry["name"]), text(entry["sep"]))
	})

	AWSPARAM = omni.Subject(func(args ...any) (any, error) {
		entry, _ := args[0].(map[string]any)
		return sekreto.AwsParam(text(entry["name"]), text(entry["prefix"]))
	})

	SIGV4 = omni.Subject(func(args ...any) (any, error) {
		// Re-encoding is the shortest honest route from omni's `any` to
		// the library's typed input, exactly as chainof does for chains.
		data, err := json.Marshal(args[0])
		if nil != err {
			return nil, err
		}

		// SigV4 lives with the aws plugin - it is the crypto edge, and
		// only the two aws kinds use it (docs/design/plugin-providers.md).
		var input aws.Sigv4Input
		if err := json.Unmarshal(data, &input); nil != err {
			return nil, err
		}

		signed, err := aws.SigV4(&input)
		if nil != err {
			return nil, err
		}

		// omni compares against the spec's JSON, so answer in that shape.
		out := map[string]any{}
		for key, value := range signed {
			out[key] = value
		}
		return out, nil
	})

	PARSEDOTENV = omni.Subject(func(args ...any) (any, error) {
		out := map[string]any{}
		for key, value := range sekreto.ParseDotenv(text(args[0])) {
			out[key] = value
		}
		return out, nil
	})

	RESOLVE = omni.Subject(func(args ...any) (any, error) {
		secrets, err := chainof(args[0])
		if nil != err {
			return nil, err
		}
		entry, _ := args[0].(map[string]any)
		return secrets.Get(text(entry["name"]))
	})

	TRYSECRET = omni.Subject(func(args ...any) (any, error) {
		secrets, err := chainof(args[0])
		if nil != err {
			return nil, err
		}
		entry, _ := args[0].(map[string]any)

		found, has, err := secrets.Try(text(entry["name"]))
		if nil != err {
			return nil, err
		}
		if !has {
			return nil, nil
		}
		return found, nil
	})

	STORES = omni.Subject(func(args ...any) (any, error) {
		secrets, err := chainof(args[0])
		if nil != err {
			return nil, err
		}

		out := []any{}
		for _, store := range secrets.Stores() {
			out = append(out, store)
		}
		return out, nil
	})

	GETFROM = omni.Subject(func(args ...any) (any, error) {
		secrets, err := chainof(args[0])
		if nil != err {
			return nil, err
		}
		entry, _ := args[0].(map[string]any)
		return secrets.GetFrom(text(entry["store"]), text(entry["name"]))
	})

	TRYFROM = omni.Subject(func(args ...any) (any, error) {
		secrets, err := chainof(args[0])
		if nil != err {
			return nil, err
		}
		entry, _ := args[0].(map[string]any)

		found, has, err := secrets.TryFrom(text(entry["store"]), text(entry["name"]))
		if nil != err {
			return nil, err
		}
		if !has {
			return nil, nil
		}
		return found, nil
	})

	SOURCES = omni.Subject(func(args ...any) (any, error) {
		secrets, err := chainof(args[0])
		if nil != err {
			return nil, err
		}

		out := []any{}
		for _, source := range secrets.Sources() {
			out = append(out, source)
		}
		return out, nil
	})

	REDACT = omni.Subject(func(args ...any) (any, error) {
		entry, _ := args[0].(map[string]any)

		values := []string{}
		if list, is := entry["values"].([]any); is {
			for _, value := range list {
				values = append(values, text(value))
			}
		}

		return sekreto.Redact(text(entry["text"]), values), nil
	})
)

func TestSekreto(t *testing.T) {
	runner, err := omni.MakeRunner(specfile(t, "sekreto.json"), nil)
	if nil != err {
		t.Fatalf("sekreto: cannot make runner: %v", err)
	}

	R, err := runner("sekreto", nil)
	if nil != err {
		t.Fatalf("sekreto: cannot resolve spec: %v", err)
	}

	groups := []struct {
		name    string
		subject omni.Subject
		flags   omni.Flags
	}{
		{"validname", VALIDNAME, omni.Flags{"null": false}},
		{"envkey", ENVKEY, nil},
		{"vaultref", VAULTREF, nil},
		{"flatname", FLATNAME, nil},
		{"awsparam", AWSPARAM, nil},
		{"parsedotenv", PARSEDOTENV, nil},
		{"resolve", RESOLVE, nil},
		{"trysecret", TRYSECRET, nil},
		{"sources", SOURCES, nil},
		{"stores", STORES, nil},
		{"getfrom", GETFROM, nil},
		{"tryfrom", TRYFROM, nil},
		{"sigv4", SIGV4, nil},
		{"redact", REDACT, nil},
	}

	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			flags := group.flags
			if nil == flags {
				flags = omni.Flags{}
			}
			if err := R.RunSetFlags(R.Set(group.name), flags, group.subject); nil != err {
				t.Fatal(err)
			}
		})
	}
}
