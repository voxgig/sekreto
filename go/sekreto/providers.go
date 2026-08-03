// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value and whether it had it - a false means "ask the next one".
// Nothing else about a provider is visible to the caller, which is the
// point: an app reads `api.token` and never learns whether it came from the
// environment, a .env file, HashiCorp Vault or a boru vault.
//
// A port of typescript/src/Providers.ts, which is canonical.

package sekreto

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Provider is a source of secrets.
type Provider interface {
	// Lookup returns the value and whether this provider has it.
	Lookup(name string) (string, bool, error)
	// Describe is a short description, shown by Sekreto.Sources.
	Describe() string
}

// ProviderSpec is the declarative form of a provider, as used in config and
// in the shared spec.
type ProviderSpec struct {
	Kind   string            `json:"kind"`
	Prefix string            `json:"prefix"`
	File   string            `json:"file"`
	Values map[string]string `json:"values"`
	Addr   string            `json:"addr"`
	Token  string            `json:"token"`
	Mount  string            `json:"mount"`
}

// EnvProvider reads environment variables: api.token from API_TOKEN.
type EnvProvider struct {
	Prefix string
	// Source overrides the process environment, for tests.
	Source map[string]string
}

func (provider *EnvProvider) Lookup(name string) (string, bool, error) {
	key, err := EnvKey(name, provider.Prefix)
	if nil != err {
		return "", false, err
	}

	if nil != provider.Source {
		value, has := provider.Source[key]
		return value, has, nil
	}

	value, has := os.LookupEnv(key)
	return value, has, nil
}

func (provider *EnvProvider) Describe() string {
	if "" != provider.Prefix {
		return "env:" + provider.Prefix
	}
	return "env"
}

// DotenvProvider reads a `.env` file once, keyed exactly like the
// environment.
type DotenvProvider struct {
	File   string
	Prefix string
	values map[string]string
}

func (provider *DotenvProvider) load() map[string]string {
	if nil == provider.values {
		text, err := os.ReadFile(provider.File)
		if nil != err {
			// A missing .env file is not an error: it means "no secrets
			// here".
			provider.values = map[string]string{}
		} else {
			provider.values = ParseDotenv(string(text))
		}
	}

	return provider.values
}

func (provider *DotenvProvider) Lookup(name string) (string, bool, error) {
	key, err := EnvKey(name, provider.Prefix)
	if nil != err {
		return "", false, err
	}

	value, has := provider.load()[key]
	return value, has, nil
}

func (provider *DotenvProvider) Describe() string {
	return "dotenv:" + provider.File
}

// MemoryProvider holds literal values, keyed like environment variables.
// The spec uses this to test chain behaviour without touching the outside
// world.
type MemoryProvider struct {
	Values map[string]string
	Prefix string
}

func (provider *MemoryProvider) Lookup(name string) (string, bool, error) {
	key, err := EnvKey(name, provider.Prefix)
	if nil != err {
		return "", false, err
	}

	value, has := provider.Values[key]
	return value, has, nil
}

func (provider *MemoryProvider) Describe() string {
	if "" != provider.Prefix {
		return "memory:" + provider.Prefix
	}
	return "memory"
}

var client = &http.Client{Timeout: 10 * time.Second}

// httpget GETs a URL, returning the status and decoded body. A 404 is a
// normal answer here, not a failure: it means the vault has no such secret.
func httpget(target string, headers map[string]string) (int, map[string]any, error) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if nil != err {
		return 0, nil, fail("sekreto: bad url: " + target)
	}

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if nil != err {
		return 0, nil, fail("sekreto: cannot reach " + target + ": " + err.Error())
	}
	defer response.Body.Close()

	text, err := io.ReadAll(response.Body)
	if nil != err {
		return response.StatusCode, nil, fail("sekreto: cannot read " + target)
	}

	var body map[string]any
	_ = json.Unmarshal(text, &body)

	return response.StatusCode, body, nil
}

// VaultProvider reads HashiCorp Vault, KV v2.
//
// api.token reads {addr}/v1/{mount}/data/api and takes the `token` field of
// data.data. A 404 means "not here", which is a miss rather than an error,
// so a vault can sit in a chain with fallbacks.
type VaultProvider struct {
	Addr  string
	Token string
	Mount string
}

func (provider *VaultProvider) mount() string {
	if "" == provider.Mount {
		return "secret"
	}
	return provider.Mount
}

func (provider *VaultProvider) Lookup(name string) (string, bool, error) {
	ref, err := NameVaultRef(name)
	if nil != err {
		return "", false, err
	}

	target := strings.TrimSuffix(provider.Addr, "/") + "/v1/" + provider.mount() +
		"/data/" + ref.Path

	status, body, err := httpget(target, map[string]string{"X-Vault-Token": provider.Token})
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: vault error: " + strconv.Itoa(status) + ": " + target)
	}

	outer, is := body["data"].(map[string]any)
	if !is {
		return "", false, nil
	}

	data, is := outer["data"].(map[string]any)
	if !is {
		return "", false, nil
	}

	value, has := data[ref.Field]
	if !has || nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *VaultProvider) Describe() string {
	return "vault:" + provider.Addr + "/" + provider.mount()
}

// BoruProvider reads a boru vault.
//
// The boru vault protocol as sekreto uses it: a GET of
// {addr}/vault/{path}?field={field} with an X-Boru-Token header, answering
// {"ok":true,"value":"..."} when the secret exists and {"ok":false} (or a
// 404) when it does not.
type BoruProvider struct {
	Addr  string
	Token string
}

func (provider *BoruProvider) Lookup(name string) (string, bool, error) {
	ref, err := NameVaultRef(name)
	if nil != err {
		return "", false, err
	}

	target := strings.TrimSuffix(provider.Addr, "/") + "/vault/" + ref.Path +
		"?field=" + url.QueryEscape(ref.Field)

	status, body, err := httpget(target, map[string]string{"X-Boru-Token": provider.Token})
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: boru vault error: " + strconv.Itoa(status) + ": " + target)
	}

	if ok, is := body["ok"].(bool); !is || !ok {
		return "", false, nil
	}

	value, has := body["value"]
	if !has || nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *BoruProvider) Describe() string {
	return "boru:" + provider.Addr
}

// tostring renders a decoded JSON scalar the way the canonical port's
// String() does.
func tostring(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		text, err := json.Marshal(typed)
		if nil != err {
			return ""
		}
		return string(text)
	}
}

// MakeProvider builds a provider from its declarative form.
func MakeProvider(spec *ProviderSpec) (Provider, error) {
	switch spec.Kind {
	case "env":
		return &EnvProvider{Prefix: spec.Prefix}, nil
	case "dotenv":
		file := spec.File
		if "" == file {
			file = ".env"
		}
		return &DotenvProvider{File: file, Prefix: spec.Prefix}, nil
	case "memory":
		values := spec.Values
		if nil == values {
			values = map[string]string{}
		}
		return &MemoryProvider{Values: values, Prefix: spec.Prefix}, nil
	case "vault":
		return &VaultProvider{Addr: spec.Addr, Token: spec.Token, Mount: spec.Mount}, nil
	case "boru":
		return &BoruProvider{Addr: spec.Addr, Token: spec.Token}, nil
	default:
		return nil, fail("sekreto: unknown provider kind: " + spec.Kind)
	}
}

// MakeChain builds a whole provider chain from its declarative form.
func MakeChain(specs []*ProviderSpec) ([]Provider, error) {
	out := []Provider{}

	for _, spec := range specs {
		provider, err := MakeProvider(spec)
		if nil != err {
			return nil, err
		}
		out = append(out, provider)
	}

	return out, nil
}
