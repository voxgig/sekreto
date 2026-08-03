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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
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
	Kind string `json:"kind"`
	// Name is the store name GetFrom addresses. Defaults to Kind.
	Name   string            `json:"name"`
	Prefix string            `json:"prefix"`
	File   string            `json:"file"`
	Values map[string]string `json:"values"`
	// hashicorp
	Addr  string `json:"addr"`
	Token string `json:"token"`
	Mount string `json:"mount"`
	// boru
	Command   string `json:"command"`
	Namespace string `json:"namespace"`
	Home      string `json:"home"`
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

// checkaddr refuses to send a Vault token in the clear.
//
// Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
// convenience. Sending X-Vault-Token over http to anything but the local
// machine puts both the token and the secret it fetches on the wire for
// anyone on the path, so sekreto will not do it. Loopback stays allowed:
// that is `vault server -dev` and this repo's own test harness.
func checkaddr(addr string) error {
	if strings.HasPrefix(addr, "https://") {
		return nil
	}

	if !strings.HasPrefix(addr, "http://") {
		return fail("sekreto: not an http(s) address: " + addr)
	}

	host := strings.Split(strings.Split(strings.TrimPrefix(addr, "http://"), "/")[0], ":")[0]

	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return nil
	}

	return fail("sekreto: refusing to send a token in plaintext to " + addr + " (use https)")
}

// HashicorpProvider reads HashiCorp Vault, KV v2.
//
// api.token reads {addr}/v1/{mount}/data/api and takes the `token` field of
// data.data. A 404 means "not here", which is a miss rather than an error,
// so a vault can sit in a chain with fallbacks.
type HashicorpProvider struct {
	Addr  string
	Token string
	Mount string
}

func (provider *HashicorpProvider) mount() string {
	if "" == provider.Mount {
		return "secret"
	}
	return provider.Mount
}

func (provider *HashicorpProvider) Lookup(name string) (string, bool, error) {
	if err := checkaddr(provider.Addr); nil != err {
		return "", false, err
	}

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
		return "", false, fail("sekreto: hashicorp error: " + strconv.Itoa(status) + ": " + target)
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

func (provider *HashicorpProvider) Describe() string {
	return "hashicorp:" + provider.Addr + "/" + provider.mount()
}

// BoruProvider reads a boru vault (https://github.com/boru-lang/boru).
//
// boru keeps secrets in a local encrypted keyring and hands a value out
// through its own CLI: `boru vault get --reveal <alias>` prints the secret on
// stdout, and nothing else.
//
// There is deliberately no HTTP read here. boru's `vault proxy` and
// `vault mcp` are a *credential broker*: they inject the real secret into an
// outbound request and forward it, so an agent can call an API without ever
// holding the credential. Handing a value back is the one thing that broker
// is built not to do, so sekreto reads the vault the way boru itself does -
// through the CLI.
//
// A sekreto name is already a valid boru alias, so api.token crosses over
// unchanged. A Namespace qualifies it the way boru writes it, ns:name.
//
// The passphrase is read by boru itself from BORU_VAULT_PASSPHRASE. sekreto
// never accepts it as config and never puts it on a command line, where it
// would show up in the process table.
type BoruProvider struct {
	Command   string
	Namespace string
	Home      string
}

func (provider *BoruProvider) command() string {
	if "" == provider.Command {
		return "boru"
	}
	return provider.Command
}

func (provider *BoruProvider) Lookup(name string) (string, bool, error) {
	if err := checkname(name); nil != err {
		return "", false, err
	}

	alias := name
	if "" != provider.Namespace {
		alias = provider.Namespace + ":" + name
	}

	run := exec.Command(provider.command(), "vault", "get", "--reveal", alias)

	if "" != provider.Home {
		run.Env = append(os.Environ(), "BORU_HOME="+provider.Home)
	}

	var out, errout bytes.Buffer
	run.Stdout = &out
	run.Stderr = &errout

	err := run.Run()

	if nil == err {
		// boru prints the value and one newline, and nothing else.
		return strings.TrimSuffix(out.String(), "\n"), true, nil
	}

	var exiterr *exec.ExitError
	if !errors.As(err, &exiterr) {
		return "", false, fail("sekreto: cannot run " + provider.command() + ": " + err.Error())
	}

	why := strings.TrimSpace(errout.String())

	// "no alias named" is boru saying it does not hold this secret, which is a
	// miss: the chain carries on to the next provider. A locked vault or a
	// wrong passphrase is not a miss - treating it as one would fall through
	// to a weaker store without saying so.
	if borumiss(why) {
		return "", false, nil
	}

	if "" == why {
		why = "exit " + strconv.Itoa(exiterr.ExitCode())
	}

	return "", false, fail("sekreto: boru vault error: " + why)
}

func (provider *BoruProvider) Describe() string {
	if "" != provider.Namespace {
		return "boru:" + provider.Namespace
	}
	return "boru"
}

// borumiss reports whether a boru failure means "no such secret" rather than
// "I could not answer". Matched on boru's own wording for a missing alias.
func borumiss(why string) bool {
	return strings.Contains(why, "no alias named")
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
	case "hashicorp":
		return &HashicorpProvider{Addr: spec.Addr, Token: spec.Token, Mount: spec.Mount}, nil
	case "boru":
		return &BoruProvider{
			Command:   spec.Command,
			Namespace: spec.Namespace,
			Home:      spec.Home,
		}, nil
	default:
		return nil, fail("sekreto: unknown provider kind: " + spec.Kind)
	}
}

// MakeChain builds a whole provider chain from its declarative form.
func MakeChain(specs []*ProviderSpec) ([]Provider, error) {
	providers, _, err := MakeNamedChain(specs)
	return providers, err
}

// MakeNamedChain builds a chain and the store name each provider answers to,
// so that Sekreto.GetFrom can address them.
func MakeNamedChain(specs []*ProviderSpec) ([]Provider, []string, error) {
	providers := []Provider{}
	names := []string{}

	for _, spec := range specs {
		provider, err := MakeProvider(spec)
		if nil != err {
			return nil, nil, err
		}
		providers = append(providers, provider)
		names = append(names, spec.Name)
	}

	return providers, names, nil
}
