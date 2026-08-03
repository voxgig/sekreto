// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from all four secret sources - which is what
// proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source env|dotenv|vault|boru|chain]
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/voxgig/sekreto/go/sekreto"
)

const lang = "go"

func envor(name string, fallback string) string {
	if value, has := os.LookupEnv(name); has && "" != value {
		return value
	}
	return fallback
}

func chainfor(source string) []*sekreto.ProviderSpec {
	envspec := &sekreto.ProviderSpec{Kind: "env", Prefix: os.Getenv("SEKRETO_PREFIX")}
	dotenvspec := &sekreto.ProviderSpec{
		Kind: "dotenv",
		File: envor("SEKRETO_DOTENV", ".env"),
	}
	vaultspec := &sekreto.ProviderSpec{
		Kind:  "vault",
		Addr:  os.Getenv("VAULT_ADDR"),
		Token: os.Getenv("VAULT_TOKEN"),
		Mount: os.Getenv("VAULT_MOUNT"),
	}
	boruspec := &sekreto.ProviderSpec{
		Kind:  "boru",
		Addr:  os.Getenv("BORU_VAULT_ADDR"),
		Token: os.Getenv("BORU_VAULT_TOKEN"),
	}

	switch source {
	case "env":
		return []*sekreto.ProviderSpec{envspec}
	case "dotenv":
		return []*sekreto.ProviderSpec{dotenvspec}
	case "vault":
		return []*sekreto.ProviderSpec{vaultspec}
	case "boru":
		return []*sekreto.ProviderSpec{boruspec}
	default:
		// The default: the chain an app would actually ship with - local
		// overrides first, shared vaults last.
		return []*sekreto.ProviderSpec{envspec, dotenvspec, vaultspec, boruspec}
	}
}

func run() int {
	args := os.Args[1:]

	url := "http://127.0.0.1:8099/whoami"
	if 0 < len(args) {
		url = args[0]
	}

	source := "chain"
	for index, arg := range args {
		if "--source" == arg && index+1 < len(args) {
			source = args[index+1]
		}
	}

	providers, err := sekreto.MakeChain(chainfor(source))
	if nil != err {
		fmt.Fprintln(os.Stderr, "sekreto-cli: "+err.Error())
		return 2
	}

	secrets := sekreto.New(&sekreto.Options{Providers: providers})

	token, err := secrets.Get("api.token")
	if nil != err {
		fmt.Fprintln(os.Stderr, "sekreto-cli: "+err.Error())
		return 2
	}

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if nil != err {
		fmt.Fprintln(os.Stderr, "sekreto-cli: bad url: "+url)
		return 2
	}

	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Sekreto-Lang", lang)

	response, err := http.DefaultClient.Do(request)
	if nil != err {
		fmt.Fprintln(os.Stderr, "sekreto-cli: "+secrets.Redact(err.Error()))
		return 1
	}
	defer response.Body.Close()

	text, _ := io.ReadAll(response.Body)

	if http.StatusOK != response.StatusCode {
		// Never print the token itself, even when the call fails.
		fmt.Fprintln(os.Stderr, "sekreto-cli: "+secrets.Redact(string(text)))
		return 1
	}

	var body map[string]any
	_ = json.Unmarshal(text, &body)

	caller, _ := body["caller"].(string)

	// A struct, not a map: encoding/json sorts map keys, and every port must
	// print the same bytes for test/integration.sh to compare them.
	out, _ := json.Marshal(struct {
		Ok     bool   `json:"ok"`
		Lang   string `json:"lang"`
		Source string `json:"source"`
		Caller string `json:"caller"`
	}{Ok: true, Lang: lang, Source: source, Caller: caller})

	fmt.Println(string(out))

	return 0
}

func main() {
	os.Exit(run())
}
