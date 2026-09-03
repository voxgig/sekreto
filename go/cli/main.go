// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
// gcpsecrets azuresecrets onepassword doppler infisical secretspec chain
//
// Each source's configuration arrives in the environment variables its
// own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
// in chainfor below.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/voxgig/sekreto/go/plugins"
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
	filespec := &sekreto.ProviderSpec{
		Kind: "file",
		Dir:  envor("SEKRETO_FILEDIR", "/run/secrets"),
	}

	// A kv of 0 means "unset", and the provider defaults it to 2.
	kv, _ := strconv.Atoi(os.Getenv("VAULT_KV"))

	var auth *sekreto.AuthSpec
	if "" != os.Getenv("VAULT_AUTH") {
		auth = &sekreto.AuthSpec{
			Method:   os.Getenv("VAULT_AUTH"),
			Role:     os.Getenv("VAULT_ROLE"),
			JwtFile:  os.Getenv("VAULT_JWT_FILE"),
			RoleID:   os.Getenv("VAULT_ROLE_ID"),
			SecretID: os.Getenv("VAULT_SECRET_ID"),
		}
	}

	hashicorpspec := &sekreto.ProviderSpec{
		Kind:           "hashicorp",
		Addr:           os.Getenv("VAULT_ADDR"),
		Token:          os.Getenv("VAULT_TOKEN"),
		Mount:          os.Getenv("VAULT_MOUNT"),
		KV:             kv,
		VaultNamespace: os.Getenv("VAULT_NAMESPACE"),
		Auth:           auth,
	}
	boruspec := &sekreto.ProviderSpec{
		Kind:      "boru",
		Command:   envor("BORU_COMMAND", "boru"),
		Namespace: os.Getenv("BORU_NAMESPACE"),
		Home:      os.Getenv("BORU_HOME"),
	}

	// The same vault over its wire protocol (`boru vault serve`) instead
	// of the CLI: an address plus a capability token from `vault grant`.
	boruwirespec := &sekreto.ProviderSpec{
		Kind:      "boru",
		Addr:      os.Getenv("BORU_ADDR"),
		Token:     os.Getenv("BORU_TOKEN"),
		Namespace: os.Getenv("BORU_NAMESPACE"),
	}

	awssecretsspec := &sekreto.ProviderSpec{
		Kind:   "awssecrets",
		Region: os.Getenv("AWS_REGION"),
		Addr:   os.Getenv("AWS_ENDPOINT"),
	}

	awsparamsspec := &sekreto.ProviderSpec{
		Kind:   "awsparams",
		Region: os.Getenv("AWS_REGION"),
		Addr:   os.Getenv("AWS_ENDPOINT"),
		Prefix: os.Getenv("AWS_PARAM_PREFIX"),
	}

	gcpspec := &sekreto.ProviderSpec{
		Kind:         "gcpsecrets",
		Project:      os.Getenv("GCP_PROJECT"),
		Addr:         os.Getenv("GCP_ADDR"),
		MetadataAddr: os.Getenv("GCP_METADATA_ADDR"),
	}

	azurespec := &sekreto.ProviderSpec{
		Kind:         "azuresecrets",
		Vault:        os.Getenv("AZURE_VAULT"),
		Token:        os.Getenv("AZURE_TOKEN"),
		Tenant:       os.Getenv("AZURE_TENANT"),
		ClientID:     os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
		LoginAddr:    os.Getenv("AZURE_LOGIN_ADDR"),
		ImdsAddr:     os.Getenv("AZURE_IMDS_ADDR"),
	}

	onepasswordspec := &sekreto.ProviderSpec{
		Kind:  "onepassword",
		Addr:  os.Getenv("OP_CONNECT_HOST"),
		Token: os.Getenv("OP_CONNECT_TOKEN"),
		Vault: os.Getenv("OP_VAULT"),
	}

	dopplerspec := &sekreto.ProviderSpec{
		Kind:    "doppler",
		Token:   os.Getenv("DOPPLER_TOKEN"),
		Project: os.Getenv("DOPPLER_PROJECT"),
		Config:  os.Getenv("DOPPLER_CONFIG"),
		Addr:    os.Getenv("DOPPLER_ADDR"),
	}

	// SecretSpec's own environment variables where it has them, so a
	// shell already set up for secretspec needs nothing further.
	secretspecspec := &sekreto.ProviderSpec{
		Kind:    "secretspec",
		Command: envor("SECRETSPEC_COMMAND", "secretspec"),
		File:    os.Getenv("SECRETSPEC_FILE"),
		Profile: os.Getenv("SECRETSPEC_PROFILE"),
		Backend: os.Getenv("SECRETSPEC_PROVIDER"),
		Reason:  os.Getenv("SECRETSPEC_REASON"),
	}

	infisicalspec := &sekreto.ProviderSpec{
		Kind:         "infisical",
		Addr:         os.Getenv("INFISICAL_ADDR"),
		Token:        os.Getenv("INFISICAL_TOKEN"),
		ClientID:     os.Getenv("INFISICAL_CLIENT_ID"),
		ClientSecret: os.Getenv("INFISICAL_CLIENT_SECRET"),
		Project:      os.Getenv("INFISICAL_PROJECT"),
		Environment:  os.Getenv("INFISICAL_ENV"),
		Path:         os.Getenv("INFISICAL_PATH"),
	}

	switch source {
	case "env":
		return []*sekreto.ProviderSpec{envspec}
	case "dotenv":
		return []*sekreto.ProviderSpec{dotenvspec}
	case "file":
		return []*sekreto.ProviderSpec{filespec}
	case "hashicorp":
		return []*sekreto.ProviderSpec{hashicorpspec}
	case "boru":
		return []*sekreto.ProviderSpec{boruspec}
	case "boruwire":
		return []*sekreto.ProviderSpec{boruwirespec}
	case "awssecrets":
		return []*sekreto.ProviderSpec{awssecretsspec}
	case "awsparams":
		return []*sekreto.ProviderSpec{awsparamsspec}
	case "gcpsecrets":
		return []*sekreto.ProviderSpec{gcpspec}
	case "azuresecrets":
		return []*sekreto.ProviderSpec{azurespec}
	case "onepassword":
		return []*sekreto.ProviderSpec{onepasswordspec}
	case "doppler":
		return []*sekreto.ProviderSpec{dopplerspec}
	case "infisical":
		return []*sekreto.ProviderSpec{infisicalspec}
	case "secretspec":
		return []*sekreto.ProviderSpec{secretspecspec}
	default:
		// The default: the chain an app would actually ship with - local
		// overrides first, shared vaults last.
		return []*sekreto.ProviderSpec{envspec, dotenvspec, hashicorpspec, boruspec}
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

	// --store names a store outright: the secret must come from that one,
	// not from whichever provider happens to answer first.
	store := ""
	for index, arg := range args {
		if "--store" == arg && index+1 < len(args) {
			store = args[index+1]
		}
	}

	// THE FULL SET, passed to New. The CLI is asked for any provider kind
	// on the command line, so it is the one consumer that legitimately
	// wants all ten plugins; an app passes the one or two it configures,
	// and links nothing else.
	secrets, err := sekreto.New(&sekreto.Options{
		Plugins:   plugins.All(),
		Providers: chainfor(source),
	})
	if nil != err {
		fmt.Fprintln(os.Stderr, "sekreto-cli: "+err.Error())
		return 2
	}

	var token string
	if "" == store {
		token, err = secrets.Get("api.token")
	} else {
		token, err = secrets.GetFrom(store, "api.token")
	}
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
		Store  string `json:"store"`
		Caller string `json:"caller"`
	}{Ok: true, Lang: lang, Source: source, Store: store, Caller: caller})

	fmt.Println(string(out))

	return 0
}

func main() {
	os.Exit(run())
}
