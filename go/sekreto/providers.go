// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value and whether it had it - a false means "ask the next one".
// Nothing else about a provider is visible to the caller, which is the
// point: an app reads `api.token` and never learns whether it came from the
// environment, a .env file, HashiCorp Vault, AWS, GCP, Azure or a boru
// vault.
//
// Two failure shapes, and they are never interchangeable. A store that does
// not hold the secret is a MISS (false) - the chain carries on. A store
// that could not answer - bad credentials, unreachable host, missing
// configuration - is an ERROR: falling through there would quietly reach
// for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

package sekreto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	// Dir is the file provider's directory of one-secret-per-file entries.
	Dir string `json:"dir"`
	// hashicorp / boru (wire) / gcp / 1password / doppler / infisical:
	// the base URL and the access token.
	Addr  string `json:"addr"`
	Token string `json:"token"`
	// Mount is the hashicorp / boru (wire) KV mount (default `secret`).
	Mount string `json:"mount"`
	// KV is the hashicorp KV engine version, 1 or 2 (default 2).
	KV int `json:"kv"`
	// VaultNamespace is the Vault Enterprise namespace (X-Vault-Namespace).
	VaultNamespace string `json:"vaultnamespace"`
	// Auth logs hashicorp in for a token instead of being handed one.
	Auth *AuthSpec `json:"auth"`
	// boru
	Command   string `json:"command"`
	Namespace string `json:"namespace"`
	Home      string `json:"home"`
	// aws: region and credentials; the standard AWS_* environment
	// variables fill whichever are not given.
	Region  string `json:"region"`
	KeyID   string `json:"keyid"`
	Secret  string `json:"secret"`
	Session string `json:"session"`
	// Project is the gcp / doppler / infisical project (GCP project id,
	// Doppler project slug, Infisical workspace id).
	Project string `json:"project"`
	// Vault is the azure Key Vault name or full URL, or the 1password
	// vault name or id.
	Vault string `json:"vault"`
	// azure: client-credential login. infisical: universal-auth login
	// (tenant is Azure-only).
	Tenant       string `json:"tenant"`
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"clientsecret"`
	// azure: where to log in / where IMDS answers. gcp: where the
	// metadata server answers. Overridable for tests and for clouds with
	// nonstandard endpoints.
	LoginAddr    string `json:"loginaddr"`
	ImdsAddr     string `json:"imdsaddr"`
	MetadataAddr string `json:"metadataaddr"`
	// ApiVersion is the azure Key Vault API version (default 7.4).
	ApiVersion string `json:"apiversion"`
	// Config is the doppler config slug (with Project).
	Config string `json:"config"`
	// infisical: the environment slug and secret path.
	Environment string `json:"environment"`
	Path        string `json:"path"`
}

// AuthSpec is how the hashicorp provider logs in for a token instead of
// being handed one.
type AuthSpec struct {
	Method string `json:"method"`
	// Mount is the auth mount, defaulting to the method name.
	Mount string `json:"mount"`
	// kubernetes: the Vault role to log in as.
	Role string `json:"role"`
	// Jwt is the service-account JWT itself (tests).
	Jwt string `json:"jwt"`
	// JwtFile is where the JWT lives; the conventional pod path by
	// default.
	JwtFile string `json:"jwtfile"`
	// approle: the role and secret ids.
	RoleID   string `json:"roleid"`
	SecretID string `json:"secretid"`
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

// FileProvider reads a directory of one-secret-per-file entries, keyed
// like the environment: api.token reads <dir>/API_TOKEN.
//
// This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
// secret, and a systemd credentials directory, so those all work with no
// further configuration. One trailing newline is stripped - tools that
// write these files disagree about it, and a newline is never part of a
// secret on purpose.
type FileProvider struct {
	Dir    string
	Prefix string
}

func (provider *FileProvider) Lookup(name string) (string, bool, error) {
	key, err := EnvKey(name, provider.Prefix)
	if nil != err {
		return "", false, err
	}

	file := filepath.Join(provider.Dir, key)

	raw, err := os.ReadFile(file)
	if nil != err {
		// An absent file - or an absent directory - means "no secrets
		// here", exactly like a missing .env. Anything else (permission
		// denied, an unreadable mount) is a store that could not answer.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return "", false, nil
		}
		return "", false, fail("sekreto: file provider cannot read " + file + ": " + err.Error())
	}

	text := string(raw)
	if strings.HasSuffix(text, "\n") {
		text = strings.TrimSuffix(strings.TrimSuffix(text, "\n"), "\r")
	}

	return text, true, nil
}

func (provider *FileProvider) Describe() string {
	return "file:" + provider.Dir
}

var client = &http.Client{Timeout: 10 * time.Second}

// httpjson makes one JSON round-trip, returning the status and decoded
// body. Network failure is always an error - an unreachable store is a
// store that could not answer.
func httpjson(method string, target string, headers map[string]string, payload string) (int, any, error) {
	var reader io.Reader
	if "" != payload {
		reader = strings.NewReader(payload)
	}

	request, err := http.NewRequest(method, target, reader)
	if nil != err {
		return 0, nil, fail("sekreto: bad url: " + target)
	}

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if nil != err {
		return 0, nil, fail("sekreto: cannot reach " +
			strings.SplitN(target, "?", 2)[0] + ": " + err.Error())
	}
	defer response.Body.Close()

	text, err := io.ReadAll(response.Body)
	if nil != err {
		return response.StatusCode, nil, fail("sekreto: cannot read " + target)
	}

	var body any
	if err := json.Unmarshal(text, &body); nil != err {
		// A success status promised JSON; a body that does not parse means
		// the store could not answer coherently, and treating it as a miss
		// would fall through to a weaker store. Error statuses may carry
		// any body - they are decided on status alone.
		if http.StatusOK == response.StatusCode {
			return response.StatusCode, nil, fail("sekreto: malformed response from " +
				strings.SplitN(target, "?", 2)[0])
		}
		body = nil
	}

	return response.StatusCode, body, nil
}

// httpget GETs a URL, returning the status and decoded body. A 404 is a
// normal answer here, not a failure: it means the vault has no such secret.
func httpget(target string, headers map[string]string) (int, any, error) {
	return httpjson(http.MethodGet, target, headers, "")
}

// dig walks a decoded JSON body by key, answering nil as soon as a step is
// not an object or the key is absent.
func dig(body any, keys ...string) any {
	node := body

	for _, key := range keys {
		object, is := node.(map[string]any)
		if !is {
			return nil
		}
		node = object[key]
	}

	return node
}

// digtext is dig rendered as text, with nil (and so any missing step)
// answering the empty string.
func digtext(body any, keys ...string) string {
	value := dig(body, keys...)
	if nil == value {
		return ""
	}
	return tostring(value)
}

// tonumber reads a decoded JSON value as a number the way the canonical
// port's Number() does: numbers pass through, numeric strings parse
// (Azure's IMDS hands expires_in back as a string), and anything else -
// missing, malformed - is zero.
func tonumber(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case string:
		number, err := strconv.ParseFloat(typed, 64)
		if nil != err {
			return 0
		}
		return number
	default:
		return 0
	}
}

// expiry is the moment a login token should be renewed: shortly before
// its lifetime (in seconds, from the login response) runs out. A missing
// or zero lifetime answers the zero time, which means never renew.
func expiry(lifetime any) time.Time {
	seconds := tonumber(lifetime)
	if 0 >= seconds {
		return time.Time{}
	}

	wait := seconds - 60
	if 1 > wait {
		wait = 1
	}

	return time.Now().Add(time.Duration(wait * float64(time.Second)))
}

// due reports whether a renewal moment has arrived; the zero time never
// arrives.
func due(renewat time.Time) bool {
	return !renewat.IsZero() && !time.Now().Before(renewat)
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

// HashicorpProvider reads HashiCorp Vault.
//
// KV v2 (the default): api.token reads {addr}/v1/{mount}/data/api and takes
// the `token` field of data.data. KV v1 (KV: 1) reads {addr}/v1/{mount}/api
// and takes the field of data. A 404 means "not here", which is a miss
// rather than an error, so a vault can sit in a chain with fallbacks.
//
// A Vault Enterprise namespace rides the X-Vault-Namespace header, on
// logins as well as reads.
//
// Instead of being handed a token, the provider can log in: Kubernetes
// auth (the pod's service-account JWT, from its conventional path) or
// AppRole. A failed login is an error, never a miss - it means this store
// could not answer at all.
type HashicorpProvider struct {
	Addr           string
	Token          string
	Mount          string
	KV             int
	VaultNamespace string
	Auth           *AuthSpec
	// The working token: a configured token is kept forever, a logged-in
	// token is renewed shortly before its lease runs out - a long-running
	// process must not keep presenting a token the vault already expired.
	livetoken string
	havetoken bool
	renewat   time.Time
}

func (provider *HashicorpProvider) mount() string {
	if "" == provider.Mount {
		return "secret"
	}
	return provider.Mount
}

func (provider *HashicorpProvider) baseheaders() map[string]string {
	headers := map[string]string{}
	if "" != provider.VaultNamespace {
		headers["X-Vault-Namespace"] = provider.VaultNamespace
	}
	return headers
}

func (provider *HashicorpProvider) login() (string, error) {
	auth := provider.Auth
	if nil == auth {
		return "", fail("sekreto: hashicorp: no token and no auth method")
	}

	mount := auth.Mount
	if "" == mount {
		mount = auth.Method
	}
	target := strings.TrimSuffix(provider.Addr, "/") + "/v1/auth/" + mount + "/login"

	var payload []byte
	switch auth.Method {
	case "kubernetes":
		jwt := auth.Jwt
		if "" == jwt {
			file := auth.JwtFile
			if "" == file {
				file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
			}
			raw, err := os.ReadFile(file)
			if nil != err {
				return "", fail("sekreto: hashicorp: cannot read jwt file " + file)
			}
			jwt = strings.TrimSpace(string(raw))
		}
		payload, _ = json.Marshal(struct {
			Role string `json:"role"`
			Jwt  string `json:"jwt"`
		}{Role: auth.Role, Jwt: jwt})
	case "approle":
		payload, _ = json.Marshal(struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}{RoleID: auth.RoleID, SecretID: auth.SecretID})
	default:
		return "", fail("sekreto: hashicorp: unknown auth method: " + auth.Method)
	}

	status, body, err := httpjson(http.MethodPost, target, provider.baseheaders(), string(payload))
	if nil != err {
		return "", err
	}

	got := digtext(body, "auth", "client_token")
	if http.StatusOK != status || "" == got {
		return "", fail("sekreto: hashicorp login failed: " + strconv.Itoa(status) + ": " + target)
	}

	provider.renewat = expiry(dig(body, "auth", "lease_duration"))

	return got, nil
}

func (provider *HashicorpProvider) Lookup(name string) (string, bool, error) {
	if err := checkaddr(provider.Addr); nil != err {
		return "", false, err
	}

	if !provider.havetoken || due(provider.renewat) {
		if "" != provider.Token {
			provider.livetoken = provider.Token
		} else {
			token, err := provider.login()
			if nil != err {
				return "", false, err
			}
			provider.livetoken = token
		}
		provider.havetoken = true
	}

	ref, err := NameVaultRef(name)
	if nil != err {
		return "", false, err
	}

	base := strings.TrimSuffix(provider.Addr, "/") + "/v1/" + provider.mount()
	target := base + "/data/" + ref.Path
	if 1 == provider.KV {
		target = base + "/" + ref.Path
	}

	headers := provider.baseheaders()
	headers["X-Vault-Token"] = provider.livetoken

	status, body, err := httpget(target, headers)
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: hashicorp error: " + strconv.Itoa(status) + ": " + target)
	}

	var value any
	if 1 == provider.KV {
		value = dig(body, "data", ref.Field)
	} else {
		value = dig(body, "data", "data", ref.Field)
	}

	if nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *HashicorpProvider) Describe() string {
	return "hashicorp:" + provider.Addr + "/" + provider.mount()
}

// BoruProvider reads a boru vault (https://github.com/boru-lang/boru).
//
// Two ways in, both boru's own.
//
// With no Addr, the CLI: `boru vault get --reveal <alias>` prints the
// secret on stdout, and nothing else. The passphrase is read by boru itself
// from BORU_VAULT_PASSPHRASE; sekreto never accepts it as config and never
// puts it on a command line, where it would show up in the process table.
//
// With an Addr, boru's wire protocol: `boru vault serve` publishes a
// read-only, HashiCorp-shaped provision API (boru's
// design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
// from `boru vault grant`. A sekreto name is already a valid boru alias,
// and boru aliases keep their dots, so api.token is the single path segment
// api.token - not the api/token split a HashiCorp KV gets. The value is the
// `value` field. A 404 is a miss; anything else the server refuses (a
// revoked capability, a sealed vault) is an error.
//
// boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
// credential *broker*, built precisely so the caller never receives the
// credential. `vault serve` is the provision endpoint, built to hand the
// value back - that is the one sekreto uses.
type BoruProvider struct {
	Command   string
	Namespace string
	Home      string
	Addr      string
	Token     string
	Mount     string
}

func (provider *BoruProvider) command() string {
	if "" == provider.Command {
		return "boru"
	}
	return provider.Command
}

func (provider *BoruProvider) wireaddr() string {
	return strings.TrimSuffix(provider.Addr, "/")
}

func (provider *BoruProvider) wiremount() string {
	if "" == provider.Mount {
		return "secret"
	}
	return provider.Mount
}

func (provider *BoruProvider) wirelookup(name string) (string, bool, error) {
	addr := provider.wireaddr()
	if err := checkaddr(addr); nil != err {
		return "", false, err
	}

	// The dotted name stays one segment: boru aliases keep their dots.
	alias := name
	if "" != provider.Namespace {
		alias = provider.Namespace + "/" + name
	}
	target := addr + "/v1/" + provider.wiremount() + "/data/" + alias

	status, body, err := httpget(target, map[string]string{"X-Vault-Token": provider.Token})
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: boru serve error: " + strconv.Itoa(status) + ": " + target)
	}

	value := dig(body, "data", "data", "value")
	if nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *BoruProvider) Lookup(name string) (string, bool, error) {
	if err := checkname(name); nil != err {
		return "", false, err
	}

	if "" != provider.Addr {
		return provider.wirelookup(name)
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
	if "" != provider.Addr {
		return "boru:" + provider.wireaddr()
	}
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

// awsnow is the YYYYMMDDTHHMMSSZ timestamp SigV4 wants, for now.
func awsnow() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

// awscreds is a resolved set of AWS credentials.
type awscreds struct {
	region  string
	keyid   string
	secret  string
	session string
}

// awsauth resolves region and credentials, from config first and the
// standard AWS_* environment variables second - those are AWS's own
// convention, and a pod or CI job that has them set should just work.
// Missing either is an error: an AWS store with no credentials could not
// answer.
func awsauth(region string, keyid string, secret string, session string) (*awscreds, error) {
	if "" == region {
		region = os.Getenv("AWS_REGION")
	}
	if "" == region {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if "" == keyid {
		keyid = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if "" == secret {
		secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if "" == session {
		session = os.Getenv("AWS_SESSION_TOKEN")
	}

	if "" == region {
		return nil, fail("sekreto: aws: no region (set region or AWS_REGION)")
	}
	if "" == keyid || "" == secret {
		return nil, fail("sekreto: aws: no credentials (set keyid/secret or " +
			"AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)")
	}

	return &awscreds{region: region, keyid: keyid, secret: secret, session: session}, nil
}

// awscall makes one signed call to an AWS JSON-1.1 API.
func awscall(
	region string, keyid string, secret string, session string, addr string,
	service string, target string, payload string,
) (int, any, error) {
	auth, err := awsauth(region, keyid, secret, session)
	if nil != err {
		return 0, nil, err
	}

	if "" == addr {
		// The China partition lives under its own suffix; every other
		// commercial region is plain amazonaws.com.
		suffix := ".amazonaws.com"
		if strings.HasPrefix(auth.region, "cn-") {
			suffix = ".amazonaws.com.cn"
		}
		addr = "https://" + service + "." + auth.region + suffix
	}
	if err := checkaddr(addr); nil != err {
		return 0, nil, err
	}

	requrl := strings.TrimSuffix(addr, "/") + "/"
	headers := map[string]string{
		"content-type": "application/x-amz-json-1.1",
		"x-amz-target": target,
	}

	signed, err := SigV4(&Sigv4Input{
		Method:   http.MethodPost,
		URL:      requrl,
		Headers:  headers,
		Body:     payload,
		Service:  service,
		Region:   auth.region,
		KeyID:    auth.keyid,
		Secret:   auth.secret,
		Session:  auth.session,
		Datetime: awsnow(),
	})
	if nil != err {
		return 0, nil, err
	}

	for key, value := range signed {
		headers[key] = value
	}

	return httpjson(http.MethodPost, requrl, headers, payload)
}

// awsmiss reports whether this AWS error body names one of the not-found
// types. Those are a miss; every other failure is a store that could not
// answer.
func awsmiss(body any, types []string) bool {
	errtype, _ := dig(body, "__type").(string)

	for _, name := range types {
		if strings.Contains(errtype, name) {
			return true
		}
	}

	return false
}

// AwsSecretsProvider reads AWS Secrets Manager.
//
// api.token reads the secret named `api` (the vaultref path, so
// db.pass.main reads db/pass) and takes the `token` field of its JSON
// SecretString - the AWS idiom of one JSON map per secret. A SecretString
// that is not JSON is the value itself, under the conventional field
// `value`. Requests are SigV4-signed in-tree; see sigv4.go.
type AwsSecretsProvider struct {
	Region  string
	KeyID   string
	Secret  string
	Session string
	Addr    string
}

func (provider *AwsSecretsProvider) Lookup(name string) (string, bool, error) {
	ref, err := NameVaultRef(name)
	if nil != err {
		return "", false, err
	}

	payload, _ := json.Marshal(struct {
		SecretID string `json:"SecretId"`
	}{SecretID: ref.Path})

	status, body, err := awscall(
		provider.Region, provider.KeyID, provider.Secret, provider.Session, provider.Addr,
		"secretsmanager", "secretsmanager.GetSecretValue", string(payload))
	if nil != err {
		return "", false, err
	}

	if http.StatusBadRequest == status && awsmiss(body, []string{"ResourceNotFoundException"}) {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: aws secretsmanager error: " + strconv.Itoa(status))
	}

	text, is := dig(body, "SecretString").(string)

	if !is {
		// A binary secret has no fields to address; only the conventional
		// `value` field can mean "the bytes themselves".
		bin, is := dig(body, "SecretBinary").(string)
		if is && "value" == ref.Field {
			decoded, _ := base64.StdEncoding.DecodeString(bin)
			return string(decoded), true, nil
		}
		return "", false, nil
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); nil == err && nil != parsed {
		value, has := parsed[ref.Field]
		if !has || nil == value {
			return "", false, nil
		}
		return tostring(value), true, nil
	}

	// A plain-string secret is the whole value; it has no named fields.
	if "value" == ref.Field {
		return text, true, nil
	}

	return "", false, nil
}

// Config only, never the environment: Describe feeds the spec's sources
// group, which must answer the same everywhere.
func (provider *AwsSecretsProvider) Describe() string {
	return "awssecrets:" + provider.Region
}

// AwsParamsProvider reads AWS SSM Parameter Store.
//
// db.pass.main reads the parameter /db/pass/main (under an optional prefix
// path), decrypted. Parameter Store carries flat strings, so there is no
// field indirection.
type AwsParamsProvider struct {
	Region  string
	KeyID   string
	Secret  string
	Session string
	Addr    string
	Prefix  string
}

func (provider *AwsParamsProvider) Lookup(name string) (string, bool, error) {
	param, err := AwsParam(name, provider.Prefix)
	if nil != err {
		return "", false, err
	}

	payload, _ := json.Marshal(struct {
		Name           string `json:"Name"`
		WithDecryption bool   `json:"WithDecryption"`
	}{Name: param, WithDecryption: true})

	status, body, err := awscall(
		provider.Region, provider.KeyID, provider.Secret, provider.Session, provider.Addr,
		"ssm", "AmazonSSM.GetParameter", string(payload))
	if nil != err {
		return "", false, err
	}

	if http.StatusBadRequest == status && awsmiss(body, []string{"ParameterNotFound"}) {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: aws ssm error: " + strconv.Itoa(status))
	}

	value := dig(body, "Parameter", "Value")
	if nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *AwsParamsProvider) Describe() string {
	return "awsparams:" + provider.Region + provider.Prefix
}

// GcpSecretsProvider reads GCP Secret Manager.
//
// api.token reads secret api_token (dots flattened to `_`; Secret Manager
// ids have no hierarchy and reject dots), latest version. The token comes
// from config, then GOOGLE_OAUTH_ACCESS_TOKEN, then the GCE/GKE metadata
// server - so on Google's own platform no credential configuration is
// needed at all.
//
// The metadata call itself is plain http to a link-local host by platform
// design; no credential rides on it, so checkaddr guards the Secret
// Manager address instead.
type GcpSecretsProvider struct {
	Project      string
	Token        string
	Addr         string
	MetadataAddr string
	// A configured token is kept forever; a metadata-server token carries
	// expires_in and is renewed shortly before it runs out.
	livetoken string
	havetoken bool
	renewat   time.Time
}

func (provider *GcpSecretsProvider) metadataaddr() string {
	if "" != provider.MetadataAddr {
		return provider.MetadataAddr
	}
	if host := os.Getenv("GCE_METADATA_HOST"); "" != host {
		return "http://" + host
	}
	return "http://metadata.google.internal"
}

func (provider *GcpSecretsProvider) login() (string, error) {
	configured := provider.Token
	if "" == configured {
		configured = os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN")
	}
	if "" != configured {
		return configured, nil
	}

	target := strings.TrimSuffix(provider.metadataaddr(), "/") +
		"/computeMetadata/v1/instance/service-accounts/default/token"

	status, body, err := httpget(target, map[string]string{"Metadata-Flavor": "Google"})
	if nil != err {
		return "", err
	}

	got := digtext(body, "access_token")
	if http.StatusOK != status || "" == got {
		return "", fail("sekreto: gcp: no token and metadata server did not answer")
	}

	provider.renewat = expiry(dig(body, "expires_in"))

	return got, nil
}

func (provider *GcpSecretsProvider) Lookup(name string) (string, bool, error) {
	if "" == provider.Project {
		return "", false, fail("sekreto: gcp: no project")
	}

	addr := provider.Addr
	if "" == addr {
		addr = "https://secretmanager.googleapis.com"
	}
	if err := checkaddr(addr); nil != err {
		return "", false, err
	}

	if !provider.havetoken || due(provider.renewat) {
		token, err := provider.login()
		if nil != err {
			return "", false, err
		}
		provider.livetoken = token
		provider.havetoken = true
	}

	flat, err := FlatName(name, "_")
	if nil != err {
		return "", false, err
	}

	target := strings.TrimSuffix(addr, "/") + "/v1/projects/" + provider.Project +
		"/secrets/" + flat + "/versions/latest:access"

	status, body, err := httpget(target,
		map[string]string{"authorization": "Bearer " + provider.livetoken})
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: gcp error: " + strconv.Itoa(status) + ": " + target)
	}

	data, is := dig(body, "payload", "data").(string)
	if !is {
		return "", false, nil
	}

	decoded, _ := base64.StdEncoding.DecodeString(data)
	return string(decoded), true, nil
}

func (provider *GcpSecretsProvider) Describe() string {
	return "gcpsecrets:" + provider.Project
}

// azureresource is the audience Azure Key Vault tokens are scoped to.
const azureresource = "https://vault.azure.net"

// AzureSecretsProvider reads Azure Key Vault.
//
// api.token reads secret api-token (dots flattened to `-`; Key Vault names
// allow nothing else), current version. The token comes from config, then
// a client-credentials login when tenant/clientid/clientsecret are given,
// then the IMDS managed-identity endpoint - so on Azure's own platform no
// credential configuration is needed.
//
// As with GCP, the IMDS call is plain http to a link-local host by
// platform design and carries no credential; the login and vault addresses
// are checkaddr-guarded.
type AzureSecretsProvider struct {
	Vault        string
	Token        string
	Tenant       string
	ClientID     string
	ClientSecret string
	LoginAddr    string
	ImdsAddr     string
	ApiVersion   string
	// A configured token is kept forever; logged-in and IMDS tokens carry
	// expires_in and are renewed shortly before they run out.
	livetoken string
	havetoken bool
	renewat   time.Time
}

func (provider *AzureSecretsProvider) login() (string, error) {
	if "" != provider.Token {
		return provider.Token, nil
	}

	if "" != provider.Tenant && "" != provider.ClientID && "" != provider.ClientSecret {
		loginaddr := provider.LoginAddr
		if "" == loginaddr {
			loginaddr = "https://login.microsoftonline.com"
		}
		if err := checkaddr(loginaddr); nil != err {
			return "", err
		}

		target := strings.TrimSuffix(loginaddr, "/") + "/" + provider.Tenant +
			"/oauth2/v2.0/token"
		form := "grant_type=client_credentials&client_id=" + uriescape(provider.ClientID) +
			"&client_secret=" + uriescape(provider.ClientSecret) +
			"&scope=" + uriescape(azureresource+"/.default")

		status, body, err := httpjson(http.MethodPost, target,
			map[string]string{"content-type": "application/x-www-form-urlencoded"}, form)
		if nil != err {
			return "", err
		}

		got := digtext(body, "access_token")
		if http.StatusOK != status || "" == got {
			return "", fail("sekreto: azure login failed: " + strconv.Itoa(status))
		}

		provider.renewat = expiry(dig(body, "expires_in"))
		return got, nil
	}

	imdsaddr := provider.ImdsAddr
	if "" == imdsaddr {
		imdsaddr = "http://169.254.169.254"
	}
	imds := strings.TrimSuffix(imdsaddr, "/") +
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
		uriescape(azureresource)

	status, body, err := httpget(imds, map[string]string{"Metadata": "true"})
	if nil != err {
		return "", err
	}

	got := digtext(body, "access_token")
	if http.StatusOK != status || "" == got {
		return "", fail("sekreto: azure: no token, no client credentials, and IMDS did not answer")
	}

	provider.renewat = expiry(dig(body, "expires_in"))
	return got, nil
}

func (provider *AzureSecretsProvider) Lookup(name string) (string, bool, error) {
	if "" == provider.Vault {
		return "", false, fail("sekreto: azure: no vault")
	}

	// Only an explicit scheme is a URL; a vault NAMED httpvault must
	// still become https://httpvault.vault.azure.net.
	vaulturl := provider.Vault
	if !strings.HasPrefix(vaulturl, "http://") && !strings.HasPrefix(vaulturl, "https://") {
		vaulturl = "https://" + vaulturl + ".vault.azure.net"
	}
	if err := checkaddr(vaulturl); nil != err {
		return "", false, err
	}

	if !provider.havetoken || due(provider.renewat) {
		token, err := provider.login()
		if nil != err {
			return "", false, err
		}
		provider.livetoken = token
		provider.havetoken = true
	}

	flat, err := FlatName(name, "-")
	if nil != err {
		return "", false, err
	}

	apiversion := provider.ApiVersion
	if "" == apiversion {
		apiversion = "7.4"
	}
	target := strings.TrimSuffix(vaulturl, "/") + "/secrets/" + flat +
		"?api-version=" + apiversion

	status, body, err := httpget(target,
		map[string]string{"authorization": "Bearer " + provider.livetoken})
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: azure error: " + strconv.Itoa(status) + ": " +
			strings.SplitN(target, "?", 2)[0])
	}

	value := dig(body, "value")
	if nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *AzureSecretsProvider) Describe() string {
	return "azuresecrets:" + provider.Vault
}

// OnePasswordProvider reads 1Password, through a Connect server.
//
// The item titled api.token (titles keep their dots), in the named vault.
// The value is the field with purpose PASSWORD, or the field labelled
// `value`. A vault that cannot be found is an error - config names it, so
// its absence is a broken store, not a missing secret.
type OnePasswordProvider struct {
	Addr      string
	Token     string
	Vault     string
	vaultid   string
	havevault bool
}

func (provider *OnePasswordProvider) auth() map[string]string {
	return map[string]string{"authorization": "Bearer " + provider.Token}
}

func (provider *OnePasswordProvider) resolvevault(addr string) (string, error) {
	want := provider.Vault
	if "" == want {
		return "", fail("sekreto: onepassword: no vault")
	}

	status, body, err := httpget(addr+"/v1/vaults", provider.auth())
	if nil != err {
		return "", err
	}

	list, is := body.([]any)
	if http.StatusOK != status || !is {
		return "", fail("sekreto: onepassword error: " + strconv.Itoa(status) + ": listing vaults")
	}

	for _, entry := range list {
		if want == digtext(entry, "id") || want == digtext(entry, "name") {
			return digtext(entry, "id"), nil
		}
	}

	return "", fail("sekreto: onepassword: no vault named " + want)
}

func (provider *OnePasswordProvider) Lookup(name string) (string, bool, error) {
	if err := checkname(name); nil != err {
		return "", false, err
	}

	addr := strings.TrimSuffix(provider.Addr, "/")
	if "" == addr {
		return "", false, fail("sekreto: onepassword: no addr")
	}
	if err := checkaddr(addr); nil != err {
		return "", false, err
	}

	if !provider.havevault {
		vaultid, err := provider.resolvevault(addr)
		if nil != err {
			return "", false, err
		}
		provider.vaultid = vaultid
		provider.havevault = true
	}

	filter := uriescape(`title eq "` + name + `"`)
	status, body, err := httpget(
		addr+"/v1/vaults/"+provider.vaultid+"/items?filter="+filter, provider.auth())
	if nil != err {
		return "", false, err
	}

	found, is := body.([]any)
	if http.StatusOK != status || !is {
		return "", false, fail("sekreto: onepassword error: " + strconv.Itoa(status) +
			": finding " + name)
	}

	if 0 == len(found) {
		return "", false, nil
	}

	itemid := digtext(found[0], "id")
	status, body, err = httpget(
		addr+"/v1/vaults/"+provider.vaultid+"/items/"+itemid, provider.auth())
	if nil != err {
		return "", false, err
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: onepassword error: " + strconv.Itoa(status) +
			": reading " + name)
	}

	fields, _ := dig(body, "fields").([]any)

	for _, field := range fields {
		if "PASSWORD" == digtext(field, "purpose") {
			value := dig(field, "value")
			if nil == value {
				return "", false, nil
			}
			return tostring(value), true, nil
		}
	}
	for _, field := range fields {
		if "value" == digtext(field, "label") {
			value := dig(field, "value")
			if nil == value {
				return "", false, nil
			}
			return tostring(value), true, nil
		}
	}

	return "", false, nil
}

func (provider *OnePasswordProvider) Describe() string {
	return "onepassword:" + provider.Vault
}

// DopplerProvider reads Doppler.
//
// The whole config is downloaded once - Doppler's own bulk endpoint - and
// answered from memory, like a remote .env: api.token is the API_TOKEN
// entry. A service token is config-scoped, so project and config are only
// needed with broader tokens.
type DopplerProvider struct {
	Token   string
	Project string
	Config  string
	Addr    string
	values  map[string]string
}

func (provider *DopplerProvider) load() (map[string]string, error) {
	if nil != provider.values {
		return provider.values, nil
	}

	addr := provider.Addr
	if "" == addr {
		addr = "https://api.doppler.com"
	}
	addr = strings.TrimSuffix(addr, "/")
	if err := checkaddr(addr); nil != err {
		return nil, err
	}

	target := addr + "/v3/configs/config/secrets/download?format=json"
	if "" != provider.Project {
		target += "&project=" + uriescape(provider.Project)
	}
	if "" != provider.Config {
		target += "&config=" + uriescape(provider.Config)
	}

	status, body, err := httpget(target,
		map[string]string{"authorization": "Bearer " + provider.Token})
	if nil != err {
		return nil, err
	}

	object, is := body.(map[string]any)
	if http.StatusOK != status || !is {
		return nil, fail("sekreto: doppler error: " + strconv.Itoa(status))
	}

	values := map[string]string{}
	for key, value := range object {
		if nil != value {
			values[key] = tostring(value)
		}
	}
	provider.values = values

	return values, nil
}

func (provider *DopplerProvider) Lookup(name string) (string, bool, error) {
	key, err := EnvKey(name, "")
	if nil != err {
		return "", false, err
	}

	values, err := provider.load()
	if nil != err {
		return "", false, err
	}

	value, has := values[key]
	return value, has, nil
}

func (provider *DopplerProvider) Describe() string {
	if "" != provider.Project {
		return "doppler:" + provider.Project + "/" + provider.Config
	}
	return "doppler"
}

// InfisicalProvider reads Infisical.
//
// api.token reads the secret keyed API_TOKEN (Infisical's own convention
// is environment-style keys) at a secret path in one environment of a
// project. Auth is a token, or a universal-auth (machine identity) login
// with clientid/clientsecret.
type InfisicalProvider struct {
	Addr         string
	Token        string
	ClientID     string
	ClientSecret string
	Project      string
	Environment  string
	Path         string
	// A configured token is kept forever; a universal-auth token carries
	// expiresIn and is renewed shortly before it runs out.
	livetoken string
	havetoken bool
	renewat   time.Time
}

func (provider *InfisicalProvider) login(addr string) (string, error) {
	if "" != provider.Token {
		return provider.Token, nil
	}

	if "" == provider.ClientID || "" == provider.ClientSecret {
		return "", fail("sekreto: infisical: no token and no client credentials")
	}

	payload, _ := json.Marshal(struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}{ClientID: provider.ClientID, ClientSecret: provider.ClientSecret})

	status, body, err := httpjson(http.MethodPost, addr+"/api/v1/auth/universal-auth/login",
		map[string]string{"content-type": "application/json"}, string(payload))
	if nil != err {
		return "", err
	}

	got := digtext(body, "accessToken")
	if http.StatusOK != status || "" == got {
		return "", fail("sekreto: infisical login failed: " + strconv.Itoa(status))
	}

	provider.renewat = expiry(dig(body, "expiresIn"))

	return got, nil
}

func (provider *InfisicalProvider) Lookup(name string) (string, bool, error) {
	addr := provider.Addr
	if "" == addr {
		addr = "https://app.infisical.com"
	}
	addr = strings.TrimSuffix(addr, "/")
	if err := checkaddr(addr); nil != err {
		return "", false, err
	}

	if "" == provider.Project || "" == provider.Environment {
		return "", false, fail("sekreto: infisical: no project/environment")
	}

	if !provider.havetoken || due(provider.renewat) {
		token, err := provider.login(addr)
		if nil != err {
			return "", false, err
		}
		provider.livetoken = token
		provider.havetoken = true
	}

	key, err := EnvKey(name, "")
	if nil != err {
		return "", false, err
	}

	path := provider.Path
	if "" == path {
		path = "/"
	}
	target := addr + "/api/v3/secrets/raw/" + key +
		"?workspaceId=" + uriescape(provider.Project) +
		"&environment=" + uriescape(provider.Environment) +
		"&secretPath=" + uriescape(path)

	status, body, err := httpget(target,
		map[string]string{"authorization": "Bearer " + provider.livetoken})
	if nil != err {
		return "", false, err
	}

	if http.StatusNotFound == status {
		return "", false, nil
	}

	if http.StatusOK != status {
		return "", false, fail("sekreto: infisical error: " + strconv.Itoa(status))
	}

	value := dig(body, "secret", "secretValue")
	if nil == value {
		return "", false, nil
	}

	return tostring(value), true, nil
}

func (provider *InfisicalProvider) Describe() string {
	return "infisical:" + provider.Project + "/" + provider.Environment
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
	case "file":
		return &FileProvider{Dir: spec.Dir, Prefix: spec.Prefix}, nil
	case "hashicorp":
		kv := spec.KV
		if 0 == kv {
			kv = 2
		}
		// A version typo like kv: 3 must not quietly behave as v2 and turn
		// its 404s into misses; there is nothing safe to assume it meant.
		if 1 != kv && 2 != kv {
			return nil, fail("sekreto: hashicorp: unsupported kv version: " + strconv.Itoa(kv))
		}
		return &HashicorpProvider{
			Addr:           spec.Addr,
			Token:          spec.Token,
			Mount:          spec.Mount,
			KV:             spec.KV,
			VaultNamespace: spec.VaultNamespace,
			Auth:           spec.Auth,
		}, nil
	case "boru":
		return &BoruProvider{
			Command:   spec.Command,
			Namespace: spec.Namespace,
			Home:      spec.Home,
			Addr:      spec.Addr,
			Token:     spec.Token,
			Mount:     spec.Mount,
		}, nil
	case "awssecrets":
		return &AwsSecretsProvider{
			Region:  spec.Region,
			KeyID:   spec.KeyID,
			Secret:  spec.Secret,
			Session: spec.Session,
			Addr:    spec.Addr,
		}, nil
	case "awsparams":
		return &AwsParamsProvider{
			Region:  spec.Region,
			KeyID:   spec.KeyID,
			Secret:  spec.Secret,
			Session: spec.Session,
			Addr:    spec.Addr,
			Prefix:  spec.Prefix,
		}, nil
	case "gcpsecrets":
		return &GcpSecretsProvider{
			Project:      spec.Project,
			Token:        spec.Token,
			Addr:         spec.Addr,
			MetadataAddr: spec.MetadataAddr,
		}, nil
	case "azuresecrets":
		return &AzureSecretsProvider{
			Vault:        spec.Vault,
			Token:        spec.Token,
			Tenant:       spec.Tenant,
			ClientID:     spec.ClientID,
			ClientSecret: spec.ClientSecret,
			LoginAddr:    spec.LoginAddr,
			ImdsAddr:     spec.ImdsAddr,
			ApiVersion:   spec.ApiVersion,
		}, nil
	case "onepassword":
		return &OnePasswordProvider{Addr: spec.Addr, Token: spec.Token, Vault: spec.Vault}, nil
	case "doppler":
		return &DopplerProvider{
			Token:   spec.Token,
			Project: spec.Project,
			Config:  spec.Config,
			Addr:    spec.Addr,
		}, nil
	case "infisical":
		return &InfisicalProvider{
			Addr:         spec.Addr,
			Token:        spec.Token,
			ClientID:     spec.ClientID,
			ClientSecret: spec.ClientSecret,
			Project:      spec.Project,
			Environment:  spec.Environment,
			Path:         spec.Path,
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
