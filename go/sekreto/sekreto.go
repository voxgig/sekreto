// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. Get asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.
//
// Go has no exceptions, so where the canonical implementation throws a
// SekretoError this port returns one as an error value.
package sekreto

import (
	"regexp"
	"strings"
)

// SekretoError is anything sekreto refuses to do: a bad name, a missing
// secret, a provider that could not be reached.
type SekretoError struct {
	Message string
}

func (err *SekretoError) Error() string {
	return err.Message
}

func fail(message string) error {
	return &SekretoError{Message: message}
}

var namepart = regexp.MustCompile(`^[a-z0-9_]+$`)

// ValidName reports whether this is a well-formed secret name.
func ValidName(name any) bool {
	text, is := name.(string)
	if !is || 0 == len(text) {
		return false
	}

	for _, part := range strings.Split(text, ".") {
		if !namepart.MatchString(part) {
			return false
		}
	}

	return true
}

func checkname(name string) error {
	if !ValidName(name) {
		return fail("sekreto: invalid name: " + name)
	}
	return nil
}

// EnvKey is the environment-variable key for a name: api.token -> API_TOKEN.
func EnvKey(name string, prefix string) (string, error) {
	if err := checkname(name); nil != err {
		return "", err
	}

	return prefix + strings.ToUpper(strings.Join(strings.Split(name, "."), "_")), nil
}

// VaultRef is where a name lives in a KV vault: api.token -> api / token.
//
// A single-segment name has no path of its own, so it becomes a secret of
// that name with the conventional field `value`.
type VaultRef struct {
	Path  string `json:"path"`
	Field string `json:"field"`
}

// NameVaultRef splits a name into its vault path and field.
func NameVaultRef(name string) (*VaultRef, error) {
	if err := checkname(name); nil != err {
		return nil, err
	}

	parts := strings.Split(name, ".")

	if 1 == len(parts) {
		return &VaultRef{Path: parts[0], Field: "value"}, nil
	}

	return &VaultRef{
		Path:  strings.Join(parts[:len(parts)-1], "/"),
		Field: parts[len(parts)-1],
	}, nil
}

// FlatName is a name flattened to one segment: api.token -> api_token (GCP
// Secret Manager, `_`) or api-token (Azure Key Vault, `-`).
//
// Those stores have no path hierarchy and reject dots in ids, so the dots
// become the store's conventional separator.
func FlatName(name string, sep string) (string, error) {
	if err := checkname(name); nil != err {
		return "", err
	}

	return strings.Join(strings.Split(name, "."), sep), nil
}

// AwsParam is the AWS SSM Parameter Store name for a name: dots become the
// path hierarchy, rooted at `/` (or at a prefix): db.pass.main ->
// /db/pass/main, or /app/db/pass/main under prefix `/app`.
func AwsParam(name string, prefix string) (string, error) {
	if err := checkname(name); nil != err {
		return "", err
	}

	base := prefix
	if "" != base && !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	base = strings.TrimSuffix(base, "/")

	return base + "/" + strings.Join(strings.Split(name, "."), "/"), nil
}

// ParseDotenv parses `.env` text into a map of raw keys to values.
//
// Deliberately small: KEY=value, optional `export`, `#` comments on their
// own line, and single- or double-quoted values (double quotes also
// unescape \n, \r, \t and \\). A line with no `=` is skipped.
func ParseDotenv(text string) map[string]string {
	out := map[string]string{}

	for _, rawline := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawline, "\r"))

		if 0 == len(line) || strings.HasPrefix(line, "#") {
			continue
		}

		body := line
		if strings.HasPrefix(line, "export ") {
			body = strings.TrimSpace(line[7:])
		}

		eq := strings.Index(body, "=")
		if 0 >= eq {
			continue
		}

		key := strings.TrimSpace(body[:eq])
		value := strings.TrimSpace(body[eq+1:])

		if 2 <= len(value) && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = unescape(value[1 : len(value)-1])
		} else if 2 <= len(value) && strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
			value = value[1 : len(value)-1]
		}

		out[key] = value
	}

	return out
}

func unescape(text string) string {
	var out strings.Builder

	for index := 0; index < len(text); index++ {
		if '\\' == text[index] && index+1 < len(text) {
			next := text[index+1]
			index++
			switch next {
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			case '\\':
				out.WriteByte('\\')
			case '"':
				out.WriteByte('"')
			default:
				out.WriteByte('\\')
				out.WriteByte(next)
			}
		} else {
			out.WriteByte(text[index])
		}
	}

	return out.String()
}

// Redact replaces known secret values in text with `[redacted]`.
//
// Only values of four characters or more are replaced: shorter ones are too
// likely to appear in ordinary text, and redacting them would make logs
// unreadable without making them safer.
func Redact(text string, values []string) string {
	out := text

	for _, value := range values {
		if 4 > len(value) {
			continue
		}
		out = strings.Join(strings.Split(out, value), "[redacted]")
	}

	return out
}

// Options configure a Sekreto.
type Options struct {
	// Providers is the chain, in resolution order.
	Providers []Provider
	// NoCache disables the resolved-value cache.
	NoCache bool
}

// entry is one provider in the chain, under the store name it answers to.
type entry struct {
	store    string
	provider Provider
}

// cached is one resolved value. A slice, not a map: the store a value came
// from stays attached, and redaction order does not vary between runs.
type cached struct {
	store string
	name  string
	value string
}

// StoreName is the store name a provider answers to when nothing says
// otherwise.
//
// Describe opens with the provider's kind - hashicorp:..., dotenv:..., plain
// env - so the kind is the natural default, and a custom provider gets a
// sensible name without implementing anything extra.
func StoreName(provider Provider) string {
	return strings.SplitN(provider.Describe(), ":", 2)[0]
}

// Sekreto is the secrets facade: a chain of providers plus a cache.
//
// Two ways to read. Get is transparent - it walks the chain and takes the
// first hit, and the caller never learns which store answered. GetFrom is
// directed - it names the store, and only that store is asked.
type Sekreto struct {
	entries []entry
	docache bool
	cache   []cached
}

// New makes a Sekreto from options. Each provider answers to its own kind as
// a store name; use NewNamed to name them explicitly.
func New(options *Options) *Sekreto {
	opts := options
	if nil == opts {
		opts = &Options{}
	}

	entries := []entry{}
	for _, provider := range opts.Providers {
		entries = append(entries, entry{store: StoreName(provider), provider: provider})
	}

	return &Sekreto{entries: entries, docache: !opts.NoCache}
}

// NewNamed makes a Sekreto whose providers answer to the given store names,
// in the same order. A name left empty falls back to the provider's kind.
func NewNamed(providers []Provider, names []string, nocache bool) *Sekreto {
	entries := []entry{}

	for index, provider := range providers {
		store := StoreName(provider)
		if index < len(names) && "" != names[index] {
			store = names[index]
		}
		entries = append(entries, entry{store: store, provider: provider})
	}

	return &Sekreto{entries: entries, docache: !nocache}
}

// Get returns the secret, or an error if no provider has it.
func (sek *Sekreto) Get(name string) (string, error) {
	found, has, err := sek.Try(name)
	if nil != err {
		return "", err
	}

	if !has {
		return "", fail("sekreto: unknown secret: " + name)
	}

	return found, nil
}

// Try returns the secret and whether any provider had it.
func (sek *Sekreto) Try(name string) (string, bool, error) {
	return sek.resolve("", name, sek.entries)
}

// GetFrom returns the secret from one named store, or an error if that store
// does not have it.
func (sek *Sekreto) GetFrom(store string, name string) (string, error) {
	found, has, err := sek.TryFrom(store, name)
	if nil != err {
		return "", err
	}

	if !has {
		return "", fail("sekreto: unknown secret: " + store + ":" + name)
	}

	return found, nil
}

// TryFrom returns the secret from one named store, and whether that store
// had it.
//
// Naming a store that is not in the chain is an error, not a miss: Try
// already means "this store may not have it", so it cannot also mean "this
// store may not exist" without hiding a typo.
func (sek *Sekreto) TryFrom(store string, name string) (string, bool, error) {
	matching := []entry{}

	for _, one := range sek.entries {
		if one.store == store {
			matching = append(matching, one)
		}
	}

	if 0 == len(matching) {
		return "", false, fail("sekreto: unknown store: " + store)
	}

	return sek.resolve(store, name, matching)
}

func (sek *Sekreto) resolve(store string, name string, entries []entry) (string, bool, error) {
	if err := checkname(name); nil != err {
		return "", false, err
	}

	if sek.docache {
		for _, hit := range sek.cache {
			if hit.store == store && hit.name == name {
				return hit.value, true, nil
			}
		}
	}

	for _, one := range entries {
		found, has, err := one.provider.Lookup(name)
		if nil != err {
			return "", false, err
		}

		if has {
			if sek.docache {
				sek.cache = append(sek.cache, cached{store: store, name: name, value: found})
			}
			return found, true, nil
		}
	}

	return "", false, nil
}

// Has reports whether any provider has this secret.
func (sek *Sekreto) Has(name string) (bool, error) {
	_, has, err := sek.Try(name)
	return has, err
}

// HasIn reports whether this named store has this secret.
func (sek *Sekreto) HasIn(store string, name string) (bool, error) {
	_, has, err := sek.TryFrom(store, name)
	return has, err
}

// All returns every named secret at once. Missing ones are an error.
func (sek *Sekreto) All(names []string) (map[string]string, error) {
	out := map[string]string{}

	for _, name := range names {
		found, err := sek.Get(name)
		if nil != err {
			return nil, err
		}
		out[name] = found
	}

	return out, nil
}

// Sources describes each provider, in resolution order.
func (sek *Sekreto) Sources() []string {
	out := []string{}

	for _, one := range sek.entries {
		out = append(out, one.provider.Describe())
	}

	return out
}

// Stores names each store that can be named by GetFrom, in resolution order
// and without repeats.
func (sek *Sekreto) Stores() []string {
	out := []string{}

	for _, one := range sek.entries {
		seen := false
		for _, already := range out {
			if already == one.store {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, one.store)
		}
	}

	return out
}

// Redact replaces every value this Sekreto has resolved with `[redacted]`.
func (sek *Sekreto) Redact(text string) string {
	values := []string{}

	for _, hit := range sek.cache {
		values = append(values, hit.value)
	}

	return Redact(text, values)
}

// Refresh drops cached values, so the next Get asks the providers again.
func (sek *Sekreto) Refresh() {
	sek.cache = nil
}
