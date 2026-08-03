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

// Sekreto is the secrets facade: a chain of providers plus a cache.
type Sekreto struct {
	providers []Provider
	docache   bool
	cache     map[string]string
	order     []string
}

// New makes a Sekreto from options.
func New(options *Options) *Sekreto {
	opts := options
	if nil == opts {
		opts = &Options{}
	}

	return &Sekreto{
		providers: opts.Providers,
		docache:   !opts.NoCache,
		cache:     map[string]string{},
	}
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
	if err := checkname(name); nil != err {
		return "", false, err
	}

	if sek.docache {
		if found, has := sek.cache[name]; has {
			return found, true, nil
		}
	}

	for _, provider := range sek.providers {
		found, has, err := provider.Lookup(name)
		if nil != err {
			return "", false, err
		}

		if has {
			if sek.docache {
				sek.cache[name] = found
				sek.order = append(sek.order, name)
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

	for _, provider := range sek.providers {
		out = append(out, provider.Describe())
	}

	return out
}

// Redact replaces every value this Sekreto has resolved with `[redacted]`.
func (sek *Sekreto) Redact(text string) string {
	// Cache order is kept explicitly: Go map iteration is randomised, and
	// redaction must not vary between runs.
	values := []string{}
	for _, name := range sek.order {
		values = append(values, sek.cache[name])
	}

	return Redact(text, values)
}

// Refresh drops cached values, so the next Get asks the providers again.
func (sek *Sekreto) Refresh() {
	sek.cache = map[string]string{}
	sek.order = nil
}
