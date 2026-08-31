package sekreto

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A Sekreto resolved from several goroutines must not lose a value.
//
// Four providers were given a mutex for exactly this reason; the facade
// holding the results was not. Two goroutines appending to `seen` from the
// same length silently dropped one - and a value missing from `seen` is a
// value Redact hands straight back into the log, which is the failure this
// guards. Run under `-race`, which the Makefile does.
func TestConcurrentResolveKeepsEverySecret(t *testing.T) {
	sek := New(&Options{Providers: []Provider{&MemoryProvider{Values: map[string]string{
		"A_ONE":   "value-one-aaaa",
		"A_TWO":   "value-two-bbbb",
		"A_THREE": "value-three-cc",
	}}}})

	names := []string{"a.one", "a.two", "a.three"}

	var wg sync.WaitGroup
	for index := 0; index < 24; index++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := sek.Get(names[n%len(names)]); nil != err {
				t.Error(err)
			}
		}(index)
	}
	wg.Wait()

	out := sek.Redact("one=value-one-aaaa two=value-two-bbbb three=value-three-cc")
	if strings.Contains(out, "value-") {
		t.Errorf("redact left a secret behind: %s", out)
	}
}

// The dotenv provider memoises its parsed file; concurrent Lookups must not
// race on that map. A racy map read is either a crash or a zero value, and a
// zero value here is a MISS where the file does hold the secret - which
// falls through to a weaker store.
func TestConcurrentDotenvLookup(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".env")
	if err := os.WriteFile(file, []byte("API_TOKEN=from-dotenv\n"), 0o600); nil != err {
		t.Fatal(err)
	}

	provider := &DotenvProvider{File: file}

	var wg sync.WaitGroup
	for index := 0; index < 16; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, has, err := provider.Lookup("api.token")
			if nil != err {
				t.Error(err)
			}
			if !has || "from-dotenv" != value {
				t.Errorf("lost the secret: has=%v value=%q", has, value)
			}
		}()
	}
	wg.Wait()
}
