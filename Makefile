# Top-level Makefile for all sekreto language ports.
#
# Usage:
#   make test         - conformance suite for every port
#   make test-go      - conformance suite for one port
#   make integration  - every port's CLI against a real token-protected API
#   make realstores   - the same, against the REAL vaults in docker
#   make all          - test + integration
#   make build        - build every port
#   make inspect      - show toolchain versions
#   make clean        - clean build artifacts
#   make spec         - recompile spec/*.json from spec/*.aon
#   make spec-check   - fail if a committed spec/*.json is stale
#
# The conformance suite proves each port computes the same answers from
# spec/sekreto.json. The integration run proves each port can actually fetch
# a secret and use it. Neither alone is enough.
#
# `realstores` is the third: the same CLIs against HashiCorp Vault,
# LocalStack, Infisical, a Key Vault emulator and a real boru, in
# containers. The mocks integration.sh uses are a claim about what those
# servers do; this checks the claim. It needs docker, takes minutes, and
# so is not part of `all` - CI runs it on a schedule.
# See doc/design/real-stores.md.

# Every port directory. Target names are the directory names, used verbatim
# as `make -C <dir>`.
LANGS = typescript javascript python ruby php perl go rust java csharp zig kotlin scala clojure swift

# THE PORT LIST, FOR ANYTHING THAT WOULD OTHERWISE REPEAT IT. Both CI
# workflows build every port in an explicit loop rather than through
# `make build`, because build-% tolerates -- and so hides -- a port whose
# build FAILS. That loop used to carry its own copy of the names, and
# adding the scala port is exactly what the duplication cost: LANGS knew,
# test/checks.sh knew, and both loops did not, so the job ran every other
# port and then failed as `scala/not-built`. They read this instead.
print-langs:
	@echo $(LANGS)

.PHONY: all test build integration realstores inspect clean check spec spec-check omni-isolation print-langs

all: test integration

# ---- per-port targets ----
#
# NOTE: these are pattern rules and must NOT be declared .PHONY - GNU make
# skips the implicit-rule search for phony targets, and they would silently
# do nothing.

test-%:
	@echo "======== $* ========"
	@$(MAKE) -C $* test

build-%:
	@echo "======== $* ========"
	@$(MAKE) -C $* build 2>/dev/null || echo "(no build target)"

inspect-%:
	@printf "%-12s " "$*"
	@$(MAKE) -s -C $* inspect 2>/dev/null || echo "(no inspect target)"

clean-%:
	@$(MAKE) -C $* clean 2>/dev/null || true

# ---- aggregate targets ----

test:
	@fail=""; \
	for lang in $(LANGS); do \
	  echo "======== $$lang ========"; \
	  if $(MAKE) -s -C $$lang test; then :; else fail="$$fail $$lang"; fi; \
	  echo ""; \
	done; \
	if [ -n "$$fail" ]; then echo "FAILED:$$fail"; exit 1; fi; \
	echo "all ports passed"

build:
	@for lang in $(LANGS); do $(MAKE) -s build-$$lang; done

# THE API SERVER IS A NODE PROGRAM WITH A DEPENDENCY, AND NOTHING INSTALLED
# IT. Both suites start `api/server.js`, which requires fastify; on a fresh
# checkout that is `Cannot find module 'fastify'` before a single port is
# exercised. CI never saw it because the workflow installs first
# (`npm --prefix api install`, ci.yml and real-stores.yml) -- so the gate was
# green while `make integration` was broken for everyone who had not happened
# to install by hand. The preparation belongs on the same side of the line as
# `build`: the Makefile prepares, the scripts test, which is why `integration`
# already depends on `build` rather than building anything itself.
#
# A DIRECTORY TARGET RATHER THAN A PHONY ONE, so the install runs when the
# manifest or the lock is newer than what is installed and not on every run.
# `install` rather than `ci` is what CI uses, and matching it is the point;
# `touch` is because npm leaves the directory's mtime older than the lock it
# just read when nothing needed changing.
API_DEPS = api/node_modules

$(API_DEPS): api/package.json api/package-lock.json
	@npm --prefix api install --no-fund --no-audit
	@touch $(API_DEPS)

# Every CLI is built first: test/integration.sh skips a port it cannot find,
# and a skipped port proves nothing.
integration: build $(API_DEPS)
	@./test/integration.sh

# The same CLIs against the real servers, in docker. Needs docker; brings
# the stack up and tears it down again. Deliberately not part of `all`.
realstores: build $(API_DEPS)
	@./test/realstores.sh

inspect:
	@for lang in $(LANGS); do $(MAKE) -s inspect-$$lang; done

clean:
	@for lang in $(LANGS); do $(MAKE) -s clean-$$lang; done

omni-isolation:
	@echo "======== omni is declared by no shipped library (register 4.13) ========"
	python3 tools/omni_isolation.py
	@echo "-------- and the guard itself, mutation-tested --------"
	python3 tools/omni_isolation_selftest.py

check: test integration omni-isolation

# spec/sekreto.json is a COMMITTED artifact compiled from spec/*.aon (and
# spec/def/*.aon) by @voxgig/model. The aontu files are the source of
# truth; every port reads only the JSON, so no port needs a Node toolchain
# to run its tests. After editing an aontu source, run `make spec` and
# commit the regenerated JSON — CI's spec-freshness check fails on a stale
# artifact.
# Both targets also unify each spec source with omni's spec-format shape
# (spec/def/omni-spec.aon, a copy of omni's) and prove the shape can go
# red. It runs AFTER the build rather than inside it: unifying the shape
# into the build would drop an optional key holding an empty container
# (omni's spec/def/omni-spec.aon says why), and the artifact must stay
# byte-exact. `spec` runs it too, and not only `spec-check`, because CI's
# spec-freshness job runs `make spec`.
spec:
	@cd tools && npm install --no-audit --no-fund --silent && npm run --silent build-spec && npm run --silent check-spec-shape

spec-check:
	@cd tools && npm install --no-audit --no-fund --silent && npm run --silent build-spec-check && npm run --silent check-spec-shape
