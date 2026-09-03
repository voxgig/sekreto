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
LANGS = typescript javascript python ruby php perl go rust java csharp zig kotlin

.PHONY: all test build integration realstores inspect clean check spec spec-check omni-isolation

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

# Every CLI is built first: test/integration.sh skips a port it cannot find,
# and a skipped port proves nothing.
integration: build
	@./test/integration.sh

# The same CLIs against the real servers, in docker. Needs docker; brings
# the stack up and tears it down again. Deliberately not part of `all`.
realstores: build
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
