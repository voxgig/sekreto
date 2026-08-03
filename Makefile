# Top-level Makefile for all sekreto language ports.
#
# Usage:
#   make test         - conformance suite for every port
#   make test-go      - conformance suite for one port
#   make integration  - every port's CLI against a real token-protected API
#   make all          - both
#   make build        - build every port
#   make inspect      - show toolchain versions
#   make clean        - clean build artifacts
#
# The conformance suite proves each port computes the same answers from
# spec/sekreto.json. The integration run proves each port can actually fetch
# a secret and use it. Neither alone is enough.

# Every port directory. Target names are the directory names, used verbatim
# as `make -C <dir>`.
LANGS = typescript javascript python ruby php perl go rust java csharp

.PHONY: all test build integration inspect clean check

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

inspect:
	@for lang in $(LANGS); do $(MAKE) -s inspect-$$lang; done

clean:
	@for lang in $(LANGS); do $(MAKE) -s clean-$$lang; done

check: test integration
