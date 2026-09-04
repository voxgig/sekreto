.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

ELIXIR ?= elixir
ELIXIRC ?= elixirc

# The library and the CLI depend on nothing but Elixir and OTP: `:crypto`
# for SHA-256 and HMAC, `:ssl` for TLS, `:public_key` for trust roots. No
# mix project, so no manifest that a resolver could ever read a dependency
# out of. Only the conformance suite needs omni, and only on its code path.
#
# The CLI is packed into an escript, which carries Elixir's own ebin with
# it: it runs from any working directory, with nothing beside it.
build:
	rm -rf build
	mkdir -p build
	$(ELIXIRC) -o build src/*.ex cli/*.ex
	$(ELIXIR) tool/escript.exs

# The suite runs against the beams `build` just made, so the library is
# compiled once however many times the tests are run.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/elixir build
	$(ELIXIR) -pa build -pa $(OMNI)/elixir/build test/sekreto_test.exs

clean:
	rm -rf build

inspect:
	@$(ELIXIR) --version | tail -1
	@echo "omni: $(OMNI)"
