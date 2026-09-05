.PHONY: build test deps check-core clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: the provider kinds are its definitions,
# so the LIBRARY needs it, not only the tests. Elixir has no registry this
# port could declare it in - there is no mix.exs here, and a mix.exs is
# exactly what this port refuses to grow - so it is found the way omni is
# found, and `deps` fetches a shallow clone into ../.plugin when nothing
# else is there. The library itself searches no path: this Makefile puts
# the built beams on the code path, and the escript packs them, and that is
# the whole of the mechanism.
#
# Recursively expanded (?=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/elixir/lib/voxgig_plugin.ex" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

PLUGINBUILD = $(PLUGIN)/elixir/build

ELIXIR ?= elixir
ELIXIRC ?= elixirc

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# The library and the CLI depend on nothing but Elixir, OTP and
# voxgig/plugin: `:crypto` for SHA-256 and HMAC, `:ssl` for TLS,
# `:public_key` for trust roots - and every one of those is reached from
# plugins/, never from src/. No mix project, so no manifest that a resolver
# could ever read a dependency out of. Only the conformance suite needs
# omni, and only on its code path.
#
# `elixirc` has no code-path switch of its own; ELIXIR_ERL_OPTIONS is how
# the runtime takes one, and it is what puts voxgig/plugin in front of the
# compiler. --warnings-as-errors is not decoration: elixir WARNS rather
# than fails on a call into a module that is not there, which is precisely
# the mistake `check-core` exists to catch.
#
# The CLI is packed into an escript, which carries Elixir's own ebin and
# voxgig/plugin's beams with it: it runs from any working directory, with
# nothing beside it.
build: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME" >&2; exit 1; }
	$(MAKE) -C $(PLUGIN)/elixir build
	rm -rf build
	mkdir -p build
	ELIXIR_ERL_OPTIONS="-pa $(PLUGINBUILD)" \
	  $(ELIXIRC) --warnings-as-errors -o build src/*.ex plugins/*.ex cli/*.ex
	$(ELIXIR) -pa build -pa $(PLUGINBUILD) tool/escript.exs $(PLUGINBUILD)

# THE CORE REACHES NO PLUGIN, compiled alone and then read back off the
# beams. See tool/checkcore.exs, which says how and why.
check-core: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME" >&2; exit 1; }
	@$(MAKE) -C $(PLUGIN)/elixir build >/dev/null
	@$(ELIXIR) tool/checkcore.exs $(PLUGINBUILD)

# Two suites. `sekreto_test.exs` is the shared conformance corpus, the same
# fourteen groups every port runs. `plugins_test.exs` is the seam the
# corpus CANNOT see: it hands every plugin to every chain it builds, so it
# can never notice a kind that was not passed in, nor a consumer that
# passed the wrong ones.
#
# Both run against the beams `build` just made, so the library is compiled
# once however many times the tests are run.
test: build check-core
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/elixir build
	$(ELIXIR) -pa build -pa $(PLUGINBUILD) -pa $(OMNI)/elixir/build test/sekreto_test.exs
	$(ELIXIR) -pa build -pa $(PLUGINBUILD) test/plugins_test.exs

clean:
	rm -rf build

inspect:
	@$(ELIXIR) --version | tail -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
