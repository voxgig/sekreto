.PHONY: build test deps clean inspect

# voxgig/plugin is a dependency of the LIBRARY, not only of the tests: the
# core builds its provider catalog on it. Perl has no manifest to declare
# that in, so the checkout is found the way every port finds omni -
# $PLUGIN_HOME, then a sibling checkout, then the usual places. Failing all
# of those, `deps` fetches a shallow clone into ../.plugin (gitignored),
# which is what `npm install` and `go mod download` do for the other two
# ports: the dependency comes from the network when it is not already on
# disk. CI therefore needs no checkout step for it.
#
# The library itself searches no path - t/PluginHome.pm does, for the tests
# and the CLI, and only when `Voxgig::Plugin` is not already loadable.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/perl/lib/Voxgig/Plugin.pm" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

# `plugins/` is a SECOND @INC ROOT, not a subdirectory of lib/. That is what
# makes the split real rather than nominal: with -Ilib alone, not one plugin
# is findable, which is what t/plugins.t checks in a fresh interpreter.
INC = -Ilib -Iplugins -I$(PLUGIN)/perl/lib

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig/plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

build: deps
	@for f in $$(find lib plugins -name '*.pm') cli/sekreto-cli.pl; do \
	  perl $(INC) -c "$$f" || exit 1; \
	done

test: deps
	PLUGIN_HOME=$(PLUGIN) prove -Ilib -Iplugins -It t/

clean:

inspect:
	@perl --version | head -2 | tail -1
	@echo "plugin: $(PLUGIN)"
