.PHONY: build test deps clean inspect check-core

# voxgig/plugin is a runtime dependency of the library itself, not only of
# the tests: a provider kind IS a plugin definition. This port ships no
# composer manifest and no vendor/ tree - plugin's own php port ships
# neither, for the reason its README gives - so the dependency is a
# CHECKOUT, found the way this port already finds voxgig/omni: $PLUGIN_HOME,
# then a sibling checkout, then the usual places. Failing all of those,
# `deps` fetches a shallow clone into ../.plugin (gitignored), which is what
# `npm install` and `pip install` do for the ports that have a registry. CI
# needs no checkout step for it because of this.
#
# src/Plugin.php runs the same search, and is the only file in the library
# that looks at the filesystem to decide what to load.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/php/src/plugin.php" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig/plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

build: deps
	@for f in src/*.php plugins/*.php cli/*.php test/*.php; do \
	  php -l $$f > /dev/null || exit 1; \
	done
	@echo "php: syntax ok"

# The conformance suite, then the plugin seam. The first hands every plugin
# to every chain it builds and so can never see a missing one; the second is
# what pins the split.
test: deps
	PLUGIN_HOME=$(PLUGIN) php test/run.php
	PLUGIN_HOME=$(PLUGIN) php test/plugins.php

# The boundary, on its own, as a grep of the require graph: requiring the
# core must pull in nothing under plugins/. test/plugins.php asserts the
# same thing and more; this target is for reading the answer directly.
check-core: deps
	@echo "requiring src/Sekreto.php pulls in:"
	@PLUGIN_HOME=$(PLUGIN) php test/included.php src/Sekreto.php | sed 's/^/  /'
	@PLUGIN_HOME=$(PLUGIN) php test/included.php src/Sekreto.php \
	  | grep -q '^plugins/' \
	  && { echo "FAIL: the core reaches a plugin"; exit 1; } \
	  || echo "ok: the core reaches no plugin"

clean:

inspect:
	@php --version | head -1
	@echo "plugin: $(PLUGIN)"
