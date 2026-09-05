.PHONY: build test deps clean inspect cli

# voxgig/omni drives the shared spec. This port takes it from npm
# (@voxgig/omni-js, a devDependency - omni register 4.13's isolation device
# for Node), so `npm install` is all the wiring there is; no checkout and
# no OMNI_HOME. `test` depends on `build` for exactly that reason.
#
# voxgig/plugin is a RUNTIME dependency, and package.json declares it the
# same way the canonical port does: from npm (@voxgig/plugin-js), which
# `npm install` fetches. The library itself searches no path.
#
# A checkout is still found the way every port finds omni, for the two
# cases npm cannot serve: a machine with no registry, and a plugin change
# not yet published. $(PLUGIN) is $PLUGIN_HOME, then a sibling checkout,
# then the usual places; `deps` fetches a shallow clone into ../.plugin
# when there is none, and `make build PLUGIN=<dir>` installs that checkout
# over the published one. Nothing here is needed for an ordinary build.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/javascript/src/index.js" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

deps:
	@if [ -f node_modules/@voxgig/plugin-js/src/index.js ]; then \
	  echo "@voxgig/plugin-js: installed"; \
	elif [ -n "$(PLUGIN)" ]; then \
	  echo "@voxgig/plugin-js: $(PLUGIN)"; \
	else \
	  echo "@voxgig/plugin-js: from npm"; \
	fi

build:
	npm install --no-audit --no-fund --silent

# Install a plugin CHECKOUT over the published package. Only for a plugin
# change not yet on npm, or a machine with no registry: `make build` is
# the ordinary path.
build-local:
	@test -n "$(PLUGIN)" || (echo "no plugin checkout found; set PLUGIN_HOME or run make plugin-fetch" && exit 1)
	npm install --no-audit --no-fund --silent
	npm install --no-audit --no-fund --silent --no-save "$(PLUGIN)/javascript"

plugin-fetch:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

test: build
	npm test

cli: build
	node cli/sekreto-cli.js $(ARGS)

clean:
	rm -rf node_modules

inspect:
	@node --version
	@echo "plugin: $(PLUGIN)"
