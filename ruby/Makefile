.PHONY: build test deps clean inspect

# voxgig/plugin is a runtime dependency of the library, required by name
# so that an installed gem wins. There is no gem yet, so a checkout finds
# the port the way every port finds omni: $PLUGIN_HOME, then a sibling
# checkout, then the usual places. Failing all of those, `deps` fetches a
# shallow clone into ../.plugin (gitignored), which is what `npm install`
# and `go mod download` do for the other two ports: the dependency comes
# from the network when it is not already on disk. CI therefore needs no
# checkout step for it.
#
# The library itself searches no path - test/pluginhome.rb does, for the
# tests and the CLI, and only when `require "voxgig_plugin"` fails.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/ruby/lib/voxgig_plugin.rb" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

deps:
	@if ruby -e 'require "voxgig_plugin"' 2>/dev/null; then \
	  echo "voxgig_plugin: installed"; \
	elif [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig_plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig_plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# Not a no-op: a syntax error in a plugin file no test happens to require
# would otherwise ship, and after the core/plugin split most files are in
# exactly that position.
build: deps
	@for f in $$(find lib cli test -name '*.rb'); do ruby -c "$$f" >/dev/null || exit 1; done

test: deps
	PLUGIN_HOME=$(PLUGIN) ruby test/test_sekreto.rb
	PLUGIN_HOME=$(PLUGIN) ruby test/test_plugins.rb

clean:

inspect:
	@ruby --version
	@echo "plugin: $(PLUGIN)"
