.PHONY: build test deps clean inspect

# voxgig/plugin is a runtime dependency, and pyproject.toml declares it
# from git - `pip install` brings it. A checkout that has not done that
# finds the port the way every port finds omni: $PLUGIN_HOME, then a
# sibling checkout, then the usual places. Failing all of those, `deps`
# fetches a shallow clone into ../.plugin (gitignored), which is what
# `npm install` and `go mod download` do for the other two ports: the
# dependency comes from the network when it is not already on disk. CI
# needs no checkout step for it because of this.
#
# The library itself searches no path - tests/pluginhome.py does, for the
# tests and the CLI, and only when `import voxgig_plugin` fails.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/python/voxgig_plugin/__init__.py" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

deps:
	@if python3 -c 'import voxgig_plugin' 2>/dev/null; then \
	  echo "voxgig_plugin: installed"; \
	elif [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig_plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig_plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

build: deps
	python3 -m compileall -q voxgig_sekreto cli tests

test: deps
	PLUGIN_HOME=$(PLUGIN) PYTHONPATH=.:tests python3 -m unittest discover -s tests -v

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

inspect:
	@python3 --version
	@echo "plugin: $(PLUGIN)"
