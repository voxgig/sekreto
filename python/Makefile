.PHONY: build test clean inspect

# voxgig/plugin is a runtime dependency (pyproject.toml declares it from
# git). For a checkout that has not pip-installed it, the tests and the
# CLI find a sibling checkout the way every port finds omni - $PLUGIN_HOME,
# then the usual places - and this is where the Makefile tells them.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/python/voxgig_plugin/__init__.py" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

build:
	python3 -m compileall -q voxgig_sekreto cli tests

test:
	PLUGIN_HOME=$(PLUGIN) PYTHONPATH=.:tests python3 -m unittest discover -s tests -v

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

inspect:
	@python3 --version
	@echo "plugin: $(PLUGIN)"
