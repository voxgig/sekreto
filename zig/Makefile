.PHONY: build build-clean deps test check-core clean inspect fmt-check

# voxgig/omni is a sibling checkout, not a published package, and it may sit
# anywhere. Find it, then name its source file on the command line - Zig 0.16
# resolves cross-directory imports as named modules, so the path is a build
# argument rather than anything written into a checked-in file.
#
# Only the conformance suite names omni. `build` does not depend on it, so
# the library and the CLI compile with no omni checkout at all (omni
# register 4.13); `build-clean` is the target that proves it.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: the library is built on its host, so the
# library needs it, not only the tests. Zig has no package registry, so it
# is found the way omni is found - $PLUGIN_HOME, then the usual places,
# then the ../.plugin that `deps` fetches when nothing else is there - and
# named on the command line as the module `plugin`, rooted at the consumer
# root plugin's zig port ships for exactly this (`zig/src/plugin.zig`).
#
# Recursively expanded (=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN_REPO ?= https://github.com/voxgig/plugin
PLUGIN_REF ?= main
PLUGIN = $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin /workspace/plugin /home/user/plugin ../.plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/zig/src/plugin.zig" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# ../.plugin is SHARED with the python port, whose `deps` clones plugin's
# main when it finds nothing - and the integration job builds every port
# on one runner, python before zig. A clone that predates the consumer
# root is therefore ordinary, not an error: it is brought up to
# $(PLUGIN_REF) in place. A checkout the caller owns ($PLUGIN_HOME, a
# sibling) is never touched; one without the root is simply not found.
deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	elif [ -d ../.plugin ]; then \
	  echo "plugin: ../.plugin predates zig/src/plugin.zig - fetching $(PLUGIN_REF) into it"; \
	  git -C ../.plugin fetch --quiet --depth 1 $(PLUGIN_REPO) $(PLUGIN_REF) && \
	  git -C ../.plugin checkout --quiet FETCH_HEAD && \
	  test -f ../.plugin/zig/src/plugin.zig; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) ($(PLUGIN_REF)) into ../.plugin"; \
	  git clone --quiet --depth 1 --branch $(PLUGIN_REF) $(PLUGIN_REPO) ../.plugin; \
	fi

# Debug, not ReleaseFast: runtime safety checks stay on, which is what a
# secrets library wants from its own test and integration runs. It is also
# what voxgig/omni and voxgig/struct's Zig ports build.
ZIG := zig build-exe

# The module graph, the same for every binary:
#
#   sekreto         src/sekreto.zig      the core - depends on plugin only
#   sekretoplugins  plugins/all.zig      the ten plugins - depends on both
#   plugin          <checkout>/zig/src/plugin.zig
#
# The core cannot reach the plugins even by accident: a module's imports
# are confined to its root's directory, and ../plugins/ is outside src/.
# A consumer that wants ONE plugin roots `sekretoplugins` at that file
# instead of all.zig and compiles nothing else.
MODULES = \
  --dep plugin -Msekreto=src/sekreto.zig \
  --dep sekreto --dep plugin -Msekretoplugins=plugins/all.zig \
  -Mplugin=$(PLUGIN)/zig/src/plugin.zig

build: deps
	mkdir -p build
	$(ZIG) -femit-bin=build/sekreto-cli \
	  --dep sekreto --dep sekretoplugins -Mroot=cli/sekreto-cli.zig $(MODULES)

# Register 4.13 proof: the library and the CLI must build with NO omni
# checkout on the machine. Nothing here reads $(OMNI), deliberately, and CI
# runs this before omni is fetched. (plugin is a dependency, not a test
# harness, and is present.)
build-clean: build

# The core reaches no plugin: no HTTP client, no crypto, no child process,
# and nothing under plugins/. The compiler enforces the last (see MODULES);
# this pins the rest, the way plugin_test.go pins its half in go.
check-core:
	@if grep -rn -E 'std\.http|std\.crypto|std\.process\.run|std\.Io\.net|@import\("[^"]*plugins' src \
	    | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//'; then \
	  echo "sekreto: the core reaches a plugin" >&2; exit 1; \
	else echo "core: reaches no plugin"; fi

test: deps check-core
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	mkdir -p build
	$(ZIG) -femit-bin=build/sekretotest \
	  --dep omni --dep sekreto --dep sekretoplugins \
	  -Mroot=test/run.zig \
	  -Momni=$(OMNI)/zig/src/omni.zig \
	  $(MODULES)
	./build/sekretotest

# The compiler is Zig's static analyser; `zig fmt --check` is the style gate.
fmt-check:
	zig fmt --check src plugins test cli

clean:
	rm -rf build .zig-cache zig-cache zig-out

inspect:
	@zig version
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
