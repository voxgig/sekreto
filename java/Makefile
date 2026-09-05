.PHONY: build core plugins deps test check-core clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: the provider kinds are its definitions,
# so the LIBRARY needs it, not only the tests. Java has no package this
# port can declare it in - there is no maven and no gradle here, by
# design - so it is found the way omni is found, and `deps` fetches a
# shallow clone into ../.plugin when nothing else is there. The library
# itself searches no path: this Makefile puts the classes on javac's
# classpath, and that is the whole of the mechanism.
#
# Recursively expanded (?=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/java/src/voxgig/plugin/Plugin.java" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# THREE OUTPUT TREES, AND THE SPLIT BETWEEN THEM IS THE BOUNDARY.
#
#   build/plugin   voxgig/plugin's library classes
#   build/core     src/  - the chain, the four built-in kinds, no plugin
#   build/plugins  plugins/ - the ten kinds that open a socket, spawn a
#                  process or sign a request, and sigv4 with them
#
# `core` compiles src/ with build/plugin on the classpath and NOTHING
# else: plugins/ is a source root of its own and is on neither the
# sourcepath nor the classpath, so `import com.voxgig.sekreto.plugins.X`
# from the core is a compile error rather than a rule to remember. That
# is javac's half; `check-core` reads the compiled result back and pins
# the rest.
core: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME" >&2; exit 1; }
	mkdir -p build/plugin build/core
	javac -d build/plugin $(PLUGIN)/java/src/voxgig/plugin/*.java
	javac -cp build/plugin -d build/core src/com/voxgig/sekreto/*.java

plugins: core
	mkdir -p build/plugins
	javac -cp build/core:build/plugin -d build/plugins plugins/com/voxgig/sekreto/plugins/*.java

# The runnable tree: test/checks.sh invokes the CLI as
# `java -cp java/build/classes sekreto.Cli`, one directory, so this is
# where the three trees and the CLI come together. A consumer that wants
# a lean build takes build/core and the plugin classes it named, and
# nothing else - which is the whole point of compiling them apart.
build: core plugins
	mkdir -p build/classes
	cp -r build/plugin/. build/classes/
	cp -r build/core/. build/classes/
	cp -r build/plugins/. build/classes/
	javac -cp build/classes -d build/classes cli/*.java

# THE CORE REACHES NO PLUGIN, read back off the compiled classes rather
# than asserted. jdeps lists every class the core actually references, so
# a plugin pulled in by a type the compiler kept, by a lambda's captured
# type, or by a constant that inlined an import would all show up here.
#
# The three greps after it are the same rule from the other side: a core
# that reaches no plugin cannot have an HTTP client, a hash function or a
# child process in it either, whatever the import graph says.
check-core: core
	@jdeps -verbose:class -cp build/plugin build/core > build/core.deps
	@if grep -q 'com\.voxgig\.sekreto\.plugins' build/core.deps; then \
	  echo "sekreto: the core reaches a plugin" >&2; \
	  grep 'com\.voxgig\.sekreto\.plugins' build/core.deps >&2; exit 1; \
	fi
	@if grep -qE 'java\.net\.http|java\.net\.URL|javax\.crypto|java\.security\.(MessageDigest|Mac)|java\.lang\.ProcessBuilder|java\.lang\.Runtime\b' build/core.deps; then \
	  echo "sekreto: the core opens a socket, signs a request or spawns a process" >&2; \
	  grep -E 'java\.net\.http|java\.net\.URL|javax\.crypto|java\.security\.|java\.lang\.ProcessBuilder|java\.lang\.Runtime\b' build/core.deps >&2; \
	  exit 1; \
	fi
	@echo "core: $$(ls build/core/com/voxgig/sekreto/*.class | wc -l) classes, and none reaches a plugin"

# Two suites. SekretoTest is the shared conformance corpus, the same
# fourteen groups every port runs. PluginsTest is the seam the corpus
# CANNOT see: it hands every plugin to every chain it builds, so it can
# never notice a kind that was not passed in.
test: build check-core
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/java build
	mkdir -p build/test
	javac -cp build/classes:$(OMNI)/java/build -d build/test test/SekretoTest.java
	javac -cp build/classes:build/core:build/plugins -d build/test test/PluginsTest.java
	java -cp build/classes:build/test:$(OMNI)/java/build SekretoTest
	java -cp build/plugin:build/core:build/plugins:build/test PluginsTest

clean:
	rm -rf build

inspect:
	@javac -version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
