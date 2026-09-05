.PHONY: build test seam check-core deps clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is a dependency of the LIBRARY, not only of the tests:
# the provider kinds are plugin definitions and Sekreto is a plugin host.
# Kotlin has no package registry this repo may use (no gradle, no maven -
# see the notes below), so the port takes it the way it takes omni: a
# checkout, found in the usual places. Failing all of them, `deps` fetches
# a shallow clone into ../.plugin (gitignored), which is what
# `npm install` and `go mod download` do for those two ports. CI needs no
# checkout step for it because of this.
PLUGIN := $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/kotlin/src/Plugin.kt" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

KOTLINC ?= kotlinc

# The stdlib that ships beside the compiler. The two library jars do NOT
# fold it in - a library jar that carries the standard library is a
# library that collides with every other one - so the runs that use them
# directly put it on the classpath. Only the CLI jar is self-contained,
# because test/checks.sh runs it from one jar.
STDLIB = $(shell dirname $$(readlink -f $$(command -v $(KOTLINC))))/../lib/kotlin-stdlib.jar

# THE SPLIT IS THREE JARS, and that is the point of it.
#
#   sekreto.jar          the core: the chain, the cache, redaction, the
#                        four built-in kinds. Nothing else.
#   sekreto-plugins.jar  the ten plugin kinds, with sigv4 and the shared
#                        HTTP-JSON transport. Compiled AGAINST the core.
#   sekreto-cli.jar      the CLI, self-contained, because test/checks.sh
#                        runs it as `java -cp <one jar> sekreto.Cli`.
#
# Two library jars rather than one, deliberately. Folding the plugins into
# sekreto.jar would make the split nominal: an app whose chain is
# [dotenv, env] would still have AWS request signing and seven HTTP vault
# clients on its classpath, which is the whole thing this architecture
# exists to stop. `make check-core` proves the core jar holds none of it.
CORE = build/sekreto.jar
PLUGINS = build/sekreto-plugins.jar
CLI = build/sekreto-cli.jar
VOXPLUGIN = build/voxgigplugin.jar

# The library and the CLI depend on nothing but the JDK, the Kotlin
# standard library and voxgig/plugin. -include-runtime folds the stdlib
# into the CLI jar, so the CLI runs under a bare `java -cp` with no stdlib
# to locate. Only the conformance suite needs omni, and only on its
# classpath.
build: $(CLI)

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig/plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# voxgig/plugin's own port, compiled here rather than in its checkout: its
# Makefile builds src AND its corpus runner together, and the corpus
# runner is not something sekreto ships.
$(VOXPLUGIN):
	@test -n "$(PLUGIN)" || { \
	  echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME or run make deps" >&2; \
	  exit 1; }
	mkdir -p build
	$(KOTLINC) $(PLUGIN)/kotlin/src/*.kt -d $(VOXPLUGIN)

# THE CORE, COMPILED WITH plugins/ NOWHERE IN SIGHT. Not a convention: the
# classpath below holds voxgig/plugin and nothing else, so a core file that
# reached for a plugin would not compile. That is this port's linking
# boundary, and it is checked on every build rather than by a rule someone
# has to remember.
$(CORE): $(VOXPLUGIN) $(wildcard src/*.kt)
	$(KOTLINC) -cp $(VOXPLUGIN) src/*.kt -d $(CORE)

$(PLUGINS): $(CORE) $(wildcard plugins/*.kt)
	$(KOTLINC) -cp $(VOXPLUGIN):$(CORE) plugins/*.kt -d $(PLUGINS)

$(CLI): $(PLUGINS) $(wildcard cli/*.kt)
	$(KOTLINC) -include-runtime $(PLUGIN)/kotlin/src/*.kt src/*.kt plugins/*.kt cli/*.kt \
	  -d $(CLI)
	# kotlinc writes the file facade's DEFAULT name into Main-Class and
	# ignores @file:JvmName, so the jar it produces names a class that is
	# not in it. Restate the entry point the CLI actually has, so that
	# `java -jar` works as well as `java -cp ... sekreto.Cli`.
	jar --update --file $(CLI) --main-class sekreto.Cli

# The suite compiles against the jars `build` just made, so the library is
# compiled once however many times the tests are run.
test: build seam
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/kotlin build
	mkdir -p build/test
	$(KOTLINC) -cp $(CLI):$(OMNI)/kotlin/build/omnitest.jar \
	  test/SekretoTest.kt -d build/test
	java -cp build/test:$(CLI):$(OMNI)/kotlin/build/omnitest.jar SekretoTest

# THE PLUGIN SEAM, which the conformance suite cannot see: it hands every
# plugin to every chain it builds, so it can never notice a missing one.
seam: build check-core
	mkdir -p build/seam
	$(KOTLINC) -cp $(VOXPLUGIN):$(CORE):$(PLUGINS) test/PluginsTest.kt -d build/seam
	java -cp build/seam:$(VOXPLUGIN):$(CORE):$(PLUGINS):$(STDLIB) PluginsTest

# THE CORE DOES NOT REACH A PLUGIN, proved of the artifact and not of the
# source. test/CoreOnly.kt is compiled and run against a classpath that
# holds voxgig/plugin and the core jar - sekreto-plugins.jar is not on it
# - so a core that named a plugin would fail to link, and one that loaded
# a plugin class at run time would throw NoClassDefFoundError. The grep of
# the jar is the second half: no class in it may so much as MENTION a
# plugin, a socket, a cipher or a subprocess.
check-core: $(CORE)
	mkdir -p build/core
	$(KOTLINC) -cp $(VOXPLUGIN):$(CORE) test/CoreOnly.kt -d build/core
	java -cp build/core:$(VOXPLUGIN):$(CORE):$(STDLIB) CoreOnly
	@sh ./corecheck.sh $(CORE)

clean:
	rm -rf build

inspect:
	@$(KOTLINC) -version 2>&1 | tail -1
	@echo "omni:   $(OMNI)"
	@echo "plugin: $(PLUGIN)"
