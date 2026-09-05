.PHONY: build test seam check-core deps clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is a dependency of the LIBRARY, not only of the tests: the
# provider kinds are plugin definitions and Sekreto is a plugin host. Scala
# has no package registry this repo may use - no sbt, no mill, no
# `libraryDependencies`, the same rule voxgig/plugin's own scala port keeps -
# so the port takes it the way it takes omni: a checkout, found in the usual
# places. Failing all of them, `deps` fetches a shallow clone into ../.plugin
# (gitignored), which is what `npm install` and `go mod download` do for
# those two ports. CI therefore needs no checkout step for it.
#
# The library itself searches no path: this Makefile puts the classes on
# scalac's classpath, and that is the whole of the mechanism.
#
# Recursively expanded (?=, not :=), so a reference AFTER `deps` has run sees
# the clone it made.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/scala/src/Plugin.scala" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

SCALAC ?= scalac

# The Scala runtime is two jars beside the compiler - the Scala 3 library
# and the Scala 2.13 one it builds on. `scalac` puts them on its own
# classpath; `java -cp` does not, so they are folded into the CLI jar (see
# below) and named explicitly for the runs that use the library jars
# directly. Found from the compiler on PATH rather than named, so a
# distribution unpacked anywhere still builds.
SCALAHOME := $(shell \
  bin=$$(command -v $(SCALAC)) || exit 0; \
  cd "$$(dirname "$$(readlink -f "$$bin")")/.." && pwd)

SCALAJARS := $(wildcard $(SCALAHOME)/lib/scala3-library_3-*.jar) \
             $(wildcard $(SCALAHOME)/lib/scala-library-*.jar)

# The same two, as one classpath. `java -cp` takes a colon-separated list
# and `$(wildcard)` yields a space-separated one.
empty :=
space := $(empty) $(empty)
SCALACP := $(subst $(space),:,$(strip $(SCALAJARS)))

# FOUR JARS, AND THE SPLIT BETWEEN THEM IS THE BOUNDARY.
#
#   voxgigplugin.jar     voxgig/plugin's own scala port
#   sekreto.jar          the core: the chain, the cache, redaction, the four
#                        built-in kinds. Nothing else.
#   sekreto-plugins.jar  the ten plugin kinds, with sigv4 and the shared
#                        HTTP-JSON transport. Compiled AGAINST the core.
#   sekreto-cli.jar      the CLI, self-contained, because test/checks.sh runs
#                        it as `java -cp <one jar> sekreto.Cli`.
#
# Two library jars rather than one, deliberately. Folding the plugins into
# sekreto.jar would make the split nominal: an app whose chain is
# [dotenv, env] would still have AWS request signing and seven HTTP vault
# clients on its classpath, which is the whole thing this architecture
# exists to stop. `make check-core` proves the core jar holds none of it.
VOXPLUGIN = build/voxgigplugin.jar
CORE = build/sekreto.jar
PLUGINS = build/sekreto-plugins.jar
CLI = build/sekreto-cli.jar

build: $(CLI)

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig/plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# voxgig/plugin's own port, compiled here rather than in its checkout: its
# Makefile builds src AND its corpus runner together, and the corpus runner
# is not something sekreto ships.
$(VOXPLUGIN):
	@test -n "$(PLUGIN)" || { \
	  echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME or run make deps" >&2; \
	  exit 1; }
	@mkdir -p build
	$(SCALAC) -d $(VOXPLUGIN) $(PLUGIN)/scala/src/*.scala

# THE CORE, COMPILED WITH plugins/ NOWHERE IN SIGHT. Not a convention: the
# classpath below holds voxgig/plugin and nothing else, and `plugins/` is a
# source root of its own that is on neither the classpath nor the sourcepath,
# so a core file that reached for a plugin would not compile. That is this
# port's linking boundary, and it is checked on every build rather than by a
# rule someone has to remember.
$(CORE): $(VOXPLUGIN) $(wildcard src/*.scala)
	@test -n "$(SCALAJARS)" || { echo "sekreto: scala runtime not found beside $(SCALAC)" >&2; exit 1; }
	$(SCALAC) -classpath $(VOXPLUGIN) -d $(CORE) src/*.scala

$(PLUGINS): $(CORE) $(wildcard plugins/*.scala)
	$(SCALAC) -classpath $(VOXPLUGIN):$(CORE) -d $(PLUGINS) plugins/*.scala

# The CLI is one self-contained jar, because test/checks.sh runs it as
# `java -cp scala/build/sekreto-cli.jar sekreto.Cli` - one entry, no stdlib
# to locate. scalac has no -include-runtime, so the four inputs and the two
# runtime jars are unpacked side by side and packed together.
#
# A consumer that wants a lean build takes $(CORE) and the plugin classes it
# named instead, and nothing else - which is the whole point of compiling
# them apart.
$(CLI): $(PLUGINS) $(wildcard cli/*.scala)
	rm -rf build/stage
	mkdir -p build/stage
	$(SCALAC) -classpath $(VOXPLUGIN):$(CORE):$(PLUGINS) -d build/stage cli/*.scala
	for jar in $(SCALAJARS); do (cd build/stage && jar --extract --file $$jar); done
	for jar in $(VOXPLUGIN) $(CORE) $(PLUGINS); do \
	  (cd build/stage && jar --extract --file $(CURDIR)/$$jar); \
	done
	# The unpacked jars bring their own manifests; `jar --create` writes the
	# one that names the entry point, and a second copy on the way in is a
	# duplicate entry.
	rm -rf build/stage/META-INF
	jar --create --file $(CLI) --main-class sekreto.Cli -C build/stage .

# Two suites. SekretoTest is the shared conformance corpus, the same fourteen
# groups every port runs. PluginsTest is the seam the corpus CANNOT see: it
# hands every plugin to every chain it builds, so it can never notice a kind
# that was not passed in.
test: build seam
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/scala build
	mkdir -p build/test
	$(SCALAC) -classpath $(CLI):$(OMNI)/scala/build \
	  -d build/test test/SekretoTest.scala
	java -cp build/test:$(CLI):$(OMNI)/scala/build SekretoTest

# THE PLUGIN SEAM, which the conformance suite cannot see.
seam: build check-core
	mkdir -p build/seam
	$(SCALAC) -classpath $(VOXPLUGIN):$(CORE):$(PLUGINS) -d build/seam test/PluginsTest.scala
	java -cp build/seam:$(VOXPLUGIN):$(CORE):$(PLUGINS):$(SCALACP) PluginsTest

# THE CORE DOES NOT REACH A PLUGIN, proved of the artifact and not of the
# source, three ways.
#
# jdeps first, because it is the only one that is a WHITELIST: it lists every
# class the compiled core actually references, so a plugin pulled in by a
# type the compiler kept, by a lambda's captured type, or by a constant that
# inlined an import all show up. The two greps after it are the same rule
# from the other side - a core that reaches no plugin cannot have an HTTP
# client, a hash function or a child process in it either.
#
# Then test/CoreOnly.scala, compiled and run against a classpath that holds
# voxgig/plugin and the core jar - sekreto-plugins.jar is not on it - so a
# core that named a plugin would fail to link, and one that loaded a plugin
# class at run time would throw NoClassDefFoundError.
#
# Then the grep of the jar, which is the half jdeps cannot do: scala 3 writes
# a `.tasty` beside every `.class` and jdeps reads only bytecode.
check-core: $(CORE)
	@jdeps -verbose:class -cp $(VOXPLUGIN):$(SCALACP) $(CORE) > build/core.deps
	@if grep -q 'com\.voxgig\.sekreto\.plugins' build/core.deps; then \
	  echo "sekreto: the core reaches a plugin" >&2; \
	  grep 'com\.voxgig\.sekreto\.plugins' build/core.deps >&2; exit 1; \
	fi
	@if grep -qE 'java\.net\.http|javax\.crypto|java\.security\.|java\.lang\.ProcessBuilder' build/core.deps; then \
	  echo "sekreto: the core opens a socket, signs a request or spawns a process" >&2; \
	  grep -E 'java\.net\.http|javax\.crypto|java\.security\.|java\.lang\.ProcessBuilder' build/core.deps >&2; \
	  exit 1; \
	fi
	mkdir -p build/core
	$(SCALAC) -classpath $(VOXPLUGIN):$(CORE) -d build/core test/CoreOnly.scala
	java -cp build/core:$(VOXPLUGIN):$(CORE):$(SCALACP) CoreOnly
	@sh ./corecheck.sh $(CORE)

clean:
	rm -rf build

inspect:
	@$(SCALAC) -version 2>&1 | tail -1
	@echo "omni:   $(OMNI)"
	@echo "plugin: $(PLUGIN)"
