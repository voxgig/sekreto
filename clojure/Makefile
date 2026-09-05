.PHONY: build test deps check-core clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: the provider kinds are its definitions,
# so the LIBRARY needs it, not only the tests. Clojure has no registry this
# port could declare it in - its clojure port ships no deps.edn, so it is
# not even a :local/root - and so it is found the way omni is found, and
# `deps` fetches a shallow clone into ../.plugin when nothing else is
# there. The library itself searches no path: this Makefile puts the source
# directory on the classpath, and that is the whole of the mechanism.
#
# Recursively expanded (?=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/clojure/src/voxgig/plugin.clj" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

# The official Clojure CLI (clojure.org/guides/install_clojure). Debian's
# package of the same name is a different program: it has no deps.edn and no
# -M, so a build there fails at the first target rather than half way.
CLOJURE ?= clojure

# THE CLASSPATH IS BUILT BY HAND, AND THAT IS THE POINT.
#
# `clojure -M` would do it, but only from deps.edn - and voxgig/plugin has
# no coordinate to put there, while `:extra-paths` outside the project is
# deprecated and prints a warning on every run. More importantly the split
# this port keeps is a CLASSPATH split, so writing the classpaths out is
# what makes it readable:
#
#   CORECP  the Clojure runtime, voxgig/plugin, and src - and NOTHING under
#           plugins/. `check-core` compiles the core against exactly this,
#           so a core namespace that required a plugin could not load at
#           all.
#   LIBCP   the library a consumer gets: the core plus the ten plugin kinds.
#
# `-Spath` is asked once, for the runtime jars deps.edn resolves.
JARS := $(shell $(CLOJURE) -Spath 2>/dev/null | tr ':' '\n' | grep '\.jar$$' | tr '\n' ':')

CORECP = $(JARS)$(PLUGIN)/clojure/src:src
LIBCP = $(CORECP):plugins

CLJ = java -cp

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# The library and the CLI depend on nothing but the JDK, Clojure itself and
# voxgig/plugin.
#
# The CLI is AOT-compiled and the Clojure runtime jars are unpacked
# alongside its classes, so `build/sekreto-cli.jar` runs under a bare
# `java -cp` - which is what test/integration.sh needs, because it runs
# every port's CLI from an EMPTY directory. A `clojure -M` invocation would
# read a deps.edn from the working directory instead, and the empty
# directory is precisely what stops a stray .env making a run pass.
#
# Compilation is transitive: compiling the CLI namespace compiles the
# library it requires, the ten plugin kinds it passes, and voxgig/plugin
# under them. *compile-path* must be on the classpath, which is why
# build/classes is on this one.
build: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME" >&2; exit 1; }
	rm -rf build/classes build/stage
	mkdir -p build/classes build/stage
	$(CLJ) "$(LIBCP):cli:build/classes" clojure.main \
	  -e '(binding [*compile-path* "build/classes"] (compile (quote sekreto.cli)))'
	cp -R build/classes/. build/stage/
	for jar in $$(echo "$(JARS)" | tr ':' '\n' | grep '\.jar$$'); do \
	  (cd build/stage && jar --extract --file $$jar); \
	done
	# The runtime jars bring their own manifests; `jar --create` writes the
	# one that names the entry point, and a second copy on the way in is a
	# duplicate entry.
	rm -rf build/stage/META-INF
	jar --create --file build/sekreto-cli.jar --main-class sekreto.Cli -C build/stage .

# THE CORE REACHES NO PLUGIN, read back off the compiled classes rather
# than asserted.
#
# The core is AOT-compiled against CORECP, which does not carry plugins/ at
# all: a core namespace that required one would fail to load here, with the
# name of the file it could not find. That is the compiler's half.
#
# jdeps then reads the classes it produced. A plugin reached through a type
# hint, an interop call or an inlined constant would show up as a class
# reference whatever the require graph says - and so would the three things
# that make a kind a plugin in the first place: an HTTP client, a hash
# function and a child process.
check-core: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME" >&2; exit 1; }
	@rm -rf build/core && mkdir -p build/core
	@$(CLJ) "$(CORECP):build/core" clojure.main \
	  -e '(binding [*compile-path* "build/core"] (compile (quote voxgig.sekreto)))' >/dev/null
	@jdeps -verbose:class -cp "$(JARS)$(PLUGIN)/clojure/src" build/core > build/core.deps 2>/dev/null || true
	@if grep -q 'voxgig\.sekreto\.plugins' build/core.deps; then \
	  echo "sekreto: the core reaches a plugin" >&2; \
	  grep 'voxgig\.sekreto\.plugins' build/core.deps >&2; exit 1; \
	fi
	@if grep -qE 'java\.net\.http|javax\.crypto|java\.security\.(MessageDigest|Mac)|java\.lang\.ProcessBuilder' build/core.deps; then \
	  echo "sekreto: the core opens a socket, signs a request or spawns a process" >&2; \
	  grep -E 'java\.net\.http|javax\.crypto|java\.security\.(MessageDigest|Mac)|java\.lang\.ProcessBuilder' build/core.deps >&2; \
	  exit 1; \
	fi
	@echo "core: $$(find build/core/voxgig/sekreto -name '*.class' | wc -l | tr -d ' ') classes, and none reaches a plugin"

# Two suites. `voxgig.sekreto.test.main` is the shared conformance corpus,
# the same fourteen groups every port runs. `voxgig.sekreto.test.plugins` is
# the seam the corpus CANNOT see: it hands every plugin to every chain it
# builds, so it can never notice a kind that was not passed in.
#
# The suites run the library from source, as Clojure does. `build` runs
# first so that `make test` also proves the artifact the integration suite
# invokes still compiles.
#
# omni reaches the classpath here and nowhere else: nothing a consumer of
# this library resolves may name the conformance runner.
test: build check-core
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/clojure build
	$(CLJ) "$(LIBCP):test:$(OMNI)/clojure/src" clojure.main -m voxgig.sekreto.test.main
	$(CLJ) "$(LIBCP):test" clojure.main -m voxgig.sekreto.test.plugins

clean:
	rm -rf build .cpcache

inspect:
	@$(CLOJURE) --version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
