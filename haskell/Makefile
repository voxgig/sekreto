.PHONY: build build-core check-core clean deps inspect test test-plugins test-spec

# voxgig/plugin is a RUNTIME dependency of this port - the core is built on
# it. It has no Hackage release and there is no cabal file to name one from,
# so the Makefile finds a checkout and puts it on GHC's include path, the
# same way every port finds omni. The LIBRARY searches nothing.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/haskell/src/Host.hs" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

GHC ?= ghc

# GHC's boot libraries have no networking at all, so plugins/tls.c is
# compiled in and linked against the system OpenSSL. That is the whole of
# the dependency: `-lssl -lcrypto`, and the distribution's OpenSSL is the
# audit surface. Nothing comes from Hackage, and there is no .cabal file
# or stack.yaml to resolve one from.
#
# IT IS ON THE PLUGIN SIDE OF THE SPLIT. The C file, the FFI declarations
# and the HTTP client above them all live under plugins/, so a binary that
# builds only the core links no socket and no TLS at all - which is what
# `make check-core` reads out of the artifact.
TLSLIBS := -optl-lssl -optl-lcrypto

# -Wall, minus the one warning the house naming convention trips: `head`
# and `value` are ordinary local names here, as they are in every port.
FLAGS := -O1 -Wall -Wno-name-shadowing

# THE INCLUDE PATH IS THE BOUNDARY. `src/` is compiled with plugin's
# sources and nothing else, so an import of a plugin module from the core
# is a compile error rather than a convention. Everything that links a
# plugin says so by adding -iplugins.
COREPATH := -isrc -i$(PLUGIN)/haskell/src
PLUGINPATH := $(COREPATH) -iplugins

deps:
	@set -e; \
	dir="$(PLUGIN)"; \
	if [ -z "$$dir" ]; then \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	  dir="$$(cd ../.plugin && pwd)"; \
	fi; \
	echo "voxgig/plugin: $$dir"

build: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - run make deps" >&2; exit 1; }
	mkdir -p build
	$(GHC) $(PLUGINPATH) -icli -outputdir build/lib -o build/sekreto-cli \
	  --make cli/Main.hs plugins/tls.c $(TLSLIBS) $(FLAGS) -v0

# The CORE ALONE, as an artifact that can be read. test/CoreOnly.hs uses
# the facade, the four built-in kinds and nothing else, and it is compiled
# WITHOUT -iplugins - so a plugin import in src/ stops the build here
# before `check-core` gets to read a single symbol.
build-core: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - run make deps" >&2; exit 1; }
	mkdir -p build
	$(GHC) $(COREPATH) -itest -outputdir build/core -o build/sekreto-core \
	  --make test/CoreOnly.hs $(FLAGS) -v0

# THE SPLIT, READ OUT OF THE BUILT ARTIFACT rather than out of the source.
# A grep of the sources proves what a reader can see; `nm` proves what is
# in the binary, which is the thing a consumer ships.
check-core: build-core
	@python3 test/checkcore.py

test: build check-core test-plugins test-spec

# The plugin seam, which the conformance suite cannot see: it hands every
# plugin to every chain it builds, so it can never notice a missing one.
test-plugins: build
	$(GHC) $(PLUGINPATH) -itest -outputdir build/plugins -o build/sekreto-plugins \
	  --make test/PluginTest.hs plugins/tls.c $(TLSLIBS) $(FLAGS) -v0
	./build/sekreto-plugins

# The suite compiles against the same sources `build` just compiled, and
# omni appears only here - never on the library's, the plugins' or the
# CLI's path.
test-spec: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/haskell build
	$(GHC) $(PLUGINPATH) -itest -i$(OMNI)/haskell/src -outputdir build/test \
	  -o build/sekreto-test --make test/SekretoTest.hs plugins/tls.c $(TLSLIBS) \
	  $(FLAGS) -Wno-duplicate-exports -v0
	./build/sekreto-test

clean:
	rm -rf build

inspect:
	@$(GHC) --version 2>&1 | tail -1
	@echo "plugin: $(PLUGIN)"
	@echo "omni: $(OMNI)"
