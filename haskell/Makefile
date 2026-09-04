.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

GHC ?= ghc

# GHC's boot libraries have no networking at all, so src/tls.c is compiled
# in and linked against the system OpenSSL. That is the whole of the
# dependency: `-lssl -lcrypto`, and the distribution's OpenSSL is the
# audit surface. Nothing comes from Hackage, and there is no .cabal file
# or stack.yaml to resolve one from.
TLSLIBS := -optl-lssl -optl-lcrypto

# -Wall, minus the one warning the house naming convention trips: `head`
# and `value` are ordinary local names here, as they are in every port.
FLAGS := -O1 -Wall -Wno-name-shadowing

build:
	mkdir -p build
	$(GHC) -isrc -icli -outputdir build/lib -o build/sekreto-cli \
	  --make cli/Main.hs src/tls.c $(TLSLIBS) $(FLAGS) -v0

# The suite compiles against the same sources `build` just compiled, and
# omni appears only here - never on the library's or the CLI's path.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/haskell build
	$(GHC) -isrc -itest -i$(OMNI)/haskell/src -outputdir build/test \
	  -o build/sekreto-test --make test/SekretoTest.hs src/tls.c $(TLSLIBS) \
	  $(FLAGS) -Wno-duplicate-exports -v0
	./build/sekreto-test

clean:
	rm -rf build

inspect:
	@$(GHC) --version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
