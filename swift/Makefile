.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

SWIFTC ?= swiftc

# swiftc is driven directly: there is no Package.swift, because SwiftPM
# would put a manifest in the shipped tree for a library that resolves
# nothing. The library becomes a static archive plus a .swiftmodule, and
# both the CLI and the conformance suite link against that one build.
#
# The library and the CLI depend on nothing but the Swift toolchain -
# Foundation for URLSession and Process, and this port's own JSON, SHA-256
# and HMAC. Only the conformance suite needs omni, and only on its link
# line.
build:
	mkdir -p build
	$(SWIFTC) -emit-module -emit-library -static -module-name Sekreto \
	  -emit-module-path build/Sekreto.swiftmodule -o build/libSekreto.a src/*.swift
	$(SWIFTC) -I build -L build -lSekreto -o build/sekreto-cli cli/Cli.swift

# The suite links the library `build` just made, so it is compiled once
# however many times the tests are run.
#
# SwiftPM leaves omni as loose object files rather than an archive, and a
# bare `.o` on a swiftc command line is not passed to the linker, so they
# are gathered into an archive here. Nothing is written inside the omni
# checkout.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/swift build
	rm -f build/libOmni.a
	ar rcs build/libOmni.a $(OMNI)/swift/.build/debug/Omni.build/*.o
	$(SWIFTC) -I build -I $(OMNI)/swift/.build/debug -L build -lSekreto -lOmni \
	  -o build/sekreto-test test/SekretoTest.swift
	./build/sekreto-test

clean:
	rm -rf build

inspect:
	@$(SWIFTC) -version 2>&1 | head -1
	@echo "omni: $(OMNI)"
