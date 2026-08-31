.PHONY: build build-clean test clean inspect fmt-check

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

# Debug, not ReleaseFast: runtime safety checks stay on, which is what a
# secrets library wants from its own test and integration runs. It is also
# what voxgig/omni and voxgig/struct's Zig ports build.
ZIG := zig build-exe

build:
	mkdir -p build
	$(ZIG) -femit-bin=build/sekreto-cli \
	  --dep sekreto -Mroot=cli/sekreto-cli.zig -Msekreto=src/sekreto.zig

# Register 4.13 proof: the library and the CLI must build with NO omni
# checkout on the machine. Nothing here reads $(OMNI), deliberately, and CI
# runs this before omni is fetched.
build-clean: build

test:
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	mkdir -p build
	$(ZIG) -femit-bin=build/sekretotest \
	  --dep omni --dep sekreto \
	  -Mroot=test/run.zig \
	  -Momni=$(OMNI)/zig/src/omni.zig \
	  -Msekreto=src/sekreto.zig
	./build/sekretotest

# The compiler is Zig's static analyser; `zig fmt --check` is the style gate.
fmt-check:
	zig fmt --check src test cli

clean:
	rm -rf build .zig-cache zig-cache zig-out

inspect:
	@zig version
	@echo "omni: $(OMNI)"
