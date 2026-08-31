.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

KOTLINC ?= kotlinc

# The library and the CLI depend on nothing but the JDK and the Kotlin
# standard library, which -include-runtime folds into the jar - so the CLI
# runs under a bare `java -cp`, with no stdlib to locate. Only the
# conformance suite needs omni, and only on its classpath.
build:
	mkdir -p build
	$(KOTLINC) src/*.kt cli/*.kt -include-runtime -d build/sekreto-cli.jar
	# kotlinc writes the file facade's DEFAULT name into Main-Class and
	# ignores @file:JvmName, so the jar it produces names a class that is
	# not in it. Restate the entry point the CLI actually has, so that
	# `java -jar` works as well as `java -cp ... sekreto.Cli`.
	jar --update --file build/sekreto-cli.jar --main-class sekreto.Cli

# The suite compiles against the jar `build` just made, so the library is
# compiled once however many times the tests are run.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/kotlin build
	mkdir -p build/test
	$(KOTLINC) -cp build/sekreto-cli.jar:$(OMNI)/kotlin/build/omnitest.jar \
	  test/*.kt -d build/test
	java -cp build/test:build/sekreto-cli.jar:$(OMNI)/kotlin/build/omnitest.jar SekretoTest

clean:
	rm -rf build

inspect:
	@$(KOTLINC) -version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
