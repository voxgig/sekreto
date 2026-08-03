.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# The library and the CLI depend on nothing but the JDK. Only the
# conformance suite needs omni on its classpath.
build:
	mkdir -p build/classes
	javac -d build/classes src/com/voxgig/sekreto/*.java cli/*.java

test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/java build
	mkdir -p build/test
	javac -cp build/classes:$(OMNI)/java/build -d build/test test/SekretoTest.java
	java -cp build/classes:build/test:$(OMNI)/java/build SekretoTest

clean:
	rm -rf build

inspect:
	@javac -version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
