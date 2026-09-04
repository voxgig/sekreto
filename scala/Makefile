.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

SCALAC ?= scalac

# The Scala runtime is two jars beside the compiler - the Scala 3 library
# and the Scala 2.13 one it builds on. `scalac` puts them on its own
# classpath; `java -cp` does not, so they are folded into the jar (see
# below). Found from the compiler on PATH rather than named, so a
# distribution unpacked anywhere still builds.
SCALAHOME := $(shell \
  bin=$$(command -v $(SCALAC)) || exit 0; \
  cd "$$(dirname "$$(readlink -f "$$bin")")/.." && pwd)

SCALAJARS := $(wildcard $(SCALAHOME)/lib/scala3-library_3-*.jar) \
             $(wildcard $(SCALAHOME)/lib/scala-library-*.jar)

# The library and the CLI depend on nothing but the JDK and the Scala
# standard library. scalac has no -include-runtime, so the runtime jars are
# unpacked alongside the compiled classes and packed with them - which is
# what lets the CLI run under a bare `java -cp`, with no stdlib to locate.
# Only the conformance suite needs omni, and only on its classpath.
build:
	@test -n "$(SCALAJARS)" || { echo "sekreto: scala runtime not found beside $(SCALAC)" >&2; exit 1; }
	rm -rf build/stage
	mkdir -p build/stage
	$(SCALAC) -d build/stage src/*.scala cli/*.scala
	for jar in $(SCALAJARS); do (cd build/stage && jar --extract --file $$jar); done
	# The runtime jars bring their own manifests; `jar --create` writes the
	# one that names the entry point, and a second copy on the way in is a
	# duplicate entry.
	rm -rf build/stage/META-INF
	jar --create --file build/sekreto-cli.jar --main-class sekreto.Cli -C build/stage .

# The suite compiles against the jar `build` just made, so the library is
# compiled once however many times the tests are run.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/scala build
	mkdir -p build/test
	$(SCALAC) -classpath build/sekreto-cli.jar:$(OMNI)/scala/build \
	  -d build/test test/*.scala
	java -cp build/test:build/sekreto-cli.jar:$(OMNI)/scala/build SekretoTest

clean:
	rm -rf build

inspect:
	@$(SCALAC) -version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
