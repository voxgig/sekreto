.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# The official Clojure CLI (clojure.org/guides/install_clojure). Debian's
# package of the same name is a different program: it has no deps.edn and no
# -M, so a build there fails at the first target rather than half way.
CLOJURE ?= clojure

# The library and the CLI depend on nothing but the JDK and Clojure itself.
#
# The CLI is AOT-compiled and the Clojure runtime jars are unpacked
# alongside its classes, so `build/sekreto-cli.jar` runs under a bare
# `java -cp` - which is what test/integration.sh needs, because it runs
# every port's CLI from an EMPTY directory. A `clojure -M` invocation would
# read a deps.edn from the working directory instead, and the empty
# directory is precisely what stops a stray .env making a run pass.
#
# Compilation is transitive: compiling the CLI namespace compiles the
# library it requires. *compile-path* must be on the classpath, which is why
# the :cli alias lists build/classes.
build:
	rm -rf build/classes build/stage
	mkdir -p build/classes build/stage
	$(CLOJURE) -M:cli -e '(binding [*compile-path* "build/classes"] (compile (quote sekreto.cli)))'
	cp -R build/classes/. build/stage/
	for jar in $$($(CLOJURE) -Spath | tr ':' '\n' | grep '\.jar$$'); do \
	  (cd build/stage && jar --extract --file $$jar); \
	done
	# The runtime jars bring their own manifests; `jar --create` writes the
	# one that names the entry point, and a second copy on the way in is a
	# duplicate entry.
	rm -rf build/stage/META-INF
	jar --create --file build/sekreto-cli.jar --main-class sekreto.Cli -C build/stage .

# The suite runs the library from source, as Clojure does. `build` runs
# first so that `make test` also proves the artifact the integration suite
# invokes still compiles.
#
# omni reaches the classpath as a local dependency named on the command
# line, never in deps.edn: nothing a consumer of this library resolves may
# name the conformance runner.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/clojure build
	$(CLOJURE) -Sdeps '{:aliases {:omni {:extra-deps {voxgig/omni {:local/root "$(OMNI)/clojure"}}}}}' \
	  -M:test:omni -m voxgig.sekreto.test.main

clean:
	rm -rf build .cpcache

inspect:
	@$(CLOJURE) --version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
