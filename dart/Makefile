.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

DART ?= dart

# The library and the CLI depend on nothing but the Dart SDK, and they reach
# each other by relative import, so `pubspec.yaml` declares no dependencies
# and `dart pub get` is never run. `compile exe` is what satisfies the
# empty-directory rule: the result is a self-contained native binary that
# resolves nothing relative to where it is started.
build:
	mkdir -p build
	$(DART) compile exe cli/cli.dart -o build/sekreto-cli

# Only the conformance suite needs omni, and it reaches it through a package
# map written here rather than through a dependency in the shipped manifest -
# so no manifest a consumer resolves can name omni. The map is a build
# artifact: `dart run --packages` reads it and pub is not involved.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/dart build
	mkdir -p build
	@printf '{"configVersion":2,"packages":[{"name":"voxgig_omni","rootUri":"file://%s/dart","packageUri":"lib/","languageVersion":"3.0"}]}\n' "$(OMNI)" > build/package_config.json
	$(DART) run --packages=build/package_config.json test/sekreto_test.dart

# `.dart_tool` is written by `dart compile exe` because a pubspec.yaml is
# present; it holds no dependencies, since none are declared.
clean:
	rm -rf build .dart_tool

inspect:
	@$(DART) --version 2>&1 | tail -1
	@echo "omni: $(OMNI)"
