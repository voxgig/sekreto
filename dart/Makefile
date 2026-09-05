.PHONY: build test seam check-core deps clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is a dependency of the LIBRARY, not only of the tests: the
# provider kinds are plugin definitions and Sekreto is a plugin host. Its
# dart port ships NO PUBSPEC - it takes no dependencies, so it has no
# manifest - which means there is nothing for `dart pub` to resolve and
# nothing a pubspec here could name. The port therefore takes it the way the
# kotlin and zig ports do, and the way every port takes omni: a checkout,
# found in the usual places. Failing all of them, `deps` fetches a shallow
# clone into ../.plugin (gitignored), which is what `npm install` and
# `go mod download` do for those two ports. CI needs no checkout step for it
# because of this.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/dart/lib/plugin.dart" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

DART ?= dart

# THE PACKAGE MAP IS THIS PORT'S CLASSPATH, and there are two of them.
#
#   build/package_config.json    voxgig/plugin, and nothing else - what the
#                                LIBRARY, the CLI and the seam are built
#                                against
#   build/test_config.json       the same, plus voxgig/omni for the
#                                conformance suite alone
#
# Written here rather than resolved by pub: `dart pub get` is never run, so
# no manifest a consumer resolves can name a checkout, and nothing here
# reaches the network. `dart compile` and `dart run` read a map given with
# --packages and pub is not involved. The port's own files - `src/`,
# `plugins/`, `cli/`, `test/` - reach each other by relative import, so
# neither map names sekreto itself.
PKG = build/package_config.json
TESTPKG = build/test_config.json

# The library and the CLI depend on nothing but the Dart SDK and
# voxgig/plugin. `compile exe` is what satisfies the empty-directory rule:
# the result is a self-contained native binary that resolves nothing
# relative to where it is started. The CLI passes `allplugins`, so this
# binary carries all ten plugin kinds - which is what a CLI whose
# `--source` is chosen at run time needs, and what an app that knows its
# chain does not.
build: $(PKG)
	$(DART) compile exe --packages=$(PKG) cli/cli.dart -o build/sekreto-cli

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig/plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

$(PKG):
	@test -n "$(PLUGIN)" || { \
	  echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME or run make deps" >&2; \
	  exit 1; }
	@mkdir -p build
	@printf '{"configVersion":2,"packages":[{"name":"voxgig_plugin","rootUri":"file://%s/dart","packageUri":"lib/","languageVersion":"3.0"}]}\n' "$(PLUGIN)" > $(PKG)

# Only the conformance suite needs omni, and it reaches it through this map
# rather than through a dependency in the shipped manifest - so no manifest
# a consumer resolves can name it. The map is a build artifact.
$(TESTPKG): $(PKG)
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	@mkdir -p build
	@printf '{"configVersion":2,"packages":[{"name":"voxgig_plugin","rootUri":"file://%s/dart","packageUri":"lib/","languageVersion":"3.0"},{"name":"voxgig_omni","rootUri":"file://%s/dart","packageUri":"lib/","languageVersion":"3.0"}]}\n' "$(PLUGIN)" "$(OMNI)" > $(TESTPKG)

test: build seam $(TESTPKG)
	$(MAKE) -C $(OMNI)/dart build
	$(DART) run --packages=$(TESTPKG) test/sekreto_test.dart

# THE PLUGIN SEAM, which the conformance suite cannot see: it hands the full
# set to every chain it builds, so it is only ever testing the one consumer
# that gets that right. Needs no omni.
seam: $(PKG) check-core
	$(DART) run --packages=$(PKG) test/plugins_test.dart

# THE CORE DOES NOT REACH A PLUGIN, proved of the artifact.
#
# test/coreonly.dart is compiled and RUN, and the compiler is asked for its
# own dependency listing while it happens (--depfile, a ninja depfile naming
# every source that went into the binary). A core that reached a plugin - by
# relative import, by package import, by anything the compiler can follow -
# would put a plugins/ path in that listing, and corecheck.sh fails on it.
# The list is the compiler's, not a grep of the source.
check-core: $(PKG)
	@mkdir -p build
	$(DART) compile exe --packages=$(PKG) test/coreonly.dart \
	  -o build/sekreto-coreonly --depfile=build/coreonly.d
	@sh ./corecheck.sh build/coreonly.d
	./build/sekreto-coreonly

clean:
	rm -rf build .dart_tool

inspect:
	@$(DART) --version 2>&1 | tail -1
	@echo "omni:   $(OMNI)"
	@echo "plugin: $(PLUGIN)"
