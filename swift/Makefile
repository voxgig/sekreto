.PHONY: build deps test lean check-core clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: the library is built on its host, so the
# library needs it and not only the tests. Swift has no package registry
# this port uses - there is no Package.swift, deliberately - so it is found
# the way omni is found, and `deps` fetches a shallow clone when there is
# nothing to find. The library itself searches no path.
#
# Recursively expanded (=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN_REPO ?= https://github.com/voxgig/plugin
PLUGIN_REF ?= main
PLUGIN = $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/swift/src/Host.swift" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

SWIFTC ?= swiftc

# ../.plugin is SHARED with the other ports whose `deps` clones plugin's
# main when they find nothing, and the integration job builds every port on
# one runner. A clone that is already there is used as it is; a checkout the
# caller owns ($PLUGIN_HOME, a sibling) is never touched.
deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) ($(PLUGIN_REF)) into ../.plugin"; \
	  git clone --quiet --depth 1 --branch $(PLUGIN_REF) $(PLUGIN_REPO) ../.plugin; \
	fi

# swiftc is driven directly: there is no Package.swift, because SwiftPM
# would put a manifest in the shipped tree for a library that resolves
# nothing. Each library becomes a static archive plus a .swiftmodule, and
# the CLI and the conformance suite link the same build.
#
# THREE MODULES, AND THE MIDDLE ONE IS THE BOUNDARY.
#
#   VoxgigPlugin    <checkout>/swift/src/*.swift   the host library
#   Sekreto         src/*.swift                    the core: the chain, the
#                                                  cache, redaction, checkaddr
#                                                  and the four built-in kinds
#   SekretoPlugins  plugins/*.swift                the ten kinds that open a
#                                                  socket, sign a request or
#                                                  spawn a process
#
# The core cannot reach the plugins even by accident: `Sekreto` is compiled
# from src/*.swift alone, so `import SekretoPlugins` in a core source names
# a module that does not exist when the core is built - and would be a
# cycle if it did, because every plugin imports Sekreto. What the compiler
# cannot see - URLSession, Process, a hash function - `make check-core`
# greps for, and test/PluginTest.swift pins both so a regression fails the
# suite and not only this target.
#
# Nothing is written inside the plugin checkout: its sources are compiled
# into build/ here, exactly as omni's objects are archived here below.
#
# -lm because plugin's Value uses floor/ceil to tell a whole double from a
# fraction, and a static swift archive does not carry libm with it.
build: deps
	mkdir -p build
	# swiftc -static APPENDS to an archive that is already there rather than
	# replacing it, so a file that moves out of a module leaves its object
	# behind - and the core kept a Crypto-1.o that nothing in src/ compiles
	# any more. A stale member is exactly what would make `nm` on the core
	# report a boundary that is not there, so the archives go first.
	rm -f build/libVoxgigPlugin.a build/libSekreto.a build/libSekretoPlugins.a
	$(SWIFTC) -emit-module -emit-library -static -module-name VoxgigPlugin \
	  -emit-module-path build/VoxgigPlugin.swiftmodule -o build/libVoxgigPlugin.a \
	  $(PLUGIN)/swift/src/*.swift
	$(SWIFTC) -I build -emit-module -emit-library -static -module-name Sekreto \
	  -emit-module-path build/Sekreto.swiftmodule -o build/libSekreto.a src/*.swift
	$(SWIFTC) -I build -emit-module -emit-library -static -module-name SekretoPlugins \
	  -emit-module-path build/SekretoPlugins.swiftmodule -o build/libSekretoPlugins.a \
	  plugins/*.swift
	$(SWIFTC) -I build -L build -lSekretoPlugins -lSekreto -lVoxgigPlugin -lm \
	  -o build/sekreto-cli cli/Cli.swift

# The core reaches no plugin.
#
# The module boundary is the compiler's job and it does most of it. This is
# the rest: the core must not name a socket, a subprocess, a hash function
# or a plugin module, and none of those is something `swiftc` would refuse
# on its own - FoundationNetworking and Process are one `import Foundation`
# away in every core file.
#
# AND SO IS POSIX. `import Foundation` re-exports Glibc on Linux, so
# `socket`, `connect` and `posix_spawn` are in scope in every core file
# with no import for a scan to key on - a socket and a child process
# without a single word from the line above. Foundation's own names are
# the polite spelling of the same two capabilities, not the only one, so
# the raw ones are named here too.
#
# Prose is exempt, and has to be: the comments in src/ point at the plugins
# on purpose, because that is how a reader finds them.
check-core:
	@if grep -rn -E \
	    'URLSession|FoundationNetworking|(^|[^A-Za-z])Process\(|Pipe\(|sha256|hmac|sigv4|import SekretoPlugins|posix_spawn|(^|[^A-Za-z_])(socket|connect|getaddrinfo|fork|execv|execve|execvp|execl|execlp|popen|dlopen|dlsym)\(' \
	    src \
	    | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//' \
	    | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*///'; then \
	  echo "sekreto: the core reaches for something that belongs in a plugin" >&2; exit 1; \
	else echo "core: reaches no plugin"; fi

# ONE PLUGIN, ON ITS OWN. A swift module is compiled whole, so a plugin
# file that reached into a neighbour would still build as part of
# SekretoPlugins with no import to give it away. This builds each plugin
# beside the two shared files and nothing else, which is what a lean
# consumer's own build line looks like, and fails the moment one of them
# needs a kind it does not name.
LEAN = Hashicorp Boru Gcpsecrets Azuresecrets Onepassword Doppler Infisical Secretspec
lean: build
	@rm -rf build/lean
	@mkdir -p build/lean
	@for kind in $(LEAN); do \
	  $(SWIFTC) -I build -emit-module -emit-library -static \
	    -module-name SekretoPlugins \
	    -emit-module-path build/lean/$$kind.swiftmodule \
	    -o build/lean/lib$$kind.a \
	    plugins/$$kind.swift plugins/Httpjson.swift plugins/Proc.swift || exit 1; \
	  echo "lean: $$kind"; \
	done
	@$(SWIFTC) -I build -emit-module -emit-library -static -module-name SekretoPlugins \
	  -emit-module-path build/lean/Aws.swiftmodule -o build/lean/libAws.a \
	  plugins/Aws.swift plugins/Httpjson.swift plugins/Sigv4.swift plugins/Crypto.swift
	@echo "lean: Aws"

# The suite links the libraries `build` just made, so they are compiled
# once however many times the tests are run.
#
# SwiftPM leaves omni as loose object files rather than an archive, and a
# bare `.o` on a swiftc command line is not passed to the linker, so they
# are gathered into an archive here. Nothing is written inside the omni
# checkout.
test: build check-core lean
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/swift build
	rm -f build/libOmni.a
	ar rcs build/libOmni.a $(OMNI)/swift/.build/debug/Omni.build/*.o
	$(SWIFTC) -I build -I $(OMNI)/swift/.build/debug -L build \
	  -lSekretoPlugins -lSekreto -lVoxgigPlugin -lOmni -lm \
	  -o build/sekreto-test test/SekretoTest.swift
	$(SWIFTC) -I build -L build -lSekretoPlugins -lSekreto -lVoxgigPlugin -lm \
	  -o build/sekreto-plugintest test/PluginTest.swift
	./build/sekreto-test
	SEKRETO_SWIFTC=$(SWIFTC) ./build/sekreto-plugintest

clean:
	rm -rf build

inspect:
	@$(SWIFTC) -version 2>&1 | head -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
