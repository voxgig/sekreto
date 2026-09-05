# The lean port.
#
# No lake, and no lakefile. Lake resolves a package's whole dependency
# graph before it compiles anything, and this port has to do three things
# lake makes awkward at once: link an in-tree C binding (`ffi/`) that no
# `lakefile.toml` target shape covers, put voxgig/omni in front of the
# CONFORMANCE SUITE ONLY, and compile `src/` with `plugins/` OUT OF
# REACH. `lean` and `leanc` are the compiler and the linker; driving them
# here keeps the library's build inputs to `src/`, voxgig/plugin and the
# toolchain, which is what register 4.13 asks for. The swift port ships
# no `Package.swift` for the same reason.
#
# elan installs to ~/.elan/bin; prepend it so a stock elan install works.
# Named separately as well, because GNU make's `$(shell ...)` does not
# see a PATH exported from inside the makefile.
ELANBIN := $(HOME)/.elan/bin
export PATH := $(ELANBIN):$(PATH)

.PHONY: build deps test check-core clean inspect ffi

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: every provider kind is a plugin
# definition and the chain is a plugin host, so the LIBRARY needs it and
# not only the tests. Lean has no package registry, so it is found the
# way omni is found - $PLUGIN_HOME, then a sibling checkout, then the
# usual places, including the ../.plugin that `deps` fetches when nothing
# else is there. CI therefore needs no checkout step for it.
#
# Recursively expanded (=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN_REPO ?= https://github.com/voxgig/plugin
PLUGIN = $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin /workspace/plugin /home/user/plugin ../.plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/lean/src/Plugin.lean" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

LEAN ?= lean
LEANC ?= leanc

B := build
HOSTLIB := $(B)/host
LIB := $(B)/lib
PLIB := $(B)/plugins
IR := $(B)/ir

# THE THREE LAYERS, AND THE ORDER IS THE BOUNDARY.
#
# `lean` compiles one module at a time and every import must already have
# an `.olean` on LEAN_PATH, so each list below is its own dependency
# order. What matters more is which LEAN_PATH each layer is compiled
# with:
#
#   voxgig/plugin  $(HOSTLIB)
#   the core       $(HOSTLIB):$(LIB)                 <- no $(PLIB)
#   the plugins    $(HOSTLIB):$(LIB):$(PLIB)
#
# The core is compiled with the plugin tree OFF ITS PATH, so a core
# module that imports one does not compile at all: Lean resolves a module
# name's first component to a single LEAN_PATH directory, which is why
# the plugins are `SekretoPlugins.*` rather than `Sekreto.Plugins.*`.
# That is this language's version of go's linking boundary and zig's
# module roots. `check-core` reads the same fact back off the compiled
# objects.
HOSTMODULES := Plugin.Value Plugin.Types Plugin.Ref Plugin.Version \
               Plugin.Capability Plugin.Resolve Plugin.Env Plugin.Config \
               Plugin.Graph Plugin.Order Plugin.Export Plugin.Depend \
               Plugin.Defs Plugin.Host Plugin.Machine Plugin

MODULES := Sekreto.Text Sekreto.Json Sekreto.Core Sekreto.Addr \
           Sekreto.Provider Sekreto.Builtin Sekreto.Chain Sekreto

PLUGINMODULES := SekretoPlugins.Httpjson SekretoPlugins.Proc \
                 SekretoPlugins.Crypto SekretoPlugins.Clock \
                 SekretoPlugins.Sigv4 SekretoPlugins.Hashicorp \
                 SekretoPlugins.Boru SekretoPlugins.Secretspec \
                 SekretoPlugins.Aws SekretoPlugins.Gcpsecrets \
                 SekretoPlugins.Azuresecrets SekretoPlugins.Onepassword \
                 SekretoPlugins.Doppler SekretoPlugins.Infisical \
                 SekretoPlugins

# The one symbol outside Lean's own naming that the core is allowed to
# want: libm's `floor`, which `Float` arithmetic compiles to. voxgig/plugin
# wants `round` for the same reason. Anything else in that position is an
# `@[extern]` somebody added to the core.
FOREIGN := floor

# The two prefix families `check-core` denies outright, and the one it
# allows. Prefixes, so that a reach nobody thought to name is still
# caught: `l_IO_Process_` is a compiled Lean function, `lean_io_process_`
# is the runtime binding under it, and BOTH are spawning. `COREMODS` is
# the core's whole import set - `Init`, voxgig/plugin, its own modules -
# read off the two module lists above.
PROCSYMS := ^(l_IO_Process_|lean_io_process_)
COREMODS := ^initialize_(Init|Plugin|Sekreto)($$|_)

HOSTOBJS := $(patsubst %,$(IR)/%.o,$(HOSTMODULES))
OBJS := $(patsubst %,$(IR)/%.o,$(MODULES))
PLUGINOBJS := $(patsubst %,$(IR)/%.o,$(PLUGINMODULES))

# The TLS binding, and the platform clock. libcurl verifies the chain and
# the hostname itself; see ffi/sekreto_curl.c. BOTH ARE PLUGIN-SIDE: the
# only Lean modules that declare them are under `plugins/`, and
# `build/sekreto-core` links neither.
#
# AUDIT SURFACE: libcurl, PLUS WHICHEVER TLS BACKEND IT WAS BUILT
# AGAINST, which this port does not choose - libcurl may be linked to
# OpenSSL, GnuTLS, NSS or Schannel, and only the OpenSSL one honours
# CURLOPT_SSL_CTX_FUNCTION, which is how SEKRETO_CA_BUNDLE adds roots
# WITHOUT replacing the system store. `-lssl -lcrypto` is for that one
# call and nothing else: SHA-256 and HMAC-SHA256 are in-tree, in
# plugins/SekretoPlugins/Crypto.lean, as the rule requires.
FFILIBS := -lcurl -lssl -lcrypto
FFIOBJS := $(IR)/sekreto_curl.o $(IR)/sekreto_clock.o

build: $(B)/sekreto-cli

ffi: $(FFIOBJS)

# The C stubs are compiled by the SYSTEM compiler, not by `leanc`.
# `leanc` runs its bundled clang under `-nostdinc` with the toolchain as
# its sysroot, so it can see <lean/lean.h> and nothing else - not
# <string.h>, and certainly not <curl/curl.h>. `leanc` still does the
# LINKING, because it knows where the Lean runtime lives.
CC ?= cc
LEANINCLUDE := $(shell PATH="$(ELANBIN):$$PATH" $(LEAN) --print-prefix)/include
SYSLIB := -L/usr/lib/$(shell $(CC) -dumpmachine)

$(IR)/%.o: ffi/%.c
	@mkdir -p $(IR)
	$(CC) -c -o $@ $< -I$(LEANINCLUDE) -fPIC -std=c11 -Wall -Wextra -Werror

# voxgig/plugin IS COMPILED HERE, from its source, rather than by
# invoking its own Makefile - for the reason the conformance suite
# compiles omni's. A `.olean` carries the exact compiler that wrote it and
# every other release refuses to load it, so taking that repository's
# build artifacts would pin it and this one to a single Lean version
# between them. Compiling sixteen modules costs a few seconds and assumes
# nothing about plugin having been built.
$(HOSTLIB)/.stamp:
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME or run make deps" >&2; exit 1; }
	@mkdir -p $(HOSTLIB) $(IR)
	@for mod in $(HOSTMODULES); do \
	  path=$$(echo $$mod | tr . /); \
	  mkdir -p "$(HOSTLIB)/$$(dirname $$path)"; \
	  echo "  lean plugin/$$path.lean"; \
	  LEAN_PATH=$(CURDIR)/$(HOSTLIB) $(LEAN) --root=$(PLUGIN)/lean/src \
	    -o $(HOSTLIB)/$$path.olean -i $(HOSTLIB)/$$path.ilean -c $(IR)/$$mod.c \
	    "$(PLUGIN)/lean/src/$$path.lean" || exit 1; \
	  $(LEANC) -c -o $(IR)/$$mod.o $(IR)/$$mod.c || exit 1; \
	done
	@touch $@

# One rule per module would need a hand-written dependency graph; the
# lists above ARE that graph, so each layer is compiled in one pass.
$(LIB)/.stamp: $(HOSTLIB)/.stamp $(wildcard src/*.lean src/Sekreto/*.lean)
	@mkdir -p $(LIB) $(IR)
	@for mod in $(MODULES); do \
	  path=$$(echo $$mod | tr . /); \
	  mkdir -p "$(LIB)/$$(dirname $$path)"; \
	  echo "  lean src/$$path.lean"; \
	  LEAN_PATH=$(CURDIR)/$(HOSTLIB):$(CURDIR)/$(LIB) $(LEAN) --root=src \
	    -o $(LIB)/$$path.olean -i $(LIB)/$$path.ilean -c $(IR)/$$mod.c "src/$$path.lean" || exit 1; \
	  $(LEANC) -c -o $(IR)/$$mod.o $(IR)/$$mod.c || exit 1; \
	done
	@touch $@

$(PLIB)/.stamp: $(LIB)/.stamp $(wildcard plugins/*.lean plugins/SekretoPlugins/*.lean)
	@mkdir -p $(PLIB) $(IR)
	@for mod in $(PLUGINMODULES); do \
	  path=$$(echo $$mod | tr . /); \
	  mkdir -p "$(PLIB)/$$(dirname $$path)"; \
	  echo "  lean plugins/$$path.lean"; \
	  LEAN_PATH=$(CURDIR)/$(HOSTLIB):$(CURDIR)/$(LIB):$(CURDIR)/$(PLIB) $(LEAN) --root=plugins \
	    -o $(PLIB)/$$path.olean -i $(PLIB)/$$path.ilean -c $(IR)/$$mod.c "plugins/$$path.lean" || exit 1; \
	  $(LEANC) -c -o $(IR)/$$mod.o $(IR)/$$mod.c || exit 1; \
	done
	@touch $@

$(B)/sekreto-cli: $(PLIB)/.stamp $(FFIOBJS) cli/Cli.lean
	@mkdir -p $(LIB) $(IR)
	LEAN_PATH=$(CURDIR)/$(HOSTLIB):$(CURDIR)/$(LIB):$(CURDIR)/$(PLIB) $(LEAN) --root=cli \
	  -o $(LIB)/Cli.olean -i $(LIB)/Cli.ilean -c $(IR)/Cli.c cli/Cli.lean
	$(LEANC) -c -o $(IR)/Cli.o $(IR)/Cli.c
	$(LEANC) -o $@ $(HOSTOBJS) $(OBJS) $(PLUGINOBJS) $(FFIOBJS) $(IR)/Cli.o $(SYSLIB) $(FFILIBS)

# THE CORE, LINKED ALONE: a real program built from the core objects and
# voxgig/plugin, with no ffi/ object file and no `-lcurl -lssl -lcrypto`
# on the command line at all.
#
# It is a proof, not a demo. `sekreto_curl_fetch` and
# `sekreto_epoch_seconds` are the two symbols the C bindings define; if
# any core module reached for either - or for anything in libcurl or
# OpenSSL behind them - this link would fail with an undefined symbol
# rather than produce a binary. It runs a chain of the four built-in
# kinds, so it also shows what such a chain can do with no plugin loaded.
$(B)/sekreto-core: $(LIB)/.stamp test/CoreOnly.lean
	@mkdir -p $(LIB) $(IR)
	LEAN_PATH=$(CURDIR)/$(HOSTLIB):$(CURDIR)/$(LIB) $(LEAN) --root=test \
	  -o $(LIB)/CoreOnly.olean -i $(LIB)/CoreOnly.ilean -c $(IR)/CoreOnly.c test/CoreOnly.lean
	$(LEANC) -c -o $(IR)/CoreOnly.o $(IR)/CoreOnly.c
	$(LEANC) -o $@ $(HOSTOBJS) $(OBJS) $(IR)/CoreOnly.o

# THE SPLIT, READ BACK OFF THE COMPILED ARTIFACTS.
#
# `lean` emits one `initialize_<Module>` symbol per import and one
# undefined reference per `@[extern]`, so the undefined symbols of a
# compiled object ARE its import graph and its platform reach, spelled
# out in full names. Three claims, matched EXACTLY and never as
# substrings:
#
#   1. the core links with no ffi/ object and no TLS library at all
#      (the rule for $(B)/sekreto-core, above)
#   2. no core object references a plugin module, the libcurl binding,
#      the clock binding or IO.Process
#   3. the plugin objects reference every one of those names
#
# A LIST OF NAMES IS NOT ENOUGH ON ITS OWN, because a core could open a
# socket under a name nobody thought to list. So the list is backed by
# three checks that need no list at all - and the shape of all three is a
# PREFIX, never an enumerated API.
#
#   1. the core's undefined symbols outside Lean's own `l_`/`lean_`/
#      `initialize_` naming must be exactly $(FOREIGN), which is what
#      `Float` arithmetic costs
#   2. no symbol from $(PROCSYMS) may appear
#   3. every `initialize_` the core wants must match $(COREMODS)
#
# (1) ALONE IS NOT THE PROOF IT LOOKS LIKE. The premise - "reaching a
# platform needs an `@[extern]`, and every `@[extern]` falls outside
# `l_`/`lean_`/`initialize_`" - is false. LEAN'S OWN RUNTIME BINDINGS ARE
# `lean_*`, so `IO.Process.spawn` compiles to an undefined
# `lean_io_process_spawn` that (1) skips, needs no `@[extern]` of ours
# and no import at all - `Init` is auto-imported - and links against the
# runtime. An audit demonstrated it: a core that
# ran `/bin/sh -c id` passed (1) and the whole target. (2) is widened to
# `lean_io_process_` for that reason.
#
# (3) closes the other half. A module the core has no business importing -
# `Std.Time`, whose wall clock is `lean_get_current_time`, or a future
# `Std.Internal.UV.TCP`, whose socket is `lean_uv_tcp_connect` - is an
# `initialize_` symbol, which (1) also skips. The core's import set is
# known exactly: `Init`, voxgig/plugin and its own modules. Anything else
# is the check firing.
#
# ...and one more, which is (2) turned around: `SekretoPlugins.Hashicorp`
# reaches exactly one other plugin module - the shared HTTP client - and
# `SekretoPlugins.Secretspec` reaches only the child-process helper, so a
# consumer that imports one plugin does not link the other nine.
#
# (3) IS THE CONTROL, and it is the half that is easy to leave out. A
# forbidden list that matched nothing - a renamed symbol, an `nm` that
# read no files, a typo - would let (2) pass while proving nothing at
# all. So the same list is required to be found on the other side of the
# boundary, and `check-core` fails if it is not.
check-core: $(PLIB)/.stamp $(B)/sekreto-core
	@set -e; \
	  { for mod in $(PLUGINMODULES); do echo "initialize_$$(echo $$mod | tr . _)"; done; \
	    echo sekreto_curl_fetch; \
	    echo sekreto_epoch_seconds; \
	    echo l_IO_Process_output; } | sort -u > $(B)/forbidden.txt; \
	  nm --undefined-only --format=posix $(OBJS) | awk 'NF>1 {print $$1}' | sort -u > $(B)/core.syms; \
	  nm --undefined-only --format=posix $(PLUGINOBJS) | awk 'NF>1 {print $$1}' | sort -u > $(B)/plugin.undef; \
	  nm --format=posix $(PLUGINOBJS) | awk 'NF>1 {print $$1}' | sort -u > $(B)/plugin.syms; \
	  nm --defined-only --format=posix $(B)/sekreto-core | awk 'NF>1 {print $$1}' | sort -u > $(B)/corebin.syms; \
	  nm --defined-only --format=posix $(B)/sekreto-cli | awk 'NF>1 {print $$1}' | sort -u > $(B)/clibin.syms; \
	  test -s $(B)/core.syms || { echo "check-core: read no symbols from the core objects" >&2; exit 1; }; \
	  grep -qx initialize_Sekreto_Chain $(B)/core.syms \
	    || { echo "check-core: the core objects do not name the chain - nm read the wrong thing" >&2; exit 1; }; \
	  grep -qx initialize_Sekreto_Chain $(B)/corebin.syms \
	    || { echo "check-core: build/sekreto-core does not name the chain - nm read the wrong thing" >&2; exit 1; }; \
	  echo "== the control: every forbidden name exists, on the plugin side"; \
	  unseen=$$(comm -23 $(B)/forbidden.txt $(B)/plugin.syms); \
	  if [ -n "$$unseen" ]; then \
	    echo "check-core: no plugin object mentions these, so the check proves nothing:" >&2; \
	    echo "$$unseen" >&2; exit 1; \
	  fi; \
	  sed 's/^/  /' $(B)/forbidden.txt; \
	  echo "== the core objects reference none of them"; \
	  reached=$$(comm -12 $(B)/forbidden.txt $(B)/core.syms); \
	  if [ -n "$$reached" ]; then \
	    echo "sekreto: the core reaches for something that belongs in a plugin:" >&2; \
	    echo "$$reached" >&2; exit 1; \
	  fi; \
	  echo "== and no plugin module is linked into build/sekreto-core"; \
	  { for mod in $(PLUGINMODULES); do echo "initialize_$$(echo $$mod | tr . _)"; done; } \
	    | sort -u > $(B)/pluginmods.txt; \
	  missing=$$(comm -23 $(B)/pluginmods.txt $(B)/clibin.syms); \
	  if [ -n "$$missing" ]; then \
	    echo "check-core: build/sekreto-cli is missing these, so the check proves nothing:" >&2; \
	    echo "$$missing" >&2; exit 1; \
	  fi; \
	  linked=$$(comm -12 $(B)/pluginmods.txt $(B)/corebin.syms); \
	  if [ -n "$$linked" ]; then \
	    echo "sekreto: build/sekreto-core links a plugin:" >&2; \
	    echo "$$linked" >&2; exit 1; \
	  fi; \
	  echo "== the core reaches outside Lean's own naming for $(FOREIGN) and nothing else"; \
	  { grep -vE '^(l_|lean_|initialize_)' $(B)/core.syms || true; } | sort -u > $(B)/core.foreign; \
	  { grep -vE '^(l_|lean_|initialize_)' $(B)/plugin.undef || true; } | sort -u > $(B)/plugin.foreign; \
	  test -s $(B)/plugin.foreign || { \
	    echo "check-core: no foreign symbol on the plugin side either - nm read nothing" >&2; exit 1; }; \
	  sed 's/^/  plugin: /' $(B)/plugin.foreign; \
	  sed 's/^/  core:   /' $(B)/core.foreign; \
	  test "$$(cat $(B)/core.foreign)" = "$(FOREIGN)" || { \
	    echo "sekreto: the core declares an @[extern] of its own - every platform call is a plugin's" >&2; \
	    exit 1; }; \
	  echo "== and spawns nothing, by either name"; \
	  test 0 -lt "$$(grep -cE '$(PROCSYMS)' $(B)/plugin.undef)" || { \
	    echo "check-core: no plugin object spawns anything, so the check proves nothing" >&2; exit 1; }; \
	  test 0 -eq "$$(grep -cE '$(PROCSYMS)' $(B)/core.syms)" || { \
	    echo "sekreto: the core spawns a process - that is a plugin's job:" >&2; \
	    grep -E '$(PROCSYMS)' $(B)/core.syms >&2; exit 1; }; \
	  echo "== and imports Init, voxgig/plugin and its own modules, and nothing else"; \
	  { grep -E '^initialize_' $(B)/plugin.undef | grep -vE '$(COREMODS)' || true; } \
	    > $(B)/plugin.extramods; \
	  test -s $(B)/plugin.extramods || { \
	    echo "check-core: no object imports past the core's own set, so the check proves nothing" >&2; \
	    exit 1; }; \
	  { grep -E '^initialize_' $(B)/core.syms | grep -vE '$(COREMODS)' || true; } \
	    > $(B)/core.extramods; \
	  test ! -s $(B)/core.extramods || { \
	    echo "sekreto: the core imports a module outside Init, voxgig/plugin and its own:" >&2; \
	    cat $(B)/core.extramods >&2; exit 1; }; \
	  echo "== one plugin reaches only the shared support it dials"; \
	  for pair in "Hashicorp:initialize_SekretoPlugins_Httpjson" "Secretspec:initialize_SekretoPlugins_Proc"; do \
	    mod=$${pair%%:*}; want=$${pair#*:}; \
	    got=$$(nm --undefined-only --format=posix $(IR)/SekretoPlugins.$$mod.o \
	      | awk '{print $$1}' | grep '^initialize_SekretoPlugins_' | sort -u | tr '\n' ' '); \
	    echo "  SekretoPlugins.$$mod -> $$got"; \
	    test "$$got" = "$$want " || { \
	      echo "sekreto: SekretoPlugins.$$mod reaches past $$want" >&2; exit 1; }; \
	  done; \
	  echo "core: $$(wc -l < $(B)/core.syms) symbols, no plugin among them"; \
	  ./$(B)/sekreto-core

# The suite compiles against the library `build` just made, so the
# library is compiled once however many times the tests are run.
#
# THE RUNNER IS BUILT HERE, from omni's SOURCE, rather than by invoking
# omni's own Makefile - the same reason voxgig/plugin is compiled here.
# Compiling `Omni.lean` into build/omni costs two seconds, assumes
# nothing about omni being built, and is what "the port builds omni
# itself" means for this language. Nothing the library builds ever
# reaches build/omni.
test: build check-core
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	@mkdir -p $(B)/omni
	LEAN_PATH=$(CURDIR)/$(B)/omni $(LEAN) --root=$(OMNI)/lean \
	  -o $(B)/omni/Omni.olean -i $(B)/omni/Omni.ilean -c $(B)/omni/Omni.c \
	  $(OMNI)/lean/Omni.lean
	$(LEANC) -c -o $(B)/omni/Omni.o $(B)/omni/Omni.c
	LEAN_PATH=$(CURDIR)/$(HOSTLIB):$(CURDIR)/$(LIB):$(CURDIR)/$(PLIB):$(CURDIR)/$(B)/omni \
	  $(LEAN) --root=test \
	  -o $(B)/omni/SekretoTest.olean -i $(B)/omni/SekretoTest.ilean \
	  -c $(B)/omni/SekretoTest.c test/SekretoTest.lean
	$(LEANC) -c -o $(B)/omni/SekretoTest.o $(B)/omni/SekretoTest.c
	$(LEANC) -o $(B)/sekreto-test $(HOSTOBJS) $(OBJS) $(PLUGINOBJS) $(FFIOBJS) \
	  $(B)/omni/Omni.o $(B)/omni/SekretoTest.o $(SYSLIB) $(FFILIBS)
	./$(B)/sekreto-test $(GROUP)

clean:
	rm -rf build

inspect:
	@$(LEAN) --version | head -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
