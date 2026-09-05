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
# library needs it and not only the tests. C++ has no package registry this
# port uses - there is no manifest at all, which is why tools/
# omni_isolation.py scans this port's source directly - so plugin is found
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
    if [ -n "$$d" ] && [ -f "$$d/cpp/src/host.hpp" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -O2

# The one linked dependency, and it is cryptographic transport: C++ has no
# TLS in its standard library, so this port binds the platform's audited
# one, as every C++ program that speaks https does. The audit surface is
# the distribution's OpenSSL. Nothing else is linked - the HTTP framing,
# the JSON, SHA-256, HMAC, base64 and PEM are all in-tree.
#
# IT IS THE PLUGINS THAT NEED IT, not the core. A consumer whose chain is
# built-ins only links libsekreto.a and libvoxgigplugin.a and NOTHING ELSE:
# no -lssl, no -lcrypto, no socket. `make check-core` proves that by doing
# it (build/coreonly), which is the boundary this port has instead of a
# manifest.
LIBS := -lssl -lcrypto

# ../.plugin is SHARED with the other ports whose `deps` clones plugin's
# main when they find nothing, and the integration job builds every port on
# one runner. A clone that is already there is used as it is; a checkout
# the caller owns ($PLUGIN_HOME, a sibling) is never touched.
deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) ($(PLUGIN_REF)) into ../.plugin"; \
	  git clone --quiet --depth 1 --branch $(PLUGIN_REF) $(PLUGIN_REPO) ../.plugin; \
	fi

# THREE ARCHIVES, AND THE MIDDLE ONE IS THE BOUNDARY.
#
#   libvoxgigplugin.a  <checkout>/cpp/src/*.cpp  the host library
#   libsekreto.a       src/*.cpp                 the core: the chain, the
#                                                cache, redaction, checkaddr
#                                                and the four built-in kinds
#   libsekretoplugins.a plugins/*.cpp            the ten kinds that open a
#                                                socket, sign a request or
#                                                spawn a process
#
# Each is compiled from ITS OWN directory and no other, so a core source
# that reached for a plugin would name a header no include path holds. What
# the compiler cannot see - a socket, a child process, a hash function,
# reached through libc with no sekreto header to give it away - `make
# check-core` reads out of the archive's own undefined-symbol list.
#
# Nothing is written inside the plugin checkout: its sources compile into
# build/ here, exactly as omni's do below.
PLUGINSRC = $(wildcard $(PLUGIN)/cpp/src/*.cpp)
CORESRC = $(wildcard src/*.cpp)
KINDSRC = $(wildcard plugins/*.cpp)

PLUGINOBJ = $(patsubst $(PLUGIN)/cpp/src/%.cpp,build/obj/voxgigplugin/%.o,$(PLUGINSRC))
COREOBJ = $(patsubst src/%.cpp,build/obj/core/%.o,$(CORESRC))
KINDOBJ = $(patsubst plugins/%.cpp,build/obj/plugins/%.o,$(KINDSRC))

build: build/sekreto-cli

build/obj/voxgigplugin/%.o: $(PLUGIN)/cpp/src/%.cpp
	@mkdir -p build/obj/voxgigplugin
	$(CXX) $(CXXFLAGS) -I$(PLUGIN)/cpp/src -c -o $@ $<

build/obj/core/%.o: src/%.cpp
	@mkdir -p build/obj/core
	$(CXX) $(CXXFLAGS) -Isrc -I$(PLUGIN)/cpp/src -c -o $@ $<

build/obj/plugins/%.o: plugins/%.cpp
	@mkdir -p build/obj/plugins
	$(CXX) $(CXXFLAGS) -Iplugins -Isrc -I$(PLUGIN)/cpp/src -c -o $@ $<

# `ar r` REPLACES a member and KEEPS every other one, so an archive that is
# already there outlives the source file a member came from: Crypto.o stayed
# inside libsekreto.a after Crypto.cpp moved to plugins/, and the core went
# on looking as though it needed SHA-256. A stale member can hide a symbol
# just as easily as invent one, so every archive is removed before it is
# built and the proofs below are taken from an archive with nothing in it
# but what was just compiled.
build/libvoxgigplugin.a: $(PLUGINOBJ)
	@rm -f $@
	ar rcs $@ $(PLUGINOBJ)

build/libsekreto.a: $(COREOBJ)
	@rm -f $@
	ar rcs $@ $(COREOBJ)

build/libsekretoplugins.a: $(KINDOBJ)
	@rm -f $@
	ar rcs $@ $(KINDOBJ)

# THE CLI PASSES THE FULL SET, so it links all three archives and OpenSSL.
build/sekreto-cli: cli/Cli.cpp build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a
	$(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o $@ cli/Cli.cpp \
	  build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a $(LIBS)

# The TLS obligations, proved in-tree. Neither `make test`'s corpus nor
# `make integration` opens an https socket, so without this a build with
# its certificate checking switched off would pass both.
build/sekreto-tlstest: test/TlsTest.cpp build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a
	$(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -pthread -o $@ test/TlsTest.cpp \
	  build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a $(LIBS)

# The seam, from both sides. Its own binary rather than part of the
# conformance suite, because it needs no omni: a checkout with no omni
# beside it can still run it.
build/sekreto-plugintest: test/PluginTest.cpp build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a
	$(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o $@ test/PluginTest.cpp \
	  build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a $(LIBS)

# ---------------------------------------------------------------------
# THE CORE REACHES NO PLUGIN, in the three ways C++ lets it be shown.
#
# 1. IT LINKS. A program that uses the core and nothing else links
#    libsekreto.a and libvoxgigplugin.a with no -lssl, no -lcrypto and no
#    plugin archive. If one core object the program reaches needed a socket,
#    a child process or a digest, this link would fail naming the symbol -
#    and the control beside it proves the line has teeth, because the same
#    program with ONE plugin object in it must NOT link without OpenSSL.
#    (An archive gives up only the members something asks for, which is why
#    the control names an object file, and why check 2 - which reads every
#    member - is the authoritative one.)
#
# 2. THE ARCHIVE'S UNDEFINED SYMBOLS say so. `nm -u` lists what the core
#    needs from outside; test/PluginTest.cpp matches those names EXACTLY
#    against socket, connect, posix_spawn, fork, execve, dlopen and the
#    rest - exactly, because a substring test finds `connect` inside
#    `disconnect` and misses nothing at all when the read fails.
#
# 3. THE SOURCE says so, for the little the first two cannot see: an
#    #include of a plugin header, a plugins/ path, an openssl/ header.
#    Matched as fixed strings on code lines, because `Socket.` as a regex
#    matches `SocketException`.
#
# This target is the human-readable half. PluginTest.cpp pins 2 and 3, and
# the -I boundary that keeps plugins/ off the core's include path, so a
# regression in any of those fails the suite on its own. THE LINK IS ONLY
# HERE - nothing in the seam binary invokes a compiler - and it is the only
# one of the three that catches a core reaching a plugin by HAND-DECLARING
# its factory: `Definition hashicorp();` written out in a core source names
# no plugin header, no plugins/ path and no platform symbol, so 2 and 3 both
# pass it and this link is what fails. `make test` depends on this target
# for exactly that reason.
check-core: build/libsekreto.a build/libvoxgigplugin.a build/libsekretoplugins.a
	@echo "== the core's sources name no plugin and no platform"
	@if grep -n -F -e '#include "Httpjson.hpp"' -e '#include "Tls.hpp"' \
	     -e '#include "Crypto.hpp"' -e '#include "Sigv4.hpp"' -e '#include "Proc.hpp"' \
	     -e '#include "All.hpp"' -e '#include <openssl/' -e '#include <sys/socket.h>' \
	     -e '#include <netdb.h>' -e 'plugins/' -e 'sha256' -e 'hmacsha256' \
	     -e 'SSL_' -e 'allplugins' \
	     src/*.cpp src/*.hpp \
	   | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//' \
	   | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*///'; then \
	  echo "sekreto: the core reaches for something that belongs in a plugin" >&2; exit 1; \
	else echo "core: names no plugin"; fi
	@echo "== the core's archive needs nothing a plugin owns"
	@nm -u build/libsekreto.a | awk '{ print $$NF }' | sort -u > build/core.syms
	@grep -q -x -E 'malloc|free|memcpy|memset|_Znwm|_ZdlPv' build/core.syms \
	  || { echo "sekreto: no libc name came out of nm - the symbol read has no teeth" >&2; \
	       exit 1; }
	@if grep -q -x -E 'socket|connect|bind|listen|accept|accept4|getaddrinfo|gethostbyname|posix_spawn|posix_spawnp|fork|vfork|execv|execve|execvp|execl|execlp|popen|system|dlopen|dlsym|SSL_[A-Za-z_0-9]*' \
	     build/core.syms; then \
	  grep -x -E 'socket|connect|bind|listen|accept|accept4|getaddrinfo|gethostbyname|posix_spawn|posix_spawnp|fork|vfork|execv|execve|execvp|execl|execlp|popen|system|dlopen|dlsym|SSL_[A-Za-z_0-9]*' build/core.syms >&2; \
	  echo "sekreto: the core archive needs a socket, a child process or TLS" >&2; exit 1; \
	else echo "core: needs no socket, no child process, no TLS"; fi
	@echo "== a core-only consumer links without OpenSSL"
	@$(CXX) $(CXXFLAGS) -Isrc -I$(PLUGIN)/cpp/src -o build/coreonly test/CoreOnly.cpp \
	  build/libsekreto.a build/libvoxgigplugin.a
	@./build/coreonly
	@if $(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o build/coreonly-control \
	     test/CoreOnly.cpp build/obj/plugins/All.o build/libsekretoplugins.a \
	     build/libsekreto.a build/libvoxgigplugin.a >/dev/null 2>&1; then \
	  echo "sekreto: one plugin in the link and still no OpenSSL needed - no teeth" >&2; \
	  exit 1; \
	else echo "core: and the same program WITH a plugin in it does not - the link has teeth"; fi

# ONE PLUGIN, ON ITS OWN. Every kind is its own translation unit, so a kind
# that reached into a neighbour would still build as part of the whole
# archive with nothing to give it away. This links each kind beside the
# shared files it declares and nothing else, which is what a lean consumer's
# own build line looks like, and the negative control is what gives it
# teeth: aws needs its signing, and linking it without Sigv4/Crypto must
# FAIL.
lean: build/libsekreto.a build/libvoxgigplugin.a $(KINDOBJ)
	@rm -rf build/lean && mkdir -p build/lean
	@set -e; for kind in Hashicorp Onepassword Doppler Infisical Azuresecrets Gcpsecrets; do \
	  $(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o build/lean/$$kind \
	    test/LeanPlugin.cpp build/obj/plugins/$$kind.o build/obj/plugins/Httpjson.o \
	    build/obj/plugins/Tls.o build/libsekreto.a build/libvoxgigplugin.a $(LIBS); \
	  echo "lean: $$kind"; \
	done
	@set -e; for kind in Boru Secretspec; do \
	  $(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o build/lean/$$kind \
	    test/LeanPlugin.cpp build/obj/plugins/$$kind.o build/obj/plugins/Httpjson.o \
	    build/obj/plugins/Tls.o build/obj/plugins/Proc.o \
	    build/libsekreto.a build/libvoxgigplugin.a $(LIBS); \
	  echo "lean: $$kind"; \
	done
	@$(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o build/lean/Aws \
	  test/LeanPlugin.cpp build/obj/plugins/Aws.o build/obj/plugins/Httpjson.o \
	  build/obj/plugins/Tls.o build/obj/plugins/Sigv4.o build/obj/plugins/Crypto.o \
	  build/libsekreto.a build/libvoxgigplugin.a $(LIBS)
	@echo "lean: Aws"
	@if $(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -o build/lean/nosign \
	     test/LeanPlugin.cpp build/obj/plugins/Aws.o build/obj/plugins/Httpjson.o \
	     build/obj/plugins/Tls.o build/libsekreto.a build/libvoxgigplugin.a $(LIBS) \
	     >/dev/null 2>&1; then \
	  echo "sekreto: aws linked without its signing - the lean check has no teeth" >&2; \
	  exit 1; \
	else echo "lean: and aws does not link without its signing"; fi
	@echo "== no plugin but aws needs a digest"
	@set -e; for kind in Hashicorp Boru Onepassword Doppler Infisical Azuresecrets \
	                     Gcpsecrets Secretspec; do \
	  if nm -C -u build/obj/plugins/$$kind.o | grep -q 'sekreto::sha256\|sekreto::hmacsha256'; then \
	    echo "sekreto: $$kind needs a digest - only aws signs" >&2; exit 1; \
	  fi; \
	done
	@echo "lean: only aws needs a digest"

# The suite links the archives `build` just made, so the library is compiled
# once however many times the tests are run.
test: build check-core lean build/sekreto-tlstest build/sekreto-plugintest
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/cpp build
	$(CXX) $(CXXFLAGS) -Isrc -Iplugins -I$(PLUGIN)/cpp/src -I$(OMNI)/cpp/src \
	  -o build/sekreto-test test/SekretoTest.cpp \
	  build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a $(LIBS)
	./build/sekreto-test
	./build/sekreto-plugintest
	./build/sekreto-tlstest

clean:
	rm -rf build

inspect:
	@$(CXX) --version 2>&1 | head -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
