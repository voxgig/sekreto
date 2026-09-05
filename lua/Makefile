.PHONY: build test conformance plugins tlscheck deps clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is a runtime dependency of the library, required by the
# plain module name `plugin` so that whatever is already on the caller's
# package.path wins. There is no rock, so a checkout finds the port the
# way every port finds omni: $PLUGIN_HOME, then a sibling checkout, then
# the usual places. Failing all of those, `deps` fetches a shallow clone
# into ../.plugin (gitignored), which is what `npm install` and
# `go mod download` do for the other ports: the dependency comes from the
# network when it is not already on disk. CI therefore needs no checkout
# step for it.
#
# The library itself searches no path - test/pluginhome.lua does, for the
# tests and the CLI, and only when `require('plugin')` fails.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/lua/src/plugin.lua" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

LUA ?= lua5.4
LUAC ?= luac5.4
CC ?= cc

# The transport binding, and the whole of it. Lua 5.4 has no sockets and
# no TLS, so this one C program opens the socket, speaks TLS through the
# platform's OpenSSL, and runs child processes with a real argv array.
#
# `-lssl -lcrypto`, and the distribution's OpenSSL is the audit surface.
# Nothing else is linked beyond libc, and nothing else is depended on at
# all: the JSON, the HTTP/1.1 framing, SHA-256, HMAC-SHA256, hex and
# base64 are Lua in src/.
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror
LDLIBS ?= -lssl -lcrypto

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "plugin: $(PLUGIN)"; \
	else \
	  echo "plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# The syntax check is NOT a no-op and is NOT part of the compile rule: a
# syntax error in a plugin file no test happens to require would
# otherwise ship, and after the core/plugin split most files are in
# exactly that position - so it runs every time, not only when the C
# source changed.
build: deps build/sekreto-net
	@for f in $$(find src cli test -name '*.lua'); do \
	  $(LUAC) -p "$$f" >/dev/null || exit 1; \
	done
	@PLUGIN_HOME=$(PLUGIN) $(LUA) -e \
	  "package.path='src/?.lua;test/?.lua;'..package.path; \
	   require('pluginhome').pluginpath(); require('sekreto')" \
	  && echo "lua: $$(find src cli test -name '*.lua' | wc -l) files parse, src/ loads"

build/sekreto-net: native/sekretonet.c
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ native/sekretonet.c $(LDLIBS)

# Two suites, because one of them cannot see the thing this port most
# needs proved. No corpus case opens a socket, so `conformance` would pass
# on a build with no transport at all; `tlscheck` is what says the TLS
# binding verifies rather than merely connects.
test: conformance plugins tlscheck

# The conformance suite needs omni; the library and the CLI do not, and
# omni is only ever on the test's own package.path.
conformance: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/lua build
	OMNI_HOME=$(OMNI) PLUGIN_HOME=$(PLUGIN) $(LUA) test/sekreto_test.lua $(GROUP)

# The plugin seam, from both sides. The conformance suite hands every
# plugin to every chain it builds, so it can never see a consumer that
# passes the wrong set, a kind that is refused, or a core that reaches a
# plugin. These do.
plugins: build
	PLUGIN_HOME=$(PLUGIN) $(LUA) test/test_plugins.lua $(SEAM)

# The TLS obligations, against `openssl s_server`: the chain, the
# hostname (a different call for an address than for a name), and
# SEKRETO_CA_BUNDLE. Nothing else in either shared suite reaches a
# handshake.
tlscheck: build
	@command -v openssl >/dev/null 2>&1 \
	  || { echo "skip - tlscheck: no openssl s_server on this machine"; exit 0; }
	@LUA=$(LUA) sh test/tlscheck.sh

clean:
	rm -rf build

inspect:
	@$(LUA) -v 2>&1 | tail -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
