.PHONY: build test conformance tlscheck clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

LUA ?= lua5.4
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

build: build/sekreto-net

build/sekreto-net: native/sekretonet.c
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ native/sekretonet.c $(LDLIBS)
	@$(LUA) -e "package.path='src/?.lua;'..package.path; require('sekreto')" \
	  && echo "lua: src/ loads"

# Two suites, because one of them cannot see the thing this port most
# needs proved. No corpus case opens a socket, so `conformance` would pass
# on a build with no transport at all; `tlscheck` is what says the TLS
# binding verifies rather than merely connects.
test: conformance tlscheck

# The conformance suite needs omni; the library and the CLI do not, and
# omni is only ever on the test's own package.path.
conformance: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/lua build
	OMNI_HOME=$(OMNI) $(LUA) test/sekreto_test.lua $(GROUP)

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
