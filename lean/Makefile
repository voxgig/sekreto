# The lean port.
#
# No lake, and no lakefile. Lake resolves a package's whole dependency
# graph before it compiles anything, and this port has to do two things
# lake makes awkward at once: link an in-tree C binding (`ffi/`) that no
# `lakefile.toml` target shape covers, and put voxgig/omni in front of
# the CONFORMANCE SUITE ONLY. `lean` and `leanc` are the compiler and the
# linker; driving them here keeps the library's build inputs to `src/`
# and the toolchain, which is what register 4.13 asks for. The swift port
# ships no `Package.swift` for the same reason.
#
# elan installs to ~/.elan/bin; prepend it so a stock elan install works.
# Named separately as well, because GNU make's `$(shell ...)` does not
# see a PATH exported from inside the makefile.
ELANBIN := $(HOME)/.elan/bin
export PATH := $(ELANBIN):$(PATH)

.PHONY: build test clean inspect ffi

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

LEAN ?= lean
LEANC ?= leanc

B := build
LIB := $(B)/lib
IR := $(B)/ir

# In dependency order: `lean` compiles one module at a time and every
# import must already have an .olean on LEAN_PATH.
MODULES := Sekreto.Text Sekreto.Json Sekreto.Crypto Sekreto.Provider \
           Sekreto.Core Sekreto.Sigv4 Sekreto.Clock Sekreto.Addr \
           Sekreto.Curl Sekreto.Providers Sekreto

OBJS := $(patsubst %,$(IR)/%.o,$(MODULES))

# The TLS binding, and the platform clock. libcurl verifies the chain and
# the hostname itself; see ffi/sekreto_curl.c.
#
# AUDIT SURFACE: libcurl, PLUS WHICHEVER TLS BACKEND IT WAS BUILT
# AGAINST, which this port does not choose - libcurl may be linked to
# OpenSSL, GnuTLS, NSS or Schannel, and only the OpenSSL one honours
# CURLOPT_SSL_CTX_FUNCTION, which is how SEKRETO_CA_BUNDLE adds roots
# WITHOUT replacing the system store. `-lssl -lcrypto` is for that one
# call and nothing else: SHA-256 and HMAC-SHA256 are in-tree, in
# src/Sekreto/Crypto.lean, as the rule requires.
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

# One rule per module would need a hand-written dependency graph; the
# list above IS that graph, so the whole library is compiled in one pass.
$(LIB)/.stamp: $(wildcard src/*.lean src/Sekreto/*.lean)
	@mkdir -p $(LIB) $(IR)
	@for mod in $(MODULES); do \
	  path=$$(echo $$mod | tr . /); \
	  mkdir -p "$(LIB)/$$(dirname $$path)"; \
	  echo "  lean src/$$path.lean"; \
	  LEAN_PATH=$(CURDIR)/$(LIB) $(LEAN) --root=src \
	    -o $(LIB)/$$path.olean -i $(LIB)/$$path.ilean -c $(IR)/$$mod.c "src/$$path.lean" || exit 1; \
	  $(LEANC) -c -o $(IR)/$$mod.o $(IR)/$$mod.c || exit 1; \
	done
	@touch $@

$(B)/sekreto-cli: $(LIB)/.stamp $(FFIOBJS) cli/Cli.lean
	@mkdir -p $(LIB) $(IR)
	LEAN_PATH=$(CURDIR)/$(LIB) $(LEAN) --root=cli \
	  -o $(LIB)/Cli.olean -i $(LIB)/Cli.ilean -c $(IR)/Cli.c cli/Cli.lean
	$(LEANC) -c -o $(IR)/Cli.o $(IR)/Cli.c
	$(LEANC) -o $@ $(OBJS) $(FFIOBJS) $(IR)/Cli.o $(SYSLIB) $(FFILIBS)

# The suite compiles against the library `build` just made, so the
# library is compiled once however many times the tests are run.
#
# omni's own .olean files are stamped with the toolchain that wrote them
# and are refused by any other, so the runner is compiled HERE, from
# omni's source, with this port's pinned toolchain. It lands in
# build/omni, which nothing the library builds ever reaches.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/lean build
	@mkdir -p $(B)/omni
	LEAN_PATH=$(CURDIR)/$(B)/omni $(LEAN) --root=$(OMNI)/lean \
	  -o $(B)/omni/Omni.olean -i $(B)/omni/Omni.ilean -c $(B)/omni/Omni.c \
	  $(OMNI)/lean/Omni.lean
	$(LEANC) -c -o $(B)/omni/Omni.o $(B)/omni/Omni.c
	LEAN_PATH=$(CURDIR)/$(LIB):$(CURDIR)/$(B)/omni $(LEAN) --root=test \
	  -o $(B)/omni/SekretoTest.olean -i $(B)/omni/SekretoTest.ilean \
	  -c $(B)/omni/SekretoTest.c test/SekretoTest.lean
	$(LEANC) -c -o $(B)/omni/SekretoTest.o $(B)/omni/SekretoTest.c
	$(LEANC) -o $(B)/sekreto-test $(OBJS) $(FFIOBJS) \
	  $(B)/omni/Omni.o $(B)/omni/SekretoTest.o $(SYSLIB) $(FFILIBS)
	./$(B)/sekreto-test $(GROUP)

clean:
	rm -rf build

inspect:
	@$(LEAN) --version | head -1
	@echo "omni: $(OMNI)"
