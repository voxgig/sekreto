.PHONY: build deps test seam clean inspect check-core check-tls tlscheck

# SERIAL, because `build` recurses and three phony targets depend on it:
# under -j, `check-core` and `check-tls` would each start their own `build`
# alongside the first, and two `ar` runs writing one archive is exactly the
# stale-member problem the rm -f below exists to avoid. The whole build is
# a few seconds; there is nothing to win here.
.NOTPARALLEL:

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# voxgig/plugin is THE dependency: the library is built on its host, so the
# library needs it and not only the tests. C has no package manager at all,
# so it is found the way omni is found - $PLUGIN_HOME, then the usual
# places, then the ../.plugin that `deps` clones when there is nothing to
# find - and compiled into build/ here. Nothing is written inside the
# checkout, and the library itself searches no path.
#
# Recursively expanded (=, not :=), so a reference AFTER `deps` has run
# sees the clone it made.
PLUGIN_REPO ?= https://github.com/voxgig/plugin
PLUGIN_REF ?= main
PLUGIN = $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/c/src/host.h" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -O2

# voxgig/plugin is compiled with ITS OWN flags, because it is a dependency
# and a dependency is built the way its own build builds it. It is C11 and
# -O1: at -O2 gcc's -Wclobbered fires on three of its setjmp frames, and
# turning a warning off - or turning -Werror off - to make someone else's
# source compile under our flags would weaken this port's gate to suit a
# checkout it does not own.
PLUGINCFLAGS ?= -std=c11 -Wall -Wextra -Werror -O1 -g

INCLUDES = -I src -I plugins -I $(PLUGIN)/c/src

# The one dependency of the PLUGINS, and it is the TLS binding: -lssl for
# the protocol, -lcrypto because libssl needs it. The audit surface is the
# distribution's OpenSSL - this port pins no version, vendors no source and
# carries no patch.
#
# THE CORE LINKS NEITHER. A consumer whose chain is `env` and `dotenv`
# needs libc and nothing else; only a binary that links a plugin needs
# these, which is what the split is for.
LDLIBS = -lssl -lcrypto

# THREE ARCHIVES, AND THE MIDDLE ONE IS THE BOUNDARY.
#
#   libvoxgigplugin.a  <checkout>/c/src/*.c  the host library
#   libsekreto.a       src/*.c               the core: the chain, the cache,
#                                            redaction, checkaddr and the
#                                            four built-in kinds
#   libsekretoplugins.a plugins/*.c          the ten kinds that open a
#                                            socket, sign a request or spawn
#                                            a process, and the transport,
#                                            TLS, digest and clock under them
#
# C has no module system, so the boundary is made out of translation units,
# archives and the link line. Nothing under src/ includes a header under
# plugins/ and nothing under src/ names a symbol defined there, so the core
# archive records no undefined symbol from either - `make check-core` reads
# `nm -u` on the archive itself and says so, with a control so that a read
# which parses nothing cannot pass by finding nothing.
CORESRC = src/util.c src/json.c src/sekreto.c src/providers.c
COREOBJ = $(CORESRC:src/%.c=build/obj/%.o)

PLUGINSRC = plugins/encode.c plugins/sha256.c plugins/sigv4.c plugins/clock.c \
            plugins/httpjson.c plugins/tls.c plugins/proc.c \
            plugins/hashicorp.c plugins/boru.c plugins/aws.c \
            plugins/gcpsecrets.c plugins/azuresecrets.c plugins/onepassword.c \
            plugins/doppler.c plugins/infisical.c plugins/secretspec.c \
            plugins/all.c
PLUGINOBJ = $(PLUGINSRC:plugins/%.c=build/pobj/%.o)

VOXGIGSRC = $(wildcard $(PLUGIN)/c/src/*.c)
VOXGIGOBJ = $(VOXGIGSRC:$(PLUGIN)/c/src/%.c=build/vobj/%.o)

# Plugins first, then the core, then the host library: a static archive is
# searched once, in order, and each layer needs the one after it.
LIBS = build/libsekretoplugins.a build/libsekreto.a build/libvoxgigplugin.a

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

# `deps` MAY CLONE THE CHECKOUT, so the objects built out of it cannot be
# prerequisites of the same make invocation that runs it: GNU make expands
# a prerequisite list when it reads the rule, and on a machine with no
# plugin yet $(PLUGIN) is empty then - so $(VOXGIGOBJ) is empty, and the
# host archive is quietly built out of nothing. Measured, not theorised:
# the archive came out with no members and the link failed on every symbol
# voxgig/plugin defines. The sub-make re-reads the makefile after `deps`
# has run, when $(PLUGIN) answers, and keeps per-file rebuilds.
build: deps
	@$(MAKE) --no-print-directory build/sekreto-cli

build/obj/%.o: src/%.c src/sekreto.h src/internal.h
	@mkdir -p build/obj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/pobj/%.o: plugins/%.c plugins/sekretoplugins.h plugins/support.h src/sekreto.h src/internal.h
	@mkdir -p build/pobj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/vobj/%.o: $(PLUGIN)/c/src/%.c
	@mkdir -p build/vobj
	$(CC) $(PLUGINCFLAGS) -I $(PLUGIN)/c/src -c $< -o $@

# `ar r` APPENDS to an archive it finds rather than replacing it, so an
# object that has moved out of a layer stays in that layer's archive - and a
# stale member is exactly what would make `nm` report a boundary that is not
# there, or invent a need that was removed. Every archive is deleted first,
# so the proof is always taken from a cold one.
build/libsekreto.a: $(COREOBJ)
	@rm -f $@
	ar rcs $@ $(COREOBJ)

build/libsekretoplugins.a: $(PLUGINOBJ)
	@rm -f $@
	ar rcs $@ $(PLUGINOBJ)

build/libvoxgigplugin.a: $(VOXGIGOBJ)
	@rm -f $@
	ar rcs $@ $(VOXGIGOBJ)

build/sekreto-cli: cli/cli.c $(LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ cli/cli.c $(LIBS) $(LDLIBS)

# THE CORE REACHES NO PLUGIN, read off the artifact rather than asserted.
#
# The whole check is in test/checkcore.sh, because it is more than a grep:
# the authoritative half is `nm -u` on the core archive, matched against
# EXACT undefined symbol names, with a control that fails the check if the
# read produced nothing. A substring match would be worse than useless -
# `connect` matches `disconnect`, and a grep of source for library names
# cannot see `socket()`, which needs no header in C at all.
check-core: build
	@SEKRETO_CC="$(CC)" SEKRETO_CFLAGS="$(CFLAGS) $(INCLUDES)" SEKRETO_LDLIBS="$(LDLIBS)" \
	  ./test/checkcore.sh

# OpenSSL is named in exactly one translation unit. A future edit that
# reached for SSL_* or an OpenSSL digest from anywhere else - which is how
# the hand-rolled crypto would quietly be replaced by libcrypto's - fails
# here rather than in review. The core is checked as well as the plugins,
# where it can only ever come out empty, because an archive that grew an
# OpenSSL edge is exactly what this is for.
check-tls: build
	@stray=$$(nm -o --undefined-only build/libsekretoplugins.a build/libsekreto.a \
	  | grep -E ' (SSL_|OPENSSL_|X509_|ERR_|EVP_|HMAC|d2i_)' \
	  | grep -v ':tls\.o:' || true); \
	if [ -n "$$stray" ]; then \
	  echo "sekreto: OpenSSL reached from outside plugins/tls.c:" >&2; \
	  echo "$$stray" >&2; \
	  exit 1; \
	fi; \
	echo "check-tls: OpenSSL confined to plugins/tls.c"

# The suite compiles against the archives `build` just made, so the library
# is compiled once however many times the tests are run. omni appears here
# and nowhere else: no shipped source file names it, which is what the
# repository's isolation guard checks.
#
# The conformance suite links the plugins because it hands every plugin to
# every chain it builds - which is also why it can never see a consumer
# that passes the wrong list. That is what `seam` is for.
test: build check-core check-tls
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/c build
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -I $(OMNI)/c/src -o build/sekretotest \
	  test/sekretotest.c $(OMNI)/c/src/json.c $(OMNI)/c/src/util.c $(OMNI)/c/src/runner.c \
	  $(LIBS) $(LDLIBS) -lm
	./build/sekretotest $(GROUP)
	$(MAKE) seam

# The plugin seam, from both sides: what the conformance suite cannot see.
seam: build
	$(CC) $(CFLAGS) $(INCLUDES) -o build/sekretoseam test/plugintest.c $(LIBS) $(LDLIBS)
	SEKRETO_CC="$(CC)" SEKRETO_CFLAGS="$(CFLAGS) $(INCLUDES)" ./build/sekretoseam $(CASE)

# The TLS gate. `make test` runs spec/sekreto.json and NO CASE IN THAT
# SPEC OPENS A SOCKET, so a port with no verification - or no networking
# at all - passes it. This is the one that fails: it stands up a real TLS
# server behind a private CA and proves the chain check, the HOSTNAME
# check (both the DNS-name and the IP-literal path), SNI in both
# directions, and that SEKRETO_CA_BUNDLE adds roots without replacing any.
tlscheck: build
	SEKRETO_CC="$(CC)" SEKRETO_CFLAGS="$(CFLAGS) $(INCLUDES)" ./test/tlscheck.sh $(PORT)

clean:
	rm -rf build

inspect:
	@$(CC) --version | head -1
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
