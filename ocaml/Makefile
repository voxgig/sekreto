.PHONY: build test deps tlscheck check-core coreproof clean inspect

# voxgig/plugin is a RUNTIME dependency of this port - the core is built on
# it (AGENTS.md rule 3, rule 4). It has no opam release, and this port takes
# no package manager, so the Makefile finds a checkout the way every port
# finds omni and compiles its modules into build/plugin.cmxa. `deps` fetches
# a shallow clone when there is none, which is what `npm install` and
# `go mod download` do for the ports whose registries carry it.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/ocaml/src/host.ml" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

OCAMLOPT ?= ocamlopt
CC ?= cc

# Where the OCaml runtime headers live, for the TLS stubs.
OCAMLLIB := $(shell $(OCAMLOPT) -where)

# THE MODULE LISTS ARE THE DEPENDENCY GRAPH, WRITTEN DOWN. OCaml compiles a
# module before anything that uses it and has no separate link step that
# would sort it out, so each list below is in order.

# voxgig/plugin's own modules, staged and compiled here because the port it
# comes from ships an executable rather than a library archive.
PLUGINSRC = value.ml types.ml ref.ml version.ml capability.ml resolve.ml \
            env.ml config.ml graph.ml order.ml export.ml depend.ml point.ml \
            defs.ml catalog.ml host.ml

# THE CORE. Four provider kinds, the chain, and nothing that opens a socket,
# signs a request or spawns a process.
CORE = src/json.ml src/secret.ml src/provider.ml src/sekreto.ml

# THE PLUGINS. Ten provider kinds, the transport they share, and the TLS
# binding under it.
PLUGINS = plugins/crypto.ml plugins/sigv4.ml plugins/tls.ml plugins/http.ml \
          plugins/httpjson.ml plugins/runcmd.ml plugins/hashicorp.ml \
          plugins/boru.ml plugins/aws.ml plugins/gcpsecrets.ml \
          plugins/azuresecrets.ml plugins/onepassword.ml plugins/doppler.ml \
          plugins/infisical.ml plugins/secretspec.ml plugins/allplugins.ml

# The one third-party edge in the whole port, and it is TRANSPORT ONLY:
# libssl, and the libcrypto beneath it. The distribution's OpenSSL is the
# audit surface. JSON, HTTP/1.1 framing, base64, SHA-256 and HMAC are all
# in-tree; see the note at the top of plugins/tls_stubs.c.
#
# ONLY A PROGRAM THAT LINKS THE PLUGIN ARCHIVE NEEDS IT. build/coreonly is
# built with neither the stubs nor these flags, and that is the split as a
# command rather than as a claim.
TLSLIBS = -cclib -lssl -cclib -lcrypto

# No dune, no ocamlfind, no opam: ocamlopt is driven directly, which is what
# the sibling voxgig/plugin OCaml port does and what keeps a consumer of
# this library free of a package manager.
#
# TWO STAGE DIRECTORIES, AND THAT IS THE BOUNDARY. Sources are copied into
# build/ before compiling, so every .cmi, .cmx and .o lands under build/ and
# the source tree stays clean - but the core is compiled with -I build/core
# ALONE, a directory holding no plugin interface at all. A core module that
# named a plugin would not compile, the way go's core cannot import a
# package it does not import.
CORESTAGE = build/core
PLUGINSTAGE = build/plugins
PLUGINLIB = build/plugin.cmxa
LIB = build/sekreto.cmxa
PLUGINSLIB = build/sekretoplugins.cmxa

build: build/sekreto-cli

deps:
	@set -e; \
	dir="$(PLUGIN)"; \
	if [ -z "$$dir" ]; then \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	  dir="$$(cd ../.plugin && pwd)"; \
	fi; \
	echo "voxgig/plugin: $$dir"

$(PLUGINLIB): $(addprefix $(PLUGIN)/ocaml/src/,$(PLUGINSRC))
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - set PLUGIN_HOME or run make deps" >&2; exit 1; }
	mkdir -p $(CORESTAGE)
	cp $(addprefix $(PLUGIN)/ocaml/src/,$(PLUGINSRC)) $(CORESTAGE)/
	$(OCAMLOPT) -a -I $(CORESTAGE) -o $(PLUGINLIB) $(addprefix $(CORESTAGE)/,$(PLUGINSRC))

$(LIB): $(PLUGINLIB) $(CORE)
	cp $(CORE) $(CORESTAGE)/
	$(OCAMLOPT) -a -I $(CORESTAGE) -o $(LIB) $(addprefix $(CORESTAGE)/,$(notdir $(CORE)))

build/tls_stubs.o: plugins/tls_stubs.c
	mkdir -p build
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -I$(OCAMLLIB) -c plugins/tls_stubs.c -o $@

$(PLUGINSLIB): $(LIB) $(PLUGINS) build/tls_stubs.o
	mkdir -p $(PLUGINSTAGE)
	cp $(PLUGINS) $(PLUGINSTAGE)/
	$(OCAMLOPT) -a -I $(CORESTAGE) -I $(PLUGINSTAGE) -o $(PLUGINSLIB) \
	  $(addprefix $(PLUGINSTAGE)/,$(notdir $(PLUGINS)))

# Everything the CLI and the suites link, in order.
LINK = unix.cmxa $(PLUGINLIB) $(LIB) $(PLUGINSLIB)
STAGES = -I $(CORESTAGE) -I $(PLUGINSTAGE)

# The library and the CLI depend on nothing but the OCaml distribution, the
# TLS binding and voxgig/plugin. The artifact is one native binary, because
# test/checks.sh runs it from an empty directory with a wiped environment.
build/sekreto-cli: $(PLUGINSLIB) cli/cli.ml
	cp cli/cli.ml $(PLUGINSTAGE)/
	$(OCAMLOPT) $(STAGES) -o $@ $(LINK) $(PLUGINSTAGE)/cli.ml \
	  build/tls_stubs.o $(TLSLIBS)

# A CONSUMER WHOSE CHAIN IS BUILT-INS ONLY, BUILT AS ONE. It links the core
# and voxgig/plugin and NOTHING ELSE: no plugin archive, no TLS stubs, no
# -lssl. If it links, the core reaches no plugin; test/plugins.ml then reads
# the artifact back and says so by symbol name.
build/coreonly: $(LIB) test/coreonly.ml
	cp test/coreonly.ml $(CORESTAGE)/
	$(OCAMLOPT) -I $(CORESTAGE) -o $@ unix.cmxa $(PLUGINLIB) $(LIB) \
	  $(CORESTAGE)/coreonly.ml

build/sekretotest: $(PLUGINSLIB) test/sekreto_test.ml
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/ocaml build
	cp $(OMNI)/ocaml/src/omni.ml test/sekreto_test.ml $(PLUGINSTAGE)/
	$(OCAMLOPT) $(STAGES) -o $@ unix.cmxa $(PLUGINSTAGE)/omni.ml $(PLUGINLIB) \
	  $(LIB) $(PLUGINSLIB) $(PLUGINSTAGE)/sekreto_test.ml build/tls_stubs.o $(TLSLIBS)

build/behaviour: $(PLUGINSLIB) test/behaviour.ml
	cp test/behaviour.ml $(PLUGINSTAGE)/
	$(OCAMLOPT) $(STAGES) -o $@ $(LINK) $(PLUGINSTAGE)/behaviour.ml \
	  build/tls_stubs.o $(TLSLIBS)

build/plugintest: $(PLUGINSLIB) build/coreonly build/sekreto-cli test/plugins.ml
	cp test/plugins.ml $(PLUGINSTAGE)/
	$(OCAMLOPT) $(STAGES) -o $@ $(LINK) $(PLUGINSTAGE)/plugins.ml \
	  build/tls_stubs.o $(TLSLIBS)

build/tlsprobe: $(PLUGINSLIB) test/tlsprobe.ml
	cp test/tlsprobe.ml $(PLUGINSTAGE)/
	$(OCAMLOPT) $(STAGES) -o $@ $(LINK) $(PLUGINSTAGE)/tlsprobe.ml \
	  build/tls_stubs.o $(TLSLIBS)

# Four suites, because the corpus alone cannot see three of the things this
# port has to get right.
#
#   sekretotest  the 14 shared corpus groups, through voxgig/omni. omni is
#                named here and nowhere else in the port.
#   behaviour    everything the corpus never reaches: the whole checkaddr
#                table, strict base64, a miss that is not a failure on a
#                real file, the cache and redaction lifecycle.
#   plugintest   the plugin seam. The corpus hands every plugin to every
#                chain it builds, so it can never see a kind that was not
#                passed in, a consumer whose list is wrong, or a core that
#                reaches a plugin. This suite reads the built artifacts.
#   tlsproof.sh  the TLS binding, against a real handshake. No case in the
#                corpus opens a socket, so a port with no transport at all
#                could pass the first two.
test: check-core build build/sekretotest build/behaviour build/plugintest build/tlsprobe
	./build/sekretotest $(GROUP)
	./build/behaviour
	./build/plugintest
	./test/tlsproof.sh

# WHAT NEITHER THE COMPILER NOR THE SYMBOL READ CAN SEE.
#
# `-I $(CORESTAGE)` stops a core module NAMING a plugin, and test/plugins.ml
# reads the built artifacts back unit by unit - but both answer by NAME. A
# core module called something else that opens a socket, spawns a child or
# hashes a secret passes both: it compiles, it links, and its unit name is
# in neither list. An audit added `src/wire.ml` calling `Unix.socket`,
# reached it from the facade, and the whole suite stayed green.
#
# An undefined-symbol read has no teeth here, which is why this is a source
# grep rather than cpp's `nm -u`: ocamlopt links the unix stubs wholesale,
# so build/coreonly already leaves `socket`, `fork` and `execve` undefined
# whatever the core does. zig, c and cpp keep the same grep for the same
# reason.
check-core:
	@if grep -n -E 'Unix\.(socket|connect|bind|listen|accept|getaddrinfo|gethostbyname|getprotoby|inet_addr_|ADDR_INET|ADDR_UNIX|PF_INET|SOCK_|create_process|open_process|establish_server|execv|execve|execvp|fork|system|pipe)|Sys\.command|Thread\.|Dynlink|Digest\.|\b(sha256|hmac|Sha256|Hmac)\b|SSL_' src/*.ml; then \
	  echo "sekreto: the core reaches for something that belongs in a plugin" >&2; exit 1; \
	else echo "core: opens no socket, spawns no process, hashes nothing"; fi

# The TLS proof on its own.
tlscheck: build/tlsprobe
	./test/tlsproof.sh

# The split, as a command: what the core-only binary links, and what the
# CLI links beside it.
coreproof: build/coreonly build/sekreto-cli build/plugintest
	@echo "== the compilation units in build/coreonly"
	@nm build/coreonly | sed -n 's/.* T caml\([A-Za-z0-9_]*\)__entry$$/\1/p' | sort
	@echo "== what each binary links beside the C runtime"
	@ldd build/coreonly | sed 's/^/  coreonly    /'
	@ldd build/sekreto-cli | sed 's/^/  sekreto-cli /'
	@./build/plugintest

clean:
	rm -rf build

inspect:
	@$(OCAMLOPT) -version | sed 's/^/ocamlopt /'
	@echo "plugin: $(PLUGIN)"
	@echo "omni: $(OMNI)"
