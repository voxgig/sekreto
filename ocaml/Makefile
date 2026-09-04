.PHONY: build test tlscheck clean inspect

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

# In dependency order: OCaml compiles a module before anything that uses it.
SRC = src/json.ml src/crypto.ml src/sekreto.ml src/sigv4.ml src/tls.ml \
      src/http.ml src/providers.ml

# The one third-party edge in the whole port, and it is TRANSPORT ONLY:
# libssl, and the libcrypto beneath it. The distribution's OpenSSL is the
# audit surface. JSON, HTTP/1.1 framing, base64, SHA-256 and HMAC are all
# in-tree; see the note at the top of src/tls_stubs.c.
TLSLIBS = -cclib -lssl -cclib -lcrypto

# No dune, no ocamlfind, no opam: ocamlopt is driven directly, which is what
# the sibling voxgig/plugin OCaml port does and what keeps a consumer of
# this library free of a package manager.
#
# Sources are staged into build/ before compiling, so every .cmi, .cmx and
# .o lands under build/ and the source tree stays clean.
STAGE = build/stage
LIB = build/sekreto.cmxa

build: build/sekreto-cli

build/tls_stubs.o: src/tls_stubs.c
	mkdir -p build
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -I$(OCAMLLIB) -c src/tls_stubs.c -o $@

$(LIB): $(SRC) build/tls_stubs.o
	mkdir -p $(STAGE)
	cp $(SRC) $(STAGE)/
	$(OCAMLOPT) -a -I $(STAGE) -o $(LIB) $(addprefix $(STAGE)/,$(notdir $(SRC)))

# The library and the CLI depend on nothing but the OCaml distribution and
# the TLS binding. The artifact is one native binary, because test/checks.sh
# runs it from an empty directory with a wiped environment.
build/sekreto-cli: $(LIB) cli/cli.ml
	cp cli/cli.ml $(STAGE)/
	$(OCAMLOPT) -I $(STAGE) -o $@ unix.cmxa $(LIB) $(STAGE)/cli.ml \
	  build/tls_stubs.o $(TLSLIBS)

build/sekretotest: $(LIB) test/sekreto_test.ml
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/ocaml build
	cp $(OMNI)/ocaml/src/omni.ml test/sekreto_test.ml $(STAGE)/
	$(OCAMLOPT) -I $(STAGE) -o $@ unix.cmxa $(STAGE)/omni.ml $(LIB) \
	  $(STAGE)/sekreto_test.ml build/tls_stubs.o $(TLSLIBS)

build/behaviour: $(LIB) test/behaviour.ml
	cp test/behaviour.ml $(STAGE)/
	$(OCAMLOPT) -I $(STAGE) -o $@ unix.cmxa $(LIB) $(STAGE)/behaviour.ml \
	  build/tls_stubs.o $(TLSLIBS)

build/tlsprobe: $(LIB) test/tlsprobe.ml
	cp test/tlsprobe.ml $(STAGE)/
	$(OCAMLOPT) -I $(STAGE) -o $@ unix.cmxa $(LIB) $(STAGE)/tlsprobe.ml \
	  build/tls_stubs.o $(TLSLIBS)

# Three suites, because the corpus alone cannot see two of the things this
# port has to get right.
#
#   sekretotest  the 14 shared corpus groups, through voxgig/omni. omni is
#                named here and nowhere else in the port.
#   behaviour    everything the corpus never reaches: the whole checkaddr
#                table, strict base64, a miss that is not a failure on a
#                real file, the cache and redaction lifecycle.
#   tlsproof.sh  the TLS binding, against a real handshake. No case in the
#                corpus opens a socket, so a port with no transport at all
#                could pass the first two.
test: build build/sekretotest build/behaviour build/tlsprobe
	./build/sekretotest $(GROUP)
	./build/behaviour
	./test/tlsproof.sh

# The TLS proof on its own.
tlscheck: build/tlsprobe
	./test/tlsproof.sh

clean:
	rm -rf build

inspect:
	@$(OCAMLOPT) -version | sed 's/^/ocamlopt /'
	@echo "omni: $(OMNI)"
