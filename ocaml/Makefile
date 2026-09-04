.PHONY: build test clean inspect

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

# In dependency order: OCaml compiles a module before anything using it.
SRC = src/json.ml src/crypto.ml src/sekreto.ml src/sigv4.ml src/tls.ml \
      src/http.ml src/providers.ml

# The one third-party edge in the whole port, and it is transport only:
# libssl for TLS and the libcrypto beneath it. The distribution's OpenSSL is
# the audit surface. JSON, HTTP/1.1 framing, base64, SHA-256 and HMAC are
# all in-tree - see src/tls_stubs.c.
TLSLIBS = -cclib -lssl -cclib -lcrypto

# No dune, no ocamlfind, no opam: ocamlopt is driven directly, which is what
# the sibling voxgig/plugin OCaml port does and what keeps a consumer of this
# library free of a package manager. Intermediate .cmi/.cmx/.o land beside
# their sources and are swept afterwards, as omni's own OCaml port does.
build: build/tls_stubs.o
	$(OCAMLOPT) -I src -I cli -o build/sekreto-cli \
	  unix.cmxa $(SRC) cli/cli.ml build/tls_stubs.o $(TLSLIBS)
	@rm -f src/*.cmi src/*.cmx src/*.o cli/*.cmi cli/*.cmx cli/*.o

build/tls_stubs.o: src/tls_stubs.c
	mkdir -p build
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -I$(OCAMLLIB) -c src/tls_stubs.c -o $@

# The suite compiles the library again beside omni's runner, because
# `build` sweeps its own intermediates. omni is named here and nowhere else
# in the port - never by the library, never by the CLI.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/ocaml build
	cp $(OMNI)/ocaml/src/omni.ml build/omni.ml
	$(OCAMLOPT) -I src -I test -I build -o build/sekretotest \
	  unix.cmxa build/omni.ml $(SRC) test/sekreto_test.ml build/tls_stubs.o $(TLSLIBS)
	@rm -f src/*.cmi src/*.cmx src/*.o test/*.cmi test/*.cmx test/*.o
	./build/sekretotest $(GROUP)

clean:
	rm -rf build
	rm -f src/*.cmi src/*.cmx src/*.o cli/*.cmi cli/*.cmx cli/*.o \
	      test/*.cmi test/*.cmx test/*.o

inspect:
	@$(OCAMLOPT) -version | sed 's/^/ocamlopt /'
	@echo "omni: $(OMNI)"
