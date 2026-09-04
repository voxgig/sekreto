.PHONY: build test clean inspect check-tls

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -O2

# The one dependency, and it is the TLS binding: -lssl for the protocol,
# -lcrypto because libssl needs it. The audit surface is the
# distribution's OpenSSL - this port pins no version, vendors no source
# and carries no patch. Nothing else is linked but libc, which
# `ldd build/sekreto-cli` shows.
LDLIBS = -lssl -lcrypto

SRC = src/util.c src/json.c src/crypto.c src/sigv4.c src/sekreto.c \
      src/proc.c src/http.c src/tls.c src/providers.c
OBJ = $(SRC:src/%.c=build/obj/%.o)

build: build/sekreto-cli

build/obj/%.o: src/%.c src/sekreto.h src/internal.h
	@mkdir -p build/obj
	$(CC) $(CFLAGS) -c $< -o $@

build/libsekreto.a: $(OBJ)
	ar rcs $@ $(OBJ)

build/sekreto-cli: cli/cli.c build/libsekreto.a
	$(CC) $(CFLAGS) -o $@ cli/cli.c build/libsekreto.a $(LDLIBS)

# The suite compiles against the archive `build` just made, so the library
# is compiled once however many times the tests are run. omni appears here
# and nowhere else: no shipped source file names it, which is what the
# repository's isolation guard checks.
test: build
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/c build
	@mkdir -p build
	$(CC) $(CFLAGS) -I src -I $(OMNI)/c/src -o build/sekretotest \
	  test/sekretotest.c $(OMNI)/c/src/json.c $(OMNI)/c/src/util.c $(OMNI)/c/src/runner.c \
	  build/libsekreto.a $(LDLIBS) -lm
	./build/sekretotest $(GROUP)

# OpenSSL is named in exactly one translation unit. A future edit that
# reached for SSL_* or an OpenSSL digest from anywhere else - which is how
# the hand-rolled crypto would quietly be replaced by libcrypto's - fails
# here rather than in review.
check-tls: build/libsekreto.a
	@stray=$$(nm -o --undefined-only build/libsekreto.a \
	  | grep -E ' (SSL_|OPENSSL_|X509_|ERR_|EVP_|HMAC|d2i_)' \
	  | grep -v 'tls\.o:' || true); \
	if [ -n "$$stray" ]; then \
	  echo "sekreto: OpenSSL reached from outside tls.c:" >&2; \
	  echo "$$stray" >&2; \
	  exit 1; \
	fi; \
	echo "check-tls: OpenSSL confined to src/tls.c"

clean:
	rm -rf build

inspect:
	@$(CC) --version | head -1
	@echo "omni: $(OMNI)"
