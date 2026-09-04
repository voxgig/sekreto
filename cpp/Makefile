.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published artifact, and it may
# sit anywhere. Find it, and build it if it has not been built yet.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
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
LIBS := -lssl -lcrypto

SRC := $(wildcard src/*.cpp)
OBJ := $(patsubst src/%.cpp,build/obj/%.o,$(SRC))

# The library and the CLI depend on nothing but the C++ standard library
# and OpenSSL. Only the conformance suite needs omni, and only on its own
# include path - so the shipped artifact carries no trace of it.
build: build/sekreto-cli

build/obj/%.o: src/%.cpp
	@mkdir -p build/obj
	$(CXX) $(CXXFLAGS) -c -o $@ $<

build/libsekreto.a: $(OBJ)
	ar rcs $@ $(OBJ)

build/sekreto-cli: cli/Cli.cpp build/libsekreto.a
	$(CXX) $(CXXFLAGS) -Isrc -o $@ cli/Cli.cpp build/libsekreto.a $(LIBS)

# The TLS obligations, proved in-tree. Neither `make test`'s corpus nor
# `make integration` opens an https socket, so without this a build with
# its certificate checking switched off would pass both.
build/sekreto-tlstest: test/TlsTest.cpp build/libsekreto.a
	$(CXX) $(CXXFLAGS) -Isrc -pthread -o $@ test/TlsTest.cpp build/libsekreto.a $(LIBS)

# The suite links the archive `build` just made, so the library is compiled
# once however many times the tests are run.
test: build build/sekreto-tlstest
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	$(MAKE) -C $(OMNI)/cpp build
	$(CXX) $(CXXFLAGS) -Isrc -I$(OMNI)/cpp/src -o build/sekreto-test \
	  test/SekretoTest.cpp build/libsekreto.a $(LIBS)
	./build/sekreto-test
	./build/sekreto-tlstest

clean:
	rm -rf build

inspect:
	@$(CXX) --version 2>&1 | head -1
	@echo "omni: $(OMNI)"
