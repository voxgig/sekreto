.PHONY: build build-clean test clean inspect vendor

# voxgig/omni is a sibling checkout, not a published crate, and it may sit
# anywhere. Link it under vendor/ so corpus/Cargo.toml can name a fixed path
# that works on any machine - Cargo path dependencies are literal and cannot
# read $OMNI_HOME.
#
# The conformance suite is a separate package (`corpus/`) so that omni stays
# out of the library's manifest entirely: Cargo resolves dev-dependencies
# even for `cargo build`, so a dev-dependency here broke a checkout with no
# omni beside it. (Omni register 4.13; the shape voxgig/struct#97 set.)
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

vendor:
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	mkdir -p vendor
	ln -sfn $(OMNI)/rust vendor/omni

build:
	cargo build --release

# Register 4.13 proof: the library (every target of it - the CLI and any of
# its own tests included) must build with NO omni checkout and NO vendor
# link. This target deliberately does NOT depend on `vendor`; CI runs it
# before omni is fetched.
build-clean:
	cargo build --all-targets

test: vendor
	cargo test
	cd corpus && cargo test

clean:
	cargo clean
	cd corpus && cargo clean
	rm -rf vendor

inspect:
	@cargo --version
	@echo "omni: $(OMNI)"
