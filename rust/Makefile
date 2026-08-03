.PHONY: build test clean inspect vendor

# voxgig/omni is a sibling checkout, not a published crate, and it may sit
# anywhere. Link it under vendor/ so Cargo.toml can name a fixed path that
# works on any machine.
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

build: vendor
	cargo build --release

test: vendor
	cargo test

clean:
	cargo clean
	rm -rf vendor

inspect:
	@cargo --version
	@echo "omni: $(OMNI)"
