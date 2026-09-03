.PHONY: build build-clean test clean inspect

# voxgig/omni drives the shared spec. The conformance suite (`corpus/`)
# takes it as a git dependency pinned to omni's `rust/vX.Y.Z` release tag
# (omni DOCS.md 8.3), which Cargo fetches itself: no checkout, no vendor
# link, no OMNI_HOME.
#
# The suite is a separate package so that omni stays out of the library's
# manifest entirely: Cargo resolves dev-dependencies even for `cargo
# build`, so a dev-dependency here broke a checkout with no omni beside
# it. (Omni register 4.13; the shape voxgig/struct#97 set.)
#
# CARGO_NET_GIT_FETCH_WITH_CLI makes Cargo fetch through the git CLI, which
# honours the proxy and CA settings git itself has; Cargo's built-in
# fetcher does not read git's config, and on a machine behind a proxy it
# fails where `git clone` works. Harmless everywhere else.

build:
	cargo build --release

# Register 4.13 proof: the library (every target of it - the CLI and any of
# its own tests included) must build with NO omni anywhere. CI runs it
# before anything fetches omni.
build-clean:
	cargo build --all-targets

test:
	cargo test
	cd corpus && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test

clean:
	cargo clean
	cd corpus && cargo clean

inspect:
	@cargo --version
	@grep -o 'tag = "[^"]*"' corpus/Cargo.toml | sed 's/^/omni: /'
