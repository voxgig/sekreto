.PHONY: build build-clean test deps check-core clean inspect

# voxgig/plugin is a RUNTIME dependency of this port - the core is built on
# it (AGENTS.md rule 3, rule 4). It has no crates.io release, so Cargo takes
# it by path, and the path is a link this Makefile makes: `.plugin/rust`,
# gitignored, pointing at whichever checkout `deps` found. The manifest
# therefore names one stable path on every machine, and the search happens
# here rather than in the library, which searches nothing.
#
# The order is the one every port uses to find omni: $PLUGIN_HOME, then a
# sibling checkout, then the usual places - including the ../.plugin that
# `deps` fetches when nothing else is there, which is what `npm install`
# and `go mod download` do for the ports whose registries carry it. CI
# needs no checkout step because of this.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/rust/Cargo.toml" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

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

deps:
	@set -e; \
	dir="$(PLUGIN)"; \
	if [ -z "$$dir" ]; then \
	  echo "voxgig_plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	  dir="$$(cd ../.plugin && pwd)"; \
	fi; \
	mkdir -p .plugin; \
	ln -sfn "$$dir/rust" .plugin/rust; \
	echo "voxgig_plugin: $$dir"

# --workspace, and it has to be: the core is the workspace ROOT package, so
# a bare `cargo build` here builds the core alone and reports a green that
# compiled no plugin and no CLI.
build: deps
	cargo build --release --workspace

# Register 4.13 proof: the library (every target of it - the CLI and any of
# its own tests included) must build with NO omni anywhere. CI runs it
# before anything fetches omni.
build-clean: deps
	cargo build --all-targets --workspace

test: deps check-core
	cargo test --workspace
	cd corpus && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test

# THE SPLIT, AS A COMMAND. `cargo tree` on the core is the whole claim in
# one line: its dependency closure is voxgig/plugin and nothing else, so a
# consumer whose chain is built-ins only compiles no TLS, no HTTP client
# and no request signing. The source scan is the second half - a dependency can
# arrive without a manifest line - and tests/plugin.rs pins both so a
# regression fails the suite rather than only this target.
check-core: deps
	@echo "== the core's dependency closure"
	@cargo tree -p voxgig_sekreto --edges normal
	@awk '/^\[/ { inside = ($$0 == "[dependencies]"); next } \
	      !inside || /^#/ || /^[ \t]*$$/ { next } \
	      { split($$0, part, "="); gsub(/[ \t]/, "", part[1]); \
	        if ("voxgig_plugin" != part[1]) { \
	          print "sekreto: the core declares " part[1] " - it belongs in a plugin"; \
	          bad = 1 } } \
	      END { exit bad ? 1 : 0 }' Cargo.toml
	@echo "== the core's sources name no plugin and no platform"
	@awk '{ line = $$0; sub(/^[ \t]*/, "", line); \
	        if (line ~ /^\/\//) next; \
	        if (line ~ /rustls|webpki|TcpStream|std::net|std::process|voxgig_sekreto_/) { \
	          printf "%s:%d: %s\n", FILENAME, FNR, $$0; bad = 1 } } \
	      END { if (bad) { \
	          print "sekreto: the core reaches for something that belongs in a plugin"; \
	          exit 1 } }' src/*.rs
	@echo "ok"

clean:
	cargo clean
	cd corpus && cargo clean

inspect:
	@cargo --version
	@echo "plugin: $(PLUGIN)"
	@grep -o 'tag = "[^"]*"' corpus/Cargo.toml | sed 's/^/omni: /'
