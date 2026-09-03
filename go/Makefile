.PHONY: build build-clean test clean inspect

# voxgig/omni drives the shared spec. The conformance suite is a nested
# module, ./testutil, which requires omni BY ITS RELEASE TAG
# (github.com/voxgig/omni/go vX.Y.Z, omni DOCS.md 8.3) and resolves it from
# the module proxy like any dependency, and replaces the library under
# test with a path relative to its own go.mod. No checkout, no OMNI_HOME
# and no go.work: a workspace was how this port used to reach a sibling
# checkout, and its module-graph loader could never resolve the phantom
# v0.0.0 the nested module required - which surfaced the moment the
# library took a real dependency.
#
# The suite is nested for the other half of the rule: `go build ./...`
# here skips a nested module, so the library compiles with no omni
# anywhere, and `go mod tidy` here cannot add omni to the published
# dependency graph. (The convention voxgig/struct#89 set; omni register
# 4.13.) The cost is that ./... does not reach the suite, so `test` names
# it.

build:
	go build ./...
	go build -o build/sekreto-cli ./cli

# Register 4.13 proof: the published module must build with NO omni
# anywhere - module-only resolution, go.mod as a consumer sees it. GOWORK=off
# guards against a stray workspace file on a developer's disk.
build-clean:
	GOWORK=off go build ./...
	GOWORK=off go test -count=1 ./...

# -count=1 disables the test cache. The spec is read at run time, so Go
# cannot see that it changed and would otherwise report a stale pass after
# spec/sekreto.json is edited.
#
# -race because this is the only port the compiler does not stop from
# sharing a Sekreto across threads, and the bug it caught - a lost entry in
# `seen`, so Redact hands a secret straight back into the log - produces a
# correct-looking result on any single run. concurrent_test.go is only a
# real guard with the detector on.
test:
	go test -race -count=1 ./...
	cd testutil && go test -race -count=1 ./...

clean:
	go clean
	rm -rf build

inspect:
	@go version
	@grep 'voxgig/omni/go' testutil/go.mod | sed 's/^[[:space:]]*/omni: /'
