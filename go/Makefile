.PHONY: build build-clean test clean inspect go.work

# voxgig/omni is a sibling checkout, not a published module, and it may sit
# anywhere. Find it, then use a go workspace to point the import at it -
# which keeps go.mod free of a path that only works on one machine.
#
# The conformance suite is a nested module, ./testutil, for the other half
# of that: `go build ./...` here skips a nested module, so the library still
# compiles with no omni checkout and no workspace, and `go mod tidy` cannot
# resolve omni from the proxy and add it to the published dependency graph.
# (The convention voxgig/struct#89 set; omni register 4.13.) The cost is
# that ./... no longer reaches the suite, so each target names it.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# PHONY, and it has to be: go.work is gitignored but survives on a
# developer's disk, so a file target would leave a workspace written
# before the testutil module existed looking up to date - and `go test
# ./testutil/...` then fails with "directory prefix testutil does not
# contain modules listed in go.work". Regenerating is cheap; being
# stale is not.
go.work:
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	@rm -f go.work go.work.sum
	go work init . ./testutil $(OMNI)/go

build: go.work
	go build ./...
	go build -o build/sekreto-cli ./cli

# Register 4.13 proof: the published module must build with NO omni checkout
# and NO workspace. GOWORK=off is exactly that machine - module-only
# resolution, go.mod as a consumer sees it - so this target needs nothing on
# disk beyond this checkout, and CI runs it before omni is fetched.
build-clean:
	GOWORK=off go build ./...
	GOWORK=off go test -count=1 ./...

# -count=1 disables the test cache. The spec is read at run time, so Go
# cannot see that it changed and would otherwise report a stale pass after
# spec/sekreto.json is edited.
test: go.work
	go test -count=1 ./... ./testutil/...

clean:
	go clean
	rm -rf build go.work go.work.sum

inspect:
	@go version
	@echo "omni: $(OMNI)"
