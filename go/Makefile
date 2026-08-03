.PHONY: build test clean inspect

# voxgig/omni is a sibling checkout, not a published module, and it may sit
# anywhere. Find it, then use a go workspace to point the import at it -
# which keeps go.mod free of a path that only works on one machine.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

go.work:
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	go work init . $(OMNI)/go

build: go.work
	go build ./...
	go build -o build/sekreto-cli ./cli

test: go.work
	go test ./...

clean:
	go clean
	rm -rf build go.work go.work.sum

inspect:
	@go version
	@echo "omni: $(OMNI)"
