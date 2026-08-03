.PHONY: build test clean inspect

export DOTNET_CLI_TELEMETRY_OPTOUT = 1
export DOTNET_NOLOGO = 1

# voxgig/omni is a sibling checkout, not a published package, and it may sit
# anywhere. Find it, and point the test project's reference at it.
OMNI := $(shell \
  for d in "$$OMNI_HOME" ../../omni ../../../omni /workspace/omni /home/user/omni; do \
    if [ -n "$$d" ] && [ -f "$$d/spec/fib.json" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

# The library and the CLI reference nothing but the BCL. Only the
# conformance suite needs omni.
build:
	dotnet build cli -c Release -v q --nologo

test:
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	dotnet build test -v q --nologo -p:OmniPath=$(OMNI)/csharp/src/Omni.csproj
	./test/bin/Debug/net8.0/sekretotest

clean:
	rm -rf src/bin src/obj test/bin test/obj cli/bin cli/obj

inspect:
	@dotnet --version
	@echo "omni: $(OMNI)"
