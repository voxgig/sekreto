.PHONY: build test test-plugins check-core deps clean inspect

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

# voxgig/plugin is a RUNTIME dependency - the library itself is built on it
# (docs/design/plugin-providers.md) - and it has no NuGet package, so it
# comes from a checkout the same way omni does: $PLUGIN_HOME, then a
# sibling checkout, then the usual places. Failing all of those, `deps`
# fetches a shallow clone into ../.plugin, which is what `dotnet restore`
# would do for a packaged dependency. The LIBRARY searches no path; this
# does, and passes the answer to msbuild.
PLUGIN ?= $(shell \
  for d in "$$PLUGIN_HOME" ../../plugin ../../../plugin ../.plugin \
           /workspace/plugin /home/user/plugin; do \
    if [ -n "$$d" ] && [ -f "$$d/csharp/src/VoxgigPlugin.csproj" ]; then \
      (cd "$$d" && pwd); break; \
    fi; \
  done)

PLUGIN_REPO ?= https://github.com/voxgig/plugin

PLUGINPROJ = $(PLUGIN)/csharp/src/VoxgigPlugin.csproj

deps:
	@if [ -n "$(PLUGIN)" ]; then \
	  echo "voxgig/plugin: $(PLUGIN)"; \
	else \
	  echo "voxgig/plugin: fetching $(PLUGIN_REPO) into ../.plugin"; \
	  git clone --quiet --depth 1 $(PLUGIN_REPO) ../.plugin; \
	fi

# The library and the CLI reference nothing but the BCL and voxgig/plugin.
# Only the conformance suite needs omni.
build: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - run make deps, or set PLUGIN_HOME" >&2; exit 1; }
	dotnet build cli -c Release -v q --nologo -p:PluginPath=$(PLUGINPROJ)

test: deps
	@test -n "$(OMNI)" || { echo "sekreto: voxgig/omni not found - set OMNI_HOME" >&2; exit 1; }
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - run make deps, or set PLUGIN_HOME" >&2; exit 1; }
	dotnet build test -v q --nologo -p:OmniPath=$(OMNI)/csharp/src/Omni.csproj -p:PluginPath=$(PLUGINPROJ)
	./test/bin/Debug/net8.0/sekretotest

# The seam the conformance suite cannot see: the plugin list is
# load-bearing, and a consumer can be broken without a single conformance
# check noticing. RUN-SOME of the same binary.
test-plugins: test
	./test/bin/Debug/net8.0/sekretotest plugins

# THE PROOF THAT THE SPLIT IS REAL. Builds the CORE ALONE - the plugins
# project is not on the command line at all - and then reads the artifact
# two ways.
#
# The output directory is the first: a referenced assembly is copied next
# to the one that references it, so VoxgigSekretoPlugins.dll being absent
# from src/bin is the reference being absent.
#
# The AssemblyRef table is the second, and it is the one that cannot be
# talked around: a .NET assembly names every assembly it references, as a
# plain string in its metadata, so a name that is not in the file is a
# type this assembly cannot resolve at run time. Four names must not be
# there - the plugin assembly itself, and the three platform assemblies
# only a plugin needs.
check-core: deps
	@test -n "$(PLUGIN)" || { echo "sekreto: voxgig/plugin not found - run make deps, or set PLUGIN_HOME" >&2; exit 1; }
	@dotnet build src -v q --nologo -p:PluginPath=$(PLUGINPROJ)
	@echo "--- src/bin/Debug/net8.0 (the core, built alone) ---"
	@ls src/bin/Debug/net8.0
	@echo "--- names in VoxgigSekreto.dll ---"
	@fail=0; for name in VoxgigSekretoPlugins System.Net.Http \
	                     System.Security.Cryptography System.Diagnostics.Process; do \
	  if grep -qa "$$name" src/bin/Debug/net8.0/VoxgigSekreto.dll; then \
	    echo "REACHED  $$name"; fail=1; \
	  else \
	    echo "absent   $$name"; \
	  fi; \
	done; \
	if [ 0 != $$fail ]; then \
	  echo "sekreto: the core reaches a plugin - the split is nominal" >&2; exit 1; \
	fi
	@echo "the core reaches no plugin"

clean:
	rm -rf src/bin src/obj test/bin test/obj cli/bin cli/obj plugins/bin plugins/obj

inspect:
	@dotnet --version
	@echo "omni: $(OMNI)"
	@echo "plugin: $(PLUGIN)"
