.PHONY: build test clean inspect cli

# voxgig/omni drives the shared spec. This port takes it from npm
# (@voxgig/omni, a devDependency - omni register 4.13's isolation device
# for Node), so `npm install` is all the wiring there is; no checkout and
# no OMNI_HOME.

build:
	npm install --no-audit --no-fund --silent
	npm run build

test: build
	npm test

cli: build
	node dist/cli/sekreto-cli.js $(ARGS)

clean:
	rm -rf dist node_modules

inspect:
	@node --version
