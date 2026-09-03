.PHONY: build test clean inspect

# voxgig/omni drives the shared spec. This port takes it from npm
# (@voxgig/omni-js, a devDependency - omni register 4.13's isolation device
# for Node), so `npm install` is all the wiring there is; no checkout and
# no OMNI_HOME. `test` depends on `build` for exactly that reason.

build:
	npm install --no-audit --no-fund --silent

test: build
	npm test

clean:
	rm -rf node_modules

inspect:
	@node --version
