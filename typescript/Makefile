.PHONY: build test clean inspect cli

# voxgig/omni drives the shared spec; it is a sibling checkout, not a
# published package (yet).
OMNI ?= $(shell node -e "const{existsSync}=require('fs');for(const p of [process.env.OMNI_HOME,'../../omni','/workspace/omni','/home/user/omni']){if(p&&existsSync(p+'/spec/fib.json')){console.log(p);break}}")

build:
	npm install --no-audit --no-fund --silent
	npm run build

test: build
	$(MAKE) -C $(OMNI)/typescript build
	OMNI_HOME=$(OMNI) npm test

cli: build
	node dist/cli/sekreto-cli.js $(ARGS)

clean:
	rm -rf dist node_modules

inspect:
	@node --version
