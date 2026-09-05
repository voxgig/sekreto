-- RUN: make plugins
-- RUN-SOME: make plugins SEAM='the core requires no plugin'
--
-- THE PLUGIN SEAM, from both sides.
--
-- Moving the provider kinds that open sockets and spawn processes out of
-- the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
-- passed in is not in the catalog, and a chain naming it is refused. That
-- is the intended behaviour, and it means a consumer can be broken
-- without a single conformance check noticing - the conformance suite
-- passes every plugin, so it can never see a missing one, and never sees
-- the CLI's list at all. So the full set is pinned here: it holds every
-- kind, every kind builds, and the CLI passes it.
--
-- No third-party test framework, for the same reason the conformance
-- suite has none: `make test` stays dependency-free.

package.path = 'src/?.lua;test/?.lua;' .. package.path

local pluginhome = require('pluginhome')

pluginhome.pluginpath()

local plugin = require('plugin')
local sekreto = require('sekreto')
local providers = require('sekreto.providers')
local allplugins = require('sekreto.plugins').allplugins

local T = plugin.types

-- This suite runs from the port directory (see the Makefile), and the
-- CLI probe below needs to name it from somewhere else.
local PORT = io.popen('pwd', 'r'):read('l')

local ONLY = arg[1]
local PASSCOUNT = 0
local FAILCOUNT = 0

-- The ten kinds that are NOT built in, sorted.
local PLUGINS = {
  'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'gcpsecrets',
  'hashicorp', 'infisical', 'onepassword', 'secretspec',
}

-- All fourteen, sorted.
local EVERY = {
  'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'dotenv',
  'env', 'file', 'gcpsecrets', 'hashicorp', 'infisical', 'memory',
  'onepassword', 'secretspec',
}

-- The five files the core is, and nothing else may be reached by
-- requiring it.
local CORE = {
  'src/sekreto.lua',
  'src/sekreto/addr.lua',
  'src/sekreto/err.lua',
  'src/sekreto/name.lua',
  'src/sekreto/providers.lua',
}

-- ------------------------------------------------------------ assertions

local function fail(message)
  error(message, 0)
end

local function shown(value)
  if 'table' == type(value) then
    local parts = {}
    for index, entry in ipairs(value) do
      parts[index] = tostring(entry)
    end
    return '[' .. table.concat(parts, ', ') .. ']'
  end
  return tostring(value)
end

local function same(got, want, what)
  if got ~= want then
    fail((what or 'value') .. ':\n  want ' .. shown(want) .. '\n  got  ' .. shown(got))
  end
end

local function samelist(got, want, what)
  local a = table.concat(got, ', ')
  local b = table.concat(want, ', ')
  if a ~= b then
    fail((what or 'list') .. ':\n  want [' .. b .. ']\n  got  [' .. a .. ']')
  end
end

local function contains(text, want, what)
  if nil == text:find(want, 1, true) then
    fail((what or 'text') .. ' does not contain:\n  ' .. want)
  end
end

local function lacks(text, unwanted, what)
  if nil ~= text:find(unwanted, 1, true) then
    fail((what or 'text') .. ' unexpectedly contains:\n  ' .. unwanted)
  end
end

--- What a call raised, as a message, or nil when it did not raise.
local function raised(body)
  local ok, why = pcall(body)
  if ok then
    return nil
  end
  return why
end

local function sekretoerror(body, want, what)
  local why = raised(body)
  if nil == why then
    fail((what or 'call') .. ' did not raise')
  end
  if not sekreto.issekretoerror(why) then
    fail((what or 'call') .. ' raised something that is not a SekretoError: ' ..
      sekreto.errmessage(why))
  end
  same(sekreto.errmessage(why), want, what)
end

local function testcase(name, body)
  if nil ~= ONLY and name ~= ONLY then
    return
  end

  local ok, why = pcall(body)

  if ok then
    PASSCOUNT = PASSCOUNT + 1
    print('ok   - ' .. name)
  else
    FAILCOUNT = FAILCOUNT + 1
    print('FAIL - ' .. name)
    print('       ' .. tostring(sekreto.errmessage(why)):gsub('\n', '\n       '))
  end
end

-- ------------------------------------------------------------- utilities

local function readall(path)
  local handle = io.open(path, 'rb')
  if nil == handle then
    fail('cannot read ' .. path)
  end
  local text = handle:read('a')
  handle:close()
  return text
end

--- A definition's name, for comparing sets of them.
local function names(definitions)
  local out = {}
  for index, definition in ipairs(definitions) do
    out[index] = definition.name
  end
  return out
end

local function sorted(list)
  local out = {}
  for index, entry in ipairs(list) do
    out[index] = entry
  end
  table.sort(out)
  return out
end

-- ------------------------------------------------ what the library holds

testcase('the full set holds every kind', function()
  same(#allplugins, 10, 'the full set size')
  samelist(sorted(names(allplugins)), PLUGINS, 'the full set')

  -- Every kind is its own module, and reachable as one.
  for _, kind in ipairs(PLUGINS) do
    local module = kind:sub(1, 3) == 'aws' and 'aws' or kind
    local held = require('sekreto.plugins.' .. module)[kind]
    same(type(held), 'table', kind .. ' is in sekreto.plugins.' .. module)
    same(held.name, kind, kind .. ' definition name')
  end

  samelist(names(providers.BUILTINS), providers.KINDS.builtin, 'the built-ins')
  samelist(sorted(providers.KINDS.plugin), PLUGINS, 'KINDS.plugin')
end)

-- Naming a kind is not enough: a kind can be in the catalog and still
-- fail to build. Construction is what the CLI does before any network.
testcase('every kind builds from a spec', function()
  local chain = {}
  for index, kind in ipairs(EVERY) do
    chain[index] = {
      kind = kind, addr = 'http://127.0.0.1:8200', token = 't',
      dir = '/tmp', file = '/tmp/.env', values = {},
    }
  end

  local secrets = sekreto.sekreto({ plugins = allplugins, providers = chain })

  samelist(secrets:stores(), EVERY, 'stores')
  samelist(T.keys(secrets.host:list()), EVERY, 'host refs')

  for _, ref in ipairs(T.keys(secrets.host:list())) do
    same(secrets.host:list()[ref], 'live', ref .. ' status')
  end
end)

-- THE ONE THING NO CONFORMANCE CHECK CAN SEE. A CLI that passes one
-- plugin instead of ten leaves all fourteen groups green and fails nine
-- integration checks. Pinned as the WHOLE call, closing brace included:
-- `contains('plugins = allplugins')` is still true of
-- `plugins = allplugins_but_one`.
testcase('the CLI passes the full set', function()
  local src = readall('cli/sekreto-cli.lua')

  contains(src, "local allplugins = require('sekreto.plugins').allplugins",
    'the CLI')
  contains(src,
    'sekreto.sekreto({ plugins = allplugins, providers = chainfor(source) })',
    'the CLI call site')
end)

-- ...and it must still FIND voxgig/plugin when it is run the way
-- test/checks.sh runs it: from another directory, with the environment
-- wiped. The library requires `plugin` by name and searches nothing, so
-- everything rests on test/pluginhome.lua - and its first candidate is
-- $PLUGIN_HOME, which is exactly the one that is not set there. An
-- earlier draft wrote that candidate into a table constructor, where an
-- unset variable is a nil, a nil is a hole, and `ipairs` stops at the
-- first hole: the whole search was skipped precisely when the
-- environment was wiped. `make test` stayed green; fifteen of the
-- nineteen integration checks failed.
--
-- `--source env` with no such variable set reaches the chain and stops
-- there, so this needs no server and touches no socket.
--
-- `env -i` rather than `env -u PLUGIN_HOME -u LUA_PATH -u LUA_CPATH`,
-- because test/checks.sh wipes the environment with `env -i` and naming
-- variables to remove cannot match that. Lua 5.4 reads LUA_PATH_5_4 in
-- PREFERENCE to LUA_PATH, so a developer with the version-suffixed
-- variable set had this check pass against the very defect it exists to
-- catch - the search skipped, the CLI finding voxgig/plugin anyway
-- because the interpreter's own path already reached it.
testcase('the CLI finds voxgig/plugin with the environment wiped', function()
  local pipe = io.popen(
    'cd / && env -i PATH="$PATH" HOME="$HOME" lua5.4 ' ..
    PORT .. "/cli/sekreto-cli.lua http://127.0.0.1:1/x --source env 2>&1", 'r')
  local out = pipe:read('a') or ''
  pipe:close()

  lacks(out, 'voxgig/plugin not found', 'the wiped-environment CLI')
  same(out, 'sekreto-cli: sekreto: unknown secret: api.token\n',
    'the wiped-environment CLI')
end)

-- --------------------------------------------------- what a consumer sees

testcase('one plugin is enough for a chain that names only it', function()
  local hashicorp = require('sekreto.plugins.hashicorp').hashicorp

  local secrets = sekreto.sekreto({
    plugins = { hashicorp },
    providers = {
      { kind = 'memory', values = { API_TOKEN = 'tok01' } },
      { kind = 'hashicorp', name = 'prod',
        addr = 'https://vault.example.com', token = 't' },
    },
  })

  samelist(secrets:stores(), { 'memory', 'prod' }, 'stores')
  samelist(secrets:sources(),
    { 'memory', 'hashicorp:https://vault.example.com/secret' }, 'sources')
  same(secrets:get('api.token'), 'tok01', 'the secret')

  -- The plugin host is what the chain is made of, and it reads like the
  -- chain: the kind, or kind$store for a named store.
  samelist(T.keys(secrets.host:list()), { 'hashicorp$prod', 'memory' }, 'host refs')
  samelist(secrets.catalog:names(),
    { 'dotenv', 'env', 'file', 'hashicorp', 'memory' }, 'the catalog')
end)

testcase('a kind that was not passed in is refused, naming the fix', function()
  local hashicorp = require('sekreto.plugins.hashicorp').hashicorp

  sekretoerror(function()
    sekreto.sekreto({
      plugins = { hashicorp },
      providers = { { kind = 'doppler', token = 't' } },
    })
  end,
  'sekreto: unknown provider kind: doppler' ..
  ' (available: dotenv, env, file, hashicorp, memory)' ..
  ' - doppler is a sekreto plugin, not built in: pass it in the plugins option',
  'an unloaded kind')

  -- A kind nobody ships is a typo, and gets no such hint.
  sekretoerror(function()
    sekreto.sekreto({ providers = { { kind = 'vualt' } } })
  end,
  'sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)',
  'a typo')
end)

-- Two providers MAY share a store name - a directed read walks both, and
-- the spec pins it - but an instance ref may not, so the second gets a
-- numbered tag from the host and keeps its store name.
testcase('a repeated store name keeps the store and numbers the instance', function()
  local secrets = sekreto.sekreto({ providers = {
    { kind = 'memory', values = {} },
    { kind = 'memory', values = { API_TOKEN = 'second' } },
    { kind = 'memory', name = 'pair', values = {} },
    { kind = 'memory', name = 'pair', values = { API_TOKEN = 'pair2' } },
  } })

  samelist(secrets:stores(), { 'memory', 'pair' }, 'stores')
  samelist(T.keys(secrets.host:list()),
    { 'memory', 'memory$1', 'memory$2', 'memory$pair' }, 'host refs')
  same(secrets:getfrom('memory', 'api.token'), 'second', 'the memory store')
  same(secrets:getfrom('pair', 'api.token'), 'pair2', 'the pair store')
end)

testcase('a store name must be a valid tag', function()
  sekretoerror(function()
    sekreto.sekreto({ providers = {
      { kind = 'memory', name = 'my store', values = {} },
    } })
  end, 'sekreto: invalid store name: my store', 'a store name with a space')
end)

-- A provider that refuses its own configuration raises a SekretoError
-- from inside the plugin's `define`. The spec pins that message byte for
-- byte, so it must come back out of the host as itself - not wrapped as
-- plugin_define_failed, and not as a plugin error.
testcase('a SekretoError raised in define comes back out as itself', function()
  local hashicorp = require('sekreto.plugins.hashicorp').hashicorp

  sekretoerror(function()
    sekreto.sekreto({
      plugins = { hashicorp },
      providers = { { kind = 'hashicorp', addr = 'http://127.0.0.1:1',
                      token = 't', kv = 3 } },
    })
  end, 'sekreto: hashicorp: unsupported kv version: 3', 'a refused kv version')
end)

-- ...and any other error is not sekreto's to rewrite: it surfaces as the
-- host reports it, naming the instance and the cause.
testcase("any other error raised in define is the host's report of it", function()
  local broken = sekreto.providerplugin('broken', function()
    error('boom', 0)
  end)

  local why = raised(function()
    sekreto.sekreto({ plugins = { broken }, providers = { { kind = 'broken' } } })
  end)

  same(sekreto.issekretoerror(why), false, 'a non-sekreto error stays foreign')
  same(plugin.codeof(why), 'plugin_define_failed', 'the code')
  contains(T.message(why), 'boom', 'the message')
end)

testcase('a custom kind is one providerplugin call', function()
  local shouty = sekreto.providerplugin('shouty', function(spec)
    local values = spec.values or {}
    return {
      lookup = function(secret) return values[secret:upper()] end,
      describe = function() return 'shouty' end,
    }
  end)

  local secrets = sekreto.sekreto({
    plugins = { shouty },
    providers = { { kind = 'shouty', values = { ['API.TOKEN'] = 'loud' } } },
  })

  same(secrets:get('api.token'), 'loud', 'the custom kind')
  samelist(T.keys(secrets.host:list()), { 'shouty' }, 'host refs')
end)

-- A plugin that names a built-in kind replaces it: that is how a host
-- substitutes an implementation, and never an accident, because the four
-- names are documented.
testcase('a plugin may replace a built-in kind', function()
  local replaced = sekreto.providerplugin('memory', function()
    return {
      lookup = function() return 'replaced' end,
      describe = function() return 'memory' end,
    }
  end)

  local secrets = sekreto.sekreto({
    plugins = { replaced },
    providers = { { kind = 'memory', values = { API_TOKEN = 'original' } } },
  })

  same(secrets:get('api.token'), 'replaced', 'the replacement')
end)

testcase('close tears the chain down and keeps redaction', function()
  local secrets = sekreto.sekreto({
    providers = { { kind = 'memory', values = { API_TOKEN = 'tok01' } } },
  })

  same(secrets:get('api.token'), 'tok01', 'before close')

  secrets:close()

  same(#T.keys(secrets.host:list()), 0, 'the host is empty')
  same(#secrets:stores(), 0, 'the stores are gone')
  same(secrets:tryget('api.token'), nil, 'nothing answers')
  same(secrets:redact('token=tok01'), 'token=[redacted]', 'redaction survives')
end)

-- The chain moved from a positional argument into `providers`, and a
-- caller still writing the old shape must be told so. Without this it
-- builds an EMPTY chain and every read raises `unknown secret`, which
-- names neither the cause nor the fix.
testcase('a list of specs is not an options table', function()
  sekretoerror(function()
    sekreto.sekreto({ { kind = 'memory', values = { API_TOKEN = 'tok01' } } })
  end,
  'sekreto: sekreto() takes an options table' ..
  ' { plugins = ..., providers = ..., cache = ... }, not a list of specs',
  'the old positional call')
end)

-- ----------------------------------------------------- the boundary itself
--
-- Lua has no link step, so the artifact-level fact is the MODULE GRAPH:
-- what `require` actually pulls in. Measured in a FRESH interpreter,
-- because this one has required everything above on purpose, and read out
-- of `package.loaded`, which is the whole truth about what the process
-- has loaded.

local PLUGINSRC = pluginhome.pluginhome() .. '/lua/src/?.lua'

if nil ~= PLUGINSRC:find("'", 1, true) then
  error('sekreto: the plugin path is not shell-safe: ' .. PLUGINSRC, 0)
end

--- Run `code` in a fresh interpreter and answer the sekreto modules it
--- loaded, sorted and space-separated.
---
--- The injected lua uses `[[...]]` strings throughout so that the whole
--- program can be one single-quoted shell word.
local function fresh(code)
  local probe = 'local out = {} ' ..
    'for k in pairs(package.loaded) do ' ..
    '  if [[sekreto]] == k:sub(1, 7) then out[#out + 1] = k end ' ..
    'end ' ..
    'table.sort(out) io.write(table.concat(out, [[ ]]))'

  local program = 'package.path = [[src/?.lua;' .. PLUGINSRC .. ';]] .. package.path ' ..
    code .. ' ' .. probe

  local pipe = io.popen("lua5.4 -e '" .. program .. "' 2>&1", 'r')
  local out = pipe:read('a') or ''
  local ok = pipe:close()

  if not ok then
    fail('the probe failed: ' .. code .. '\n' .. out)
  end

  return out
end

-- The core requires no plugin: requiring `sekreto` brings in the chain,
-- the built-ins and voxgig/plugin, and not one module under plugins/ -
-- so not the HTTP client, not SHA-256, and not sekreto.plugins.net,
-- which is the only thing that runs native/sekretonet.c. A chain of
-- built-in kinds therefore needs no compiled artifact at all, and the
-- probe below proves it by resolving a secret from one.
testcase('the core requires no plugin', function()
  same(fresh('require [[sekreto]]'),
    'sekreto sekreto.addr sekreto.err sekreto.name sekreto.providers',
    'the core module graph')

  local working = fresh(
    'local s = require [[sekreto]].sekreto({ providers = { ' ..
    '{ kind = [[memory]], values = { API_TOKEN = [[tok01]] } } } }) ' ..
    'assert([[tok01]] == s:get([[api.token]]))')

  same(working,
    'sekreto sekreto.addr sekreto.err sekreto.name sekreto.providers',
    'a working built-in chain')
end)

-- ...and what a module graph cannot see: a socket, a child process or a
-- hash the core grew DIRECTLY rather than by requiring a plugin. Comments
-- are stripped first, so the prose above may say `io.popen` while the
-- code may not.
testcase('the core opens nothing of its own', function()
  local forbidden = {
    'io.popen', 'os.execute', 'os.tmpname', 'sekreto-net',
    'sha256', 'hmac', 'unbase64', 'socket',
  }

  for _, path in ipairs(CORE) do
    local code = {}
    for line in (readall(path) .. '\n'):gmatch('([^\n]*)\n') do
      local cut = line:find('%-%-')
      code[#code + 1] = (nil == cut) and line or line:sub(1, cut - 1)
    end
    code = table.concat(code, '\n')

    for _, word in ipairs(forbidden) do
      lacks(code, word, path)
    end

    -- And no require of anything under plugins/, in any spelling.
    lacks(code, 'sekreto.plugins', path .. ' requires')
  end
end)

-- One plugin requires only itself, and the shared plugin-side modules it
-- actually uses. Lua runs no package initializer for a submodule, so the
-- laziness python's plugins package has to arrange with a module
-- `__getattr__` is what a directory of files already does - this pins
-- that it stays true.
testcase('one plugin requires only itself', function()
  same(fresh('require [[sekreto.plugins.hashicorp]]'),
    'sekreto.addr sekreto.err sekreto.name sekreto.plugins.hashicorp ' ..
    'sekreto.plugins.httpjson sekreto.plugins.json sekreto.plugins.net ' ..
    'sekreto.plugins.support sekreto.providers',
    'the hashicorp module graph')
end)

-- The full set is loaded on demand, and reaching it loads everything -
-- including the crypto edge, which only the two aws kinds use.
testcase('the full set is loaded on demand', function()
  local before = fresh('require [[sekreto.plugins.hashicorp]]')

  for _, absent in ipairs({ 'sekreto.plugins.doppler', 'sekreto.plugins.sigv4',
                            'sekreto.plugins.crypto', 'sekreto.plugins.aws' }) do
    lacks(before, absent, 'one plugin')
  end

  local after = fresh('require [[sekreto.plugins]]')

  for _, module in ipairs({ 'hashicorp', 'boru', 'aws', 'gcpsecrets',
                            'azuresecrets', 'onepassword', 'doppler',
                            'infisical', 'secretspec', 'sigv4', 'crypto',
                            'httpjson', 'json', 'net', 'support' }) do
    contains(after, 'sekreto.plugins.' .. module, 'the full set')
  end
end)

-- `require('sekreto.plugins.hashicorp')` is the MODULE, and the
-- definition is one field further on - so the thing nearest to hand is
-- not a definition. Refused by name, saying what to pass instead.
testcase('a module passed as a plugin is refused', function()
  sekretoerror(function()
    sekreto.sekreto({ plugins = { require('sekreto.plugins.hashicorp') } })
  end,
  'sekreto: not a plugin definition: the module sekreto.plugins.hashicorp' ..
  " - pass a definition it holds, such as require('sekreto.plugins.hashicorp')" ..
  '.hashicorp',
  'a single-kind module')

  sekretoerror(function()
    sekreto.sekreto({ plugins = { require('sekreto.plugins') } })
  end,
  'sekreto: not a plugin definition: the module sekreto.plugins' ..
  " - pass a definition it holds, such as require('sekreto.plugins').allplugins",
  'the full-set module')

  sekretoerror(function()
    sekreto.sekreto({ plugins = { true } })
  end, 'sekreto: not a plugin definition: true', 'a boolean')
end)

print('\n' .. PASSCOUNT .. ' passed, ' .. FAILCOUNT .. ' failed')

os.exit(0 == FAILCOUNT and 0 or 1)
