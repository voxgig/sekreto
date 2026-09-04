-- RUN: make test
-- RUN-SOME: lua5.4 test/sekreto_test.lua envkey
--
-- The sekreto conformance suite. Every port runs these same groups, from
-- the same spec/sekreto.json, through its own voxgig/omni runner.
--
-- No third-party test framework: a failing omni check raises an OmniError
-- table, which any host framework would report as a failure. This harness
-- keeps `make test` dependency-free.
--
-- Two value models meet here. omni tags every container with a metatable
-- and carries explicit NULL and ABSENT sentinels, because a Lua table can
-- hold neither a nil nor an ordering; the library takes plain Lua values
-- and plain spec tables. The bridge below converts between them
-- explicitly, so nothing about absent, null and value is guessed.
--
-- This is the ONLY part of the port that may name voxgig/omni.

-- ------------------------------------------------------------ the paths

--- Walk up from the working directory looking for `spec/<name>`.
local function specfile(name)
  local dir = '.'

  for _ = 1, 8 do
    local cand = dir .. '/spec/' .. name
    local handle = io.open(cand, 'r')
    if nil ~= handle then
      handle:close()
      return cand
    end
    dir = dir .. '/..'
  end

  error('sekreto: spec not found: ' .. name, 0)
end

--- voxgig/omni is a sibling checkout, not a published artifact, and it
--- may sit anywhere. The same five-path search every port's Makefile
--- performs, repeated here so that a single group can be run by hand.
local function omniroot()
  local candidates = {
    os.getenv('OMNI_HOME'), '../../omni', '../../../omni',
    '/workspace/omni', '/home/user/omni',
  }

  for _, dir in ipairs(candidates) do
    if nil ~= dir and '' ~= dir then
      local handle = io.open(dir .. '/spec/fib.json', 'r')
      if nil ~= handle then
        handle:close()
        return dir
      end
    end
  end

  error('sekreto: voxgig/omni not found - set OMNI_HOME', 0)
end

package.path = 'src/?.lua;' .. omniroot() .. '/lua/src/?.lua;' .. package.path

local runner = require('runner')
local u = require('util')

local sekreto = require('sekreto')
local providers = require('sekreto.providers')

local ONLY = arg[1]
local PASSCOUNT = 0
local FAILCOUNT = 0

-- ------------------------------------------------------------ the bridge

--- omni's model -> a plain Lua value. ABSENT and NULL both read as nil.
local function plain(value)
  if u.isabsent(value) or u.isnull(value) then
    return nil
  end

  if u.islist(value) then
    local out = {}
    for index, entry in ipairs(value) do
      out[index] = plain(entry)
    end
    return out
  end

  if u.ismap(value) then
    local out = {}
    for key, entry in pairs(value) do
      out[key] = plain(entry)
    end
    return out
  end

  return value
end

--- A Lua string list -> omni's model.
local function textlist(values)
  local out = u.list({})
  for index, text in ipairs(values) do
    out[index] = text
  end
  return out
end

--- A key list plus a value table -> an omni map, in that key order.
local function textmap(keys, values)
  local out = u.map({})
  for _, key in ipairs(keys) do
    rawset(out, key, values[key])
  end
  return out
end

--- A field of an omni map, as a string or nil.
local function str(entry, key)
  local value = u.get(entry, key)
  return u.isstr(value) and value or nil
end

--- One provider spec, out of the spec's declarative chain description.
local function specof(entry)
  local values = nil
  local given = u.get(entry, 'values')

  if u.ismap(given) then
    values = {}
    for key, value in pairs(given) do
      values[key] = u.stringify(value)
    end
  end

  local auth = nil
  local givenauth = u.get(entry, 'auth')

  if u.ismap(givenauth) then
    auth = providers.authspec({
      method = str(givenauth, 'method') or '',
      mount = str(givenauth, 'mount'),
      role = str(givenauth, 'role'),
      jwt = str(givenauth, 'jwt'),
      jwtfile = str(givenauth, 'jwtfile'),
      roleid = str(givenauth, 'roleid'),
      secretid = str(givenauth, 'secretid'),
    })
  end

  local kv = u.get(entry, 'kv')

  return providers.spec({
    kind = str(entry, 'kind') or '',
    name = str(entry, 'name'),
    prefix = str(entry, 'prefix'),
    file = str(entry, 'file'),
    values = values,
    dir = str(entry, 'dir'),
    addr = str(entry, 'addr'),
    token = str(entry, 'token'),
    mount = str(entry, 'mount'),
    kv = u.isnum(kv) and math.tointeger(kv) or nil,
    vaultnamespace = str(entry, 'vaultnamespace'),
    auth = auth,
    command = str(entry, 'command'),
    profile = str(entry, 'profile'),
    backend = str(entry, 'backend'),
    reason = str(entry, 'reason'),
    namespace = str(entry, 'namespace'),
    home = str(entry, 'home'),
    region = str(entry, 'region'),
    keyid = str(entry, 'keyid'),
    secret = str(entry, 'secret'),
    session = str(entry, 'session'),
    project = str(entry, 'project'),
    vault = str(entry, 'vault'),
    tenant = str(entry, 'tenant'),
    clientid = str(entry, 'clientid'),
    clientsecret = str(entry, 'clientsecret'),
    loginaddr = str(entry, 'loginaddr'),
    imdsaddr = str(entry, 'imdsaddr'),
    metadataaddr = str(entry, 'metadataaddr'),
    apiversion = str(entry, 'apiversion'),
    config = str(entry, 'config'),
    environment = str(entry, 'environment'),
    path = str(entry, 'path'),
  })
end

--- Build a Sekreto from the spec's declarative chain description.
---
--- Built INSIDE each subject, never before it: four corpus entries expect
--- `unsupported kv version`, which the CONSTRUCTOR raises, and only a
--- construction inside the subject delivers that to omni as a subject
--- error. Caching is off on every constructed chain.
local function chainof(entry)
  local specs = {}
  local chain = u.get(entry, 'chain')

  if u.islist(chain) then
    for index, spec in ipairs(chain) do
      specs[index] = specof(spec)
    end
  end

  return sekreto.sekreto(specs, false)
end

--- The name a group's entry asks about.
local function namearg(entry)
  return str(entry, 'name') or ''
end

-- ----------------------------------------------------------- the subjects

-- `validname` answers whatever Lua calls true; the spec says JSON true,
-- so the adaptation happens here rather than in the library.
local function VALIDNAME(input)
  return sekreto.validname(plain(input))
end

local function ENVKEY(input)
  return sekreto.envkey(plain(u.get(input, 'name')), str(input, 'prefix'))
end

local function VAULTREF(input)
  local ref = sekreto.vaultref(plain(input))
  return u.map({ path = ref.path, field = ref.field })
end

local function FLATNAME(input)
  return sekreto.flatname(plain(u.get(input, 'name')), str(input, 'sep') or '')
end

local function AWSPARAM(input)
  return sekreto.awsparam(plain(u.get(input, 'name')), str(input, 'prefix'))
end

local function PARSEDOTENV(input)
  local values, order = sekreto.parsedotenv(plain(input))
  return textmap(order, values)
end

local function RESOLVE(input)
  return chainof(input):get(namearg(input))
end

local function TRYSECRET(input)
  return chainof(input):tryget(namearg(input))
end

local function SOURCES(input)
  return textlist(chainof(input):sources())
end

local function STORES(input)
  return textlist(chainof(input):stores())
end

local function GETFROM(input)
  return chainof(input):getfrom(str(input, 'store') or '', namearg(input))
end

local function TRYFROM(input)
  return chainof(input):tryfrom(str(input, 'store') or '', namearg(input))
end

-- Answers the ordered output map itself, which omni compares as a JSON
-- object against the spec's known-answer signatures.
local function SIGV4(input)
  local headers = {}
  local given = u.get(input, 'headers')

  if u.ismap(given) then
    for key, value in pairs(given) do
      headers[#headers + 1] = { key, u.stringify(value) }
    end
  end

  local signed = sekreto.sigv4({
    method = str(input, 'method') or '',
    url = str(input, 'url') or '',
    service = str(input, 'service') or '',
    region = str(input, 'region') or '',
    keyid = str(input, 'keyid') or '',
    secret = str(input, 'secret') or '',
    datetime = str(input, 'datetime') or '',
    headers = headers,
    body = str(input, 'body') or '',
    session = str(input, 'session'),
  })

  local out = u.map({})
  for _, pair in ipairs(signed) do
    rawset(out, pair[1], pair[2])
  end

  return out
end

local function REDACT(input)
  local values = nil
  local given = u.get(input, 'values')

  if u.islist(given) then
    values = {}
    for index, value in ipairs(given) do
      values[index] = plain(value)
    end
  end

  return sekreto.redact(plain(u.get(input, 'text')), values)
end

-- ------------------------------------------------------------- the runner

local function testcase(name, body)
  if nil ~= ONLY and name ~= ONLY then
    return
  end

  local ok, failure = pcall(body)

  if ok then
    PASSCOUNT = PASSCOUNT + 1
    print('ok   - ' .. name)
  else
    FAILCOUNT = FAILCOUNT + 1
    print('FAIL - ' .. name)
    print(runner.errmessage(failure))
  end
end

-- makeRunner answers a function of the section name, which resolves
-- `primary.sekreto`. There is no DEF section, so the provider is empty:
-- every subject is called with exactly one argument, the deep-cloned
-- `in`.
local R = runner.makeRunner(specfile('sekreto.json'))('sekreto')

testcase('validname', function()
  R.runsetflags(R.set('validname'), { null = false }, VALIDNAME)
end)
testcase('envkey', function() R.runset(R.set('envkey'), ENVKEY) end)
testcase('vaultref', function() R.runset(R.set('vaultref'), VAULTREF) end)
testcase('flatname', function() R.runset(R.set('flatname'), FLATNAME) end)
testcase('awsparam', function() R.runset(R.set('awsparam'), AWSPARAM) end)
testcase('parsedotenv', function() R.runset(R.set('parsedotenv'), PARSEDOTENV) end)
testcase('resolve', function() R.runset(R.set('resolve'), RESOLVE) end)
testcase('trysecret', function() R.runset(R.set('trysecret'), TRYSECRET) end)
testcase('sources', function() R.runset(R.set('sources'), SOURCES) end)
testcase('stores', function() R.runset(R.set('stores'), STORES) end)
testcase('getfrom', function() R.runset(R.set('getfrom'), GETFROM) end)
testcase('tryfrom', function() R.runset(R.set('tryfrom'), TRYFROM) end)
testcase('sigv4', function() R.runset(R.set('sigv4'), SIGV4) end)
testcase('redact', function() R.runset(R.set('redact'), REDACT) end)

print('\n' .. PASSCOUNT .. ' passed, ' .. FAILCOUNT .. ' failed')

os.exit(0 == FAILCOUNT and 0 or 1)
