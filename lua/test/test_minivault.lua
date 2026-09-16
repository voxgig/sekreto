-- RUN: make vaulttest
-- RUN-SOME: lua5.4 test/test_minivault.lua restricted
--
-- The mini vault, from both sides: the store a chain reads, and the
-- programmatic API a plugin definition can publish beside it.
--
-- The vault is not in spec/sekreto.json and cannot be until every port
-- ships the kind. The spec runs against all twenty-three of them, so an
-- entry naming `minivault` would fail the ports that have no such
-- provider. What the shared corpus would have carried is here instead,
-- plus the one thing it could not carry either way: a file written by
-- this port and read by another, pinned by the vaults in test/fixture.
--
-- It names no omni, so it runs with no omni checkout at all.
--
-- A port of typescript/test/minivault.test.ts.

package.path = 'src/?.lua;test/?.lua;' .. package.path

local pluginhome = require('pluginhome')
pluginhome.pluginpath()

local sekreto = require('sekreto')
local mv = require('sekreto.plugins.minivault')

local MASTER = 'master-passphrase'

-- The rounds every case here uses. The library default is 210000, which
-- is the point of PBKDF2 and the wrong thing to pay per assertion.
local ROUNDS = 1000

local ONLY = arg[1]
local PASSCOUNT = 0
local FAILCOUNT = 0
local COUNT = 0
local WORK = nil

-- ---------------------------------------------------------- the harness

local function fail(why)
  error({ sekretominivaulttest = why }, 0)
end

local function whyof(held)
  if 'table' == type(held) and nil ~= held.sekretominivaulttest then
    return held.sekretominivaulttest
  end
  return tostring(sekreto.errmessage(held))
end

local function same(got, want, what)
  if got ~= want then
    fail((what or 'value') .. ':\n  want ' .. tostring(want) .. '\n  got  ' .. tostring(got))
  end
end

local function samelist(got, want, what)
  local a = table.concat(got, ', ')
  local b = table.concat(want, ', ')
  if a ~= b then
    fail((what or 'list') .. ':\n  want [' .. b .. ']\n  got  [' .. a .. ']')
  end
end

local function truth(got, what)
  if not got then
    fail(what)
  end
end

local function holds(got, want, what)
  if 'string' ~= type(got) or nil == got:find(want, 1, true) then
    fail((what or 'text') .. ':\n  want to contain ' .. want .. '\n  got  ' .. tostring(got))
  end
end

--- The message a call refused with, as a SekretoError. Anything else
--- escapes and fails the case, which is what pins the error type.
local function refusal(what, body)
  local ok, why = pcall(body)
  if ok then
    fail(what .. ': nothing was refused')
  end
  if not sekreto.issekretoerror(why) then
    fail(what .. ': not a SekretoError: ' .. whyof(why))
  end
  return sekreto.errmessage(why)
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
    print('       ' .. whyof(why):gsub('\n', '\n       '))
  end
end

-- -------------------------------------------------- the vault under test

local function vaultpath()
  COUNT = COUNT + 1
  return WORK .. '/vault' .. COUNT .. '.skmv'
end

local function vaultopts(file, key, passphrase)
  return { file = file, key = key, passphrase = passphrase, iterations = ROUNDS }
end

local function fresh()
  return mv.createvault(vaultopts(vaultpath(), nil, MASTER))
end

local function openas(file, key, passphrase)
  return mv.openvault(vaultopts(file, key, passphrase))
end

local function grantof(key, passphrase, names, write)
  return { key = key, passphrase = passphrase, names = names, write = write,
           iterations = ROUNDS }
end

local function slurp(path)
  local handle = io.open(path, 'rb')
  if nil == handle then
    fail('cannot read ' .. path)
  end
  local raw = handle:read('a')
  handle:close()
  return raw
end

local function spill(path, raw)
  local handle = io.open(path, 'wb')
  if nil == handle then
    fail('cannot write ' .. path)
  end
  handle:write(raw)
  handle:close()
end

--- Where the committed vaults live, found by walking up.
local function fixturedir()
  local dir = '.'

  for _ = 1, 8 do
    local probe = io.open(dir .. '/test/fixture/minivault.skmv', 'rb')
    if nil ~= probe then
      probe:close()
      return dir .. '/test/fixture'
    end
    dir = dir .. '/..'
  end

  fail('the fixture directory was not found')
end

--- EVERY committed vault, read off disk rather than listed here. A
--- hard-coded list is one more place to edit when a port lands, and the
--- edit that gets forgotten is the one that makes this suite stop
--- checking the port that just arrived.
local function fixtures()
  local out = {}
  local listing = io.popen("ls -1 '" .. fixturedir() .. "'", 'r')

  if nil ~= listing then
    for line in listing:lines() do
      if nil ~= line:match('%.skmv$') then
        out[#out + 1] = line
      end
    end
    listing:close()
  end

  table.sort(out)

  return out
end

--- A committed vault, copied so that a case which writes cannot edit the
--- bytes the format contract is made of.
local function fixture(name)
  local mine = vaultpath()
  spill(mine, slurp(fixturedir() .. '/' .. name))
  return mine
end

local function vaultspec(file, key, passphrase)
  return { kind = 'minivault', file = file, vaultkey = key, passphrase = passphrase }
end

local function memoryspec(key, value)
  return { kind = 'memory', values = { [key] = value } }
end

local function thechain(specs)
  return sekreto.sekreto({ providers = specs, plugins = { mv.minivault }, cache = false })
end

-- -------------------------------------------------------------- the file

local function anewvaultholdsnothing()
  local v = fresh()

  samelist(v:list(), {}, 'list')
  same(v:key(), 'master', 'key')

  local info = v:open()
  truth(info.master, 'the master key is not master')
  truth(info.write, 'the master key may not write')
  samelist(info.grants, {}, 'grants')
end

local function awrittensecretcomesback()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:set('db.pass', 'hunter2')

  same(v:get('api.token'), 'tok01', 'get')
  samelist(v:list(), { 'api.token', 'db.pass' }, 'list')
  truth(v:has('api.token'), 'has said no')
  truth(not v:has('nope'), 'has said yes to an unknown name')
  same(v:get('nope'), nil, 'an unknown name answered')

  -- A SECOND HANDLE on the same file, so the assertion is about the bytes
  -- rather than about what this handle happens to remember.
  same(openas(v:file(), nil, MASTER):get('api.token'), 'tok01', 'a new handle')
end

local function thefileisbinary()
  local v = fresh()
  v:set('api.token', 'tok01')

  local raw = slurp(v:file())
  same(raw:sub(1, 4), 'SKMV', 'the magic')

  -- NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
  -- the secret's name and its value are not, and neither is the
  -- passphrase that unwrapped them.
  for _, secret in ipairs({ 'api.token', 'tok01', MASTER }) do
    truth(nil == raw:find(secret, 1, true), secret .. ' is in the file')
  end

  truth(nil ~= raw:find('master', 1, true), 'the key id is not in the file')
end

local function rewritinganamereplacesit()
  local v = fresh()

  v:set('api.token', 'first')
  v:set('api.token', 'second')

  same(v:get('api.token'), 'second', 'get')
  samelist(v:list(), { 'api.token' }, 'one entry')
end

local function removedropsaname()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:set('db.pass', 'hunter2')
  v:remove('api.token')

  samelist(v:list(), { 'db.pass' }, 'list')
  same(v:get('api.token'), nil, 'a removed name answered')
  holds(refusal('remove again', function() v:remove('api.token') end),
    'no such secret: api.token', 'remove again')
end

local function abadnameisrefused()
  local v = fresh()

  holds(refusal('set', function() v:set('API.TOKEN', 'x') end), 'invalid name', 'set')
  holds(refusal('get', function() v:get('api..token') end), 'invalid name', 'get')
  holds(refusal('remove', function() v:remove('') end), 'invalid name', 'remove')
end

-- -------------------------------------------------------------- the keys

local function arestrictedkeyreadsitsgrants()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:set('db.pass', 'hunter2')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, false))

  local ci = openas(v:file(), 'ci', 'ci-passphrase')
  same(ci:get('api.token'), 'tok01', 'granted')

  -- THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and
  -- this key cannot derive its key, so the answer is the one a stranger
  -- gets: a miss.
  same(ci:get('db.pass'), nil, 'an ungranted name answered')
  samelist(ci:list(), { 'api.token' }, 'list')

  local info = ci:open()
  truth(not info.master, 'a restricted key reports master')
  truth(not info.write, 'a read-only key reports write')
  samelist(info.grants, { 'api.token' }, 'grants')
end

local function areadonlykeyrefusestowrite()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('reader', 'reader-passphrase', { 'api.token' }, false))
  v:grant(grantof('writer', 'writer-passphrase', { 'api.token' }, true))

  local reader = openas(v:file(), 'reader', 'reader-passphrase')
  holds(refusal('read-only', function() reader:set('api.token', 'x') end),
    'key reader is read-only', 'read-only')

  local writer = openas(v:file(), 'writer', 'writer-passphrase')
  writer:set('api.token', 'rewritten')

  same(v:get('api.token'), 'rewritten', 'the master sees it')
end

local function arestrictedkeycannotwriteanungrantedname()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, true))

  local ci = openas(v:file(), 'ci', 'ci-passphrase')
  holds(refusal('ungranted', function() ci:set('db.pass', 'x') end),
    'key ci was not granted db.pass', 'ungranted')
end

local function agrantednamethatdoesnotexistyet()
  local v = fresh()

  -- Granted BEFORE the name exists, which is the point: a deploy key is
  -- minted from a list of what a service will need.
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, false))

  local ci = openas(v:file(), 'ci', 'ci-passphrase')
  samelist(ci:list(), {}, 'nothing yet')
  same(ci:get('api.token'), nil, 'a name that does not exist answered')

  v:set('api.token', 'tok01')

  same(ci:get('api.token'), 'tok01', 'once written')
  samelist(ci:list(), { 'api.token' }, 'list')
end

local function themasterlistseverykey()
  local v = fresh()

  v:grant(grantof('ci', 'ci-passphrase', { 'db.pass', 'api.token' }, true))

  local keys = v:keys()
  same(#keys, 2, 'key count')

  same(keys[1].key, 'master', 'the master')
  truth(keys[1].master, 'the master is not master')
  samelist(keys[1].grants, {}, 'a master is granted nothing')

  same(keys[2].key, 'ci', 'the restricted key')
  truth(not keys[2].master, 'ci reports master')
  truth(keys[2].write, 'ci may not write')
  -- SORTED, so the record reads the same however the grant was spelled.
  samelist(keys[2].grants, { 'api.token', 'db.pass' }, 'grants')
end

local function themasteronlymethodsrefusearestrictedkey()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, true))

  local ci = openas(v:file(), 'ci', 'ci-passphrase')

  holds(refusal('keys', function() ci:keys() end),
    'listing the keys needs a master key', 'keys')
  holds(refusal('grant', function() ci:grant(grantof('x', 'y', {}, false)) end),
    'granting a key needs a master key', 'grant')
  holds(refusal('revoke', function() ci:revoke('master') end),
    'revoking a key needs a master key', 'revoke')
  holds(refusal('rotate', function() ci:rotate() end),
    'rotating the vault needs a master key', 'rotate')
  holds(refusal('remove', function() ci:remove('api.token') end),
    'removing a secret needs a master key', 'remove')
end

local function arepeatedkeyidisrefused()
  local v = fresh()

  v:grant(grantof('ci', 'p', {}, false))

  holds(refusal('repeated', function() v:grant(grantof('ci', 'q', {}, false)) end),
    'key already exists: ci', 'repeated')
  holds(refusal('no id', function() v:grant(grantof('', 'p', {}, false)) end),
    'a grant needs a key id', 'no id')
  holds(refusal('no passphrase', function() v:grant(grantof('x', '', {}, false)) end),
    'a grant needs a passphrase', 'no passphrase')
end

local function revokedropsakey()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, false))
  v:revoke('ci')

  local ci = openas(v:file(), 'ci', 'ci-passphrase')
  holds(refusal('revoked', function() ci:get('api.token') end), 'no such key: ci', 'revoked')
  holds(refusal('revoke again', function() v:revoke('ci') end), 'no such key: ci',
    'revoke again')
  holds(refusal('itself', function() v:revoke('master') end), 'a key cannot revoke itself',
    'itself')

  -- THE SECRET IS UNTOUCHED: revoking bars a key, not a value.
  same(v:get('api.token'), 'tok01', 'the secret stays')
end

local function rotatekeepsthesecrets()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:set('db.pass', 'hunter2')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, false))

  v:rotate()

  same(v:get('api.token'), 'tok01', 'api.token survives')
  same(v:get('db.pass'), 'hunter2', 'db.pass survives')
  samelist(v:list(), { 'api.token', 'db.pass' }, 'list')

  local keys = v:keys()
  same(#keys, 1, 'key count after rotate')
  same(keys[1].key, 'master', 'the only key')

  -- EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
  -- rings were sealed under passphrases this process does not have.
  local ci = openas(v:file(), 'ci', 'ci-passphrase')
  holds(refusal('ci is gone', function() ci:get('api.token') end), 'no such key: ci',
    'ci is gone')
end

-- ---------------------------------------------------------- the refusals

local function awrongpassphraseandamissingfile()
  local v = fresh()
  v:set('api.token', 'tok01')

  local wrong = openas(v:file(), nil, 'not-the-passphrase')
  holds(refusal('wrong passphrase', function() wrong:get('api.token') end),
    'wrong passphrase for key master, or a damaged vault', 'wrong passphrase')

  local unknown = openas(v:file(), 'nope', MASTER)
  holds(refusal('unknown key', function() unknown:get('api.token') end),
    'no such key: nope', 'unknown key')

  local missing = openas(WORK .. '/not-there.skmv', nil, MASTER)
  holds(refusal('missing file', function() missing:get('api.token') end),
    'no vault file', 'missing file')
end

local function adamagedfileisrefused()
  local v = fresh()
  v:set('api.token', 'tok01')
  local raw = slurp(v:file())

  local function refuses(what, want, made)
    local where = vaultpath()
    spill(where, made)
    local held = openas(where, nil, MASTER)
    holds(refusal(what, function() held:get('api.token') end), want, what)
  end

  -- Not a vault at all.
  refuses('not a vault', 'not a vault file', 'nonsense')
  -- Cut off part way through.
  refuses('truncated', 'truncated', raw:sub(1, #raw - 20))
  -- One byte of ciphertext flipped, which the GCM tag catches.
  refuses('flipped', 'damaged',
    raw:sub(1, #raw - 1) .. string.char(raw:byte(#raw) ~ 0xff))
  -- Trailing bytes, which a reader that stopped at the last record would
  -- have accepted.
  refuses('trailing', 'trailing bytes', raw .. 'junk')
end

local function creatingoveranexistingvaultisrefused()
  local v = fresh()

  holds(refusal('create over', function()
    mv.createvault(vaultopts(v:file(), nil, MASTER))
  end), 'vault file already exists', 'create over')
end

local function avaultneedsafileandapassphrase()
  holds(refusal('no file', function() mv.openvault(vaultopts('', nil, 'p')) end),
    'a vault needs a file', 'no file')
  holds(refusal('no passphrase', function() mv.openvault(vaultopts('v.skmv', nil, '')) end),
    'a vault needs a passphrase', 'no passphrase')
end

-- An EMPTY key is no key, so it means `master`. It is not a contrived
-- case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
-- expands to the empty string rather than to nothing at all.
local function anemptykeymeansthemasterkey()
  local vault = fresh()
  vault:set('api.token', 'tok01')

  local opened = openas(vault:file(), '', MASTER)
  same(opened:get('api.token'), 'tok01', 'api.token')
  same(opened:open().key, 'master', 'key')
end

local function createmakesthefileonlywhenasked()
  local where = vaultpath()

  local off = openas(where, nil, MASTER)
  holds(refusal('create off', function() off:get('api.token') end), 'no vault file',
    'create off')

  local options = vaultopts(where, nil, MASTER)
  options.create = true
  local on = mv.openvault(options)

  same(on:get('api.token'), nil, 'a new vault answered')
  on:set('api.token', 'tok01')
  same(on:get('api.token'), 'tok01', 'written')

  -- The file is there now, so the handle that refused reads it.
  same(openas(where, nil, MASTER):get('api.token'), 'tok01', 'the same file')
end

local function akeyidlongerthantheformatallows()
  local v = fresh()
  local big = string.rep('k', 300)

  holds(refusal('grant', function() v:grant(grantof(big, 'p', {}, false)) end),
    'key id is longer than 255 bytes', 'grant')
  holds(refusal('open', function() mv.openvault(vaultopts(v:file(), big, 'p')) end),
    'key id is longer than 255 bytes', 'open')

  -- AND THE VAULT IS UNHARMED: the refusal came before the write, so a
  -- 300-character id did not shift every field after it.
  same(#v:keys(), 1, 'key count')
end

local function theinfoacallergetscannotchangewhatthekeymaydo()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('reader', 'reader-passphrase', { 'api.token' }, false))

  local reader = openas(v:file(), 'reader', 'reader-passphrase')
  local info = reader:open()
  truth(not info.write, 'the reader key may write')

  -- A COPY, and the vault reads its own. Flipping the bit and adding a
  -- grant here is the defect the review round found in the canonical, and
  -- it changes nothing.
  info.write = true
  info.grants[#info.grants + 1] = 'db.pass'

  holds(refusal('still refused', function() reader:set('api.token', 'x') end),
    'key reader is read-only', 'still refused')
  samelist(reader:open().grants, { 'api.token' }, 'the grants the vault still reads')
end

local function arevokedkeystopsreading()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, false))

  -- OPEN AND READING FIRST, so the handle holds its derived keys.
  local ci = openas(v:file(), 'ci', 'ci-passphrase')
  same(ci:get('api.token'), 'tok01', 'before')

  v:revoke('ci')

  -- The live file no longer holds the key, and a handle that answered
  -- from memory here would make `revoke` a suggestion.
  holds(refusal('after', function() ci:get('api.token') end), 'no such key: ci', 'after')
end

local function aregrantedkeyid()
  local v = fresh()

  v:set('api.token', 'tok01')
  v:grant(grantof('ci', 'first-passphrase', { 'api.token' }, false))

  local ci = openas(v:file(), 'ci', 'first-passphrase')
  same(ci:get('api.token'), 'tok01', 'before')

  v:revoke('ci')
  v:grant(grantof('ci', 'second-passphrase', { 'api.token' }, false))

  -- SAME ID, DIFFERENT KEY. The handle re-derives because the sealed ring
  -- changed, and the old passphrase does not unwrap the new one.
  holds(refusal('the old passphrase', function() ci:get('api.token') end),
    'wrong passphrase for key ci, or a damaged vault', 'the old passphrase')

  same(openas(v:file(), 'ci', 'second-passphrase'):get('api.token'), 'tok01',
    'the new passphrase')
end

local function closeforgetsthederivedkeys()
  local v = fresh()

  v:set('api.token', 'tok01')
  same(v:get('api.token'), 'tok01', 'before')

  v:close()

  same(v:get('api.token'), 'tok01', 'after')
end

-- --------------------------------------------------- the committed files

--- Every port's vault holds the same keys and the same secrets, so the
--- assertions do not vary with which file this is.
local function readsthefixture(name)
  return function()
    local file = fixture(name)
    local owner = openas(file, nil, 'fixture-master')

    samelist(owner:list(), { 'api.token', 'db.pass', 'deep.nested.name' }, 'list')
    same(owner:get('api.token'), 'fixture-token', 'api.token')
    same(owner:get('db.pass'), 'fixture-pass', 'db.pass')
    same(owner:get('deep.nested.name'), 'fixture-deep', 'deep.nested.name')

    local ids = {}
    for at, info in ipairs(owner:keys()) do
      ids[at] = info.key
    end
    table.sort(ids)
    samelist(ids, { 'master', 'reader', 'writer' }, 'keys')

    local reader = openas(file, 'reader', 'fixture-reader')
    samelist(reader:list(), { 'api.token' }, 'reader list')
    same(reader:get('api.token'), 'fixture-token', 'reader reads')
    same(reader:get('db.pass'), nil, 'the reader key read db.pass')
    holds(refusal('reader writes', function() reader:set('api.token', 'x') end),
      'read-only', 'reader writes')

    local writer = openas(file, 'writer', 'fixture-writer')
    samelist(writer:list(), { 'db.pass' }, 'writer list')
    same(writer:get('db.pass'), 'fixture-pass', 'writer reads')

    -- The copy is this case's own, so writing it proves the round trip
    -- without touching the committed bytes.
    writer:set('db.pass', 'rewritten')
    same(owner:get('db.pass'), 'rewritten', 'the master sees it')
  end
end

-- ------------------------------------------------------------- the chain

local function avaultisonestoreinachain()
  local v = fresh()
  v:set('api.token', 'from the vault')

  local secrets = thechain({
    vaultspec(v:file(), nil, MASTER),
    memoryspec('DB_PASS', 'from memory'),
  })

  samelist(secrets:stores(), { 'minivault', 'memory' }, 'stores')
  samelist(secrets:sources(), { 'minivault:' .. v:file(), 'memory' }, 'sources')
  same(secrets:get('api.token'), 'from the vault', 'the vault')
  same(secrets:get('db.pass'), 'from memory', 'memory')
end

local function arestrictedkeyinachainfallsthrough()
  local v = fresh()

  v:set('api.token', 'from the vault')
  v:set('db.pass', 'also in the vault')
  v:grant(grantof('ci', 'ci-passphrase', { 'api.token' }, false))

  local secrets = thechain({
    vaultspec(v:file(), 'ci', 'ci-passphrase'),
    memoryspec('DB_PASS', 'from memory'),
  })

  same(secrets:get('api.token'), 'from the vault', 'the grant')
  -- A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
  -- than stopping at a store that holds the name but not for this key.
  same(secrets:get('db.pass'), 'from memory', 'falls through')
end

local function thevaultbehindastoreisreachable()
  local v = fresh()
  v:set('api.token', 'tok01')

  local secrets = thechain({ vaultspec(v:file(), nil, MASTER) })
  local api = mv.vaultof(secrets)

  samelist(api:list(), { 'api.token' }, 'list')

  -- A CHAIN READS; the API writes. Both see the same file.
  api:set('db.pass', 'written through the api')
  same(secrets:get('db.pass'), 'written through the api', 'the chain')
end

local function anamedstoreisreachedbyname()
  local first = fresh()
  first:set('api.token', 'first')
  local second = fresh()
  second:set('api.token', 'second')

  local app = vaultspec(first:file(), nil, MASTER)
  app.name = 'app'
  local ops = vaultspec(second:file(), nil, MASTER)
  ops.name = 'ops'

  local secrets = thechain({ app, ops })

  samelist(secrets:stores(), { 'app', 'ops' }, 'stores')
  same(mv.vaultof(secrets, 'app'):file(), first:file(), 'app')
  same(mv.vaultof(secrets, 'ops'):file(), second:file(), 'ops')

  -- A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in
  -- for it: picking one would be a guess, and the guess writes.
  holds(refusal('a store that is not there', function() mv.vaultof(secrets, 'nope') end),
    'no minivault store named nope in this chain', 'a store that is not there')
end

local function achainwithnovaultsaysso()
  local secrets = thechain({ memoryspec('API_TOKEN', 'tok01') })

  holds(refusal('no vault', function() mv.vaultof(secrets) end),
    'no minivault store in this chain', 'no vault')
end

local function achainmissingthefileisrefused()
  holds(refusal('no file', function() thechain({ vaultspec(nil, nil, 'p') }) end),
    'a vault needs a file', 'no file')
  holds(refusal('no passphrase', function() thechain({ vaultspec('v.skmv', nil, nil) }) end),
    'a vault needs a passphrase', 'no passphrase')
end

local function thefileisreachedatthefirstlookup()
  -- The file does not exist, and building the chain still succeeds: the
  -- handle is lazy, so a chain costs no PBKDF2 until a secret is actually
  -- wanted.
  local secrets = thechain({ vaultspec(WORK .. '/never.skmv', nil, MASTER) })

  holds(refusal('at the first lookup', function() secrets:get('api.token') end),
    'no vault file', 'at the first lookup')
end

-- ---------------------------------------------------------------- the run

WORK = os.tmpname()
os.remove(WORK)
os.execute("mkdir -p '" .. WORK .. "'")

testcase('newvault', anewvaultholdsnothing)
testcase('written', awrittensecretcomesback)
testcase('binary', thefileisbinary)
testcase('rewrite', rewritinganamereplacesit)
testcase('remove', removedropsaname)
testcase('badname', abadnameisrefused)
testcase('restricted', arestrictedkeyreadsitsgrants)
testcase('readonly', areadonlykeyrefusestowrite)
testcase('ungranted', arestrictedkeycannotwriteanungrantedname)
testcase('laternamed', agrantednamethatdoesnotexistyet)
testcase('keys', themasterlistseverykey)
testcase('masteronly', themasteronlymethodsrefusearestrictedkey)
testcase('repeatedid', arepeatedkeyidisrefused)
testcase('revoke', revokedropsakey)
testcase('rotate', rotatekeepsthesecrets)
testcase('wrongphrase', awrongpassphraseandamissingfile)
testcase('damaged', adamagedfileisrefused)
testcase('createover', creatingoveranexistingvaultisrefused)
testcase('needsfile', avaultneedsafileandapassphrase)
testcase('emptykey', anemptykeymeansthemasterkey)
testcase('createflag', createmakesthefileonlywhenasked)
testcase('longkeyid', akeyidlongerthantheformatallows)
testcase('infocopy', theinfoacallergetscannotchangewhatthekeymaydo)
testcase('revokedcached', arevokedkeystopsreading)
testcase('regranted', aregrantedkeyid)
testcase('close', closeforgetsthederivedkeys)

local files = fixtures()
if 0 == #files then
  FAILCOUNT = FAILCOUNT + 1
  print('FAIL - fixtures\n       no committed vault was found')
end
for _, name in ipairs(files) do
  testcase('fixture:' .. name, readsthefixture(name))
end

testcase('chain', avaultisonestoreinachain)
testcase('chainfallthrough', arestrictedkeyinachainfallsthrough)
testcase('api', thevaultbehindastoreisreachable)
testcase('namedstore', anamedstoreisreachedbyname)
testcase('novault', achainwithnovaultsaysso)
testcase('badconfig', achainmissingthefileisrefused)
testcase('lazy', thefileisreachedatthefirstlookup)

print()
print(PASSCOUNT .. ' passed, ' .. FAILCOUNT .. ' failed')

os.exit(0 == FAILCOUNT and 0 or 1)
