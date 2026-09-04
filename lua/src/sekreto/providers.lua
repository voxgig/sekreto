-- The providers a Sekreto chains together.
--
-- A provider answers one question: "do you have this secret?" It returns
-- the value, or nil to mean "ask the next one". Nothing else about a
-- provider is visible to the caller - which is the point: an app reads
-- `api.token` and never learns whether it came from the environment, a
-- .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
--
-- Two failure shapes, and they are never interchangeable. A store that
-- does not hold the secret is a MISS (nil) - the chain carries on. A
-- store that could not answer - bad credentials, unreachable host,
-- missing configuration - is an ERROR: falling through there would
-- quietly reach for a weaker store.
--
-- A provider is a plain table with two functions, `lookup` and
-- `describe`, and no lifecycle. It is duck-typed: anything with a
-- callable `lookup` is a provider, whatever built it.
--
-- A port of typescript's providers, which are canonical, following the
-- kotlin port's single-file shape.

local err = require('sekreto.err')
local name = require('sekreto.name')
local addr = require('sekreto.addr')
local json = require('sekreto.json')
local crypto = require('sekreto.crypto')
local http = require('sekreto.http')
local net = require('sekreto.net')
local sigv4 = require('sekreto.sigv4')

local fail = err.fail

local M = {}

--- Never renewed: a configured token does not expire.
local NEVER = math.maxinteger

-- ------------------------------------------------------------ the specs

--- What a credential field reports about itself.
local function setornot(value)
  if nil == value or '' == value then
    return '[unset]'
  end
  return '[set]'
end

--- Printed without its credentials.
---
--- Lua's `tostring` on a bare table prints an address, but anything that
--- walks a spec - a config dumper, a logging helper - would otherwise
--- reach the Vault token, the AWS secret access key and the Azure client
--- secret. Fields holding a credential report whether they are set, never
--- what they are.
local SPECMT = {
  __tostring = function(spec)
    return 'ProviderSpec(kind=' .. tostring(spec.kind) ..
      ', name=' .. tostring(spec.name) ..
      ', addr=' .. tostring(spec.addr) ..
      ', token=' .. setornot(spec.token) ..
      ', secret=' .. setornot(spec.secret) ..
      ', clientsecret=' .. setornot(spec.clientsecret) ..
      ', auth=' .. tostring(spec.auth) .. ')'
  end,
  __name = 'ProviderSpec',
}

local AUTHMT = {
  __tostring = function(auth)
    return 'AuthSpec(method=' .. tostring(auth.method) ..
      ', mount=' .. tostring(auth.mount) ..
      ', role=' .. tostring(auth.role) ..
      ', jwtfile=' .. tostring(auth.jwtfile) ..
      ', roleid=' .. tostring(auth.roleid) ..
      ', jwt=' .. setornot(auth.jwt) ..
      ', secretid=' .. setornot(auth.secretid) .. ')'
  end,
  __name = 'AuthSpec',
}

--- The declarative form of a provider, as used in config and in the
--- shared spec. `kind` picks the provider; everything else is that
--- kind's own.
function M.spec(fields)
  return setmetatable(fields or {}, SPECMT)
end

--- Logging in to a vault instead of being handed a token. `method` is
--- `kubernetes` or `approle`; `mount` defaults to the method name.
function M.authspec(fields)
  return setmetatable(fields or {}, AUTHMT)
end

-- -------------------------------------------------------------- helpers

--- The first candidate that is set and non-empty, or empty.
---
--- Walked with `select`, never with `ipairs` over a packed table: a nil
--- argument leaves a hole, and `ipairs` stops dead at the first one - so
--- `first(nil, os.getenv('AWS_ACCESS_KEY_ID'))` would answer empty with
--- the variable plainly set.
local function first(...)
  local count = select('#', ...)

  for index = 1, count do
    local candidate = select(index, ...)
    if nil ~= candidate and '' ~= candidate then
      return candidate
    end
  end

  return ''
end

M.first = first

local function trimslash(text)
  if '/' == text:sub(-1) then
    return text:sub(1, #text - 1)
  end
  return text
end

local function nonempty(value)
  return nil ~= value and '' ~= value
end

--- The whole of a file, or nil plus the reason.
---
--- Absence - of the file OR of a directory on the way to it - is "no
--- secrets here" and answers nil with no reason, so the caller can tell
--- it from a permission error, which is a store that could not answer.
--- The reason string is not consulted; it comes from the C library's
--- strerror and follows the machine's locale.
local function readfile(path)
  local handle, why, code = io.open(path, 'rb')

  if nil == handle then
    -- ENOENT (2) and ENOTDIR (20): the file is not there, or a component
    -- of the path is not a directory. Both mean "no secrets here".
    if 2 == code or 20 == code then
      return nil, nil
    end
    return nil, ((why or 'cannot read'):gsub('^.-: ', ''))
  end

  local text = handle:read('a')
  handle:close()

  if nil == text then
    return nil, 'cannot read'
  end

  return text
end

M.readfile = readfile

--- One JSON round-trip's result: the status, and the parsed body.
---
--- Network failure is always an error - an unreachable store is a store
--- that could not answer, and answering a miss there would fall silently
--- through to a weaker store.
local function fetchjson(method, url, headers, body)
  local res, why = http.request(method, url, headers, body)

  if nil == res then
    fail('sekreto: cannot reach ' .. addr.bare(url) .. ': ' .. why)
  end

  -- One byte over the bound is enough to know it was exceeded. An endless
  -- body is a store that could not answer, so this raises rather than
  -- returning a miss - the latter would fall through to a weaker store on
  -- an attacker's cue.
  if http.MAXBODY < res.raw then
    fail('sekreto: oversized response from ' .. addr.bare(url))
  end

  local parsed = json.parse(res.body)

  -- A success status promised JSON; a body that does not parse means the
  -- store could not answer coherently. Error statuses may carry any body
  -- - they are decided on status alone.
  if 200 == res.status and nil == parsed then
    fail('sekreto: malformed response from ' .. addr.bare(url))
  end

  return { status = res.status, body = parsed }
end

M.fetchjson = fetchjson

--- Milliseconds since the epoch, near enough for token renewal.
local function nowms()
  return os.time() * 1000
end

--- When a logged-in token must be renewed, from its expiry in seconds (a
--- JSON number, or a string as Azure IMDS sends it): now + max(seconds -
--- 60, 1). A missing or zero expiry means never renew.
local function renewtime(expires)
  local seconds = 0

  if 'number' == type(expires) then
    seconds = expires
  elseif 'string' == type(expires) then
    seconds = tonumber(expires) or 0
  end

  if seconds ~= seconds or 0 >= seconds then
    return NEVER
  end

  return nowms() + math.floor(math.max(seconds - 60, 1) * 1000)
end

M.renewtime = renewtime

--- What a finished child process left behind.
---
--- Both streams are drained concurrently and stdin is closed; see
--- native/sekretonet.c, which does the draining. Argv is an array and
--- never a shell string, and no secret is ever put on a command line.
local function runcmd(argv, overrides, command)
  local ran, why = net.exec(argv, overrides)

  if nil == ran then
    fail('sekreto: cannot run ' .. command .. ': ' .. why)
  end

  return ran.out, name.trim(ran.why), ran.status
end

M.runcmd = runcmd

--- The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.
local function awsnow()
  return os.date('!%Y%m%dT%H%M%SZ')
end

local function stripnewline(text)
  if '\n' == text:sub(-1) then
    return text:sub(1, #text - 1)
  end
  return text
end

-- ------------------------------------------------------- built-in kinds
--
-- The criterion for "built in" is needing nothing of the platform beyond
-- reading a local file: no socket, no TLS, no crypto, no child process.

--- Environment variables: `api.token` from `API_TOKEN`.
function M.env(prefix, source)
  return {
    lookup = function(secret)
      local key = name.envkey(secret, prefix)
      if nil == source then
        return os.getenv(key)
      end
      return source[key]
    end,
    describe = function()
      return 'env' .. (nonempty(prefix) and (':' .. prefix) or '')
    end,
  }
end

--- A `.env` file, read once, keyed exactly like the environment.
---
--- Loaded LAZILY. The `stores` corpus group puts a dotenv provider in a
--- chain and never looks anything up; an eager constructor would read
--- whatever `.env` happens to sit in the working directory.
function M.dotenv(file, prefix)
  local usefile = file or '.env'
  local values = nil

  local function load()
    if nil ~= values then
      return values
    end

    local text, why = readfile(usefile)

    if nil == text then
      if nil ~= why then
        fail('sekreto: dotenv provider cannot read ' .. usefile .. ': ' .. why)
      end
      -- An absent file, or an absent directory, means "no secrets here",
      -- exactly like the file provider.
      values = {}
    else
      values = name.parsedotenv(text)
    end

    return values
  end

  return {
    lookup = function(secret)
      return load()[name.envkey(secret, prefix)]
    end,
    describe = function()
      return 'dotenv:' .. usefile
    end,
  }
end

--- Literal values, keyed like environment variables. The shared spec uses
--- this to test chain behaviour without touching the outside world.
function M.memory(values, prefix)
  local usevalues = values or {}

  return {
    lookup = function(secret)
      return usevalues[name.envkey(secret, prefix)]
    end,
    describe = function()
      return 'memory' .. (nonempty(prefix) and (':' .. prefix) or '')
    end,
  }
end

--- A directory of one-secret-per-file entries, keyed like the
--- environment: `api.token` reads `<dir>/API_TOKEN`.
---
--- This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
--- secret, and a systemd credentials directory, so those all work with no
--- further configuration. Read on every lookup, never cached. One
--- trailing newline is stripped - tools that write these files disagree
--- about it, and a newline is never part of a secret on purpose.
function M.file(dir, prefix)
  local usedir = dir or ''

  return {
    lookup = function(secret)
      local path = ('' == usedir) and name.envkey(secret, prefix)
        or (trimslash(usedir) .. '/' .. name.envkey(secret, prefix))

      local text, why = readfile(path)

      if nil == text then
        if nil ~= why then
          fail('sekreto: file provider cannot read ' .. path .. ': ' .. why)
        end
        return nil
      end

      if '\r\n' == text:sub(-2) then
        return text:sub(1, #text - 2)
      end
      if '\n' == text:sub(-1) then
        return text:sub(1, #text - 1)
      end

      return text
    end,
    describe = function()
      return 'file:' .. usedir
    end,
  }
end

-- ------------------------------------------------------------ hashicorp

--- HashiCorp Vault.
---
--- KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api`
--- and takes the `token` field of `data.data`. KV v1 reads
--- `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means
--- "not here" - a miss - so a vault can sit in a chain with fallbacks.
---
--- A Vault Enterprise namespace rides the X-Vault-Namespace header, on
--- logins as well as reads.
---
--- Instead of being handed a token, the provider can log in: Kubernetes
--- auth (the pod's service-account JWT, from its conventional path) or
--- AppRole. A failed login is an error, never a miss - it means this
--- store could not answer at all.
function M.hashicorp(useaddr, token, mount, kv, vaultnamespace, auth)
  local address = useaddr or ''
  local usemount = nonempty(mount) and mount or 'secret'
  local usekv = kv or 2

  -- A version typo like kv: 3 must not quietly behave as v2 and turn its
  -- 404s into misses; there is nothing safe to assume it meant.
  if 1 ~= usekv and 2 ~= usekv then
    fail('sekreto: hashicorp: unsupported kv version: ' .. json.numstr(usekv))
  end

  local livetoken = nonempty(token) and token or nil
  local renewat = NEVER

  local function baseheaders()
    local out = {}
    if nonempty(vaultnamespace) then
      out[#out + 1] = { 'X-Vault-Namespace', vaultnamespace }
    end
    return out
  end

  local function login()
    if nil == auth then
      fail('sekreto: hashicorp: no token and no auth method')
    end

    local authmount = first(auth.mount, auth.method)
    local url = trimslash(address) .. '/v1/auth/' .. authmount .. '/login'
    local body

    if 'kubernetes' == auth.method then
      local jwt = auth.jwt

      if nil == jwt then
        local file = auth.jwtfile or
          '/var/run/secrets/kubernetes.io/serviceaccount/token'
        local text = readfile(file)
        if nil == text then
          fail('sekreto: hashicorp: cannot read jwt file ' .. file)
        end
        jwt = name.trim(text)
      end

      body = json.obj({ { 'role', auth.role or '' }, { 'jwt', jwt } })
    elseif 'approle' == auth.method then
      body = json.obj({
        { 'role_id', auth.roleid or '' },
        { 'secret_id', auth.secretid or '' },
      })
    else
      fail('sekreto: hashicorp: unknown auth method: ' .. tostring(auth.method))
    end

    local res = fetchjson('POST', url, baseheaders(), json.stringify(body))
    local got = json.text(json.dig(res.body, 'auth', 'client_token'))

    if 200 ~= res.status or nil == got or '' == got then
      fail('sekreto: hashicorp login failed: ' .. res.status .. ': ' .. url)
    end

    renewat = renewtime(json.dig(res.body, 'auth', 'lease_duration'))

    return got
  end

  return {
    lookup = function(secret)
      addr.checkaddr(address)

      if nil == livetoken or nowms() >= renewat then
        livetoken = login()
      end

      local ref = name.vaultref(secret)
      local base = trimslash(address) .. '/v1/' .. usemount
      local url = (1 == usekv) and (base .. '/' .. ref.path)
        or (base .. '/data/' .. ref.path)

      local headers = baseheaders()
      headers[#headers + 1] = { 'X-Vault-Token', livetoken or '' }

      local res = fetchjson('GET', url, headers)

      if 404 == res.status then
        return nil
      end

      if 200 ~= res.status then
        fail('sekreto: hashicorp error: ' .. res.status .. ': ' .. url)
      end

      local data = (1 == usekv) and json.dig(res.body, 'data')
        or json.dig(res.body, 'data', 'data')

      return json.text(json.dig(data, ref.field))
    end,
    describe = function()
      return 'hashicorp:' .. address .. '/' .. usemount
    end,
  }
end

-- ----------------------------------------------------------------- boru

--- Does this boru failure mean "no such secret" rather than "I could not
--- answer"? Matched on boru's own wording for a missing alias.
function M.borumiss(why)
  return nil ~= why:find('no alias named', 1, true)
end

--- A boru vault (https://github.com/boru-lang/boru).
---
--- Two ways in, both boru's own. With no `addr`, the CLI:
--- `boru vault get --reveal <alias>` prints the secret on stdout and
--- nothing else. The passphrase is read by boru itself from
--- BORU_VAULT_PASSPHRASE; sekreto never accepts it as config and never
--- puts it on a command line, where the process table would publish it.
---
--- With an `addr`, boru's wire protocol: a read-only, HashiCorp-shaped
--- provision API. A sekreto name is already a valid boru alias, and boru
--- aliases keep their dots, so `api.token` is the single path segment
--- `api.token` - not the `api`/`token` split a HashiCorp KV gets.
function M.boru(command, namespace, home, useaddr, token, mount)
  local usecommand = nonempty(command) and command or 'boru'
  local address = (nil == useaddr) and '' or trimslash(useaddr)
  local usetoken = token or ''
  local usemount = nonempty(mount) and mount or 'secret'

  local function wirelookup(secret)
    addr.checkaddr(address)

    local alias = nonempty(namespace) and (namespace .. '/' .. secret) or secret
    local url = address .. '/v1/' .. usemount .. '/data/' .. alias

    local res = fetchjson('GET', url, { { 'X-Vault-Token', usetoken } })

    if 404 == res.status then
      return nil
    end

    if 200 ~= res.status then
      fail('sekreto: boru serve error: ' .. res.status .. ': ' .. url)
    end

    return json.text(json.dig(res.body, 'data', 'data', 'value'))
  end

  return {
    lookup = function(secret)
      name.checkname(secret)

      if '' ~= address then
        return wirelookup(secret)
      end

      local alias = nonempty(namespace) and (namespace .. ':' .. secret) or secret

      -- BORU_HOME is the only variable sekreto sets for the child; the
      -- passphrase is boru's own to read from BORU_VAULT_PASSPHRASE, and
      -- is never config here and never on a command line.
      local overrides = nil
      if nonempty(home) then
        overrides = { 'BORU_HOME=' .. home }
      end

      local out, why, status = runcmd(
        { usecommand, 'vault', 'get', '--reveal', alias }, overrides, usecommand
      )

      if 0 == status then
        -- boru prints the value and one newline, and nothing else.
        return stripnewline(out)
      end

      -- "no alias named" is boru saying it does not hold this secret,
      -- which is a miss. A locked vault or a wrong passphrase is not -
      -- treating it as one would fall through to a weaker store without
      -- saying so.
      if M.borumiss(why) then
        return nil
      end

      fail('sekreto: boru vault error: ' ..
        (('' == why) and ('exit ' .. status) or why))
    end,
    describe = function()
      if '' ~= address then
        return 'boru:' .. address
      end
      return 'boru' .. (nonempty(namespace) and (':' .. namespace) or '')
    end,
  }
end

-- ----------------------------------------------------------- secretspec

--- Does this SecretSpec failure mean "no such secret" rather than "I
--- could not answer"?
---
--- MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
--- `Provider backend 'keyring' not found`, which is a store that could
--- not answer at all - and reading that as a miss is the worst failure
--- this library has, because the chain then falls through to a weaker
--- store without saying so. The key is required to appear, so the two
--- cannot be confused.
function M.secretspecmiss(why, key)
  return nil ~= why:find("Secret '" .. key .. "' not found", 1, true)
end

--- SecretSpec (https://secretspec.dev), read through its CLI.
---
--- `backend` selects one of SecretSpec's own backends (`--provider`) and
--- is called `backend` here only because `provider` already means a
--- sekreto provider. A reason is required, not optional: SecretSpec
--- records every read in an audit log and refuses to read without one.
function M.secretspec(command, file, profile, backend, reason, prefix)
  local usecommand = nonempty(command) and command or 'secretspec'

  return {
    lookup = function(secret)
      local key = name.envkey(secret, prefix)

      local argv = { usecommand }
      if nonempty(file) then
        argv[#argv + 1] = '--file'
        argv[#argv + 1] = file
      end
      argv[#argv + 1] = 'get'
      argv[#argv + 1] = key
      if nonempty(backend) then
        argv[#argv + 1] = '--provider'
        argv[#argv + 1] = backend
      end
      if nonempty(profile) then
        argv[#argv + 1] = '--profile'
        argv[#argv + 1] = profile
      end
      argv[#argv + 1] = '--reason'
      argv[#argv + 1] = first(reason, 'sekreto')

      local out, why, status = runcmd(argv, nil, usecommand)

      if 0 == status then
        return stripnewline(out)
      end

      if M.secretspecmiss(why, key) then
        return nil
      end

      fail('sekreto: secretspec error: ' ..
        (('' == why) and ('exit ' .. status) or why))
    end,
    describe = function()
      return 'secretspec' .. (nonempty(backend) and (':' .. backend) or '')
    end,
  }
end

-- ------------------------------------------------------------------ aws

--- Region and credentials, from config first and the standard AWS_*
--- environment variables second. Missing either is an error: an AWS store
--- with no credentials could not answer.
local function awsauth(region, keyid, secret, session)
  local useregion = first(region, os.getenv('AWS_REGION'), os.getenv('AWS_DEFAULT_REGION'))
  local usekeyid = first(keyid, os.getenv('AWS_ACCESS_KEY_ID'))
  local usesecret = first(secret, os.getenv('AWS_SECRET_ACCESS_KEY'))
  local usesession = first(session, os.getenv('AWS_SESSION_TOKEN'))

  if '' == useregion then
    fail('sekreto: aws: no region (set region or AWS_REGION)')
  end
  if '' == usekeyid or '' == usesecret then
    fail('sekreto: aws: no credentials' ..
      ' (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)')
  end

  return {
    region = useregion,
    keyid = usekeyid,
    secret = usesecret,
    session = ('' == usesession) and nil or usesession,
  }
end

M.awsauth = awsauth

--- One signed call to an AWS JSON-1.1 API.
local function awscall(region, keyid, secret, session, useaddr, service, target, payload)
  local auth = awsauth(region, keyid, secret, session)

  -- The China partition lives under its own suffix; every other
  -- commercial region is plain amazonaws.com.
  local suffix = ('cn-' == auth.region:sub(1, 3)) and '.amazonaws.com.cn'
    or '.amazonaws.com'
  local address = first(useaddr, 'https://' .. service .. '.' .. auth.region .. suffix)
  addr.checkaddr(address)

  local url = trimslash(address) .. '/'

  local extras = {
    { 'content-type', 'application/x-amz-json-1.1' },
    { 'x-amz-target', target },
  }

  local signed = sigv4.sigv4({
    method = 'POST',
    url = url,
    service = service,
    region = auth.region,
    keyid = auth.keyid,
    secret = auth.secret,
    datetime = awsnow(),
    headers = extras,
    body = payload,
    session = auth.session,
  })

  local headers = {}
  for _, pair in ipairs(extras) do
    headers[#headers + 1] = pair
  end
  for _, pair in ipairs(signed) do
    headers[#headers + 1] = pair
  end

  return fetchjson('POST', url, headers, payload)
end

--- Does this AWS error body name one of the not-found types? Those are a
--- miss; every other failure is a store that could not answer.
local function awsmiss(body, ...)
  local errtype = json.asstr(json.dig(body, '__type'))
  if nil == errtype then
    return false
  end

  for _, want in ipairs({ ... }) do
    if nil ~= errtype:find(want, 1, true) then
      return true
    end
  end

  return false
end

M.awsmiss = awsmiss

--- AWS Secrets Manager.
---
--- `api.token` reads the secret named `api` (the vaultref path) and takes
--- the `token` field of its JSON SecretString - the AWS idiom of one JSON
--- map per secret. A SecretString that is not JSON is the value itself,
--- under the conventional field `value`.
function M.awssecrets(region, keyid, secret, session, useaddr)
  return {
    lookup = function(name_)
      local ref = name.vaultref(name_)

      local res = awscall(
        region, keyid, secret, session, useaddr,
        'secretsmanager', 'secretsmanager.GetSecretValue',
        json.stringify(json.obj({ { 'SecretId', ref.path } }))
      )

      if 400 == res.status and awsmiss(res.body, 'ResourceNotFoundException') then
        return nil
      end

      if 200 ~= res.status then
        fail('sekreto: aws secretsmanager error: ' .. res.status)
      end

      local text = json.asstr(json.dig(res.body, 'SecretString'))

      if nil == text then
        -- A binary secret has no fields to address; only the conventional
        -- `value` field can mean "the bytes themselves".
        local bin = json.asstr(json.dig(res.body, 'SecretBinary'))
        if nil ~= bin and 'value' == ref.field then
          local decoded = crypto.unbase64(bin)
          if nil == decoded then
            fail('sekreto: aws secretsmanager: undecodable secret')
          end
          return decoded
        end
        return nil
      end

      local parsed = json.parse(text)

      if json.isobj(parsed) then
        return json.text(parsed.vals[ref.field])
      end

      -- A plain-string secret is the whole value; it has no named fields.
      if 'value' == ref.field then
        return text
      end

      return nil
    end,
    -- Config only, never the environment: describe() feeds the spec's
    -- sources group, which must answer the same everywhere.
    describe = function()
      return 'awssecrets:' .. (region or '')
    end,
  }
end

--- AWS SSM Parameter Store.
---
--- `db.pass.main` reads the parameter `/db/pass/main` (under an optional
--- prefix path), decrypted. Parameter Store carries flat strings, so
--- there is no field indirection.
function M.awsparams(region, keyid, secret, session, useaddr, prefix)
  return {
    lookup = function(name_)
      local payload = json.obj({
        { 'Name', name.awsparam(name_, prefix) },
        { 'WithDecryption', true },
      })

      local res = awscall(
        region, keyid, secret, session, useaddr,
        'ssm', 'AmazonSSM.GetParameter', json.stringify(payload)
      )

      if 400 == res.status and awsmiss(res.body, 'ParameterNotFound') then
        return nil
      end

      if 200 ~= res.status then
        fail('sekreto: aws ssm error: ' .. res.status)
      end

      return json.text(json.dig(res.body, 'Parameter', 'Value'))
    end,
    describe = function()
      return 'awsparams:' .. (region or '') .. (prefix or '')
    end,
  }
end

-- ------------------------------------------------------------------ gcp

--- GCP Secret Manager.
---
--- `api.token` reads secret `api_token` (dots flattened to `_`; Secret
--- Manager ids have no hierarchy and reject dots), latest version. The
--- token comes from config, then GOOGLE_OAUTH_ACCESS_TOKEN, then the
--- GCE/GKE metadata server - so on Google's own platform no credential
--- configuration is needed at all.
---
--- The metadata call itself is plain http to a link-local host by
--- platform design and carries no credential, so `checkaddr` guards the
--- Secret Manager address instead.
function M.gcpsecrets(project, token, useaddr, metadataaddr)
  local livetoken = nil
  local renewat = NEVER

  local function usemetadataaddr()
    if nonempty(metadataaddr) then
      return metadataaddr
    end

    local host = os.getenv('GCE_METADATA_HOST')
    if nonempty(host) then
      return 'http://' .. host
    end

    return 'http://metadata.google.internal'
  end

  local function login()
    local configured = first(token, os.getenv('GOOGLE_OAUTH_ACCESS_TOKEN'))
    if '' ~= configured then
      return configured
    end

    local url = trimslash(usemetadataaddr()) ..
      '/computeMetadata/v1/instance/service-accounts/default/token'

    local res = fetchjson('GET', url, { { 'Metadata-Flavor', 'Google' } })
    local got = json.text(json.dig(res.body, 'access_token'))

    if 200 ~= res.status or nil == got or '' == got then
      fail('sekreto: gcp: no token and metadata server did not answer')
    end

    renewat = renewtime(json.dig(res.body, 'expires_in'))

    return got
  end

  return {
    lookup = function(secret)
      local useproject = project or ''
      if '' == useproject then
        fail('sekreto: gcp: no project')
      end

      local address = first(useaddr, 'https://secretmanager.googleapis.com')
      addr.checkaddr(address)

      if nil == livetoken or nowms() >= renewat then
        livetoken = login()
      end

      local url = trimslash(address) .. '/v1/projects/' .. useproject ..
        '/secrets/' .. name.flatname(secret, '_') .. '/versions/latest:access'

      local res = fetchjson('GET', url, { { 'authorization', 'Bearer ' .. livetoken } })

      if 404 == res.status then
        return nil
      end

      if 200 ~= res.status then
        fail('sekreto: gcp error: ' .. res.status .. ': ' .. url)
      end

      local data = json.asstr(json.dig(res.body, 'payload', 'data'))
      if nil == data then
        return nil
      end

      local decoded = crypto.unbase64(data)
      if nil == decoded then
        fail('sekreto: gcp: undecodable secret')
      end

      return decoded
    end,
    describe = function()
      return 'gcpsecrets:' .. (project or '')
    end,
  }
end

-- ---------------------------------------------------------------- azure

local AZURERESOURCE = 'https://vault.azure.net'

--- Azure Key Vault.
---
--- `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
--- names allow nothing else), current version. The token comes from
--- config, then a client-credentials login when tenant/clientid/
--- clientsecret are given, then the IMDS managed-identity endpoint.
function M.azuresecrets(vault, token, tenant, clientid, clientsecret,
  loginaddr, imdsaddr, apiversion)
  local livetoken = nil
  local renewat = NEVER

  local function login()
    if nonempty(token) then
      return token
    end

    if nonempty(tenant) and nonempty(clientid) and nonempty(clientsecret) then
      local useloginaddr = first(loginaddr, 'https://login.microsoftonline.com')
      addr.checkaddr(useloginaddr)

      local url = trimslash(useloginaddr) .. '/' .. tenant .. '/oauth2/v2.0/token'
      local form = 'grant_type=client_credentials&client_id=' ..
        sigv4.uriescape(clientid) ..
        '&client_secret=' .. sigv4.uriescape(clientsecret) ..
        '&scope=' .. sigv4.uriescape(AZURERESOURCE .. '/.default')

      local res = fetchjson(
        'POST', url,
        { { 'content-type', 'application/x-www-form-urlencoded' } },
        form
      )

      local got = json.text(json.dig(res.body, 'access_token'))
      if 200 ~= res.status or nil == got or '' == got then
        fail('sekreto: azure login failed: ' .. res.status)
      end

      renewat = renewtime(json.dig(res.body, 'expires_in'))
      return got
    end

    local imds = trimslash(first(imdsaddr, 'http://169.254.169.254')) ..
      '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' ..
      sigv4.uriescape(AZURERESOURCE)

    local res = fetchjson('GET', imds, { { 'Metadata', 'true' } })

    local got = json.text(json.dig(res.body, 'access_token'))
    if 200 ~= res.status or nil == got or '' == got then
      fail('sekreto: azure: no token, no client credentials, and IMDS did not answer')
    end

    -- IMDS sends expires_in as a STRING, unlike everyone else.
    renewat = renewtime(json.dig(res.body, 'expires_in'))
    return got
  end

  return {
    lookup = function(secret)
      local usevault = vault or ''
      if '' == usevault then
        fail('sekreto: azure: no vault')
      end

      -- Only an explicit scheme is a URL; a vault NAMED httpvault must
      -- still become https://httpvault.vault.azure.net.
      local vaulturl
      if 'http://' == usevault:sub(1, 7) or 'https://' == usevault:sub(1, 8) then
        vaulturl = usevault
      else
        vaulturl = 'https://' .. usevault .. '.vault.azure.net'
      end
      addr.checkaddr(vaulturl)

      if nil == livetoken or nowms() >= renewat then
        livetoken = login()
      end

      local url = trimslash(vaulturl) .. '/secrets/' .. name.flatname(secret, '-') ..
        '?api-version=' .. first(apiversion, '7.4')

      local res = fetchjson('GET', url, { { 'authorization', 'Bearer ' .. livetoken } })

      if 404 == res.status then
        return nil
      end

      if 200 ~= res.status then
        fail('sekreto: azure error: ' .. res.status .. ': ' .. addr.bare(url))
      end

      return json.text(json.dig(res.body, 'value'))
    end,
    describe = function()
      return 'azuresecrets:' .. (vault or '')
    end,
  }
end

-- ---------------------------------------------------------- 1password

--- 1Password, through a Connect server.
---
--- The item titled `api.token` (titles keep their dots), in the named
--- vault. The value is the field with purpose PASSWORD, or the field
--- labelled `value`. A vault that cannot be found is an error - config
--- names it, so its absence is a broken store, not a missing secret.
function M.onepassword(useaddr, token, vault)
  local vaultid = nil

  local function auth()
    return { { 'authorization', 'Bearer ' .. (token or '') } }
  end

  local function resolvevault(address)
    local want = vault or ''
    if '' == want then
      fail('sekreto: onepassword: no vault')
    end

    local res = fetchjson('GET', address .. '/v1/vaults', auth())
    local list = json.asarr(res.body)

    if 200 ~= res.status or nil == list then
      fail('sekreto: onepassword error: ' .. res.status .. ': listing vaults')
    end

    for _, entry in ipairs(list) do
      local id = json.text(json.dig(entry, 'id'))
      if want == id or want == json.text(json.dig(entry, 'name')) then
        return id or ''
      end
    end

    fail('sekreto: onepassword: no vault named ' .. want)
  end

  return {
    lookup = function(secret)
      name.checkname(secret)

      local address = trimslash(useaddr or '')
      if '' == address then
        fail('sekreto: onepassword: no addr')
      end
      addr.checkaddr(address)

      if nil == vaultid then
        vaultid = resolvevault(address)
      end

      local filter = sigv4.uriescape('title eq "' .. secret .. '"')
      local found = fetchjson(
        'GET', address .. '/v1/vaults/' .. vaultid .. '/items?filter=' .. filter, auth()
      )

      local items = json.asarr(found.body)
      if 200 ~= found.status or nil == items then
        fail('sekreto: onepassword error: ' .. found.status .. ': finding ' .. secret)
      end

      if 0 == #items then
        return nil
      end

      local item = fetchjson(
        'GET',
        address .. '/v1/vaults/' .. vaultid .. '/items/' ..
          (json.text(json.dig(items[1], 'id')) or ''),
        auth()
      )

      if 200 ~= item.status then
        fail('sekreto: onepassword error: ' .. item.status .. ': reading ' .. secret)
      end

      local fields = json.asarr(json.dig(item.body, 'fields')) or {}

      for _, entry in ipairs(fields) do
        if 'PASSWORD' == json.asstr(json.dig(entry, 'purpose')) then
          return json.text(json.dig(entry, 'value'))
        end
      end
      for _, entry in ipairs(fields) do
        if 'value' == json.asstr(json.dig(entry, 'label')) then
          return json.text(json.dig(entry, 'value'))
        end
      end

      return nil
    end,
    describe = function()
      return 'onepassword:' .. (vault or '')
    end,
  }
end

-- ------------------------------------------------------------- doppler

--- Doppler.
---
--- The whole config is downloaded once - Doppler's own bulk endpoint -
--- and answered from memory, like a remote .env: `api.token` is the
--- `API_TOKEN` entry. A failed load caches nothing, so it retries.
function M.doppler(token, project, config, useaddr)
  local values = nil

  local function load()
    if nil ~= values then
      return values
    end

    local address = trimslash(first(useaddr, 'https://api.doppler.com'))
    addr.checkaddr(address)

    local url = address .. '/v3/configs/config/secrets/download?format=json'
    if nonempty(project) then
      url = url .. '&project=' .. sigv4.uriescape(project)
    end
    if nonempty(config) then
      url = url .. '&config=' .. sigv4.uriescape(config)
    end

    local res = fetchjson(
      'GET', url, { { 'authorization', 'Bearer ' .. (token or '') } }
    )

    local body = json.asobj(res.body)
    if 200 ~= res.status or nil == body then
      fail('sekreto: doppler error: ' .. res.status)
    end

    local loaded = {}
    for _, key in ipairs(body.keys) do
      local text = json.text(body.vals[key])
      if nil ~= text then
        loaded[key] = text
      end
    end

    values = loaded
    return loaded
  end

  return {
    -- The `prefix` option is deliberately not consulted by this kind.
    lookup = function(secret)
      return load()[name.envkey(secret)]
    end,
    describe = function()
      return 'doppler' ..
        (nonempty(project) and (':' .. project .. '/' .. (config or '')) or '')
    end,
  }
end

-- ------------------------------------------------------------ infisical

--- Infisical.
---
--- `api.token` reads the secret keyed `API_TOKEN` at a secret path in one
--- environment of a project. Auth is a token, or a universal-auth
--- (machine identity) login with clientid/clientsecret.
function M.infisical(useaddr, token, clientid, clientsecret, project, environment, path)
  local livetoken = nil
  local renewat = NEVER

  local function login(address)
    if nonempty(token) then
      return token
    end

    if not nonempty(clientid) or not nonempty(clientsecret) then
      fail('sekreto: infisical: no token and no client credentials')
    end

    local body = json.obj({
      { 'clientId', clientid },
      { 'clientSecret', clientsecret },
    })

    local res = fetchjson(
      'POST', address .. '/api/v1/auth/universal-auth/login',
      { { 'content-type', 'application/json' } }, json.stringify(body)
    )

    local got = json.text(json.dig(res.body, 'accessToken'))
    if 200 ~= res.status or nil == got or '' == got then
      fail('sekreto: infisical login failed: ' .. res.status)
    end

    -- camelCase, unlike everyone else's expires_in.
    renewat = renewtime(json.dig(res.body, 'expiresIn'))

    return got
  end

  return {
    lookup = function(secret)
      local address = trimslash(first(useaddr, 'https://app.infisical.com'))
      addr.checkaddr(address)

      local useproject = project or ''
      local useenvironment = environment or ''
      if '' == useproject or '' == useenvironment then
        fail('sekreto: infisical: no project/environment')
      end

      if nil == livetoken or nowms() >= renewat then
        livetoken = login(address)
      end

      local url = address .. '/api/v3/secrets/raw/' .. name.envkey(secret) ..
        '?workspaceId=' .. sigv4.uriescape(useproject) ..
        '&environment=' .. sigv4.uriescape(useenvironment) ..
        '&secretPath=' .. sigv4.uriescape(first(path, '/'))

      local res = fetchjson('GET', url, { { 'authorization', 'Bearer ' .. livetoken } })

      if 404 == res.status then
        return nil
      end

      if 200 ~= res.status then
        fail('sekreto: infisical error: ' .. res.status)
      end

      return json.text(json.dig(res.body, 'secret', 'secretValue'))
    end,
    describe = function()
      return 'infisical:' .. (project or '') .. '/' .. (environment or '')
    end,
  }
end

-- ------------------------------------------------------------- the list

--- Every kind this build knows, in the order they are documented.
M.KINDS = {
  'env', 'dotenv', 'memory', 'file',
  'hashicorp', 'boru', 'secretspec',
  'awssecrets', 'awsparams', 'gcpsecrets', 'azuresecrets',
  'onepassword', 'doppler', 'infisical',
}

--- Build a provider from its declarative form - the same shape the shared
--- spec and an app's config file use.
function M.makeprovider(spec)
  local kind = spec.kind

  if 'env' == kind then
    return M.env(spec.prefix)
  elseif 'dotenv' == kind then
    return M.dotenv(spec.file or '.env', spec.prefix)
  elseif 'memory' == kind then
    return M.memory(spec.values, spec.prefix)
  elseif 'file' == kind then
    return M.file(spec.dir or '', spec.prefix)
  elseif 'hashicorp' == kind then
    return M.hashicorp(spec.addr, spec.token, spec.mount, spec.kv,
      spec.vaultnamespace, spec.auth)
  elseif 'boru' == kind then
    return M.boru(spec.command, spec.namespace, spec.home, spec.addr,
      spec.token, spec.mount)
  elseif 'awssecrets' == kind then
    return M.awssecrets(spec.region, spec.keyid, spec.secret, spec.session, spec.addr)
  elseif 'awsparams' == kind then
    return M.awsparams(spec.region, spec.keyid, spec.secret, spec.session,
      spec.addr, spec.prefix)
  elseif 'gcpsecrets' == kind then
    return M.gcpsecrets(spec.project, spec.token, spec.addr, spec.metadataaddr)
  elseif 'azuresecrets' == kind then
    return M.azuresecrets(spec.vault, spec.token, spec.tenant, spec.clientid,
      spec.clientsecret, spec.loginaddr, spec.imdsaddr, spec.apiversion)
  elseif 'onepassword' == kind then
    return M.onepassword(spec.addr, spec.token, spec.vault)
  elseif 'doppler' == kind then
    return M.doppler(spec.token, spec.project, spec.config, spec.addr)
  elseif 'infisical' == kind then
    return M.infisical(spec.addr, spec.token, spec.clientid, spec.clientsecret,
      spec.project, spec.environment, spec.path)
  elseif 'secretspec' == kind then
    return M.secretspec(spec.command, spec.file, spec.profile, spec.backend,
      spec.reason, spec.prefix)
  end

  fail('sekreto: unknown provider kind: ' .. tostring(kind))
end

return M
