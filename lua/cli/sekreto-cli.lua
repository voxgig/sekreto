-- A tiny app that needs a secret.
--
-- It asks sekreto for `api.token` and calls the token-protected API with
-- it. Every port ships this same CLI, and test/integration.sh runs all of
-- them against the same server from every secret source - which is what
-- proves the library, rather than the spec alone.
--
-- Usage: lua5.4 cli/sekreto-cli.lua <api-url>
--            [--source <source>] [--store <name>]
--
-- Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
--          gcpsecrets azuresecrets onepassword doppler infisical
--          secretspec chain
--
-- Each source's configuration arrives in the environment variables its
-- own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
-- in chainfor below.

-- The suite runs this from an EMPTY working directory with the
-- environment wiped, so the library is found from this script's own path
-- and from nothing else.
local root = (arg[0] or ''):match('^(.*)/cli/[^/]+$') or '.'
package.path = root .. '/src/?.lua;' .. root .. '/test/?.lua;' .. package.path

-- voxgig/plugin: already on the path, or a sibling checkout (see
-- test/pluginhome.lua). The library requires it by name and searches no
-- path of its own.
require('pluginhome').pluginpath()

local sekreto = require('sekreto')

-- THE FULL SET, passed to Sekreto. The CLI is asked for any provider kind
-- on the command line, so it is the one consumer that legitimately wants
-- all ten plugins; an app passes the one or two it configures.
local allplugins = require('sekreto.plugins').allplugins

-- The HTTP client and the JSON reader this CLI uses for the API call
-- ITSELF - not for a secret. Both live under plugins/ because lua has
-- neither in its standard library and a core that carried them would
-- carry a socket.
local httpjson = require('sekreto.plugins.httpjson')
local json = require('sekreto.plugins.json')

local LANG = 'lua'

local function envor(name, fallback)
  local value = os.getenv(name)
  if nil == value or '' == value then
    return fallback
  end
  return value
end

--- An environment value, or nil when it is absent OR empty: "not
--- configured" and "configured empty" mean the same thing everywhere in
--- this library.
local function envopt(name)
  local value = os.getenv(name)
  if nil == value or '' == value then
    return nil
  end
  return value
end

local function chainfor(source)
  local envspec = sekreto.spec({ kind = 'env', prefix = envopt('SEKRETO_PREFIX') })
  local dotenvspec = sekreto.spec({
    kind = 'dotenv', file = envor('SEKRETO_DOTENV', '.env'),
  })
  local filespec = sekreto.spec({
    kind = 'file', dir = envor('SEKRETO_FILEDIR', '/run/secrets'),
  })

  local vaultauth = envopt('VAULT_AUTH')
  local hashicorpspec = sekreto.spec({
    kind = 'hashicorp',
    addr = envor('VAULT_ADDR', ''),
    token = envor('VAULT_TOKEN', ''),
    mount = envopt('VAULT_MOUNT'),
    kv = tonumber(envor('VAULT_KV', '')) and
      math.tointeger(tonumber(envor('VAULT_KV', ''))) or nil,
    vaultnamespace = envopt('VAULT_NAMESPACE'),
    auth = vaultauth and sekreto.authspec({
      method = vaultauth,
      role = envopt('VAULT_ROLE'),
      jwtfile = envopt('VAULT_JWT_FILE'),
      roleid = envopt('VAULT_ROLE_ID'),
      secretid = envopt('VAULT_SECRET_ID'),
    }) or nil,
  })

  local boruspec = sekreto.spec({
    kind = 'boru',
    command = envor('BORU_COMMAND', 'boru'),
    namespace = envopt('BORU_NAMESPACE'),
    home = envopt('BORU_HOME'),
  })

  -- The same vault over its wire protocol (`boru vault serve`) instead of
  -- the CLI: an address plus a capability token from `vault grant`.
  local boruwirespec = sekreto.spec({
    kind = 'boru',
    addr = envor('BORU_ADDR', ''),
    token = envor('BORU_TOKEN', ''),
    namespace = envopt('BORU_NAMESPACE'),
  })

  local awssecretsspec = sekreto.spec({
    kind = 'awssecrets',
    region = envopt('AWS_REGION'),
    addr = envopt('AWS_ENDPOINT'),
  })

  local awsparamsspec = sekreto.spec({
    kind = 'awsparams',
    region = envopt('AWS_REGION'),
    addr = envopt('AWS_ENDPOINT'),
    prefix = envopt('AWS_PARAM_PREFIX'),
  })

  local gcpspec = sekreto.spec({
    kind = 'gcpsecrets',
    project = envopt('GCP_PROJECT'),
    addr = envopt('GCP_ADDR'),
    metadataaddr = envopt('GCP_METADATA_ADDR'),
  })

  local azurespec = sekreto.spec({
    kind = 'azuresecrets',
    vault = envopt('AZURE_VAULT'),
    token = envopt('AZURE_TOKEN'),
    tenant = envopt('AZURE_TENANT'),
    clientid = envopt('AZURE_CLIENT_ID'),
    clientsecret = envopt('AZURE_CLIENT_SECRET'),
    loginaddr = envopt('AZURE_LOGIN_ADDR'),
    imdsaddr = envopt('AZURE_IMDS_ADDR'),
  })

  local onepasswordspec = sekreto.spec({
    kind = 'onepassword',
    addr = envopt('OP_CONNECT_HOST'),
    token = envopt('OP_CONNECT_TOKEN'),
    vault = envopt('OP_VAULT'),
  })

  local dopplerspec = sekreto.spec({
    kind = 'doppler',
    token = envopt('DOPPLER_TOKEN'),
    project = envopt('DOPPLER_PROJECT'),
    config = envopt('DOPPLER_CONFIG'),
    addr = envopt('DOPPLER_ADDR'),
  })

  -- SecretSpec's own environment variables where it has them, so a shell
  -- already set up for secretspec needs nothing further.
  local secretspecspec = sekreto.spec({
    kind = 'secretspec',
    command = envor('SECRETSPEC_COMMAND', 'secretspec'),
    file = envopt('SECRETSPEC_FILE'),
    profile = envopt('SECRETSPEC_PROFILE'),
    backend = envopt('SECRETSPEC_PROVIDER'),
    reason = envopt('SECRETSPEC_REASON'),
  })

  local infisicalspec = sekreto.spec({
    kind = 'infisical',
    addr = envopt('INFISICAL_ADDR'),
    token = envopt('INFISICAL_TOKEN'),
    clientid = envopt('INFISICAL_CLIENT_ID'),
    clientsecret = envopt('INFISICAL_CLIENT_SECRET'),
    project = envopt('INFISICAL_PROJECT'),
    environment = envopt('INFISICAL_ENV'),
    path = envopt('INFISICAL_PATH'),
  })

  local named = {
    env = { envspec },
    dotenv = { dotenvspec },
    file = { filespec },
    hashicorp = { hashicorpspec },
    boru = { boruspec },
    boruwire = { boruwirespec },
    awssecrets = { awssecretsspec },
    awsparams = { awsparamsspec },
    gcpsecrets = { gcpspec },
    azuresecrets = { azurespec },
    onepassword = { onepasswordspec },
    doppler = { dopplerspec },
    infisical = { infisicalspec },
    secretspec = { secretspecspec },
  }

  -- The default: the chain an app would actually ship with - local
  -- overrides first, shared vaults last.
  return named[source] or { envspec, dotenvspec, hashicorpspec, boruspec }
end

--- The value of a `--flag value` pair, or "" when the flag is absent.
--- Positional, by index-of: no argument-parsing library.
local function flag(name)
  for index = 1, #arg do
    if name == arg[index] and index < #arg then
      return arg[index + 1]
    end
  end
  return ''
end

local function run()
  local url = (nil ~= arg[1] and '--' ~= arg[1]:sub(1, 2)) and arg[1]
    or 'http://127.0.0.1:8099/whoami'

  local source = flag('--source')
  if '' == source then
    source = 'chain'
  end

  -- --store names a store outright: the secret must come from that one,
  -- not from whichever provider happens to answer first.
  local store = flag('--store')

  local secrets

  local ok, token = pcall(function()
    secrets = sekreto.sekreto({ plugins = allplugins, providers = chainfor(source) })
    if '' == store then
      return secrets:get('api.token')
    end
    return secrets:getfrom(store, 'api.token')
  end)

  if not ok then
    -- Every failure path is redacted, including this one: a provider
    -- message can quote a store's own answer.
    local why = sekreto.errmessage(token)
    io.stderr:write('sekreto-cli: ' ..
      (secrets and secrets:redact(why) or why) .. '\n')
    return 2
  end

  local res, why = httpjson.request('GET', url, {
    { 'Authorization', 'Bearer ' .. token },
    { 'X-Sekreto-Lang', LANG },
  })

  if nil == res then
    io.stderr:write('sekreto-cli: ' .. secrets:redact(why) .. '\n')
    return 1
  end

  if 200 ~= res.status then
    -- Never print the token itself, even when the call fails.
    io.stderr:write('sekreto-cli: ' .. secrets:redact(res.body) .. '\n')
    return 1
  end

  local caller = json.dig(json.parse(res.body), 'caller')

  -- Assembled field by field, in the spec's order. Printing a map here is
  -- what has bitten port after port: the language's own key order is not
  -- the one every other port prints.
  io.write('{"ok":true' ..
    ',"lang":' .. json.quote(LANG) ..
    ',"source":' .. json.quote(source) ..
    ',"store":' .. json.quote(store) ..
    ',"caller":' .. json.stringify(caller) ..
    '}\n')

  return 0
end

os.exit(run())
