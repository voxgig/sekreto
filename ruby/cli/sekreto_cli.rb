# frozen_string_literal: true

# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with
# it. Every port ships this same CLI, and test/integration.sh runs all of
# them against the same server from every secret source - which is
# what proves the library, rather than the spec alone.
#
# Usage: ruby sekreto_cli.rb <api-url> [--source <source>] [--store <name>]
#
# Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
#          gcpsecrets azuresecrets onepassword doppler infisical chain
#
# Each source's configuration arrives in the environment variables its
# own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
# in chainfor below.

require 'json'
require 'net/http'
require 'uri'

require_relative '../lib/voxgig_sekreto'

LANG = 'ruby'

def chainfor(source)
  envspec = { 'kind' => 'env', 'prefix' => ENV.fetch('SEKRETO_PREFIX', nil) }
  dotenvspec = { 'kind' => 'dotenv', 'file' => ENV['SEKRETO_DOTENV'] || '.env' }
  filespec = { 'kind' => 'file', 'dir' => ENV['SEKRETO_FILEDIR'] || '/run/secrets' }

  vaultauth = ENV.fetch('VAULT_AUTH', nil)
  vaultkv = ENV.fetch('VAULT_KV', nil)

  hashicorpspec = {
    'kind' => 'hashicorp',
    'addr' => ENV['VAULT_ADDR'] || '',
    'token' => ENV['VAULT_TOKEN'] || '',
    'mount' => ENV.fetch('VAULT_MOUNT', nil),
    'kv' => vaultkv && !vaultkv.empty? ? vaultkv.to_i : nil,
    'vaultnamespace' => ENV.fetch('VAULT_NAMESPACE', nil),
    'auth' => if vaultauth && !vaultauth.empty?
                {
                  'method' => vaultauth,
                  'role' => ENV.fetch('VAULT_ROLE', nil),
                  'jwtfile' => ENV.fetch('VAULT_JWT_FILE', nil),
                  'roleid' => ENV.fetch('VAULT_ROLE_ID', nil),
                  'secretid' => ENV.fetch('VAULT_SECRET_ID', nil)
                }
              end
  }

  boruspec = {
    'kind' => 'boru',
    'command' => ENV['BORU_COMMAND'] || 'boru',
    'namespace' => ENV.fetch('BORU_NAMESPACE', nil),
    'home' => ENV.fetch('BORU_HOME', nil)
  }

  # The same vault over its wire protocol (`boru vault serve`) instead
  # of the CLI: an address plus a capability token from `vault grant`.
  boruwirespec = {
    'kind' => 'boru',
    'addr' => ENV['BORU_ADDR'] || '',
    'token' => ENV['BORU_TOKEN'] || '',
    'namespace' => ENV.fetch('BORU_NAMESPACE', nil)
  }

  awssecretsspec = {
    'kind' => 'awssecrets',
    'region' => ENV.fetch('AWS_REGION', nil),
    'addr' => ENV.fetch('AWS_ENDPOINT', nil)
  }

  awsparamsspec = {
    'kind' => 'awsparams',
    'region' => ENV.fetch('AWS_REGION', nil),
    'addr' => ENV.fetch('AWS_ENDPOINT', nil),
    'prefix' => ENV.fetch('AWS_PARAM_PREFIX', nil)
  }

  gcpspec = {
    'kind' => 'gcpsecrets',
    'project' => ENV.fetch('GCP_PROJECT', nil),
    'addr' => ENV.fetch('GCP_ADDR', nil),
    'metadataaddr' => ENV.fetch('GCP_METADATA_ADDR', nil)
  }

  azurespec = {
    'kind' => 'azuresecrets',
    'vault' => ENV.fetch('AZURE_VAULT', nil),
    'token' => ENV.fetch('AZURE_TOKEN', nil),
    'tenant' => ENV.fetch('AZURE_TENANT', nil),
    'clientid' => ENV.fetch('AZURE_CLIENT_ID', nil),
    'clientsecret' => ENV.fetch('AZURE_CLIENT_SECRET', nil),
    'loginaddr' => ENV.fetch('AZURE_LOGIN_ADDR', nil),
    'imdsaddr' => ENV.fetch('AZURE_IMDS_ADDR', nil)
  }

  onepasswordspec = {
    'kind' => 'onepassword',
    'addr' => ENV.fetch('OP_CONNECT_HOST', nil),
    'token' => ENV.fetch('OP_CONNECT_TOKEN', nil),
    'vault' => ENV.fetch('OP_VAULT', nil)
  }

  dopplerspec = {
    'kind' => 'doppler',
    'token' => ENV.fetch('DOPPLER_TOKEN', nil),
    'project' => ENV.fetch('DOPPLER_PROJECT', nil),
    'config' => ENV.fetch('DOPPLER_CONFIG', nil),
    'addr' => ENV.fetch('DOPPLER_ADDR', nil)
  }

  infisicalspec = {
    'kind' => 'infisical',
    'addr' => ENV.fetch('INFISICAL_ADDR', nil),
    'token' => ENV.fetch('INFISICAL_TOKEN', nil),
    'clientid' => ENV.fetch('INFISICAL_CLIENT_ID', nil),
    'clientsecret' => ENV.fetch('INFISICAL_CLIENT_SECRET', nil),
    'project' => ENV.fetch('INFISICAL_PROJECT', nil),
    'environment' => ENV.fetch('INFISICAL_ENV', nil),
    'path' => ENV.fetch('INFISICAL_PATH', nil)
  }

  case source
  when 'env' then [envspec]
  when 'dotenv' then [dotenvspec]
  when 'file' then [filespec]
  when 'hashicorp' then [hashicorpspec]
  when 'boru' then [boruspec]
  when 'boruwire' then [boruwirespec]
  when 'awssecrets' then [awssecretsspec]
  when 'awsparams' then [awsparamsspec]
  when 'gcpsecrets' then [gcpspec]
  when 'azuresecrets' then [azurespec]
  when 'onepassword' then [onepasswordspec]
  when 'doppler' then [dopplerspec]
  when 'infisical' then [infisicalspec]
  else
    # The default: the chain an app would actually ship with - local
    # overrides first, shared vaults last.
    [envspec, dotenvspec, hashicorpspec, boruspec]
  end
end

def main
  args = ARGV
  url = args[0] || 'http://127.0.0.1:8099/whoami'

  flag = args.index('--source')
  source = flag.nil? ? 'chain' : args[flag + 1]

  # --store names a store outright: the secret must come from that one, not
  # from whichever provider happens to answer first.
  storeflag = args.index('--store')
  store = storeflag.nil? ? '' : args[storeflag + 1]

  secrets = VoxgigSekreto::Sekreto.new('providers' => chainfor(source))

  begin
    token = store.empty? ? secrets.get('api.token') : secrets.getfrom(store, 'api.token')
  rescue StandardError => e
    warn 'sekreto-cli: ' + e.message
    return 2
  end

  uri = URI.parse(url)
  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = 'Bearer ' + token
  request['X-Sekreto-Lang'] = LANG

  response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: 'https' == uri.scheme) do |http|
    http.request(request)
  end

  if '200' != response.code
    # Never print the token itself, even when the call fails.
    warn 'sekreto-cli: ' + secrets.redact(response.body.to_s)
    return 1
  end

  body = JSON.parse(response.body)

  puts JSON.generate({ 'ok' => true, 'lang' => LANG, 'source' => source,
                       'store' => store, 'caller' => body['caller'] })

  0
end

exit(main)
