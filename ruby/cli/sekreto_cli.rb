# frozen_string_literal: true

# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with
# it. Every port ships this same CLI, and test/integration.sh runs all of
# them against the same server from all four secret sources - which is
# what proves the library, rather than the spec alone.
#
# Usage: ruby sekreto_cli.rb <api-url> [--source env|dotenv|hashicorp|boru|chain]
#                                      [--store <name>]   directed read

require 'json'
require 'net/http'
require 'uri'

require_relative '../lib/voxgig_sekreto'

LANG = 'ruby'

def chainfor(source)
  envspec = { 'kind' => 'env', 'prefix' => ENV.fetch('SEKRETO_PREFIX', nil) }
  dotenvspec = { 'kind' => 'dotenv', 'file' => ENV['SEKRETO_DOTENV'] || '.env' }
  hashicorpspec = {
    'kind' => 'hashicorp',
    'addr' => ENV['VAULT_ADDR'] || '',
    'token' => ENV['VAULT_TOKEN'] || '',
    'mount' => ENV.fetch('VAULT_MOUNT', nil)
  }
  boruspec = {
    'kind' => 'boru',
    'command' => ENV['BORU_COMMAND'] || 'boru',
    'namespace' => ENV.fetch('BORU_NAMESPACE', nil),
    'home' => ENV.fetch('BORU_HOME', nil)
  }

  case source
  when 'env' then [envspec]
  when 'dotenv' then [dotenvspec]
  when 'hashicorp' then [hashicorpspec]
  when 'boru' then [boruspec]
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
