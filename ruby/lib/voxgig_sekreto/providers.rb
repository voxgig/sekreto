# frozen_string_literal: true

# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns
# the value, or nil to mean "ask the next one". Nothing else about a
# provider is visible to the caller - which is the point: an app reads
# `api.token` and never learns whether it came from the environment, a
# .env file, HashiCorp Vault or a boru vault.
#
# A port of typescript/src/Providers.ts, which is canonical.

require 'json'
require 'net/http'
require 'uri'

module VoxgigSekreto
  # Environment variables: `api.token` from `API_TOKEN`.
  class EnvProvider
    def initialize(prefix = nil, source = nil)
      @prefix = prefix
      @source = source || ENV
    end

    def lookup(name)
      value = @source[VoxgigSekreto.envkey(name, @prefix)]
      value.nil? ? nil : value.to_s
    end

    def describe
      'env' + (@prefix ? ':' + @prefix : '')
    end
  end

  # A `.env` file, read once, keyed exactly like the environment.
  class DotenvProvider
    def initialize(file, prefix = nil)
      @file = file
      @prefix = prefix
      @values = nil
    end

    def load
      if @values.nil?
        @values = begin
          VoxgigSekreto.parsedotenv(File.read(@file))
        rescue SystemCallError
          # A missing .env file is not an error: it means "no secrets here".
          {}
        end
      end
      @values
    end

    def lookup(name)
      load[VoxgigSekreto.envkey(name, @prefix)]
    end

    def describe
      'dotenv:' + @file
    end
  end

  # Literal values, keyed like environment variables. The spec uses this to
  # test chain behaviour without touching the outside world.
  class MemoryProvider
    def initialize(values, prefix = nil)
      @values = values || {}
      @prefix = prefix
    end

    def lookup(name)
      @values[VoxgigSekreto.envkey(name, @prefix)]
    end

    def describe
      'memory' + (@prefix ? ':' + @prefix : '')
    end
  end

  module_function

  # GET url, returning [status, parsed-json-or-nil]. A 404 is a normal
  # answer here, not an exception: it means the vault has no such secret.
  def httpget(url, headers)
    uri = URI.parse(url)
    request = Net::HTTP::Get.new(uri)
    headers.each { |key, value| request[key] = value }

    response = begin
      Net::HTTP.start(uri.hostname, uri.port, use_ssl: 'https' == uri.scheme) do |http|
        http.request(request)
      end
    rescue StandardError => e
      raise SekretoError, 'sekreto: cannot reach ' + url + ': ' + e.message
    end

    body = begin
      JSON.parse(response.body)
    rescue JSON::ParserError
      nil
    end

    [response.code.to_i, body]
  end

  # HashiCorp Vault, KV v2.
  #
  # `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
  # field of `data.data`. A 404 means "not here", which is a miss rather
  # than an error, so a vault can sit in a chain with fallbacks.
  class VaultProvider
    def initialize(addr, token, mount = nil)
      @addr = addr
      @token = token
      @mount = mount || 'secret'
    end

    def lookup(name)
      ref = VoxgigSekreto.vaultref(name)
      url = @addr.sub(%r{/\z}, '') + '/v1/' + @mount + '/data/' + ref['path']

      status, body = VoxgigSekreto.httpget(url, { 'X-Vault-Token' => @token })

      return nil if 404 == status

      raise SekretoError, 'sekreto: vault error: ' + status.to_s + ': ' + url if 200 != status

      data = body.is_a?(Hash) && body['data'].is_a?(Hash) ? body['data']['data'] : nil
      value = data.is_a?(Hash) ? data[ref['field']] : nil

      value.nil? ? nil : value.to_s
    end

    def describe
      'vault:' + @addr + '/' + @mount
    end
  end

  # A boru vault.
  #
  # The boru vault protocol as sekreto uses it: a GET of
  # `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
  # answering `{"ok":true,"value":"..."}` when the secret exists and
  # `{"ok":false}` (or 404) when it does not.
  class BoruProvider
    def initialize(addr, token)
      @addr = addr
      @token = token
    end

    def lookup(name)
      ref = VoxgigSekreto.vaultref(name)
      url = @addr.sub(%r{/\z}, '') + '/vault/' + ref['path'] +
            '?field=' + URI.encode_www_form_component(ref['field'])

      status, body = VoxgigSekreto.httpget(url, { 'X-Boru-Token' => @token })

      return nil if 404 == status

      raise SekretoError, 'sekreto: boru vault error: ' + status.to_s + ': ' + url if 200 != status

      return nil unless body.is_a?(Hash) && true == body['ok']

      body['value'].nil? ? nil : body['value'].to_s
    end

    def describe
      'boru:' + @addr
    end
  end

  # Build a provider from its declarative form.
  def makeprovider(spec)
    kind = spec['kind'] || spec[:kind]
    get = ->(key) { spec[key.to_s].nil? ? spec[key] : spec[key.to_s] }

    case kind
    when 'env' then EnvProvider.new(get.call(:prefix))
    when 'dotenv' then DotenvProvider.new(get.call(:file) || '.env', get.call(:prefix))
    when 'memory' then MemoryProvider.new(get.call(:values) || {}, get.call(:prefix))
    when 'vault'
      VaultProvider.new(get.call(:addr) || '', get.call(:token) || '', get.call(:mount))
    when 'boru' then BoruProvider.new(get.call(:addr) || '', get.call(:token) || '')
    else raise SekretoError, 'sekreto: unknown provider kind: ' + kind.to_s
    end
  end
end
