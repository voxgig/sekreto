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
require 'open3'
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

  # Refuse to send a Vault token in the clear.
  #
  # Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
  # convenience. Sending `X-Vault-Token` over http to anything but the local
  # machine puts both the token and the secret it fetches on the wire for
  # anyone on the path, so sekreto will not do it. Loopback stays allowed:
  # that is `vault server -dev` and this repo's own test harness.
  def checkaddr(addr)
    return if addr.start_with?('https://')

    raise SekretoError, 'sekreto: not an http(s) address: ' + addr unless addr.start_with?('http://')

    host = addr[7..].split('/')[0].split(':')[0]

    return if ['localhost', '127.0.0.1', '::1', '[::1]'].include?(host)

    raise SekretoError,
          'sekreto: refusing to send a token in plaintext to ' + addr + ' (use https)'
  end

  # HashiCorp Vault, KV v2.
  #
  # `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
  # field of `data.data`. A 404 means "not here", which is a miss rather
  # than an error, so a vault can sit in a chain with fallbacks.
  class HashicorpProvider
    def initialize(addr, token, mount = nil)
      @addr = addr
      @token = token
      @mount = mount || 'secret'
    end

    def lookup(name)
      VoxgigSekreto.checkaddr(@addr)

      ref = VoxgigSekreto.vaultref(name)
      url = @addr.sub(%r{/\z}, '') + '/v1/' + @mount + '/data/' + ref['path']

      status, body = VoxgigSekreto.httpget(url, { 'X-Vault-Token' => @token })

      return nil if 404 == status

      raise SekretoError, 'sekreto: hashicorp error: ' + status.to_s + ': ' + url if 200 != status

      data = body.is_a?(Hash) && body['data'].is_a?(Hash) ? body['data']['data'] : nil
      value = data.is_a?(Hash) ? data[ref['field']] : nil

      value.nil? ? nil : value.to_s
    end

    def describe
      'hashicorp:' + @addr + '/' + @mount
    end
  end

  # A boru vault (https://github.com/boru-lang/boru).
  #
  # boru keeps secrets in a local encrypted keyring and hands a value out
  # through its own CLI: `boru vault get --reveal <alias>` prints the secret
  # on stdout, and nothing else.
  #
  # There is deliberately no HTTP read here. boru's `vault proxy` and
  # `vault mcp` are a *credential broker*: they inject the real secret into
  # an outbound request and forward it, so an agent can call an API without
  # ever holding the credential. Handing a value back is the one thing that
  # broker is built not to do, so sekreto reads the vault the way boru itself
  # does - through the CLI.
  #
  # A sekreto name is already a valid boru alias, so `api.token` crosses over
  # unchanged. A `namespace` qualifies it the way boru writes it,
  # `<namespace>:<name>`.
  #
  # The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
  # sekreto never accepts it as config and never puts it on a command line,
  # where it would show up in the process table.
  class BoruProvider
    def initialize(command = nil, namespace = nil, home = nil)
      @command = command || 'boru'
      @namespace = namespace
      @home = home
    end

    def lookup(name)
      VoxgigSekreto.checkname(name)

      alias_name = @namespace ? @namespace + ':' + name : name
      env = @home ? { 'BORU_HOME' => @home } : {}

      begin
        out, err, status = Open3.capture3(env, @command, 'vault', 'get', '--reveal', alias_name)
      rescue SystemCallError => e
        raise SekretoError, 'sekreto: cannot run ' + @command + ': ' + e.message
      end

      # boru prints the value and one newline, and nothing else.
      return out.sub(/\n\z/, '') if status.success?

      why = err.to_s.strip

      # "no alias named" is boru saying it does not hold this secret, which is
      # a miss: the chain carries on to the next provider. A locked vault or a
      # wrong passphrase is not a miss - treating it as one would fall through
      # to a weaker store without saying so.
      return nil if VoxgigSekreto.borumiss(why)

      raise SekretoError,
            'sekreto: boru vault error: ' + (why.empty? ? 'exit ' + status.exitstatus.to_s : why)
    end

    def describe
      'boru' + (@namespace ? ':' + @namespace : '')
    end
  end

  module_function

  # Does this boru failure mean "no such secret" rather than "I could not
  # answer"? Matched on boru's own wording for a missing alias.
  def borumiss(why)
    why.include?('no alias named')
  end

  # Build a provider from its declarative form.
  def makeprovider(spec)
    kind = spec['kind'] || spec[:kind]
    get = ->(key) { spec[key.to_s].nil? ? spec[key] : spec[key.to_s] }

    case kind
    when 'env' then EnvProvider.new(get.call(:prefix))
    when 'dotenv' then DotenvProvider.new(get.call(:file) || '.env', get.call(:prefix))
    when 'memory' then MemoryProvider.new(get.call(:values) || {}, get.call(:prefix))
    when 'hashicorp'
      HashicorpProvider.new(get.call(:addr) || '', get.call(:token) || '', get.call(:mount))
    when 'boru'
      BoruProvider.new(get.call(:command), get.call(:namespace), get.call(:home))
    else raise SekretoError, 'sekreto: unknown provider kind: ' + kind.to_s
    end
  end
end
