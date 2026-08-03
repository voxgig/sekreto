# frozen_string_literal: true

# sekreto: one interface for secrets, wherever they live.
#
# A Sekreto is an ordered chain of providers. `get` asks each in turn and
# returns the first hit, so an app can be configured from environment
# variables in development and a vault in production without changing a
# line of its own code.
#
# A port of typescript/src/Sekreto.ts, which is canonical.

module VoxgigSekreto
  # Anything sekreto refuses to do: a bad name, a missing secret, a
  # provider that could not be reached.
  class SekretoError < StandardError; end

  NAMEPART = /\A[a-z0-9_]+\z/.freeze

  module_function

  # Is this a well-formed secret name?
  def validname(name)
    return false unless name.is_a?(String)
    return false if name.empty?

    name.split('.', -1).all? { |part| NAMEPART.match?(part) }
  end

  def checkname(name)
    raise SekretoError, 'sekreto: invalid name: ' + (name.nil? ? '' : name.to_s) unless validname(name)

    name
  end

  # The environment-variable key for a name: `api.token` -> `API_TOKEN`.
  def envkey(name, prefix = nil)
    checkname(name)
    (prefix || '') + name.split('.', -1).join('_').upcase
  end

  # Where a name lives in a KV vault: `api.token` -> `api` / `token`.
  #
  # A single-segment name has no path of its own, so it becomes a secret of
  # that name with the conventional field `value`.
  def vaultref(name)
    checkname(name)

    parts = name.split('.', -1)

    return { 'path' => parts[0], 'field' => 'value' } if 1 == parts.length

    { 'path' => parts[0...-1].join('/'), 'field' => parts[-1] }
  end

  # A name flattened to one segment: `api.token` -> `api_token` (GCP
  # Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).
  #
  # Those stores have no path hierarchy and reject dots in ids, so the
  # dots become the store's conventional separator. With `-` as the
  # separator, underscores flatten too: Azure Key Vault's alphabet is
  # letters, digits and hyphens only, and a valid sekreto name like
  # `with_underscore` must still be representable there. (The resulting
  # `.`/`_` collision mirrors the documented envkey behaviour, where
  # both already map to `_`.)
  def flatname(name, sep)
    checkname(name)
    flat = name.split('.', -1).join(sep)
    '-' == sep ? flat.split('_', -1).join('-') : flat
  end

  # The AWS SSM Parameter Store name for a name: dots become the path
  # hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
  # `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
  def awsparam(name, prefix = nil)
    checkname(name)

    base = prefix || ''
    base = '/' + base if '' != base && !base.start_with?('/')
    base = base.sub(%r{/\z}, '')

    base + '/' + name.split('.', -1).join('/')
  end

  # Parse `.env` text into a map of raw keys to values.
  #
  # Deliberately small: `KEY=value`, optional `export`, `#` comments on
  # their own line, and single- or double-quoted values (double quotes also
  # unescape \n, \r, \t and \\). A line with no `=` is skipped.
  def parsedotenv(text)
    out = {}

    return out unless text.is_a?(String)

    text.split("\n", -1).each do |rawline|
      line = rawline.sub(/\r\z/, '').strip

      next if line.empty? || line.start_with?('#')

      body = line.start_with?('export ') ? line[7..].strip : line

      eq = body.index('=')
      next if eq.nil? || 0 >= eq

      key = body[0...eq].strip
      value = body[(eq + 1)..].strip

      if 2 <= value.length && value.start_with?('"') && value.end_with?('"')
        value = unescape(value[1...-1])
      elsif 2 <= value.length && value.start_with?("'") && value.end_with?("'")
        value = value[1...-1]
      end

      out[key] = value
    end

    out
  end

  def unescape(text)
    out = +''
    index = 0

    while index < text.length
      if '\\' == text[index] && index + 1 < text.length
        nxt = text[index + 1]
        index += 2
        out << case nxt
               when 'n' then "\n"
               when 'r' then "\r"
               when 't' then "\t"
               when '\\' then '\\'
               when '"' then '"'
               else '\\' + nxt
               end
      else
        out << text[index]
        index += 1
      end
    end

    out
  end

  # Replace known secret values in text with `[redacted]`.
  #
  # Only values of four characters or more are replaced: shorter ones are
  # too likely to appear in ordinary text, and redacting them would make
  # logs unreadable without making them safer.
  def redact(text, values)
    out = text.is_a?(String) ? text : ''

    (values || []).each do |value|
      next unless value.is_a?(String)
      next if 4 > value.length

      out = out.split(value, -1).join('[redacted]')
    end

    out
  end

  # The store name a provider answers to when its spec does not say.
  #
  # `describe` opens with the provider's kind - `hashicorp:...`,
  # `dotenv:...`, plain `env` - so the kind is the natural default, and a
  # custom provider gets a sensible name without implementing anything extra.
  def storename(provider, spec = nil)
    named = spec && (spec['name'] || spec[:name])
    return named if named

    provider.describe.split(':')[0]
  end

  # The secrets facade: a chain of providers plus a cache.
  #
  # Two ways to read. `get` is transparent - it walks the chain and takes the
  # first hit, and the caller never learns which store answered. `getfrom` is
  # directed - it names the store, and only that store is asked.
  class Sekreto
    def initialize(options = nil)
      opts = options || {}

      @entries = (opts['providers'] || opts[:providers] || []).map do |entry|
        if entry.respond_to?(:lookup)
          [VoxgigSekreto.storename(entry), entry]
        else
          provider = VoxgigSekreto.makeprovider(entry)
          [VoxgigSekreto.storename(provider, entry), provider]
        end
      end

      cache = opts.key?('cache') ? opts['cache'] : opts[:cache]
      @docache = false != cache

      # A list, not a hash: the store a value came from stays attached, and
      # redaction order does not vary between runs.
      @cache = []

      # Every value ever resolved, for redact. Kept independently of the
      # read cache so that redaction still works when cache is off -
      # otherwise `cache: false` would silently disable redact and leak
      # secrets to logs.
      @seen = []
    end

    # The secret, or a SekretoError if no provider has it.
    def get(name)
      found = try(name)

      raise SekretoError, 'sekreto: unknown secret: ' + name if found.nil?

      found
    end

    # The secret, or nil if no provider has it.
    def try(name)
      resolve('', name, @entries)
    end

    # The secret from one named store, or a SekretoError if that store does
    # not have it.
    def getfrom(store, name)
      found = tryfrom(store, name)

      raise SekretoError, 'sekreto: unknown secret: ' + store + ':' + name if found.nil?

      found
    end

    # The secret from one named store, or nil if that store does not have it.
    #
    # Naming a store that is not in the chain is an error, not a miss: `try`
    # already means "this store may not have it", so it cannot also mean
    # "this store may not exist" without hiding a typo.
    def tryfrom(store, name)
      matching = @entries.select { |entry| entry[0] == store }

      raise SekretoError, 'sekreto: unknown store: ' + store if matching.empty?

      resolve(store, name, matching)
    end

    # Does any provider have this secret?
    def has(name)
      !try(name).nil?
    end

    # Does this named store have this secret?
    def hasin(store, name)
      !tryfrom(store, name).nil?
    end

    # Every named secret at once. Missing ones are an error.
    def all(names)
      names.each_with_object({}) { |name, out| out[name] = get(name) }
    end

    # A description of each provider, in resolution order.
    def sources
      @entries.map { |_store, provider| provider.describe }
    end

    # The name of each store that can be named by `getfrom`, in resolution
    # order and without repeats.
    def stores
      @entries.map { |store, _provider| store }.uniq
    end

    # Replace every value this Sekreto has resolved with `[redacted]`.
    #
    # Works whether or not caching is enabled: the redaction list is kept
    # independently of the read cache.
    def redact(text)
      VoxgigSekreto.redact(text, @seen)
    end

    # Drop cached values, so the next `get` asks the providers again.
    def refresh
      @cache.clear
    end

    private

    def resolve(store, name, entries)
      VoxgigSekreto.checkname(name)

      if @docache
        hit = @cache.find { |cached| cached[0] == store && cached[1] == name }
        return hit[2] unless hit.nil?
      end

      entries.each do |_store, provider|
        found = provider.lookup(name)

        unless found.nil?
          @cache << [store, name, found] if @docache
          @seen << found
          return found
        end
      end

      nil
    end
  end

  # Make a Sekreto from options.
  def sekreto(options = nil)
    Sekreto.new(options)
  end
end
