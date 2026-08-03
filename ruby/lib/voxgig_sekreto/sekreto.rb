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

  # The secrets facade: a chain of providers plus a cache.
  class Sekreto
    def initialize(options = nil)
      opts = options || {}

      @providers = (opts['providers'] || opts[:providers] || []).map do |entry|
        entry.respond_to?(:lookup) ? entry : VoxgigSekreto.makeprovider(entry)
      end

      cache = opts.key?('cache') ? opts['cache'] : opts[:cache]
      @docache = false != cache
      @cache = {}
    end

    # The secret, or a SekretoError if no provider has it.
    def get(name)
      found = try(name)

      raise SekretoError, 'sekreto: unknown secret: ' + name if found.nil?

      found
    end

    # The secret, or nil if no provider has it.
    def try(name)
      VoxgigSekreto.checkname(name)

      return @cache[name] if @docache && @cache.key?(name)

      @providers.each do |provider|
        found = provider.lookup(name)

        unless found.nil?
          @cache[name] = found if @docache
          return found
        end
      end

      nil
    end

    # Does any provider have this secret?
    def has(name)
      !try(name).nil?
    end

    # Every named secret at once. Missing ones are an error.
    def all(names)
      names.each_with_object({}) { |name, out| out[name] = get(name) }
    end

    # A description of each provider, in resolution order.
    def sources
      @providers.map(&:describe)
    end

    # Replace every value this Sekreto has resolved with `[redacted]`.
    def redact(text)
      VoxgigSekreto.redact(text, @cache.values)
    end

    # Drop cached values, so the next `get` asks the providers again.
    def refresh
      @cache.clear
    end
  end

  # Make a Sekreto from options.
  def sekreto(options = nil)
    Sekreto.new(options)
  end
end
