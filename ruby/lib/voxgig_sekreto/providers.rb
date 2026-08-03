# frozen_string_literal: true

# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns
# the value, or nil to mean "ask the next one". Nothing else about a
# provider is visible to the caller - which is the point: an app reads
# `api.token` and never learns whether it came from the environment, a
# .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
#
# Two failure shapes, and they are never interchangeable. A store that
# does not hold the secret is a MISS (nil) - the chain carries on. A
# store that could not answer - bad credentials, unreachable host,
# missing configuration - is an ERROR: falling through there would
# quietly reach for a weaker store.
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

  # A directory of one-secret-per-file entries, keyed like the
  # environment: `api.token` reads `<dir>/API_TOKEN`.
  #
  # This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
  # secret, and a systemd credentials directory, so those all work with no
  # further configuration. One trailing newline is stripped - tools that
  # write these files disagree about it, and a newline is never part of a
  # secret on purpose.
  class FileProvider
    def initialize(dir, prefix = nil)
      @dir = dir
      @prefix = prefix
    end

    def lookup(name)
      file = File.join(@dir, VoxgigSekreto.envkey(name, @prefix))

      text = begin
        File.read(file)
      rescue Errno::ENOENT, Errno::ENOTDIR
        # An absent file - or an absent directory - means "no secrets
        # here", exactly like a missing .env. Anything else (permission
        # denied, an unreadable mount) is a store that could not answer.
        return nil
      rescue StandardError => e
        raise SekretoError, 'sekreto: file provider cannot read ' + file + ': ' + e.message
      end

      text.sub(/\r?\n\z/, '')
    end

    def describe
      'file:' + @dir
    end
  end

  module_function

  # Is this optional config value actually set? Both nil and the empty
  # string mean "not given", matching the canonical port's truthiness.
  def given(value)
    !value.nil? && '' != value
  end

  # One JSON round-trip, returning [status, parsed-json-or-nil]. A 404 is
  # a normal answer here, not an exception: callers decide on status
  # first. Network failure is always an error - an unreachable store is a
  # store that could not answer.
  def fetchjson(method, url, headers, body = nil)
    uri = URI.parse(url)

    request = 'POST' == method ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
    headers.each { |key, value| request[key] = value }
    request.body = body unless body.nil?

    response = begin
      Net::HTTP.start(uri.hostname, uri.port, use_ssl: 'https' == uri.scheme) do |http|
        http.request(request)
      end
    rescue StandardError => e
      raise SekretoError, 'sekreto: cannot reach ' + url.split('?')[0] + ': ' + e.message
    end

    parsed = begin
      JSON.parse(response.body)
    rescue JSON::ParserError, TypeError
      # A success status promised JSON; a body that does not parse means
      # the store could not answer coherently, and treating it as a miss
      # would fall through to a weaker store. Error statuses may carry
      # any body - they are decided on status alone.
      if 200 == response.code.to_i
        raise SekretoError, 'sekreto: malformed response from ' + url.split('?')[0]
      end

      nil
    end

    [response.code.to_i, parsed]
  end

  # Refuse to send a secret-bearing credential in the clear.
  #
  # A vault API is HTTPS in any real deployment; plaintext is a dev-mode
  # convenience. Sending a token over http to anything but the local
  # machine puts both the token and the secret it fetches on the wire for
  # anyone on the path, so sekreto will not do it. Loopback stays allowed:
  # that is `vault server -dev`, `boru vault serve`, and this repo's own
  # test harness.
  def checkaddr(addr)
    return if addr.start_with?('https://')

    raise SekretoError, 'sekreto: not an http(s) address: ' + addr unless addr.start_with?('http://')

    host = addr[7..].split('/')[0].split(':')[0]

    return if ['localhost', '127.0.0.1', '::1', '[::1]'].include?(host)

    raise SekretoError,
          'sekreto: refusing to send a token in plaintext to ' + addr + ' (use https)'
  end

  # HashiCorp Vault.
  #
  # KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api`
  # and takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
  # `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means
  # "not here" - a miss - so a vault can sit in a chain with fallbacks.
  #
  # A Vault Enterprise namespace rides the X-Vault-Namespace header, on
  # logins as well as reads.
  #
  # Instead of being handed a token, the provider can log in: Kubernetes
  # auth (the pod's service-account JWT, from its conventional path) or
  # AppRole. A failed login is an error, never a miss - it means this
  # store could not answer at all.
  class HashicorpProvider
    def initialize(addr, token, options = nil)
      opts = options || {}
      @addr = addr
      @mount = opts['mount'] || 'secret'
      @kv = opts['kv'] || 2
      @vaultnamespace = opts['vaultnamespace']
      @auth = opts['auth']

      # A version typo like kv: 3 must not quietly behave as v2 and turn
      # its 404s into misses; there is nothing safe to assume it meant.
      if 1 != @kv && 2 != @kv
        raise SekretoError, 'sekreto: hashicorp: unsupported kv version: ' + @kv.to_s
      end

      # The working token: a configured token is kept forever, a logged-in
      # token is renewed shortly before its lease runs out - a long-running
      # process must not keep presenting a token the vault already expired.
      @livetoken = VoxgigSekreto.given(token) ? token : nil
      @renewat = Float::INFINITY
    end

    def baseheaders
      headers = {}
      headers['X-Vault-Namespace'] = @vaultnamespace if @vaultnamespace
      headers
    end

    def login
      raise SekretoError, 'sekreto: hashicorp: no token and no auth method' if @auth.nil?

      method = @auth['method']
      mount = @auth['mount'] || method
      url = @addr.sub(%r{/\z}, '') + '/v1/auth/' + mount.to_s + '/login'

      body = if 'kubernetes' == method
               jwt = @auth['jwt']
               if jwt.nil?
                 file = @auth['jwtfile'] || '/var/run/secrets/kubernetes.io/serviceaccount/token'
                 jwt = begin
                   File.read(file).strip
                 rescue StandardError
                   raise SekretoError, 'sekreto: hashicorp: cannot read jwt file ' + file
                 end
               end
               { 'role' => @auth['role'] || '', 'jwt' => jwt }
             elsif 'approle' == method
               { 'role_id' => @auth['roleid'] || '', 'secret_id' => @auth['secretid'] || '' }
             else
               raise SekretoError, 'sekreto: hashicorp: unknown auth method: ' + method.to_s
             end

      status, resbody = VoxgigSekreto.fetchjson('POST', url, baseheaders, JSON.generate(body))

      got = resbody.is_a?(Hash) && resbody['auth'].is_a?(Hash) ? resbody['auth']['client_token'] : nil
      unless 200 == status && VoxgigSekreto.given(got)
        raise SekretoError, 'sekreto: hashicorp login failed: ' + status.to_s + ': ' + url
      end

      lease = resbody['auth']['lease_duration'].to_f
      @renewat = 0 < lease ? Time.now.to_f + [lease - 60, 1].max : Float::INFINITY

      got.to_s
    end

    def lookup(name)
      VoxgigSekreto.checkaddr(@addr)

      @livetoken = login if @livetoken.nil? || Time.now.to_f >= @renewat

      ref = VoxgigSekreto.vaultref(name)
      base = @addr.sub(%r{/\z}, '') + '/v1/' + @mount
      url = 1 == @kv ? base + '/' + ref['path'] : base + '/data/' + ref['path']

      headers = baseheaders
      headers['X-Vault-Token'] = @livetoken

      status, body = VoxgigSekreto.fetchjson('GET', url, headers)

      return nil if 404 == status

      raise SekretoError, 'sekreto: hashicorp error: ' + status.to_s + ': ' + url if 200 != status

      data = if 1 == @kv
               body.is_a?(Hash) ? body['data'] : nil
             else
               body.is_a?(Hash) && body['data'].is_a?(Hash) ? body['data']['data'] : nil
             end
      value = data.is_a?(Hash) ? data[ref['field']] : nil

      value.nil? ? nil : value.to_s
    end

    def describe
      'hashicorp:' + @addr + '/' + @mount
    end
  end

  # A boru vault (https://github.com/boru-lang/boru).
  #
  # Two ways in, both boru's own.
  #
  # With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
  # secret on stdout and nothing else. The passphrase is read by boru
  # itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as
  # config and never puts it on a command line, where it would show up in
  # the process table.
  #
  # With an `addr`, boru's wire protocol: `boru vault serve` publishes a
  # read-only, HashiCorp-shaped provision API (boru's
  # design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
  # from `boru vault grant`. A sekreto name is already a valid boru
  # alias, and boru aliases keep their dots, so `api.token` is the single
  # path segment `api.token` - not the `api`/`token` split a HashiCorp KV
  # gets. The value is the `value` field. A 404 is a miss; anything else
  # the server refuses (a revoked capability, a sealed vault) is an
  # error.
  #
  # boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
  # credential *broker*, built precisely so the caller never receives the
  # credential. `vault serve` is the provision endpoint, built to hand
  # the value back - that is the one sekreto uses.
  class BoruProvider
    def initialize(command = nil, namespace = nil, home = nil, addr = nil, token = nil, mount = nil)
      @command = command || 'boru'
      @namespace = namespace
      @home = home
      @addr = VoxgigSekreto.given(addr) ? addr.sub(%r{/\z}, '') : nil
      @token = token
      @mount = mount || 'secret'
    end

    def wirelookup(name)
      VoxgigSekreto.checkname(name)
      VoxgigSekreto.checkaddr(@addr)

      alias_name = @namespace ? @namespace + '/' + name : name
      url = @addr + '/v1/' + @mount + '/data/' + alias_name

      status, body = VoxgigSekreto.fetchjson('GET', url, { 'X-Vault-Token' => @token || '' })

      return nil if 404 == status

      raise SekretoError, 'sekreto: boru serve error: ' + status.to_s + ': ' + url if 200 != status

      data = body.is_a?(Hash) && body['data'].is_a?(Hash) ? body['data']['data'] : nil
      value = data.is_a?(Hash) ? data['value'] : nil

      value.nil? ? nil : value.to_s
    end

    def lookup(name)
      return wirelookup(name) if @addr

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
      return 'boru:' + @addr if @addr

      'boru' + (@namespace ? ':' + @namespace : '')
    end
  end

  module_function

  # Does this boru failure mean "no such secret" rather than "I could not
  # answer"? Matched on boru's own wording for a missing alias.
  def borumiss(why)
    why.include?('no alias named')
  end

  # The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.
  def awsnow
    Time.now.utc.strftime('%Y%m%dT%H%M%SZ')
  end

  # Region and credentials, from config first and the standard AWS_*
  # environment variables second - those are AWS's own convention, and a
  # pod or CI job that has them set should just work. Missing either is
  # an error: an AWS store with no credentials could not answer.
  def awsauth(opts)
    region = opts['region'] || ENV['AWS_REGION'] || ENV['AWS_DEFAULT_REGION'] || ''
    keyid = opts['keyid'] || ENV['AWS_ACCESS_KEY_ID'] || ''
    secret = opts['secret'] || ENV['AWS_SECRET_ACCESS_KEY'] || ''
    session = opts['session'] || ENV.fetch('AWS_SESSION_TOKEN', nil)

    raise SekretoError, 'sekreto: aws: no region (set region or AWS_REGION)' if '' == region

    if '' == keyid || '' == secret
      raise SekretoError,
            'sekreto: aws: no credentials (set keyid/secret or ' \
            'AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)'
    end

    { 'region' => region, 'keyid' => keyid, 'secret' => secret, 'session' => session }
  end

  # One signed call to an AWS JSON-1.1 API.
  def awscall(opts, service, target, payload)
    auth = awsauth(opts)
    # The China partition lives under its own suffix; every other
    # commercial region is plain amazonaws.com.
    suffix = auth['region'].start_with?('cn-') ? '.amazonaws.com.cn' : '.amazonaws.com'
    addr = opts['addr'] || 'https://' + service + '.' + auth['region'] + suffix
    checkaddr(addr)

    url = addr.sub(%r{/\z}, '') + '/'
    body = JSON.generate(payload)
    headers = {
      'content-type' => 'application/x-amz-json-1.1',
      'x-amz-target' => target
    }

    signed = sigv4(
      'method' => 'POST',
      'url' => url,
      'headers' => headers,
      'body' => body,
      'service' => service,
      'region' => auth['region'],
      'keyid' => auth['keyid'],
      'secret' => auth['secret'],
      'session' => auth['session'],
      'datetime' => awsnow
    )

    fetchjson('POST', url, headers.merge(signed), body)
  end

  # Does this AWS error body name one of the not-found types? Those are
  # a miss; every other failure is a store that could not answer.
  def awsmiss(body, types)
    errtype = body.is_a?(Hash) && body['__type'].is_a?(String) ? body['__type'] : ''
    types.any? { |name| errtype.include?(name) }
  end

  # AWS Secrets Manager.
  #
  # `api.token` reads the secret named `api` (the vaultref path, so
  # `db.pass.main` reads `db/pass`) and takes the `token` field of its
  # JSON SecretString - the AWS idiom of one JSON map per secret. A
  # SecretString that is not JSON is the value itself, under the
  # conventional field `value`. Requests are SigV4-signed in-tree; see
  # sigv4.rb.
  class AwssecretsProvider
    def initialize(opts = nil)
      @opts = opts || {}
    end

    def lookup(name)
      ref = VoxgigSekreto.vaultref(name)

      status, body = VoxgigSekreto.awscall(@opts, 'secretsmanager',
                                           'secretsmanager.GetSecretValue',
                                           { 'SecretId' => ref['path'] })

      return nil if 400 == status && VoxgigSekreto.awsmiss(body, ['ResourceNotFoundException'])

      raise SekretoError, 'sekreto: aws secretsmanager error: ' + status.to_s if 200 != status

      text = body.is_a?(Hash) ? body['SecretString'] : nil

      unless text.is_a?(String)
        # A binary secret has no fields to address; only the conventional
        # `value` field can mean "the bytes themselves".
        bin = body.is_a?(Hash) ? body['SecretBinary'] : nil
        return bin.unpack1('m').force_encoding('UTF-8') if bin.is_a?(String) && 'value' == ref['field']

        return nil
      end

      parsed = begin
        JSON.parse(text)
      rescue JSON::ParserError
        nil
      end

      if parsed.is_a?(Hash)
        value = parsed[ref['field']]
        return value.nil? ? nil : value.to_s
      end

      # A plain-string secret is the whole value; it has no named fields.
      'value' == ref['field'] ? text : nil
    end

    # Config only, never the environment: describe feeds the spec's
    # sources group, which must answer the same everywhere.
    def describe
      'awssecrets:' + (@opts['region'] || '')
    end
  end

  # AWS SSM Parameter Store.
  #
  # `db.pass.main` reads the parameter `/db/pass/main` (under an optional
  # prefix path), decrypted. Parameter Store carries flat strings, so
  # there is no field indirection.
  class AwsparamsProvider
    def initialize(opts = nil)
      @opts = opts || {}
    end

    def lookup(name)
      status, body = VoxgigSekreto.awscall(@opts, 'ssm', 'AmazonSSM.GetParameter',
                                           { 'Name' => VoxgigSekreto.awsparam(name, @opts['prefix']),
                                             'WithDecryption' => true })

      return nil if 400 == status && VoxgigSekreto.awsmiss(body, ['ParameterNotFound'])

      raise SekretoError, 'sekreto: aws ssm error: ' + status.to_s if 200 != status

      value = body.is_a?(Hash) && body['Parameter'].is_a?(Hash) ? body['Parameter']['Value'] : nil
      value.nil? ? nil : value.to_s
    end

    def describe
      'awsparams:' + (@opts['region'] || '') + (@opts['prefix'] || '')
    end
  end

  # GCP Secret Manager.
  #
  # `api.token` reads secret `api_token` (dots flattened to `_`; Secret
  # Manager ids have no hierarchy and reject dots), latest version. The
  # token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
  # GCE/GKE metadata server - so on Google's own platform no credential
  # configuration is needed at all.
  #
  # The metadata call itself is plain http to a link-local host by
  # platform design; no credential rides on it, so `checkaddr` guards the
  # Secret Manager address instead.
  class GcpsecretsProvider
    def initialize(opts = nil)
      @opts = opts || {}

      # A configured token is kept forever; a metadata-server token carries
      # expires_in and is renewed shortly before it runs out.
      @livetoken = nil
      @renewat = Float::INFINITY
    end

    def metadataaddr
      return @opts['metadataaddr'] if VoxgigSekreto.given(@opts['metadataaddr'])

      host = ENV.fetch('GCE_METADATA_HOST', nil)
      VoxgigSekreto.given(host) ? 'http://' + host : 'http://metadata.google.internal'
    end

    def login
      configured = @opts['token'] || ENV.fetch('GOOGLE_OAUTH_ACCESS_TOKEN', nil)
      return configured if VoxgigSekreto.given(configured)

      url = metadataaddr.sub(%r{/\z}, '') +
            '/computeMetadata/v1/instance/service-accounts/default/token'

      status, body = VoxgigSekreto.fetchjson('GET', url, { 'Metadata-Flavor' => 'Google' })

      got = body.is_a?(Hash) ? body['access_token'] : nil
      unless 200 == status && VoxgigSekreto.given(got)
        raise SekretoError, 'sekreto: gcp: no token and metadata server did not answer'
      end

      expires = body['expires_in'].to_f
      @renewat = 0 < expires ? Time.now.to_f + [expires - 60, 1].max : Float::INFINITY

      got.to_s
    end

    def lookup(name)
      project = @opts['project'] || ''
      raise SekretoError, 'sekreto: gcp: no project' if '' == project

      addr = @opts['addr'] || 'https://secretmanager.googleapis.com'
      VoxgigSekreto.checkaddr(addr)

      @livetoken = login if @livetoken.nil? || Time.now.to_f >= @renewat

      url = addr.sub(%r{/\z}, '') + '/v1/projects/' + project + '/secrets/' +
            VoxgigSekreto.flatname(name, '_') + '/versions/latest:access'

      status, body = VoxgigSekreto.fetchjson('GET', url,
                                             { 'authorization' => 'Bearer ' + @livetoken })

      return nil if 404 == status

      raise SekretoError, 'sekreto: gcp error: ' + status.to_s + ': ' + url if 200 != status

      data = body.is_a?(Hash) && body['payload'].is_a?(Hash) ? body['payload']['data'] : nil
      return nil unless data.is_a?(String)

      data.unpack1('m').force_encoding('UTF-8')
    end

    def describe
      'gcpsecrets:' + (@opts['project'] || '')
    end
  end

  # Azure Key Vault.
  #
  # `api.token` reads secret `api-token` (dots flattened to `-`; Key
  # Vault names allow nothing else), current version. The token comes
  # from config, then a client-credentials login when tenant/clientid/
  # clientsecret are given, then the IMDS managed-identity endpoint - so
  # on Azure's own platform no credential configuration is needed.
  #
  # As with GCP, the IMDS call is plain http to a link-local host by
  # platform design and carries no credential; the login and vault
  # addresses are `checkaddr`-guarded.
  class AzuresecretsProvider
    RESOURCE = 'https://vault.azure.net'

    def initialize(opts = nil)
      @opts = opts || {}

      # A configured token is kept forever; logged-in and IMDS tokens carry
      # expires_in and are renewed shortly before they run out.
      @livetoken = nil
      @renewat = Float::INFINITY
    end

    def expiry(expires)
      seconds = expires.to_f
      0 < seconds ? Time.now.to_f + [seconds - 60, 1].max : Float::INFINITY
    end

    def login
      return @opts['token'] if VoxgigSekreto.given(@opts['token'])

      if VoxgigSekreto.given(@opts['tenant']) && VoxgigSekreto.given(@opts['clientid']) &&
         VoxgigSekreto.given(@opts['clientsecret'])
        loginaddr = @opts['loginaddr'] || 'https://login.microsoftonline.com'
        VoxgigSekreto.checkaddr(loginaddr)

        url = loginaddr.sub(%r{/\z}, '') + '/' + @opts['tenant'] + '/oauth2/v2.0/token'
        form = 'grant_type=client_credentials' \
               '&client_id=' + VoxgigSekreto.uriescape(@opts['clientid']) +
               '&client_secret=' + VoxgigSekreto.uriescape(@opts['clientsecret']) +
               '&scope=' + VoxgigSekreto.uriescape(RESOURCE + '/.default')

        status, body = VoxgigSekreto.fetchjson(
          'POST', url, { 'content-type' => 'application/x-www-form-urlencoded' }, form
        )

        got = body.is_a?(Hash) ? body['access_token'] : nil
        unless 200 == status && VoxgigSekreto.given(got)
          raise SekretoError, 'sekreto: azure login failed: ' + status.to_s
        end

        @renewat = expiry(body['expires_in'])
        return got.to_s
      end

      imds = (@opts['imdsaddr'] || 'http://169.254.169.254').sub(%r{/\z}, '') +
             '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' +
             VoxgigSekreto.uriescape(RESOURCE)

      status, body = VoxgigSekreto.fetchjson('GET', imds, { 'Metadata' => 'true' })

      got = body.is_a?(Hash) ? body['access_token'] : nil
      unless 200 == status && VoxgigSekreto.given(got)
        raise SekretoError,
              'sekreto: azure: no token, no client credentials, and IMDS did not answer'
      end

      @renewat = expiry(body['expires_in'])
      got.to_s
    end

    def lookup(name)
      vault = @opts['vault'] || ''
      raise SekretoError, 'sekreto: azure: no vault' if '' == vault

      # Only an explicit scheme is a URL; a vault NAMED httpvault must
      # still become https://httpvault.vault.azure.net.
      vaulturl = if vault.start_with?('http://', 'https://')
                   vault
                 else
                   'https://' + vault + '.vault.azure.net'
                 end
      VoxgigSekreto.checkaddr(vaulturl)

      @livetoken = login if @livetoken.nil? || Time.now.to_f >= @renewat

      url = vaulturl.sub(%r{/\z}, '') + '/secrets/' + VoxgigSekreto.flatname(name, '-') +
            '?api-version=' + (@opts['apiversion'] || '7.4')

      status, body = VoxgigSekreto.fetchjson('GET', url,
                                             { 'authorization' => 'Bearer ' + @livetoken })

      return nil if 404 == status

      if 200 != status
        raise SekretoError, 'sekreto: azure error: ' + status.to_s + ': ' + url.split('?')[0]
      end

      value = body.is_a?(Hash) ? body['value'] : nil
      value.nil? ? nil : value.to_s
    end

    def describe
      'azuresecrets:' + (@opts['vault'] || '')
    end
  end

  # 1Password, through a Connect server.
  #
  # The item titled `api.token` (titles keep their dots), in the named
  # vault. The value is the field with purpose PASSWORD, or the field
  # labelled `value`. A vault that cannot be found is an error - config
  # names it, so its absence is a broken store, not a missing secret.
  class OnepasswordProvider
    def initialize(opts = nil)
      @opts = opts || {}
      @vaultid = nil
    end

    def auth
      { 'authorization' => 'Bearer ' + (@opts['token'] || '') }
    end

    def resolvevault(addr)
      want = @opts['vault'] || ''
      raise SekretoError, 'sekreto: onepassword: no vault' if '' == want

      status, body = VoxgigSekreto.fetchjson('GET', addr + '/v1/vaults', auth)

      unless 200 == status && body.is_a?(Array)
        raise SekretoError, 'sekreto: onepassword error: ' + status.to_s + ': listing vaults'
      end

      body.each do |entry|
        return entry['id'].to_s if entry.is_a?(Hash) && (want == entry['id'] || want == entry['name'])
      end

      raise SekretoError, 'sekreto: onepassword: no vault named ' + want
    end

    def lookup(name)
      VoxgigSekreto.checkname(name)

      addr = (@opts['addr'] || '').sub(%r{/\z}, '')
      raise SekretoError, 'sekreto: onepassword: no addr' if '' == addr

      VoxgigSekreto.checkaddr(addr)

      @vaultid = resolvevault(addr) if @vaultid.nil?

      filter = VoxgigSekreto.uriescape('title eq "' + name + '"')
      status, found = VoxgigSekreto.fetchjson(
        'GET', addr + '/v1/vaults/' + @vaultid + '/items?filter=' + filter, auth
      )

      unless 200 == status && found.is_a?(Array)
        raise SekretoError, 'sekreto: onepassword error: ' + status.to_s + ': finding ' + name
      end

      return nil if found.empty?

      status, item = VoxgigSekreto.fetchjson(
        'GET', addr + '/v1/vaults/' + @vaultid + '/items/' + found[0]['id'].to_s, auth
      )

      if 200 != status
        raise SekretoError, 'sekreto: onepassword error: ' + status.to_s + ': reading ' + name
      end

      fields = item.is_a?(Hash) && item['fields'].is_a?(Array) ? item['fields'] : []

      fields.each do |field|
        next unless field.is_a?(Hash) && 'PASSWORD' == field['purpose']

        return field['value'].nil? ? nil : field['value'].to_s
      end
      fields.each do |field|
        next unless field.is_a?(Hash) && 'value' == field['label']

        return field['value'].nil? ? nil : field['value'].to_s
      end

      nil
    end

    def describe
      'onepassword:' + (@opts['vault'] || '')
    end
  end

  # Doppler.
  #
  # The whole config is downloaded once - Doppler's own bulk endpoint -
  # and answered from memory, like a remote .env: `api.token` is the
  # `API_TOKEN` entry. A service token is config-scoped, so project and
  # config are only needed with broader tokens.
  class DopplerProvider
    def initialize(opts = nil)
      @opts = opts || {}
      @values = nil
    end

    def load
      return @values unless @values.nil?

      addr = (@opts['addr'] || 'https://api.doppler.com').sub(%r{/\z}, '')
      VoxgigSekreto.checkaddr(addr)

      url = addr + '/v3/configs/config/secrets/download?format=json'
      url += '&project=' + VoxgigSekreto.uriescape(@opts['project']) if VoxgigSekreto.given(@opts['project'])
      url += '&config=' + VoxgigSekreto.uriescape(@opts['config']) if VoxgigSekreto.given(@opts['config'])

      status, body = VoxgigSekreto.fetchjson(
        'GET', url, { 'authorization' => 'Bearer ' + (@opts['token'] || '') }
      )

      raise SekretoError, 'sekreto: doppler error: ' + status.to_s if 200 != status || !body.is_a?(Hash)

      @values = {}
      body.each { |key, value| @values[key] = value.to_s unless value.nil? }

      @values
    end

    def lookup(name)
      load[VoxgigSekreto.envkey(name)]
    end

    def describe
      return 'doppler' unless VoxgigSekreto.given(@opts['project'])

      'doppler:' + @opts['project'] + '/' + (@opts['config'] || '')
    end
  end

  # Infisical.
  #
  # `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
  # convention is environment-style keys) at a secret path in one
  # environment of a project. Auth is a token, or a universal-auth
  # (machine identity) login with clientid/clientsecret.
  class InfisicalProvider
    def initialize(opts = nil)
      @opts = opts || {}

      # A configured token is kept forever; a universal-auth token carries
      # expiresIn and is renewed shortly before it runs out.
      @livetoken = nil
      @renewat = Float::INFINITY
    end

    def login(addr)
      return @opts['token'] if VoxgigSekreto.given(@opts['token'])

      unless VoxgigSekreto.given(@opts['clientid']) && VoxgigSekreto.given(@opts['clientsecret'])
        raise SekretoError, 'sekreto: infisical: no token and no client credentials'
      end

      status, body = VoxgigSekreto.fetchjson(
        'POST', addr + '/api/v1/auth/universal-auth/login',
        { 'content-type' => 'application/json' },
        JSON.generate('clientId' => @opts['clientid'], 'clientSecret' => @opts['clientsecret'])
      )

      got = body.is_a?(Hash) ? body['accessToken'] : nil
      unless 200 == status && VoxgigSekreto.given(got)
        raise SekretoError, 'sekreto: infisical login failed: ' + status.to_s
      end

      expires = body['expiresIn'].to_f
      @renewat = 0 < expires ? Time.now.to_f + [expires - 60, 1].max : Float::INFINITY

      got.to_s
    end

    def lookup(name)
      addr = (@opts['addr'] || 'https://app.infisical.com').sub(%r{/\z}, '')
      VoxgigSekreto.checkaddr(addr)

      project = @opts['project'] || ''
      environment = @opts['environment'] || ''
      if '' == project || '' == environment
        raise SekretoError, 'sekreto: infisical: no project/environment'
      end

      @livetoken = login(addr) if @livetoken.nil? || Time.now.to_f >= @renewat

      url = addr + '/api/v3/secrets/raw/' + VoxgigSekreto.envkey(name) +
            '?workspaceId=' + VoxgigSekreto.uriescape(project) +
            '&environment=' + VoxgigSekreto.uriescape(environment) +
            '&secretPath=' + VoxgigSekreto.uriescape(@opts['path'] || '/')

      status, body = VoxgigSekreto.fetchjson('GET', url,
                                             { 'authorization' => 'Bearer ' + @livetoken })

      return nil if 404 == status

      raise SekretoError, 'sekreto: infisical error: ' + status.to_s if 200 != status

      value = body.is_a?(Hash) && body['secret'].is_a?(Hash) ? body['secret']['secretValue'] : nil
      value.nil? ? nil : value.to_s
    end

    def describe
      'infisical:' + (@opts['project'] || '') + '/' + (@opts['environment'] || '')
    end
  end

  module_function

  # Build a provider from its declarative form.
  def makeprovider(spec)
    kind = spec['kind'] || spec[:kind]
    get = ->(key) { spec[key.to_s].nil? ? spec[key] : spec[key.to_s] }
    opts = ->(*keys) { keys.each_with_object({}) { |key, out| out[key.to_s] = get.call(key) } }

    case kind
    when 'env' then EnvProvider.new(get.call(:prefix))
    when 'dotenv' then DotenvProvider.new(get.call(:file) || '.env', get.call(:prefix))
    when 'memory' then MemoryProvider.new(get.call(:values) || {}, get.call(:prefix))
    when 'file' then FileProvider.new(get.call(:dir) || '', get.call(:prefix))
    when 'hashicorp'
      HashicorpProvider.new(get.call(:addr) || '', get.call(:token) || '',
                            opts.call(:mount, :kv, :vaultnamespace, :auth))
    when 'boru'
      BoruProvider.new(get.call(:command), get.call(:namespace), get.call(:home),
                       get.call(:addr), get.call(:token), get.call(:mount))
    when 'awssecrets'
      AwssecretsProvider.new(opts.call(:region, :keyid, :secret, :session, :addr))
    when 'awsparams'
      AwsparamsProvider.new(opts.call(:region, :keyid, :secret, :session, :addr, :prefix))
    when 'gcpsecrets'
      GcpsecretsProvider.new(opts.call(:project, :token, :addr, :metadataaddr))
    when 'azuresecrets'
      AzuresecretsProvider.new(opts.call(:vault, :token, :tenant, :clientid, :clientsecret,
                                         :loginaddr, :imdsaddr, :apiversion))
    when 'onepassword'
      OnepasswordProvider.new(opts.call(:addr, :token, :vault))
    when 'doppler'
      DopplerProvider.new(opts.call(:token, :project, :config, :addr))
    when 'infisical'
      InfisicalProvider.new(opts.call(:addr, :token, :clientid, :clientsecret,
                                      :project, :environment, :path))
    else raise SekretoError, 'sekreto: unknown provider kind: ' + kind.to_s
    end
  end
end
