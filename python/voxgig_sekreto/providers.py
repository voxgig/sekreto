# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns
# the value, or None to mean "ask the next one". Nothing else about a
# provider is visible to the caller - which is the point: an app reads
# `api.token` and never learns whether it came from the environment, a
# .env file, HashiCorp Vault or a boru vault.
#
# Two failure shapes, and they are never interchangeable. A store that
# does not hold the secret is a MISS (None) - the chain carries on. A
# store that could not answer - bad credentials, unreachable host,
# missing configuration - is an ERROR: falling through there would
# quietly reach for a weaker store.
#
# A port of typescript/src/Providers.ts, which is canonical.

import base64
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from .sekreto import (
    SekretoError,
    awsparam,
    checkname,
    envkey,
    flatname,
    parsedotenv,
    vaultref,
)
from .sigv4 import sigv4


class Provider:
    """A source of secrets. `lookup` returns the value or None."""

    def lookup(self, name):
        raise NotImplementedError

    def describe(self):
        raise NotImplementedError


class EnvProvider(Provider):
    """Environment variables: `api.token` from `API_TOKEN`."""

    def __init__(self, prefix=None, source=None):
        self.prefix = prefix
        self.source = source if source is not None else os.environ

    def lookup(self, name):
        value = self.source.get(envkey(name, self.prefix))
        return None if value is None else str(value)

    def describe(self):
        return 'env' + (':' + self.prefix if self.prefix else '')


class DotenvProvider(Provider):
    """A `.env` file, read once, keyed exactly like the environment."""

    def __init__(self, file, prefix=None):
        self.file = file
        self.prefix = prefix
        self.values = None

    def load(self):
        if self.values is None:
            try:
                with open(self.file, 'r', encoding='utf8') as handle:
                    self.values = parsedotenv(handle.read())
            except (FileNotFoundError, NotADirectoryError):
                # An absent file - or an absent directory - means "no
                # secrets here", exactly like FileProvider. Anything else
                # (permission denied, an unreadable mount) is a store that
                # could not answer, and swallowing it would fall through to
                # a weaker store.
                self.values = {}
            except OSError as err:
                raise SekretoError(
                    'sekreto: dotenv provider cannot read ' + self.file + ': ' + str(err)
                )
        return self.values

    def lookup(self, name):
        return self.load().get(envkey(name, self.prefix))

    def describe(self):
        return 'dotenv:' + self.file


class MemoryProvider(Provider):
    """Literal values, keyed like environment variables. The spec uses this
    to test chain behaviour without touching the outside world."""

    def __init__(self, values, prefix=None):
        self.values = values or {}
        self.prefix = prefix

    def lookup(self, name):
        return self.values.get(envkey(name, self.prefix))

    def describe(self):
        return 'memory' + (':' + self.prefix if self.prefix else '')


class FileProvider(Provider):
    """A directory of one-secret-per-file entries, keyed like the
    environment: `api.token` reads `<dir>/API_TOKEN`.

    This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
    secret, and a systemd credentials directory, so those all work with no
    further configuration. One trailing newline is stripped - tools that
    write these files disagree about it, and a newline is never part of a
    secret on purpose.
    """

    def __init__(self, dir, prefix=None):
        self.dir = dir
        self.prefix = prefix

    def lookup(self, name):
        file = os.path.join(self.dir, envkey(name, self.prefix))

        try:
            with open(file, 'r', encoding='utf8') as handle:
                text = handle.read()
        except (FileNotFoundError, NotADirectoryError):
            # An absent file - or an absent directory - means "no secrets
            # here", exactly like a missing .env. Anything else (permission
            # denied, an unreadable mount) is a store that could not answer.
            return None
        except OSError as err:
            raise SekretoError(
                'sekreto: file provider cannot read ' + file + ': ' + str(err)
            )

        if text.endswith('\r\n'):
            return text[:-2]
        if text.endswith('\n'):
            return text[:-1]
        return text

    def describe(self):
        return 'file:' + self.dir


_HTTP_TIMEOUT = 10  # seconds; the same bound every port carries


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that refuses to follow: a vault API never
    legitimately redirects, and following one would resend the vault token
    to the redirect's host."""

    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _fetchjson(method, url, headers, body=None):
    """One JSON round-trip, returning (status, parsed-json-or-None).

    A 404 is a normal answer here, not an exception: callers decide on
    status. Network failure is always an error - an unreachable store is a
    store that could not answer.
    """
    data = None if body is None else body.encode('utf8')
    request = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        # No redirects (a followed one carries X-Vault-Token to the target,
        # which checkaddr cannot see) and a bounded wait (an accepted-but-
        # silent endpoint must not hang the caller forever). A 3xx surfaces
        # as an HTTPError below and is treated as a store error.
        with _opener.open(request, timeout=_HTTP_TIMEOUT) as response:
            status = response.status
            text = response.read().decode('utf8')
    except urllib.error.HTTPError as err:
        status = err.code
        text = err.read().decode('utf8')
    except urllib.error.URLError as err:
        raise SekretoError(
            'sekreto: cannot reach ' + url.split('?')[0] + ': ' + str(err.reason)
        )

    try:
        return status, json.loads(text)
    except ValueError:
        # A success status promised JSON; a body that does not parse means
        # the store could not answer coherently, and treating it as a miss
        # would fall through to a weaker store. Error statuses may carry
        # any body - they are decided on status alone.
        if 200 == status:
            raise SekretoError('sekreto: malformed response from ' + url.split('?')[0])
        return status, None


def urlpart(text):
    """One URL component, escaped the way encodeURIComponent does it -
    the addresses built here must match the canonical port's byte for
    byte."""
    return urllib.parse.quote(str(text), safe="-_.!~*'()")


def _tonumber(value):
    """The canonical port's Number() as expiry fields need it: a number
    or numeric string converts (expires_in may arrive as a string);
    anything else becomes 0, which means "never renew"."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0


def checkaddr(addr):
    """Refuse to send a Vault token in the clear.

    Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
    convenience. Sending `X-Vault-Token` over http to anything but the local
    machine puts both the token and the secret it fetches on the wire for
    anyone on the path, so sekreto will not do it. Loopback stays allowed:
    that is `vault server -dev` and this repo's own test harness.

    The address is read by hand, in the same handful of steps in every port,
    rather than by each platform's URL parser. That is deliberate. Twelve
    parsers disagree about malformed input - where userinfo ends, whether
    `0177.0.0.1` is loopback, what an unclosed bracket means - and a check
    that answers differently in different ports is not a check.

    The rule this parse obeys, and the reason it can be trusted: it is never
    more permissive than the HTTP client that will dial the address. It ends
    the authority at `/`, `?` or `#` only, so a client that also breaks on
    `\\` (WHATWG does) can only ever see a SHORTER host than this does. It
    refuses userinfo outright rather than locating its end. It compares the
    host literally, so a numeric form no parser here agrees on is refused
    rather than guessed at.
    """
    if addr.startswith('https://'):
        scheme = 'https://'
    elif addr.startswith('http://'):
        scheme = 'http://'
    else:
        raise SekretoError('sekreto: not an http(s) address: ' + addr)

    rest = addr[len(scheme):]
    end = len(rest)
    for mark in ('/', '?', '#'):
        at = rest.find(mark)
        if -1 != at and at < end:
            end = at
    authority = rest[:end]

    # Userinfo is refused outright rather than parsed around, and on https as
    # well as http. No store this library speaks authenticates by userinfo -
    # they take a token or a signature - so an address carrying one is a
    # mistake at best. At worst it is the attack this whole function exists
    # to stop: `http://localhost:8200@evil.example.com/` is a request to
    # evil.example.com that reads, to anything that splits the authority on
    # ':', as loopback.
    if '@' in authority:
        raise SekretoError(
            'sekreto: refusing an address with embedded credentials: ' + addr
        )

    # An opening bracket with no closing one is not an address at all.
    if authority.startswith('[') and ']' not in authority:
        raise SekretoError('sekreto: not a valid http(s) address: ' + addr)

    if 'https://' == scheme:
        return

    # A bracketed IPv6 literal keeps its brackets. Splitting the authority on
    # the first colon yields '[', so `http://[::1]:8200` could never match -
    # which made the '[::1]' entry below unreachable, and refused a
    # legitimate local vault.
    if authority.startswith('['):
        host = authority[:authority.index(']') + 1]
    else:
        host = authority.split(':')[0]

    if host.lower() in ('localhost', '127.0.0.1', '::1', '[::1]'):
        return

    raise SekretoError(
        'sekreto: refusing to send a token in plaintext to ' + addr + ' (use https)'
    )


class HashicorpProvider(Provider):
    """HashiCorp Vault.

    KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api`
    and takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
    `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means
    "not here" - a miss - so a vault can sit in a chain with fallbacks.

    A Vault Enterprise namespace rides the X-Vault-Namespace header, on
    logins as well as reads.

    Instead of being handed a token, the provider can log in: Kubernetes
    auth (the pod's service-account JWT, from its conventional path) or
    AppRole. A failed login is an error, never a miss - it means this
    store could not answer at all.
    """

    def __init__(self, addr, token, mount=None, kv=None, vaultnamespace=None, auth=None):
        self.addr = addr
        self.mount = mount or 'secret'
        self.kv = kv or 2
        self.vaultnamespace = vaultnamespace
        self.auth = auth

        # A version typo like kv: 3 must not quietly behave as v2 and turn
        # its 404s into misses; there is nothing safe to assume it meant.
        if 1 != self.kv and 2 != self.kv:
            raise SekretoError(
                'sekreto: hashicorp: unsupported kv version: ' + str(self.kv)
            )

        # The working token: a configured token is kept forever, a logged-in
        # token is renewed shortly before its lease runs out - a long-running
        # process must not keep presenting a token the vault already expired.
        self.livetoken = None if '' == token else token
        self.renewat = float('inf')

    def baseheaders(self):
        headers = {}
        if self.vaultnamespace:
            headers['X-Vault-Namespace'] = self.vaultnamespace
        return headers

    def login(self):
        auth = self.auth
        if not auth:
            raise SekretoError('sekreto: hashicorp: no token and no auth method')

        method = auth.get('method')
        mount = auth.get('mount') or method
        url = self.addr.rstrip('/') + '/v1/auth/' + str(mount) + '/login'

        if 'kubernetes' == method:
            jwt = auth.get('jwt')
            if jwt is None:
                file = (
                    auth.get('jwtfile')
                    or '/var/run/secrets/kubernetes.io/serviceaccount/token'
                )
                try:
                    with open(file, 'r', encoding='utf8') as handle:
                        jwt = handle.read().strip()
                except OSError:
                    raise SekretoError('sekreto: hashicorp: cannot read jwt file ' + file)
            body = {'role': auth.get('role') or '', 'jwt': jwt}
        elif 'approle' == method:
            body = {
                'role_id': auth.get('roleid') or '',
                'secret_id': auth.get('secretid') or '',
            }
        else:
            raise SekretoError(
                'sekreto: hashicorp: unknown auth method: ' + str(method)
            )

        status, resbody = _fetchjson(
            'POST', url, self.baseheaders(), json.dumps(body, separators=(',', ':'))
        )

        got = ((resbody or {}).get('auth') or {}).get('client_token')
        if 200 != status or not got:
            raise SekretoError(
                'sekreto: hashicorp login failed: ' + str(status) + ': ' + url
            )

        lease = _tonumber(((resbody or {}).get('auth') or {}).get('lease_duration'))
        self.renewat = time.time() + max(lease - 60, 1) if 0 < lease else float('inf')

        return str(got)

    def lookup(self, name):
        checkaddr(self.addr)

        if self.livetoken is None or time.time() >= self.renewat:
            self.livetoken = self.login()

        ref = vaultref(name)
        base = self.addr.rstrip('/') + '/v1/' + self.mount
        url = base + '/' + ref['path'] if 1 == self.kv else base + '/data/' + ref['path']

        headers = self.baseheaders()
        headers['X-Vault-Token'] = self.livetoken

        status, body = _fetchjson('GET', url, headers)

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: hashicorp error: ' + str(status) + ': ' + url)

        if 1 == self.kv:
            data = (body or {}).get('data')
        else:
            data = ((body or {}).get('data') or {}).get('data')

        value = data.get(ref['field']) if isinstance(data, dict) else None

        return None if value is None else str(value)

    def describe(self):
        return 'hashicorp:' + self.addr + '/' + self.mount


class BoruProvider(Provider):
    """A boru vault (https://github.com/boru-lang/boru).

    Two ways in, both boru's own.

    With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
    secret on stdout and nothing else. The passphrase is read by boru
    itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as
    config and never puts it on a command line, where it would show up in
    the process table.

    With an `addr`, boru's wire protocol: `boru vault serve` publishes a
    read-only, HashiCorp-shaped provision API (boru's
    design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
    from `boru vault grant`. A sekreto name is already a valid boru
    alias, and boru aliases keep their dots, so `api.token` is the single
    path segment `api.token` - not the `api`/`token` split a HashiCorp KV
    gets. The value is the `value` field. A 404 is a miss; anything else
    the server refuses (a revoked capability, a sealed vault) is an
    error.

    boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
    credential *broker*, built precisely so the caller never receives the
    credential. `vault serve` is the provision endpoint, built to hand
    the value back - that is the one sekreto uses.
    """

    def __init__(self, command=None, namespace=None, home=None,
                 addr=None, token=None, mount=None):
        self.command = command or 'boru'
        self.namespace = namespace
        self.home = home
        self.addr = addr.rstrip('/') if addr else None
        self.token = token
        self.mount = mount or 'secret'

    def lookup(self, name):
        checkname(name)

        if self.addr:
            return self.wirelookup(name)

        alias = self.namespace + ':' + name if self.namespace else name

        env = dict(os.environ)
        if self.home:
            env['BORU_HOME'] = self.home

        try:
            run = subprocess.run(
                [self.command, 'vault', 'get', '--reveal', alias],
                capture_output=True,
                text=True,
                env=env,
            )
        except OSError as err:
            raise SekretoError('sekreto: cannot run ' + self.command + ': ' + str(err))

        if 0 == run.returncode:
            # boru prints the value and one newline, and nothing else.
            return run.stdout[:-1] if run.stdout.endswith('\n') else run.stdout

        why = (run.stderr or '').strip()

        # "no alias named" is boru saying it does not hold this secret, which
        # is a miss: the chain carries on to the next provider. A locked vault
        # or a wrong passphrase is not a miss - treating it as one would fall
        # through to a weaker store without saying so.
        if borumiss(why):
            return None

        raise SekretoError(
            'sekreto: boru vault error: ' + (why or 'exit ' + str(run.returncode))
        )

    def wirelookup(self, name):
        checkaddr(self.addr)

        alias = self.namespace + '/' + name if self.namespace else name
        url = self.addr + '/v1/' + self.mount + '/data/' + alias

        status, body = _fetchjson('GET', url, {'X-Vault-Token': self.token or ''})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: boru serve error: ' + str(status) + ': ' + url)

        data = ((body or {}).get('data') or {}).get('data')
        value = data.get('value') if isinstance(data, dict) else None

        return None if value is None else str(value)

    def describe(self):
        if self.addr:
            return 'boru:' + self.addr
        return 'boru' + (':' + self.namespace if self.namespace else '')


def borumiss(why):
    """Does this boru failure mean "no such secret" rather than "I could not
    answer"? Matched on boru's own wording for a missing alias."""
    return 'no alias named' in why


class SecretspecProvider(Provider):
    """SecretSpec (https://secretspec.dev).

    SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
    project needs - plus a chain of its own backends to satisfy them from.
    That makes it the same shape as sekreto one level down, and the reason
    to support it is the same reason sekreto exists: a project that has
    already declared its secrets there should not have to declare them
    again here.

    Read through its CLI, as boru is, because that is the interface it
    offers a program in another language: `secretspec get API_TOKEN`
    prints the value on stdout and nothing else. A sekreto name maps to a
    SecretSpec key exactly as it maps to an environment variable -
    `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
    examples use.

    `backend` selects one of SecretSpec's backends (`--provider`, e.g.
    `keyring` or `dotenv://.env`) and is called `backend` here only
    because `provider` already means something else in this library.

    A reason is required, not optional: SecretSpec records every read in
    an audit log and refuses to read at all without one. sekreto sends
    `sekreto` unless told otherwise, so the audit trail says which tool
    asked.
    """

    def __init__(self, command=None, file=None, profile=None,
                 backend=None, reason=None, prefix=None):
        self.command = command or 'secretspec'
        self.file = file
        self.profile = profile
        self.backend = backend
        self.reason = reason
        self.prefix = prefix

    def lookup(self, name):
        key = envkey(name, self.prefix)

        args = [self.command]
        if self.file:
            args += ['--file', self.file]
        args += ['get', key]
        if self.backend:
            args += ['--provider', self.backend]
        if self.profile:
            args += ['--profile', self.profile]
        args += ['--reason', self.reason or 'sekreto']

        try:
            run = subprocess.run(args, capture_output=True, text=True)
        except OSError as err:
            raise SekretoError('sekreto: cannot run ' + self.command + ': ' + str(err))

        if 0 == run.returncode:
            # The value and one newline, and nothing else.
            return run.stdout[:-1] if run.stdout.endswith('\n') else run.stdout

        why = (run.stderr or '').strip()

        if secretspecmiss(why, key):
            return None

        raise SekretoError(
            'sekreto: secretspec error: ' + (why or 'exit ' + str(run.returncode))
        )

    def describe(self):
        return 'secretspec' + (':' + self.backend if self.backend else '')


def secretspecmiss(why, key):
    """Does this SecretSpec failure mean "no such secret" rather than "I
    could not answer"?

    SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
    not declare and one declared with no value, and both are misses: this
    store does not hold it, so the chain carries on.

    MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
    `Provider backend 'keyring' not found`, which is a store that could
    not answer at all - and reading that as a miss is the worst failure
    this library has, because the chain then falls through to a weaker
    store without saying so. The key is required to appear, so the two
    cannot be confused."""
    return ("Secret '" + key + "' not found") in why


def awsnow():
    """The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now."""
    return time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())


def awsauth(opts):
    """Region and credentials, from config first and the standard AWS_*
    environment variables second - those are AWS's own convention, and a
    pod or CI job that has them set should just work. Missing either is
    an error: an AWS store with no credentials could not answer."""
    env = os.environ

    region = opts.get('region') or env.get('AWS_REGION') or env.get('AWS_DEFAULT_REGION') or ''
    keyid = opts.get('keyid') or env.get('AWS_ACCESS_KEY_ID') or ''
    secret = opts.get('secret') or env.get('AWS_SECRET_ACCESS_KEY') or ''
    session = opts.get('session') or env.get('AWS_SESSION_TOKEN') or None

    if '' == region:
        raise SekretoError('sekreto: aws: no region (set region or AWS_REGION)')
    if '' == keyid or '' == secret:
        raise SekretoError(
            'sekreto: aws: no credentials (set keyid/secret or'
            + ' AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)'
        )

    return {'region': region, 'keyid': keyid, 'secret': secret, 'session': session}


def awscall(opts, service, target, payload):
    """One signed call to an AWS JSON-1.1 API."""
    auth = awsauth(opts)
    # The China partition lives under its own suffix; every other
    # commercial region is plain amazonaws.com.
    suffix = '.amazonaws.com.cn' if auth['region'].startswith('cn-') else '.amazonaws.com'
    addr = opts.get('addr') or 'https://' + service + '.' + auth['region'] + suffix
    checkaddr(addr)

    url = addr.rstrip('/') + '/'
    body = json.dumps(payload, separators=(',', ':'))
    headers = {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': target,
    }

    signed = sigv4({
        'method': 'POST',
        'url': url,
        'headers': headers,
        'body': body,
        'service': service,
        'region': auth['region'],
        'keyid': auth['keyid'],
        'secret': auth['secret'],
        'session': auth['session'],
        'datetime': awsnow(),
    })

    allheaders = dict(headers)
    allheaders.update(signed)

    return _fetchjson('POST', url, allheaders, body)


def awsmiss(body, types):
    """Does this AWS error body name one of the not-found types? Those are
    a miss; every other failure is a store that could not answer."""
    errtype = body.get('__type') if isinstance(body, dict) else None
    if not isinstance(errtype, str):
        errtype = ''
    return any(name in errtype for name in types)


class AwssecretsProvider(Provider):
    """AWS Secrets Manager.

    `api.token` reads the secret named `api` (the vaultref path, so
    `db.pass.main` reads `db/pass`) and takes the `token` field of its
    JSON SecretString - the AWS idiom of one JSON map per secret. A
    SecretString that is not JSON is the value itself, under the
    conventional field `value`. Requests are SigV4-signed in-tree; see
    sigv4.py.
    """

    def __init__(self, options=None):
        self.opts = options or {}

    def lookup(self, name):
        ref = vaultref(name)

        status, body = awscall(
            self.opts, 'secretsmanager', 'secretsmanager.GetSecretValue',
            {'SecretId': ref['path']},
        )

        if 400 == status and awsmiss(body, ['ResourceNotFoundException']):
            return None

        if 200 != status:
            raise SekretoError('sekreto: aws secretsmanager error: ' + str(status))

        text = (body or {}).get('SecretString')

        if not isinstance(text, str):
            # A binary secret has no fields to address; only the conventional
            # `value` field can mean "the bytes themselves".
            binary = (body or {}).get('SecretBinary')
            if isinstance(binary, str) and 'value' == ref['field']:
                return base64.b64decode(binary).decode('utf8')
            return None

        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None

        if isinstance(parsed, dict):
            value = parsed.get(ref['field'])
            return None if value is None else str(value)

        # A plain-string secret is the whole value; it has no named fields.
        return text if 'value' == ref['field'] else None

    def describe(self):
        # Config only, never the environment: describe() feeds the spec's
        # sources group, which must answer the same everywhere.
        return 'awssecrets:' + (self.opts.get('region') or '')


class AwsparamsProvider(Provider):
    """AWS SSM Parameter Store.

    `db.pass.main` reads the parameter `/db/pass/main` (under an optional
    prefix path), decrypted. Parameter Store carries flat strings, so
    there is no field indirection.
    """

    def __init__(self, options=None):
        self.opts = options or {}

    def lookup(self, name):
        status, body = awscall(self.opts, 'ssm', 'AmazonSSM.GetParameter', {
            'Name': awsparam(name, self.opts.get('prefix')),
            'WithDecryption': True,
        })

        if 400 == status and awsmiss(body, ['ParameterNotFound']):
            return None

        if 200 != status:
            raise SekretoError('sekreto: aws ssm error: ' + str(status))

        value = ((body or {}).get('Parameter') or {}).get('Value')
        return None if value is None else str(value)

    def describe(self):
        return 'awsparams:' + (self.opts.get('region') or '') + (self.opts.get('prefix') or '')


class GcpsecretsProvider(Provider):
    """GCP Secret Manager.

    `api.token` reads secret `api_token` (dots flattened to `_`; Secret
    Manager ids have no hierarchy and reject dots), latest version. The
    token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
    GCE/GKE metadata server - so on Google's own platform no credential
    configuration is needed at all.

    The metadata call itself is plain http to a link-local host by
    platform design; no credential rides on it, so `checkaddr` guards the
    Secret Manager address instead.
    """

    def __init__(self, options=None):
        self.opts = options or {}

        # A configured token is kept forever; a metadata-server token carries
        # expires_in and is renewed shortly before it runs out.
        self.livetoken = None
        self.renewat = float('inf')

    def metadataaddr(self):
        if self.opts.get('metadataaddr'):
            return self.opts['metadataaddr']
        host = os.environ.get('GCE_METADATA_HOST')
        return 'http://' + host if host else 'http://metadata.google.internal'

    def login(self):
        configured = self.opts.get('token') or os.environ.get('GOOGLE_OAUTH_ACCESS_TOKEN')
        if configured:
            return configured

        url = (self.metadataaddr().rstrip('/')
               + '/computeMetadata/v1/instance/service-accounts/default/token')

        status, body = _fetchjson('GET', url, {'Metadata-Flavor': 'Google'})

        got = (body or {}).get('access_token')
        if 200 != status or not got:
            raise SekretoError('sekreto: gcp: no token and metadata server did not answer')

        expires = _tonumber((body or {}).get('expires_in'))
        self.renewat = time.time() + max(expires - 60, 1) if 0 < expires else float('inf')

        return str(got)

    def lookup(self, name):
        project = self.opts.get('project') or ''
        if '' == project:
            raise SekretoError('sekreto: gcp: no project')

        addr = self.opts.get('addr') or 'https://secretmanager.googleapis.com'
        checkaddr(addr)

        if self.livetoken is None or time.time() >= self.renewat:
            self.livetoken = self.login()

        url = (addr.rstrip('/') + '/v1/projects/' + project + '/secrets/'
               + flatname(name, '_') + '/versions/latest:access')

        status, body = _fetchjson('GET', url, {'authorization': 'Bearer ' + self.livetoken})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: gcp error: ' + str(status) + ': ' + url)

        data = ((body or {}).get('payload') or {}).get('data')
        if not isinstance(data, str):
            return None

        return base64.b64decode(data).decode('utf8')

    def describe(self):
        return 'gcpsecrets:' + (self.opts.get('project') or '')


class AzuresecretsProvider(Provider):
    """Azure Key Vault.

    `api.token` reads secret `api-token` (dots flattened to `-`; Key
    Vault names allow nothing else), current version. The token comes
    from config, then a client-credentials login when tenant/clientid/
    clientsecret are given, then the IMDS managed-identity endpoint - so
    on Azure's own platform no credential configuration is needed.

    As with GCP, the IMDS call is plain http to a link-local host by
    platform design and carries no credential; the login and vault
    addresses are `checkaddr`-guarded.
    """

    RESOURCE = 'https://vault.azure.net'

    def __init__(self, options=None):
        self.opts = options or {}

        # A configured token is kept forever; logged-in and IMDS tokens carry
        # expires_in and are renewed shortly before they run out.
        self.livetoken = None
        self.renewat = float('inf')

    def expiry(self, expires):
        seconds = _tonumber(expires)
        return time.time() + max(seconds - 60, 1) if 0 < seconds else float('inf')

    def login(self):
        opts = self.opts

        if opts.get('token'):
            return opts['token']

        if opts.get('tenant') and opts.get('clientid') and opts.get('clientsecret'):
            loginaddr = opts.get('loginaddr') or 'https://login.microsoftonline.com'
            checkaddr(loginaddr)

            url = loginaddr.rstrip('/') + '/' + opts['tenant'] + '/oauth2/v2.0/token'
            form = ('grant_type=client_credentials&client_id=' + urlpart(opts['clientid'])
                    + '&client_secret=' + urlpart(opts['clientsecret'])
                    + '&scope=' + urlpart(self.RESOURCE + '/.default'))

            status, body = _fetchjson(
                'POST', url, {'content-type': 'application/x-www-form-urlencoded'}, form
            )

            got = (body or {}).get('access_token')
            if 200 != status or not got:
                raise SekretoError('sekreto: azure login failed: ' + str(status))

            self.renewat = self.expiry((body or {}).get('expires_in'))
            return str(got)

        imds = ((opts.get('imdsaddr') or 'http://169.254.169.254').rstrip('/')
                + '/metadata/identity/oauth2/token?api-version=2018-02-01&resource='
                + urlpart(self.RESOURCE))

        status, body = _fetchjson('GET', imds, {'Metadata': 'true'})

        got = (body or {}).get('access_token')
        if 200 != status or not got:
            raise SekretoError(
                'sekreto: azure: no token, no client credentials, and IMDS did not answer'
            )

        self.renewat = self.expiry((body or {}).get('expires_in'))
        return str(got)

    def lookup(self, name):
        vault = self.opts.get('vault') or ''
        if '' == vault:
            raise SekretoError('sekreto: azure: no vault')

        # Only an explicit scheme is a URL; a vault NAMED httpvault must
        # still become https://httpvault.vault.azure.net.
        if vault.startswith('http://') or vault.startswith('https://'):
            vaulturl = vault
        else:
            vaulturl = 'https://' + vault + '.vault.azure.net'
        checkaddr(vaulturl)

        if self.livetoken is None or time.time() >= self.renewat:
            self.livetoken = self.login()

        url = (vaulturl.rstrip('/') + '/secrets/' + flatname(name, '-')
               + '?api-version=' + (self.opts.get('apiversion') or '7.4'))

        status, body = _fetchjson('GET', url, {'authorization': 'Bearer ' + self.livetoken})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError(
                'sekreto: azure error: ' + str(status) + ': ' + url.split('?')[0]
            )

        value = (body or {}).get('value')
        return None if value is None else str(value)

    def describe(self):
        return 'azuresecrets:' + (self.opts.get('vault') or '')


class OnepasswordProvider(Provider):
    """1Password, through a Connect server.

    The item titled `api.token` (titles keep their dots), in the named
    vault. The value is the field with purpose PASSWORD, or the field
    labelled `value`. A vault that cannot be found is an error - config
    names it, so its absence is a broken store, not a missing secret.
    """

    def __init__(self, options=None):
        self.opts = options or {}
        self.vaultid = None

    def authheaders(self):
        return {'authorization': 'Bearer ' + (self.opts.get('token') or '')}

    def resolvevault(self, addr):
        want = self.opts.get('vault') or ''
        if '' == want:
            raise SekretoError('sekreto: onepassword: no vault')

        status, body = _fetchjson('GET', addr + '/v1/vaults', self.authheaders())

        if 200 != status or not isinstance(body, list):
            raise SekretoError(
                'sekreto: onepassword error: ' + str(status) + ': listing vaults'
            )

        for entry in body:
            if isinstance(entry, dict) and (want == entry.get('id') or want == entry.get('name')):
                return str(entry.get('id'))

        raise SekretoError('sekreto: onepassword: no vault named ' + want)

    def lookup(self, name):
        checkname(name)

        addr = (self.opts.get('addr') or '').rstrip('/')
        if '' == addr:
            raise SekretoError('sekreto: onepassword: no addr')
        checkaddr(addr)

        if self.vaultid is None:
            self.vaultid = self.resolvevault(addr)

        filterpart = urlpart('title eq "' + name + '"')
        status, found = _fetchjson(
            'GET',
            addr + '/v1/vaults/' + self.vaultid + '/items?filter=' + filterpart,
            self.authheaders(),
        )

        if 200 != status or not isinstance(found, list):
            raise SekretoError(
                'sekreto: onepassword error: ' + str(status) + ': finding ' + name
            )

        if 0 == len(found):
            return None

        status, item = _fetchjson(
            'GET',
            addr + '/v1/vaults/' + self.vaultid + '/items/' + str(found[0].get('id')),
            self.authheaders(),
        )

        if 200 != status:
            raise SekretoError(
                'sekreto: onepassword error: ' + str(status) + ': reading ' + name
            )

        fields = (item or {}).get('fields') or []

        for field in fields:
            if isinstance(field, dict) and 'PASSWORD' == field.get('purpose'):
                value = field.get('value')
                return None if value is None else str(value)
        for field in fields:
            if isinstance(field, dict) and 'value' == field.get('label'):
                value = field.get('value')
                return None if value is None else str(value)

        return None

    def describe(self):
        return 'onepassword:' + (self.opts.get('vault') or '')


class DopplerProvider(Provider):
    """Doppler.

    The whole config is downloaded once - Doppler's own bulk endpoint -
    and answered from memory, like a remote .env: `api.token` is the
    `API_TOKEN` entry. A service token is config-scoped, so project and
    config are only needed with broader tokens.
    """

    def __init__(self, options=None):
        self.opts = options or {}
        self.values = None

    def load(self):
        if self.values is not None:
            return self.values

        addr = (self.opts.get('addr') or 'https://api.doppler.com').rstrip('/')
        checkaddr(addr)

        url = addr + '/v3/configs/config/secrets/download?format=json'
        if self.opts.get('project'):
            url += '&project=' + urlpart(self.opts['project'])
        if self.opts.get('config'):
            url += '&config=' + urlpart(self.opts['config'])

        status, body = _fetchjson(
            'GET', url, {'authorization': 'Bearer ' + (self.opts.get('token') or '')}
        )

        if 200 != status or not isinstance(body, dict):
            raise SekretoError('sekreto: doppler error: ' + str(status))

        self.values = {}
        for key, value in body.items():
            if value is not None:
                self.values[key] = str(value)

        return self.values

    def lookup(self, name):
        return self.load().get(envkey(name))

    def describe(self):
        if self.opts.get('project'):
            return 'doppler:' + self.opts['project'] + '/' + (self.opts.get('config') or '')
        return 'doppler'


class InfisicalProvider(Provider):
    """Infisical.

    `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
    convention is environment-style keys) at a secret path in one
    environment of a project. Auth is a token, or a universal-auth
    (machine identity) login with clientid/clientsecret.
    """

    def __init__(self, options=None):
        self.opts = options or {}

        # A configured token is kept forever; a universal-auth token carries
        # expiresIn and is renewed shortly before it runs out.
        self.livetoken = None
        self.renewat = float('inf')

    def login(self, addr):
        if self.opts.get('token'):
            return self.opts['token']

        if not self.opts.get('clientid') or not self.opts.get('clientsecret'):
            raise SekretoError('sekreto: infisical: no token and no client credentials')

        status, body = _fetchjson(
            'POST',
            addr + '/api/v1/auth/universal-auth/login',
            {'content-type': 'application/json'},
            json.dumps(
                {'clientId': self.opts['clientid'], 'clientSecret': self.opts['clientsecret']},
                separators=(',', ':'),
            ),
        )

        got = (body or {}).get('accessToken')
        if 200 != status or not got:
            raise SekretoError('sekreto: infisical login failed: ' + str(status))

        expires = _tonumber((body or {}).get('expiresIn'))
        self.renewat = time.time() + max(expires - 60, 1) if 0 < expires else float('inf')

        return str(got)

    def lookup(self, name):
        addr = (self.opts.get('addr') or 'https://app.infisical.com').rstrip('/')
        checkaddr(addr)

        project = self.opts.get('project') or ''
        environment = self.opts.get('environment') or ''
        if '' == project or '' == environment:
            raise SekretoError('sekreto: infisical: no project/environment')

        if self.livetoken is None or time.time() >= self.renewat:
            self.livetoken = self.login(addr)

        url = (addr + '/api/v3/secrets/raw/' + envkey(name)
               + '?workspaceId=' + urlpart(project)
               + '&environment=' + urlpart(environment)
               + '&secretPath=' + urlpart(self.opts.get('path') or '/'))

        status, body = _fetchjson('GET', url, {'authorization': 'Bearer ' + self.livetoken})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: infisical error: ' + str(status))

        value = ((body or {}).get('secret') or {}).get('secretValue')
        return None if value is None else str(value)

    def describe(self):
        return ('infisical:' + (self.opts.get('project') or '')
                + '/' + (self.opts.get('environment') or ''))


def makeprovider(spec):
    """Build a provider from its declarative form."""
    kind = spec.get('kind')

    if 'env' == kind:
        return EnvProvider(spec.get('prefix'))
    if 'dotenv' == kind:
        return DotenvProvider(spec.get('file') or '.env', spec.get('prefix'))
    if 'memory' == kind:
        return MemoryProvider(spec.get('values') or {}, spec.get('prefix'))
    if 'file' == kind:
        return FileProvider(spec.get('dir') or '', spec.get('prefix'))
    if 'hashicorp' == kind:
        return HashicorpProvider(
            spec.get('addr') or '',
            spec.get('token') or '',
            spec.get('mount'),
            spec.get('kv'),
            spec.get('vaultnamespace'),
            spec.get('auth'),
        )
    if 'boru' == kind:
        return BoruProvider(
            spec.get('command'),
            spec.get('namespace'),
            spec.get('home'),
            spec.get('addr'),
            spec.get('token'),
            spec.get('mount'),
        )
    if 'awssecrets' == kind:
        return AwssecretsProvider(spec)
    if 'awsparams' == kind:
        return AwsparamsProvider(spec)
    if 'gcpsecrets' == kind:
        return GcpsecretsProvider(spec)
    if 'azuresecrets' == kind:
        return AzuresecretsProvider(spec)
    if 'onepassword' == kind:
        return OnepasswordProvider(spec)
    if 'doppler' == kind:
        return DopplerProvider(spec)
    if 'infisical' == kind:
        return InfisicalProvider(spec)
    if 'secretspec' == kind:
        return SecretspecProvider(
            spec.get('command'),
            spec.get('file'),
            spec.get('profile'),
            spec.get('backend'),
            spec.get('reason'),
            spec.get('prefix'),
        )

    raise SekretoError('sekreto: unknown provider kind: ' + str(kind))
