# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns
# the value, or None to mean "ask the next one". Nothing else about a
# provider is visible to the caller - which is the point: an app reads
# `api.token` and never learns whether it came from the environment, a
# .env file, HashiCorp Vault or a boru vault.
#
# A port of typescript/src/Providers.ts, which is canonical.

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from .sekreto import SekretoError, checkname, envkey, parsedotenv, vaultref


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
            except OSError:
                # A missing .env file is not an error: it means "no
                # secrets here".
                self.values = {}
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


def _fetch(url, headers):
    """GET url, returning (status, parsed-json-or-None).

    A 404 is a normal answer here, not an exception: it means the vault
    does not hold this secret.
    """
    request = urllib.request.Request(url, headers=headers, method='GET')

    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode('utf8'))
    except urllib.error.HTTPError as err:
        body = err.read().decode('utf8')
        try:
            return err.code, json.loads(body)
        except ValueError:
            return err.code, None
    except urllib.error.URLError as err:
        raise SekretoError('sekreto: cannot reach ' + url + ': ' + str(err.reason))


def checkaddr(addr):
    """Refuse to send a Vault token in the clear.

    Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
    convenience. Sending `X-Vault-Token` over http to anything but the local
    machine puts both the token and the secret it fetches on the wire for
    anyone on the path, so sekreto will not do it. Loopback stays allowed:
    that is `vault server -dev` and this repo's own test harness.
    """
    if addr.startswith('https://'):
        return

    if not addr.startswith('http://'):
        raise SekretoError('sekreto: not an http(s) address: ' + addr)

    host = addr[len('http://'):].split('/')[0].split(':')[0]

    if host in ('localhost', '127.0.0.1', '::1', '[::1]'):
        return

    raise SekretoError(
        'sekreto: refusing to send a token in plaintext to ' + addr + ' (use https)'
    )


class HashicorpProvider(Provider):
    """HashiCorp Vault, KV v2.

    `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
    field of `data.data`. A 404 means "not here", which is a miss rather
    than an error, so a vault can sit in a chain with fallbacks.
    """

    def __init__(self, addr, token, mount=None):
        self.addr = addr
        self.token = token
        self.mount = mount or 'secret'

    def lookup(self, name):
        checkaddr(self.addr)

        ref = vaultref(name)
        url = self.addr.rstrip('/') + '/v1/' + self.mount + '/data/' + ref['path']

        status, body = _fetch(url, {'X-Vault-Token': self.token})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: hashicorp error: ' + str(status) + ': ' + url)

        data = (body or {}).get('data', {}).get('data')
        value = data.get(ref['field']) if isinstance(data, dict) else None

        return None if value is None else str(value)

    def describe(self):
        return 'hashicorp:' + self.addr + '/' + self.mount


class BoruProvider(Provider):
    """A boru vault (https://github.com/boru-lang/boru).

    boru keeps secrets in a local encrypted keyring and hands a value out
    through its own CLI: `boru vault get --reveal <alias>` prints the secret
    on stdout, and nothing else.

    There is deliberately no HTTP read here. boru's `vault proxy` and
    `vault mcp` are a *credential broker*: they inject the real secret into
    an outbound request and forward it, so an agent can call an API without
    ever holding the credential. Handing a value back is the one thing that
    broker is built not to do, so sekreto reads the vault the way boru
    itself does - through the CLI.

    A sekreto name is already a valid boru alias, so `api.token` crosses
    over unchanged. A `namespace` qualifies it the way boru writes it,
    `<namespace>:<name>`.

    The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
    sekreto never accepts it as config and never puts it on a command line,
    where it would show up in the process table.
    """

    def __init__(self, command=None, namespace=None, home=None):
        self.command = command or 'boru'
        self.namespace = namespace
        self.home = home

    def lookup(self, name):
        checkname(name)

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

    def describe(self):
        return 'boru' + (':' + self.namespace if self.namespace else '')


def borumiss(why):
    """Does this boru failure mean "no such secret" rather than "I could not
    answer"? Matched on boru's own wording for a missing alias."""
    return 'no alias named' in why


def makeprovider(spec):
    """Build a provider from its declarative form."""
    kind = spec.get('kind')

    if 'env' == kind:
        return EnvProvider(spec.get('prefix'))
    if 'dotenv' == kind:
        return DotenvProvider(spec.get('file') or '.env', spec.get('prefix'))
    if 'memory' == kind:
        return MemoryProvider(spec.get('values') or {}, spec.get('prefix'))
    if 'hashicorp' == kind:
        return HashicorpProvider(
            spec.get('addr') or '', spec.get('token') or '', spec.get('mount')
        )
    if 'boru' == kind:
        return BoruProvider(spec.get('command'), spec.get('namespace'), spec.get('home'))

    raise SekretoError('sekreto: unknown provider kind: ' + str(kind))
