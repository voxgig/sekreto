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
import urllib.error
import urllib.parse
import urllib.request

from .sekreto import SekretoError, envkey, parsedotenv, vaultref


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


class VaultProvider(Provider):
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
        ref = vaultref(name)
        url = self.addr.rstrip('/') + '/v1/' + self.mount + '/data/' + ref['path']

        status, body = _fetch(url, {'X-Vault-Token': self.token})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: vault error: ' + str(status) + ': ' + url)

        data = (body or {}).get('data', {}).get('data')
        value = data.get(ref['field']) if isinstance(data, dict) else None

        return None if value is None else str(value)

    def describe(self):
        return 'vault:' + self.addr + '/' + self.mount


class BoruProvider(Provider):
    """A boru vault.

    The boru vault protocol as sekreto uses it: a GET of
    `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
    answering `{"ok":true,"value":"..."}` when the secret exists and
    `{"ok":false}` (or 404) when it does not.
    """

    def __init__(self, addr, token):
        self.addr = addr
        self.token = token

    def lookup(self, name):
        ref = vaultref(name)
        url = (
            self.addr.rstrip('/')
            + '/vault/'
            + ref['path']
            + '?field='
            + urllib.parse.quote(ref['field'], safe='')
        )

        status, body = _fetch(url, {'X-Boru-Token': self.token})

        if 404 == status:
            return None

        if 200 != status:
            raise SekretoError('sekreto: boru vault error: ' + str(status) + ': ' + url)

        if not isinstance(body, dict) or True is not body.get('ok'):
            return None

        value = body.get('value')
        return None if value is None else str(value)

    def describe(self):
        return 'boru:' + self.addr


def makeprovider(spec):
    """Build a provider from its declarative form."""
    kind = spec.get('kind')

    if 'env' == kind:
        return EnvProvider(spec.get('prefix'))
    if 'dotenv' == kind:
        return DotenvProvider(spec.get('file') or '.env', spec.get('prefix'))
    if 'memory' == kind:
        return MemoryProvider(spec.get('values') or {}, spec.get('prefix'))
    if 'vault' == kind:
        return VaultProvider(spec.get('addr') or '', spec.get('token') or '', spec.get('mount'))
    if 'boru' == kind:
        return BoruProvider(spec.get('addr') or '', spec.get('token') or '')

    raise SekretoError('sekreto: unknown provider kind: ' + str(kind))
