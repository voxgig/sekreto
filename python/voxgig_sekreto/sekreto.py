# sekreto: one interface for secrets, wherever they live.
#
# A Sekreto is an ordered chain of providers. `get` asks each in turn and
# returns the first hit, so an app can be configured from environment
# variables in development and a vault in production without changing a
# line of its own code.
#
# A port of typescript/src/Sekreto.ts, which is canonical.

import re


class SekretoError(Exception):
    """Anything sekreto refuses to do: a bad name, a missing secret, a
    provider that could not be reached."""


NAMEPART = re.compile(r'^[a-z0-9_]+$')


def validname(name):
    """Is this a well-formed secret name?"""
    if not isinstance(name, str) or 0 == len(name):
        return False

    for part in name.split('.'):
        if not NAMEPART.match(part):
            return False

    return True


def checkname(name):
    if not validname(name):
        raise SekretoError('sekreto: invalid name: ' + ('' if name is None else str(name)))
    return name


def envkey(name, prefix=None):
    """The environment-variable key for a name: `api.token` -> `API_TOKEN`."""
    checkname(name)
    return (prefix or '') + '_'.join(name.split('.')).upper()


def vaultref(name):
    """Where a name lives in a KV vault: `api.token` -> `api` / `token`.

    A single-segment name has no path of its own, so it becomes a secret of
    that name with the conventional field `value`.
    """
    checkname(name)

    parts = name.split('.')

    if 1 == len(parts):
        return {'path': parts[0], 'field': 'value'}

    return {'path': '/'.join(parts[:-1]), 'field': parts[-1]}


def flatname(name, sep):
    """A name flattened to one segment: `api.token` -> `api_token` (GCP
    Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).

    Those stores have no path hierarchy and reject dots in ids, so the
    dots become the store's conventional separator.
    """
    checkname(name)
    return sep.join(name.split('.'))


def awsparam(name, prefix=None):
    """The AWS SSM Parameter Store name for a name: dots become the path
    hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
    `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
    """
    checkname(name)

    base = prefix or ''
    if '' != base and not base.startswith('/'):
        base = '/' + base
    if base.endswith('/'):
        base = base[:-1]

    return base + '/' + '/'.join(name.split('.'))


def parsedotenv(text):
    """Parse `.env` text into a map of raw keys to values.

    Deliberately small: `KEY=value`, optional `export`, `#` comments on
    their own line, and single- or double-quoted values (double quotes also
    unescape `\\n`, `\\r`, `\\t` and `\\\\`). A line with no `=` is skipped.
    """
    out = {}

    if not isinstance(text, str):
        return out

    for rawline in text.split('\n'):
        line = rawline[:-1].strip() if rawline.endswith('\r') else rawline.strip()

        if 0 == len(line) or line.startswith('#'):
            continue

        body = line[7:].strip() if line.startswith('export ') else line

        eq = body.find('=')
        if 0 >= eq:
            continue

        key = body[:eq].strip()
        value = body[eq + 1:].strip()

        if 2 <= len(value) and value.startswith('"') and value.endswith('"'):
            value = _unescape(value[1:-1])
        elif 2 <= len(value) and value.startswith("'") and value.endswith("'"):
            value = value[1:-1]

        out[key] = value

    return out


def _unescape(text):
    out = ''
    index = 0

    while index < len(text):
        if '\\' == text[index] and index + 1 < len(text):
            nxt = text[index + 1]
            index += 2
            if 'n' == nxt:
                out += '\n'
            elif 'r' == nxt:
                out += '\r'
            elif 't' == nxt:
                out += '\t'
            elif '\\' == nxt:
                out += '\\'
            elif '"' == nxt:
                out += '"'
            else:
                out += '\\' + nxt
        else:
            out += text[index]
            index += 1

    return out


def redact(text, values):
    """Replace known secret values in text with `[redacted]`.

    Only values of four characters or more are replaced: shorter ones are
    too likely to appear in ordinary text, and redacting them would make
    logs unreadable without making them safer.
    """
    out = text if isinstance(text, str) else ''

    for value in values or []:
        if not isinstance(value, str) or 4 > len(value):
            continue
        out = '[redacted]'.join(out.split(value))

    return out


def storename(provider, spec=None):
    """The store name a provider answers to when its spec does not say.

    `describe()` opens with the provider's kind - `hashicorp:...`,
    `dotenv:...`, plain `env` - so the kind is the natural default, and a
    custom provider gets a sensible name without implementing anything
    extra.
    """
    if spec and spec.get('name'):
        return spec['name']
    return provider.describe().split(':')[0]


class Sekreto:
    """The secrets facade: a chain of providers plus a cache.

    Two ways to read. `get` is transparent - it walks the chain and takes
    the first hit, and the caller never learns which store answered.
    `getfrom` is directed - it names the store, and only that store is
    asked.
    """

    def __init__(self, options=None):
        from .providers import makeprovider

        opts = options or {}

        self.entries = []
        for entry in opts.get('providers') or []:
            if callable(getattr(entry, 'lookup', None)):
                self.entries.append((storename(entry), entry))
            else:
                provider = makeprovider(entry)
                self.entries.append((storename(provider, entry), provider))

        self.docache = False is not opts.get('cache', True)

        # A list, not a dict: the store a value came from stays attached,
        # and redaction order does not vary between runs.
        self.cache = []

    def get(self, name):
        """The secret, or a SekretoError if no provider has it."""
        found = self.try_(name)

        if found is None:
            raise SekretoError('sekreto: unknown secret: ' + name)

        return found

    def try_(self, name):
        """The secret, or None if no provider has it."""
        return self._resolve('', name, self.entries)

    def getfrom(self, store, name):
        """The secret from one named store, or a SekretoError if that store
        does not have it."""
        found = self.tryfrom(store, name)

        if found is None:
            raise SekretoError('sekreto: unknown secret: ' + store + ':' + name)

        return found

    def tryfrom(self, store, name):
        """The secret from one named store, or None if that store does not
        have it.

        Naming a store that is not in the chain is an error, not a miss:
        `try` already means "this store may not have it", so it cannot also
        mean "this store may not exist" without hiding a typo.
        """
        matching = [entry for entry in self.entries if entry[0] == store]

        if 0 == len(matching):
            raise SekretoError('sekreto: unknown store: ' + store)

        return self._resolve(store, name, matching)

    def _resolve(self, store, name, entries):
        checkname(name)

        if self.docache:
            for cached in self.cache:
                if cached[0] == store and cached[1] == name:
                    return cached[2]

        for _storename, provider in entries:
            found = provider.lookup(name)

            if found is not None:
                if self.docache:
                    self.cache.append((store, name, found))
                return found

        return None

    def has(self, name):
        """Does any provider have this secret?"""
        return self.try_(name) is not None

    def hasin(self, store, name):
        """Does this named store have this secret?"""
        return self.tryfrom(store, name) is not None

    def all(self, names):
        """Every named secret at once. Missing ones are an error."""
        return {name: self.get(name) for name in names}

    def sources(self):
        """A description of each provider, in resolution order."""
        return [provider.describe() for _store, provider in self.entries]

    def stores(self):
        """The name of each store that can be named by `getfrom`, in
        resolution order and without repeats."""
        out = []

        for store, _provider in self.entries:
            if store not in out:
                out.append(store)

        return out

    def redact(self, text):
        """Replace every value this Sekreto has resolved with `[redacted]`."""
        return redact(text, [cached[2] for cached in self.cache])

    def refresh(self):
        """Drop cached values, so the next `get` asks the providers again."""
        self.cache.clear()


def sekreto(options=None):
    """Make a Sekreto from options."""
    return Sekreto(options)
