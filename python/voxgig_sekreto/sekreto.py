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


class Sekreto:
    """The secrets facade: a chain of providers plus a cache."""

    def __init__(self, options=None):
        from .providers import makeprovider

        opts = options or {}
        self.providers = [
            entry if callable(getattr(entry, 'lookup', None)) else makeprovider(entry)
            for entry in (opts.get('providers') or [])
        ]
        self.docache = False is not opts.get('cache', True)
        self.cache = {}

    def get(self, name):
        """The secret, or a SekretoError if no provider has it."""
        found = self.try_(name)

        if found is None:
            raise SekretoError('sekreto: unknown secret: ' + name)

        return found

    def try_(self, name):
        """The secret, or None if no provider has it."""
        checkname(name)

        if self.docache and name in self.cache:
            return self.cache[name]

        for provider in self.providers:
            found = provider.lookup(name)

            if found is not None:
                if self.docache:
                    self.cache[name] = found
                return found

        return None

    def has(self, name):
        """Does any provider have this secret?"""
        return self.try_(name) is not None

    def all(self, names):
        """Every named secret at once. Missing ones are an error."""
        return {name: self.get(name) for name in names}

    def sources(self):
        """A description of each provider, in resolution order."""
        return [provider.describe() for provider in self.providers]

    def redact(self, text):
        """Replace every value this Sekreto has resolved with `[redacted]`."""
        return redact(text, list(self.cache.values()))

    def refresh(self):
        """Drop cached values, so the next `get` asks the providers again."""
        self.cache.clear()


def sekreto(options=None):
    """Make a Sekreto from options."""
    return Sekreto(options)
