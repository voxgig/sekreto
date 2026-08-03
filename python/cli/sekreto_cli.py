#!/usr/bin/env python3
# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with
# it. Every port ships this same CLI, and test/integration.sh runs all of
# them against the same server from all four secret sources - which is
# what proves the library, rather than the spec alone.
#
# Usage: sekreto_cli.py <api-url> [--source env|dotenv|vault|boru|chain]

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from voxgig_sekreto import Sekreto  # noqa: E402

LANG = 'python'


def chainfor(source):
    env = os.environ

    envspec = {'kind': 'env', 'prefix': env.get('SEKRETO_PREFIX')}
    dotenvspec = {'kind': 'dotenv', 'file': env.get('SEKRETO_DOTENV') or '.env'}
    vaultspec = {
        'kind': 'vault',
        'addr': env.get('VAULT_ADDR') or '',
        'token': env.get('VAULT_TOKEN') or '',
        'mount': env.get('VAULT_MOUNT'),
    }
    boruspec = {
        'kind': 'boru',
        'addr': env.get('BORU_VAULT_ADDR') or '',
        'token': env.get('BORU_VAULT_TOKEN') or '',
    }

    if 'env' == source:
        return [envspec]
    if 'dotenv' == source:
        return [dotenvspec]
    if 'vault' == source:
        return [vaultspec]
    if 'boru' == source:
        return [boruspec]

    # The default: the chain an app would actually ship with - local
    # overrides first, shared vaults last.
    return [envspec, dotenvspec, vaultspec, boruspec]


def main():
    args = sys.argv[1:]
    url = args[0] if args else 'http://127.0.0.1:8099/whoami'

    source = args[args.index('--source') + 1] if '--source' in args else 'chain'

    secrets = Sekreto({'providers': chainfor(source)})

    try:
        token = secrets.get('api.token')
    except Exception as err:
        print('sekreto-cli: ' + str(err), file=sys.stderr)
        return 2

    request = urllib.request.Request(
        url,
        headers={'Authorization': 'Bearer ' + token, 'X-Sekreto-Lang': LANG},
        method='GET',
    )

    try:
        with urllib.request.urlopen(request) as response:
            body = json.loads(response.read().decode('utf8'))
    except urllib.error.HTTPError as err:
        # Never print the token itself, even when the call fails.
        print('sekreto-cli: ' + secrets.redact(err.read().decode('utf8')), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {'ok': True, 'lang': LANG, 'source': source, 'caller': body.get('caller')},
            separators=(',', ':'),
        )
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
