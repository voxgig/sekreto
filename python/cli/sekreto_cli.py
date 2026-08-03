#!/usr/bin/env python3
# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with
# it. Every port ships this same CLI, and test/integration.sh runs all of
# them against the same server from all four secret sources - which is
# what proves the library, rather than the spec alone.
#
# Usage: sekreto_cli.py <api-url> [--source env|dotenv|hashicorp|boru|chain]
#                                 [--store <name>]   directed read

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
    hashicorpspec = {
        'kind': 'hashicorp',
        'addr': env.get('VAULT_ADDR') or '',
        'token': env.get('VAULT_TOKEN') or '',
        'mount': env.get('VAULT_MOUNT'),
    }
    boruspec = {
        'kind': 'boru',
        'command': env.get('BORU_COMMAND') or 'boru',
        'namespace': env.get('BORU_NAMESPACE'),
        'home': env.get('BORU_HOME'),
    }

    if 'env' == source:
        return [envspec]
    if 'dotenv' == source:
        return [dotenvspec]
    if 'hashicorp' == source:
        return [hashicorpspec]
    if 'boru' == source:
        return [boruspec]

    # The default: the chain an app would actually ship with - local
    # overrides first, shared vaults last.
    return [envspec, dotenvspec, hashicorpspec, boruspec]


def main():
    args = sys.argv[1:]
    url = args[0] if args else 'http://127.0.0.1:8099/whoami'

    source = args[args.index('--source') + 1] if '--source' in args else 'chain'

    # --store names a store outright: the secret must come from that one,
    # not from whichever provider happens to answer first.
    store = args[args.index('--store') + 1] if '--store' in args else ''

    secrets = Sekreto({'providers': chainfor(source)})

    try:
        token = secrets.getfrom(store, 'api.token') if store else secrets.get('api.token')
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
            {
                'ok': True,
                'lang': LANG,
                'source': source,
                'store': store,
                'caller': body.get('caller'),
            },
            separators=(',', ':'),
        )
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
