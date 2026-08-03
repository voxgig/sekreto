#!/usr/bin/env python3
# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with
# it. Every port ships this same CLI, and test/integration.sh runs all of
# them against the same server from all four secret sources - which is
# what proves the library, rather than the spec alone.
#
# Usage: sekreto_cli.py <api-url> [--source <source>] [--store <name>]
#
# Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
#          gcpsecrets azuresecrets onepassword doppler infisical chain
#
# Each source's configuration arrives in the environment variables its
# own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
# in chainfor below.

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
    filespec = {'kind': 'file', 'dir': env.get('SEKRETO_FILEDIR') or '/run/secrets'}

    hashicorpspec = {
        'kind': 'hashicorp',
        'addr': env.get('VAULT_ADDR') or '',
        'token': env.get('VAULT_TOKEN') or '',
        'mount': env.get('VAULT_MOUNT'),
        'kv': int(env['VAULT_KV']) if env.get('VAULT_KV') else None,
        'vaultnamespace': env.get('VAULT_NAMESPACE'),
        'auth': {
            'method': env.get('VAULT_AUTH'),
            'role': env.get('VAULT_ROLE'),
            'jwtfile': env.get('VAULT_JWT_FILE'),
            'roleid': env.get('VAULT_ROLE_ID'),
            'secretid': env.get('VAULT_SECRET_ID'),
        } if env.get('VAULT_AUTH') else None,
    }

    boruspec = {
        'kind': 'boru',
        'command': env.get('BORU_COMMAND') or 'boru',
        'namespace': env.get('BORU_NAMESPACE'),
        'home': env.get('BORU_HOME'),
    }

    # The same vault over its wire protocol (`boru vault serve`) instead
    # of the CLI: an address plus a capability token from `vault grant`.
    boruwirespec = {
        'kind': 'boru',
        'addr': env.get('BORU_ADDR') or '',
        'token': env.get('BORU_TOKEN') or '',
        'namespace': env.get('BORU_NAMESPACE'),
    }

    awssecretsspec = {
        'kind': 'awssecrets',
        'region': env.get('AWS_REGION'),
        'addr': env.get('AWS_ENDPOINT'),
    }

    awsparamsspec = {
        'kind': 'awsparams',
        'region': env.get('AWS_REGION'),
        'addr': env.get('AWS_ENDPOINT'),
        'prefix': env.get('AWS_PARAM_PREFIX'),
    }

    gcpspec = {
        'kind': 'gcpsecrets',
        'project': env.get('GCP_PROJECT'),
        'addr': env.get('GCP_ADDR'),
        'metadataaddr': env.get('GCP_METADATA_ADDR'),
    }

    azurespec = {
        'kind': 'azuresecrets',
        'vault': env.get('AZURE_VAULT'),
        'token': env.get('AZURE_TOKEN'),
        'tenant': env.get('AZURE_TENANT'),
        'clientid': env.get('AZURE_CLIENT_ID'),
        'clientsecret': env.get('AZURE_CLIENT_SECRET'),
        'loginaddr': env.get('AZURE_LOGIN_ADDR'),
        'imdsaddr': env.get('AZURE_IMDS_ADDR'),
    }

    onepasswordspec = {
        'kind': 'onepassword',
        'addr': env.get('OP_CONNECT_HOST'),
        'token': env.get('OP_CONNECT_TOKEN'),
        'vault': env.get('OP_VAULT'),
    }

    dopplerspec = {
        'kind': 'doppler',
        'token': env.get('DOPPLER_TOKEN'),
        'project': env.get('DOPPLER_PROJECT'),
        'config': env.get('DOPPLER_CONFIG'),
        'addr': env.get('DOPPLER_ADDR'),
    }

    infisicalspec = {
        'kind': 'infisical',
        'addr': env.get('INFISICAL_ADDR'),
        'token': env.get('INFISICAL_TOKEN'),
        'clientid': env.get('INFISICAL_CLIENT_ID'),
        'clientsecret': env.get('INFISICAL_CLIENT_SECRET'),
        'project': env.get('INFISICAL_PROJECT'),
        'environment': env.get('INFISICAL_ENV'),
        'path': env.get('INFISICAL_PATH'),
    }

    bysource = {
        'env': [envspec],
        'dotenv': [dotenvspec],
        'file': [filespec],
        'hashicorp': [hashicorpspec],
        'boru': [boruspec],
        'boruwire': [boruwirespec],
        'awssecrets': [awssecretsspec],
        'awsparams': [awsparamsspec],
        'gcpsecrets': [gcpspec],
        'azuresecrets': [azurespec],
        'onepassword': [onepasswordspec],
        'doppler': [dopplerspec],
        'infisical': [infisicalspec],
    }

    found = bysource.get(source)
    if found is not None:
        return found

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
