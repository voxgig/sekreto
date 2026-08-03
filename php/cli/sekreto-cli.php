<?php

/**
 * A tiny app that needs a secret.
 *
 * It asks sekreto for `api.token` and calls the token-protected API with
 * it. Every port ships this same CLI, and test/integration.sh runs all of
 * them against the same server from every secret source - which is what
 * proves the library, rather than the spec alone.
 *
 * Usage: php sekreto-cli.php <api-url> [--source <source>] [--store <name>]
 *
 * Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
 *          gcpsecrets azuresecrets onepassword doppler infisical chain
 *
 * Each source's configuration arrives in the environment variables its
 * own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
 * in chainfor below.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto\Cli;

use Voxgig\Sekreto\Sekreto;

use function Voxgig\Sekreto\httpget;

require_once __DIR__ . '/../src/Sekreto.php';

const LANG = 'php';

/** @return array<int, array<string, mixed>> */
function chainfor(string $source): array
{
    $envspec = ['kind' => 'env', 'prefix' => getenv('SEKRETO_PREFIX') ?: null];
    $dotenvspec = ['kind' => 'dotenv', 'file' => getenv('SEKRETO_DOTENV') ?: '.env'];
    $filespec = ['kind' => 'file', 'dir' => getenv('SEKRETO_FILEDIR') ?: '/run/secrets'];

    $vaultauth = getenv('VAULT_AUTH') ?: null;
    $hashicorpspec = [
        'kind' => 'hashicorp',
        'addr' => getenv('VAULT_ADDR') ?: '',
        'token' => getenv('VAULT_TOKEN') ?: '',
        'mount' => getenv('VAULT_MOUNT') ?: null,
        'kv' => getenv('VAULT_KV') ? (int) getenv('VAULT_KV') : null,
        'vaultnamespace' => getenv('VAULT_NAMESPACE') ?: null,
        'auth' => null === $vaultauth ? null : [
            'method' => $vaultauth,
            'role' => getenv('VAULT_ROLE') ?: null,
            'jwtfile' => getenv('VAULT_JWT_FILE') ?: null,
            'roleid' => getenv('VAULT_ROLE_ID') ?: null,
            'secretid' => getenv('VAULT_SECRET_ID') ?: null,
        ],
    ];

    $boruspec = [
        'kind' => 'boru',
        'command' => getenv('BORU_COMMAND') ?: 'boru',
        'namespace' => getenv('BORU_NAMESPACE') ?: null,
        'home' => getenv('BORU_HOME') ?: null,
    ];

    // The same vault over its wire protocol (`boru vault serve`) instead
    // of the CLI: an address plus a capability token from `vault grant`.
    $boruwirespec = [
        'kind' => 'boru',
        'addr' => getenv('BORU_ADDR') ?: '',
        'token' => getenv('BORU_TOKEN') ?: '',
        'namespace' => getenv('BORU_NAMESPACE') ?: null,
    ];

    $awssecretsspec = [
        'kind' => 'awssecrets',
        'region' => getenv('AWS_REGION') ?: null,
        'addr' => getenv('AWS_ENDPOINT') ?: null,
    ];

    $awsparamsspec = [
        'kind' => 'awsparams',
        'region' => getenv('AWS_REGION') ?: null,
        'addr' => getenv('AWS_ENDPOINT') ?: null,
        'prefix' => getenv('AWS_PARAM_PREFIX') ?: null,
    ];

    $gcpspec = [
        'kind' => 'gcpsecrets',
        'project' => getenv('GCP_PROJECT') ?: null,
        'addr' => getenv('GCP_ADDR') ?: null,
        'metadataaddr' => getenv('GCP_METADATA_ADDR') ?: null,
    ];

    $azurespec = [
        'kind' => 'azuresecrets',
        'vault' => getenv('AZURE_VAULT') ?: null,
        'token' => getenv('AZURE_TOKEN') ?: null,
        'tenant' => getenv('AZURE_TENANT') ?: null,
        'clientid' => getenv('AZURE_CLIENT_ID') ?: null,
        'clientsecret' => getenv('AZURE_CLIENT_SECRET') ?: null,
        'loginaddr' => getenv('AZURE_LOGIN_ADDR') ?: null,
        'imdsaddr' => getenv('AZURE_IMDS_ADDR') ?: null,
    ];

    $onepasswordspec = [
        'kind' => 'onepassword',
        'addr' => getenv('OP_CONNECT_HOST') ?: null,
        'token' => getenv('OP_CONNECT_TOKEN') ?: null,
        'vault' => getenv('OP_VAULT') ?: null,
    ];

    $dopplerspec = [
        'kind' => 'doppler',
        'token' => getenv('DOPPLER_TOKEN') ?: null,
        'project' => getenv('DOPPLER_PROJECT') ?: null,
        'config' => getenv('DOPPLER_CONFIG') ?: null,
        'addr' => getenv('DOPPLER_ADDR') ?: null,
    ];

    $infisicalspec = [
        'kind' => 'infisical',
        'addr' => getenv('INFISICAL_ADDR') ?: null,
        'token' => getenv('INFISICAL_TOKEN') ?: null,
        'clientid' => getenv('INFISICAL_CLIENT_ID') ?: null,
        'clientsecret' => getenv('INFISICAL_CLIENT_SECRET') ?: null,
        'project' => getenv('INFISICAL_PROJECT') ?: null,
        'environment' => getenv('INFISICAL_ENV') ?: null,
        'path' => getenv('INFISICAL_PATH') ?: null,
    ];

    return match ($source) {
        'env' => [$envspec],
        'dotenv' => [$dotenvspec],
        'file' => [$filespec],
        'hashicorp' => [$hashicorpspec],
        'boru' => [$boruspec],
        'boruwire' => [$boruwirespec],
        'awssecrets' => [$awssecretsspec],
        'awsparams' => [$awsparamsspec],
        'gcpsecrets' => [$gcpspec],
        'azuresecrets' => [$azurespec],
        'onepassword' => [$onepasswordspec],
        'doppler' => [$dopplerspec],
        'infisical' => [$infisicalspec],
        // The default: the chain an app would actually ship with - local
        // overrides first, shared vaults last.
        default => [$envspec, $dotenvspec, $hashicorpspec, $boruspec],
    };
}

function main(array $argv): int
{
    $args = array_slice($argv, 1);
    $url = $args[0] ?? 'http://127.0.0.1:8099/whoami';

    $flag = array_search('--source', $args, true);
    $source = false === $flag ? 'chain' : ($args[$flag + 1] ?? 'chain');

    // --store names a store outright: the secret must come from that one,
    // not from whichever provider happens to answer first.
    $storeflag = array_search('--store', $args, true);
    $store = false === $storeflag ? '' : ($args[$storeflag + 1] ?? '');

    $secrets = new Sekreto(['providers' => chainfor($source)]);

    try {
        $token = '' === $store
            ? $secrets->get('api.token')
            : $secrets->getfrom($store, 'api.token');
    } catch (\Throwable $err) {
        fwrite(STDERR, 'sekreto-cli: ' . $err->getMessage() . "\n");
        return 2;
    }

    [$status, $body] = httpget($url, [
        'Authorization: Bearer ' . $token,
        'X-Sekreto-Lang: ' . LANG,
    ]);

    if (200 !== $status) {
        // Never print the token itself, even when the call fails.
        fwrite(STDERR, 'sekreto-cli: ' . $secrets->redact(json_encode($body)) . "\n");
        return 1;
    }

    echo json_encode([
        'ok' => true,
        'lang' => LANG,
        'source' => $source,
        'store' => $store,
        'caller' => $body['caller'] ?? null,
    ]) . "\n";

    return 0;
}

exit(main($argv));
