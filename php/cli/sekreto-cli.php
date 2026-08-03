<?php

/**
 * A tiny app that needs a secret.
 *
 * It asks sekreto for `api.token` and calls the token-protected API with
 * it. Every port ships this same CLI, and test/integration.sh runs all of
 * them against the same server from all four secret sources - which is what
 * proves the library, rather than the spec alone.
 *
 * Usage: php sekreto-cli.php <api-url> [--source env|dotenv|hashicorp|boru|chain]
 *                                      [--store <name>]   directed read
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
    $hashicorpspec = [
        'kind' => 'hashicorp',
        'addr' => getenv('VAULT_ADDR') ?: '',
        'token' => getenv('VAULT_TOKEN') ?: '',
        'mount' => getenv('VAULT_MOUNT') ?: null,
    ];
    $boruspec = [
        'kind' => 'boru',
        'command' => getenv('BORU_COMMAND') ?: 'boru',
        'namespace' => getenv('BORU_NAMESPACE') ?: null,
        'home' => getenv('BORU_HOME') ?: null,
    ];

    return match ($source) {
        'env' => [$envspec],
        'dotenv' => [$dotenvspec],
        'hashicorp' => [$hashicorpspec],
        'boru' => [$boruspec],
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
