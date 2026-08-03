<?php

/**
 * A tiny app that needs a secret.
 *
 * It asks sekreto for `api.token` and calls the token-protected API with
 * it. Every port ships this same CLI, and test/integration.sh runs all of
 * them against the same server from all four secret sources - which is what
 * proves the library, rather than the spec alone.
 *
 * Usage: php sekreto-cli.php <api-url> [--source env|dotenv|vault|boru|chain]
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
    $vaultspec = [
        'kind' => 'vault',
        'addr' => getenv('VAULT_ADDR') ?: '',
        'token' => getenv('VAULT_TOKEN') ?: '',
        'mount' => getenv('VAULT_MOUNT') ?: null,
    ];
    $boruspec = [
        'kind' => 'boru',
        'addr' => getenv('BORU_VAULT_ADDR') ?: '',
        'token' => getenv('BORU_VAULT_TOKEN') ?: '',
    ];

    return match ($source) {
        'env' => [$envspec],
        'dotenv' => [$dotenvspec],
        'vault' => [$vaultspec],
        'boru' => [$boruspec],
        // The default: the chain an app would actually ship with - local
        // overrides first, shared vaults last.
        default => [$envspec, $dotenvspec, $vaultspec, $boruspec],
    };
}

function main(array $argv): int
{
    $args = array_slice($argv, 1);
    $url = $args[0] ?? 'http://127.0.0.1:8099/whoami';

    $flag = array_search('--source', $args, true);
    $source = false === $flag ? 'chain' : ($args[$flag + 1] ?? 'chain');

    $secrets = new Sekreto(['providers' => chainfor($source)]);

    try {
        $token = $secrets->get('api.token');
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
        'caller' => $body['caller'] ?? null,
    ]) . "\n";

    return 0;
}

exit(main($argv));
