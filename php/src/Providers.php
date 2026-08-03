<?php

/**
 * The providers a Sekreto chains together.
 *
 * A provider answers one question: "do you have this secret?" It returns
 * the value, or null to mean "ask the next one". Nothing else about a
 * provider is visible to the caller - which is the point: an app reads
 * `api.token` and never learns whether it came from the environment, a
 * .env file, HashiCorp Vault or a boru vault.
 *
 * A port of typescript/src/Providers.ts, which is canonical.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto;

require_once __DIR__ . '/Sekreto.php';

/** A source of secrets. `lookup` returns the value or null. */
interface Provider
{
    public function lookup(string $name): ?string;

    public function describe(): string;
}

/** Environment variables: `api.token` from `API_TOKEN`. */
class EnvProvider implements Provider
{
    /** @param array<string, string>|null $source */
    public function __construct(private ?string $prefix = null, private ?array $source = null)
    {
    }

    public function lookup(string $name): ?string
    {
        $key = Name::envkey($name, $this->prefix);

        if (null !== $this->source) {
            return $this->source[$key] ?? null;
        }

        $value = getenv($key);

        return false === $value ? null : $value;
    }

    public function describe(): string
    {
        return 'env' . ($this->prefix ? ':' . $this->prefix : '');
    }
}

/** A `.env` file, read once, keyed exactly like the environment. */
class DotenvProvider implements Provider
{
    /** @var array<string, string>|null */
    private ?array $values = null;

    public function __construct(private string $file, private ?string $prefix = null)
    {
    }

    /** @return array<string, string> */
    private function load(): array
    {
        if (null === $this->values) {
            // A missing .env file is not an error: it means "no secrets here".
            $text = @file_get_contents($this->file);
            $this->values = false === $text ? [] : parsedotenv($text);
        }

        return $this->values;
    }

    public function lookup(string $name): ?string
    {
        return $this->load()[Name::envkey($name, $this->prefix)] ?? null;
    }

    public function describe(): string
    {
        return 'dotenv:' . $this->file;
    }
}

/**
 * Literal values, keyed like environment variables. The spec uses this to
 * test chain behaviour without touching the outside world.
 */
class MemoryProvider implements Provider
{
    /** @param array<string, string> $values */
    public function __construct(private array $values, private ?string $prefix = null)
    {
    }

    public function lookup(string $name): ?string
    {
        $value = $this->values[Name::envkey($name, $this->prefix)] ?? null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'memory' . ($this->prefix ? ':' . $this->prefix : '');
    }
}

/**
 * GET a URL, returning [status, decoded-json-or-null].
 *
 * A 404 is a normal answer here, not a failure: it means the vault does not
 * hold this secret. Uses the stream wrapper so that no extension beyond the
 * default build is required.
 *
 * @param array<int, string> $headers
 * @return array{0: int, 1: mixed}
 */
function httpget(string $url, array $headers): array
{
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", $headers),
            // Read the body of an error response rather than throwing it away.
            'ignore_errors' => true,
            'timeout' => 10,
        ],
    ]);

    $body = @file_get_contents($url, false, $context);

    if (false === $body) {
        throw new SekretoError('sekreto: cannot reach ' . $url);
    }

    $status = 0;
    foreach ($http_response_header ?? [] as $line) {
        if (1 === preg_match('#^HTTP/\S+\s+(\d+)#', $line, $match)) {
            $status = (int) $match[1];
        }
    }

    return [$status, json_decode($body, true)];
}

/**
 * HashiCorp Vault, KV v2.
 *
 * `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token` field
 * of `data.data`. A 404 means "not here", which is a miss rather than an
 * error, so a vault can sit in a chain with fallbacks.
 */
class VaultProvider implements Provider
{
    private string $mount;

    public function __construct(private string $addr, private string $token, ?string $mount = null)
    {
        $this->mount = $mount ?? 'secret';
    }

    public function lookup(string $name): ?string
    {
        $ref = Name::vaultref($name);
        $url = rtrim($this->addr, '/') . '/v1/' . $this->mount . '/data/' . $ref['path'];

        [$status, $body] = httpget($url, ['X-Vault-Token: ' . $this->token]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: vault error: ' . $status . ': ' . $url);
        }

        $data = $body['data']['data'] ?? null;
        $value = is_array($data) ? ($data[$ref['field']] ?? null) : null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'vault:' . $this->addr . '/' . $this->mount;
    }
}

/**
 * A boru vault.
 *
 * The boru vault protocol as sekreto uses it: a GET of
 * `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
 * answering `{"ok":true,"value":"..."}` when the secret exists and
 * `{"ok":false}` (or 404) when it does not.
 */
class BoruProvider implements Provider
{
    public function __construct(private string $addr, private string $token)
    {
    }

    public function lookup(string $name): ?string
    {
        $ref = Name::vaultref($name);
        $url = rtrim($this->addr, '/') . '/vault/' . $ref['path']
            . '?field=' . rawurlencode($ref['field']);

        [$status, $body] = httpget($url, ['X-Boru-Token: ' . $this->token]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: boru vault error: ' . $status . ': ' . $url);
        }

        if (!is_array($body) || true !== ($body['ok'] ?? null)) {
            return null;
        }

        $value = $body['value'] ?? null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'boru:' . $this->addr;
    }
}

/**
 * Build a provider from its declarative form.
 *
 * @param array<string, mixed> $spec
 */
function makeprovider(array $spec): Provider
{
    $kind = $spec['kind'] ?? null;

    return match ($kind) {
        'env' => new EnvProvider($spec['prefix'] ?? null),
        'dotenv' => new DotenvProvider($spec['file'] ?? '.env', $spec['prefix'] ?? null),
        'memory' => new MemoryProvider($spec['values'] ?? [], $spec['prefix'] ?? null),
        'vault' => new VaultProvider(
            $spec['addr'] ?? '',
            $spec['token'] ?? '',
            $spec['mount'] ?? null
        ),
        'boru' => new BoruProvider($spec['addr'] ?? '', $spec['token'] ?? ''),
        default => throw new SekretoError(
            'sekreto: unknown provider kind: ' . (null === $kind ? '' : (string) $kind)
        ),
    };
}
