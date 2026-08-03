<?php

/**
 * sekreto: one interface for secrets, wherever they live.
 *
 * A Sekreto is an ordered chain of providers. `get` asks each in turn and
 * returns the first hit, so an app can be configured from environment
 * variables in development and a vault in production without changing a
 * line of its own code.
 *
 * A port of typescript/src/Sekreto.ts, which is canonical.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto;

require_once __DIR__ . '/Providers.php';

/**
 * Anything sekreto refuses to do: a bad name, a missing secret, a provider
 * that could not be reached.
 */
class SekretoError extends \RuntimeException
{
}

final class Name
{
    private const NAMEPART = '/^[a-z0-9_]+$/';

    /** Is this a well-formed secret name? */
    public static function valid($name): bool
    {
        if (!is_string($name) || '' === $name) {
            return false;
        }

        foreach (explode('.', $name) as $part) {
            if (1 !== preg_match(self::NAMEPART, $part)) {
                return false;
            }
        }

        return true;
    }

    public static function check($name): string
    {
        if (!self::valid($name)) {
            throw new SekretoError(
                'sekreto: invalid name: ' . (null === $name ? '' : (string) $name)
            );
        }

        return $name;
    }

    /** The environment-variable key for a name: `api.token` -> `API_TOKEN`. */
    public static function envkey(string $name, ?string $prefix = null): string
    {
        self::check($name);

        return ($prefix ?? '') . strtoupper(implode('_', explode('.', $name)));
    }

    /**
     * Where a name lives in a KV vault: `api.token` -> `api` / `token`.
     *
     * A single-segment name has no path of its own, so it becomes a secret
     * of that name with the conventional field `value`.
     *
     * @return array{path: string, field: string}
     */
    public static function vaultref(string $name): array
    {
        self::check($name);

        $parts = explode('.', $name);

        if (1 === count($parts)) {
            return ['path' => $parts[0], 'field' => 'value'];
        }

        $field = array_pop($parts);

        return ['path' => implode('/', $parts), 'field' => $field];
    }
}

/**
 * Parse `.env` text into a map of raw keys to values.
 *
 * Deliberately small: `KEY=value`, optional `export`, `#` comments on their
 * own line, and single- or double-quoted values (double quotes also
 * unescape \n, \r, \t and \\). A line with no `=` is skipped.
 *
 * @return array<string, string>
 */
function parsedotenv($text): array
{
    $out = [];

    if (!is_string($text)) {
        return $out;
    }

    foreach (explode("\n", $text) as $rawline) {
        $line = trim(preg_replace('/\r$/', '', $rawline));

        if ('' === $line || str_starts_with($line, '#')) {
            continue;
        }

        $body = str_starts_with($line, 'export ') ? trim(substr($line, 7)) : $line;

        $eq = strpos($body, '=');
        if (false === $eq || 0 >= $eq) {
            continue;
        }

        $key = trim(substr($body, 0, $eq));
        $value = trim(substr($body, $eq + 1));

        if (2 <= strlen($value) && str_starts_with($value, '"') && str_ends_with($value, '"')) {
            $value = unescape(substr($value, 1, -1));
        } elseif (2 <= strlen($value) && str_starts_with($value, "'") && str_ends_with($value, "'")) {
            $value = substr($value, 1, -1);
        }

        $out[$key] = $value;
    }

    return $out;
}

function unescape(string $text): string
{
    $out = '';
    $index = 0;
    $len = strlen($text);

    while ($index < $len) {
        if ('\\' === $text[$index] && $index + 1 < $len) {
            $next = $text[$index + 1];
            $index += 2;
            $out .= match ($next) {
                'n' => "\n",
                'r' => "\r",
                't' => "\t",
                '\\' => '\\',
                '"' => '"',
                default => '\\' . $next,
            };
        } else {
            $out .= $text[$index];
            $index++;
        }
    }

    return $out;
}

/**
 * Replace known secret values in text with `[redacted]`.
 *
 * Only values of four characters or more are replaced: shorter ones are too
 * likely to appear in ordinary text, and redacting them would make logs
 * unreadable without making them safer.
 *
 * @param array<int, mixed> $values
 */
function redact($text, $values): string
{
    $out = is_string($text) ? $text : '';

    foreach ($values ?? [] as $value) {
        if (!is_string($value) || 4 > strlen($value)) {
            continue;
        }
        $out = implode('[redacted]', explode($value, $out));
    }

    return $out;
}

/** The secrets facade: a chain of providers plus a cache. */
class Sekreto
{
    /** @var array<int, Provider> */
    private array $providers;
    private bool $docache;
    /** @var array<string, string> */
    private array $cache = [];

    /** @param array<string, mixed>|null $options */
    public function __construct(?array $options = null)
    {
        $opts = $options ?? [];

        $this->providers = array_map(
            fn($entry) => $entry instanceof Provider ? $entry : makeprovider($entry),
            $opts['providers'] ?? []
        );

        $this->docache = false !== ($opts['cache'] ?? true);
    }

    /** The secret, or a SekretoError if no provider has it. */
    public function get(string $name): string
    {
        $found = $this->try($name);

        if (null === $found) {
            throw new SekretoError('sekreto: unknown secret: ' . $name);
        }

        return $found;
    }

    /** The secret, or null if no provider has it. */
    public function try(string $name): ?string
    {
        Name::check($name);

        if ($this->docache && array_key_exists($name, $this->cache)) {
            return $this->cache[$name];
        }

        foreach ($this->providers as $provider) {
            $found = $provider->lookup($name);

            if (null !== $found) {
                if ($this->docache) {
                    $this->cache[$name] = $found;
                }
                return $found;
            }
        }

        return null;
    }

    /** Does any provider have this secret? */
    public function has(string $name): bool
    {
        return null !== $this->try($name);
    }

    /**
     * Every named secret at once. Missing ones are an error.
     *
     * @param array<int, string> $names
     * @return array<string, string>
     */
    public function all(array $names): array
    {
        $out = [];

        foreach ($names as $name) {
            $out[$name] = $this->get($name);
        }

        return $out;
    }

    /**
     * A description of each provider, in resolution order.
     *
     * @return array<int, string>
     */
    public function sources(): array
    {
        return array_values(array_map(fn(Provider $p) => $p->describe(), $this->providers));
    }

    /** Replace every value this Sekreto has resolved with `[redacted]`. */
    public function redact(string $text): string
    {
        return redact($text, array_values($this->cache));
    }

    /** Drop cached values, so the next `get` asks the providers again. */
    public function refresh(): void
    {
        $this->cache = [];
    }
}

/**
 * Make a Sekreto from options.
 *
 * @param array<string, mixed>|null $options
 */
function sekreto(?array $options = null): Sekreto
{
    return new Sekreto($options);
}
