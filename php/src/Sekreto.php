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

    /**
     * A name flattened to one segment: `api.token` -> `api_token` (GCP
     * Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).
     *
     * Those stores have no path hierarchy and reject dots in ids, so the
     * dots become the store's conventional separator. With `-` as the
     * separator, underscores flatten too: Azure Key Vault's alphabet is
     * letters, digits and hyphens only, and a valid sekreto name like
     * `with_underscore` must still be representable there. (The resulting
     * `.`/`_` collision mirrors the documented envkey behaviour, where
     * both already map to `_`.)
     */
    public static function flatname(string $name, string $sep): string
    {
        self::check($name);

        $flat = implode($sep, explode('.', $name));

        return '-' === $sep ? str_replace('_', '-', $flat) : $flat;
    }

    /**
     * The AWS SSM Parameter Store name for a name: dots become the path
     * hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
     * `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
     */
    public static function awsparam(string $name, ?string $prefix = null): string
    {
        self::check($name);

        $base = $prefix ?? '';
        if ('' !== $base && !str_starts_with($base, '/')) {
            $base = '/' . $base;
        }
        $base = preg_replace('#/$#', '', $base);

        return $base . '/' . implode('/', explode('.', $name));
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

/**
 * The store name a provider answers to when its spec does not say.
 *
 * `describe()` opens with the provider's kind - `hashicorp:...`,
 * `dotenv:...`, plain `env` - so the kind is the natural default, and a
 * custom provider gets a sensible name without implementing anything extra.
 *
 * @param array<string, mixed>|null $spec
 */
function storename(Provider $provider, ?array $spec = null): string
{
    if (null !== $spec && !empty($spec['name'])) {
        return (string) $spec['name'];
    }

    return explode(':', $provider->describe())[0];
}

/**
 * The secrets facade: a chain of providers plus a cache.
 *
 * Two ways to read. `get` is transparent - it walks the chain and takes the
 * first hit, and the caller never learns which store answered. `getfrom` is
 * directed - it names the store, and only that store is asked.
 */
class Sekreto
{
    /** @var array<int, array{0: string, 1: Provider}> */
    private array $entries = [];
    private bool $docache;
    /** @var array<int, array{0: string, 1: string, 2: string}> */
    private array $cache = [];
    /**
     * Every value ever resolved, for redact(). Kept independently of the
     * read cache so that redaction still works when cache is off -
     * otherwise `cache: false` would silently disable redact() and leak
     * secrets to logs.
     *
     * @var array<int, string>
     */
    private array $seen = [];

    /** @param array<string, mixed>|null $options */
    public function __construct(?array $options = null)
    {
        $opts = $options ?? [];

        foreach ($opts['providers'] ?? [] as $entry) {
            if ($entry instanceof Provider) {
                $this->entries[] = [storename($entry), $entry];
                continue;
            }

            $provider = makeprovider($entry);
            $this->entries[] = [storename($provider, $entry), $provider];
        }

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
        return $this->resolve('', $name, $this->entries);
    }

    /**
     * The secret from one named store, or a SekretoError if that store does
     * not have it.
     */
    public function getfrom(string $store, string $name): string
    {
        $found = $this->tryfrom($store, $name);

        if (null === $found) {
            throw new SekretoError('sekreto: unknown secret: ' . $store . ':' . $name);
        }

        return $found;
    }

    /**
     * The secret from one named store, or null if that store does not have
     * it.
     *
     * Naming a store that is not in the chain is an error, not a miss: `try`
     * already means "this store may not have it", so it cannot also mean
     * "this store may not exist" without hiding a typo.
     */
    public function tryfrom(string $store, string $name): ?string
    {
        $matching = array_values(
            array_filter($this->entries, fn(array $entry) => $entry[0] === $store)
        );

        if (0 === count($matching)) {
            throw new SekretoError('sekreto: unknown store: ' . $store);
        }

        return $this->resolve($store, $name, $matching);
    }

    /** @param array<int, array{0: string, 1: Provider}> $entries */
    private function resolve(string $store, string $name, array $entries): ?string
    {
        Name::check($name);

        if ($this->docache) {
            foreach ($this->cache as $cached) {
                if ($cached[0] === $store && $cached[1] === $name) {
                    return $cached[2];
                }
            }
        }

        foreach ($entries as [$entrystore, $provider]) {
            $found = $provider->lookup($name);

            if (null !== $found) {
                if ($this->docache) {
                    $this->cache[] = [$store, $name, $found];
                }
                $this->seen[] = $found;
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

    /** Does this named store have this secret? */
    public function hasin(string $store, string $name): bool
    {
        return null !== $this->tryfrom($store, $name);
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
        return array_values(array_map(fn(array $entry) => $entry[1]->describe(), $this->entries));
    }

    /**
     * The name of each store that can be named by `getfrom`, in resolution
     * order and without repeats.
     *
     * @return array<int, string>
     */
    /**
     * What a Sekreto shows of itself when something prints it.
     *
     * `var_dump`, `print_r` and `var_export` all reach private properties,
     * and $cache and $seen between them hold every value this chain has
     * ever resolved - so one ordinary debugging call writes every secret
     * out.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['stores' => $this->stores()];
    }

    public function stores(): array
    {
        $out = [];

        foreach ($this->entries as [$store, $provider]) {
            if (!in_array($store, $out, true)) {
                $out[] = $store;
            }
        }

        return $out;
    }

    /**
     * Replace every value this Sekreto has resolved with `[redacted]`.
     *
     * Works whether or not caching is enabled: the redaction list is kept
     * independently of the read cache.
     */
    public function redact(string $text): string
    {
        return redact($text, $this->seen);
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
