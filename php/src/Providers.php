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
 * Refuse to send a Vault token in the clear.
 *
 * Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
 * convenience. Sending `X-Vault-Token` over http to anything but the local
 * machine puts both the token and the secret it fetches on the wire for
 * anyone on the path, so sekreto will not do it. Loopback stays allowed:
 * that is `vault server -dev` and this repo's own test harness.
 */
function checkaddr(string $addr): void
{
    if (str_starts_with($addr, 'https://')) {
        return;
    }

    if (!str_starts_with($addr, 'http://')) {
        throw new SekretoError('sekreto: not an http(s) address: ' . $addr);
    }

    $host = explode(':', explode('/', substr($addr, 7))[0])[0];

    if (in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true)) {
        return;
    }

    throw new SekretoError(
        'sekreto: refusing to send a token in plaintext to ' . $addr . ' (use https)'
    );
}

/**
 * HashiCorp Vault, KV v2.
 *
 * `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token` field
 * of `data.data`. A 404 means "not here", which is a miss rather than an
 * error, so a vault can sit in a chain with fallbacks.
 */
class HashicorpProvider implements Provider
{
    private string $mount;

    public function __construct(private string $addr, private string $token, ?string $mount = null)
    {
        $this->mount = $mount ?? 'secret';
    }

    public function lookup(string $name): ?string
    {
        checkaddr($this->addr);

        $ref = Name::vaultref($name);
        $url = rtrim($this->addr, '/') . '/v1/' . $this->mount . '/data/' . $ref['path'];

        [$status, $body] = httpget($url, ['X-Vault-Token: ' . $this->token]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: hashicorp error: ' . $status . ': ' . $url);
        }

        $data = $body['data']['data'] ?? null;
        $value = is_array($data) ? ($data[$ref['field']] ?? null) : null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'hashicorp:' . $this->addr . '/' . $this->mount;
    }
}

/**
 * A boru vault (https://github.com/boru-lang/boru).
 *
 * boru keeps secrets in a local encrypted keyring and hands a value out
 * through its own CLI: `boru vault get --reveal <alias>` prints the secret
 * on stdout, and nothing else.
 *
 * There is deliberately no HTTP read here. boru's `vault proxy` and
 * `vault mcp` are a *credential broker*: they inject the real secret into an
 * outbound request and forward it, so an agent can call an API without ever
 * holding the credential. Handing a value back is the one thing that broker
 * is built not to do, so sekreto reads the vault the way boru itself does -
 * through the CLI.
 *
 * A sekreto name is already a valid boru alias, so `api.token` crosses over
 * unchanged. A `namespace` qualifies it the way boru writes it,
 * `<namespace>:<name>`.
 *
 * The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
 * sekreto never accepts it as config and never puts it on a command line,
 * where it would show up in the process table.
 */
class BoruProvider implements Provider
{
    private string $command;

    public function __construct(
        ?string $command = null,
        private ?string $namespace = null,
        private ?string $home = null
    ) {
        $this->command = $command ?? 'boru';
    }

    public function lookup(string $name): ?string
    {
        Name::check($name);

        $alias = $this->namespace ? $this->namespace . ':' . $name : $name;

        $cmd = escapeshellarg($this->command) . ' vault get --reveal ' . escapeshellarg($alias);

        if ($this->home) {
            $cmd = 'BORU_HOME=' . escapeshellarg($this->home) . ' ' . $cmd;
        }

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = @proc_open($cmd, $descriptors, $pipes);

        if (!is_resource($process)) {
            throw new SekretoError('sekreto: cannot run ' . $this->command);
        }

        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);

        if (0 === $status) {
            // boru prints the value and one newline, and nothing else.
            return preg_replace('/\n$/', '', $out);
        }

        $why = trim($err);

        // "no alias named" is boru saying it does not hold this secret, which
        // is a miss: the chain carries on to the next provider. A locked vault
        // or a wrong passphrase is not a miss - treating it as one would fall
        // through to a weaker store without saying so.
        if (borumiss($why)) {
            return null;
        }

        throw new SekretoError(
            'sekreto: boru vault error: ' . ('' === $why ? 'exit ' . $status : $why)
        );
    }

    public function describe(): string
    {
        return 'boru' . ($this->namespace ? ':' . $this->namespace : '');
    }
}

/**
 * Does this boru failure mean "no such secret" rather than "I could not
 * answer"? Matched on boru's own wording for a missing alias.
 */
function borumiss(string $why): bool
{
    return str_contains($why, 'no alias named');
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
        'hashicorp' => new HashicorpProvider(
            $spec['addr'] ?? '',
            $spec['token'] ?? '',
            $spec['mount'] ?? null
        ),
        'boru' => new BoruProvider(
            $spec['command'] ?? null,
            $spec['namespace'] ?? null,
            $spec['home'] ?? null
        ),
        default => throw new SekretoError(
            'sekreto: unknown provider kind: ' . (null === $kind ? '' : (string) $kind)
        ),
    };
}
