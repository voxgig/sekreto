<?php

/**
 * The providers a Sekreto chains together.
 *
 * A provider answers one question: "do you have this secret?" It returns
 * the value, or null to mean "ask the next one". Nothing else about a
 * provider is visible to the caller - which is the point: an app reads
 * `api.token` and never learns whether it came from the environment, a
 * .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
 *
 * Two failure shapes, and they are never interchangeable. A store that
 * does not hold the secret is a MISS (null) - the chain carries on. A
 * store that could not answer - bad credentials, unreachable host,
 * missing configuration - is an ERROR: falling through there would
 * quietly reach for a weaker store.
 *
 * A port of typescript/src/Providers.ts, which is canonical.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto;

require_once __DIR__ . '/Sekreto.php';
require_once __DIR__ . '/Sigv4.php';

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
 * A directory of one-secret-per-file entries, keyed like the environment:
 * `api.token` reads `<dir>/API_TOKEN`.
 *
 * This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
 * secret, and a systemd credentials directory, so those all work with no
 * further configuration. One trailing newline is stripped - tools that
 * write these files disagree about it, and a newline is never part of a
 * secret on purpose.
 */
class FileProvider implements Provider
{
    public function __construct(private string $dir, private ?string $prefix = null)
    {
    }

    public function lookup(string $name): ?string
    {
        $file = $this->dir . '/' . Name::envkey($name, $this->prefix);

        // Attempt the read outright rather than pre-checking with
        // file_exists(): that also reports false when a parent directory
        // is unreadable for permission reasons, which is a store that
        // could not answer, not a store without the secret. Any raised
        // error counts as a failed read, not only a false return - PHP
        // reports reading a directory as '' plus a notice.
        error_clear_last();
        $text = @file_get_contents($file);
        $raised = error_get_last();

        if (false === $text || null !== $raised) {
            $why = $raised['message'] ?? 'unknown error';

            // PHP's warning text carries the OS reason after its
            // "Failed to open stream:" preamble; keep just the reason.
            if (1 === preg_match('/Failed to open stream: (.*)$/s', $why, $match)) {
                $why = $match[1];
            }

            // An absent file - or an absent directory - means "no secrets
            // here", exactly like a missing .env. Anything else (permission
            // denied, an unreadable mount) is a store that could not answer.
            if (str_contains($why, 'No such file or directory')
                || str_contains($why, 'Not a directory')
            ) {
                return null;
            }

            throw new SekretoError(
                'sekreto: file provider cannot read ' . $file . ': ' . $why
            );
        }

        return preg_replace('/\r?\n$/', '', $text);
    }

    public function describe(): string
    {
        return 'file:' . $this->dir;
    }
}

/**
 * One JSON round-trip, returning [status, decoded-json-or-null].
 *
 * A 404 is a normal answer here, not a failure: it means the store does not
 * hold this secret. Network failure is always an error - an unreachable
 * store is a store that could not answer. Uses the stream wrapper so that
 * no extension beyond the default build is required.
 *
 * @param array<int, string> $headers
 * @return array{0: int, 1: mixed}
 */
function fetchjson(string $method, string $url, array $headers, ?string $body = null): array
{
    $options = [
        'method' => $method,
        'header' => implode("\r\n", $headers),
        // Read the body of an error response rather than throwing it away.
        'ignore_errors' => true,
        'timeout' => 10,
    ];

    if (null !== $body) {
        $options['content'] = $body;
    }

    $context = stream_context_create(['http' => $options]);

    $text = @file_get_contents($url, false, $context);

    if (false === $text) {
        throw new SekretoError('sekreto: cannot reach ' . explode('?', $url)[0]);
    }

    $status = 0;
    foreach ($http_response_header ?? [] as $line) {
        if (1 === preg_match('#^HTTP/\S+\s+(\d+)#', $line, $match)) {
            $status = (int) $match[1];
        }
    }

    $parsed = json_decode($text, true);

    if (null === $parsed && JSON_ERROR_NONE !== json_last_error()) {
        // A success status promised JSON; a body that does not parse means
        // the store could not answer coherently, and treating it as a miss
        // would fall through to a weaker store. Error statuses may carry
        // any body - they are decided on status alone.
        if (200 === $status) {
            throw new SekretoError('sekreto: malformed response from ' . explode('?', $url)[0]);
        }
        $parsed = null;
    }

    return [$status, $parsed];
}

/**
 * GET a URL, returning [status, decoded-json-or-null].
 *
 * @param array<int, string> $headers
 * @return array{0: int, 1: mixed}
 */
function httpget(string $url, array $headers): array
{
    return fetchjson('GET', $url, $headers);
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
 * HashiCorp Vault.
 *
 * KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
 * takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
 * `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
 * here" - a miss - so a vault can sit in a chain with fallbacks.
 *
 * A Vault Enterprise namespace rides the X-Vault-Namespace header, on
 * logins as well as reads.
 *
 * Instead of being handed a token, the provider can log in: Kubernetes
 * auth (the pod's service-account JWT, from its conventional path) or
 * AppRole. A failed login is an error, never a miss - it means this store
 * could not answer at all.
 */
class HashicorpProvider implements Provider
{
    private string $mount;
    private int $kv;

    /**
     * The working token: a configured token is kept forever, a logged-in
     * token is renewed shortly before its lease runs out - a long-running
     * process must not keep presenting a token the vault already expired.
     */
    private ?string $livetoken;
    private float $renewat = INF;

    /** @param array<string, mixed>|null $auth */
    public function __construct(
        private string $addr,
        string $token,
        ?string $mount = null,
        ?int $kv = null,
        private ?string $vaultnamespace = null,
        private ?array $auth = null
    ) {
        $this->mount = $mount ?? 'secret';
        $this->kv = $kv ?: 2;

        // A version typo like kv: 3 must not quietly behave as v2 and turn
        // its 404s into misses; there is nothing safe to assume it meant.
        if (1 !== $this->kv && 2 !== $this->kv) {
            throw new SekretoError(
                'sekreto: hashicorp: unsupported kv version: ' . $this->kv
            );
        }

        $this->livetoken = '' === $token ? null : $token;
    }

    /** @return array<int, string> */
    private function baseheaders(): array
    {
        $headers = [];

        if ($this->vaultnamespace) {
            $headers[] = 'X-Vault-Namespace: ' . $this->vaultnamespace;
        }

        return $headers;
    }

    private function login(): string
    {
        $auth = $this->auth;

        if (null === $auth) {
            throw new SekretoError('sekreto: hashicorp: no token and no auth method');
        }

        $method = $auth['method'] ?? null;
        $mount = $auth['mount'] ?? $method;
        $url = rtrim($this->addr, '/') . '/v1/auth/' . $mount . '/login';

        if ('kubernetes' === $method) {
            $jwt = $auth['jwt'] ?? null;
            if (null === $jwt) {
                $file = ($auth['jwtfile'] ?? null)
                    ?: '/var/run/secrets/kubernetes.io/serviceaccount/token';
                $text = @file_get_contents($file);
                if (false === $text) {
                    throw new SekretoError('sekreto: hashicorp: cannot read jwt file ' . $file);
                }
                $jwt = trim($text);
            }
            $body = ['role' => $auth['role'] ?? '', 'jwt' => $jwt];
        } elseif ('approle' === $method) {
            $body = [
                'role_id' => $auth['roleid'] ?? '',
                'secret_id' => $auth['secretid'] ?? '',
            ];
        } else {
            throw new SekretoError(
                'sekreto: hashicorp: unknown auth method: ' . (string) $method
            );
        }

        [$status, $answer] = fetchjson('POST', $url, $this->baseheaders(), json_encode($body));

        $got = $answer['auth']['client_token'] ?? null;
        if (200 !== $status || !$got) {
            throw new SekretoError('sekreto: hashicorp login failed: ' . $status . ': ' . $url);
        }

        $lease = (float) ($answer['auth']['lease_duration'] ?? 0);
        $this->renewat = 0 < $lease ? microtime(true) + max($lease - 60, 1) : INF;

        return (string) $got;
    }

    public function lookup(string $name): ?string
    {
        checkaddr($this->addr);

        if (null === $this->livetoken || microtime(true) >= $this->renewat) {
            $this->livetoken = $this->login();
        }

        $ref = Name::vaultref($name);
        $base = rtrim($this->addr, '/') . '/v1/' . $this->mount;
        $url = 1 === $this->kv ? $base . '/' . $ref['path'] : $base . '/data/' . $ref['path'];

        $headers = $this->baseheaders();
        $headers[] = 'X-Vault-Token: ' . $this->livetoken;

        [$status, $body] = fetchjson('GET', $url, $headers);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: hashicorp error: ' . $status . ': ' . $url);
        }

        $data = 1 === $this->kv ? ($body['data'] ?? null) : ($body['data']['data'] ?? null);
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
 * Two ways in, both boru's own.
 *
 * With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
 * secret on stdout and nothing else. The passphrase is read by boru itself
 * from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config and
 * never puts it on a command line, where it would show up in the process
 * table.
 *
 * With an `addr`, boru's wire protocol: `boru vault serve` publishes a
 * read-only, HashiCorp-shaped provision API (boru's
 * design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
 * from `boru vault grant`. A sekreto name is already a valid boru alias,
 * and boru aliases keep their dots, so `api.token` is the single path
 * segment `api.token` - not the `api`/`token` split a HashiCorp KV gets.
 * The value is the `value` field. A 404 is a miss; anything else the
 * server refuses (a revoked capability, a sealed vault) is an error.
 *
 * boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
 * credential *broker*, built precisely so the caller never receives the
 * credential. `vault serve` is the provision endpoint, built to hand the
 * value back - that is the one sekreto uses.
 */
class BoruProvider implements Provider
{
    private string $command;
    private ?string $addr;

    public function __construct(
        ?string $command = null,
        private ?string $namespace = null,
        private ?string $home = null,
        ?string $addr = null,
        private ?string $token = null,
        private ?string $mount = null
    ) {
        $this->command = $command ?? 'boru';
        $this->addr = $addr ? preg_replace('#/$#', '', $addr) : null;
    }

    private function wirelookup(string $name): ?string
    {
        Name::check($name);
        checkaddr($this->addr);

        $alias = $this->namespace ? $this->namespace . '/' . $name : $name;
        $url = $this->addr . '/v1/' . ($this->mount ?: 'secret') . '/data/' . $alias;

        [$status, $body] = fetchjson('GET', $url, ['X-Vault-Token: ' . ($this->token ?? '')]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: boru serve error: ' . $status . ': ' . $url);
        }

        $data = $body['data']['data'] ?? null;
        $value = is_array($data) ? ($data['value'] ?? null) : null;

        return null === $value ? null : (string) $value;
    }

    public function lookup(string $name): ?string
    {
        if ($this->addr) {
            return $this->wirelookup($name);
        }

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
        if ($this->addr) {
            return 'boru:' . $this->addr;
        }

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

/** The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. */
function awsnow(): string
{
    return gmdate('Ymd\THis\Z');
}

/**
 * Region and credentials, from config first and the standard AWS_*
 * environment variables second - those are AWS's own convention, and a
 * pod or CI job that has them set should just work. Missing either is an
 * error: an AWS store with no credentials could not answer.
 *
 * @param array<string, mixed> $opts
 * @return array{region: string, keyid: string, secret: string, session: ?string}
 */
function awsauth(array $opts): array
{
    $region = ($opts['region'] ?? null)
        ?: (getenv('AWS_REGION') ?: (getenv('AWS_DEFAULT_REGION') ?: ''));
    $keyid = ($opts['keyid'] ?? null) ?: (getenv('AWS_ACCESS_KEY_ID') ?: '');
    $secret = ($opts['secret'] ?? null) ?: (getenv('AWS_SECRET_ACCESS_KEY') ?: '');
    $session = ($opts['session'] ?? null) ?: (getenv('AWS_SESSION_TOKEN') ?: null);

    if ('' === $region) {
        throw new SekretoError('sekreto: aws: no region (set region or AWS_REGION)');
    }
    if ('' === $keyid || '' === $secret) {
        throw new SekretoError(
            'sekreto: aws: no credentials'
            . ' (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)'
        );
    }

    return ['region' => $region, 'keyid' => $keyid, 'secret' => $secret, 'session' => $session];
}

/**
 * One signed call to an AWS JSON-1.1 API.
 *
 * @param array<string, mixed> $opts
 * @param array<string, mixed> $payload
 * @return array{0: int, 1: mixed}
 */
function awscall(array $opts, string $service, string $target, array $payload): array
{
    $auth = awsauth($opts);
    // The China partition lives under its own suffix; every other
    // commercial region is plain amazonaws.com.
    $suffix = str_starts_with($auth['region'], 'cn-') ? '.amazonaws.com.cn' : '.amazonaws.com';
    $addr = ($opts['addr'] ?? null)
        ?: 'https://' . $service . '.' . $auth['region'] . $suffix;
    checkaddr($addr);

    $url = preg_replace('#/$#', '', $addr) . '/';
    // Unescaped slashes, so the body signed here is byte-identical to the
    // canonical port's JSON.stringify output.
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
    $headers = [
        'content-type' => 'application/x-amz-json-1.1',
        'x-amz-target' => $target,
    ];

    $signed = sigv4([
        'method' => 'POST',
        'url' => $url,
        'headers' => $headers,
        'body' => $body,
        'service' => $service,
        'region' => $auth['region'],
        'keyid' => $auth['keyid'],
        'secret' => $auth['secret'],
        'session' => $auth['session'],
        'datetime' => awsnow(),
    ]);

    $lines = [];
    foreach (array_merge($headers, $signed) as $key => $value) {
        $lines[] = $key . ': ' . $value;
    }

    return fetchjson('POST', $url, $lines, $body);
}

/**
 * Does this AWS error body name one of the not-found types? Those are a
 * miss; every other failure is a store that could not answer.
 *
 * @param array<int, string> $types
 */
function awsmiss(mixed $body, array $types): bool
{
    $errtype = is_array($body) && is_string($body['__type'] ?? null) ? $body['__type'] : '';

    foreach ($types as $name) {
        if (str_contains($errtype, $name)) {
            return true;
        }
    }

    return false;
}

/**
 * AWS Secrets Manager.
 *
 * `api.token` reads the secret named `api` (the vaultref path, so
 * `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
 * SecretString - the AWS idiom of one JSON map per secret. A SecretString
 * that is not JSON is the value itself, under the conventional field
 * `value`. Requests are SigV4-signed in-tree; see Sigv4.php.
 */
class AwsSecretsProvider implements Provider
{
    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    public function lookup(string $name): ?string
    {
        $ref = Name::vaultref($name);

        [$status, $body] = awscall(
            $this->opts,
            'secretsmanager',
            'secretsmanager.GetSecretValue',
            ['SecretId' => $ref['path']]
        );

        if (400 === $status && awsmiss($body, ['ResourceNotFoundException'])) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: aws secretsmanager error: ' . $status);
        }

        $text = $body['SecretString'] ?? null;

        if (!is_string($text)) {
            // A binary secret has no fields to address; only the conventional
            // `value` field can mean "the bytes themselves".
            $bin = $body['SecretBinary'] ?? null;
            if (is_string($bin) && 'value' === $ref['field']) {
                return base64_decode($bin);
            }
            return null;
        }

        // Decoded without assoc, so a JSON object is distinguishable from a
        // JSON array: only an object carries named fields.
        $parsed = json_decode($text);

        if ($parsed instanceof \stdClass) {
            $value = $parsed->{$ref['field']} ?? null;
            return null === $value ? null : (string) $value;
        }

        // A plain-string secret is the whole value; it has no named fields.
        return 'value' === $ref['field'] ? $text : null;
    }

    // Config only, never the environment: describe() feeds the spec's
    // sources group, which must answer the same everywhere.
    public function describe(): string
    {
        return 'awssecrets:' . ($this->opts['region'] ?? '');
    }
}

/**
 * AWS SSM Parameter Store.
 *
 * `db.pass.main` reads the parameter `/db/pass/main` (under an optional
 * prefix path), decrypted. Parameter Store carries flat strings, so there
 * is no field indirection.
 */
class AwsParamsProvider implements Provider
{
    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    public function lookup(string $name): ?string
    {
        [$status, $body] = awscall($this->opts, 'ssm', 'AmazonSSM.GetParameter', [
            'Name' => Name::awsparam($name, $this->opts['prefix'] ?? null),
            'WithDecryption' => true,
        ]);

        if (400 === $status && awsmiss($body, ['ParameterNotFound'])) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: aws ssm error: ' . $status);
        }

        $value = $body['Parameter']['Value'] ?? null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'awsparams:' . ($this->opts['region'] ?? '') . ($this->opts['prefix'] ?? '');
    }
}

/**
 * GCP Secret Manager.
 *
 * `api.token` reads secret `api_token` (dots flattened to `_`; Secret
 * Manager ids have no hierarchy and reject dots), latest version. The
 * token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
 * GCE/GKE metadata server - so on Google's own platform no credential
 * configuration is needed at all.
 *
 * The metadata call itself is plain http to a link-local host by platform
 * design; no credential rides on it, so `checkaddr` guards the Secret
 * Manager address instead.
 */
class GcpSecretsProvider implements Provider
{
    // A configured token is kept forever; a metadata-server token carries
    // expires_in and is renewed shortly before it runs out.
    private ?string $livetoken = null;
    private float $renewat = INF;

    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    private function metadataaddr(): string
    {
        $addr = $this->opts['metadataaddr'] ?? null;
        if ($addr) {
            return $addr;
        }

        $host = getenv('GCE_METADATA_HOST');

        return $host ? 'http://' . $host : 'http://metadata.google.internal';
    }

    private function login(): string
    {
        $configured = ($this->opts['token'] ?? null) ?: getenv('GOOGLE_OAUTH_ACCESS_TOKEN');
        if ($configured) {
            return $configured;
        }

        $url = rtrim($this->metadataaddr(), '/')
            . '/computeMetadata/v1/instance/service-accounts/default/token';

        [$status, $body] = fetchjson('GET', $url, ['Metadata-Flavor: Google']);

        $got = $body['access_token'] ?? null;
        if (200 !== $status || !$got) {
            throw new SekretoError('sekreto: gcp: no token and metadata server did not answer');
        }

        $expires = (float) ($body['expires_in'] ?? 0);
        $this->renewat = 0 < $expires ? microtime(true) + max($expires - 60, 1) : INF;

        return (string) $got;
    }

    public function lookup(string $name): ?string
    {
        $project = $this->opts['project'] ?? '';
        if ('' === $project || null === $project) {
            throw new SekretoError('sekreto: gcp: no project');
        }

        $addr = ($this->opts['addr'] ?? null) ?: 'https://secretmanager.googleapis.com';
        checkaddr($addr);

        if (null === $this->livetoken || microtime(true) >= $this->renewat) {
            $this->livetoken = $this->login();
        }

        $url = rtrim($addr, '/') . '/v1/projects/' . $project . '/secrets/'
            . Name::flatname($name, '_') . '/versions/latest:access';

        [$status, $body] = fetchjson('GET', $url, ['Authorization: Bearer ' . $this->livetoken]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: gcp error: ' . $status . ': ' . $url);
        }

        $data = $body['payload']['data'] ?? null;
        if (!is_string($data)) {
            return null;
        }

        return base64_decode($data);
    }

    public function describe(): string
    {
        return 'gcpsecrets:' . ($this->opts['project'] ?? '');
    }
}

/**
 * Azure Key Vault.
 *
 * `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
 * names allow nothing else), current version. The token comes from
 * config, then a client-credentials login when tenant/clientid/
 * clientsecret are given, then the IMDS managed-identity endpoint - so on
 * Azure's own platform no credential configuration is needed.
 *
 * As with GCP, the IMDS call is plain http to a link-local host by
 * platform design and carries no credential; the login and vault
 * addresses are `checkaddr`-guarded.
 */
class AzureSecretsProvider implements Provider
{
    private const RESOURCE = 'https://vault.azure.net';

    // A configured token is kept forever; logged-in and IMDS tokens carry
    // expires_in and are renewed shortly before they run out.
    private ?string $livetoken = null;
    private float $renewat = INF;

    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    /** The renewal moment for an expires_in (which may be a string). */
    private function expiry(mixed $expires): float
    {
        $seconds = (float) $expires;

        return 0 < $seconds ? microtime(true) + max($seconds - 60, 1) : INF;
    }

    private function login(): string
    {
        $opts = $this->opts;

        if ($opts['token'] ?? null) {
            return $opts['token'];
        }

        if (($opts['tenant'] ?? null) && ($opts['clientid'] ?? null)
            && ($opts['clientsecret'] ?? null)
        ) {
            $loginaddr = ($opts['loginaddr'] ?? null) ?: 'https://login.microsoftonline.com';
            checkaddr($loginaddr);

            $url = rtrim($loginaddr, '/') . '/' . $opts['tenant'] . '/oauth2/v2.0/token';
            $form = 'grant_type=client_credentials'
                . '&client_id=' . rawurlencode($opts['clientid'])
                . '&client_secret=' . rawurlencode($opts['clientsecret'])
                . '&scope=' . rawurlencode(self::RESOURCE . '/.default');

            [$status, $body] = fetchjson(
                'POST',
                $url,
                ['Content-Type: application/x-www-form-urlencoded'],
                $form
            );

            $got = $body['access_token'] ?? null;
            if (200 !== $status || !$got) {
                throw new SekretoError('sekreto: azure login failed: ' . $status);
            }

            $this->renewat = $this->expiry($body['expires_in'] ?? null);

            return (string) $got;
        }

        $imds = rtrim(($opts['imdsaddr'] ?? null) ?: 'http://169.254.169.254', '/')
            . '/metadata/identity/oauth2/token?api-version=2018-02-01&resource='
            . rawurlencode(self::RESOURCE);

        [$status, $body] = fetchjson('GET', $imds, ['Metadata: true']);

        $got = $body['access_token'] ?? null;
        if (200 !== $status || !$got) {
            throw new SekretoError(
                'sekreto: azure: no token, no client credentials, and IMDS did not answer'
            );
        }

        $this->renewat = $this->expiry($body['expires_in'] ?? null);

        return (string) $got;
    }

    public function lookup(string $name): ?string
    {
        $vault = $this->opts['vault'] ?? '';
        if ('' === $vault || null === $vault) {
            throw new SekretoError('sekreto: azure: no vault');
        }

        // Only an explicit scheme is a URL; a vault NAMED httpvault must
        // still become https://httpvault.vault.azure.net.
        $vaulturl = str_starts_with($vault, 'http://') || str_starts_with($vault, 'https://')
            ? $vault
            : 'https://' . $vault . '.vault.azure.net';
        checkaddr($vaulturl);

        if (null === $this->livetoken || microtime(true) >= $this->renewat) {
            $this->livetoken = $this->login();
        }

        $url = rtrim($vaulturl, '/') . '/secrets/' . Name::flatname($name, '-')
            . '?api-version=' . (($this->opts['apiversion'] ?? null) ?: '7.4');

        [$status, $body] = fetchjson('GET', $url, ['Authorization: Bearer ' . $this->livetoken]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError(
                'sekreto: azure error: ' . $status . ': ' . explode('?', $url)[0]
            );
        }

        $value = $body['value'] ?? null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'azuresecrets:' . ($this->opts['vault'] ?? '');
    }
}

/**
 * 1Password, through a Connect server.
 *
 * The item titled `api.token` (titles keep their dots), in the named
 * vault. The value is the field with purpose PASSWORD, or the field
 * labelled `value`. A vault that cannot be found is an error - config
 * names it, so its absence is a broken store, not a missing secret.
 */
class OnePasswordProvider implements Provider
{
    private ?string $vaultid = null;

    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    /** @return array<int, string> */
    private function auth(): array
    {
        return ['Authorization: Bearer ' . ($this->opts['token'] ?? '')];
    }

    private function resolvevault(string $addr): string
    {
        $want = $this->opts['vault'] ?? '';
        if ('' === $want || null === $want) {
            throw new SekretoError('sekreto: onepassword: no vault');
        }

        [$status, $body] = fetchjson('GET', $addr . '/v1/vaults', $this->auth());

        if (200 !== $status || !is_array($body)) {
            throw new SekretoError('sekreto: onepassword error: ' . $status . ': listing vaults');
        }

        foreach ($body as $entry) {
            if (is_array($entry)
                && ($want === ($entry['id'] ?? null) || $want === ($entry['name'] ?? null))
            ) {
                return (string) $entry['id'];
            }
        }

        throw new SekretoError('sekreto: onepassword: no vault named ' . $want);
    }

    public function lookup(string $name): ?string
    {
        Name::check($name);

        $addr = rtrim($this->opts['addr'] ?? '', '/');
        if ('' === $addr) {
            throw new SekretoError('sekreto: onepassword: no addr');
        }
        checkaddr($addr);

        if (null === $this->vaultid) {
            $this->vaultid = $this->resolvevault($addr);
        }

        $filter = rawurlencode('title eq "' . $name . '"');
        [$status, $found] = fetchjson(
            'GET',
            $addr . '/v1/vaults/' . $this->vaultid . '/items?filter=' . $filter,
            $this->auth()
        );

        if (200 !== $status || !is_array($found)) {
            throw new SekretoError(
                'sekreto: onepassword error: ' . $status . ': finding ' . $name
            );
        }

        if (0 === count($found)) {
            return null;
        }

        [$status, $item] = fetchjson(
            'GET',
            $addr . '/v1/vaults/' . $this->vaultid . '/items/' . $found[0]['id'],
            $this->auth()
        );

        if (200 !== $status) {
            throw new SekretoError(
                'sekreto: onepassword error: ' . $status . ': reading ' . $name
            );
        }

        $fields = $item['fields'] ?? [];

        foreach ($fields as $field) {
            if (is_array($field) && 'PASSWORD' === ($field['purpose'] ?? null)) {
                $value = $field['value'] ?? null;
                return null === $value ? null : (string) $value;
            }
        }
        foreach ($fields as $field) {
            if (is_array($field) && 'value' === ($field['label'] ?? null)) {
                $value = $field['value'] ?? null;
                return null === $value ? null : (string) $value;
            }
        }

        return null;
    }

    public function describe(): string
    {
        return 'onepassword:' . ($this->opts['vault'] ?? '');
    }
}

/**
 * Doppler.
 *
 * The whole config is downloaded once - Doppler's own bulk endpoint - and
 * answered from memory, like a remote .env: `api.token` is the
 * `API_TOKEN` entry. A service token is config-scoped, so project and
 * config are only needed with broader tokens.
 */
class DopplerProvider implements Provider
{
    /** @var array<string, string>|null */
    private ?array $values = null;

    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    /** @return array<string, string> */
    private function load(): array
    {
        if (null !== $this->values) {
            return $this->values;
        }

        $addr = rtrim(($this->opts['addr'] ?? null) ?: 'https://api.doppler.com', '/');
        checkaddr($addr);

        $url = $addr . '/v3/configs/config/secrets/download?format=json';
        if ($this->opts['project'] ?? null) {
            $url .= '&project=' . rawurlencode($this->opts['project']);
        }
        if ($this->opts['config'] ?? null) {
            $url .= '&config=' . rawurlencode($this->opts['config']);
        }

        [$status, $body] = fetchjson(
            'GET',
            $url,
            ['Authorization: Bearer ' . ($this->opts['token'] ?? '')]
        );

        if (200 !== $status || !is_array($body)) {
            throw new SekretoError('sekreto: doppler error: ' . $status);
        }

        $this->values = [];
        foreach ($body as $key => $value) {
            if (null !== $value) {
                $this->values[$key] = (string) $value;
            }
        }

        return $this->values;
    }

    public function lookup(string $name): ?string
    {
        return $this->load()[Name::envkey($name)] ?? null;
    }

    public function describe(): string
    {
        $project = $this->opts['project'] ?? null;

        return 'doppler'
            . ($project ? ':' . $project . '/' . ($this->opts['config'] ?? '') : '');
    }
}

/**
 * Infisical.
 *
 * `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
 * convention is environment-style keys) at a secret path in one
 * environment of a project. Auth is a token, or a universal-auth (machine
 * identity) login with clientid/clientsecret.
 */
class InfisicalProvider implements Provider
{
    // A configured token is kept forever; a universal-auth token carries
    // expiresIn and is renewed shortly before it runs out.
    private ?string $livetoken = null;
    private float $renewat = INF;

    /** @param array<string, mixed> $opts */
    public function __construct(private array $opts = [])
    {
    }

    private function login(string $addr): string
    {
        if ($this->opts['token'] ?? null) {
            return $this->opts['token'];
        }

        $clientid = $this->opts['clientid'] ?? null;
        $clientsecret = $this->opts['clientsecret'] ?? null;
        if (!$clientid || !$clientsecret) {
            throw new SekretoError('sekreto: infisical: no token and no client credentials');
        }

        [$status, $body] = fetchjson(
            'POST',
            $addr . '/api/v1/auth/universal-auth/login',
            ['Content-Type: application/json'],
            json_encode(['clientId' => $clientid, 'clientSecret' => $clientsecret])
        );

        $got = $body['accessToken'] ?? null;
        if (200 !== $status || !$got) {
            throw new SekretoError('sekreto: infisical login failed: ' . $status);
        }

        $expires = (float) ($body['expiresIn'] ?? 0);
        $this->renewat = 0 < $expires ? microtime(true) + max($expires - 60, 1) : INF;

        return (string) $got;
    }

    public function lookup(string $name): ?string
    {
        $addr = rtrim(($this->opts['addr'] ?? null) ?: 'https://app.infisical.com', '/');
        checkaddr($addr);

        $project = $this->opts['project'] ?? '';
        $environment = $this->opts['environment'] ?? '';
        if ('' === $project || null === $project
            || '' === $environment || null === $environment
        ) {
            throw new SekretoError('sekreto: infisical: no project/environment');
        }

        if (null === $this->livetoken || microtime(true) >= $this->renewat) {
            $this->livetoken = $this->login($addr);
        }

        $url = $addr . '/api/v3/secrets/raw/' . Name::envkey($name)
            . '?workspaceId=' . rawurlencode($project)
            . '&environment=' . rawurlencode($environment)
            . '&secretPath=' . rawurlencode(($this->opts['path'] ?? null) ?: '/');

        [$status, $body] = fetchjson('GET', $url, ['Authorization: Bearer ' . $this->livetoken]);

        if (404 === $status) {
            return null;
        }

        if (200 !== $status) {
            throw new SekretoError('sekreto: infisical error: ' . $status);
        }

        $value = $body['secret']['secretValue'] ?? null;

        return null === $value ? null : (string) $value;
    }

    public function describe(): string
    {
        return 'infisical:' . ($this->opts['project'] ?? '')
            . '/' . ($this->opts['environment'] ?? '');
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
        'file' => new FileProvider($spec['dir'] ?? '', $spec['prefix'] ?? null),
        'hashicorp' => new HashicorpProvider(
            $spec['addr'] ?? '',
            $spec['token'] ?? '',
            $spec['mount'] ?? null,
            isset($spec['kv']) ? (int) $spec['kv'] : null,
            $spec['vaultnamespace'] ?? null,
            $spec['auth'] ?? null
        ),
        'boru' => new BoruProvider(
            $spec['command'] ?? null,
            $spec['namespace'] ?? null,
            $spec['home'] ?? null,
            $spec['addr'] ?? null,
            $spec['token'] ?? null,
            $spec['mount'] ?? null
        ),
        'awssecrets' => new AwsSecretsProvider($spec),
        'awsparams' => new AwsParamsProvider($spec),
        'gcpsecrets' => new GcpSecretsProvider($spec),
        'azuresecrets' => new AzureSecretsProvider($spec),
        'onepassword' => new OnePasswordProvider($spec),
        'doppler' => new DopplerProvider($spec),
        'infisical' => new InfisicalProvider($spec),
        default => throw new SekretoError(
            'sekreto: unknown provider kind: ' . (null === $kind ? '' : (string) $kind)
        ),
    };
}
