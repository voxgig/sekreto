<?php

/**
 * RUN: php test/plugins.php
 * RUN-SOME: php test/plugins.php thecoreremembersnoplugin
 *
 * THE PLUGIN SEAM, from both sides.
 *
 * Moving the provider kinds that open sockets and spawn processes out of
 * the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
 * passed in is not in the catalog, and a chain naming it is refused. That
 * is the intended behaviour, and it means a consumer can be broken without
 * a single conformance test noticing - the conformance suite passes every
 * plugin, so it can never see a missing one. So the full set is pinned
 * here: it holds every kind, every kind builds, and the CLI passes it.
 *
 * The other half is the boundary itself. PHP has no compiler to erase an
 * unused import and no linker to drop an unreferenced object, so the
 * boundary here is the REQUIRE GRAPH plus the namespace: `src/` is
 * `Voxgig\Sekreto`, `plugins/` is `Voxgig\Sekreto\Plugins`, and nothing in
 * the first requires or names anything in the second. `php
 * test/included.php` reports that graph from a fresh interpreter, which is
 * the only place it can be read - this one has required everything, on
 * purpose.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto\Test;

use Voxgig\Plugin\PluginError;
use Voxgig\Sekreto\Provider;
use Voxgig\Sekreto\Sekreto;
use Voxgig\Sekreto\SekretoError;

use function Voxgig\Sekreto\builtins;
use function Voxgig\Sekreto\providerplugin;
use function Voxgig\Sekreto\Plugins\allplugins;
use function Voxgig\Sekreto\Plugins\hashicorp;

require_once __DIR__ . '/../src/Sekreto.php';
require_once __DIR__ . '/../plugins/plugins.php';
require_once __DIR__ . '/../plugins/hashicorp.php';

const PLUGINS = [
    'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'gcpsecrets',
    'hashicorp', 'infisical', 'onepassword', 'secretspec',
];

const EVERY = [
    'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'dotenv',
    'env', 'file', 'gcpsecrets', 'hashicorp', 'infisical', 'memory',
    'onepassword', 'secretspec',
];

$only = $argv[1] ?? null;
$pass = 0;
$fail = 0;

function testcase(string $name, callable $body): void
{
    global $only, $pass, $fail;

    if (null !== $only && $name !== $only) {
        return;
    }

    try {
        $body();
        $pass++;
        echo "ok   - $name\n";
    } catch (\Throwable $err) {
        $fail++;
        echo "FAIL - $name\n     " . $err->getMessage() . "\n";
    }
}

/** @param mixed $want @param mixed $got */
function same($want, $got, string $what = ''): void
{
    if ($want !== $got) {
        throw new \RuntimeException(
            ('' === $what ? '' : $what . ': ') . 'want ' . json_encode($want)
            . ', got ' . json_encode($got)
        );
    }
}

/** @return string the message of the exception the body threw */
function threw(string $class, callable $body): \Throwable
{
    try {
        $body();
    } catch (\Throwable $err) {
        if (!($err instanceof $class)) {
            throw new \RuntimeException(
                'want a ' . $class . ', got a ' . get_class($err) . ': ' . $err->getMessage()
            );
        }
        return $err;
    }

    throw new \RuntimeException('want a ' . $class . ', nothing was thrown');
}

/** Names, sorted, of a list of definitions. @param array<int, mixed> $defs */
function names(array $defs): array
{
    $out = array_map(fn(array $def) => $def['name'], $defs);
    sort($out, SORT_STRING);
    return $out;
}

/**
 * One file's CODE, with every comment stripped.
 *
 * The boundary is what the core executes and names, not what it explains:
 * `Sekreto.php` documents the split in its header, and a grep of the raw
 * text would read its own documentation as a breach.
 */
function codeof(string $file): string
{
    $out = '';

    foreach (token_get_all((string) file_get_contents($file)) as $token) {
        if (is_array($token)) {
            if (T_COMMENT === $token[0] || T_DOC_COMMENT === $token[0]) {
                continue;
            }
            $out .= $token[1];
            continue;
        }

        $out .= $token;
    }

    return $out;
}

/**
 * What requiring one file costs, in a FRESH interpreter.
 *
 * @return array<int, string>
 */
function included(string $target): array
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/included.php')
        . ' ' . escapeshellarg($target) . ' 2>&1';
    $text = shell_exec($cmd);
    $out = array_values(array_filter(array_map('trim', explode("\n", (string) $text))));
    sort($out, SORT_STRING);
    return $out;
}

// --- the full set --------------------------------------------------------

testcase('thefullsetholdseverykind', function (): void {
    same(PLUGINS, names(allplugins()));
    same(\Voxgig\Sekreto\BUILTIN_KINDS, array_map(fn(array $d) => $d['name'], builtins()));

    $plugin = \Voxgig\Sekreto\PLUGIN_KINDS;
    sort($plugin, SORT_STRING);
    same(PLUGINS, $plugin);
});

// Naming a kind is not enough: a kind can be in the catalog and still fail
// to build. Construction is what the CLI does before any network.
testcase('everykindbuildsfromaspec', function (): void {
    $chain = [];
    foreach (EVERY as $kind) {
        $chain[] = [
            'kind' => $kind, 'addr' => 'http://127.0.0.1:8200', 'token' => 't',
            'dir' => '/tmp', 'file' => '/tmp/.env', 'values' => [],
        ];
    }

    $secrets = new Sekreto(['plugins' => allplugins(), 'providers' => $chain]);

    same(EVERY, $secrets->stores());
    same(EVERY, array_keys($secrets->host->list()));
    same(['live'], array_values(array_unique(array_values($secrets->host->list()))));
});

testcase('theclipassesthefullset', function (): void {
    $src = (string) file_get_contents(__DIR__ . '/../cli/sekreto-cli.php');
    same(true, str_contains($src, "require_once __DIR__ . '/../plugins/plugins.php';"));
    same(true, str_contains($src, "'plugins' => allplugins()"));
});

// --- what a consumer sees ------------------------------------------------

testcase('onepluginisenoughforachainthatnamesonlyit', function (): void {
    $secrets = new Sekreto([
        'plugins' => [hashicorp()],
        'providers' => [
            ['kind' => 'memory', 'values' => ['API_TOKEN' => 'tok01']],
            ['kind' => 'hashicorp', 'name' => 'prod',
             'addr' => 'https://vault.example.com', 'token' => 't'],
        ],
    ]);

    same(['memory', 'prod'], $secrets->stores());
    same(['memory', 'hashicorp:https://vault.example.com/secret'], $secrets->sources());
    same('tok01', $secrets->get('api.token'));

    // The plugin host is what the chain is made of, and it reads like the
    // chain: the kind, or kind$store for a named store.
    same(['hashicorp$prod' => 'live', 'memory' => 'live'], $secrets->host->list());
    same(['dotenv', 'env', 'file', 'hashicorp', 'memory'], $secrets->catalog->names());
});

testcase('akindthatwasnotpassedinisrefusednamingthefix', function (): void {
    $err = threw(SekretoError::class, fn() => new Sekreto([
        'plugins' => [hashicorp()],
        'providers' => [['kind' => 'doppler', 'token' => 't']],
    ]));
    same(
        'sekreto: unknown provider kind: doppler'
        . ' (available: dotenv, env, file, hashicorp, memory)'
        . ' - doppler is a sekreto plugin, not built in: pass it in the plugins option',
        $err->getMessage()
    );

    // A kind nobody ships is a typo, and gets no such hint.
    $err = threw(SekretoError::class, fn() => new Sekreto([
        'providers' => [['kind' => 'vualt']],
    ]));
    same(
        'sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)',
        $err->getMessage()
    );
});

// Two providers MAY share a store name - a directed read walks both, and
// the spec pins it - but an instance ref may not, so the second gets a
// numbered tag from the host and keeps its store name.
testcase('arepeatedstorenamekeepsthestoreandnumberstheinstance', function (): void {
    $secrets = new Sekreto(['providers' => [
        ['kind' => 'memory', 'values' => []],
        ['kind' => 'memory', 'values' => ['API_TOKEN' => 'second']],
        ['kind' => 'memory', 'name' => 'pair', 'values' => []],
        ['kind' => 'memory', 'name' => 'pair', 'values' => ['API_TOKEN' => 'pair2']],
    ]]);

    same(['memory', 'pair'], $secrets->stores());
    same(
        ['memory', 'memory$1', 'memory$2', 'memory$pair'],
        array_keys($secrets->host->list())
    );
    same('second', $secrets->getfrom('memory', 'api.token'));
    same('pair2', $secrets->getfrom('pair', 'api.token'));
});

testcase('astorenamemustbeavalidtag', function (): void {
    $err = threw(SekretoError::class, fn() => new Sekreto([
        'providers' => [['kind' => 'memory', 'name' => 'my store', 'values' => []]],
    ]));
    same('sekreto: invalid store name: my store', $err->getMessage());
});

// A provider that refuses its own configuration throws a SekretoError from
// inside the plugin's `define`. The spec pins that message byte for byte,
// so it must come back out of the host as itself - not wrapped as
// plugin_define_failed, and not as a PluginError.
testcase('asekretoerrorthrownindefinecomesbackoutasitself', function (): void {
    $err = threw(SekretoError::class, fn() => new Sekreto([
        'plugins' => [hashicorp()],
        'providers' => [['kind' => 'hashicorp', 'addr' => 'http://127.0.0.1:1',
                         'token' => 't', 'kv' => 3]],
    ]));
    same('sekreto: hashicorp: unsupported kv version: 3', $err->getMessage());
});

// ...and any other error is not sekreto's to rewrite: it surfaces as the
// host reports it, naming the instance and the cause.
testcase('anyothererrorthrownindefineisthehostsreportofit', function (): void {
    $broken = providerplugin('broken', function (array $spec): Provider {
        throw new \TypeError('boom');
    });

    $err = threw(PluginError::class, fn() => new Sekreto([
        'plugins' => [$broken],
        'providers' => [['kind' => 'broken']],
    ]));
    same('plugin_define_failed', $err->code);
    same(true, str_contains($err->getMessage(), 'boom'));
});

testcase('acustomkindisoneproviderplugincall', function (): void {
    $shouty = providerplugin('shouty', fn(array $spec) => new class ($spec['values'] ?? []) implements Provider {
        /** @param array<string, string> $values */
        public function __construct(private array $values)
        {
        }

        public function lookup(string $name): ?string
        {
            return $this->values[strtoupper($name)] ?? null;
        }

        public function describe(): string
        {
            return 'shouty';
        }
    });

    $secrets = new Sekreto([
        'plugins' => [$shouty],
        'providers' => [['kind' => 'shouty', 'values' => ['API.TOKEN' => 'loud']]],
    ]);

    same('loud', $secrets->get('api.token'));
    same(['shouty' => 'live'], $secrets->host->list());
});

// A plugin that names a built-in kind replaces it: that is how a host
// substitutes an implementation, and never an accident, because the four
// names are documented.
testcase('apluginmayreplaceabuiltinkind', function (): void {
    $replaced = providerplugin('memory', fn(array $spec) => new class implements Provider {
        public function lookup(string $name): ?string
        {
            return 'replaced';
        }

        public function describe(): string
        {
            return 'memory';
        }
    });

    $secrets = new Sekreto([
        'plugins' => [$replaced],
        'providers' => [['kind' => 'memory', 'values' => ['API_TOKEN' => 'original']]],
    ]);

    same('replaced', $secrets->get('api.token'));
});

testcase('closetearsthechaindownandkeepsredaction', function (): void {
    $secrets = new Sekreto([
        'providers' => [['kind' => 'memory', 'values' => ['API_TOKEN' => 'tok01']]],
    ]);
    same('tok01', $secrets->get('api.token'));

    $secrets->close();

    same([], $secrets->host->list());
    same([], $secrets->stores());
    same(null, $secrets->try('api.token'));
    same('token=[redacted]', $secrets->redact('token=tok01'));
});

// --- the boundary --------------------------------------------------------

// The core requires no plugin: requiring src/Sekreto.php brings in the
// chain, the built-ins, the address checks and voxgig/plugin, and not one
// file under plugins/.
testcase('thecorerequiresnoplugin', function (): void {
    same(
        ['src/Addr.php', 'src/Plugin.php', 'src/Providers.php', 'src/Sekreto.php'],
        included('src/Sekreto.php')
    );

    // ...and it names none of them either. PHP erases nothing, so the
    // namespace is the second half of the boundary: CODE in the core that
    // never writes `Voxgig\Sekreto\Plugins` and never requires a path under
    // plugins/ cannot reach a plugin by accident. Comments are stripped
    // first - this file's own header documents the split, and prose about
    // the boundary is not a breach of it.
    foreach (glob(__DIR__ . '/../src/*.php') as $file) {
        $code = codeof($file);
        same(false, str_contains($code, 'Sekreto\\Plugins'), basename($file));
        same(false, str_contains($code, '/plugins/'), basename($file));

        // What the plugins hold, the core does not: no socket, no
        // signature, no child process. `file_get_contents` stays - reading
        // a local file is what makes a kind built in.
        foreach (['proc_open', 'stream_context_create', 'fsockopen', 'curl_init',
                  'hash_hmac', 'hash(', 'openssl_'] as $call) {
            same(false, str_contains($code, $call), basename($file) . ' uses ' . $call);
        }
    }
});

// ...and one plugin requires only itself, plus the core and the shared
// HTTP helper it speaks through. Requiring one kind must not drag in AWS
// request signing and the two child-process kinds behind it.
testcase('onepluginrequiresonlyitself', function (): void {
    same(
        ['plugins/hashicorp.php', 'plugins/httpjson.php', 'src/Addr.php',
         'src/Plugin.php', 'src/Providers.php', 'src/Sekreto.php'],
        included('plugins/hashicorp.php')
    );
});

// The full set is built on demand, and reaching it requires everything.
// The requires live inside `allplugins()` for exactly this reason: at file
// scope, naming the list would load all ten as a side effect.
testcase('thefullsetisbuiltondemand', function (): void {
    same(['plugins/plugins.php'], included('plugins/plugins.php'));

    $after = included('test/allplugins.php');
    foreach (['hashicorp', 'boru', 'aws', 'sigv4', 'gcpsecrets', 'azuresecrets',
              'onepassword', 'doppler', 'infisical', 'secretspec', 'httpjson',
              'runcmd'] as $mod) {
        same(true, in_array('plugins/' . $mod . '.php', $after, true), $mod);
    }
});

// A plugin file holds a FUNCTION that builds the definition, because a
// definition holds closures and PHP has no constant that can. Passing the
// function instead of calling it is the mistake that shape makes easy, so
// it is refused by name, saying what to do instead.
testcase('afunctionpassedasapluginisrefused', function (): void {
    $err = threw(SekretoError::class, fn() => new Sekreto([
        'plugins' => [hashicorp(...)],
        'providers' => [],
    ]));
    same(
        'sekreto: not a plugin definition: the function Voxgig\\Sekreto\\Plugins\\hashicorp'
        . ' - call it for the definition it holds',
        $err->getMessage()
    );

    // And anything else that is not a definition is refused too.
    $err = threw(SekretoError::class, fn() => new Sekreto([
        'plugins' => ['hashicorp'],
        'providers' => [],
    ]));
    same("sekreto: not a plugin definition: 'hashicorp'", $err->getMessage());
});

echo "\n$pass passed, $fail failed\n";
exit(0 === $fail ? 0 : 1);
