<?php

/**
 * RUN: php test/run.php
 * RUN-SOME: php test/run.php envkey
 *
 * The sekreto conformance suite. Every port runs these same groups, from
 * the same spec/sekreto.json, through its own voxgig/omni runner.
 *
 * No third-party test framework: a failing omni check throws OmniError, so
 * any host framework (PHPUnit included) reports it as a failure. This
 * harness keeps `make test` dependency-free.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto\Test;

use Voxgig\Omni\Runner;
use Voxgig\Sekreto\Name;
use Voxgig\Sekreto\Sekreto;

use function Voxgig\Sekreto\parsedotenv;
use function Voxgig\Sekreto\redact;

require_once __DIR__ . '/../src/Sekreto.php';

// The conformance suite hands EVERY plugin to every chain it builds, which
// is exactly why it can never see a plugin that a consumer failed to pass
// in - test/plugins.php pins that half. `sigv4` lives with the aws plugin:
// it is the crypto edge, and only a program that names an AWS kind
// requires it.
require_once __DIR__ . '/../plugins/plugins.php';
require_once __DIR__ . '/../plugins/aws.php';

use function Voxgig\Sekreto\Plugins\allplugins;
use function Voxgig\Sekreto\Plugins\sigv4;

/** Find the shared spec directory by walking up from this file. */
function specfile(string $name): string
{
    $dir = __DIR__;
    for ($i = 0; $i < 8; $i++) {
        $cand = $dir . '/spec/' . $name;
        if (file_exists($cand)) {
            return $cand;
        }
        $dir = dirname($dir);
    }
    throw new \RuntimeException('sekreto: spec not found: ' . $name);
}

/** omni is a sibling checkout, not a published package (yet). */
function omnihome(): string
{
    $cands = [
        getenv('OMNI_HOME') ?: null,
        __DIR__ . '/../../../omni',
        __DIR__ . '/../../../../omni',
        '/workspace/omni',
        '/home/user/omni',
    ];

    foreach ($cands as $cand) {
        if (null !== $cand && file_exists($cand . '/spec/fib.json')) {
            return $cand;
        }
    }

    throw new \RuntimeException('sekreto: voxgig/omni not found - set OMNI_HOME');
}

require_once omnihome() . '/php/src/Runner.php';

/**
 * Build a Sekreto from the spec's declarative chain description.
 *
 * @param array<string, mixed> $spec
 */
function chainof(array $spec): Sekreto
{
    return new Sekreto([
        'plugins' => allplugins(),
        'providers' => $spec['chain'],
        'cache' => false,
    ]);
}

$only = $argv[1] ?? null;
$pass = 0;
$fail = 0;

/** Run one named test case, reporting pass or fail. */
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
        echo "FAIL - $name\n" . $err->getMessage() . "\n";
    }
}

$R = (Runner::makeRunner(specfile('sekreto.json')))('sekreto');
$spec = $R['spec'];
$runset = $R['runset'];
$runsetflags = $R['runsetflags'];

testcase(
    'validname',
    fn() => $runsetflags($spec['validname'], ['null' => false], fn($name) => Name::valid($name))
);
testcase(
    'envkey',
    fn() => $runset($spec['envkey'], fn($vin) => Name::envkey($vin['name'], $vin['prefix'] ?? null))
);
testcase('vaultref', fn() => $runset($spec['vaultref'], fn($name) => Name::vaultref($name)));
testcase(
    'flatname',
    fn() => $runset($spec['flatname'], fn($vin) => Name::flatname($vin['name'], $vin['sep']))
);
testcase(
    'awsparam',
    fn() => $runset($spec['awsparam'], fn($vin) => Name::awsparam($vin['name'], $vin['prefix'] ?? null))
);
testcase('parsedotenv', fn() => $runset($spec['parsedotenv'], fn($text) => parsedotenv($text)));
testcase('resolve', fn() => $runset($spec['resolve'], fn($vin) => chainof($vin)->get($vin['name'])));
testcase(
    'trysecret',
    fn() => $runset($spec['trysecret'], fn($vin) => chainof($vin)->try($vin['name']))
);
testcase('sources', fn() => $runset($spec['sources'], fn($vin) => chainof($vin)->sources()));
testcase('stores', fn() => $runset($spec['stores'], fn($vin) => chainof($vin)->stores()));
testcase(
    'getfrom',
    fn() => $runset($spec['getfrom'], fn($vin) => chainof($vin)->getfrom($vin['store'], $vin['name']))
);
testcase(
    'tryfrom',
    fn() => $runset($spec['tryfrom'], fn($vin) => chainof($vin)->tryfrom($vin['store'], $vin['name']))
);
testcase('sigv4', fn() => $runset($spec['sigv4'], fn($vin) => sigv4($vin)));
testcase(
    'redact',
    fn() => $runset($spec['redact'], fn($vin) => redact($vin['text'], $vin['values']))
);

echo "\n$pass passed, $fail failed\n";
exit(0 === $fail ? 0 : 1);
