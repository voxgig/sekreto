<?php

/**
 * RUN: php test/minivault.php
 * RUN-SOME: php test/minivault.php awrittensecretcomesback
 *
 * The mini vault, from both sides: the store a chain reads, and the
 * programmatic API a plugin definition can publish beside it.
 *
 * The vault is not in spec/sekreto.json and cannot be until every port
 * ships the kind. The spec runs against all twenty-three of them, so an
 * entry naming `minivault` would fail the ports that have no such
 * provider. What the shared corpus would have carried is here instead,
 * plus the one thing it could not carry either way: a file written by
 * this port and read by another, pinned by test/fixture/*.skmv.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto\Test;

require_once __DIR__ . '/../src/Sekreto.php';
require_once __DIR__ . '/../plugins/minivault.php';

use Voxgig\Sekreto\Sekreto;
use Voxgig\Sekreto\SekretoError;

use function Voxgig\Sekreto\Plugins\createvault;
use function Voxgig\Sekreto\Plugins\mvjson;
use function Voxgig\Sekreto\Plugins\minivault;
use function Voxgig\Sekreto\Plugins\openvault;
use function Voxgig\Sekreto\Plugins\vaultof;

const MASTER = 'master-passphrase';

/**
 * The rounds every test here uses. The library default is 210000, which
 * is the point of PBKDF2 and the wrong thing to pay per assertion.
 */
const ROUNDS = 1000;

$only = $argv[1] ?? null;
$pass = 0;
$fail = 0;
$work = sys_get_temp_dir() . '/sekreto-minivault-' . bin2hex(random_bytes(6));
$count = 0;

mkdir($work, 0700, true);

function vaultpath(): string
{
    global $work, $count;
    $count++;

    return $work . '/vault' . $count . '.skmv';
}

function fresh(): \Voxgig\Sekreto\Plugins\MiniVault
{
    return createvault(['file' => vaultpath(), 'passphrase' => MASTER,
                        'iterations' => ROUNDS]);
}

function fixturedir(): string
{
    return __DIR__ . '/../../test/fixture';
}

/**
 * A committed vault, copied so that a test which writes cannot edit the
 * bytes the format contract is made of.
 */
function fixture(string $name): string
{
    $mine = vaultpath();
    copy(fixturedir() . '/' . $name, $mine);

    return $mine;
}

/**
 * EVERY committed vault, read off disk rather than listed here. A
 * hard-coded list is one more place to edit when a port lands, and the
 * edit that gets forgotten is the one that makes this suite stop checking
 * the port that just arrived.
 *
 * @return array<int, string>
 */
function fixtures(): array
{
    $out = array_map('basename', glob(fixturedir() . '/*.skmv'));
    sort($out);

    return $out;
}

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

function has(string $needle, string $haystack): void
{
    if (!str_contains($haystack, $needle)) {
        throw new \RuntimeException('want ' . json_encode($needle) . ' in '
                                    . json_encode($haystack));
    }
}

// --- the file --------------------------------------------------------

testcase('anewvaultholdsnothing', function (): void {
    $vault = fresh();

    same([], $vault->list());
    same('master', $vault->key());
    same(['key' => 'master', 'master' => true, 'write' => true, 'grants' => []],
         $vault->open());
});

testcase('awrittensecretcomesback', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');
    $vault->set('db.pass', 'hunter2');

    same('tok01', $vault->get('api.token'));
    same(['api.token', 'db.pass'], $vault->list());
    same(true, $vault->has('api.token'));
    same(false, $vault->has('nope'));
    same(null, $vault->get('nope'));

    $again = openvault(['file' => $vault->file(), 'passphrase' => MASTER]);
    same('tok01', $again->get('api.token'));
});

testcase('thefileisbinaryandnamesnothinginplaintext', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');

    $raw = (string) file_get_contents($vault->file());

    same('SKMV', substr($raw, 0, 4));
    // The key ids are plaintext and documented as such; a secret name is
    // not, and neither is a value.
    same(true, str_contains($raw, 'master'));
    same(false, str_contains($raw, 'api.token'));
    same(false, str_contains($raw, 'tok01'));
});

testcase('rewritinganamereplacesit', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'one');
    $vault->set('api.token', 'two');

    same('two', $vault->get('api.token'));
    same(['api.token'], $vault->list());
});

testcase('removedropsaname', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');
    $vault->remove('api.token');

    same([], $vault->list());
    same(null, $vault->get('api.token'));

    has('no such secret', threw(SekretoError::class,
                                fn() => $vault->remove('api.token'))->getMessage());
});

testcase('abadnameisrefused', function (): void {
    $vault = fresh();

    threw(SekretoError::class, fn() => $vault->get(''));
    threw(SekretoError::class, fn() => $vault->set('bad name', 'x'));
});

// --- the keys --------------------------------------------------------

testcase('arestrictedkeyreadsitsgrants', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');
    $vault->set('db.pass', 'hunter2');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase',
                   'names' => ['api.token'], 'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci',
                     'passphrase' => 'ci-phrase']);

    same(['api.token'], $ci->list());
    same('tok01', $ci->get('api.token'));
    // Not an error: the vault answers as the key that opened it, so a
    // name outside the grant is a miss.
    same(null, $ci->get('db.pass'));
    same(['key' => 'ci', 'master' => false, 'write' => false,
          'grants' => ['api.token']], $ci->open());
});

testcase('areadonlykeyrefusestowrite', function (): void {
    $vault = fresh();
    $vault->set('db.pass', 'hunter2');
    $vault->grant(['key' => 'ro', 'passphrase' => 'ro-phrase',
                   'names' => ['db.pass'], 'iterations' => ROUNDS]);
    $vault->grant(['key' => 'rw', 'passphrase' => 'rw-phrase', 'names' => ['db.pass'],
                   'write' => true, 'iterations' => ROUNDS]);

    $ro = openvault(['file' => $vault->file(), 'key' => 'ro',
                     'passphrase' => 'ro-phrase']);
    has('read-only', threw(SekretoError::class,
                           fn() => $ro->set('db.pass', 'nope'))->getMessage());

    $rw = openvault(['file' => $vault->file(), 'key' => 'rw',
                     'passphrase' => 'rw-phrase']);
    $rw->set('db.pass', 'changed');

    same('changed', $vault->get('db.pass'));
});

testcase('arestrictedkeycannotwriteanungrantedname', function (): void {
    $vault = fresh();
    $vault->set('db.pass', 'hunter2');
    $vault->grant(['key' => 'rw', 'passphrase' => 'rw-phrase', 'names' => ['db.pass'],
                   'write' => true, 'iterations' => ROUNDS]);

    $rw = openvault(['file' => $vault->file(), 'key' => 'rw',
                     'passphrase' => 'rw-phrase']);

    has('was not granted', threw(SekretoError::class,
                                 fn() => $rw->set('other.name', 'x'))->getMessage());
});

testcase('agrantednamethatdoesnotexistyet', function (): void {
    $vault = fresh();
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase',
                   'names' => ['later.name'], 'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci',
                     'passphrase' => 'ci-phrase']);

    same([], $ci->list());
    same(null, $ci->get('later.name'));

    $vault->set('later.name', 'here now');

    same('here now', $ci->get('later.name'));
    same(['later.name'], $ci->list());
});

testcase('themasterlistseverykey', function (): void {
    $vault = fresh();
    $vault->grant(['key' => 'ro', 'passphrase' => 'p1', 'names' => ['a.one'],
                   'iterations' => ROUNDS]);
    $vault->grant(['key' => 'rw', 'passphrase' => 'p2', 'names' => ['a.one', 'b.two'],
                   'write' => true, 'iterations' => ROUNDS]);

    same([
        ['key' => 'master', 'master' => true, 'write' => true, 'grants' => []],
        ['key' => 'ro', 'master' => false, 'write' => false, 'grants' => ['a.one']],
        ['key' => 'rw', 'master' => false, 'write' => true,
         'grants' => ['a.one', 'b.two']],
    ], $vault->keys());
});

testcase('themasteronlymethodsrefusearestrictedkey', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['a.one'],
                   'write' => true, 'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci',
                     'passphrase' => 'ci-phrase']);

    $calls = [
        fn() => $ci->keys(),
        fn() => $ci->remove('a.one'),
        fn() => $ci->rotate(),
        fn() => $ci->revoke('master'),
        fn() => $ci->grant(['key' => 'x', 'passphrase' => 'y', 'names' => []]),
    ];

    foreach ($calls as $call) {
        has('master key', threw(SekretoError::class, $call)->getMessage());
    }
});

testcase('arepeatedkeyidisrefused', function (): void {
    $vault = fresh();
    $vault->grant(['key' => 'ci', 'passphrase' => 'one', 'names' => [],
                   'iterations' => ROUNDS]);

    has('key already exists', threw(SekretoError::class, fn() => $vault->grant(
        ['key' => 'ci', 'passphrase' => 'two', 'names' => [], 'iterations' => ROUNDS]
    ))->getMessage());
});

testcase('revokedropsakey', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['a.one'],
                   'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci',
                     'passphrase' => 'ci-phrase']);
    same('x', $ci->get('a.one'));

    $vault->revoke('ci');

    has('no such key', threw(SekretoError::class, fn() => $ci->get('a.one'))->getMessage());
    has('cannot revoke itself',
        threw(SekretoError::class, fn() => $vault->revoke('master'))->getMessage());
});

testcase('rotatekeepsthesecrets', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');
    $vault->set('db.pass', 'hunter2');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase',
                   'names' => ['api.token'], 'iterations' => ROUNDS]);

    $vault->rotate();

    same(['api.token', 'db.pass'], $vault->list());
    same('tok01', $vault->get('api.token'));
    same('hunter2', $vault->get('db.pass'));
    same(['master'], array_map(fn(array $k) => $k['key'], $vault->keys()));

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci',
                     'passphrase' => 'ci-phrase']);
    threw(SekretoError::class, fn() => $ci->get('api.token'));
});

// --- refusals --------------------------------------------------------

testcase('awrongpassphraseandamissingfilerefuse', function (): void {
    global $work;
    $vault = fresh();
    $vault->set('a.one', 'x');

    $bad = openvault(['file' => $vault->file(), 'passphrase' => 'wrong']);
    has('wrong passphrase',
        threw(SekretoError::class, fn() => $bad->get('a.one'))->getMessage());

    $nokey = openvault(['file' => $vault->file(), 'key' => 'nope',
                        'passphrase' => MASTER]);
    threw(SekretoError::class, fn() => $nokey->get('a.one'));

    $missing = openvault(['file' => $work . '/nothing.skmv', 'passphrase' => MASTER]);
    has('no vault file',
        threw(SekretoError::class, fn() => $missing->get('a.one'))->getMessage());
});

testcase('adamagedfileisrefused', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    $raw = (string) file_get_contents($vault->file());

    $short = vaultpath();
    file_put_contents($short, substr($raw, 0, strlen($raw) - 10));
    has('truncated', threw(SekretoError::class, fn() => openvault(
        ['file' => $short, 'passphrase' => MASTER]
    )->get('a.one'))->getMessage());

    $trailing = vaultpath();
    file_put_contents($trailing, $raw . 'junk');
    has('trailing bytes', threw(SekretoError::class, fn() => openvault(
        ['file' => $trailing, 'passphrase' => MASTER]
    )->get('a.one'))->getMessage());

    $notvault = vaultpath();
    file_put_contents($notvault, 'NOPE' . substr($raw, 4));
    has('not a vault file', threw(SekretoError::class, fn() => openvault(
        ['file' => $notvault, 'passphrase' => MASTER]
    )->get('a.one'))->getMessage());
});

testcase('creatingoveranexistingvaultisrefused', function (): void {
    $vault = fresh();

    has('already exists', threw(SekretoError::class, fn() => createvault(
        ['file' => $vault->file(), 'passphrase' => MASTER, 'iterations' => ROUNDS]
    ))->getMessage());
});

testcase('avaultneedsafileandapassphrase', function (): void {
    threw(SekretoError::class, fn() => openvault(['file' => '', 'passphrase' => MASTER]));
    threw(SekretoError::class, fn() => openvault(['file' => vaultpath(), 'passphrase' => '']));
});

// A RING'S `grants` IS AN OBJECT, whatever is in it - and PHP is the one
// port that has to be told. `0` is a valid secret name, PHP turns the
// string key "0" into the integer key 0, and `json_encode` writes an
// array for any map whose keys run 0..n. A ring written that way is one
// PHP reads back perfectly and no other port can read at all, which no
// round trip inside this port would ever catch: the assertion is on the
// BYTES the ring encodes to.
testcase('aringencodesitsgrantsasanobject', function (): void {
    $grants = ['0' => 'AAAA', '1' => 'BBBB'];
    $ring = mvjson(['v' => 1, 'write' => false, 'grants' => $grants]);
    same('{"v":1,"write":false,"grants":{"0":"AAAA","1":"BBBB"}}', $ring);

    // ...and a meta record's `grants` is a LIST of names, which stays one.
    $meta = mvjson(['v' => 1, 'master' => false, 'write' => false, 'grants' => ['0', '1']]);
    same('{"v":1,"master":false,"write":false,"grants":["0","1"]}', $meta);

    // End to end: a grant on a numerically named secret reads back.
    $vault = fresh();
    $vault->set('0', 'zero');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-pass', 'names' => ['0'],
                   'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci', 'passphrase' => 'ci-pass']);
    same('zero', $ci->get('0'));
    same(['0'], $ci->list());
});

// An EMPTY key is no key, so it means `master`. It is not a contrived
// case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
// expands to the empty string rather than to nothing at all - and `??`
// answers for null alone.
testcase('anemptykeymeansthemasterkey', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');

    $opened = openvault(['file' => $vault->file(), 'key' => '', 'passphrase' => MASTER]);
    same('tok01', $opened->get('api.token'));
    same('master', $opened->open()['key']);
});

testcase('createmakesthefileonlywhenasked', function (): void {
    $path = vaultpath();

    $refuses = openvault(['file' => $path, 'passphrase' => MASTER, 'iterations' => ROUNDS]);
    threw(SekretoError::class, fn() => $refuses->list());
    same(false, file_exists($path));

    $makes = openvault(['file' => $path, 'passphrase' => MASTER,
                        'iterations' => ROUNDS, 'create' => true]);
    same([], $makes->list());
    same(true, file_exists($path));
});

testcase('akeyidlongerthantheformatallowsisrefused', function (): void {
    $vault = fresh();
    $long = str_repeat('k', 256);

    has('longer than 255', threw(SekretoError::class, fn() => $vault->grant(
        ['key' => $long, 'passphrase' => 'p', 'names' => [], 'iterations' => ROUNDS]
    ))->getMessage());
    same(['master'], array_map(fn(array $k) => $k['key'], $vault->keys()));
});

// --- the handle ------------------------------------------------------

testcase('theinfoacallergetscannotchangewhatthekeymaydo', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    $vault->grant(['key' => 'ro', 'passphrase' => 'ro-phrase', 'names' => ['a.one'],
                   'iterations' => ROUNDS]);

    $ro = openvault(['file' => $vault->file(), 'key' => 'ro',
                     'passphrase' => 'ro-phrase']);
    $info = $ro->open();
    $info['write'] = true;
    $info['grants'][] = 'b.two';

    has('read-only', threw(SekretoError::class,
                           fn() => $ro->set('a.one', 'nope'))->getMessage());
    same(['a.one'], $ro->open()['grants']);
});

testcase('arevokedkeystopsreadingfromacachedhandle', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['a.one'],
                   'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci',
                     'passphrase' => 'ci-phrase']);
    same('x', $ci->get('a.one'));

    $vault->revoke('ci');
    threw(SekretoError::class, fn() => $ci->get('a.one'));
});

testcase('aregrantedkeyiddoesnotkeeptheoldpassphraseworking', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    $vault->grant(['key' => 'ci', 'passphrase' => 'first', 'names' => ['a.one'],
                   'iterations' => ROUNDS]);

    $ci = openvault(['file' => $vault->file(), 'key' => 'ci', 'passphrase' => 'first']);
    same('x', $ci->get('a.one'));

    $vault->revoke('ci');
    $vault->grant(['key' => 'ci', 'passphrase' => 'second', 'names' => ['a.one'],
                   'iterations' => ROUNDS]);

    has('wrong passphrase',
        threw(SekretoError::class, fn() => $ci->get('a.one'))->getMessage());

    $freshci = openvault(['file' => $vault->file(), 'key' => 'ci',
                          'passphrase' => 'second']);
    same('x', $freshci->get('a.one'));
});

testcase('closeforgetsthederivedkeys', function (): void {
    $vault = fresh();
    $vault->set('a.one', 'x');
    same('x', $vault->get('a.one'));

    $vault->close();
    same('x', $vault->get('a.one'));
});

// --- the format, across ports ----------------------------------------

// EVERY COMMITTED VAULT, not only this port's. A suite that reads only
// the vault its own port wrote proves the reader agrees with the writer
// beside it - which a port whose serializer and parser share a mistake
// satisfies perfectly.
foreach (fixtures() as $name) {
    testcase('thecommittedfixturereads_' . str_replace(['-', '.'], '_', $name),
        function () use ($name): void {
            $file = fixture($name);

            $master = openvault(['file' => $file, 'passphrase' => 'fixture-master']);

            same(['api.token', 'db.pass', 'deep.nested.name'], $master->list());
            same('fixture-token', $master->get('api.token'));
            same('fixture-pass', $master->get('db.pass'));
            same('fixture-deep', $master->get('deep.nested.name'));

            same([
                ['key' => 'master', 'master' => true, 'write' => true, 'grants' => []],
                ['key' => 'reader', 'master' => false, 'write' => false,
                 'grants' => ['api.token']],
                ['key' => 'writer', 'master' => false, 'write' => true,
                 'grants' => ['db.pass']],
            ], $master->keys());

            $reader = openvault(['file' => $file, 'key' => 'reader',
                                 'passphrase' => 'fixture-reader']);
            same(['api.token'], $reader->list());
            same('fixture-token', $reader->get('api.token'));
            same(null, $reader->get('db.pass'));

            $writer = openvault(['file' => $file, 'key' => 'writer',
                                 'passphrase' => 'fixture-writer']);
            $writer->set('db.pass', 'written by this port');
            same('written by this port', $master->get('db.pass'));
        });
}

// --- the chain -------------------------------------------------------

testcase('avaultisonestoreinachain', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'from the vault');

    $secrets = new Sekreto([
        'plugins' => [minivault()],
        'providers' => [
            ['kind' => 'memory', 'values' => ['DB_PASS' => 'from memory']],
            ['kind' => 'minivault', 'file' => $vault->file(), 'passphrase' => MASTER],
        ],
    ]);

    same('from the vault', $secrets->get('api.token'));
    same('from memory', $secrets->get('db.pass'));
});

testcase('arestrictedkeyinachainfallsthrough', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'from the vault');
    $vault->set('db.pass', 'in the vault, not granted');
    $vault->grant(['key' => 'ci', 'passphrase' => 'ci-phrase',
                   'names' => ['api.token'], 'iterations' => ROUNDS]);

    $secrets = new Sekreto([
        'plugins' => [minivault()],
        'providers' => [
            ['kind' => 'minivault', 'file' => $vault->file(), 'vaultkey' => 'ci',
             'passphrase' => 'ci-phrase'],
            ['kind' => 'memory', 'values' => ['DB_PASS' => 'from memory']],
        ],
    ]);

    same('from the vault', $secrets->get('api.token'));
    same('from memory', $secrets->get('db.pass'));
});

testcase('thevaultbehindastoreisreachableasanapi', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');

    $secrets = new Sekreto([
        'plugins' => [minivault()],
        'providers' => [
            ['kind' => 'minivault', 'file' => $vault->file(), 'passphrase' => MASTER],
        ],
    ]);

    $api = vaultof($secrets);
    same(['api.token'], $api->list());

    $api->set('db.pass', 'written through the api');
    same('written through the api', $secrets->get('db.pass'));
});

testcase('anamedstoreisreachedbyname', function (): void {
    $vault = fresh();
    $vault->set('api.token', 'tok01');

    $secrets = new Sekreto([
        'plugins' => [minivault()],
        'providers' => [
            ['kind' => 'minivault', 'name' => 'app', 'file' => $vault->file(),
             'passphrase' => MASTER],
        ],
    ]);

    same(['api.token'], vaultof($secrets, 'app')->list());
    same(['api.token'], vaultof($secrets)->list());

    has('no minivault store named',
        threw(SekretoError::class, fn() => vaultof($secrets, 'minivault'))->getMessage());
});

testcase('achainwithnovaultsaysso', function (): void {
    $secrets = new Sekreto([
        'plugins' => [minivault()],
        'providers' => [['kind' => 'memory', 'values' => []]],
    ]);

    has('no minivault store',
        threw(SekretoError::class, fn() => vaultof($secrets))->getMessage());
});

testcase('achainmissingthefileisrefusedatconstruction', function (): void {
    has('a vault needs a file', threw(SekretoError::class, fn() => new Sekreto([
        'plugins' => [minivault()],
        'providers' => [['kind' => 'minivault', 'passphrase' => MASTER]],
    ]))->getMessage());

    has('a vault needs a passphrase', threw(SekretoError::class, fn() => new Sekreto([
        'plugins' => [minivault()],
        'providers' => [['kind' => 'minivault', 'file' => vaultpath()]],
    ]))->getMessage());
});

testcase('thefileisreachedatthefirstlookup', function (): void {
    $path = vaultpath();

    // No file, and construction still succeeds: the handle is lazy.
    $secrets = new Sekreto([
        'plugins' => [minivault()],
        'providers' => [['kind' => 'minivault', 'file' => $path,
                         'passphrase' => MASTER]],
    ]);

    has('no vault file',
        threw(SekretoError::class, fn() => $secrets->get('api.token'))->getMessage());
});

foreach (glob($work . '/*') as $leftover) {
    unlink($leftover);
}
rmdir($work);

echo "\n$pass passed, $fail failed\n";
exit(0 === $fail ? 0 : 1);
