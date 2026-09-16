# RUN: prove -Ilib -Iplugins -It t/
# RUN-SOME: perl -Ilib -Iplugins -It t/minivault.t
#
# THE MINI VAULT: a store this library owns outright, and the port's
# worked example of a plugin publishing an API beside its provider.
#
# Three things are pinned here. THE BEHAVIOUR: what a master key may do,
# what a restricted key may do, and what each is refused. THE FORMAT: the
# vaults committed under test/fixture are read byte for byte, so a change
# to the writer that this port's own reader would forgive is caught by the
# files every other port wrote. THE SEAM: a vault is one store in a chain,
# and `vaultof` reaches the API behind it.

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Path     qw(mkpath rmtree);
use File::Spec;
use Test::More tests => 38;

use PluginHome ();

BEGIN { PluginHome::pluginpath() }

use Voxgig::Sekreto ();
use Voxgig::Sekreto::Plugins::Minivault
  qw(createvault minivault openvault vaultof);

my $MASTER = 'master-pass';
my $READER = 'reader-pass';
my $WRITER = 'writer-pass';

# The fixtures are written with 1000 rounds and so is everything here: the
# library default of 210000 is the right cost for a real vault and the
# wrong one for a suite that opens a hundred of them.
my $ROUNDS = 1000;

my $MASTERKEY = Voxgig::Sekreto::Plugins::Minivault::MASTERKEY();

my $HERE = dirname( File::Spec->rel2abs(__FILE__) );
my $FIXTURES = File::Spec->catdir( $HERE, '..', '..', 'test', 'fixture' );

my $FIXTUREMASTER = 'fixture-master';
my $FIXTUREREADER = 'fixture-reader';
my $FIXTUREWRITER = 'fixture-writer';

my $WORK = File::Spec->catdir( File::Spec->tmpdir, 'sekreto-minivault-pl-' . $$ );
mkpath($WORK);
END { rmtree($WORK) if defined $WORK }

my $COUNT = 0;

sub vaultpath {
    $COUNT += 1;
    return File::Spec->catfile( $WORK, 'vault' . $COUNT . '.skmv' );
}

sub opts {
    my ( $file, $key, $passphrase, %more ) = @_;

    return {
        file       => $file,
        key        => $key,
        passphrase => defined $passphrase ? $passphrase : $MASTER,
        iterations => $ROUNDS,
        %more,
    };
}

sub fresh { return createvault( opts( vaultpath(), undef, $MASTER ) ) }

sub openas {
    my ( $file, $key, $passphrase ) = @_;
    return openvault( opts( $file, $key, $passphrase ) );
}

# The message from a call that must refuse, or a marker that says it did
# not - so a test that stops failing because the call started succeeding
# says so rather than passing.
sub refusal {
    my ($call) = @_;

    my $ok = eval { $call->(); 1 };
    return 'NO REFUSAL' if $ok;

    return "$@";
}

# A copy, because the committed bytes are the contract: a test that writes
# to one proves nothing about what the other ports wrote.
sub copyof {
    my ($name) = @_;

    my $to = File::Spec->catfile( $WORK, $name );

    open( my $from, '<', File::Spec->catfile( $FIXTURES, $name ) )
      or die "no fixture $name: $!";
    binmode($from);
    local $/ = undef;
    my $raw = <$from>;
    close($from);

    open( my $out, '>', $to ) or die "cannot write $to: $!";
    binmode($out);
    print {$out} $raw;
    close($out);

    return $to;
}

sub sizeof { return -s $_[0] }

subtest 'a new vault holds nothing and answers as its master key' => sub {
    plan tests => 6;

    my $vault = fresh();

    is_deeply( $vault->list, [], 'nothing in it' );
    is_deeply(
        $vault->open,
        { key => $MASTERKEY, master => 1, write => 1, grants => [] },
        'the master key'
    );
    is( $vault->key, $MASTERKEY, 'opened as master' );
    is( $vault->get('api.token'), undef, 'a miss' );
    is( $vault->has('api.token'), 0,     'and has says so' );

    # 0600 AT CREATION. A vault readable by everyone on the box for even a
    # moment is a vault that leaked.
    is( ( stat( $vault->file ) )[2] & oct('777'), oct('600'), 'owner only' );
};

subtest 'a written secret comes back and a new handle reads it' => sub {
    plan tests => 5;

    my $vault = fresh();
    $vault->set( 'api.token',        'tok01' );
    $vault->set( 'deep.nested.name', 'deep01' );

    is( $vault->get('api.token'), 'tok01', 'the value' );
    is( $vault->has('api.token'), 1,       'and has says so' );
    is_deeply( $vault->list, [ 'api.token', 'deep.nested.name' ], 'both names' );

    # A SECOND HANDLE, from the file alone: nothing here is cached into
    # the answer.
    my $again = openas( $vault->file, undef, $MASTER );
    is( $again->get('api.token'),        'tok01',  'read from the file' );
    is( $again->get('deep.nested.name'), 'deep01', 'and the deep name too' );
};

subtest 'the file is binary and names nothing in plaintext' => sub {
    plan tests => 5;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );

    open( my $handle, '<', $vault->file ) or die $!;
    binmode($handle);
    local $/ = undef;
    my $raw = <$handle>;
    close($handle);

    is( substr( $raw, 0, 4 ), 'SKMV', 'the magic' );
    unlike( $raw, qr/api\.token/, 'no name' );
    unlike( $raw, qr/tok01/,      'no value' );
    unlike( $raw, qr/\Q$MASTER\E/, 'no passphrase' );

    # The key id IS in the file: a reader has to find its own record
    # before it can try a passphrase against it.
    like( $raw, qr/\Q$MASTERKEY\E/, 'the key id, in the clear' );
};

subtest 'rewriting a name replaces it rather than adding one' => sub {
    plan tests => 2;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'api.token', 'tok02' );

    is( $vault->get('api.token'), 'tok02', 'the new value' );
    is_deeply( $vault->list, ['api.token'], 'one entry' );
};

subtest 'remove drops a name and refuses one that is not there' => sub {
    plan tests => 3;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->remove('api.token');

    is_deeply( $vault->list, ['db.pass'], 'the rest' );
    is( $vault->get('api.token'), undef, 'gone' );
    is(
        refusal( sub { $vault->remove('api.token') } ),
        'sekreto: minivault: no such secret: api.token',
        'and removing it again refuses'
    );
};

subtest 'a name the library refuses is refused here too' => sub {
    plan tests => 11;

    my $vault = fresh();

    for my $bad ( '', 'API.TOKEN', 'api..token', '.api', 'api token' ) {
        is( refusal( sub { $vault->get($bad) } ),
            'sekreto: invalid name: ' . $bad, 'get ' . $bad );
        is( refusal( sub { $vault->set( $bad, 'v' ) } ),
            'sekreto: invalid name: ' . $bad, 'set ' . $bad );
    }

    is(
        refusal( sub { $vault->set( 'api.token', undef ) } ),
        'sekreto: minivault: a secret value must be text: api.token',
        'a value must be text'
    );
};

# --- restricted keys ------------------------------------------------------

subtest 'a restricted key reads its grants and misses on the rest' => sub {
    plan tests => 5;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    my $ci = openas( $vault->file, 'ci', $READER );

    is_deeply(
        $ci->open,
        { key => 'ci', master => 0, write => 0, grants => ['api.token'] },
        'what it may do'
    );
    is_deeply( $ci->list, ['api.token'], 'what it can see' );
    is( $ci->get('api.token'), 'tok01', 'and read' );

    # NOT AN ERROR, A MISS: the vault answers as the key that opened it,
    # so a name this key cannot read is a name this store does not hold
    # for this caller.
    is( $ci->get('db.pass'), undef, 'outside the grant is a miss' );
    is( $ci->has('db.pass'), 0,     'and has says so' );
};

subtest 'a read-only key refuses to write and a write key updates' => sub {
    plan tests => 4;

    my $vault = fresh();
    $vault->set( 'db.pass', 'pw01' );
    $vault->grant( { key => 'ro', passphrase => $READER, names => ['db.pass'] } );
    $vault->grant(
        { key => 'rw', passphrase => $WRITER, names => ['db.pass'], write => 1 } );

    my $ro = openas( $vault->file, 'ro', $READER );
    is(
        refusal( sub { $ro->set( 'db.pass', 'pw02' ) } ),
        'sekreto: minivault: key ro is read-only',
        'read-only refuses'
    );

    my $rw = openas( $vault->file, 'rw', $WRITER );
    $rw->set( 'db.pass', 'pw02' );

    is( $rw->get('db.pass'),    'pw02', 'the write key sees its write' );
    is( $vault->get('db.pass'), 'pw02', 'and so does the master' );
    is( $rw->open->{write},     1,      'it says it may write' );
};

subtest 'a restricted key cannot write a name it was not granted' => sub {
    plan tests => 3;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->grant(
        { key => 'rw', passphrase => $WRITER, names => ['db.pass'], write => 1 } );

    my $rw = openas( $vault->file, 'rw', $WRITER );

    is(
        refusal( sub { $rw->set( 'api.token', 'tok02' ) } ),
        'sekreto: minivault: key rw was not granted api.token',
        'outside the grant'
    );

    # ...and it cannot grow the vault either: a new name needs the name
    # key, which only a master holds.
    is(
        refusal( sub { $rw->set( 'new.name', 'v' ) } ),
        'sekreto: minivault: key rw was not granted new.name',
        'and cannot grow it'
    );

    is( $vault->get('api.token'), 'tok01', 'the value is untouched' );
};

subtest 'a granted name that does not exist yet reads once a master writes it' =>
  sub {
    plan tests => 5;

    my $vault = fresh();
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    my $ci = openas( $vault->file, 'ci', $READER );
    is( $ci->get('api.token'), undef, 'not there yet' );

    # Granted but not yet written, so `list` does not offer it.
    is_deeply( $ci->list, [], 'and list does not offer it' );
    is_deeply( $ci->open->{grants}, ['api.token'], 'though the grant is there' );

    $vault->set( 'api.token', 'tok01' );

    is( $ci->get('api.token'), 'tok01', 'now it reads' );
    is_deeply( $ci->list, ['api.token'], 'and lists' );
  };

subtest 'the master lists every key and what it may do' => sub {
    plan tests => 1;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );
    $vault->grant(
        {
            key        => 'rw',
            passphrase => $WRITER,
            names      => [ 'db.pass', 'api.token' ],
            write      => 1
        }
    );

    is_deeply(
        $vault->keys,
        [
            { key => $MASTERKEY, master => 1, write => 1, grants => [] },
            { key => 'ci', master => 0, write => 0, grants => ['api.token'] },
            {
                key    => 'rw',
                master => 0,
                write  => 1,
                grants => [ 'api.token', 'db.pass' ]
            },
        ],
        'every key, with what it may do'
    );
};

subtest 'the master-only methods refuse a restricted key' => sub {
    plan tests => 6;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->grant(
        {
            key        => 'ci',
            passphrase => $READER,
            names      => [ 'api.token', 'new.name' ],
            write      => 1
        }
    );

    my $ci = openas( $vault->file, 'ci', $READER );
    my $restricted = ' needs a master key, and ci is restricted';

    is( refusal( sub { $ci->remove('api.token') } ),
        'sekreto: minivault: removing a secret' . $restricted, 'remove' );
    is( refusal( sub { $ci->keys } ),
        'sekreto: minivault: listing the keys' . $restricted, 'keys' );
    is(
        refusal( sub { $ci->grant( { key => 'x', passphrase => 'p' } ) } ),
        'sekreto: minivault: granting a key' . $restricted,
        'grant'
    );
    is( refusal( sub { $ci->revoke('x') } ),
        'sekreto: minivault: revoking a key' . $restricted, 'revoke' );
    is( refusal( sub { $ci->rotate } ),
        'sekreto: minivault: rotating the vault' . $restricted, 'rotate' );

    # A NEW NAME NEEDS THE NAME KEY, which only a master holds - so a
    # write key granted a name the vault does not hold yet updates nothing
    # and cannot grow the vault either.
    is(
        refusal( sub { $ci->set( 'new.name', 'v' ) } ),
        'sekreto: minivault: creating the secret new.name' . $restricted,
        'creating a name'
    );
};

subtest 'a repeated key id is refused rather than overwriting one' => sub {
    plan tests => 4;

    my $vault = fresh();
    $vault->grant( { key => 'ci', passphrase => $READER, names => [] } );

    is(
        refusal( sub { $vault->grant( { key => 'ci', passphrase => $WRITER } ) } ),
        'sekreto: minivault: key already exists: ci',
        'a granted id'
    );
    is(
        refusal(
            sub { $vault->grant( { key => $MASTERKEY, passphrase => $WRITER } ) }
        ),
        'sekreto: minivault: key already exists: ' . $MASTERKEY,
        'and the master id'
    );
    is(
        refusal( sub { $vault->grant( { passphrase => $WRITER } ) } ),
        'sekreto: minivault: a grant needs a key id',
        'a grant needs an id'
    );
    is(
        refusal( sub { $vault->grant( { key => 'x' } ) } ),
        'sekreto: minivault: a grant needs a passphrase',
        'and a passphrase'
    );
};

# A ring with no `grants` is a MASTER's ring in every port's reader, so a
# key granted nothing has to write the empty map rather than leave the
# field out - otherwise the smaller file is a key that reads the whole
# vault. The size is the evidence: the field is inside the sealed ring,
# where nothing else can see it.
subtest 'a key granted nothing still writes a grants map' => sub {
    plan tests => 3;

    my $vault = fresh();
    $vault->grant( { key => 'ci', passphrase => $READER, names => [] } );

    my $none = openas( $vault->file, 'ci', $READER );

    is_deeply(
        $none->open,
        { key => 'ci', master => 0, write => 0, grants => [] },
        'granted nothing, and no master'
    );
    is_deeply( $none->list, [], 'and it sees nothing' );
    is( sizeof( $vault->file ), 401, 'the empty map is in the file' );
};

subtest 'revoke drops a key and a key cannot revoke itself' => sub {
    plan tests => 4;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );
    $vault->revoke('ci');

    is_deeply( [ map { $_->{key} } @{ $vault->keys } ],
        [$MASTERKEY], 'only the master is left' );
    is(
        refusal( sub { openas( $vault->file, 'ci', $READER )->list } ),
        'sekreto: minivault: no such key: ci',
        'and the revoked key cannot open'
    );
    is( refusal( sub { $vault->revoke('gone') } ),
        'sekreto: minivault: no such key: gone', 'an unknown key' );
    is(
        refusal( sub { $vault->revoke($MASTERKEY) } ),
        'sekreto: minivault: a key cannot revoke itself: ' . $MASTERKEY,
        'and itself'
    );
};

subtest 'rotate keeps the secrets and drops every other key' => sub {
    plan tests => 5;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    $vault->rotate;

    is_deeply( $vault->list, [ 'api.token', 'db.pass' ], 'the names survive' );
    is( $vault->get('api.token'), 'tok01', 'and the values' );
    is_deeply( [ map { $_->{key} } @{ $vault->keys } ],
        [$MASTERKEY], 'every other key is gone' );

    # The same passphrase still opens it, from a fresh handle.
    my $again = openas( $vault->file, undef, $MASTER );
    is( $again->get('db.pass'), 'pw01', 'a fresh handle reads it' );

    # ...and the revoked key's derived keys are gone with the root.
    is(
        refusal( sub { openas( $vault->file, 'ci', $READER )->list } ),
        'sekreto: minivault: no such key: ci',
        'the old grant is unreachable'
    );
};

# --- refusals --------------------------------------------------------------

subtest 'a wrong passphrase an unknown key and a missing file all refuse' =>
  sub {
    plan tests => 3;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );

    is(
        refusal( sub { openas( $vault->file, undef, 'wrong' )->list } ),
        'sekreto: minivault: wrong passphrase for key '
          . $MASTERKEY
          . ', or a damaged vault',
        'a wrong passphrase'
    );
    is(
        refusal( sub { openas( $vault->file, 'nobody', $MASTER )->list } ),
        'sekreto: minivault: no such key: nobody',
        'an unknown key'
    );

    my $gone = File::Spec->catfile( $WORK, 'gone.skmv' );
    is(
        refusal( sub { openas( $gone, undef, $MASTER )->list } ),
        'sekreto: minivault: no vault file: ' . $gone,
        'and a missing file'
    );
  };

subtest 'a damaged file is refused rather than read as a short one' => sub {
    plan tests => 6;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );

    open( my $handle, '<', $vault->file ) or die $!;
    binmode($handle);
    local $/ = undef;
    my $raw = <$handle>;
    close($handle);

    my $written = sub {
        my ($bytes) = @_;
        my $path = vaultpath();
        open( my $out, '>', $path ) or die $!;
        binmode($out);
        print {$out} $bytes;
        close($out);
        return openas( $path, undef, $MASTER );
    };

    is(
        refusal( sub { $written->( 'nope' . substr( $raw, 4 ) )->list } ),
        'sekreto: minivault: not a vault file',
        'the wrong magic'
    );
    is(
        refusal(
            sub {
                $written->(
                    substr( $raw, 0, 4 ) . chr(9) . substr( $raw, 5 ) )->list;
            }
        ),
        'sekreto: minivault: unsupported format version: 9',
        'a version from the future'
    );
    is(
        refusal(
            sub {
                $written->(
                    substr( $raw, 0, 5 ) . chr(9) . substr( $raw, 6 ) )->list;
            }
        ),
        'sekreto: minivault: unsupported kdf or cipher: 9/1',
        'an unknown kdf'
    );
    is(
        refusal( sub { $written->( substr( $raw, 0, length($raw) - 1 ) )->list } ),
        'sekreto: minivault: the vault file is truncated',
        'a truncated file'
    );
    is(
        refusal( sub { $written->( $raw . chr(0) )->list } ),
        'sekreto: minivault: the vault file has trailing bytes',
        'and a long one'
    );

    # A FLIPPED BYTE IN A SEALED BLOB is what the tag is for: the
    # ciphertext still parses and the vault still refuses it.
    my $damaged = $raw;
    substr( $damaged, -1, 1 ) =
      chr( ord( substr( $damaged, -1, 1 ) ) ^ 0xff );

    is(
        refusal( sub { $written->($damaged)->get('api.token') } ),
        'sekreto: minivault: the value of api.token is damaged',
        'a flipped byte'
    );
};

subtest 'creating over an existing vault is refused' => sub {
    plan tests => 2;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );

    is(
        refusal( sub { createvault( opts( $vault->file, undef, $MASTER ) ) } ),
        'sekreto: minivault: vault file already exists: ' . $vault->file,
        'it refuses'
    );

    # ...and the vault it refused to replace is untouched.
    is( openas( $vault->file, undef, $MASTER )->get('api.token'),
        'tok01', 'and the secrets are still there' );
};

subtest 'a vault needs a file and a passphrase' => sub {
    plan tests => 6;

    is( refusal( sub { openvault( { passphrase => $MASTER } ) } ),
        'sekreto: minivault: a vault needs a file', 'no file' );
    is(
        refusal( sub { openvault( { file => '', passphrase => $MASTER } ) } ),
        'sekreto: minivault: a vault needs a file',
        'an empty file'
    );
    is( refusal( sub { openvault( { file => 'x.skmv' } ) } ),
        'sekreto: minivault: a vault needs a passphrase', 'no passphrase' );
    is(
        refusal( sub { openvault( { file => 'x.skmv', passphrase => '' } ) } ),
        'sekreto: minivault: a vault needs a passphrase',
        'an empty passphrase'
    );
    is( refusal( sub { createvault( { passphrase => $MASTER } ) } ),
        'sekreto: minivault: a vault needs a file', 'and create wants a file' );
    is( refusal( sub { createvault( { file => 'x.skmv' } ) } ),
        'sekreto: minivault: a vault needs a passphrase',
        'and a passphrase' );
};

# AN EMPTY KEY IS NO KEY, so it means `master`. A CLI reaches here with
# SEKRETO_VAULT_KEY set and empty, which is what an unset shell variable
# expands to.
subtest 'an empty key means the master key' => sub {
    plan tests => 3;

    my $vault = createvault( opts( vaultpath(), '', $MASTER ) );
    $vault->set( 'api.token', 'tok01' );

    is( $vault->key, $MASTERKEY, 'created as master' );
    is( openas( $vault->file, '', $MASTER )->get('api.token'),
        'tok01', 'an empty key opens it' );
    is( openas( $vault->file, undef, $MASTER )->get('api.token'),
        'tok01', 'and so does no key at all' );
};

subtest 'create makes the file and only when asked' => sub {
    plan tests => 4;

    my $path = vaultpath();

    # Without `create`, a missing vault is a broken deployment rather than
    # an empty store: answering a miss would send the chain on to a weaker
    # source.
    is(
        refusal( sub { openas( $path, undef, $MASTER )->list } ),
        'sekreto: minivault: no vault file: ' . $path,
        'a missing vault refuses'
    );
    ok( !-e $path, 'and nothing was written' );

    my $made = openvault( opts( $path, undef, $MASTER, create => 1 ) );
    $made->set( 'api.token', 'tok01' );

    ok( -e $path, 'create made it' );
    is( openas( $path, undef, $MASTER )->get('api.token'),
        'tok01', 'and it holds the secret' );
};

# A length is written in ONE byte, so a longer id would wrap it and every
# field after it would shift. Checked where an id is ACCEPTED, so the
# refusal names the id rather than the file.
subtest 'a key id longer than the format allows is refused' => sub {
    plan tests => 3;

    my $vault = fresh();
    my $long  = 'k' x 256;
    my $why =
        'sekreto: minivault: key id is longer than 255 bytes: '
      . substr( $long, 0, 32 ) . '...';

    is( refusal( sub { $vault->grant( { key => $long, passphrase => $READER } ) } ),
        $why, 'granting one' );
    is( refusal( sub { openvault( opts( vaultpath(), $long, $MASTER ) ) } ),
        $why, 'and opening as one' );

    # 255 bytes is the largest the format can record, and it works.
    my $fits = 'k' x 255;
    $vault->grant( { key => $fits, passphrase => $READER, names => [] } );
    is_deeply( [ map { $_->{key} } @{ $vault->keys } ],
        [ $MASTERKEY, $fits ], 'and 255 fits' );
};

subtest 'the key information a caller gets cannot change what the key may do' =>
  sub {
    plan tests => 2;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    my $ci   = openas( $vault->file, 'ci', $READER );
    my $info = $ci->open;
    $info->{write} = 1;
    push @{ $info->{grants} }, 'db.pass';

    is_deeply(
        $ci->open,
        { key => 'ci', master => 0, write => 0, grants => ['api.token'] },
        'the vault is unchanged'
    );
    is(
        refusal( sub { $ci->set( 'api.token', 'tok02' ) } ),
        'sekreto: minivault: key ci is read-only',
        'and it still refuses'
    );
  };

subtest 'a revoked key stops reading even from a handle that already read' =>
  sub {
    plan tests => 2;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    my $ci = openas( $vault->file, 'ci', $READER );
    is( $ci->get('api.token'), 'tok01', 'it reads' );

    $vault->revoke('ci');

    # THE FILE IS THE AUTHORITY, checked on every call: a handle that
    # answered from what it derived would keep reading a key the master
    # has taken away.
    is(
        refusal( sub { $ci->get('api.token') } ),
        'sekreto: minivault: no such key: ci',
        'and stops the moment it is revoked'
    );
  };

subtest 'a re-granted key id does not keep the old passphrase working' => sub {
    plan tests => 4;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    my $ci = openas( $vault->file, 'ci', $READER );
    is( $ci->get('api.token'), 'tok01', 'it reads' );

    $vault->revoke('ci');
    $vault->grant( { key => 'ci', passphrase => $WRITER, names => ['db.pass'] } );

    # The id is the same and the RING IS NOT, which is what the handle
    # notices: a key re-granted under another passphrase is a different
    # key wearing the id.
    is(
        refusal( sub { $ci->get('api.token') } ),
        'sekreto: minivault: wrong passphrase for key ci, or a damaged vault',
        'the old handle is refused'
    );

    my $new = openas( $vault->file, 'ci', $WRITER );
    is_deeply( $new->list, ['db.pass'], 'the new key reads its own grant' );
    is( $new->get('api.token'), undef, 'and not the old one' );
};

subtest 'close forgets the derived keys and the next call opens again' => sub {
    plan tests => 1;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );

    $vault->close;

    is( $vault->get('api.token'), 'tok01', 'it opens again' );
};

# TWO HANDLES ON ONE FILE, IN SEQUENCE, and this port carries no lock.
#
# Every other port's suite has a concurrent version of this. Perl's
# interpreter threads COPY rather than share: a `threads->create` hands
# the child its own copy of every variable, a lock table included, so a
# table of locks here would serialize nothing - and `threads::shared`
# cannot lock a hash element, which is what a per-path table is made of.
# Perl's own documentation discourages ithreads, and without them there is
# no second thread of execution to interleave with, exactly as in
# typescript, javascript, php, lua and ocaml.
#
# So what is pinned is what this port does guarantee: two handles writing
# one after another both land, because each reads the file again.
subtest 'two handles writing in turn both land' => sub {
    plan tests => 1;

    my $vault = fresh();
    my $one   = openas( $vault->file, undef, $MASTER );
    my $two   = openas( $vault->file, undef, $MASTER );

    for my $at ( 0 .. 19 ) {
        $one->set( 'one.n' . $at, 'v' . $at );
        $two->set( 'two.n' . $at, 'v' . $at );
    }

    my @want = sort( ( map { 'one.n' . $_ } 0 .. 19 ),
        ( map { 'two.n' . $_ } 0 .. 19 ) );

    is_deeply( openas( $vault->file, undef, $MASTER )->list,
        \@want, 'nothing is lost' );
};

# A NON-ASCII PASSPHRASE OR VALUE IS UTF-8 ON DISK, or this port writes
# vaults nobody else can open.
#
# THE VAULT TAKES TEXT, and text in perl is characters. The same string
# lives as Latin-1 bytes or as UTF-8 depending on what has happened to it,
# and `utf8::upgrade` moves it between the two without changing it - so a
# conversion that read `utf8::is_utf8` would hash one passphrase two ways.
# That is what these first two cases pin.
#
# The other side of the contract is the boundary: a scalar that is already
# UTF-8 bytes, which is what `%ENV` hands back, is decoded before it gets
# here, and `cli/sekreto-cli.pl` is where that happens.
subtest 'a non-ascii passphrase and value are utf-8 on disk' => sub {
    plan tests => 5;

    my $phrase = "p\x{e4}ssw\x{f6}rd";
    my $value  = "v\x{e4}lue-\x{fc}";

    my $file = vaultpath();
    my $made = createvault(
        { file => $file, passphrase => $phrase, iterations => $ROUNDS } );
    $made->set( 'api.token', $value );

    is( $made->get('api.token'), $value, 'it round trips' );

    # THE SAME STRING, held the other way. `upgrade` changes the internal
    # representation and nothing else, so it must be the same passphrase.
    my $upgraded = $phrase;
    utf8::upgrade($upgraded);
    is( openvault( { file => $file, passphrase => $upgraded } )->get('api.token'),
        $value, 'and the upgraded form is the same passphrase' );

    # ...and so is the downgraded one, from the other direction.
    my $downgraded = $upgraded;
    utf8::downgrade($downgraded);
    is( openvault( { file => $file, passphrase => $downgraded } )->get('api.token'),
        $value, 'and so is the downgraded form' );

    # The value comes back as characters, as JSON::PP hands a provider its
    # values, rather than as the bytes the file holds.
    ok( utf8::is_utf8( $made->get('api.token') ), 'and comes back decoded' );

    # THE BOUNDARY, as the CLI crosses it: UTF-8 bytes, decoded, are the
    # same passphrase. Undecoded they are a different one, which is why the
    # CLI decodes.
    my $bytes = $phrase;
    utf8::encode($bytes);
    utf8::decode($bytes);

    is( openvault( { file => $file, passphrase => $bytes } )->get('api.token'),
        $value, 'and utf-8 bytes decoded at the boundary are too' );
};

# --- the committed format --------------------------------------------------

# EVERY FIXTURE IN THE DIRECTORY, not a list: a port joins by adding its
# file, and this suite reads the new one without being edited.
subtest 'every committed fixture reads' => sub {
    opendir( my $dir, $FIXTURES ) or die "no fixture directory: $!";
    my @names = sort grep { m{\.skmv\z} } readdir($dir);
    closedir($dir);

    plan tests => 1 + 9 * scalar @names;

    cmp_ok( scalar @names, '>', 1, 'more than one port wrote one' );

    for my $name (@names) {
        my $file = copyof($name);

        my $master = openas( $file, undef, $FIXTUREMASTER );
        is_deeply( $master->list,
            [ 'api.token', 'db.pass', 'deep.nested.name' ], $name . ': names' );
        is( $master->get('api.token'), 'fixture-token', $name . ': token' );
        is( $master->get('db.pass'),   'fixture-pass',  $name . ': pass' );
        is( $master->get('deep.nested.name'),
            'fixture-deep', $name . ': deep' );

        is_deeply(
            $master->keys,
            [
                { key => 'master', master => 1, write => 1, grants => [] },
                {
                    key    => 'reader',
                    master => 0,
                    write  => 0,
                    grants => ['api.token']
                },
                {
                    key    => 'writer',
                    master => 0,
                    write  => 1,
                    grants => ['db.pass']
                },
            ],
            $name . ': keys'
        );

        my $reader = openas( $file, 'reader', $FIXTUREREADER );
        is_deeply( $reader->list, ['api.token'], $name . ': the reader' );
        is( $reader->get('db.pass'), undef, $name . ': and no more' );
        is(
            refusal( sub { $reader->set( 'api.token', 'x' ) } ),
            'sekreto: minivault: key reader is read-only',
            $name . ': read-only'
        );

        my $writer = openas( $file, 'writer', $FIXTUREWRITER );
        $writer->set( 'db.pass', 'changed' );
        is( $master->get('db.pass'), 'changed', $name . ': the writer wrote' );
    }
};

# --- the seam --------------------------------------------------------------

sub vaultspec {
    my ( $file, $key, $passphrase, %more ) = @_;

    return {
        kind       => 'minivault',
        file       => $file,
        vaultkey   => $key,
        passphrase => defined $passphrase ? $passphrase : $MASTER,
        iterations => $ROUNDS,
        %more,
    };
}

sub chainof {
    my ($providers) = @_;
    return Voxgig::Sekreto->new(
        { plugins => [ minivault() ], providers => $providers } );
}

subtest 'a vault is one store in a chain' => sub {
    plan tests => 4;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );

    my $secrets = chainof( [ vaultspec( $vault->file ) ] );

    is_deeply( $secrets->stores, ['minivault'], 'one store' );
    is_deeply( $secrets->sources, [ 'minivault:' . $vault->file ], 'and it says so' );
    is( $secrets->get('api.token'), 'tok01', 'the chain reads' );
    is( $secrets->has('api.token'), 1,       'and has says so' );
};

subtest 'a restricted key in a chain falls through on what it cannot read' =>
  sub {
    plan tests => 2;

    my $vault = fresh();
    $vault->set( 'api.token', 'tok01' );
    $vault->set( 'db.pass',   'pw01' );
    $vault->grant(
        { key => 'ci', passphrase => $READER, names => ['api.token'] } );

    my $secrets = chainof(
        [
            vaultspec( $vault->file, 'ci', $READER ),
            { kind => 'memory', values => { DB_PASS => 'fallback' } },
        ]
    );

    is( $secrets->get('api.token'), 'tok01', 'what it was granted' );

    # The vault holds `db.pass` and this key cannot read it, so the chain
    # carries on rather than failing.
    is( $secrets->get('db.pass'), 'fallback', 'and the chain carries on' );
  };

subtest 'the vault behind a store is reachable as an api' => sub {
    plan tests => 3;

    my $vault   = fresh();
    my $secrets = chainof( [ vaultspec( $vault->file ) ] );

    my $api = vaultof($secrets);
    $api->set( 'api.token', 'written-through-the-api' );

    is( $secrets->get('api.token'),
        'written-through-the-api', 'the chain reads what the api wrote' );
    is_deeply( $api->list, ['api.token'], 'and the api lists it' );
    is( $api->file, $vault->file, 'it is the same file' );
};

subtest 'a named store is reached by name and the alias by itself' => sub {
    plan tests => 3;

    my $one = fresh();
    $one->set( 'api.token', 'one' );
    my $two = fresh();
    $two->set( 'api.token', 'two' );

    my $secrets = chainof(
        [
            vaultspec( $one->file, undef, $MASTER, name => 'first' ),
            vaultspec( $two->file, undef, $MASTER, name => 'second' ),
        ]
    );

    is( vaultof( $secrets, 'first' )->get('api.token'),  'one', 'the first' );
    is( vaultof( $secrets, 'second' )->get('api.token'), 'two', 'the second' );

    # A NAMED STORE MUST EXIST, and the alias must not stand in for it:
    # `exports` falls back to the alias when the exact ref misses.
    is(
        refusal( sub { vaultof( $secrets, 'third' ) } ),
        'sekreto: minivault: no minivault store named third in this chain',
        'and a name that is not there refuses'
    );
};

subtest 'a chain that has no vault says so' => sub {
    plan tests => 1;

    my $secrets = chainof( [ { kind => 'memory', values => {} } ] );

    is(
        refusal( sub { vaultof($secrets) } ),
        'sekreto: minivault: no minivault store in this chain',
        'it says so'
    );
};

subtest 'a chain missing the file or the passphrase is refused at construction'
  => sub {
    plan tests => 2;

    is(
        refusal( sub { chainof( [ vaultspec('') ] ) } ),
        'sekreto: minivault: a vault needs a file',
        'no file'
    );
    is(
        refusal( sub { chainof( [ vaultspec( 'x.skmv', undef, '' ) ] ) } ),
        'sekreto: minivault: a vault needs a passphrase',
        'and no passphrase'
    );
  };

# The handle is LAZY: a chain is built without touching the disk, so a
# vault that is not there yet is a failed lookup rather than a failed
# startup.
subtest 'the file is reached at the first lookup never at construction' => sub {
    plan tests => 2;

    my $path    = vaultpath();
    my $secrets = chainof( [ vaultspec($path) ] );

    is_deeply( $secrets->sources, [ 'minivault:' . $path ], 'it built' );
    is(
        refusal( sub { $secrets->get('api.token') } ),
        'sekreto: minivault: no vault file: ' . $path,
        'and the file is reached at the lookup'
    );
};

# CryptX IS LOADED AT THE FIRST SEAL, NEVER AT COMPILE TIME.
#
# `allplugins` loads every kind whether or not a chain names one, so a
# consumer with no vault configured must not be stopped by a missing
# package - and must not pay for one that is there either.
subtest 'the crypto is loaded at the first seal never at compile time' => sub {
    plan tests => 2;

    my $HEREDIR = dirname( File::Spec->rel2abs(__FILE__) );

    my $run = sub {
        my ($code) = @_;

        local $ENV{PERL5LIB} = '';
        local $ENV{PERLLIB}  = '';

        my @cmd = (
            $^X,
            '-I' . File::Spec->catdir( $HEREDIR, '..', 'lib' ),
            '-I' . File::Spec->catdir( $HEREDIR, '..', 'plugins' ),
            '-I' . File::Spec->catdir( PluginHome::pluginhome(), 'perl', 'lib' ),
            '-e', $code . '; print exists $INC{"Crypt/AuthEnc/GCM.pm"} ? "yes" : "no"'
        );

        open( my $handle, '-|', @cmd ) or die "cannot run perl: $!";
        local $/ = undef;
        my $out = <$handle>;
        close($handle);

        return defined $out ? $out : '';
    };

    is( $run->('use Voxgig::Sekreto::Plugins::Minivault ()'),
        'no', 'loading the module loads no crypto' );
    is(
        $run->(
                'use Voxgig::Sekreto::Plugins::Minivault ();'
              . ' Voxgig::Sekreto::Plugins::Minivault::seal("k" x 32, "v", "aad")'
        ),
        'yes',
        'and the first seal loads it'
    );
};
