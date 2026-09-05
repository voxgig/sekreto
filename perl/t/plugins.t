# RUN: prove -Ilib -Iplugins -It t/
# RUN-SOME: perl -Ilib -Iplugins -It t/plugins.t
#
# THE PLUGIN SEAM, from both sides.
#
# Moving the provider kinds that open sockets and spawn processes out of the
# core made a consumer's PLUGIN LIST load-bearing: a kind nobody passed in is
# not in the catalog, and a chain naming it is refused. That is the intended
# behaviour, and it means a consumer can be broken without a single
# conformance test noticing - t/sekreto.t hands the full set to every chain
# it builds, so it can never see a missing one. So the full set is pinned
# here: it holds every kind, every kind builds, and the CLI passes it.
#
# The other half is the boundary itself. `plugins/` is a second @INC root,
# so `perl -Ilib` cannot find one of these modules at all - and the three
# tests at the end run a FRESH INTERPRETER to prove it, because this one has
# loaded everything on purpose.

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Spec;
use Test::More tests => 17;

use PluginHome ();

BEGIN { PluginHome::pluginpath() }

use Voxgig::Sekreto qw(providerplugin);
use Voxgig::Sekreto::Plugins qw(allplugins);
use Voxgig::Sekreto::Plugins::Hashicorp qw(hashicorp);

my @PLUGINS = sort qw(
  awsparams awssecrets azuresecrets boru doppler gcpsecrets
  hashicorp infisical onepassword secretspec
);

my @BUILTIN = qw(env memory dotenv file);

my @EVERY = sort( @BUILTIN, @PLUGINS );

my $HERE = dirname( File::Spec->rel2abs(__FILE__) );
my $LIB     = File::Spec->catdir( $HERE, '..', 'lib' );
my $PLUGINS = File::Spec->catdir( $HERE, '..', 'plugins' );

# What loading something pulls in, read from a FRESH interpreter: this one
# has loaded every plugin above, deliberately, so it cannot answer the
# question itself.
sub fresh {
    my ( $code, @inc ) = @_;

    my @cmd = (
        $^X, ( map { '-I' . $_ } @inc ),
        '-e', $code . '; print join(",", sort grep { m{^Voxgig/Sekreto} } keys %INC)'
    );

    # @INC IS THE BOUNDARY, so the child must not inherit one. `prove -I`
    # exports PERL5LIB, and a grandchild picks it up: with `plugins` still on
    # the path this test read as green while proving only that the core did
    # not HAPPEN to load a plugin, rather than that it could not find one.
    local $ENV{PERL5LIB} = '';
    local $ENV{PERLLIB}  = '';

    open( my $handle, '-|', @cmd ) or die "cannot run perl: $!";
    local $/ = undef;
    my $out = <$handle>;
    close($handle);

    return defined $out ? $out : '';
}

# --- the full set --------------------------------------------------------

is_deeply(
    [ sort map { $_->{name} } @{ allplugins() } ],
    \@PLUGINS,
    'the full set holds every kind'
);

# Naming a kind is not enough: a kind can be in the catalog and still fail to
# build. Construction is what the CLI does before any network.
subtest 'every kind builds from a spec' => sub {
    plan tests => 3;

    my $secrets = Voxgig::Sekreto->new(
        {
            plugins   => allplugins(),
            providers => [
                map {
                    {
                        kind   => $_,
                        addr   => 'http://127.0.0.1:8200',
                        token  => 't',
                        dir    => '/tmp',
                        file   => '/tmp/.env',
                        values => {},
                    }
                } @EVERY
            ],
        }
    );

    is_deeply( $secrets->stores, \@EVERY, 'every kind is a store' );

    my $live = $secrets->host->list;
    is_deeply( [ sort keys %{$live} ], \@EVERY, 'every kind is an instance' );
    is_deeply( [ sort keys %{ { map { $_ => 1 } values %{$live} } } ],
        ['live'], 'and every instance is live' );
};

subtest 'the cli passes the full set' => sub {
    plan tests => 2;

    open( my $handle, '<', File::Spec->catfile( $HERE, '..', 'cli', 'sekreto-cli.pl' ) )
      or die "cannot read the cli: $!";
    local $/ = undef;
    my $src = <$handle>;
    close($handle);

    like( $src, qr/use Voxgig::Sekreto::Plugins qw\(allplugins\);/, 'it loads the full set' );
    like( $src, qr/plugins\s*=>\s*allplugins\(\)/,                  'and it passes it' );
};

# --- what a consumer sees ------------------------------------------------

subtest 'one plugin is enough for a chain that names only it' => sub {
    plan tests => 5;

    my $secrets = Voxgig::Sekreto->new(
        {
            plugins   => [ hashicorp() ],
            providers => [
                { kind => 'memory', values => { API_TOKEN => 'tok01' } },
                {
                    kind  => 'hashicorp',
                    name  => 'prod',
                    addr  => 'https://vault.example.com',
                    token => 't',
                },
            ],
        }
    );

    is_deeply( $secrets->stores, [ 'memory', 'prod' ], 'the chain is what was asked for' );
    is_deeply(
        $secrets->sources,
        [ 'memory', 'hashicorp:https://vault.example.com/secret' ],
        'and it describes itself'
    );
    is( $secrets->get('api.token'), 'tok01', 'and it resolves' );

    # The plugin host is what the chain is made of, and it reads like the
    # chain: the kind, or kind$store for a named store.
    is_deeply(
        $secrets->host->list,
        { 'memory' => 'live', 'hashicorp$prod' => 'live' },
        'the host reads like the chain'
    );
    is_deeply(
        $secrets->catalog->names,
        [ 'dotenv', 'env', 'file', 'hashicorp', 'memory' ],
        'and the catalog is the four built-ins plus the one that was passed'
    );
};

subtest 'a kind that was not passed in is refused, naming the fix' => sub {
    plan tests => 2;

    eval {
        Voxgig::Sekreto->new(
            { plugins => [ hashicorp() ], providers => [ { kind => 'doppler', token => 't' } ] } );
    };
    is(
        "$@",
        'sekreto: unknown provider kind: doppler'
          . ' (available: dotenv, env, file, hashicorp, memory)'
          . ' - doppler is a sekreto plugin, not built in: pass it in the plugins option',
        'a plugin that was not passed in says what to pass'
    );

    # A kind nobody ships is a typo, and gets no such hint.
    eval { Voxgig::Sekreto->new( { providers => [ { kind => 'vualt' } ] } ) };
    is(
        "$@",
        'sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)',
        'a kind nobody ships is just unknown'
    );
};

# Two providers MAY share a store name - a directed read walks both, and the
# spec pins it - but an instance ref may not, so the second gets a numbered
# tag from the host and keeps its store name.
subtest 'a repeated store name keeps the store and numbers the instance' => sub {
    plan tests => 4;

    my $secrets = Voxgig::Sekreto->new(
        {
            providers => [
                { kind => 'memory', values => {} },
                { kind => 'memory', values => { API_TOKEN => 'second' } },
                { kind => 'memory', name   => 'pair', values => {} },
                { kind => 'memory', name   => 'pair', values => { API_TOKEN => 'pair2' } },
            ]
        }
    );

    is_deeply( $secrets->stores, [ 'memory', 'pair' ], 'the stores are the two names' );
    is_deeply(
        [ sort keys %{ $secrets->host->list } ],
        [ 'memory', 'memory$1', 'memory$2', 'memory$pair' ],
        'and the instances are four'
    );
    is( $secrets->getfrom( 'memory', 'api.token' ), 'second', 'a directed read walks both' );
    is( $secrets->getfrom( 'pair',   'api.token' ), 'pair2',  'under either name' );
};

eval {
    Voxgig::Sekreto->new(
        { providers => [ { kind => 'memory', name => 'my store', values => {} } ] } );
};
is( "$@", 'sekreto: invalid store name: my store', 'a store name must be a valid tag' );

# A provider that refuses its own configuration raises a SekretoError from
# inside the plugin's `define`. The spec pins that message byte for byte, so
# it must come back out of the host as itself - not wrapped as
# plugin_define_failed, and not as a Voxgig::Plugin::Error.
subtest 'a SekretoError raised in define comes back out as itself' => sub {
    plan tests => 2;

    eval {
        Voxgig::Sekreto->new(
            {
                plugins   => [ hashicorp() ],
                providers => [
                    { kind => 'hashicorp', addr => 'http://127.0.0.1:1', token => 't', kv => 3 }
                ],
            }
        );
    };

    isa_ok( $@, 'Voxgig::Sekreto::SekretoError', 'the error' );
    is( "$@", 'sekreto: hashicorp: unsupported kv version: 3', 'and it is byte for byte' );
};

# ...and any other error is not sekreto's to rewrite: it surfaces as the host
# reports it, naming the instance and the cause.
subtest 'any other error raised in define is the hosts report of it' => sub {
    plan tests => 2;

    eval {
        Voxgig::Sekreto->new(
            {
                plugins   => [ providerplugin( 'broken', sub { die "boom\n" } ) ],
                providers => [ { kind => 'broken' } ],
            }
        );
    };

    is( $@->code, 'plugin_define_failed', 'the host wrapped it' );
    like( "$@", qr/boom/, 'and it still names the cause' );
};

subtest 'a custom kind is one providerplugin call' => sub {
    plan tests => 2;

    my $shouty = providerplugin( 'shouty',
        sub { Shouty->new( $_[0]->{values} || {} ) } );

    my $secrets = Voxgig::Sekreto->new(
        {
            plugins   => [$shouty],
            providers => [ { kind => 'shouty', values => { 'API.TOKEN' => 'loud' } } ],
        }
    );

    is( $secrets->get('api.token'), 'loud', 'a custom kind resolves' );
    is_deeply( $secrets->host->list, { shouty => 'live' }, 'and it is an instance like any other' );
};

# A plugin that names a built-in kind replaces it: that is how a host
# substitutes an implementation, and never an accident, because the four
# names are documented.
{
    my $secrets = Voxgig::Sekreto->new(
        {
            plugins   => [ providerplugin( 'memory', sub { Replaced->new } ) ],
            providers => [ { kind => 'memory', values => { API_TOKEN => 'original' } } ],
        }
    );

    is( $secrets->get('api.token'), 'replaced', 'a plugin may replace a built-in kind' );
}

subtest 'close tears the chain down and keeps redaction' => sub {
    plan tests => 5;

    my $secrets =
      Voxgig::Sekreto->new(
        { providers => [ { kind => 'memory', values => { API_TOKEN => 'tok01' } } ] } );

    is( $secrets->get('api.token'), 'tok01', 'it resolves while it is live' );

    $secrets->close;

    is_deeply( $secrets->host->list, {}, 'every instance is gone' );
    is_deeply( $secrets->stores,       [], 'and so is every store' );
    is( $secrets->try('api.token'), undef, 'there is nothing left to read from' );
    is( $secrets->redactall('token=tok01'),
        'token=[redacted]', 'and redaction still knows every value' );
};

# --- the boundary itself -------------------------------------------------

# The core loads no plugin. `plugins/` is NOT on @INC below, so this is not
# a claim about what the core happens to reach: with -Ilib alone not one
# plugin module is findable, and the core builds and resolves a chain of
# built-ins anyway.
subtest 'the core loads no plugin' => sub {
    plan tests => 2;

    is(
        fresh( 'use Voxgig::Sekreto ()', $LIB, PluginHome::pluginlib() ),
        'Voxgig/Sekreto.pm,Voxgig/Sekreto/Addr.pm,Voxgig/Sekreto/Providers.pm',
        'loading the core loads the core'
    );

    is(
        fresh(
            'use Voxgig::Sekreto (); my $s = Voxgig::Sekreto->new({providers=>[{kind=>"memory",'
              . 'values=>{API_TOKEN=>"tok01"}},{kind=>"env"},{kind=>"dotenv"},{kind=>"file",dir=>"/tmp"}]});'
              . 'die "wrong" if "tok01" ne $s->get("api.token")',
            $LIB, PluginHome::pluginlib()
        ),
        'Voxgig/Sekreto.pm,Voxgig/Sekreto/Addr.pm,Voxgig/Sekreto/Providers.pm',
        'and a chain of built-ins runs with no plugin on @INC at all'
    );
};

# ...and one plugin loads only itself: the core, this module, and the shared
# HTTP half. Not the other nine, and not `Sigv4` - request signing belongs to
# the two aws kinds, and it was Httpjson borrowing its URL escaper that used
# to drag a hash function into a chain that speaks to Doppler.
is(
    fresh( 'use Voxgig::Sekreto::Plugins::Hashicorp ()', $LIB, $PLUGINS, PluginHome::pluginlib() ),
    'Voxgig/Sekreto.pm,Voxgig/Sekreto/Addr.pm,Voxgig/Sekreto/Plugins/Hashicorp.pm,'
      . 'Voxgig/Sekreto/Plugins/Httpjson.pm,Voxgig/Sekreto/Providers.pm',
    'one plugin loads only itself'
);

# The full set is built on demand: having Voxgig::Sekreto::Plugins on @INC
# costs nothing until something calls allplugins(), which is the moment the
# whole cost of every store client is paid.
subtest 'the full set is built on demand' => sub {
    plan tests => 2;

    is(
        fresh( 'use Voxgig::Sekreto::Plugins ()', $LIB, $PLUGINS, PluginHome::pluginlib() ),
        'Voxgig/Sekreto/Plugins.pm',
        'the full set module alone loads nothing'
    );

    my $after = fresh( 'use Voxgig::Sekreto::Plugins qw(allplugins); allplugins()',
        $LIB, $PLUGINS, PluginHome::pluginlib() );

    my @missing = grep { -1 == index( $after, 'Plugins/' . $_ . '.pm' ) }
      qw(Hashicorp Boru Aws Gcpsecrets Azuresecrets Onepassword Doppler
      Infisical Secretspec Sigv4 Httpjson Proc);

    is_deeply( \@missing, [], 'and calling it loads every one of them' );
};

# `plugins => ['Voxgig::Sekreto::Plugins::Hashicorp']` is the module, not the
# definition it holds, and a module is refused by name, saying what to call.
subtest 'a module passed as a plugin is refused' => sub {
    plan tests => 2;

    eval {
        Voxgig::Sekreto->new(
            { plugins => ['Voxgig::Sekreto::Plugins::Hashicorp'], providers => [] } );
    };
    is(
        "$@",
        'sekreto: not a plugin definition: the module Voxgig::Sekreto::Plugins::Hashicorp'
          . ' - call the definition it holds:'
          . ' use Voxgig::Sekreto::Plugins::Hashicorp qw(hashicorp); hashicorp()',
        'the module name names the call that was meant'
    );

    # And the other half of the same mistake: the sub, uncalled.
    eval { Voxgig::Sekreto->new( { plugins => [ \&hashicorp ], providers => [] } ) };
    is(
        "$@",
        'sekreto: not a plugin definition: a code reference'
          . ' - a definition is what calling it returns',
        'an uncalled definition sub is refused too'
    );
};

# What the compiler cannot see, a grep does: the core must not so much as
# name the platform modules the split moved out. `use HTTP::Tiny` in
# lib/ would still pass every test above - the boundary is @INC, and
# HTTP::Tiny is not under plugins/ - so the rule that a built-in kind reads
# at most a local file is checked here directly.
subtest 'the core loads no platform module' => sub {
    my @core = glob( File::Spec->catfile( $LIB, 'Voxgig', '*.pm' ) );
    push @core, glob( File::Spec->catfile( $LIB, 'Voxgig', 'Sekreto', '*.pm' ) );

    plan tests => scalar(@core);

    for my $file (@core) {
        open( my $handle, '<', $file ) or die "cannot read $file: $!";
        my @named = grep {
            m{^\s*(?:use|require)\s+(HTTP::|Digest::|IPC::|MIME::|IO::Socket|Net::|Socket)}
        } <$handle>;
        close($handle);

        is_deeply( [ map { s/^\s+|\s+$//gr } @named ],
            [], ( File::Spec->splitpath($file) )[2] . ' names no socket, hash or subprocess' );
    }
};

# A custom provider: anything with `lookup` and `describe`.
{

    package Shouty;

    sub new { return bless { values => $_[1] }, $_[0] }
    sub lookup { return $_[0]->{values}{ uc( $_[1] ) } }
    sub describe { return 'shouty' }
}

{

    package Replaced;

    sub new { return bless {}, $_[0] }
    sub lookup   { return 'replaced' }
    sub describe { return 'memory' }
}
