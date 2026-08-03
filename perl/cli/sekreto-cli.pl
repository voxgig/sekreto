#!/usr/bin/env perl

# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with it.
# Every port ships this same CLI, and test/integration.sh runs all of them
# against the same server from all four secret sources - which is what
# proves the library, rather than the spec alone.
#
# Usage: perl -Ilib cli/sekreto-cli.pl <api-url> [--source <source>] [--store <name>]

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Spec;
use HTTP::Tiny ();
use JSON::PP   ();

BEGIN {
    unshift @INC, File::Spec->catdir( dirname( File::Spec->rel2abs(__FILE__) ), '..', 'lib' );
}

use Voxgig::Sekreto ();

my $LANG = 'perl';

sub chainfor {
    my ($source) = @_;

    my $envspec    = { kind => 'env', prefix => $ENV{SEKRETO_PREFIX} };
    my $dotenvspec = { kind => 'dotenv', file => $ENV{SEKRETO_DOTENV} || '.env' };
    my $hashicorpspec = {
        kind  => 'hashicorp',
        addr  => $ENV{VAULT_ADDR} || '',
        token => $ENV{VAULT_TOKEN} || '',
        mount => $ENV{VAULT_MOUNT},
    };
    my $boruspec = {
        kind      => 'boru',
        command   => $ENV{BORU_COMMAND} || 'boru',
        namespace => $ENV{BORU_NAMESPACE},
        home      => $ENV{BORU_HOME},
    };

    return [$envspec]    if 'env' eq $source;
    return [$dotenvspec] if 'dotenv' eq $source;
    return [$hashicorpspec] if 'hashicorp' eq $source;
    return [$boruspec]   if 'boru' eq $source;

    # The default: the chain an app would actually ship with - local
    # overrides first, shared vaults last.
    return [ $envspec, $dotenvspec, $hashicorpspec, $boruspec ];
}

sub main {
    my @args = @ARGV;
    my $url = $args[0] || 'http://127.0.0.1:8099/whoami';

    my $source = 'chain';
    for my $index ( 0 .. $#args ) {
        $source = $args[ $index + 1 ]
          if '--source' eq $args[$index] && $index + 1 <= $#args;
    }

    # --store names a store outright: the secret must come from that one, not
    # from whichever provider happens to answer first.
    my $store = '';
    for my $index ( 0 .. $#args ) {
        $store = $args[ $index + 1 ]
          if '--store' eq $args[$index] && $index + 1 <= $#args;
    }

    my $secrets = Voxgig::Sekreto->new( { providers => chainfor($source) } );

    my $token = eval {
        '' eq $store ? $secrets->get('api.token') : $secrets->getfrom( $store, 'api.token' );
    };
    if ( !defined $token ) {
        my $err = $@;
        print STDERR 'sekreto-cli: ' . "$err" . "\n";
        return 2;
    }

    my $response = HTTP::Tiny->new( timeout => 10 )->get(
        $url,
        {
            headers => {
                'Authorization'  => 'Bearer ' . $token,
                'X-Sekreto-Lang' => $LANG,
            }
        }
    );

    if ( 200 != $response->{status} ) {
        # Never print the token itself, even when the call fails.
        print STDERR 'sekreto-cli: '
          . $secrets->redactall( $response->{content} || '' ) . "\n";
        return 1;
    }

    my $body = eval { JSON::PP->new->decode( $response->{content} ) } || {};

    # Assembled field by field, not encoded from a hash: Perl hashes have no
    # insertion order, and every port must print the same bytes for
    # test/integration.sh to compare them.
    my $json = JSON::PP->new;

    print '{"ok":true'
      . ',"lang":' . $json->encode($LANG)
      . ',"source":' . $json->encode($source)
      . ',"store":' . $json->encode($store)
      . ',"caller":' . $json->encode( $body->{caller} ) . "}\n";

    return 0;
}

exit( main() );
