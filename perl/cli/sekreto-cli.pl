#!/usr/bin/env perl

# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with it.
# Every port ships this same CLI, and test/integration.sh runs all of them
# against the same server from every secret source - which is what proves
# the library, rather than the spec alone.
#
# Usage: perl -Ilib cli/sekreto-cli.pl <api-url> [--source <source>] [--store <name>]
#
# Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
#          gcpsecrets azuresecrets onepassword doppler infisical
#          secretspec chain
#
# Each source's configuration arrives in the environment variables its own
# ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
# chainfor below.

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
    my $filespec   = { kind => 'file', dir => $ENV{SEKRETO_FILEDIR} || '/run/secrets' };

    my $hashicorpspec = {
        kind           => 'hashicorp',
        addr           => $ENV{VAULT_ADDR} || '',
        token          => $ENV{VAULT_TOKEN} || '',
        mount          => $ENV{VAULT_MOUNT},
        kv             => $ENV{VAULT_KV} ? 0 + $ENV{VAULT_KV} : undef,
        vaultnamespace => $ENV{VAULT_NAMESPACE},
        auth           => $ENV{VAULT_AUTH}
        ? {
            method   => $ENV{VAULT_AUTH},
            role     => $ENV{VAULT_ROLE},
            jwtfile  => $ENV{VAULT_JWT_FILE},
            roleid   => $ENV{VAULT_ROLE_ID},
            secretid => $ENV{VAULT_SECRET_ID},
          }
        : undef,
    };

    my $boruspec = {
        kind      => 'boru',
        command   => $ENV{BORU_COMMAND} || 'boru',
        namespace => $ENV{BORU_NAMESPACE},
        home      => $ENV{BORU_HOME},
    };

    # The same vault over its wire protocol (`boru vault serve`) instead of
    # the CLI: an address plus a capability token from `vault grant`.
    my $boruwirespec = {
        kind      => 'boru',
        addr      => $ENV{BORU_ADDR} || '',
        token     => $ENV{BORU_TOKEN} || '',
        namespace => $ENV{BORU_NAMESPACE},
    };

    my $awssecretsspec = {
        kind   => 'awssecrets',
        region => $ENV{AWS_REGION},
        addr   => $ENV{AWS_ENDPOINT},
    };

    my $awsparamsspec = {
        kind   => 'awsparams',
        region => $ENV{AWS_REGION},
        addr   => $ENV{AWS_ENDPOINT},
        prefix => $ENV{AWS_PARAM_PREFIX},
    };

    my $gcpspec = {
        kind         => 'gcpsecrets',
        project      => $ENV{GCP_PROJECT},
        addr         => $ENV{GCP_ADDR},
        metadataaddr => $ENV{GCP_METADATA_ADDR},
    };

    my $azurespec = {
        kind         => 'azuresecrets',
        vault        => $ENV{AZURE_VAULT},
        token        => $ENV{AZURE_TOKEN},
        tenant       => $ENV{AZURE_TENANT},
        clientid     => $ENV{AZURE_CLIENT_ID},
        clientsecret => $ENV{AZURE_CLIENT_SECRET},
        loginaddr    => $ENV{AZURE_LOGIN_ADDR},
        imdsaddr     => $ENV{AZURE_IMDS_ADDR},
    };

    my $onepasswordspec = {
        kind  => 'onepassword',
        addr  => $ENV{OP_CONNECT_HOST},
        token => $ENV{OP_CONNECT_TOKEN},
        vault => $ENV{OP_VAULT},
    };

    my $dopplerspec = {
        kind    => 'doppler',
        token   => $ENV{DOPPLER_TOKEN},
        project => $ENV{DOPPLER_PROJECT},
        config  => $ENV{DOPPLER_CONFIG},
        addr    => $ENV{DOPPLER_ADDR},
    };

    # SecretSpec's own environment variables where it has them, so a shell
    # already set up for secretspec needs nothing further.
    my $secretspecspec = {
        kind    => 'secretspec',
        command => $ENV{SECRETSPEC_COMMAND} || 'secretspec',
        file    => $ENV{SECRETSPEC_FILE},
        profile => $ENV{SECRETSPEC_PROFILE},
        backend => $ENV{SECRETSPEC_PROVIDER},
        reason  => $ENV{SECRETSPEC_REASON},
    };

    my $infisicalspec = {
        kind         => 'infisical',
        addr         => $ENV{INFISICAL_ADDR},
        token        => $ENV{INFISICAL_TOKEN},
        clientid     => $ENV{INFISICAL_CLIENT_ID},
        clientsecret => $ENV{INFISICAL_CLIENT_SECRET},
        project      => $ENV{INFISICAL_PROJECT},
        environment  => $ENV{INFISICAL_ENV},
        path         => $ENV{INFISICAL_PATH},
    };

    return [$envspec]          if 'env' eq $source;
    return [$dotenvspec]       if 'dotenv' eq $source;
    return [$filespec]         if 'file' eq $source;
    return [$hashicorpspec]    if 'hashicorp' eq $source;
    return [$boruspec]         if 'boru' eq $source;
    return [$boruwirespec]     if 'boruwire' eq $source;
    return [$awssecretsspec]   if 'awssecrets' eq $source;
    return [$awsparamsspec]    if 'awsparams' eq $source;
    return [$gcpspec]          if 'gcpsecrets' eq $source;
    return [$azurespec]        if 'azuresecrets' eq $source;
    return [$onepasswordspec]  if 'onepassword' eq $source;
    return [$dopplerspec]      if 'doppler' eq $source;
    return [$infisicalspec]    if 'infisical' eq $source;
    return [$secretspecspec]   if 'secretspec' eq $source;

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
