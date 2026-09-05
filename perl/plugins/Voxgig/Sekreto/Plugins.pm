package Voxgig::Sekreto::Plugins;

# THE PLUGINS TREE - one module per plugin, and the full set on demand.
#
# One plugin is one module, and loading it loads nothing else:
#
#     use Voxgig::Sekreto::Plugins::Hashicorp qw(hashicorp);
#
#     my $secrets = Voxgig::Sekreto->new({
#         plugins   => [ hashicorp() ],
#         providers => [ { kind => 'env' }, { kind => 'hashicorp', ... } ],
#     });
#
# THIS MODULE LOADS NO PLUGIN AT COMPILE TIME. `allplugins` requires the ten
# of them when it is called, and not before, so that merely having this file
# on @INC costs nothing:
#
#     use Voxgig::Sekreto::Plugins qw(allplugins);
#     Voxgig::Sekreto->new({ plugins => allplugins(), providers => [ ... ] });
#
# The full set is for the CLI, the conformance suite, and an app whose chain
# is decided at run time. Reaching for it loads every store client, AWS
# request signing and the two CLIs - which is the cost the core/plugin split
# exists to remove; an app loads the kinds it actually configures.
#
# This tree is a SECOND @INC ROOT, not a subdirectory of `lib/`, and that is
# what makes the boundary real rather than nominal: a program built with
# `-Ilib` alone cannot find a single file under it, so the core cannot reach
# a plugin even by mistake. `perl/Makefile` adds `-Iplugins` for the tests,
# and `cli/sekreto-cli.pl` adds it for itself.
#
# A port of typescript/plugins/index.ts, which is canonical. See
# docs/design/plugin-providers.md.

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(allplugins);

# The ten plugin kinds, in the order the design lists them, as
# module/definition pairs.
our @PLUGINS = (
    [ 'Hashicorp',    'hashicorp' ],
    [ 'Boru',         'boru' ],
    [ 'Aws',          'awssecrets' ],
    [ 'Aws',          'awsparams' ],
    [ 'Gcpsecrets',   'gcpsecrets' ],
    [ 'Azuresecrets', 'azuresecrets' ],
    [ 'Onepassword',  'onepassword' ],
    [ 'Doppler',      'doppler' ],
    [ 'Infisical',    'infisical' ],
    [ 'Secretspec',   'secretspec' ],
);

# Every plugin kind this library ships, loaded now and built now.
sub allplugins {
    my @out;

    for my $entry (@PLUGINS) {
        my ( $module, $kind ) = @{$entry};
        my $package = 'Voxgig::Sekreto::Plugins::' . $module;

        # A runtime require, so that this file costs nothing until the full
        # set is actually asked for. `eval` because `require` wants a bare
        # module name and this one is computed.
        eval "require $package; 1"    ## no critic (ProhibitStringyEval)
          or die $@;

        no strict 'refs';
        push @out, &{ $package . '::' . $kind }();
    }

    return \@out;
}

1;
