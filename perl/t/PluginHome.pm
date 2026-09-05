package PluginHome;

# Where voxgig/plugin is, for a checkout that has not installed it.
#
# Voxgig::Sekreto depends on voxgig/plugin - the perl port of it - and perl
# has no manifest to declare that in, so the tests and the CLI look for a
# checkout the same way every port looks for omni: $PLUGIN_HOME, then the
# usual places, including the `../.plugin` that the Makefile's `deps` target
# fetches when nothing else is found. An installed distribution wins - if
# `Voxgig::Plugin` is already loadable, nothing here touches @INC.
#
# THE LIBRARY ITSELF SEARCHES NO PATH. This module is in `t/`, not in
# `lib/`, for that reason.

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Spec;

use Exporter 'import';

our @EXPORT_OK = qw(pluginhome pluginlib pluginpath);

sub pluginhome {
    my $here = dirname( File::Spec->rel2abs(__FILE__) );

    for my $cand (
        $ENV{PLUGIN_HOME},
        File::Spec->catdir( $here, '..', '..', '..', 'plugin' ),
        File::Spec->catdir( $here, '..', '..', '..', '..', 'plugin' ),
        File::Spec->catdir( $here, '..', '..', '.plugin' ),
        '/workspace/plugin',
        '/home/user/plugin',
      )
    {
        return $cand
          if defined $cand
          && -e File::Spec->catfile( $cand, 'perl', 'lib', 'Voxgig', 'Plugin.pm' );
    }

    die 'sekreto: voxgig/plugin not found - set PLUGIN_HOME';
}

sub pluginlib {
    return File::Spec->catdir( pluginhome(), 'perl', 'lib' );
}

# Make Voxgig::Plugin loadable: already installed, or from a checkout.
sub pluginpath {
    return if eval { require Voxgig::Plugin; 1 };
    unshift @INC, pluginlib();
    return;
}

1;
