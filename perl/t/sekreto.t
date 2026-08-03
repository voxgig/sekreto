# RUN: prove -Ilib -It t/
# RUN-SOME: perl -Ilib -It t/sekreto.t
#
# The sekreto conformance suite. Every port runs these same groups, from
# the same spec/sekreto.json, through its own voxgig/omni runner.

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Spec;
use JSON::PP ();
use Test::More tests => 11;

use Voxgig::Sekreto qw(envkey parsedotenv redact validname vaultref);

# Find the shared spec directory by walking up from this file.
sub specfile {
    my ($name) = @_;
    my $dir = dirname( File::Spec->rel2abs(__FILE__) );
    for ( 1 .. 8 ) {
        my $cand = File::Spec->catfile( $dir, 'spec', $name );
        return $cand if -e $cand;
        $dir = dirname($dir);
    }
    die "sekreto: spec not found: $name";
}

# omni is a sibling checkout, not a published distribution (yet), so its lib
# is added to @INC by path.
sub omnihome {
    my $here = dirname( File::Spec->rel2abs(__FILE__) );

    for my $cand (
        $ENV{OMNI_HOME},
        File::Spec->catdir( $here, '..', '..', '..', 'omni' ),
        File::Spec->catdir( $here, '..', '..', '..', '..', 'omni' ),
        '/workspace/omni',
        '/home/user/omni',
      )
    {
        return $cand if defined $cand && -e File::Spec->catfile( $cand, 'spec', 'fib.json' );
    }

    die 'sekreto: voxgig/omni not found - set OMNI_HOME';
}

# omnihome is already compiled by the time this BEGIN runs, so @INC is
# extended before the `use` below is resolved.
BEGIN { unshift @INC, File::Spec->catdir( omnihome(), 'perl', 'lib' ) }

use Voxgig::Omni::Runner qw(makeRunner);

# Build a Sekreto from the spec's declarative chain description.
sub chainof {
    my ($spec) = @_;
    return Voxgig::Sekreto->new( { providers => $spec->{chain}, cache => 0 } );
}

my $R = makeRunner( specfile('sekreto.json') )->('sekreto');

my $spec        = $R->{spec};
my $runset      = $R->{runset};
my $runsetflags = $R->{runsetflags};

# Run one group, reporting pass or fail through Test::More.
sub group {
    my ( $name, $body ) = @_;
    my $ok = eval { $body->(); 1 };
    if ($ok) {
        pass($name);
    }
    else {
        fail($name);
        diag("$@");
    }
}

# The spec says true/false, so the Perl port's 1/0 is adapted here rather
# than making the library itself hand back JSON booleans.
group(
    'validname',
    sub {
        $runsetflags->( $spec->{validname}, { null => 0 },
            sub { validname( $_[0] ) ? JSON::PP::true : JSON::PP::false } );
    }
);
group( 'envkey',
    sub { $runset->( $spec->{envkey}, sub { envkey( $_[0]->{name}, $_[0]->{prefix} ) } ) } );
group( 'vaultref', sub { $runset->( $spec->{vaultref}, sub { vaultref( $_[0] ) } ) } );
group( 'parsedotenv', sub { $runset->( $spec->{parsedotenv}, sub { parsedotenv( $_[0] ) } ) } );
group( 'resolve',
    sub { $runset->( $spec->{resolve}, sub { chainof( $_[0] )->get( $_[0]->{name} ) } ) } );
group( 'trysecret',
    sub { $runset->( $spec->{trysecret}, sub { chainof( $_[0] )->try( $_[0]->{name} ) } ) } );
group( 'sources', sub { $runset->( $spec->{sources}, sub { chainof( $_[0] )->sources() } ) } );
group( 'stores',  sub { $runset->( $spec->{stores},  sub { chainof( $_[0] )->stores() } ) } );
group(
    'getfrom',
    sub {
        $runset->( $spec->{getfrom},
            sub { chainof( $_[0] )->getfrom( $_[0]->{store}, $_[0]->{name} ) } );
    }
);
group(
    'tryfrom',
    sub {
        $runset->( $spec->{tryfrom},
            sub { chainof( $_[0] )->tryfrom( $_[0]->{store}, $_[0]->{name} ) } );
    }
);
group( 'redact',
    sub { $runset->( $spec->{redact}, sub { redact( $_[0]->{text}, $_[0]->{values} ) } ) } );
