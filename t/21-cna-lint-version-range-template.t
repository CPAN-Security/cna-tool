use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CNA::Lint ();
use CPANSec::CVE::Model ();

my $model = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9921',
    distribution => 'Example-Dist',
    module => 'Example::Module',
    author => 'AUTHOR',
    affected => ['<= 1.0'],
    title => 'Example::Module {{VERSION_RANGE}} for Perl has an issue',
    description => "Example::Module {{VERSION_RANGE}} for Perl has an issue.\n\nMore details.",
    references => [ { link => 'https://github.com/example/repo', tags => ['patch'] } ],
  },
);

my $lint = CPANSec::CNA::Lint->new;
my $findings = $lint->run_model($model, path => 't/var/CVE-1900-9921.yaml');
my %by_id = map { ($_->{id} => $_) } @$findings;

ok(!$by_id{announce_wording_mismatch}, 'VERSION_RANGE token is handled by announce wording lint');
ok(!$by_id{title_style_standard}, 'VERSION_RANGE token is handled by title style lint');

done_testing();
