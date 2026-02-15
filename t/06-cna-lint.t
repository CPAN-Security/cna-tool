use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CNA::Lint ();
use CPANSec::CVE::Model ();

my $model = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9999',
    distribution => 'Example-Dist',
    module => 'Example::Module',
    author => 'AUTHOR',
    affected => ['<= 1.0'],
    title => 'Example::Module before 1.0 for Perl has an issue',
    description => "Example::Module before 1.0 for Perl has an issue\n\nMore details.",
    references => [ { link => 'https://example.invalid/TODO', tags => ['advisory'] } ],
  },
);

my $lint = CPANSec::CNA::Lint->new;
my $findings = $lint->run_model($model, path => 't/var/CVE-1900-9999.yaml');

ok(ref($findings) eq 'ARRAY', 'run_model returns an arrayref');
my %by_id = map { ($_->{id} => $_) } @$findings;

ok($by_id{title_repeated_in_description}, 'detects title repeated in description');
ok($by_id{announce_wording_mismatch}, 'warns when title/description lead diverge from announce-style version phrasing');
ok($by_id{placeholder_content}, 'detects placeholder content');
ok($by_id{missing_solution_or_mitigation}, 'warns when solution/mitigation is missing');

done_testing();
