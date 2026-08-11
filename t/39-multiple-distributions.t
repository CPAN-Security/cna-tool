use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CVE::Model ();
use CPANSec::CVE::YAML2CVE ();

my $converter = CPANSec::CVE::YAML2CVE->new;

subtest 'dual-life record emits one affected entry per distribution' => sub {
  my $cna = $converter->convert_yaml_file('t/var/CVE-1900-9997.yaml')->{containers}{cna};
  my $affected = $cna->{affected};

  is(scalar @$affected, 2, 'two affected entries');

  is($affected->[0]{packageName}, 'Encode', 'first entry is the CPAN distribution');
  is($affected->[0]{packageURL}, 'pkg:cpan/Encode', 'first entry purl');
  is($affected->[0]{repo}, 'https://github.com/dankogai/p5-encode', 'first entry repo');

  is($affected->[1]{packageName}, 'perl', 'second entry is perl core');
  is($affected->[1]{packageURL}, 'pkg:cpan/perl', 'second entry purl');
  is($affected->[1]{repo}, 'https://github.com/Perl/perl5', 'second entry repo');

  # The module is shared, so it appears in both entries.
  is_deeply($affected->[$_]{modules}, ['Encode'], "entry $_ carries the shared module")
    for 0, 1;

  # Each entry must satisfy the schema's versions-or-defaultStatus requirement.
  ok($_->{versions} && @{$_->{versions}}, 'entry has versions') for @$affected;

  isnt(
    $affected->[0]{versions}[0]{lessThanOrEqual},
    $affected->[1]{versions}[0]{lessThanOrEqual},
    'the two distributions keep their own version ranges',
  );
};

subtest 'the single-distribution spelling still desugars to one entry' => sub {
  my $model = $converter->load_yaml_model('t/var/CVE-2025-40933.yaml');
  my $dists = $model->distributions;

  is(scalar @$dists, 1, 'one normalized entry');
  is($dists->[0]{distribution}, 'Apache-AuthAny', 'distribution lifted from the flat key');
  is_deeply($dists->[0]{versions}, ['0.19 <= 0.201'], 'version ranges lifted from affected');
};

subtest 'contradictory spellings are rejected' => sub {
  my $mixed = CPANSec::CVE::Model->new(cpansec => {
    affected => ['<= 1.0', { distribution => 'Foo', versions => ['<= 2.0'] }],
  });
  like(
    (eval { $mixed->distributions; 1 } ? '' : $@),
    qr/must not mix/,
    'mixing version strings with distribution objects dies',
  );

  my $both = CPANSec::CVE::Model->new(cpansec => {
    distribution => 'Foo',
    affected => [{ distribution => 'Foo', versions => ['<= 2.0'] }],
  });
  like(
    (eval { $both->distributions; 1 } ? '' : $@),
    qr/must not be set/,
    'a flat distribution alongside the object form dies',
  );

  my $neither = CPANSec::CVE::Model->new(cpansec => { affected => ['<= 1.0'] });
  like(
    (eval { $neither->distributions; 1 } ? '' : $@),
    qr/is required/,
    'version ranges without a distribution dies',
  );
};

done_testing();
