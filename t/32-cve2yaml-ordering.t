use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CVE::CVE2YAML ();

my $conv = CPANSec::CVE::CVE2YAML->new;
my $yaml = $conv->encode_cpansec_yaml({
  references => [ { link => 'https://example.invalid/advisory' } ],
  mitigation => "Mitigate\n",
  affected => [ '<= 1.2.3' ],
  distribution => 'Example-Dist',
  title => 'Example title',
  repo => 'https://example.invalid/repo',
  files => [ 'lib/Foo.pm' ],
  description => "Example description\n",
  cwes => [ 'CWE-330: Use of Insufficiently Random Values' ],
  solution => "Upgrade\n",
  credits => [ { type => 'finder', value => 'A. Finder' } ],
  cve => 'CVE-1900-9988',
  module => 'Example::Module',
  author => 'AUTHORID',
  impacts => [ 'CAPEC-100 Overflow Buffers' ],
  routines => [ 'Example::Module::run' ],
  timeline => [ { time => '2025-12-01', value => 'Reported' } ],
});

my $line = _line_index_map($yaml);

my @expected = qw(
  cve distribution module author repo affected
  title description
  cwes impacts solution mitigation files routines timeline credits
  references
);

my $prev = -1;
for my $key (@expected) {
  ok(exists $line->{$key}, "$key emitted");
  cmp_ok($line->{$key}, '>', $prev, "$key appears after previous key");
  $prev = $line->{$key};
}

unlike($yaml, qr/[ \t]+\n/, 'no trailing horizontal whitespace');

done_testing();

sub _line_index_map ($yaml_text) {
  my %idx;
  my $i = 0;
  for my $ln (split /\n/, $yaml_text) {
    if ($ln =~ /^  ([a-z][a-z0-9_]*):/) {
      $idx{$1} //= $i;
    }
    $i++;
  }
  return \%idx;
}
