use strict;
use v5.42;

use JSON::PP ();
use Test::More;

use lib 'lib';
use CPANSec::CVE::Announce ();
use CPANSec::CVE::CVE2YAML ();
use CPANSec::CVE::YAML2CVE ();

# Fixtures taken from real published CPANSec advisories. Only the CVE ID is
# synthetic (CVE-1900-*); titles, descriptions, metadata and references are
# verbatim so generated output can be compared against what was published.
#
#   CVE-1900-9995  <- CVE-2026-13708  Imager::File::JPEG, single distribution
#   CVE-1900-9994  <- CVE-2026-13221  perl interpreter core
#   CVE-1900-9996      the same advisory as 9995, rewritten as two distributions

my $converter = CPANSec::CVE::YAML2CVE->new;

subtest 'published records still import under the round-trip guard' => sub {
  # These predate the 5.2.0 changes: they carry vendor/product and no
  # packageURL, so they exercise the legacy fallbacks on real data.
  for my $cve (qw(CVE-1900-9995 CVE-1900-9994)) {
    my $source = "t/var/$cve.source.json";
    my $json = JSON::PP->new->decode(do {
      open my $fh, '<', $source or die "cannot read $source: $!";
      local $/; <$fh>;
    });
    my $affected = $json->{containers}{cna}{affected}[0];

    ok(exists $affected->{product}, "$cve fixture is the old product/vendor shape");
    ok(!exists $affected->{packageURL}, "$cve fixture predates packageURL");

    my $yaml = eval { CPANSec::CVE::CVE2YAML->new->convert_json_file_to_yaml($source, guard => 1) };
    is($@, '', "$cve imports with the guard enabled") or diag $@;

    like($yaml, qr/^  module: \Q$affected->{product}\E$/m, "$cve recovers module from product");
    like($yaml, qr/^  author: \Q$affected->{vendor}\E$/m, "$cve recovers author from vendor");
  }
};

subtest 'the perl core record emits the perl distribution purl' => sub {
  my $yaml = CPANSec::CVE::CVE2YAML->new->convert_json_file_to_yaml('t/var/CVE-1900-9994.source.json');

  my $path = "t/var/.tmp-perl-core-$$.yaml";
  open my $fh, '>', $path or die $!;
  print {$fh} $yaml;
  close $fh;

  my $affected = eval { $converter->convert_yaml_file($path)->{containers}{cna}{affected}[0] };
  my $err = $@;
  unlink $path;
  is($err, '', 'the imported perl core record converts back') or diag $err;

  is($affected->{packageName}, 'perl', 'distribution is perl');
  is($affected->{packageURL}, 'pkg:cpan/perl', 'perl core gets the plain distribution purl');
  is_deeply($affected->{modules}, ['perl'], 'module recorded in modules[]');
};

subtest 'the bundled-handler advisory as two distributions' => sub {
  my $cna = $converter->convert_yaml_file('t/var/CVE-1900-9996.yaml')->{containers}{cna};
  my $affected = $cna->{affected};

  is(scalar @$affected, 2, 'both affected distributions are recorded');

  is($affected->[0]{packageName}, 'Imager-File-JPEG', 'own distribution first');
  is($affected->[0]{packageURL}, 'pkg:cpan/Imager-File-JPEG', 'first purl');
  is($affected->[0]{versions}[0]{lessThan}, '1.003', 'own distribution fix version');

  is($affected->[1]{packageName}, 'Imager', 'bundling distribution second');
  is($affected->[1]{packageURL}, 'pkg:cpan/Imager', 'second purl');
  is($affected->[1]{versions}[0]{lessThan}, '1.032', 'bundled copy has its own fix version');

  # The title must still read exactly as the advisory was published, with the
  # token resolving against the primary distribution.
  my $published = JSON::PP->new->decode(do {
    open my $fh, '<', 't/var/CVE-1900-9995.source.json' or die $!;
    local $/; <$fh>;
  })->{containers}{cna}{title};
  is($cna->{title}, $published, 'title matches the published wording');

  my $text = CPANSec::CVE::Announce->new->render_cve5_hash(
    $converter->convert_yaml_file('t/var/CVE-1900-9996.yaml'));
  like($text, qr/Distribution:\s+Imager-File-JPEG\n\s*Versions:\s+before 1\.003\n/, 'first block');
  like($text, qr/Distribution:\s+Imager\n\s*Versions:\s+before 1\.032\n/, 'second block');
};

done_testing();
