use strict;
use v5.42;

use File::Copy ();
use File::Path ();
use File::Temp ();
use JSON::PP ();
use Test::More;

use lib 'lib';
use CPANSec::CNA::Lint ();
use CPANSec::CVE::Announce ();
use CPANSec::CVE::CVE2YAML ();
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

subtest 'the announcement repeats a block per distribution' => sub {
  my $json = $converter->convert_yaml_file('t/var/CVE-1900-9997.yaml');
  my $text = CPANSec::CVE::Announce->new->render_cve5_hash($json);

  like($text, qr/^\s*Distribution:\s+Encode$/m, 'names the CPAN distribution');
  like($text, qr/^\s*Distribution:\s+perl$/m, 'names perl core');
  like($text, qr{^\s*MetaCPAN:\s+\Qhttps://metacpan.org/dist/perl\E$}m, 'per-distribution MetaCPAN link');
  like($text, qr{^\s*VCS Repo:\s+\Qhttps://github.com/Perl/perl5\E$}m, 'per-distribution repo');

  # Each range must stay attached to its own distribution.
  like($text, qr/Distribution:\s+Encode\n\s*Versions:\s+through 3\.20\n/, 'Encode keeps its range');
  like($text, qr/Distribution:\s+perl\n\s*Versions:\s+from 5\.36\.0 through 5\.38\.2\n/, 'perl keeps its range');
};

subtest 'a dual-life record survives import with the guard on' => sub {
  my ($fh, $json_path) = File::Temp::tempfile(SUFFIX => '.json', UNLINK => 1);
  print {$fh} $converter->convert_yaml_file_to_json('t/var/CVE-1900-9997.yaml');
  close($fh);

  my $yaml = eval { CPANSec::CVE::CVE2YAML->new->convert_json_file_to_yaml($json_path, guard => 1) };
  is($@, '', 'round-trip guard passes for multiple distributions') or diag $@;

  # Round-tripping must regenerate the object spelling, not silently collapse
  # to the first distribution.
  like($yaml, qr/^\s+- distribution: Encode$/m, 'Encode entry regenerated');
  like($yaml, qr/^\s+- distribution: perl$/m, 'perl entry regenerated');
  unlike($yaml, qr/^  distribution:/m, 'no flat distribution key alongside the object form');
};

subtest 'divergent per-entry modules cannot be silently lost' => sub {
  # The macro carries one shared module, so a record whose entries name
  # different modules is not representable. The guard must say so rather than
  # quietly keeping the first.
  my $doc = $converter->convert_yaml_file('t/var/CVE-1900-9997.yaml');
  $doc->{containers}{cna}{affected}[1]{modules} = ['PerlIO::encoding'];

  my ($fh, $json_path) = File::Temp::tempfile(SUFFIX => '.json', UNLINK => 1);
  print {$fh} JSON::PP->new->utf8->canonical->encode($doc);
  close($fh);

  my $ok = eval { CPANSec::CVE::CVE2YAML->new->convert_json_file_to_yaml($json_path, guard => 1); 1 };
  ok(!$ok, 'guard rejects a record it cannot represent');
  like($@, qr/distributions\[1\]\.module differs/, 'diff points at the offending entry');
};

subtest 'the CLI handles an object-form record' => sub {
  my $root = File::Temp::tempdir(CLEANUP => 1);
  File::Path::make_path("$root/cves");
  File::Copy::copy('t/var/CVE-1900-9997.yaml', "$root/cves/CVE-1900-9997.yaml")
    or die "cannot stage fixture: $!";

  my $json = qx(scripts/cna --cpansec-cna-root '$root' emit CVE-1900-9997 2>&1);
  is($? >> 8, 0, 'emit succeeds') or diag $json;
  like($json, qr/pkg:cpan\/perl/, 'emit reaches the second distribution');

  my $text = qx(scripts/cna --cpansec-cna-root '$root' announce CVE-1900-9997 2>&1);
  is($? >> 8, 0, 'announce succeeds') or diag $text;
  like($text, qr/Distribution:\s+perl/, 'announce reaches the second distribution');
};

subtest 'placeholder distributions are caught in the object form' => sub {
  my $model = CPANSec::CVE::Model->new(cpansec => {
    cve => 'CVE-1900-0001',
    module => 'Foo',
    affected => [{ distribution => 'TODO', versions => ['<= 1.0'] }],
  });

  my $ids = join ',', map { $_->{id} } @{CPANSec::CNA::Lint->new->run_model($model, path => '')};
  like($ids, qr/placeholder_content/, 'a TODO distribution is still flagged without a flat key');
};

subtest 'contradictory records annotate rather than crash' => sub {
  # distribution stopped being schema-required, so these are caught in the model
  # instead. They must still reach CI as inline annotations, not as a bare die.
  my %bad = (
    'CVE-1900-0001' => <<'Y',
cpansec:
  cve: CVE-1900-0001
  module: Foo
  affected: ["<= 1.0"]
  title: Foo through 1.0 for Perl breaks
  description: Foo through 1.0 for Perl breaks.
  references:
    - link: https://example.com/a
Y
    'CVE-1900-0002' => <<'Y',
cpansec:
  cve: CVE-1900-0002
  module: Foo
  affected:
    - "<= 1.0"
    - distribution: Bar
      versions: ["<= 2.0"]
  title: Foo through 1.0 for Perl breaks
  description: Foo through 1.0 for Perl breaks.
  references:
    - link: https://example.com/a
Y
  );

  my $root = File::Temp::tempdir(CLEANUP => 1);
  File::Path::make_path("$root/cves");
  for my $cve (sort keys %bad) {
    open my $fh, '>', "$root/cves/$cve.yaml" or die $!;
    print {$fh} $bad{$cve};
    close $fh;

    my $out = qx(scripts/cna --cpansec-cna-root '$root' check --format github $cve 2>&1);
    isnt($? >> 8, 0, "$cve fails check");
    like($out, qr{^::error file=\Qcves/$cve.yaml\E,line=\d+,title=schema_validation::}m,
      "$cve reports an annotated schema_validation error");
  }
};

subtest 'an ambiguous version-range token is refused, not emitted' => sub {
  my $root = File::Temp::tempdir(CLEANUP => 1);
  File::Path::make_path("$root/cves");

  open my $src, '<', 't/var/CVE-1900-9997.yaml' or die $!;
  my $yaml = do { local $/; <$src> };
  close $src;
  $yaml =~ s/^  title: .*$/  title: Encode {{VERSION_RANGE}} for Perl mishandles a decoding edge case/m;

  open my $fh, '>', "$root/cves/CVE-1900-9997.yaml" or die $!;
  print {$fh} $yaml;
  close $fh;

  for my $cmd (qw(emit build)) {
    my $out = qx(scripts/cna --cpansec-cna-root '$root' $cmd CVE-1900-9997 2>&1);
    isnt($? >> 8, 0, "$cmd refuses the record");
    like($out, qr/ambiguous when the record affects 2 distributions/, "$cmd explains why");
    unlike($out, qr/^\s*"title"\s*:.*VERSION_RANGE/m, "$cmd does not emit the raw token");
  }

  # The record can never be built, so lint must not pass it as merely advisory.
  my $model = $converter->load_yaml_model("$root/cves/CVE-1900-9997.yaml");
  my ($finding) = grep { $_->{id} eq 'template_token_unresolved' }
    @{CPANSec::CNA::Lint->new->run_model($model, path => '')};
  is($finding->{severity}, 'error', 'lint raises it to an error for multi-distribution records');
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
