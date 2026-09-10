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

my @metacpan_changelog_cases = (
  { url => 'https://metacpan.org/release/SHAY/perl-5.38.4/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/SHAY/perl-5.40.2/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/RRWO/Linux-Statm-Tiny-0.0701/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/dist/YAML-Syck/changes', expect_warn => 1 },
  { url => 'https://metacpan.org/dist/Crypt-Sodium-XS/changes', expect_warn => 1 },
  { url => 'https://metacpan.org/release/WREIS/DBIx-Class-EncodedColumn-0.00032/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/WREIS/DBIx-Class-EncodedColumn-0.00032/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/TOBYINK/Mite-0.013000/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/dist/Sub-HandlesVia/changes#L12', expect_warn => 1 },
  { url => 'https://metacpan.org/release/RRWO/Net-CIDR-Set-0.14/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/GRYPHON/Mojolicious-Plugin-CSRF-1.04/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/GRYPHON/Mojolicious-Plugin-CaptchaPNG-1.06/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/RURBAN/Cpanel-JSON-XS-4.40/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/PJUHASZ/JSON-SIMD-1.07/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/JV/HarfBuzz-Shaper-0.032/changes', expect_warn => 0 },
  { url => 'https://metacpan.org/release/DDICK/Crypt-URandom-0.55/source/Changes', expect_warn => 0 },
);

# Regression: the perl interpreter core (distribution and module both 'perl')
# uses the 'Perl <version range> have ...' wording, not '<module> ... for Perl'.
# The announce wording lint must accept that form and not warn.
my $perl_core_model = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9998',
    distribution => 'perl',
    module => 'perl',
    author => 'AUTHOR',
    affected => ['<= 5.43.10'],
    title => 'Perl versions through 5.43.10 have a buffer overflow',
    description => "Perl versions through 5.43.10 have a buffer overflow.\n\nMore details.",
    solution => 'Update to a fixed release.',
    references => [ { link => 'https://example.invalid/TODO', tags => ['advisory'] } ],
  },
);
my $perl_core_findings = $lint->run_model($perl_core_model, path => 't/var/CVE-1900-9998.yaml');
my %perl_core_by_id = map { ($_->{id} => $_) } @$perl_core_findings;
ok(
  !$perl_core_by_id{announce_wording_mismatch},
  'no announce_wording_mismatch for perl core record using "Perl <range> have ..." wording',
);

# A perl core record whose lead text genuinely diverges from the version
# phrasing should still warn.
my $perl_core_bad_model = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9997',
    distribution => 'perl',
    module => 'perl',
    author => 'AUTHOR',
    affected => ['<= 5.43.10'],
    title => 'A buffer overflow affects the interpreter',
    description => "A buffer overflow affects the interpreter.\n\nMore details.",
    solution => 'Update to a fixed release.',
    references => [ { link => 'https://example.invalid/TODO', tags => ['advisory'] } ],
  },
);
my $perl_core_bad_findings = $lint->run_model($perl_core_bad_model, path => 't/var/CVE-1900-9997.yaml');
my %perl_core_bad_by_id = map { ($_->{id} => $_) } @$perl_core_bad_findings;
ok(
  $perl_core_bad_by_id{announce_wording_mismatch},
  'still warns for perl core record whose lead text does not match version phrasing',
);

for my $i (0 .. $#metacpan_changelog_cases) {
  my $case = $metacpan_changelog_cases[$i];
  my $case_model = CPANSec::CVE::Model->new(
    cpansec => {
      cve => sprintf('CVE-1900-%04d', 9800 + $i),
      distribution => 'Example-Dist',
      module => 'Example::Module',
      author => 'AUTHOR',
      affected => ['<= 1.0'],
      title => 'Example::Module before 1.0 for Perl has an issue',
      description => "Example::Module before 1.0 for Perl has an issue.\n\nMore details.",
      solution => 'Update to a fixed release.',
      references => [
        { link => $case->{url}, tags => ['release-notes'] },
      ],
    },
  );
  my $case_findings = $lint->run_model($case_model, path => sprintf('t/var/CVE-1900-%04d.yaml', 9800 + $i));
  my %case_by_id = map { ($_->{id} => $_) } @$case_findings;
  if ($case->{expect_warn}) {
    ok(
      $case_by_id{metacpan_changelog_not_version_pinned},
      "warns for non-version-pinned changelog URL: $case->{url}",
    );
  } else {
    ok(
      !$case_by_id{metacpan_changelog_not_version_pinned},
      "accepts version-pinned changelog URL: $case->{url}",
    );
  }
}

# author is deprecated: nothing emits it, so its presence only earns a warning.
ok($by_id{deprecated_author}, 'warns when the record-level author key is present');
is($by_id{deprecated_author}{severity}, 'warning', 'deprecated author is advisory');

my $entry_author = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9999',
    module => 'Example::Module',
    affected => [
      { distribution => 'Example-Dist', versions => ['<= 1.0'], author => 'AUTHOR' },
    ],
    title => 'Example::Module versions through 1.0 for Perl has an issue',
    description => "Example::Module versions through 1.0 for Perl has an issue.\n\nMore details.",
    solution => 'Update to a fixed release.',
    references => [ { link => 'https://example.com/advisory', tags => ['patch'] } ],
  },
);
my %entry_by_id = map { ($_->{id} => $_) } @{ $lint->run_model($entry_author, path => 't/var/CVE-1900-9999.yaml') };
ok($entry_by_id{deprecated_author}, 'warns when an affected entry carries author');

my $no_author = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9999',
    distribution => 'Example-Dist',
    module => 'Example::Module',
    affected => ['<= 1.0'],
    title => 'Example::Module versions through 1.0 for Perl has an issue',
    description => "Example::Module versions through 1.0 for Perl has an issue.\n\nMore details.",
    solution => 'Update to a fixed release.',
    references => [ { link => 'https://example.com/advisory', tags => ['patch'] } ],
  },
);
my %clean_by_id = map { ($_->{id} => $_) } @{ $lint->run_model($no_author, path => 't/var/CVE-1900-9999.yaml') };
ok(!$clean_by_id{deprecated_author}, 'silent without author');

# A leading v on a version is a CPAN spelling quirk (podlators-v6.0.2); the
# range should carry the bare number so phrasing and comparisons stay uniform.
my $v_prefixed = CPANSec::CVE::Model->new(
  cpansec => {
    cve => 'CVE-1900-9999',
    module => 'Pod::Man',
    affected => [
      { distribution => 'podlators', versions => ['< v6.0.2', 'v4.0 <= 5.0'] },
      { distribution => 'perl', versions => ['< 5.44.0'] },
    ],
    title => 'Pod::Man versions before 6.0.2 for Perl has an issue',
    description => "Pod::Man versions before 6.0.2 for Perl has an issue.\n\nMore details.",
    solution => 'Update to a fixed release.',
    references => [ { link => 'https://example.com/advisory', tags => ['patch'] } ],
  },
);
my @v_findings = grep { $_->{id} eq 'version_v_prefix' } @{ $lint->run_model($v_prefixed, path => 't/var/CVE-1900-9999.yaml') };
is(scalar @v_findings, 2, 'one warning per v-prefixed range');
is($v_findings[0]{severity}, 'warning', 'v prefix is advisory');
like($v_findings[0]{message}, qr/\Q< v6.0.2\E.*\Q< 6.0.2\E/, 'names the range and its normalized form');
like($v_findings[1]{message}, qr/\Qv4.0 <= 5.0\E.*\Q4.0 <= 5.0\E/, 'strips the prefix from the lower bound too');
ok(!grep({ $_->{id} eq 'version_v_prefix' } @{ $lint->run_model($no_author, path => 't/var/CVE-1900-9999.yaml') }), 'silent for bare versions');

done_testing();
