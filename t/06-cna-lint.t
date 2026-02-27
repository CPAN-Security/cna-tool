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

done_testing();
