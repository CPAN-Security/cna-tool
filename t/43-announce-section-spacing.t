use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

sub announce ($cve, $yaml) {
  open(my $fh, '>', "$cves/$cve.yaml") or die "Cannot write $cve: $!";
  print {$fh} $yaml;
  close($fh);
  my $out = qx(scripts/cna --cpansec-cna-root '$root' announce $cve 2>&1);
  is($? >> 8, 0, "announce $cve succeeds") or diag($out);
  return $out;
}

sub headers ($announce) {
  return [ $announce =~ /^([A-Z][A-Za-z ]+)\n-+$/mg ];
}

# The double blank lines above the title block are deliberate; from the first
# section header down to the trailing pad, sections are one blank line apart.
sub body ($announce) {
  my ($body) = $announce =~ /^(Description\n-+\n.*?)\n*\z/ms;
  return $body;
}

# Every optional section filled, with multi-valued mitigation/solution and a
# solution that carries its own paragraph break, so section spacing is
# exercised at both boundaries at once.
my $full = announce('CVE-1900-9943', <<'YAML');
cpansec:
  cve: CVE-1900-9943
  distribution: Unicorn-Foobar
  module: Unicorn::Foobar
  repo: https://example.invalid/repo
  affected:
    - "< 0.55"
  title: Unicorn::Foobar {{VERSION_RANGE}} for Perl is vulnerable
  description: |-
    Unicorn::Foobar {{VERSION_RANGE}} for Perl is vulnerable.
  cwes:
    - CWE-190 Integer Overflow or Wraparound
  impacts:
    - CAPEC-92 Forced Integer Overflow
  mitigation:
    - Disable the rainbow feature.
    - Reject negative lengths at the call site.
  solution:
    - Upgrade to 0.55 or later.
    - |-
      Rebuild any XS consumers against the fixed headers.

      Downstream packagers should rebuild dependent distributions too.
  references:
    - link: https://example.invalid/advisory
      tags: [vendor-advisory]
  timeline:
    - time: "2026-04-25"
      value: Issue discovered.
  credits:
    - type: reporter
      value: A. Reporter
YAML

is_deeply(
  headers($full),
  ['Description', 'Problem types', 'Impacts', 'Workarounds', 'Solutions', 'References', 'Timeline', 'Credits'],
  'every optional section renders',
);

my $full_body = body($full);
ok(defined $full_body, 'body starts at the description header');
unlike($full_body, qr/\n\n\n/, 'no section is separated from the next by more than one blank line');

for my $header (@{headers($full)}[1 .. $#{headers($full)}]) {
  like($full_body, qr/\S\n\n\Q$header\E\n-+\n/, "exactly one blank line precedes $header");
}

like(
  $full_body,
  qr/^Workarounds\n-+\nDisable the rainbow feature\.\n\nReject negative lengths at the call site\.\n\nSolutions\n/m,
  'multiple values stay one blank line apart, and the last does not double the section gap',
);

like(
  $full_body,
  qr/fixed headers\.\n\nDownstream packagers/,
  'a paragraph break inside a value survives',
);

# The reported shape: most optional sections absent, so the doubled gap landed
# between Solutions and References.
my $sparse = announce('CVE-1900-9942', <<'YAML');
cpansec:
  cve: CVE-1900-9942
  distribution: Unicorn-Foobar
  module: Unicorn::Foobar
  repo: https://example.invalid/repo
  affected:
    - "< 0.55"
  title: Unicorn::Foobar {{VERSION_RANGE}} for Perl is vulnerable
  description: |-
    Unicorn::Foobar {{VERSION_RANGE}} for Perl is vulnerable.
  cwes:
    - CWE-190 Integer Overflow or Wraparound
  solution: Upgrade to 0.55 or later.
  references:
    - link: https://example.invalid/advisory
      tags: [vendor-advisory]
YAML

is_deeply(
  headers($sparse),
  ['Description', 'Problem types', 'Solutions', 'References'],
  'a record with few sections renders only those',
);
unlike(body($sparse), qr/\n\n\n/, 'skipped sections do not widen the gaps between the remaining ones');

done_testing();
