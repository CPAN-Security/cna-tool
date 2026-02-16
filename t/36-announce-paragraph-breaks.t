use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9944';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9944
  distribution: Unicorn-Foobar
  module: Unicorn::Foobar
  author: EXAMPLE
  repo: https://example.invalid/repo
  affected:
    - "0.41 < 0.55"
  title: Unicorn::Foobar {{VERSION_RANGE}} for Perl is vulnerable
  description: |-
    Unicorn::Foobar {{VERSION_RANGE}} for Perl is vulnerable to a heap buffer overflow in the XS function unicorn_foobar_rainbow().

    The function does not validate that the length parameter is non-negative. If a negative value (e.g. -1) is supplied, this may cause writes beyond allocated memory and result in denial of service.

    In common usage, the length argument is typically hardcoded by the caller, which reduces the likelihood of attacker-controlled exploitation.
  references:
    - link: https://example.invalid/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my $ann = qx(scripts/cna --cpansec-cna-root '$root' announce $cve 2>&1);
my $rc = $? >> 8;
is($rc, 0, 'announce succeeds');

like(
  $ann,
  qr/unicorn_foobar_rainbow\(\)\.\n\nThe function does not validate/s,
  'announce keeps first paragraph break in description',
);
like(
  $ann,
  qr/denial of service\.\n\nIn common usage/s,
  'announce keeps second paragraph break in description',
);

done_testing();
