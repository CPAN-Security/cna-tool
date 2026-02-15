use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use CPANSec::CVE ();
use Test::More;
use Test::Warnings ();

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9919';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9919
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  affected:
    - "<= 1.0"
  title: Example::Module {{VERSION_RANGE for Perl has an issue
  description: |
    Example::Module {{VERSION_RANGE}} for Perl has an issue.
    More detail.
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my $out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>&1);
my $rc = $? >> 8;

is($rc, 0, 'emit succeeds when template delimiters are malformed (warn-only)');
like($out, qr/unmatched template delimiters/, 'warns about malformed template delimiters');
like($out, qr/\{\{VERSION_RANGE for Perl has an issue/, 'malformed token text remains unchanged');

my $obj = CPANSec::CVE->from_yaml_file($yaml);
my @warnings = Test::Warnings::warnings { $obj->to_cve5_json };
my $joined = join '', @warnings;
like($joined, qr/unmatched template delimiters/, 'converter warns via Perl warn for malformed delimiters');

done_testing();
