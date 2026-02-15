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

my $cve = 'CVE-1900-9922';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9922
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  affected:
    - "<= 1.0"
  title: Example::Module {{VERSN_RANGE}} for Perl has an issue
  description: |
    Example::Module {{VERSN_RANGE}} for Perl has an issue.
    More detail.
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my $check_out = qx(scripts/cna --cpansec-cna-root '$root' check $cve 2>&1);
my $check_rc = $? >> 8;
is($check_rc, 0, 'check remains non-blocking by default');
like($check_out, qr/template_token_unresolved/, 'check warns about unresolved/unknown template token');
like($check_out, qr/\{\{VERSN_RANGE\}\}/, 'warning includes misspelled token');

my $emit_out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>&1);
my $emit_rc = $? >> 8;
is($emit_rc, 0, 'emit succeeds with unsupported template token (warn-only)');
like($emit_out, qr/unsupported template token \{\{VERSN_RANGE\}\}/, 'emit warns about unsupported token');
like($emit_out, qr/\{\{VERSN_RANGE\}\}/, 'unsupported token remains unchanged in output');

my $obj = CPANSec::CVE->from_yaml_file($yaml);
my @warnings = Test::Warnings::warnings { $obj->to_cve5_json };
my $joined = join '', @warnings;
like($joined, qr/unsupported template token \{\{VERSN_RANGE\}\}/, 'converter warns via Perl warn for unsupported token');

done_testing();
