use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9927';
my $yml = "$cves/$cve.yml";
open(my $fh, '>', $yml) or die "Cannot write $yml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9927
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  affected:
    - "<= 1.0"
  title: Example::Module versions through 1.0 for Perl has an issue
  description: Example::Module versions through 1.0 for Perl has an issue.
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my $check_target = qx(scripts/cna --cpansec-cna-root '$root' check $cve 2>&1);
my $check_target_rc = $? >> 8;
is($check_target_rc, 2, 'check with explicit CVE fails when only .yml exists');
like($check_target, qr/Cannot find YAML for \Q$cve\E under cves\/ or encrypted\//, 'failure points to missing .yaml source');

my $check_all = qx(scripts/cna --cpansec-cna-root '$root' check --changed 2>&1);
my $check_all_rc = $? >> 8;
is($check_all_rc, 0, 'check --changed ignores .yml files');
like($check_all, qr/No CVE YAML files to check\./, 'check reports no .yaml files');

my $reconcile = qx(scripts/cna --cpansec-cna-root '$root' reconcile 2>&1);
my $reconcile_rc = $? >> 8;
is($reconcile_rc, 0, 'reconcile ignores .yml files');
like($reconcile, qr/No local CVE records found under cves\/\*\.\{yaml,json\}/, 'reconcile scopes to yaml/json');

done_testing();
