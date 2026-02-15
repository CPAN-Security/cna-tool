use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use File::Copy qw(copy);
use JSON::PP qw(decode_json);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9928';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9928
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  repo: https://github.com/example/project
  affected:
    - "<= 1.0"
  title: Example::Module versions through 1.0 for Perl has an issue
  description: |
    Example::Module versions through 1.0 for Perl has an issue, with details.
  references:
    - link: https://github.com/example/project/commit/abc123
      tags: [patch]
YAML
close($fh);

my $build_out = qx(scripts/cna --cpansec-cna-root '$root' build $cve --force 2>&1);
is($? >> 8, 0, 'build creates JSON from YAML');
like($build_out, qr/Wrote .*\/\Q$cve\E\.json/, 'build wrote json file');

my $check_ok = qx(scripts/cna --cpansec-cna-root '$root' check $cve 2>&1);
is($? >> 8, 0, 'check succeeds for synchronized YAML/JSON');
unlike($check_ok, qr/json_out_of_date/, 'no stale-json warning when JSON is in sync');

my $json = "$cves/$cve.json";
my $doc = _read_json($json);
$doc->{containers}{cna}{title} = 'manually drifted title';
_write_json($json, $doc);

my $check_drift = qx(scripts/cna --cpansec-cna-root '$root' check $cve 2>&1);
is($? >> 8, 0, 'check remains advisory when JSON is out of date');
like($check_drift, qr/json_out_of_date/, 'check warns when JSON is stale vs YAML');

my $import_root = tempdir(CLEANUP => 1);
make_path("$import_root/cves");
my $import_json = "$import_root/cves/CVE-2025-40906.json";
copy('t/var/CVE-2025-40906.source.json', $import_json) or die "Cannot copy import fixture: $!";
my $import_out = qx(scripts/cna --cpansec-cna-root '$import_root' import CVE-2025-40906 --force 2>&1);
is($? >> 8, 0, 'import from JSON fixture succeeds');
like($import_out, qr/Round-trip guard: enabled/, 'import reports guard enabled');

my $check_after_import = qx(scripts/cna --cpansec-cna-root '$import_root' check CVE-2025-40906 2>&1);
is($? >> 8, 0, 'check succeeds after import');
unlike($check_after_import, qr/json_out_of_date/, 'no false json_out_of_date warning right after import');

done_testing();

sub _read_json ($path) {
  open(my $rfh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $doc = decode_json(<$rfh>);
  close($rfh);
  return $doc;
}

sub _write_json ($path, $doc) {
  open(my $wfh, '>', $path) or die "Cannot write $path: $!";
  print {$wfh} JSON::PP->new->canonical->pretty->encode($doc);
  close($wfh);
}
