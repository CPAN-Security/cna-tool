use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use JSON::PP qw(decode_json);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9918';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9918
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  affected:
    - "<= 1.0"
  title: Example::Module versions through 1.0 for Perl do a thing
  description: |
    Example::Module versions through 1.0 for Perl do a thing.
    More detail.
  solution: |
    
  mitigation: |
    
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my $check_out = qx(scripts/cna --cpansec-cna-root '$root' check $cve 2>&1);
my $check_rc = $? >> 8;
is($check_rc, 0, 'check succeeds with empty block solution/mitigation');
like($check_out, qr/missing_solution_or_mitigation/, 'empty blocks are treated as missing by lint');

my ($emit_err_fh, $emit_err) = tempfile();
close($emit_err_fh);
my $json_out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve --cna-container-only 2>'$emit_err');
my $json_rc = $? >> 8;
is($json_rc, 0, 'emit succeeds');
my $cna = decode_json($json_out);

ok(!exists $cna->{solutions}, 'empty solution block does not create solutions array');
ok(!exists $cna->{workarounds}, 'empty mitigation block does not create workarounds array');

done_testing();
