use strict;
use v5.42;
use utf8;

use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use JSON::PP qw(decode_json);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9930';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>:encoding(UTF-8)', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9930
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  repo: https://example.invalid/repo
  affected:
    - "<= 1.0"
  title: Example::Module versions until 1.0 for Perl has blåbærsyltetøy
  description: |-
    Example::Module versions until 1.0 for Perl has blåbærsyltetøy.
    More blåbærsyltetøy.
  solution: |-
    Use blåbærsyltetøy.
  mitigation: |-
    Avoid blåbærsyltetøy.
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my ($emit_err_fh, $emit_err) = tempfile();
close($emit_err_fh);
my $out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>'$emit_err');
my $rc = $? >> 8;
is($rc, 0, 'emit succeeds with UTF-8 YAML');

my $doc = decode_json($out);
my $cna = $doc->{containers}{cna};
like($cna->{title}, qr/blåbærsyltetøy/, 'title preserves UTF-8');
like($cna->{descriptions}[0]{value}, qr/blåbærsyltetøy/, 'description preserves UTF-8');
like($cna->{solutions}[0]{value}, qr/blåbærsyltetøy/, 'solution preserves UTF-8');
like($cna->{workarounds}[0]{value}, qr/blåbærsyltetøy/, 'mitigation preserves UTF-8');

done_testing();
