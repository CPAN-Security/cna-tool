use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use JSON::PP qw(decode_json);
use Test::More;

my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);

my $cve = 'CVE-1900-9920';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9920
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  affected:
    - "<= 1.0"
    - "1.2 <= 1.3"
    - "1.5 < *"
  title: Example::Module {{VERSION_RANGE}} for Perl has an issue
  description: |
    Example::Module {{VERSION_RANGE}} for Perl has an issue.
    More detail.
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my ($emit_err_fh, $emit_err) = tempfile();
close($emit_err_fh);
my $out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve --cna-container-only 2>'$emit_err');
my $rc = $? >> 8;
is($rc, 0, 'emit succeeds with multiple affected version ranges');

my $cna = decode_json($out);
like(
  $cna->{title},
  qr/versions through 1\.0, from 1\.2 through 1\.3, from 1\.5/,
  'VERSION_RANGE interpolates all affected ranges in title',
);
like(
  $cna->{descriptions}[0]{value},
  qr/versions through 1\.0, from 1\.2 through 1\.3, from 1\.5/,
  'VERSION_RANGE interpolates all affected ranges in description',
);

done_testing();
