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

my $cve = 'CVE-1900-9940';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>:encoding(UTF-8)', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-9940
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  repo: https://example.invalid/repo
  affected:
    - "<= 1.0"
  title: Example::Module versions until 1.0 for Perl has too many unicorns
  description: |
    Example::Module versions until 1.0 for Perl has too many unicorns.

    Unicorns are nice, but not if there are too many of them. They require care
    and attention, and can become a vulnerability if you are not able to provide
    enough clouds, rainbows and blåbærsyltetøy.

      Run $ perl -E 'say ABC-foobar "123"'
      Run $ echo done
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
close($fh);

my ($emit_err_fh, $emit_err) = tempfile();
close($emit_err_fh);
my $out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>'$emit_err');
my $rc = $? >> 8;
is($rc, 0, 'emit succeeds');

my $doc = decode_json($out);
my $desc = $doc->{containers}{cna}{descriptions}[0]{value};

like($desc, qr/require care and attention, and can become/, 'wrapped prose lines are reflowed');
unlike($desc, qr/require care\\nand attention/, 'soft line wraps are removed from prose');
like($desc, qr/\n\n\s+Run \$ perl -E 'say ABC-foobar "123"'\n\s+Run \$ echo done/s, 'indented block keeps explicit newlines');

done_testing();
