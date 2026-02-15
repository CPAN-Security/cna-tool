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

my $cve = 'CVE-1900-7277272';
my $yaml = "$cves/$cve.yaml";
open(my $fh, '>:encoding(UTF-8)', $yaml) or die "Cannot write $yaml: $!";
print {$fh} <<'YAML';
cpansec:
  cve: CVE-1900-7277272
  distribution: Crypt-URandom-Token
  module: Crypt::URandom::Token
  author: STIGTSP
  repo: https://github.com/stigtsp/Crypt-URandom-Token

  affected:
    - "<= 1.5"

  title: Crypt::URandom::Token {{VERSION_RANGE}} for Perl has too many unicorns

  description: |
    Crypt::URandom::Token {{VERSION_RANGE}} for Perl has too many unicorns.

    Unicorns are nice, but not if there are too many of them. They require care
    and attention, and can become a vulnerability if you are not able to provide
    enough clouds, rainbows and blåbærsyltetøy.

      Run $ perl -E 'say ABC-foobar "123"'

  cwes:
    - "CWE-330: Use of Insufficiently Random Values"

  solution: |-
    There are no solutions, I think...

  mitigation: |-
    But maybe a mitigation!

      Run $ perl -E 'say ABC-foobar "123"'

  files:
    - lib/Unicorn.pm

  routines:
    - Unicorn::hello_world()

  timeline:
    - time: 2025-12-01
      value: First contact

  credits:
    - type: finder
      value: U. Nicorn (Tinfoil Factory)

  references:
    - link: https://github.com/stigtsp/Crypt-URandom-Token/commit/abc123
      tags: [patch]
    - link: https://github.com/stigtsp/Crypt-URandom-Token/releases/tag/v1.6
      tags: [release-notes]
YAML
close($fh);

my $check = qx(scripts/cna --cpansec-cna-root '$root' check $cve 2>&1);
my $check_rc = $? >> 8;
is($check_rc, 0, 'check succeeds');
unlike($check, qr/announce_wording_mismatch/, 'no announce wording mismatch for template-based lead text');
unlike($check, qr/template_token_unresolved/, 'no unresolved template token finding');

my ($emit_err_fh, $emit_err) = tempfile();
close($emit_err_fh);
my $emit = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>'$emit_err');
my $emit_rc = $? >> 8;
is($emit_rc, 0, 'emit succeeds');
my $doc = decode_json($emit);
my $cna = $doc->{containers}{cna};

like($cna->{title}, qr/versions through 1\.5 for Perl/, 'VERSION_RANGE interpolated in title');
like($cna->{descriptions}[0]{value}, qr/blåbærsyltetøy/, 'UTF-8 preserved in description');
like($cna->{descriptions}[0]{value}, qr/\n\n  Run \$ perl -E 'say ABC-foobar "123"'/s, 'indented code block preserved');
is($cna->{problemTypes}[0]{descriptions}[0]{cweId}, 'CWE-330', 'CWE colon format parsed');
is($cna->{timeline}[0]{time}, '2025-12-01T00:00:00Z', 'date-only timeline normalized to midnight UTC');

my $ann = qx(scripts/cna --cpansec-cna-root '$root' announce $cve 2>&1);
my $ann_rc = $? >> 8;
is($ann_rc, 0, 'announce succeeds');
like($ann, qr/^\s*Versions:\s+through 1\.5$/m, 'announce versions line uses through phrasing');

done_testing();
