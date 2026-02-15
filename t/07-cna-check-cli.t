use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $tmp_cve = 'CVE-1900-9998';
my $fixture = "t/var/$tmp_cve.yaml";
my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);
my $yaml = "$cves/$tmp_cve.yaml";

ok(-f $fixture, 'fixture yaml exists in t/var');
copy($fixture, $yaml) or die "Cannot copy $fixture -> $yaml: $!";

my $out = qx(scripts/cna --cpansec-cna-root '$root' check $tmp_cve --format github 2>&1);
my $rc = $? >> 8;

is($rc, 0, 'check is non-blocking for lint findings by default');
like($out, qr/::error file=cves\/CVE-1900-9998\.yaml,line=\d+,title=title_repeated_in_description::/,
  'github output contains error annotation');
like($out, qr/Summary: /, 'output includes summary');

my $strict_out = qx(scripts/cna --cpansec-cna-root '$root' check $tmp_cve --strict 2>&1);
my $strict_rc = $? >> 8;
ok($strict_rc != 0, 'check --strict remains blocking for lint findings');
like($strict_out, qr/strict mode/i, 'strict output indicates strict mode');

done_testing();
