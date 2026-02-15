use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $source_cve = 'CVE-2025-40906';
my $cve = 'CVE-1900-9908';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);
my $yaml = "$cves/$cve.yaml";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
_rewrite_cve_in_yaml($yaml, $cve);

my $out = qx(scripts/cna --cpansec-cna-root '$root' announce $cve 2>&1);
my $rc = $? >> 8;

is($rc, 0, 'announce to stdout succeeds');
like($out, qr/^Subject: \Q$cve\E:/m, 'announce stdout has subject');

my $tmp = tempdir(CLEANUP => 1);
my $target = "$tmp/$cve.txt";
my $out2 = qx(scripts/cna --cpansec-cna-root '$root' announce $cve --output $target 2>&1);
my $rc2 = $? >> 8;

is($rc2, 0, 'announce --output succeeds');
like($out2, qr/^Wrote /m, 'announce --output reports file written');
ok(-f $target, 'announce output file created');

open(my $fh, '<', $target) or die $!;
local $/;
my $text = <$fh>;
close($fh);
like($text, qr/^Subject: \Q$cve\E:/m, 'announce file contains subject');

done_testing();

sub _rewrite_cve_in_yaml ($path, $cve) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $content = <$fh>;
  close($fh);
  $content =~ s/^  cve:\s+\S+/  cve: $cve/m
    or die "Cannot rewrite cve in $path";
  open(my $wh, '>', $path) or die "Cannot write $path: $!";
  print {$wh} $content;
  close($wh);
}
