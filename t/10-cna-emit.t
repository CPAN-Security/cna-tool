use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON::PP qw(decode_json);
use Test::More;

my $source_cve = 'CVE-2025-40906';
my $cve = 'CVE-1900-9906';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);
my $yaml = "$cves/$cve.yaml";
my $json_file = "$cves/$cve.json";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
_rewrite_cve_in_yaml($yaml, $cve);
open(my $jfh, '>', $json_file) or die "Cannot write $json_file: $!";
print {$jfh} "{}\n";
close($jfh);

ok(-f $yaml, 'fixture yaml exists');
ok(-f $json_file, 'fixture json exists');
my $before_mtime = (stat($json_file))[9];

my $err = "/tmp/cpansec-cna-emit-$$.err";
my $out = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>$err);
my $rc = $? >> 8;

is($rc, 0, 'emit exits successfully');
my $doc = eval { decode_json($out) };
ok($doc, 'emit stdout is valid JSON');
is($doc->{cveMetadata}{cveId}, $cve, 'emit output contains expected CVE id');

# emit must not write/modify target json file as a side effect
my $after_mtime = (stat($json_file))[9];
is($after_mtime, $before_mtime, 'emit did not modify cves/<CVE>.json');

unlink $err;

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
