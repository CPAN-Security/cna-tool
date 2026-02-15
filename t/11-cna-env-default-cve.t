use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON::PP qw(decode_json);
use Test::More;

my $source_cve = 'CVE-2025-40906';
my $cve = 'CVE-1900-9907';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);
my $yaml = "$cves/$cve.yaml";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
_rewrite_cve_in_yaml($yaml, $cve);

local $ENV{CPANSEC_CNA_CVE} = $cve;

my $err = "/tmp/cpansec-cna-env-$$.err";
my $out = qx(scripts/cna --cpansec-cna-root '$root' emit 2>$err);
my $rc = $? >> 8;

is($rc, 0, 'emit succeeds using CPANSEC_CNA_CVE override');
my $doc = eval { decode_json($out) };
ok($doc, 'emit output is valid JSON');
is($doc->{cveMetadata}{cveId}, $ENV{CPANSEC_CNA_CVE}, 'emitted CVE id follows CPANSEC_CNA_CVE');

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
