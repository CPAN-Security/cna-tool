use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use JSON::PP qw(decode_json encode_json);
use Test::More;

my ($gitcfg_fh, $gitcfg) = tempfile();
close($gitcfg_fh);
$ENV{GIT_CONFIG_GLOBAL} = $gitcfg;
$ENV{GIT_CONFIG_SYSTEM} = $gitcfg;
$ENV{GIT_CONFIG_NOSYSTEM} = 1;
$ENV{GIT_TERMINAL_PROMPT} = 0;

my $cve = 'CVE-1900-9933';
my $branch = $cve . '-import-default';
my $root = tempdir(CLEANUP => 1);

_init_git_repo($root, $branch);
make_path("$root/cves");

my $json_in = "$root/cves/$cve.json";
_write_json_fixture_with_cve($json_in, $cve);

local $ENV{CPANSEC_CNA_CVE} = '';
my $out = qx(scripts/cna --cpansec-cna-root '$root' import --force 2>&1);
my $rc = $? >> 8;

is($rc, 0, 'import succeeds using branch-derived default CVE');
like($out, qr/Wrote cves\/\Q$cve\E\.yaml/, 'import writes YAML for branch-derived CVE');
like($out, qr/Round-trip guard: enabled/, 'import reports guard enabled');
ok(-f "$root/cves/$cve.yaml", 'yaml output file exists');

done_testing();

sub _init_git_repo ($root, $branch) {
  my $rc = system('git', 'init', '-q', '-b', $branch, $root);
  die "git init failed ($rc)\n" if $rc != 0;
}

sub _write_json_fixture_with_cve ($target, $cve) {
  my $src = 't/var/CVE-2025-40916.source.json';
  copy($src, $target) or die "copy failed: $!";
  open(my $fh, '<', $target) or die "Cannot read $target: $!";
  local $/;
  my $text = <$fh>;
  close($fh);
  my $doc = decode_json($text);
  $doc->{cveMetadata}{cveId} = $cve;
  open(my $out, '>', $target) or die "Cannot write $target: $!";
  print {$out} encode_json($doc);
  close($out);
}
