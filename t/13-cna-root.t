use strict;
use v5.42;

use Cwd qw(abs_path);
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $script = abs_path('scripts/cna');

my $source_cve = 'CVE-2025-40906';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $cve_env = 'CVE-1900-9911';
my $cve_opt = 'CVE-1900-9912';
my $data_root = tempdir(CLEANUP => 1);
my $cves = "$data_root/cves";
make_path($cves);
my $yaml_env = "$cves/$cve_env.yaml";
my $yaml_opt = "$cves/$cve_opt.yaml";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml_env) or die "Cannot copy $fixture_yaml -> $yaml_env: $!";
copy($fixture_yaml, $yaml_opt) or die "Cannot copy $fixture_yaml -> $yaml_opt: $!";
_rewrite_cve_in_yaml($yaml_env, $cve_env);
_rewrite_cve_in_yaml($yaml_opt, $cve_opt);

my $err1 = "/tmp/cpansec-cna-root-env-$$.err";
my $out1 = qx(cd /tmp && CPANSEC_CNA_ROOT='$data_root' '$script' emit $cve_env 2>'$err1');
my $rc1 = $? >> 8;
is($rc1, 0, 'emit succeeds from outside repo with CPANSEC_CNA_ROOT');
like($out1, qr/"cveId"\s*:\s*"\Q$cve_env\E"/, 'env-root emit uses expected CVE');

my $err2 = "/tmp/cpansec-cna-root-opt-$$.err";
my $out2 = qx(cd /tmp && '$script' --cpansec-cna-root '$data_root' emit $cve_opt 2>'$err2');
my $rc2 = $? >> 8;
is($rc2, 0, 'emit succeeds from outside repo with --cpansec-cna-root');
like($out2, qr/"cveId"\s*:\s*"\Q$cve_opt\E"/, 'option-root emit uses expected CVE');

unlink $err1;
unlink $err2;

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
