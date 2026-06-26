use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use Test::More;

my ($gitcfg_fh, $gitcfg) = tempfile();
print {$gitcfg_fh} <<'GITCONFIG';
[user]
  name = CNA Test
  email = cna-test@example.invalid
[init]
  defaultBranch = main
[commit]
  gpgsign = false
[tag]
  gpgsign = false
GITCONFIG
close($gitcfg_fh);
$ENV{GIT_CONFIG_GLOBAL} = $gitcfg;
$ENV{GIT_CONFIG_SYSTEM} = $gitcfg;
$ENV{GIT_CONFIG_NOSYSTEM} = 1;
$ENV{GIT_TERMINAL_PROMPT} = 0;

my $source_cve = 'CVE-2025-40906';
my $cve = 'CVE-1900-9915';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $root = tempdir(CLEANUP => 1);
# cna inspects the CNA-root's git branch to enforce the "no encrypted ops on
# main" policy, so the root must be a real git repo on a non-main branch.
_init_root_repo($root);
my $enc = "$root/encrypted";
make_path($enc);
my $yaml = "$enc/$cve.yaml";
my $json = "$enc/$cve.json";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
_rewrite_cve_in_yaml($yaml, $cve);

my $out_locked = qx(CPANSEC_CNA_GIT_CRYPT_SHIM=locked scripts/cna --cpansec-cna-root '$root' build $cve 2>&1);
my $rc_locked = $? >> 8;
is($rc_locked, 2, 'build fails when git-crypt shim reports locked');
like($out_locked, qr/Refusing encrypted write: git-crypt appears locked/i, 'locked refusal is explicit');

my $out_unprotected = qx(CPANSEC_CNA_GIT_CRYPT_SHIM=unprotected scripts/cna --cpansec-cna-root '$root' build $cve 2>&1);
my $rc_unprotected = $? >> 8;
is($rc_unprotected, 2, 'build fails when git-crypt shim reports unprotected');
like($out_unprotected, qr/not protected by attributes/i, 'unprotected refusal is explicit');

my $out_ok = qx(CPANSEC_CNA_GIT_CRYPT_SHIM=ok scripts/cna --cpansec-cna-root '$root' build $cve --force 2>&1);
my $rc_ok = $? >> 8;
is($rc_ok, 0, 'build succeeds when git-crypt shim reports ok');
# cna chdir's into the CNA root, so it prints the repo-relative path.
like($out_ok, qr{^Wrote \Qencrypted/$cve.json\E$}m, 'build writes encrypted json with ok shim');
ok(-f $json, 'encrypted json was written');

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

sub _init_root_repo ($dir) {
  my $rc = system('git', 'init', '-q', '-b', 'cve-test-branch', $dir);
  die "git init failed ($rc)\n" if $rc != 0;
}
