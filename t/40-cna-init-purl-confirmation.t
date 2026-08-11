use strict;
use v5.42;

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

my $cna = 'scripts/cna';

subtest 'unconfirmed distribution is flagged as an unreliable purl' => sub {
  my $root = _init_git_repo('main');
  my $cve = 'CVE-1900-2222';
  _reserve($root, $cve);
  _commit_all($root, 'reserve');

  # No network under the harness, so the MetaCPAN lookup yields nothing and the
  # distribution falls back to a guess derived from the module name.
  my $out = qx(printf 'n\\nn\\n' | $cna --cpansec-cna-root '$root' init $cve LWP::UserAgent 2>&1);
  is($? >> 8, 0, 'init succeeds');

  like($out, qr/NOT confirmed against MetaCPAN/, 'warns the distribution is unconfirmed');
  like($out, qr{pkg:cpan/LWP-UserAgent}, 'names the purl that may not resolve');
  unlike($out, qr/confirmed via MetaCPAN\./, 'does not claim confirmation');
};

done_testing();

sub _init_git_repo ($branch) {
  my $root = tempdir(CLEANUP => 1);
  my $rc = system('git', 'init', '-q', '-b', $branch, $root);
  die "git init failed ($rc)\n" if $rc != 0;
  return $root;
}

sub _reserve ($root, $cve) {
  make_path("$root/reserved");
  open(my $fh, '>', "$root/reserved/$cve") or die "Cannot reserve $cve: $!";
  close($fh);
}

sub _commit_all ($root, $msg) {
  my $rc_add = system('git', '-C', $root, 'add', '-A');
  die "git add failed ($rc_add)\n" if $rc_add != 0;
  my $rc_commit = system(
    'git', '-C', $root,
    'commit', '-q', '-m', $msg,
  );
  die "git commit failed ($rc_commit)\n" if $rc_commit != 0;
}
