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

subtest 'init stages removal of the reservation it consumes' => sub {
  my $root = _init_git_repo('feature');
  my $cve = 'CVE-1900-3333';
  _reserve($root, $cve);
  _commit_all($root, 'reserve');

  my $out = qx(printf 'n\\n' | $cna --cpansec-cna-root '$root' init $cve Foo::Bar 2>&1);
  is($? >> 8, 0, 'init succeeds');
  like($out, qr/Staged removal of \Qreserved\E.\Q$cve\E/, 'reports the staged removal');

  my $status = qx(git -C '$root' status --short);
  like($status, qr/^D\s+\Qreserved\E.\Q$cve\E$/m, 'reservation is staged for deletion');
  unlike($out, qr/should be retired in the PR/, 'no main warning on a work branch');
};

subtest 'init leaves the reservation alone on main' => sub {
  # On main the reserved file is the record that the ID is held. Staging its
  # deletion there risks losing the reservation without the CVE being issued.
  my $root = _init_git_repo('main');
  my $cve = 'CVE-1900-4444';
  _reserve($root, $cve);
  _commit_all($root, 'reserve');

  my $out = qx(printf 'n\\nn\\n' | $cna --cpansec-cna-root '$root' init $cve Foo::Bar 2>&1);
  is($? >> 8, 0, 'init succeeds');
  like($out, qr/Left \Qreserved\E.\Q$cve\E in place/, 'says why it was left');
  unlike($out, qr/Staged removal/, 'nothing staged for deletion');

  my $status = qx(git -C '$root' status --short);
  unlike($status, qr/^D\s+\Qreserved\E/m, 'reservation is untouched in git');
  ok(-f "$root/reserved/$cve", 'reserved file still on disk');
};

subtest 'init with --force has no reservation to retire' => sub {
  my $root = _init_git_repo('feature');

  my $out = qx(printf 'n\\n' | $cna --cpansec-cna-root '$root' init --force CVE-1900-5555 Foo::Bar 2>&1);
  is($? >> 8, 0, 'init succeeds without a reserved file');
  unlike($out, qr/Staged removal|could not .git rm/, 'says nothing about reservations');
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
