use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $cna = 'scripts/cna';

subtest 'clean main offers branch switch prompt' => sub {
  my $root = _init_git_repo('main');
  my $cve = 'CVE-1900-1111';
  _reserve($root, $cve);
  _commit_all($root, 'reserve');

  my $out = qx(printf 'n\\nn\\n' | $cna --cpansec-cna-root '$root' init $cve Foo::Bar 2>&1);
  my $rc = $? >> 8;

  is($rc, 0, 'init succeeds');
  like($out, qr/Switch to '\Q$cve\E--[^']+'\?/, 'branch switch prompt is shown on clean main');
};

subtest 'dirty main skips branch switch prompt' => sub {
  my $root = _init_git_repo('main');
  my $cve = 'CVE-1900-1112';
  _reserve($root, $cve);
  _commit_all($root, 'reserve');
  open(my $fh, '>', "$root/dirty.txt") or die "Cannot write dirty file: $!";
  print {$fh} "dirty\n";
  close($fh);

  my $out = qx(printf 'y\\nn\\n' | $cna --cpansec-cna-root '$root' init $cve Foo::Bar 2>&1);
  my $rc = $? >> 8;

  is($rc, 0, 'init succeeds');
  unlike($out, qr/Switch to '\Q$cve\E--[^']+'\?/, 'branch switch prompt is not shown on dirty main');
  like($out, qr/Skipping branch switch prompt: working tree has uncommitted changes\./, 'skip reason is reported');
  like($out, qr/Continue on current branch without switching\?/, 'continue confirmation is shown');
};

subtest 'non-main skips branch switch prompt' => sub {
  my $root = _init_git_repo('topic');
  my $cve = 'CVE-1900-1113';
  _reserve($root, $cve);
  _commit_all($root, 'reserve');

  my $out = qx(printf 'n\\n' | $cna --cpansec-cna-root '$root' init $cve Foo::Bar 2>&1);
  my $rc = $? >> 8;

  is($rc, 0, 'init succeeds');
  unlike($out, qr/Switch to '\Q$cve\E--[^']+'\?/, 'branch switch prompt is not shown on non-main');
  like($out, qr/Skipping branch switch prompt: current branch is 'topic' \(only offered from 'main'\)\./, 'skip reason is reported');
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
    '-c', 'user.name=Test User',
    '-c', 'user.email=test@example.invalid',
    'commit', '-q', '-m', $msg,
  );
  die "git commit failed ($rc_commit)\n" if $rc_commit != 0;
}
