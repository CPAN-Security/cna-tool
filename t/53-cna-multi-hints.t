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
GITCONFIG
close($gitcfg_fh);
$ENV{GIT_CONFIG_GLOBAL} = $gitcfg;
$ENV{GIT_CONFIG_SYSTEM} = $gitcfg;
$ENV{GIT_CONFIG_NOSYSTEM} = 1;
$ENV{GIT_TERMINAL_PROMPT} = 0;

my $cna = 'scripts/cna';

my $note_stale = qr/^Note: this branch's announce-multi batch is out of date; run: cpansec-cna announce-multi --sync$/m;

subtest 'build and announce hint when the branch batch is out of date' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  my ($rc, $out) = _run($root, 'build CVE-1900-9902');
  is($rc, 0, 'build succeeds') or diag $out;
  unlike($out, qr/^Note: /m, 'no hint while in sync');

  _edit("$root/cves/CVE-1900-9903.yaml", sub { s/which is insecure\./which is insecure. Edited./ or die 'no match' });
  ($rc, $out) = _run($root, 'build CVE-1900-9903');
  is($rc, 0, 'build still succeeds') or diag $out;
  like($out, $note_stale, 'build hints');
  ($rc, $out) = _run($root, 'announce CVE-1900-9903 --write');
  is($rc, 0, 'announce still succeeds') or diag $out;
  like($out, $note_stale, 'announce --write hints');
};

subtest 'a new draft makes the batch out of date' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'build CVE-1900-9904');
  like($out, $note_stale, 'hints about the missing CVE');
};

subtest 'no batch, no hints' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my ($rc, $out) = _run($root, 'build CVE-1900-9902');
  is($rc, 0, 'build succeeds') or diag $out;
  unlike($out, qr/announce-multi/, 'silent for people who do not batch');
};

subtest 'init hints when the branch has a batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  my $out = qx(printf 'n\\nn\\n' | $cna --cpansec-cna-root '$root' init --force CVE-1900-9904 Foo::Bar 2>&1);
  is($? >> 8, 0, 'init succeeds') or diag $out;
  like($out, qr/^Note: this branch has an announce-multi batch; once CVE-1900-9904 is filled in, run: cpansec-cna announce-multi --sync$/m,
    'init hints');
};

subtest 'init is silent without a batch' => sub {
  my $root = _repo();
  my $out = qx(printf 'n\\nn\\n' | $cna --cpansec-cna-root '$root' init --force CVE-1900-9904 Foo::Bar 2>&1);
  is($? >> 8, 0, 'init succeeds') or diag $out;
  unlike($out, qr/announce-multi/, 'no hint');
};

subtest 'check suggests --sync for a stale batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  _edit("$root/cves/CVE-1900-9903.yaml", sub { s/which is insecure\./which is insecure. Edited./ or die 'no match' });
  my ($rc, $out) = _run($root, 'check CVE-1900-9902');
  like($out, qr/multi_mismatch/, 'stale batch');
  like($out, qr/regenerate it with: cpansec-cna announce-multi --sync \(branch batches\) or announce-multi CVE-1900-9902 CVE-1900-9903 --write/,
    'names both ways to regenerate');
};

done_testing();

sub _repo (@base) {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for @base;
  _write_raw("$root/.seed", "seed\n");
  _commit_all($root, 'base');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
  return $root;
}

sub _seed ($root, $cve, $fixture = 't/var/CVE-2025-40916.yaml') {
  make_path("$root/cves");
  my $target = "$root/cves/$cve.yaml";
  copy($fixture, $target) or die "copy failed: $!";
  _edit($target, sub { s/^  cve:\s+\S+/  cve: $cve/m or die "Cannot rewrite cve in $target" });
}

sub _edit ($path, $code) {
  open(my $fh, '<:encoding(UTF-8)', $path) or die "Cannot read $path: $!";
  local $/;
  local $_ = <$fh>;
  close($fh);
  $code->();
  open(my $out, '>:encoding(UTF-8)', $path) or die "Cannot write $path: $!";
  print {$out} $_;
  close($out);
}

sub _run ($root, $args) {
  my $out = qx($cna --cpansec-cna-root '$root' $args 2>&1);
  return ($? >> 8, $out);
}

sub _slurp_raw ($path) {
  open(my $fh, '<:raw', $path) or die "Cannot read $path: $!";
  local $/;
  return <$fh>;
}

sub _write_raw ($path, $text) {
  open(my $fh, '>:raw', $path) or die "Cannot write $path: $!";
  print {$fh} $text;
  close($fh);
}

sub _commit_all ($root, $msg) {
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', $msg) == 0 or die 'git commit failed';
}
