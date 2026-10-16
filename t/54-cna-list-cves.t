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

subtest 'committed, staged, unstaged and untracked changes' => sub {
  my $root = _repo();
  _write_raw("$root/reserved/CVE-1900-9902", '');
  _write_raw("$root/reserved/CVE-1900-9903", '');
  _commit_all($root, 'reserve');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';

  _seed($root, 'CVE-1900-9902');
  system('git', '-C', $root, 'rm', '-q', 'reserved/CVE-1900-9902') == 0 or die 'git rm failed';
  _commit_all($root, 'draft 9902');                                # committed
  _seed($root, 'CVE-1900-9903');
  system('git', '-C', $root, 'add', 'cves/CVE-1900-9903.yaml') == 0 or die 'git add failed';  # staged
  _edit("$root/cves/CVE-1900-9901.yaml", sub { s/which is insecure\./which is insecure. Updated./ or die });  # unstaged
  _write_raw("$root/announce/CVE-1900-9903.txt", "text\n");       # untracked
  _write_raw("$root/announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9902+9903.txt", "text\n");

  my ($rc, $out) = _run($root, 'list-cves --branch');
  is($rc, 0, 'succeeds') or diag $out;
  is($out, <<'EOT', 'one block per CVE with git status letters');
CVE-1900-9901
  M cves/CVE-1900-9901.yaml
CVE-1900-9902
  ? announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9902+9903.txt
  A cves/CVE-1900-9902.yaml
  D reserved/CVE-1900-9902
CVE-1900-9903
  ? announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9902+9903.txt
  ? announce/CVE-1900-9903.txt
  A cves/CVE-1900-9903.yaml
EOT

  ($rc, $out) = _run($root, 'list-cves --branch --ids');
  is($out, "CVE-1900-9901\nCVE-1900-9902\nCVE-1900-9903\n", '--ids prints bare IDs');
};

subtest 'changes on main after the branch split are not listed' => sub {
  my $root = _repo();
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
  system('git', '-C', $root, 'switch', '-q', 'main') == 0 or die 'git switch failed';
  _seed($root, 'CVE-1900-9905');
  _commit_all($root, 'other work on main');
  system('git', '-C', $root, 'switch', '-q', 'work') == 0 or die 'git switch failed';

  my ($rc, $out) = _run($root, 'list-cves --branch');
  is($rc, 0, 'succeeds') or diag $out;
  is($out, "No CVEs changed on this branch (since main).\n", 'nothing to list');
  ($rc, $out) = _run($root, 'list-cves --branch --ids');
  is($out, '', '--ids prints nothing');
};

subtest 'usage errors' => sub {
  my $root = _repo();
  my ($rc, $out) = _run($root, 'list-cves');
  isnt($rc, 0, '--branch is required');
  like($out, qr/Usage: list-cves --branch/, 'prints usage');
  ($rc, $out) = _run($root, 'list-cves --branch --bogus');
  like($out, qr/Unknown option '--bogus'/, 'unknown option');

  my $plain = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'trunk', $plain) == 0 or die 'git init failed';
  ($rc, $out) = _run($plain, 'list-cves --branch');
  isnt($rc, 0, 'refuses without a merged ref');
  like($out, qr/needs origin\/main or main/, 'says why');
};

done_testing;

sub _repo () {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  make_path(map { "$root/$_" } qw(reserved announce announce-multi));
  _seed($root, 'CVE-1900-9901');
  _commit_all($root, 'base');
  return $root;
}

sub _seed ($root, $cve) {
  make_path("$root/cves");
  my $target = "$root/cves/$cve.yaml";
  copy('t/var/CVE-2025-40916.yaml', $target) or die "copy failed: $!";
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

sub _write_raw ($path, $text) {
  open(my $fh, '>:raw', $path) or die "Cannot write $path: $!";
  print {$fh} $text;
  close($fh);
}

sub _commit_all ($root, $msg) {
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', $msg) == 0 or die 'git commit failed';
}
