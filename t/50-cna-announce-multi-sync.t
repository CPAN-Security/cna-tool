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
my $mojo = 'announce-multi/Mojolicious-Plugin-CaptchaPNG';

subtest 'preview lists the plan and writes nothing' => sub {
  my $root = _repo('CVE-1900-9901');
  _seed($root, 'CVE-1900-9902');
  _commit_all($root, 'draft 9902');
  _seed($root, 'CVE-1900-9903');    # never git-added
  my ($rc, $out) = _run($root, 'announce-multi --sync');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^  writes \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'branch CVEs, committed or not');
  unlike($out, qr/9901/, 'the merged CVE is left out');
  like($out, qr/^Run with --write to apply\.$/m, 'says how to apply');
  ok(!-e "$root/announce-multi", 'nothing written');
};

subtest '--write writes the same text as the explicit form' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my $path = "$mojo--CVE-1900-9902+9903.txt";
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$path\E$/m, 'reports the write');
  is(_slurp_raw("$root/$path"), _stdout($root, 'announce-multi CVE-1900-9902 CVE-1900-9903'), 'same text');
  ($rc, $out) = _run($root, 'announce-multi --sync --write');
  like($out, qr/^Unchanged \Q$path\E$/m, 're-running is a no-op');
};

subtest 'a new draft replaces the old batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$mojo\E--CVE-1900-9902\+9903\+9904\.txt$/m, 'writes the new set');
  like($out, qr/^Removed \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'reports the removal');
  ok(!-e "$root/$mojo--CVE-1900-9902+9903.txt", 'old batch gone');
};

subtest 'a dropped draft removes the batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  unlink "$root/cves/CVE-1900-9903.yaml" or die "unlink failed: $!";
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Removed \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'removes the obsolete batch');
  like($out, qr/^Skipped Mojolicious-Plugin-CaptchaPNG: only CVE-1900-9902 /m, 'reports the single CVE');
  ok(!-e "$root/$mojo--CVE-1900-9902+9903.txt", 'batch gone');
};

subtest 'batches of published CVEs are left alone' => sub {
  my $root = _repo(qw(CVE-1900-9900 CVE-1900-9901));
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  ok(-f "$root/$mojo--CVE-1900-9900+9901.txt", 'published-only batch kept');
  unlike($out, qr/^Removed/m, 'nothing removed');
};

subtest 'an explicit set that is already merged is reported, not rewritten' => sub {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9900 CVE-1900-9901);
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _commit_all($root, 'base with batch');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
  my $path = "$mojo--CVE-1900-9900+9901.txt";
  my $before = _slurp_raw("$root/$path");
  _edit("$root/cves/CVE-1900-9901.yaml", sub { s/which is insecure\./which is insecure. Updated./ or die 'no match' });
  my ($rc, $out) = _run($root, 'announce-multi --sync CVE-1900-9900 CVE-1900-9901 --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Already merged \Q$path\E$/m, 'reports the merged batch');
  is(_slurp_raw("$root/$path"), $before, 'merged batch untouched');
};

subtest 'explicit IDs join the branch CVEs' => sub {
  my $root = _repo('CVE-1900-9901');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my ($rc, $out) = _run($root, 'announce-multi --sync CVE-1900-9901 --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$mojo\E--CVE-1900-9901\+9902\+9903\.txt$/m, 'merged CVE included on request');
};

subtest 'one CVE per distribution is reported, not batched' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _seed($root, 'CVE-1900-9905', 't/var/CVE-2025-40906.yaml');
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'batches the pair');
  like($out, qr/^Skipped BSON-XS: only CVE-1900-9905 /m, 'reports the single');
  is_deeply([glob("$root/announce-multi/BSON-XS--*")], [], 'no BSON-XS batch');
};

subtest 'errors' => sub {
  my $trunk = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'trunk', $trunk) == 0 or die 'git init failed';
  _seed($trunk, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _commit_all($trunk, 'trunk');
  my ($rc, $out) = _run($trunk, 'announce-multi --sync');
  isnt($rc, 0, 'refuses without a merged ref');
  like($out, qr{neither origin/main nor main exists}, 'explains why');

  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  ($rc, $out) = _run($root, 'announce-multi --sync --output x.txt');
  isnt($rc, 0, 'refuses --output');
  like($out, qr/--output cannot be combined with --sync/, 'explains --output');
  ($rc, $out) = _run($root, 'announce-multi --sync --force');
  isnt($rc, 0, 'refuses --force');
  like($out, qr/--force cannot be combined with --sync/, 'explains --force');
  ($rc, $out) = _run($root, 'announce-multi --sync CVE-1900-9999');
  isnt($rc, 0, 'refuses a missing explicit CVE');
  like($out, qr/CVE-1900-9999/, 'names it');

  _write_raw("$root/cves/CVE-1900-9906.yaml", "cpansec: [\n");
  ($rc, $out) = _run($root, 'announce-multi --sync --write');
  isnt($rc, 0, 'refuses to write with a broken draft');
  like($out, qr/Cannot sync: these CVEs cannot be loaded/, 'explains');
  like($out, qr/CVE-1900-9906/, 'names the broken draft');
  ok(!-e "$root/announce-multi", 'nothing written');
  ($rc, $out) = _run($root, 'announce-multi --sync');
  is($rc, 0, 'preview still works') or diag $out;
  like($out, qr/Skipped \(cannot be loaded\):\n  CVE-1900-9906/, 'preview reports the broken draft');
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

sub _stdout ($root, $args) {
  my $out = qx($cna --cpansec-cna-root '$root' $args 2>/dev/null);
  die "command failed: $args\n" if $? >> 8;
  return $out;
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
