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

subtest 'nothing new' => sub {
  my $root = _repo('CVE-1900-9901');
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr/^Branch: work$/m, 'names the branch');
  like($out, qr/^Merged ref: main$/m, 'names the merged ref');
  like($out, qr/^New CVEs on this branch: none$/m, 'nothing new');
  like($out, qr/Nothing to batch from this branch/, 'says so');
  like($out, qr/^  cpansec-cna announce-multi <CVE-ID> <CVE-ID>\.\.\. --write$/m, 'suggests the explicit form');
};

subtest 'new CVEs without a batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _seed($root, 'CVE-1900-9905', 't/var/CVE-2025-40906.yaml');
  make_path("$root/encrypted");
  copy('t/var/CVE-2025-40916.yaml', "$root/encrypted/CVE-1900-9908.yaml") or die "copy failed: $!";
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr/^  Mojolicious-Plugin-CaptchaPNG +CVE-1900-9902, CVE-1900-9903$/m, 'groups by distribution');
  like($out, qr/^  BSON-XS +CVE-1900-9905 \(only one, nothing to batch\)$/m, 'notes single CVEs');
  like($out, qr{^  1 CVE under encrypted/ skipped \(batches are public-only\)$}m, 'counts encrypted drafts');
  like($out, qr/^Next:\n  cpansec-cna announce-multi --create   \(batches are optional\)\n      writes \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m,
    'suggests creating a batch');
  ok(!-e "$root/announce-multi", 'writes nothing');
};

subtest 'in sync, then stale' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  my $path = "$mojo--CVE-1900-9902+9903.txt";
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^  \Q$path\E\n      unmerged, in sync$/m, 'in sync');
  like($out, qr/^  All batches are in sync\.\n  cpansec-cna check --changed$/m, 'suggests check');

  _edit("$root/cves/CVE-1900-9903.yaml", sub { s/which is insecure\./which is insecure. Edited./ or die 'no match' });
  ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^      unmerged, stale: content out of date$/m, 'stale');
  like($out, qr/^      writes \Q$path\E$/m, 'suggests rewriting it');
  like($out, qr/^  cpansec-cna announce-multi --sync$/m, 'suggests --sync');
};

subtest 'out of sync' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^      unmerged, out of sync: missing CVE-1900-9904$/m, 'names the missing CVE');
  like($out, qr/^      writes \Q$mojo\E--CVE-1900-9902\+9903\+9904\.txt$/m, 'suggests the new batch');
  like($out, qr/^      removes \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'and the removal');
  unlike($out, qr/batches are optional/, 'no optional note when a batch exists');
  like($out, qr/^  cpansec-cna announce-multi --sync$/m, 'suggests --sync');
};

subtest 'a carried published CVE stays in sync' => sub {
  my $root = _repo('CVE-1900-9901');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create CVE-1900-9901');
  my $path = "$mojo--CVE-1900-9901+9902+9903.txt";
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^  \Q$path\E\n      unmerged, in sync$/m, 'in sync');
  like($out, qr/^  All batches are in sync\.$/m, 'nothing to do');
};

subtest 'published-only batches are listed but left alone' => sub {
  my $root = _repo(qw(CVE-1900-9900 CVE-1900-9901));
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^  \Q$mojo\E--CVE-1900-9900\+9901\.txt\n      unmerged, not tied to this branch \(left alone by --sync\)$/m,
    'explains it is not the branch');
};

subtest 'merged batches not touching the branch are not listed' => sub {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9900 CVE-1900-9901);
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _commit_all($root, 'base with batch');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
  my ($rc, $out) = _run($root, 'announce-multi');
  unlike($out, qr/CVE-1900-9900\+9901/, 'not listed');
};

subtest 'no merged ref' => sub {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'trunk', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _commit_all($root, 'trunk');
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr{neither origin/main nor main exists}, 'explains');
  like($out, qr/^  cpansec-cna announce-multi <CVE-ID> <CVE-ID>\.\.\. --write$/m, 'suggests the explicit form');
};

subtest 'invalid draft' => sub {
  my $root = _repo();
  make_path("$root/cves");
  _write_raw("$root/cves/CVE-1900-9906.yaml", "cpansec: [\n");
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr/^  CVE-1900-9906: cannot be loaded: /m, 'lists the broken draft');
  like($out, qr/^  Fix the CVEs that cannot be loaded, then sync\.$/m, 'says to fix it');
  unlike($out, qr/Nothing to batch/, 'no contradictory advice');
};

subtest '--write without CVEs is still a usage error' => sub {
  my $root = _repo();
  my ($rc, $out) = _run($root, 'announce-multi --write');
  isnt($rc, 0, 'refuses');
  like($out, qr/Usage: cna announce-multi/, 'shows usage');
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

sub _write_raw ($path, $text) {
  open(my $fh, '>:raw', $path) or die "Cannot write $path: $!";
  print {$fh} $text;
  close($fh);
}

sub _commit_all ($root, $msg) {
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', $msg) == 0 or die 'git commit failed';
}
