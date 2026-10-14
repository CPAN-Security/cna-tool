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
subtest 'a branch batch missing a branch CVE warns, without blocking' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  my (undef, $in_sync) = _run($root, 'check CVE-1900-9902');
  my ($strict_in_sync) = _run($root, 'check CVE-1900-9902 --strict');
  unlike($in_sync, qr/multi_incomplete/, 'in sync: no warning');

  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'check CVE-1900-9902');
  is($rc, 0, 'not blocking') or diag $out;
  like($out, qr/multi_incomplete/, 'warns');
  like($out, qr/leaves out CVE-1900-9904/, 'names the missing CVE');
  is(_warnings($out), _warnings($in_sync) + 1, 'counted as one more warning');
  my ($strict_rc) = _run($root, 'check CVE-1900-9902 --strict');
  is($strict_rc, 1, '--strict blocks on the out-of-date batch');
  # Fixture lint warnings may already fail --strict; only compare when in sync passes.
  is($strict_in_sync, 0, '--strict passes while in sync') if $strict_in_sync == 0;
};

subtest 'no batch, no warning' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my (undef, $out) = _run($root, 'check CVE-1900-9902');
  unlike($out, qr/multi_incomplete/, 'batches are optional');
};

subtest 'a batch of published CVEs does not warn' => sub {
  my $root = _repo(qw(CVE-1900-9900 CVE-1900-9901));
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my (undef, $out) = _run($root, 'check CVE-1900-9900');
  unlike($out, qr/multi_incomplete/, 'not the branch batch');
};

subtest 'under --pr-policy the base is the reference' => sub {
  my $root = _repo();
  my $base = qx(git -C '$root' rev-parse HEAD);
  chomp $base;
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --create');
  _seed($root, 'CVE-1900-9904');
  my (undef, $out) = _run($root, "check CVE-1900-9902 --pr-policy --base-sha $base");
  like($out, qr/multi_incomplete/, 'warns against the PR base');
};

done_testing();

sub _warnings ($out) {
  my ($n) = $out =~ /Summary: \d+ error\(s\), (\d+) warning\(s\)/ or die "no summary in:\n$out";
  return $n;
}

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
