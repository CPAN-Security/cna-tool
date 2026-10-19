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
my $batch = 'announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9902.txt';

subtest 'a new batch for existing CVEs is allowed' => sub {
  my ($root, $base) = _base(with_batch => 0);
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  my ($rc, $out) = _run($root, "check CVE-1900-9901 --pr-policy --base-sha $base");
  is($rc, 0, 'passes') or diag $out;
  unlike($out, qr/multi_/, 'no batch findings');
  like($out, qr/^Checked batch \Q$batch\E: OK$/m, 'names the checked batch');
};

subtest 'a new stale batch is rejected' => sub {
  my ($root, $base) = _base(with_batch => 0);
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  _append_raw("$root/$batch", "hand edit\n");
  my ($rc, $out) = _run($root, "check CVE-1900-9901 --pr-policy --base-sha $base");
  is($rc, 1, 'fails');
  like($out, qr/multi_mismatch/, 'compared with generated output');
  like($out, qr/^Checked batch \Q$batch\E: 1 error\(s\), 0 warning\(s\)$/m, 'reports the batch result');
};

subtest 'a merged batch must not change' => sub {
  my ($root, $base) = _base(with_batch => 1);
  _append_raw("$root/$batch", "hand edit\n");
  my ($rc, $out) = _run($root, "check CVE-1900-9901 --pr-policy --base-sha $base");
  is($rc, 1, 'fails');
  like($out, qr/multi_not_allowed/, 'policy finding');
  like($out, qr/must not change once merged/, 'explains it');
  unlike($out, qr/multi_mismatch/, 'merged batches are not regenerated');
};

subtest 'a merged batch must not be removed' => sub {
  my ($root, $base) = _base(with_batch => 1);
  unlink "$root/$batch" or die "unlink failed: $!";
  my ($rc, $out) = _run($root, "check CVE-1900-9902 --pr-policy --base-sha $base");
  is($rc, 1, 'fails');
  like($out, qr/must not be removed once merged/, 'explains it');
};

subtest 'removing a merged batch is caught when nothing else is targeted' => sub {
  my ($root, $base) = _base(with_batch => 1);
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'switch failed';
  system('git', '-C', $root, 'rm', '-q', $batch) == 0 or die 'git rm failed';
  system('git', '-C', $root, 'commit', '-q', '-m', 'remove batch') == 0 or die 'commit failed';
  my ($rc, $out) = _run($root, "check --changed --pr-policy --base-sha $base");
  is($rc, 1, 'fails') or diag $out;
  like($out, qr/must not be removed once merged/, 'explains it');
};

subtest 'updating a CVE in a merged batch is allowed' => sub {
  my ($root, $base) = _base(with_batch => 1);
  _edit("$root/cves/CVE-1900-9902.yaml", sub { s/which is insecure\./which is insecure. Updated./ or die 'no match' });
  my ($rc, $out) = _run($root, "check CVE-1900-9902 --pr-policy --base-sha $base");
  is($rc, 0, 'passes') or diag $out;
};

subtest 'a CVE check ignores batches that do not name it' => sub {
  my ($root, $base) = _base(with_batch => 1);
  _append_raw("$root/$batch", "hand edit\n");
  my ($rc, $out) = _run($root, "check CVE-1900-9903 --pr-policy --base-sha $base");
  is($rc, 0, 'passes') or diag $out;
  unlike($out, qr/multi_/, 'no batch findings');
  unlike($out, qr/^Checked batch/m, 'no batch is named');
};

done_testing();

# A repo on main whose base commit holds CVE-1900-9901..9903 and, optionally,
# the 9901+9902 batch. Returns the root and the base commit.
sub _base (%opt) {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902 CVE-1900-9903);
  if ($opt{with_batch}) {
    my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
    die "announce-multi failed: $out" if $rc;
  }
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', 'base') == 0 or die 'git commit failed';
  my $sha = qx(git -C '$root' rev-parse HEAD);
  chomp $sha;
  return ($root, $sha);
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

sub _append_raw ($path, $text) {
  open(my $fh, '>>:raw', $path) or die "Cannot append $path: $!";
  print {$fh} $text;
  close($fh);
}
