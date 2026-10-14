use strict;
use v5.42;
use utf8;

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

subtest 'a fresh batch passes' => sub {
  my $root = _root_with_batch();
  my ($rc, $out) = _run($root, 'check CVE-1900-9901');
  is($rc, 0, 'check passes') or diag $out;
  unlike($out, qr/multi_/, 'no batch findings');
};

subtest 'checking a CVE covers batches that name it' => sub {
  my $root = _root_with_batch();
  _edit("$root/cves/CVE-1900-9902.yaml", sub { s/which is insecure\./which is insecure. Edited./ or die 'no match' });

  my ($rc, $out) = _run($root, 'check CVE-1900-9901');
  is($rc, 1, 'targeted check fails');
  like($out, qr/multi_mismatch/, 'reports the stale batch');

  ($rc, $out) = _run($root, 'check');
  is($rc, 1, 'full check fails');
  like($out, qr/multi_mismatch/, 'full check reports it too');
};

subtest 'filename problems' => sub {
  my $root = _root_with_batch();
  my $text = _slurp_raw("$root/$batch");
  my %bad = (
    'announce-multi/notes.txt' => qr/notes\.txt is not a valid announce-multi filename/,
    'announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901.txt' => qr/must name at least 2 distinct CVE IDs/,
    'announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9902+CVE-1900-9901.txt'
      => qr/not in canonical form; expected Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901\+9902\.txt/,
  );
  for my $path (sort keys %bad) {
    _write_raw("$root/$path", $text);
    my ($rc, $out) = _run($root, 'check');
    is($rc, 1, "$path fails");
    like($out, qr/multi_filename/, "$path reports multi_filename");
    like($out, $bad{$path}, "$path explains the problem");
    unlink "$root/$path";
  }
};

subtest 'CVE problems' => sub {
  my $root = _root_with_batch();
  my $text = _slurp_raw("$root/$batch");
  _seed($root, 'CVE-1900-9903', 't/var/CVE-2025-40906.yaml');
  _write_raw("$root/cves/CVE-1900-9906.yaml", "cpansec: [\n");
  make_path("$root/encrypted");
  copy('t/var/CVE-2025-40916.yaml', "$root/encrypted/CVE-1900-9908.yaml") or die "copy failed: $!";

  my %bad = (
    'Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9909.txt' => [multi_cve_missing => qr{CVE-1900-9909 has no YAML under cves/}],
    'Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9908.txt' => [multi_cve_missing => qr{CVE-1900-9908 resolves to encrypted/}],
    'Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9906.txt' => [multi_cve_invalid => qr/CVE-1900-9906 cannot be rendered/],
    'Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9903.txt' => [multi_distribution => qr/differs for CVE-1900-9903 \(BSON-XS\)/],
    'Other-Dist--CVE-1900-9901+9902.txt' => [multi_distribution => qr/primary distribution Other-Dist/],
  );
  for my $name (sort keys %bad) {
    my ($id, $re) = $bad{$name}->@*;
    my $path = "$root/announce-multi/$name";
    _write_raw($path, $text);
    my ($rc, $out) = _run($root, 'check CVE-1900-9901');
    is($rc, 1, "$name fails");
    like($out, qr/$id/, "$name reports $id");
    like($out, $re, "$name explains the problem");
    unlink $path;
  }
};

subtest 'non-ASCII text round-trips' => sub {
  my $root = tempdir(CLEANUP => 1);
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902);
  _edit("$root/cves/CVE-1900-9902.yaml",
    sub { s/which is insecure\./which is insecure (reported from Ærøskøbing)./ or die 'no match' });
  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  is($rc, 0, 'writes the batch') or diag $out;
  ($rc, $out) = _run($root, 'check CVE-1900-9901');
  is($rc, 0, 'check passes on the written file') or diag $out;
};

subtest 'merged batches are records, not regenerated' => sub {
  my $root = _init_git_repo('main');
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902);
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  _commit_all($root, 'batch on main');

  _edit("$root/cves/CVE-1900-9902.yaml", sub { s/which is insecure\./which is insecure. Updated./ or die 'no match' });
  my ($rc, $out) = _run($root, 'check CVE-1900-9901');
  is($rc, 0, 'updating a CVE in a merged batch keeps check green') or diag $out;
  unlike($out, qr/multi_mismatch/, 'no mismatch for a merged batch');

  _edit("$root/cves/CVE-1900-9902.yaml",
    sub { s/^  distribution: .*/  distribution: Other-Dist/m or die 'no match' });
  ($rc, $out) = _run($root, 'check CVE-1900-9901');
  is($rc, 0, 'a later change of primary distribution keeps check green') or diag $out;
  unlike($out, qr/multi_distribution/, 'no content checks for a merged batch');
};

subtest 'merged means origin/main when there is no local main' => sub {
  my $root = _init_git_repo('trunk');
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902);
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  _commit_all($root, 'batch on the default branch');
  system('git', '-C', $root, 'update-ref', 'refs/remotes/origin/main', 'HEAD') == 0 or die 'update-ref failed';

  _edit("$root/cves/CVE-1900-9902.yaml", sub { s/which is insecure\./which is insecure. Updated./ or die 'no match' });
  my ($rc, $out) = _run($root, 'check CVE-1900-9901');
  is($rc, 0, 'a batch on origin/main counts as merged') or diag $out;
};

subtest '--changed covers a batch changed on its own' => sub {
  my $root = _init_git_repo('main');
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902);
  _commit_all($root, 'seed cves');
  system('git', '-C', $root, 'switch', '-q', '-c', 'batch-work') == 0 or die 'git switch failed';

  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  _append_raw("$root/$batch", "hand edit\n");
  _commit_all($root, 'add batch');

  my ($rc, $out) = _run($root, 'check --changed');
  is($rc, 1, 'the changed batch is checked');
  like($out, qr/multi_mismatch/, 'reports the hand edit');
};

done_testing();

sub _root_with_batch () {
  my $root = tempdir(CLEANUP => 1);
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902);
  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  die "announce-multi failed: $out" if $rc;
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

sub _append_raw ($path, $text) {
  open(my $fh, '>>:raw', $path) or die "Cannot append $path: $!";
  print {$fh} $text;
  close($fh);
}

sub _init_git_repo ($branch) {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', $branch, $root) == 0 or die 'git init failed';
  return $root;
}

sub _commit_all ($root, $msg) {
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', $msg) == 0 or die 'git commit failed';
}
