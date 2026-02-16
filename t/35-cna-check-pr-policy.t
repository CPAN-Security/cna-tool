use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use Test::More;

my ($gitcfg_fh, $gitcfg) = tempfile();
close($gitcfg_fh);
$ENV{GIT_CONFIG_GLOBAL} = $gitcfg;
$ENV{GIT_CONFIG_SYSTEM} = $gitcfg;
$ENV{GIT_CONFIG_NOSYSTEM} = 1;
$ENV{GIT_TERMINAL_PROMPT} = 0;

my $cna = 'scripts/cna';

subtest 'new CVE requires announce file' => sub {
  my $root = _init_git_repo('main');
  _seed_base_commit($root);
  my $base_sha = _head_sha($root);

  my $cve = 'CVE-1900-9941';
  _write_yaml_from_fixture($root, $cve);

  my $out = qx($cna --cpansec-cna-root '$root' check $cve --pr-policy --base-sha $base_sha 2>&1);
  my $rc = $? >> 8;

  is($rc, 1, 'check fails when announce is missing for new CVE');
  like($out, qr/announce_missing/, 'reports announce_missing policy id');
};

subtest 'new CVE with matching announce passes pr policy' => sub {
  my $root = _init_git_repo('main');
  _seed_base_commit($root);
  my $base_sha = _head_sha($root);

  my $cve = 'CVE-1900-9942';
  _write_yaml_from_fixture($root, $cve);
  make_path("$root/announce");
  my $rc_announce = system(
    'bash', '-lc',
    "$cna --cpansec-cna-root '$root' announce $cve > '$root/announce/$cve.txt'",
  );
  is($rc_announce >> 8, 0, 'announce file generated');

  my $out = qx($cna --cpansec-cna-root '$root' check $cve --pr-policy --base-sha $base_sha 2>&1);
  my $rc = $? >> 8;

  is($rc, 0, "check passes with matching announce\n$out");
  unlike($out, qr/announce_missing|announce_mismatch|announce_not_allowed/, 'no announce policy errors');
};

subtest 'existing CVE announce changes are rejected' => sub {
  my $root = _init_git_repo('main');

  my $cve = 'CVE-1900-9943';
  _write_yaml_from_fixture($root, $cve);
  make_path("$root/announce");
  my $rc_announce = system(
    'bash', '-lc',
    "$cna --cpansec-cna-root '$root' announce $cve > '$root/announce/$cve.txt'",
  );
  is($rc_announce >> 8, 0, 'announce file generated');
  _commit_all($root, 'base cve with announce');
  my $base_sha = _head_sha($root);

  open(my $fh, '>>', "$root/announce/$cve.txt") or die "Cannot modify announce: $!";
  print {$fh} "\nExtra line\n";
  close($fh);

  my $out = qx($cna --cpansec-cna-root '$root' check $cve --pr-policy --base-sha $base_sha 2>&1);
  my $rc = $? >> 8;

  is($rc, 1, 'check fails when existing CVE announce is changed');
  like($out, qr/announce_not_allowed/, 'reports announce_not_allowed policy id');
};

done_testing();

sub _init_git_repo ($branch) {
  my $root = tempdir(CLEANUP => 1);
  my $rc = system('git', 'init', '-q', '-b', $branch, $root);
  die "git init failed ($rc)\n" if $rc != 0;
  return $root;
}

sub _seed_base_commit ($root) {
  open(my $fh, '>', "$root/.seed") or die "Cannot write seed: $!";
  print {$fh} "seed\n";
  close($fh);
  _commit_all($root, 'seed base');
}

sub _write_yaml_from_fixture ($root, $cve) {
  make_path("$root/cves");
  my $target = "$root/cves/$cve.yaml";
  copy('t/var/CVE-2025-40916.yaml', $target) or die "copy failed: $!";
  open(my $fh, '<', $target) or die "Cannot read $target: $!";
  local $/;
  my $content = <$fh>;
  close($fh);
  $content =~ s/^  cve:\s+\S+/  cve: $cve/m
    or die "Cannot rewrite cve in $target";
  open(my $out, '>', $target) or die "Cannot write $target: $!";
  print {$out} $content;
  close($out);
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

sub _head_sha ($root) {
  my $sha = qx(git -C '$root' rev-parse HEAD);
  chomp $sha;
  return $sha;
}
