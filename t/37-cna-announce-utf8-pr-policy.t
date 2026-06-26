use strict;
use v5.42;
use utf8;

use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use Test::More;

# Isolate git config so the host environment cannot influence the test repo.
my ($gitcfg_fh, $gitcfg) = tempfile();
close($gitcfg_fh);
$ENV{GIT_CONFIG_GLOBAL} = $gitcfg;
$ENV{GIT_CONFIG_SYSTEM} = $gitcfg;
$ENV{GIT_CONFIG_NOSYSTEM} = 1;
$ENV{GIT_TERMINAL_PROMPT} = 0;

my $cna = 'scripts/cna';

# A non-ASCII credit value (synthetic researcher name containing U+0142 "ł"
# plus other diacritics) reaches the generated announcement. Before the fix,
# the writer relied on implicit wide-char auto-encoding (emitting a
# "Wide character in print" warning) and the --pr-policy reader slurped raw
# bytes, so the in-memory comparison reported a spurious announce_mismatch.
my $credit_value = 'Tëst Reséarcher Łówski (EXAMPLE)';

my $root = _init_git_repo('main');
_seed_base_commit($root);
my $base_sha = _head_sha($root);

my $cve = 'CVE-1900-9950';
_write_yaml($root, $cve, $credit_value);

# Writer: capture stderr so we can assert there is no "Wide character" warning.
my ($warn_fh, $warn_file) = tempfile();
close($warn_fh);
qx($cna --cpansec-cna-root '$root' announce $cve --write 2>'$warn_file');
is($? >> 8, 0, 'announce --write succeeds for non-ASCII credit');

my $warnings = _slurp($warn_file);
unlike($warnings, qr/Wide character/, 'no "Wide character in print" warning on write');

my $announce_path = "$root/announce/$cve.txt";
ok(-f $announce_path, 'announce file written');

# Written file must be valid UTF-8 and carry the wide character intact.
my $written = _slurp_utf8($announce_path);
like($written, qr/\QŁówski\E/, 'announce file preserves non-ASCII credit');

# CI-equivalent check: must report no announce_mismatch for the new CVE.
my $out = qx($cna --cpansec-cna-root '$root' check $cve --pr-policy --base-sha $base_sha 2>&1);
my $rc = $? >> 8;

is($rc, 0, "pr-policy check passes for non-ASCII announce\n$out");
unlike($out, qr/announce_mismatch/, 'no spurious announce_mismatch for non-ASCII content');

done_testing();

sub _init_git_repo ($branch) {
  my $dir = tempdir(CLEANUP => 1);
  my $rc = system('git', 'init', '-q', '-b', $branch, $dir);
  die "git init failed ($rc)\n" if $rc != 0;
  return $dir;
}

sub _seed_base_commit ($dir) {
  open(my $fh, '>', "$dir/.seed") or die "Cannot write seed: $!";
  print {$fh} "seed\n";
  close($fh);
  _commit_all($dir, 'seed base');
}

sub _write_yaml ($dir, $id, $credit) {
  make_path("$dir/cves");
  my $target = "$dir/cves/$id.yaml";
  open(my $fh, '>:encoding(UTF-8)', $target) or die "Cannot write $target: $!";
  print {$fh} <<"YAML";
cpansec:
  cve: $id
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  repo: https://example.invalid/repo
  affected:
    - "<= 1.0"
  title: Example::Module versions until 1.0 for Perl has an issue
  description: |-
    Example::Module versions until 1.0 for Perl has an issue.
    More detail.
  solution: |-
    Upgrade to 1.1.
  credits:
    - type: finder
      value: "$credit"
  references:
    - link: https://example.com/advisory
      tags: [vendor-advisory]
YAML
  close($fh);
}

sub _commit_all ($dir, $msg) {
  my $rc_add = system('git', '-C', $dir, 'add', '-A');
  die "git add failed ($rc_add)\n" if $rc_add != 0;
  my $rc_commit = system(
    'git', '-C', $dir,
    '-c', 'user.name=Test User',
    '-c', 'user.email=test@example.invalid',
    'commit', '-q', '-m', $msg,
  );
  die "git commit failed ($rc_commit)\n" if $rc_commit != 0;
}

sub _head_sha ($dir) {
  my $sha = qx(git -C '$dir' rev-parse HEAD);
  chomp $sha;
  return $sha;
}

sub _slurp ($path) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $txt = <$fh>;
  close($fh);
  return $txt // '';
}

sub _slurp_utf8 ($path) {
  open(my $fh, '<:encoding(UTF-8)', $path) or die "Cannot read $path: $!";
  local $/;
  my $txt = <$fh>;
  close($fh);
  return $txt // '';
}
