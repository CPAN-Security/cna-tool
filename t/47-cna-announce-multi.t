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

subtest 'stdout' => sub {
  my $root = _root();
  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9902 CVE-1900-9901');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/\ASubject: Mojolicious::Plugin::CaptchaPNG version 1.05 for Perl \(2 CVEs\)\n/, 'batch subject');

  my ($header) = split /^={72}$/m, $out, 2;
  like($header, qr/^CVE-1900-9901\n.*^CVE-1900-9902\n/ms, 'index sorted by CVE ID');
  unlike($out, qr/^Subject: CVE-/m, 'no per-CVE subject lines');

  for my $cve (qw(CVE-1900-9901 CVE-1900-9902)) {
    my $single = _stdout($root, "announce $cve");
    (my $body = $single) =~ s/\ASubject: [^\n]*\n\n\n// or die "no subject line in single announcement";
    ok(index($out, $body) >= 0, "$cve announcement included unchanged");
  }
};

subtest '--write' => sub {
  my $root = _root();
  my $stdout = _stdout($root, 'announce-multi CVE-1900-9901 CVE-1900-9902');
  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9902 CVE-1900-9901 --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$batch\E$/m, 'reports the canonical batch path');
  is(_slurp_raw("$root/$batch"), $stdout, 'file matches stdout output');
};

subtest 'a merged batch is not silently overwritten' => sub {
  my $root = _root();
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', 'batch') == 0 or die 'git commit failed';
  my $before = _slurp_raw("$root/$batch");

  my $yaml = "$root/cves/CVE-1900-9902.yaml";
  my $content = _slurp_raw($yaml);
  $content =~ s/which is insecure\./which is insecure. Updated./ or die 'no match';
  open(my $fh, '>:raw', $yaml) or die "Cannot write $yaml: $!";
  print {$fh} $content;
  close($fh);

  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  isnt($rc, 0, 'refuses');
  like($out, qr/Refusing to overwrite/, 'says why');
  is(_slurp_raw("$root/$batch"), $before, 'file unchanged');

  ($rc, $out) = _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write --force');
  is($rc, 0, '--force overwrites') or diag $out;
  like(_slurp_raw("$root/$batch"), qr/Updated\./, 'file updated');
};

subtest '--output' => sub {
  my $root = _root();
  my $target = tempdir(CLEANUP => 1) . '/batch.txt';
  my ($rc, $out) = _run($root, "announce-multi CVE-1900-9901 CVE-1900-9902 --output '$target'");
  is($rc, 0, 'succeeds') or diag $out;
  ok(-f $target, 'writes the requested path');
  ok(!-e "$root/announce-multi", 'does not create announce-multi/');
};

subtest 'overlapping batches are reported, never removed' => sub {
  my $root = _root();
  _seed($root, 'CVE-1900-9905');
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9905 --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^  \Q$batch\E \(CVE-1900-9901\)$/m, 'names the overlapping file and shared CVE');
  ok(-f "$root/$batch", 'older batch left in place');
  ok(-f "$root/announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9905.txt", 'new batch written');
};

subtest 'errors' => sub {
  my $root = _root();
  _seed($root, 'CVE-1900-9903', 't/var/CVE-2025-40906.yaml');
  make_path("$root/encrypted");
  copy('t/var/CVE-2025-40916.yaml', "$root/encrypted/CVE-1900-9904.yaml") or die "copy failed: $!";

  my @cases = (
    ['announce-multi --write', qr/Usage: cna announce-multi/, 'no CVEs with --write'],
    ['announce-multi CVE-1900-9901', qr/use 'announce CVE-1900-9901' for a single CVE/, 'a single CVE'],
    ['announce-multi CVE-1900-9901 CVE-1900-9901', qr/Duplicate CVE ID CVE-1900-9901/, 'duplicate IDs'],
    ['announce-multi CVE-1900-9901 CVE-1900-9903', qr/share the primary distribution/, 'different distributions'],
    ['announce-multi CVE-1900-9901 CVE-1900-9904', qr{CVE-1900-9904 is under encrypted/}, 'an encrypted CVE'],
    ['announce-multi CVE-1900-9901 CVE-1900-9909', qr{Cannot find YAML for CVE-1900-9909 under cves/}, 'a missing CVE'],
    ['announce-multi CVE-1900-9901 CVE-1900-9902 --write --output x.txt', qr/cannot be combined/, '--write with --output'],
    ['announce-multi CVE-1900-9901 not-a-cve', qr/CVE must match/, 'a malformed ID'],
    ['announce-multi CVE-1900-9901 CVE-1900-9902 --bogus', qr/Unknown option '--bogus'/, 'an unknown option'],
  );
  for my $case (@cases) {
    my ($args, $re, $what) = @$case;
    my ($rc, $out) = _run($root, $args);
    isnt($rc, 0, "refuses $what");
    like($out, $re, "explains $what");
  }
  ok(!-e "$root/announce-multi", 'nothing written');
};

done_testing();

sub _root () {
  my $root = tempdir(CLEANUP => 1);
  _seed($root, $_) for qw(CVE-1900-9901 CVE-1900-9902);
  return $root;
}

sub _seed ($root, $cve, $fixture = 't/var/CVE-2025-40916.yaml') {
  make_path("$root/cves");
  my $target = "$root/cves/$cve.yaml";
  copy($fixture, $target) or die "copy failed: $!";
  open(my $fh, '<', $target) or die "Cannot read $target: $!";
  local $/;
  my $content = <$fh>;
  close($fh);
  $content =~ s/^  cve:\s+\S+/  cve: $cve/m or die "Cannot rewrite cve in $target";
  open(my $out, '>', $target) or die "Cannot write $target: $!";
  print {$out} $content;
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
