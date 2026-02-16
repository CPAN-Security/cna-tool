use strict;
use v5.42;

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

subtest 'edit with explicit CVE opens matching YAML' => sub {
  my $root = _init_git_repo('main');
  my $cve = 'CVE-1900-9934';
  _write_yaml($root, $cve);

  my $log = "$root/editor-explicit.log";
  my $editor = _write_editor_stub($root);
  local $ENV{VISUAL} = '';
  local $ENV{EDITOR} = "$editor --mode explicit";
  local $ENV{EDITOR_LOG} = $log;

  my $out = qx($cna --cpansec-cna-root '$root' edit $cve 2>&1);
  my $rc = $? >> 8;

  is($rc, 0, "edit succeeds\n$out");
  ok(-f $log, 'editor log was written');
  if (-f $log) {
    my $logged = _slurp($log);
    like($logged, qr/\bcves\/\Q$cve\E\.yaml\b/, 'editor received explicit CVE yaml path');
  }
};

subtest 'edit without CVE uses branch-derived default' => sub {
  my $cve = 'CVE-1900-9935';
  my $root = _init_git_repo($cve . '-topic');
  _write_yaml($root, $cve);

  my $log = "$root/editor-default.log";
  my $editor = _write_editor_stub($root);
  local $ENV{CPANSEC_CNA_CVE} = '';
  local $ENV{VISUAL} = '';
  local $ENV{EDITOR} = "$editor --mode default";
  local $ENV{EDITOR_LOG} = $log;

  my $out = qx($cna --cpansec-cna-root '$root' edit 2>&1);
  my $rc = $? >> 8;

  is($rc, 0, "edit succeeds with branch-derived default\n$out");
  ok(-f $log, 'editor log was written');
  if (-f $log) {
    my $logged = _slurp($log);
    like($logged, qr/\bcves\/\Q$cve\E\.yaml\b/, 'editor received branch-derived CVE yaml path');
  }
};

done_testing();

sub _init_git_repo ($branch) {
  my $root = tempdir(CLEANUP => 1);
  my $rc = system('git', 'init', '-q', '-b', $branch, $root);
  die "git init failed ($rc)\n" if $rc != 0;
  return $root;
}

sub _write_yaml ($root, $cve) {
  make_path("$root/cves");
  open(my $fh, '>', "$root/cves/$cve.yaml") or die "Cannot write yaml: $!";
  print {$fh} <<"YAML";
cpansec:
  cve: $cve
  distribution: Example-Dist
  module: Example::Module
  author: AUTHORID
  repo: https://example.invalid/repo
  affected:
    - "<= 1.0"
  title: Example::Module {{VERSION_RANGE}} for Perl has an issue
  description: |-
    Example::Module {{VERSION_RANGE}} for Perl has an issue.
  references:
    - link: https://example.invalid/advisory
      tags: [ advisory ]
YAML
  close($fh);
}

sub _write_editor_stub ($root) {
  my $stub = "$root/editor-stub.sh";
  open(my $fh, '>', $stub) or die "Cannot write editor stub: $!";
  print {$fh} <<'SH';
#!/usr/bin/env bash
printf '%s\n' "$@" > "$EDITOR_LOG"
SH
  close($fh);
  chmod 0755, $stub or die "Cannot chmod editor stub: $!";
  return $stub;
}

sub _slurp ($path) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $txt = <$fh>;
  close($fh);
  return $txt;
}
