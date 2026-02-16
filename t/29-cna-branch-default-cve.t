use strict;
use v5.42;

use Cwd qw(abs_path);
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir tempfile);
use JSON::PP qw(decode_json);
use Test::More;

my $fixture_yaml = 't/var/CVE-2025-40906.yaml';
my $schema_json = abs_path('cve-schema/schema/CVE_Record_Format.json');

subtest 'branch default CVE works with double-dash slug' => sub {
  _assert_branch_default('CVE-1900-9929--double-dash-slug', 'CVE-1900-9929');
};

subtest 'branch default CVE works with single-dash slug' => sub {
  _assert_branch_default('CVE-1900-9931-single-dash-slug', 'CVE-1900-9931');
};

done_testing();

sub _assert_branch_default ($branch, $cve) {
  my $root = tempdir(CLEANUP => 1);
  _init_git_repo($root, $branch);

  my $cves = "$root/cves";
  make_path($cves);
  my $yaml = "$cves/$cve.yaml";
  copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
  _rewrite_cve_in_yaml($yaml, $cve);

  local $ENV{CPANSEC_CNA_CVE} = '';
  local $ENV{CPANSEC_CNA_CVE_SCHEMA} = $schema_json;
  my ($err_fh, $err_file) = tempfile(DIR => $root, SUFFIX => '.err');
  close $err_fh;

  my $out = qx(scripts/cna --cpansec-cna-root '$root' emit 2>'$err_file');
  my $rc = $? >> 8;
  my $err_text = do {
    open(my $eh, '<', $err_file) or die "Cannot read $err_file: $!";
    local $/;
    my $txt = <$eh>;
    close($eh);
    $txt;
  };

  is($rc, 0, "emit succeeds using branch-derived default CVE\n$err_text");
  my $doc = eval { decode_json($out) };
  ok($doc, 'emit output is valid JSON');
  is($doc->{cveMetadata}{cveId}, $cve, 'emitted CVE id follows branch-derived CVE');
}

sub _init_git_repo ($root, $branch) {
  my $rc = system('git', 'init', '-q', '-b', $branch, $root);
  die "git init failed ($rc)\n" if $rc != 0;
}

sub _rewrite_cve_in_yaml ($path, $cve) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $content = <$fh>;
  close($fh);
  $content =~ s/^  cve:\s+\S+/  cve: $cve/m
    or die "Cannot rewrite cve in $path";
  open(my $wh, '>', $path) or die "Cannot write $path: $!";
  print {$wh} $content;
  close($wh);
}
