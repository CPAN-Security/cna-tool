use strict;
use v5.42;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON::PP qw(decode_json);
use Test::More;

my $fixture_json = 't/var/CVE-2025-40916.source.json';
ok(-f $fixture_json, 'fixture local CVE json exists in t/var');

my $cve = 'CVE-1900-9916';
my $missing_cve = 'CVE-1900-9934';
my $root = tempdir(CLEANUP => 1);
my $cves = "$root/cves";
make_path($cves);
my $local = "$cves/$cve.json";
my $remote;

my $tmp = tempdir(CLEANUP => 1);
my $remote_dir = "$tmp/remote";
mkdir $remote_dir or die "mkdir $remote_dir: $!";
$remote = "$remote_dir/$cve.json";

my $cleanup = sub {
  unlink $local if defined $local && -f $local;
};

eval {
  my $doc = _read_json($fixture_json);
  $doc->{cveMetadata}{cveId} = $cve;
  _write_json($local, $doc);
  _write_json($remote, $doc);

  my $out_same = qx(scripts/cna --cpansec-cna-root '$root' reconcile $cve --api-base file://$remote_dir 2>&1);
  my $rc_same = $? >> 8;
  is($rc_same, 0, 'reconcile succeeds when local and remote CNA match');
  like($out_same, qr/^OK \Q$cve\E: containers\.cna matches/m, 'match output is reported');

  # mutate remote CNA title to force a diff
  my $doc_diff = _read_json($remote);
  $doc_diff->{containers}{cna}{title} .= ' (remote change)';
  _write_json($remote, $doc_diff);

  my $out_diff = qx(scripts/cna --cpansec-cna-root '$root' reconcile $cve --api-base file://$remote_dir 2>&1);
  my $rc_diff = $? >> 8;
  is($rc_diff, 1, 'reconcile exits non-zero when CNA differs');
  like($out_diff, qr/^DIFF \Q$cve\E: containers\.cna differs/m, 'diff output is reported');
  like($out_diff, qr/^--- \Q$cve\E local/m, 'unified diff header printed');

  # providerMetadata-only differences should be ignored
  my $doc2 = _read_json($remote);
  $doc2->{containers}{cna}{title} = $doc->{containers}{cna}{title};
  $doc2->{containers}{cna}{providerMetadata} = {
    orgId => '9b29abf9-4ab0-4765-b253-1875cd9b441e',
    shortName => 'CPANSec',
    dateUpdated => '2026-01-01T00:00:00.000Z',
  };
  _write_json($remote, $doc2);

  my $out_meta = qx(scripts/cna --cpansec-cna-root '$root' reconcile $cve --api-base file://$remote_dir 2>&1);
  my $rc_meta = $? >> 8;
  is($rc_meta, 0, 'reconcile ignores providerMetadata-only differences');
  like($out_meta, qr/^OK \Q$cve\E: containers\.cna matches/m, 'metadata-only change is treated as match');

  # missing remote record should be reported explicitly
  my $missing_doc = _read_json($fixture_json);
  $missing_doc->{cveMetadata}{cveId} = $missing_cve;
  _write_json("$cves/$missing_cve.json", $missing_doc);
  my $out_missing = qx(scripts/cna --cpansec-cna-root '$root' reconcile $missing_cve --api-base file://$remote_dir 2>&1);
  my $rc_missing = $? >> 8;
  is($rc_missing, 1, 'reconcile exits non-zero when remote CVE is missing');
  like($out_missing, qr/^MISSING \Q$missing_cve\E: /m, 'missing remote record is reported');
  like($out_missing, qr/Summary: .* missing, /, 'summary includes missing count');

  1;
} or do {
  my $err = $@ || 'unknown test error';
  fail("reconcile test setup/exec failed: $err");
};

$cleanup->();
unlink "$cves/$missing_cve.json" if -f "$cves/$missing_cve.json";

my $enc_root = tempdir(CLEANUP => 1);
make_path("$enc_root/encrypted");
open(my $enc_fh, '>', "$enc_root/encrypted/CVE-1900-7777.yaml")
  or die "Cannot write encrypted fixture: $!";
print {$enc_fh} <<'YAML';
cpansec:
  cve: CVE-1900-7777
  distribution: Example-Dist
  module: Example::Module
  author: EXAMPLE
  repo: https://example.com/repo
  affected:
    - "<= 1.0"
  title: Example::Module versions through 1.0 for Perl has an issue
  description: Example::Module versions through 1.0 for Perl has an issue.
  references:
    - link: https://example.com/advisory
      tags: [advisory]
YAML
close($enc_fh);

my $out_enc = qx(scripts/cna --cpansec-cna-root '$enc_root' reconcile 2>&1);
my $rc_enc = $? >> 8;
is($rc_enc, 0, 'reconcile ignores encrypted-only records when no cves/ records exist');
like($out_enc, qr/No local CVE records found under cves\/\*\.\{yaml,json\}/, 'status message scopes reconcile to cves/');

done_testing();

sub _read_json ($path) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $doc = decode_json(<$fh>);
  close($fh);
  return $doc;
}

sub _write_json ($path, $doc) {
  open(my $fh, '>', $path) or die "Cannot write $path: $!";
  print {$fh} JSON::PP->new->canonical->pretty->encode($doc);
  close($fh);
}
