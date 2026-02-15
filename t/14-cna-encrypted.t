use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $branch = _current_branch();
if (defined $branch && $branch eq 'main') {
  plan skip_all => "encrypted CVE operations are disallowed on main";
}

my $source_cve = 'CVE-2025-40906';
my $cve = 'CVE-1900-9914';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $root = tempdir(CLEANUP => 1);
my $enc = "$root/encrypted";
make_path($enc);
my $yaml = "$enc/$cve.yaml";
my $json = "$enc/$cve.json";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
_rewrite_cve_in_yaml($yaml, $cve);

my $err_emit = "/tmp/cpansec-cna-encrypted-emit-$$.err";
my $out_emit = qx(scripts/cna --cpansec-cna-root '$root' emit $cve 2>$err_emit);
my $rc_emit = $? >> 8;
is($rc_emit, 0, 'emit works when CVE is auto-detected in encrypted/');
like($out_emit, qr/"cveId"\s*:\s*"\Q$cve\E"/, 'emit output contains expected CVE id');
my $emit_stderr = _read_text($err_emit);
like($emit_stderr, qr/SENSITIVE CVE CONTEXT DETECTED/i, 'encrypted detection warning is loud');
like($emit_stderr, qr/Network access is disabled/i, 'warning includes network-disabled notice');

open(my $jfh, '>', $json) or die "Cannot write $json: $!";
print {$jfh} $out_emit;
close($jfh);

my $err_rec = "/tmp/cpansec-cna-encrypted-reconcile-$$.err";
my $out_rec = qx(scripts/cna --cpansec-cna-root '$root' reconcile $cve --api-base https://cveawg.mitre.org/api/cve 2>$err_rec);
my $rc_rec = $? >> 8;
is($rc_rec, 1, 'reconcile fails for encrypted CVE source');
like($out_rec, qr/Refusing reconcile for encrypted CVE source/i, 'reconcile refusal is explicit');
my $rec_stderr = _read_text($err_rec);
unlike($rec_stderr, qr/SENSITIVE CVE CONTEXT DETECTED/i, 'reconcile does not enter encrypted context');

my $out_ann = qx(scripts/cna --cpansec-cna-root '$root' announce $cve 2>&1);
my $rc_ann = $? >> 8;
is($rc_ann, 2, 'announce fails for encrypted CVE source');
like($out_ann, qr/Refusing to generate announcement from encrypted CVE source/i, 'announce refusal is explicit');

unlink $err_emit;
unlink $err_rec;

done_testing();

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

sub _current_branch () {
  my $b = qx(git branch --show-current 2>/dev/null);
  chomp $b;
  return length($b) ? $b : undef;
}

sub _read_text ($path) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $txt = <$fh>;
  close($fh);
  return $txt // '';
}
