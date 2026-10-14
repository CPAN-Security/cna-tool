# announce-multi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `cpansec-cna announce-multi`, which renders one optional announcement email covering several CVEs of the same primary distribution, writes it under `announce-multi/`, and is fully covered by `cpansec-cna check`.

**Architecture:** `CPANSec::CVE::Announce` is split so its body (banner down) can be reused unchanged. A new `CPANSec::CVE::BatchName` builds and parses batch filenames; a new `CPANSec::CVE::AnnounceMulti` renders a batch (header + index + unchanged bodies). `CPANSec::CNA::App` gains the `announce-multi` command, batch checks in `check`, and a PR-policy rule that freezes merged batch files.

**Tech Stack:** Perl v5.42, `feature 'class'`, `Text::Wrap`, `Test::More`, git, Nix dev shell.

**Spec:** `multi-announce-handoff.md` — read the "Decisions (2026-10-14)" section; it is the source of truth for format and rules.

## Global Constraints

- Target runtime Perl `v5.42`; project modules use `feature 'class'` with `no warnings qw(experimental::class)`.
- No new dependencies; core modules and already-adopted CPAN modules only.
- No test may call the internet. Test input fixtures live under `t/var/`; tests copy them into temp roots.
- Run tests with `nix develop --offline -c prove -lr t` (a bare `prove` lacks `JSON::Validator`). The `cve-schema` submodule must be checked out.
- Announcement text wraps at 72 columns.
- Single-CVE `announce` output must stay byte-identical.
- Batch subject and title: `<primary distribution> for Perl: N CVEs`.
- Batch filename: `announce-multi/<Dist>--<IDs>.txt`, IDs sorted numerically, joined with `+`, year written in full for the first ID of each year and only the number for later IDs of that year.
- Batches are public-only: never read `encrypted/`.
- Ask the user before creating/switching branches; commit messages are short imperative sentences (see `git log`) ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- A published CVE in a merged batch gets its YAML updated, even its primary distribution, including in a CI checkout that only has `origin/main`: `check` must stay green (Task 5 "merged batches" and "origin/main" tests, Task 6 "updating a CVE" test).
- CVE IDs spanning years, with leading-zero numbers (`CVE-2026-0042`) or 5+ digits: filenames must round-trip the exact ID strings and sort numerically (Task 2 tests).
- Non-ASCII text in a CVE (`Ærøskøbing`): a file written by `--write` must pass `check` byte-for-byte (Task 5 "non-ASCII" test).
- A merged batch file deleted in a PR: there is no file left to check, so the policy must look at the base side (Task 6 "must not be removed" test).
- Only a batch file changed on a branch, no YAML: `check --changed` must still check it instead of printing "No CVE YAML files to check." (Task 5 "--changed" test).

---

### Task 0: Branch and baseline

- [ ] **Step 1: Ask the user, then create the branch**

Ask for consent first (AGENTS.md). Then:

```bash
git switch -c announce-multi
```

- [ ] **Step 2: Confirm the baseline is green**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.` (44 files at time of writing). If it fails on a missing schema, the `cve-schema` submodule is not checked out — ask the user to run `git submodule update --init` (network).

- [ ] **Step 3: Commit the spec and this plan**

```bash
git add multi-announce-handoff.md docs/superpowers/plans/2026-10-14-announce-multi.md
git commit -m "Add multi-CVE announcement handoff and plan

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1: Split the announcement body from its subject line

**Files:**
- Modify: `lib/CPANSec/CVE/Announce.pm` (method `render_cve5_hash`, add `subject_line`, `render_cve5_body`, sub `_cna`)
- Test: `t/44-announce-body-split.t`

**Interfaces:**
- Produces:
  - `CPANSec::CVE::Announce->subject_line($cve5_hash) -> Str` — `"Subject: <cveId>: <title>"`, no newline.
  - `CPANSec::CVE::Announce->render_cve5_body($cve5_hash) -> Str` — everything from the first `====` banner line to the end, exactly as in today's output.
  - Invariant: `render_cve5_hash($c) eq subject_line($c) . "\n\n\n" . render_cve5_body($c)`.

- [ ] **Step 1: Record golden output before touching code**

```bash
golden="${TMPDIR:-/tmp}/cna-announce-golden"
mkdir -p "$golden"
for f in CVE-2025-40906 CVE-2025-40916 CVE-2025-40933; do
  nix develop --offline -c perl -Ilib -MCPANSec::CVE::Announce \
    -e 'binmode STDOUT, ":encoding(UTF-8)"; print CPANSec::CVE::Announce->new->render_cve5_file(shift)' \
    "t/var/$f.source.json" > "$golden/$f.txt"
done
```

Step 5 reads the same fixed path, so it works from a fresh shell.

- [ ] **Step 2: Write the failing test**

Create `t/44-announce-body-split.t`:

```perl
use strict;
use v5.42;

use JSON::PP qw(decode_json);
use Test::More;

use lib 'lib';
use CPANSec::CVE::Announce ();

my $announce = CPANSec::CVE::Announce->new;

for my $fixture (qw(CVE-2025-40906 CVE-2025-40916 CVE-2025-40933)) {
  my $cve = _read_json("t/var/$fixture.source.json");
  my $id = $cve->{cveMetadata}{cveId};
  my $body = $announce->render_cve5_body($cve);

  is($announce->subject_line($cve), "Subject: $id: $cve->{containers}{cna}{title}", "$fixture subject line");
  like($body, qr/\A={72}\n\Q$id\E +CPAN Security Group\n={72}\n/, "$fixture body starts at the banner");
  unlike($body, qr/^Subject:/m, "$fixture body has no subject line");
  is(
    $announce->render_cve5_hash($cve),
    $announce->subject_line($cve) . "\n\n\n" . $body,
    "$fixture full announcement is subject line + body",
  );
}

eval { $announce->render_cve5_body({}) };
like($@, qr/Expected CVE JSON record with containers\.cna/, 'body rejects records without a CNA container');

done_testing();

sub _read_json ($path) {
  open(my $fh, '<:raw', $path) or die "Cannot read $path: $!";
  local $/;
  return decode_json(<$fh>);
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/44-announce-body-split.t`
Expected: FAIL — `Can't locate object method "render_cve5_body"`.

- [ ] **Step 4: Implement the split**

In `lib/CPANSec/CVE/Announce.pm`, replace the whole `method render_cve5_hash ($cve) { ... }` with:

```perl
  method render_cve5_hash ($cve) {
    return $self->subject_line($cve) . "\n\n\n" . $self->render_cve5_body($cve);
  }

  method subject_line ($cve) {
    my $cna = _cna($cve);
    return "Subject: $cve->{cveMetadata}->{cveId}: $cna->{title}";
  }

  # Everything below the Subject line, from the banner down. A multi-CVE
  # announcement concatenates these unchanged.
  method render_cve5_body ($cve) {
    my $cna = _cna($cve);

    local $Text::Wrap::columns = $wrap_columns;

    my @affected = @{$cna->{affected} // []};
    @affected = ({}) unless @affected;

    my @lines = (
      _header([$cve->{cveMetadata}->{cveId}, "CPAN Security Group"], "="),
      "",
      _dt("CVE ID", $cve->{cveMetadata}->{cveId}),
      "",
      _distribution_blocks(@affected),
      "",
      "",
      Text::Wrap::wrap('', '', $cna->{title}),
      "",
      _header("Description"),
      _wrap_description(_descriptions_text($cna)),
      "",
      ($cna->{problemTypes} ? _section(
        "Problem types", map { Text::Wrap::wrap('- ', '  ', _first_description($_)) } $cna->{problemTypes}->@*
      ) : ()),
      ($cna->{impacts} ? _section(
        "Impacts", map { Text::Wrap::wrap('- ', '  ', _first_description($_)) } $cna->{impacts}->@*
      ) : ()),
      ($cna->{workarounds} ? _section("Workarounds", _paragraphs($cna->{workarounds})) : ()),
      ($cna->{solutions} ? _section("Solutions", _paragraphs($cna->{solutions})) : ()),
      ($cna->{references} ? _section(
        "References", map { "$_->{url}" } $cna->{references}->@*
      ) : ()),
      ($cna->{timeline} ? _section(
        "Timeline", map { Text::Wrap::wrap('- ', '  ', _timeline_entry($_)) } $cna->{timeline}->@*
      ) : ()),
      ($cna->{credits} ? _section(
        "Credits", map { "$_->{value}, $_->{type}" } $cna->{credits}->@*
      ) : ()),
      "",
      "",
    );

    return join("\n", @lines);
  }
```

Add next to the other subs, after `sub _header`:

```perl
sub _cna ($cve) {
  my $cna = $cve->{containers}->{cna};
  die "Expected CVE JSON record with containers.cna\n" unless ref($cna) eq 'HASH';
  return $cna;
}
```

- [ ] **Step 5: Verify output is byte-identical and tests pass**

```bash
golden="${TMPDIR:-/tmp}/cna-announce-golden"
for f in CVE-2025-40906 CVE-2025-40916 CVE-2025-40933; do
  nix develop --offline -c perl -Ilib -MCPANSec::CVE::Announce \
    -e 'binmode STDOUT, ":encoding(UTF-8)"; print CPANSec::CVE::Announce->new->render_cve5_file(shift)' \
    "t/var/$f.source.json" | diff -u "$golden/$f.txt" - && echo "$f identical"
done
nix develop --offline -c prove -lr t
```

Expected: three `identical` lines, `All tests successful.`

- [ ] **Step 6: Commit**

```bash
git add lib/CPANSec/CVE/Announce.pm t/44-announce-body-split.t
git commit -m "Split the announcement body from its subject line

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Batch filenames

**Files:**
- Create: `lib/CPANSec/CVE/BatchName.pm`
- Test: `t/45-announce-multi-name.t`

**Interfaces:**
- Produces (all exported on request):
  - `sort_cve_ids(@ids) -> @ids` — numeric by year then sequence number; dies `Invalid CVE ID '<id>'` on bad input.
  - `batch_filename($distribution, @ids) -> Str` — e.g. `Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt`; sorts its input.
  - `parse_batch_filename($basename) -> ($distribution, @ids)` or empty list when the name does not parse.

- [ ] **Step 1: Write the failing test**

Create `t/45-announce-multi-name.t`:

```perl
use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CVE::BatchName qw(sort_cve_ids batch_filename parse_batch_filename);

subtest 'sort_cve_ids' => sub {
  is_deeply(
    [sort_cve_ids(qw(CVE-2026-10001 CVE-2025-40906 CVE-2026-9999 CVE-2026-0042))],
    [qw(CVE-2025-40906 CVE-2026-0042 CVE-2026-9999 CVE-2026-10001)],
    'by year, then numerically by sequence number',
  );
  is_deeply(
    [sort_cve_ids(qw(CVE-2026-12345678901234567891 CVE-2026-12345678901234567890))],
    [qw(CVE-2026-12345678901234567890 CVE-2026-12345678901234567891)],
    'long sequence numbers compare exactly',
  );
  eval { sort_cve_ids('CVE-26-1') };
  like($@, qr/Invalid CVE ID 'CVE-26-1'/, 'rejects malformed IDs');
};

subtest 'batch_filename' => sub {
  is(batch_filename('Foo-Bar', qw(CVE-2026-1003 CVE-2026-1001 CVE-2026-1002)),
    'Foo-Bar--CVE-2026-1001+1002+1003.txt', 'one year, sorted, year written once');
  is(batch_filename('Foo-Bar', qw(CVE-2026-1002 CVE-2025-40906 CVE-2026-1001)),
    'Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt', 'year written again when it changes');
  is(batch_filename('Foo-Bar', qw(CVE-2026-1001 CVE-2026-0042)),
    'Foo-Bar--CVE-2026-0042+1001.txt', 'leading zeros kept verbatim');
};

subtest 'parse_batch_filename' => sub {
  is_deeply(
    [parse_batch_filename('Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt')],
    ['Foo-Bar', qw(CVE-2025-40906 CVE-2026-1001 CVE-2026-1002)],
    'bare numbers take the year of the nearest full ID before them',
  );
  for my $name (
    'Foo-Bar--CVE-2026-1001+1002+1003.txt',
    'Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt',
    'Foo-Bar--CVE-2026-0042+1001.txt',
  ) {
    my ($dist, @ids) = parse_batch_filename($name);
    is(batch_filename($dist, @ids), $name, "$name round-trips");
  }
  for my $bad (
    'Foo-Bar.txt',
    'Foo-Bar--1001+1002.txt',
    'Foo-Bar--CVE-2026-1001+.txt',
    'Foo-Bar--CVE-2026-1001+12.txt',
    'Foo-Bar--CVE-2026-1001+1002.yaml',
    '--CVE-2026-1001+1002.txt',
  ) {
    is_deeply([parse_batch_filename($bad)], [], "$bad does not parse");
  }
};

done_testing();
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/45-announce-multi-name.t`
Expected: FAIL — `Can't locate CPANSec/CVE/BatchName.pm`.

- [ ] **Step 3: Implement**

Create `lib/CPANSec/CVE/BatchName.pm`:

```perl
package CPANSec::CVE::BatchName;

use v5.42;

use Exporter 'import';
our @EXPORT_OK = qw(sort_cve_ids batch_filename parse_batch_filename);

my $CVE_ID = qr/CVE-(\d{4})-(\d{4,19})/;

# Numeric by year, then by sequence number. A sequence number can be longer
# than a double holds exactly, so it is compared as a digit string with
# leading zeros stripped: shorter is smaller, equal lengths compare lexically.
sub sort_cve_ids (@ids) {
  return map { $_->[0] }
    sort { $a->[1] <=> $b->[1] || length($a->[2]) <=> length($b->[2]) || $a->[2] cmp $b->[2] }
    map {
      my ($year, $number) = /^$CVE_ID\z/ or die "Invalid CVE ID '$_'\n";
      [$_, $year, $number =~ s/^0+(?=\d)//r]
    } @ids;
}

# Every ID appears, sorted and joined with '+'. The year is written out for
# the first ID of each year; later IDs of that year are just the number.
sub batch_filename ($distribution, @ids) {
  my $year = '';
  my @parts;
  for my $id (sort_cve_ids(@ids)) {
    my ($y, $number) = $id =~ /^$CVE_ID\z/;
    push @parts, $y eq $year ? $number : $id;
    $year = $y;
  }
  return "$distribution--" . join('+', @parts) . '.txt';
}

# Inverse of batch_filename: a bare number takes the year of the nearest full
# ID before it. Returns an empty list when the name does not parse.
sub parse_batch_filename ($name) {
  my ($distribution, $list) = $name =~ m{^([^/]+?)--(CVE-[^/]+)\.txt\z} or return;
  my ($year, @ids);
  for my $part (split /\+/, $list, -1) {
    if ($part =~ /^$CVE_ID\z/) {
      $year = $1;
      push @ids, $part;
      next;
    }
    return unless defined $year && $part =~ /^\d{4,19}\z/;
    push @ids, "CVE-$year-$part";
  }
  return ($distribution, @ids);
}

1;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `nix develop --offline -c prove -l t/45-announce-multi-name.t`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/CPANSec/CVE/BatchName.pm t/45-announce-multi-name.t
git commit -m "Add batch filename helpers for multi-CVE announcements

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Render a multi-CVE announcement

**Files:**
- Create: `lib/CPANSec/CVE/AnnounceMulti.pm`
- Create: `t/var/CVE-1900-9989.yaml` (Encode-only fixture to batch with the dual-life `t/var/CVE-1900-9997.yaml`)
- Test: `t/46-announce-multi-render.t`

**Interfaces:**
- Consumes: `CPANSec::CVE::Announce->render_cve5_body` (Task 1), `sort_cve_ids` (Task 2).
- Produces:
  - `CPANSec::CVE::AnnounceMulti->new(announcer => ..., wrap_columns => 72)`
  - `->primary_distribution($cve5_hash) -> Str` — `containers.cna.affected[0].packageName`, `''` if absent.
  - `->render(@cve5_hashes) -> Str` — dies on fewer than 2 records (`at least 2 CVEs`), duplicate IDs (`Duplicate CVE IDs`), or differing primary distributions (`All CVEs must share the primary distribution <dist>; differs for <ids>`).

- [ ] **Step 1: Add the fixture**

Create `t/var/CVE-1900-9989.yaml`:

```yaml
# yaml-language-server: $schema=../schema/cpansec-cna-schema-01.yaml
cpansec:
  cve: CVE-1900-9989
  distribution: Encode
  module: Encode
  repo: https://github.com/dankogai/p5-encode

  affected:
    - "<= 3.19"

  title: Encode versions through 3.19 for Perl mishandles a second decoding edge case

  description: |-
    Encode versions through 3.19 for Perl mishandles a second decoding edge case.

  references:
    - link: https://example.invalid/advisory-2
      tags:
        - vendor-advisory
```

- [ ] **Step 2: Write the failing test**

Create `t/46-announce-multi-render.t`:

```perl
use strict;
use v5.42;

use Storable qw(dclone);
use Test::More;

use lib 'lib';
use CPANSec::CVE::Announce ();
use CPANSec::CVE::AnnounceMulti ();
use CPANSec::CVE::YAML2CVE ();

my $converter = CPANSec::CVE::YAML2CVE->new;
my $announce = CPANSec::CVE::Announce->new;
my $multi = CPANSec::CVE::AnnounceMulti->new;

my $first = _record('t/var/CVE-2025-40916.yaml', 'CVE-1900-9901');
my $second = _record('t/var/CVE-2025-40916.yaml', 'CVE-1900-9902');

subtest 'header, index and unchanged bodies' => sub {
  my $header = <<'EOT';
Subject: Mojolicious-Plugin-CaptchaPNG for Perl: 2 CVEs


Mojolicious-Plugin-CaptchaPNG for Perl: 2 CVEs

CVE-1900-9901
  Mojolicious::Plugin::CaptchaPNG version 1.05 for Perl uses a weak
  random number source for generating the captcha text

CVE-1900-9902
  Mojolicious::Plugin::CaptchaPNG version 1.05 for Perl uses a weak
  random number source for generating the captcha text


EOT
  is(
    $multi->render($second, $first),
    $header . $announce->render_cve5_body($first) . $announce->render_cve5_body($second),
    'sorted by CVE ID regardless of argument order; bodies are the single announcements',
  );
};

subtest 'primary distribution' => sub {
  is($multi->primary_distribution($first), 'Mojolicious-Plugin-CaptchaPNG', 'single-distribution record');
  is($multi->primary_distribution(_record('t/var/CVE-1900-9997.yaml', 'CVE-1900-9997')),
    'Encode', 'dual-life record: the first affected entry');
};

subtest 'dual-life records batch on their primary distribution' => sub {
  my $text = $multi->render(
    _record('t/var/CVE-1900-9997.yaml', 'CVE-1900-9997'),
    _record('t/var/CVE-1900-9989.yaml', 'CVE-1900-9989'),
  );
  like($text, qr/\ASubject: Encode for Perl: 2 CVEs\n/, 'titled by the primary distribution');
  like($text, qr/^\s*Distribution:\s+perl$/m, 'the perl core block of the dual-life record is kept');
};

subtest 'rejections' => sub {
  eval { $multi->render($first) };
  like($@, qr/at least 2 CVEs/, 'a single CVE');
  eval { $multi->render($first, dclone($first)) };
  like($@, qr/Duplicate CVE IDs/, 'the same CVE twice');
  eval { $multi->render($first, _record('t/var/CVE-2025-40906.yaml', 'CVE-1900-9903')) };
  like($@, qr/share the primary distribution Mojolicious-Plugin-CaptchaPNG; differs for CVE-1900-9903/,
    'different primary distributions');
};

done_testing();

sub _record ($path, $id) {
  my $record = dclone($converter->convert_yaml_file($path));
  $record->{cveMetadata}{cveId} = $id;
  return $record;
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/46-announce-multi-render.t`
Expected: FAIL — `Can't locate CPANSec/CVE/AnnounceMulti.pm`.

- [ ] **Step 4: Implement**

Create `lib/CPANSec/CVE/AnnounceMulti.pm`:

```perl
package CPANSec::CVE::AnnounceMulti;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CVE::Announce ();
use CPANSec::CVE::BatchName qw(sort_cve_ids);
use Text::Wrap ();

class CPANSec::CVE::AnnounceMulti {
  field $announcer :param = CPANSec::CVE::Announce->new;
  field $wrap_columns :param = 72;

  # The first affected entry is the primary distribution, as in the single
  # announcement. A batch is keyed on it, so dual-life records can join.
  method primary_distribution ($cve) {
    return $cve->{containers}{cna}{affected}[0]{packageName} // '';
  }

  # A short header (title plus an index of CVE IDs and their full titles),
  # then each CVE's single announcement unchanged, minus its Subject line.
  method render (@cves) {
    die "A multi-CVE announcement needs at least 2 CVEs\n" unless @cves >= 2;

    my %by_id = map { ($_->{cveMetadata}{cveId} => $_) } @cves;
    die "Duplicate CVE IDs in multi-CVE announcement\n" if keys %by_id != @cves;
    my @sorted = @by_id{ sort_cve_ids(keys %by_id) };

    my $distribution = $self->primary_distribution($sorted[0]);
    my @others = map { $_->{cveMetadata}{cveId} }
      grep { $self->primary_distribution($_) ne $distribution } @sorted;
    die "All CVEs must share the primary distribution $distribution; differs for @others\n" if @others;

    my $title = sprintf('%s for Perl: %d CVEs', $distribution, scalar @sorted);

    local $Text::Wrap::columns = $wrap_columns;
    my @index;
    for my $cve (@sorted) {
      push @index, '' if @index;
      push @index, $cve->{cveMetadata}{cveId}, Text::Wrap::wrap('  ', '  ', $cve->{containers}{cna}{title});
    }

    my $header = join("\n", "Subject: $title", '', '', $title, '', @index, '', '') . "\n";
    return $header . join('', map { $announcer->render_cve5_body($_) } @sorted);
  }
}

1;
```

- [ ] **Step 5: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 6: Commit**

```bash
git add lib/CPANSec/CVE/AnnounceMulti.pm t/var/CVE-1900-9989.yaml t/46-announce-multi-render.t
git commit -m "Render multi-CVE announcements

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: The `announce-multi` command

**Files:**
- Modify: `lib/CPANSec/CNA/App.pm` (imports, `run` dispatch, `_usage_text`, new methods after `_cmd_announce`)
- Modify: `AGENTS.md` (workflow section, module list, script inventory, quick reference)
- Test: `t/47-cna-announce-multi.t`

**Interfaces:**
- Consumes: `CPANSec::CVE::AnnounceMulti->render/primary_distribution` (Task 3), `batch_filename`, `parse_batch_filename` (Task 2).
- Produces (used by Task 5):
  - `$app->_load_multi_cve5($cve_id) -> HashRef` — dies `... is under encrypted/ ...` or `Cannot find YAML for <id> under cves/`; never reads `encrypted/`.

- [ ] **Step 1: Write the failing test**

Create `t/47-cna-announce-multi.t`:

```perl
use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $cna = 'scripts/cna';
my $batch = 'announce-multi/Mojolicious-Plugin-CaptchaPNG--CVE-1900-9901+9902.txt';

subtest 'stdout' => sub {
  my $root = _root();
  my ($rc, $out) = _run($root, 'announce-multi CVE-1900-9902 CVE-1900-9901');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/\ASubject: Mojolicious-Plugin-CaptchaPNG for Perl: 2 CVEs\n/, 'batch subject');

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
    ['announce-multi', qr/^Usage: cna announce-multi/m, 'no CVEs'],
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/47-cna-announce-multi.t`
Expected: FAIL — `Unknown command 'announce-multi'`.

- [ ] **Step 3: Implement the command**

In `lib/CPANSec/CNA/App.pm`, add imports after `use CPANSec::CVE::Announce ();`:

```perl
use CPANSec::CVE::AnnounceMulti ();
use CPANSec::CVE::BatchName qw(batch_filename parse_batch_filename);
```

In `run`, after the `announce` dispatch:

```perl
    if ($cmd eq 'announce-multi') {
      return $self->_cmd_announce_multi(@argv);
    }
```

In `_usage_text`, after the `announce` entry:

```
  announce-multi <CVE-ID> <CVE-ID>... [--write|--output path]
                                    Render one announcement covering several CVEs
                                    of the same distribution (--write: announce-multi/)
```

After `method _cmd_announce`, add:

```perl
  method _cmd_announce_multi (@args) {
    my %opt = (write => 0);
    my @ids;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--write') { $opt{write} = 1; next; }
      if ($a =~ /^--output=(.+)$/) { $opt{output} = $1; next; }
      if ($a eq '--output') { $opt{output} = shift(@args) // die "--output requires value\n"; next; }
      die "Unknown option '$a'\n" if $a =~ /^-/;
      push @ids, $a;
    }

    die "announce-multi needs at least 2 CVEs; use 'announce $ids[0]' for a single CVE.\n" if @ids == 1;
    die "Usage: cna announce-multi <CVE-ID> <CVE-ID>... [--write|--output path]\n" unless @ids >= 2;
    die "--write and --output cannot be combined\n" if $opt{write} && defined $opt{output};

    my ($text, $filename) = $self->_render_announce_multi(@ids);

    if (!$opt{write} && !defined $opt{output}) {
      binmode(STDOUT, ':encoding(UTF-8)');
      print $text;
      return 0;
    }

    my $out = $opt{output} // File::Spec->catfile('announce-multi', $filename);
    if ($opt{write}) {
      # Merged batches are frozen, so an overlap can be legitimate: report it
      # and leave any cleanup to the operator.
      my @overlap = $self->_overlapping_batches($out, @ids);
      print STDERR "Note: other batch files also cover some of these CVEs (left untouched):\n",
        map("  $_\n", @overlap)
        if @overlap;
    }
    $self->_assert_encrypted_write_safe($out);
    my $dir = dirname($out);
    make_path($dir) unless -d $dir;
    open(my $fh, '>:encoding(UTF-8)', $out) or die "Cannot write $out: $!\n";
    print {$fh} $text;
    close($fh);
    print "Wrote $out\n";
    return 0;
  }

  method _render_announce_multi (@ids) {
    my %seen;
    for my $id (@ids) {
      die "CVE must match CVE-YYYY-NNNN format\n" unless $id =~ /^CVE-\d{4}-\d{4,19}$/;
      die "Duplicate CVE ID $id\n" if $seen{$id}++;
    }
    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my @cves = map { $self->_load_multi_cve5($_) } @ids;
    my $text = $multi->render(@cves);
    return ($text, batch_filename($multi->primary_distribution($cves[0]), @ids));
  }

  # Batches are public-only, like announce: they read cves/ and never touch
  # encrypted/, so no encrypted context is ever entered here.
  method _load_multi_cve5 ($cve) {
    die "Refusing multi-announcement: $cve is under encrypted/. Publish it to cves/ first.\n"
      if -f File::Spec->catfile('encrypted', "$cve.yaml");
    my $yaml = File::Spec->catfile('cves', "$cve.yaml");
    die "Cannot find YAML for $cve under cves/\n" unless -f $yaml;
    return CPANSec::CVE->from_yaml_file($yaml)->to_cve5_hash;
  }

  method _overlapping_batches ($path, @ids) {
    my %want = map { $_ => 1 } @ids;
    my @hits;
    for my $other (sort glob('announce-multi/*.txt')) {
      next if $other eq $path;
      my (undef, @covered) = parse_batch_filename(basename($other));
      my @shared = grep { $want{$_} } @covered;
      push @hits, "$other (" . join(', ', @shared) . ')' if @shared;
    }
    return @hits;
  }
```

- [ ] **Step 4: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 5: Document the command in AGENTS.md**

After the `### 5. Announcement Generation` block, add:

```markdown
### 5b. Multi-CVE Announcements
- `cpansec-cna announce-multi CVE-A CVE-B ...` (stdout)
- `cpansec-cna announce-multi CVE-A CVE-B ... --write` (to `announce-multi/`)
- `cpansec-cna announce-multi CVE-A CVE-B ... --output <path>`
- Optional: one email for several CVEs of the same primary distribution, e.g. for
  oss-security. Always in addition to the per-CVE `announce/<CVE>.txt` files.
- Output: subject and title `<Distribution> for Perl: N CVEs`, an index of CVE IDs with
  their full titles, then each CVE's normal announcement unchanged minus its `Subject:` line.
- At least 2 CVEs, sorted numerically by ID. All must share the primary distribution (the
  first `affected` entry, so dual-life records batch on it). Public-only: refuses any CVE
  under `encrypted/`.
- The filename lists every ID, year written once per year:
  `announce-multi/<Dist>--CVE-2025-40906+CVE-2026-1001+1002.txt`.
  `CPANSec::CVE::BatchName` builds and parses it.
- `--write` notes other batch files covering the same CVEs and never removes them.
```

Under "Key modules", after `CPANSec::CVE::Announce`, add:

```markdown
- `CPANSec::CVE::AnnounceMulti`
  - Multi-CVE announcement rendering; reuses `Announce::render_cve5_body`.
- `CPANSec::CVE::BatchName`
  - Batch filename build/parse and numeric CVE ID sorting.
```

In "Script Inventory", add `announce-multi` to the command list. In "Quick Command Reference", after the `announce` line, add:

```markdown
- `cpansec-cna announce-multi <CVE> <CVE>... [--write|--output PATH]`
```

- [ ] **Step 6: Commit**

```bash
git add lib/CPANSec/CNA/App.pm t/47-cna-announce-multi.t AGENTS.md
git commit -m "Add the announce-multi command

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Check batch files

**Files:**
- Modify: `lib/CPANSec/CNA/App.pm` (`_cmd_check`, `_changed_yaml_files`; add `_changed_paths`, `_resolve_multi_check_targets`, `_announce_multi_findings`, `_multi_file_problems`, sub `_batch_covers`)
- Modify: `AGENTS.md` (`### 3. Edit + Validate`)
- Test: `t/48-cna-check-announce-multi.t`

**Interfaces:**
- Consumes: `_load_multi_cve5` (Task 4), `CPANSec::CVE::AnnounceMulti` (Task 3), `batch_filename`, `parse_batch_filename` (Task 2), existing `_git_path_exists_at_ref($ref, $path)`, `_read_text_file($path)`, `_merge_findings`.
- Produces (used by Task 6):
  - `_batch_covers($path, \%ids) -> Bool` (plain sub).
  - In `_cmd_check`: `$target_cve` (explicit or default CVE) is a named variable.

Finding IDs (all severity `error`, all blocking): `multi_filename`, `multi_cve_missing`, `multi_cve_invalid`, `multi_distribution`, `multi_mismatch`. A merged batch (present on the PR base under `--pr-policy`; otherwise on `origin/main` if that ref exists, else `main`) only gets the `multi_filename` checks: it is a record of what was sent, and its CVEs may legitimately change afterwards.

- [ ] **Step 1: Write the failing test**

Create `t/48-cna-check-announce-multi.t`:

```perl
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/48-cna-check-announce-multi.t`
Expected: FAIL — `checking a CVE covers batches that name it` and later subtests fail (no `multi_` findings exist yet).

- [ ] **Step 3: Factor out the changed-paths list**

In `lib/CPANSec/CNA/App.pm`, replace the start of `_changed_yaml_files`:

```perl
  method _changed_yaml_files () {
    my @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'origin/main...HEAD');
    if (!@cand) {
      @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'HEAD~1...HEAD');
    }

    my %seen;
    my @files;
    for my $f (@cand) {
      chomp $f;
```

with:

```perl
  method _changed_yaml_files () {
    my %seen;
    my @files;
    for my $f ($self->_changed_paths) {
```

(leave the rest of the loop unchanged) and add before it:

```perl
  method _changed_paths () {
    my @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'origin/main...HEAD');
    @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'HEAD~1...HEAD') if !@cand;
    chomp @cand;
    return @cand;
  }
```

- [ ] **Step 4: Add batch targeting and findings**

After `_changed_yaml_files`, add:

```perl
  # A full check covers every batch file. A targeted or --changed check covers
  # batches naming a targeted CVE, plus (with --changed) batch files changed
  # on the branch.
  method _resolve_multi_check_targets ($cve, $changed, $yaml_files) {
    my @all = sort grep { -f $_ } glob('announce-multi/*.txt');
    my $targeted = defined $cve && length $cve;
    return @all unless $targeted || $changed;

    my %ids = map { m{(CVE-\d{4}-\d{4,19})\.yaml$}i ? ($1 => 1) : () } @$yaml_files;
    $ids{$cve} = 1 if $targeted;
    my %changed_batch;
    if ($changed) {
      $changed_batch{$_} = 1 for grep { m{^announce-multi/[^/]+\.txt$} } $self->_changed_paths;
    }
    return grep { $changed_batch{$_} || _batch_covers($_, \%ids) } @all;
  }

  # $merged_ref is where a batch counts as merged: the PR base under
  # --pr-policy, _merged_ref otherwise.
  method _announce_multi_findings ($files, $merged_ref) {
    my %findings_by_file;
    my $errors = 0;
    for my $path (@$files) {
      my @findings = map {
        +{ severity => 'error', id => $_->[0], message => $_->[1], path => $path, line => 1 }
      } $self->_multi_file_problems($path, $merged_ref);
      $findings_by_file{$path} = \@findings;
      $errors += @findings;
    }
    return (\%findings_by_file, $errors);
  }

  # Where a batch counts as merged when not under --pr-policy. CI checkouts
  # usually have origin/main but no local main, matching _changed_paths.
  method _merged_ref () {
    my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--verify', '--quiet', 'origin/main');
    return defined($rc) && $rc == 0 ? 'origin/main' : 'main';
  }

  # Problems as [finding id, message] pairs. A merged batch is a record of what
  # was sent: published CVEs can be updated (or even re-ordered or rejected)
  # later, so once merged only its filename is checked.
  method _multi_file_problems ($path, $merged_ref) {
    my $name = basename($path);
    my ($distribution, @ids) = parse_batch_filename($name);
    return ['multi_filename', "$name is not a valid announce-multi filename (expected <Distribution>--CVE-YYYY-NNNN+NNNN.txt)."]
      unless defined $distribution;
    my %seen;
    return ['multi_filename', "$name must name at least 2 distinct CVE IDs."]
      if @ids < 2 || grep { $seen{$_}++ } @ids;

    my @problems;
    my $canonical = batch_filename($distribution, @ids);
    push @problems, ['multi_filename', "$name is not in canonical form; expected $canonical."]
      if $name ne $canonical;
    return @problems if $self->_git_path_exists_at_ref($merged_ref, $path);

    my @cves;
    for my $id (@ids) {
      if (-f File::Spec->catfile('encrypted', "$id.yaml")) {
        push @problems, ['multi_cve_missing', "$id resolves to encrypted/; batches may only contain published CVEs under cves/."];
      } elsif (!-f File::Spec->catfile('cves', "$id.yaml")) {
        push @problems, ['multi_cve_missing', "$id has no YAML under cves/."];
      } elsif (my $cve = eval { $self->_load_multi_cve5($id) }) {
        push @cves, $cve;
      } else {
        (my $err = $@) =~ s/\s+\z//;
        push @problems, ['multi_cve_invalid', "$id cannot be rendered: $err"];
      }
    }
    return @problems if @cves != @ids;

    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my @off = grep { $multi->primary_distribution($_) ne $distribution } @cves;
    if (@off) {
      my $list = join(', ', map { "$_->{cveMetadata}{cveId} (" . $multi->primary_distribution($_) . ')' } @off);
      return @problems, ['multi_distribution',
        "Every CVE must have primary distribution $distribution (from the filename); differs for $list."];
    }

    push @problems, ['multi_mismatch', "$path does not match generated announce-multi output; regenerate it with announce-multi --write."]
      if $multi->render(@cves) ne _read_text_file($path);
    return @problems;
  }
```

After `sub _read_text_file`, add:

```perl
sub _batch_covers ($path, $ids) {
  my (undef, @covered) = parse_batch_filename(basename($path));
  return scalar grep { $ids->{$_} } @covered;
}
```

- [ ] **Step 5: Wire batch checks into `_cmd_check`**

Replace this part of `_cmd_check`:

```perl
    my @yaml_files = $self->_resolve_check_targets($positionals[0] // $default_cve, $opt{changed});
    if (!@yaml_files) {
      print "No CVE YAML files to check.\n";
      return 0;
    }

    my ($findings_by_file, $errors, $warnings) = $self->_lint_and_validate_files(@yaml_files);
    my $pr_policy_errors = 0;
```

with:

```perl
    my $target_cve = $positionals[0] // $default_cve;
    my @yaml_files = $self->_resolve_check_targets($target_cve, $opt{changed});
    my @multi_files = $self->_resolve_multi_check_targets($target_cve, $opt{changed}, \@yaml_files);
    if (!@yaml_files && !@multi_files) {
      print "No CVE YAML files to check.\n";
      return 0;
    }

    my ($findings_by_file, $errors, $warnings) = $self->_lint_and_validate_files(@yaml_files);
    my ($multi_findings, $multi_errors)
      = $self->_announce_multi_findings(\@multi_files, $opt{pr_policy} ? $opt{base_sha} : $self->_merged_ref);
    $self->_merge_findings($findings_by_file, $multi_findings);
    $errors += $multi_errors;
    my $pr_policy_errors = 0;
```

and replace:

```perl
    if ($pr_policy_errors > 0) {
```

with:

```perl
    if ($pr_policy_errors > 0 || $multi_errors > 0) {
```

- [ ] **Step 6: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 7: Document in AGENTS.md**

In `### 3. Edit + Validate`, under "Behavior:", add:

```markdown
  - Also checks `announce-multi/` batch files: all of them on a full check, those naming
    the CVE for `check CVE`, plus changed ones with `--changed`. Findings
    `multi_filename`, `multi_cve_missing`, `multi_cve_invalid`, `multi_distribution` and
    `multi_mismatch` are blocking. A merged batch (on `origin/main`, else `main`, or the PR
    base under `--pr-policy`) only gets the filename checks: it is a record of what was
    sent, and its CVEs may be updated afterwards.
```

- [ ] **Step 8: Commit**

```bash
git add lib/CPANSec/CNA/App.pm t/48-cna-check-announce-multi.t AGENTS.md
git commit -m "Check announce-multi batch files

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Freeze merged batches in the PR policy, and the CI example

**Files:**
- Modify: `lib/CPANSec/CNA/App.pm` (`_cmd_check` pr-policy block; add `_pr_policy_announce_multi_findings`)
- Modify: `examples/github-actions/cna-pr-check.yml`
- Modify: `AGENTS.md` (`## CI / PR Integration`)
- Test: `t/49-cna-check-announce-multi-pr-policy.t`

**Interfaces:**
- Consumes: `_batch_covers` and `$target_cve` (Task 5), existing `_git_show_text_at_ref`, `_run_cmd_capture`, `_read_text_file`.
- Produces: finding ID `multi_not_allowed` (severity `error`, blocking under `--pr-policy`).

- [ ] **Step 1: Write the failing test**

Create `t/49-cna-check-announce-multi-pr-policy.t`:

```perl
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
};

subtest 'a new stale batch is rejected' => sub {
  my ($root, $base) = _base(with_batch => 0);
  _run($root, 'announce-multi CVE-1900-9901 CVE-1900-9902 --write');
  _append_raw("$root/$batch", "hand edit\n");
  my ($rc, $out) = _run($root, "check CVE-1900-9901 --pr-policy --base-sha $base");
  is($rc, 1, 'fails');
  like($out, qr/multi_mismatch/, 'compared with generated output');
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/49-cna-check-announce-multi-pr-policy.t`
Expected: FAIL — `a merged batch must not change` and `must not be removed` fail (no `multi_not_allowed` yet).

- [ ] **Step 3: Implement the policy rule**

In `lib/CPANSec/CNA/App.pm`, after `_pr_policy_announce_findings`, add:

```perl
  # A batch file on the base is frozen, like announce/<CVE>.txt. New batch
  # files are always allowed, so only base-side files are examined. $ids limits
  # this to batches naming those CVEs; undef means every batch.
  method _pr_policy_announce_multi_findings ($base_sha, $ids) {
    my %findings_by_file;
    my $errors = 0;
    for my $path ($self->_run_cmd_capture('git', 'ls-tree', '--name-only', $base_sha, '--', 'announce-multi/')) {
      chomp $path;
      next unless $path =~ m{^announce-multi/[^/]+\.txt$};
      next if $ids && !_batch_covers($path, $ids);

      my $message;
      if (!-f $path) {
        $message = "$path must not be removed once merged.";
      } elsif ($self->_git_show_text_at_ref($base_sha, $path) ne _read_text_file($path)) {
        $message = "$path must not change once merged.";
      }
      next unless defined $message;

      push @{$findings_by_file{$path}}, {
        severity => 'error', id => 'multi_not_allowed', message => $message, path => $path, line => 1,
      };
      $errors++;
    }
    return (\%findings_by_file, $errors);
  }
```

In `_cmd_check`, inside `if ($opt{pr_policy}) { ... }`, after the existing `$pr_policy_errors += $extra_errors;` line, add:

```perl
      my $scope = defined $target_cve && length $target_cve ? { $target_cve => 1 } : undef;
      my ($multi_policy, $multi_policy_errors)
        = $self->_pr_policy_announce_multi_findings($opt{base_sha}, $scope);
      $self->_merge_findings($findings_by_file, $multi_policy);
      $errors += $multi_policy_errors;
      $pr_policy_errors += $multi_policy_errors;
```

- [ ] **Step 4: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 5: Update the CI example**

In `examples/github-actions/cna-pr-check.yml`:

Add to `on.pull_request.paths`:

```yaml
      - "announce-multi/*.txt"
```

Change the diff line to include batch files:

```bash
          if ! changed_raw="$(git diff --name-only "${base_sha}...${head_sha}" -- 'cves/*.yaml' 'cves/*.json' 'announce/*.txt' 'announce-multi/*.txt')"; then
```

Replace the `mapfile -t cves < <(...)` block with:

```bash
          bad_batch=0
          for f in "${changed[@]}"; do
            case "$f" in
              announce-multi/*)
                if ! printf '%s\n' "$f" | grep -qE '^announce-multi/[^/]+--CVE-[0-9]{4}-[0-9]{4,19}(\+(CVE-[0-9]{4}-)?[0-9]{4,19})+\.txt$'; then
                  echo "::error file=$f::announce-multi filename must list at least two CVE IDs (<Dist>--CVE-YYYY-NNNN+NNNN.txt)"
                  bad_batch=1
                fi
                ;;
            esac
          done

          # A batch maps to every CVE it names; checking each CVE also checks
          # (and applies the PR policy to) the batches naming it.
          mapfile -t cves < <(
            {
              printf '%s\n' "${changed[@]}" \
                | sed -nE 's#^(cves|announce)/(CVE-[0-9]{4}-[0-9]{4,19})\.(yaml|json|txt)$#\2#p'
              printf '%s\n' "${changed[@]}" \
                | perl -nE 'next unless m{^announce-multi/[^/]+?--(CVE-.+)\.txt$}; my $y; for (split /\+/, $1) { if (/^CVE-(\d{4})-\d+$/) { $y = $1; say } elsif (defined $y) { say "CVE-$y-$_" } }'
            } | sort -u
          )
```

And change the final status handling so a bad batch name also fails the job — replace:

```bash
          if [ "$status" -ne 0 ]; then
```

with:

```bash
          if [ "$bad_batch" -ne 0 ]; then
            status=1
          fi

          if [ "$status" -ne 0 ]; then
```

Verify the mapping by hand:

```bash
printf '%s\n' announce-multi/Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt cves/CVE-2026-1003.yaml \
  | perl -nE 'next unless m{^announce-multi/[^/]+?--(CVE-.+)\.txt$}; my $y; for (split /\+/, $1) { if (/^CVE-(\d{4})-\d+$/) { $y = $1; say } elsif (defined $y) { say "CVE-$y-$_" } }'
```

Expected:

```
CVE-2025-40906
CVE-2026-1001
CVE-2026-1002
```

- [ ] **Step 6: Document in AGENTS.md**

In `## CI / PR Integration`, after the GitHub Action bullets, add:

```markdown
`announce-multi/` under `--pr-policy`:
- New batch files are always allowed, including for CVEs already on the base.
- A batch file on the base must not change or be removed (`multi_not_allowed`).
- The example workflow watches `announce-multi/*.txt`, maps each changed batch to the CVEs
  its filename names, and fails on batch filenames that do not parse.
- The data repo's `cna-lint.yml` (`check --changed`) must also include
  `announce-multi/*.txt` in any `paths:` filter, or a PR that only adds a batch file is
  never checked.
```

- [ ] **Step 7: Commit**

```bash
git add lib/CPANSec/CNA/App.pm t/49-cna-check-announce-multi-pr-policy.t examples/github-actions/cna-pr-check.yml AGENTS.md
git commit -m "Freeze merged announce-multi batches in the PR policy

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: End-to-end sanity

- [ ] **Step 1: Full suite**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.` (50 files).

- [ ] **Step 2: Render a real-looking batch by hand and read it**

```bash
root=$(mktemp -d); mkdir -p "$root/cves"
for id in CVE-1900-9901 CVE-1900-9902; do
  sed "s/^  cve: .*/  cve: $id/" t/var/CVE-2025-40916.yaml > "$root/cves/$id.yaml"
done
nix develop --offline -c scripts/cna --cpansec-cna-root "$root" announce-multi CVE-1900-9902 CVE-1900-9901 | head -30
```

Expected: `Subject: Mojolicious-Plugin-CaptchaPNG for Perl: 2 CVEs`, two blank lines, the title, the two-entry index, two blank lines, then the `CVE-1900-9901` banner. No line wider than 72 columns.
