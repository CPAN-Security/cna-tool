# announce-multi sync and status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a branch that drafts several CVEs keep its multi-CVE batch in step automatically: `announce-multi --sync [--write]`, a status report from bare `announce-multi`, and a non-blocking `check` warning when a branch batch leaves out a branch CVE.

**Architecture:** Everything lives in `CPANSec::CNA::App`, next to the existing `announce-multi` code. One planning method (`_sync_plan`) computes the branch's new CVEs, groups them by primary distribution, and decides which batch files to write, keep, or remove; `--sync`, the status report and the check warning all read it (or its helpers), so they can never disagree.

**Tech Stack:** Perl v5.42, `feature 'class'`, `List::Util` (core), git, `Test::More`, Nix dev shell.

**Spec:** `multi-announce-handoff.md`, sections "Decisions (2026-10-14)" and "Decisions: branch sync and status (2026-10-14)".

## Global Constraints

- Perl `v5.42`; keep the style of the surrounding `announce-multi` code in `lib/CPANSec/CNA/App.pm`.
- No new non-core dependencies. No network in tests; fixtures come from `t/var/` and are copied into temp git repos.
- Run tests with `nix develop --offline -c prove -lr t`.
- "New on this branch" = `cves/<CVE>.yaml` exists in the working tree (committed or not) and does not exist on the merged ref. Merged ref = `origin/main`, else `main`, only if the ref exists; under `check --pr-policy` it is the base sha.
- `encrypted/` is never read for batching; encrypted drafts are only counted (by filename).
- `--sync --write` may delete only unmerged batch files that name at least one branch CVE and are not a sync target. Merged batches and unmerged batches naming no branch CVE are never touched. Every removal is printed.
- `--output` and `--force` do not combine with `--sync`.
- Bare `announce-multi` changes nothing and exits 0.
- `multi_incomplete` has severity `warning` (blocking only under `--strict`) and never fires when no batch exists.
- `scripts/cna` prefixes die messages with `ERROR: `; never anchor die-output regexes at line start.
- Commit messages: short imperative subject, blank line, `Co-Authored-By: <model> <noreply@anthropic.com>`.

## Review Focus

- An uncommitted draft CVE (file exists, never `git add`ed) must count as new on the branch (Task 1 "preview" test).
- An unmerged batch made from already-published CVEs only must survive `--sync --write` (Task 1 "left alone" test).
- Dropping a draft below two CVEs must remove the now-obsolete branch batch, not leave it stale (Task 1 "dropped draft" test).
- A repo with no `origin/main` and no `main` must not treat every CVE as new: `--sync` refuses, status says why (Task 1 and Task 2 "no merged ref" tests).
- A broken draft YAML must block `--sync --write` with its CVE ID named, but not crash status (Task 1 "errors", Task 2 "invalid draft").

---

### Task 1: `announce-multi --sync`

**Files:**
- Modify: `lib/CPANSec/CNA/App.pm` (imports; `_cmd_announce_multi`; `_warn_if_no_merged_ref`; `_usage_text`; new methods `_existing_merged_ref`, `_write_text_file`, `_new_on_branch`, `_load_groups`, `_sync_plan`, `_sync_plan_lines`, `_announce_multi_sync`)
- Modify: `AGENTS.md` (section `### 5b. Multi-CVE Announcements`, Quick Command Reference)
- Test: `t/50-cna-announce-multi-sync.t`

**Interfaces:**
- Consumes (existing): `_load_multi_cve5($id)`, `_git_path_exists_at_ref($ref, $path)`, `_assert_encrypted_write_safe($path)`, `_run_cmd_capture_with_rc(@cmd)`, plain sub `_read_text_file($path)`, `CPANSec::CVE::AnnounceMulti->render/primary_distribution`, `batch_filename`, `parse_batch_filename`, `sort_cve_ids`.
- Produces (used by Tasks 2 and 3):
  - `_existing_merged_ref() -> Str|undef` — `'origin/main'`, else `'main'`, else undef.
  - `_new_on_branch($ref, $base_dir) -> @ids` — sorted CVE IDs with `$base_dir/<id>.yaml` in the working tree but not on `$ref`.
  - `_load_groups(@ids) -> (\%groups, \@invalid)` — `%groups = (dist => [[id, cve5], ...])`, `@invalid = ([id, error], ...)`.
  - `_sync_plan($ref, @explicit) -> HashRef` with keys `ref`, `branch` (ids), `invalid`, `groups` (`dist => [ids]`), `batches` (`[{distribution, ids, path, text, state}]`, state `write|unchanged|merged`), `singles` (`[[dist, id]]`), `removes` (paths).
  - `_sync_plan_lines($plan) -> @lines` — `writes P`, `unchanged P`, `already merged P`, `removes P`, `skips D: only ID (a batch needs 2+ CVEs)`, or `nothing to batch`.

- [ ] **Step 1: Write the failing test**

Create `t/50-cna-announce-multi-sync.t`:

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
my $mojo = 'announce-multi/Mojolicious-Plugin-CaptchaPNG';

subtest 'preview lists the plan and writes nothing' => sub {
  my $root = _repo('CVE-1900-9901');
  _seed($root, 'CVE-1900-9902');
  _commit_all($root, 'draft 9902');
  _seed($root, 'CVE-1900-9903');    # never git-added
  my ($rc, $out) = _run($root, 'announce-multi --sync');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^  writes \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'branch CVEs, committed or not');
  unlike($out, qr/9901/, 'the merged CVE is left out');
  like($out, qr/^Run with --write to apply\.$/m, 'says how to apply');
  ok(!-e "$root/announce-multi", 'nothing written');
};

subtest '--write writes the same text as the explicit form' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my $path = "$mojo--CVE-1900-9902+9903.txt";
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$path\E$/m, 'reports the write');
  is(_slurp_raw("$root/$path"), _stdout($root, 'announce-multi CVE-1900-9902 CVE-1900-9903'), 'same text');
  ($rc, $out) = _run($root, 'announce-multi --sync --write');
  like($out, qr/^Unchanged \Q$path\E$/m, 're-running is a no-op');
};

subtest 'a new draft replaces the old batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$mojo\E--CVE-1900-9902\+9903\+9904\.txt$/m, 'writes the new set');
  like($out, qr/^Removed \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'reports the removal');
  ok(!-e "$root/$mojo--CVE-1900-9902+9903.txt", 'old batch gone');
};

subtest 'a dropped draft removes the batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  unlink "$root/cves/CVE-1900-9903.yaml" or die "unlink failed: $!";
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Removed \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'removes the obsolete batch');
  like($out, qr/^Skipped Mojolicious-Plugin-CaptchaPNG: only CVE-1900-9902 /m, 'reports the single CVE');
  ok(!-e "$root/$mojo--CVE-1900-9902+9903.txt", 'batch gone');
};

subtest 'batches of published CVEs are left alone' => sub {
  my $root = _repo(qw(CVE-1900-9900 CVE-1900-9901));
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  ok(-f "$root/$mojo--CVE-1900-9900+9901.txt", 'published-only batch kept');
  unlike($out, qr/^Removed/m, 'nothing removed');
};

subtest 'an explicit set that is already merged is reported, not rewritten' => sub {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9900 CVE-1900-9901);
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _commit_all($root, 'base with batch');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
  my $path = "$mojo--CVE-1900-9900+9901.txt";
  my $before = _slurp_raw("$root/$path");
  _edit("$root/cves/CVE-1900-9901.yaml", sub { s/which is insecure\./which is insecure. Updated./ or die 'no match' });
  my ($rc, $out) = _run($root, 'announce-multi --sync CVE-1900-9900 CVE-1900-9901 --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Already merged \Q$path\E$/m, 'reports the merged batch');
  is(_slurp_raw("$root/$path"), $before, 'merged batch untouched');
};

subtest 'explicit IDs join the branch CVEs' => sub {
  my $root = _repo('CVE-1900-9901');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my ($rc, $out) = _run($root, 'announce-multi --sync CVE-1900-9901 --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$mojo\E--CVE-1900-9901\+9902\+9903\.txt$/m, 'merged CVE included on request');
};

subtest 'one CVE per distribution is reported, not batched' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _seed($root, 'CVE-1900-9905', 't/var/CVE-2025-40906.yaml');
  my ($rc, $out) = _run($root, 'announce-multi --sync --write');
  is($rc, 0, 'succeeds') or diag $out;
  like($out, qr/^Wrote \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'batches the pair');
  like($out, qr/^Skipped BSON-XS: only CVE-1900-9905 /m, 'reports the single');
  is_deeply([glob("$root/announce-multi/BSON-XS--*")], [], 'no BSON-XS batch');
};

subtest 'errors' => sub {
  my $trunk = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'trunk', $trunk) == 0 or die 'git init failed';
  _seed($trunk, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _commit_all($trunk, 'trunk');
  my ($rc, $out) = _run($trunk, 'announce-multi --sync');
  isnt($rc, 0, 'refuses without a merged ref');
  like($out, qr{neither origin/main nor main exists}, 'explains why');

  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  ($rc, $out) = _run($root, 'announce-multi --sync --output x.txt');
  isnt($rc, 0, 'refuses --output');
  like($out, qr/--output cannot be combined with --sync/, 'explains --output');
  ($rc, $out) = _run($root, 'announce-multi --sync --force');
  isnt($rc, 0, 'refuses --force');
  like($out, qr/--force cannot be combined with --sync/, 'explains --force');
  ($rc, $out) = _run($root, 'announce-multi --sync CVE-1900-9999');
  isnt($rc, 0, 'refuses a missing explicit CVE');
  like($out, qr/CVE-1900-9999/, 'names it');

  _write_raw("$root/cves/CVE-1900-9906.yaml", "cpansec: [\n");
  ($rc, $out) = _run($root, 'announce-multi --sync --write');
  isnt($rc, 0, 'refuses to write with a broken draft');
  like($out, qr/Cannot sync: these CVEs cannot be loaded/, 'explains');
  like($out, qr/CVE-1900-9906/, 'names the broken draft');
  ok(!-e "$root/announce-multi", 'nothing written');
  ($rc, $out) = _run($root, 'announce-multi --sync');
  is($rc, 0, 'preview still works') or diag $out;
  like($out, qr/Skipped \(cannot be loaded\):\n  CVE-1900-9906/, 'preview reports the broken draft');
};

done_testing();

sub _repo (@base) {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for @base;
  _write_raw("$root/.seed", "seed\n");
  _commit_all($root, 'base');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
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

sub _write_raw ($path, $text) {
  open(my $fh, '>:raw', $path) or die "Cannot write $path: $!";
  print {$fh} $text;
  close($fh);
}

sub _commit_all ($root, $msg) {
  system('git', '-C', $root, 'add', '-A') == 0 or die 'git add failed';
  system('git', '-C', $root, 'commit', '-q', '-m', $msg) == 0 or die 'git commit failed';
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/50-cna-announce-multi-sync.t`
Expected: FAIL — `Unknown option '--sync'`.

- [ ] **Step 3: Imports and shared helpers**

In `lib/CPANSec/CNA/App.pm` change the BatchName import and add List::Util:

```perl
use CPANSec::CVE::BatchName qw(batch_filename parse_batch_filename sort_cve_ids);
```

```perl
use List::Util qw(max uniq);
```

(place `List::Util` alphabetically among the other `use` lines, after `JSON::PP`).

Next to `_merged_ref`, add:

```perl
  # origin/main, else main, but only a ref that exists.
  method _existing_merged_ref () {
    for my $ref (qw(origin/main main)) {
      my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--verify', '--quiet', $ref);
      return $ref if defined($rc) && $rc == 0;
    }
    return undef;
  }
```

and in `_warn_if_no_merged_ref` replace the `for my $ref (qw(origin/main main)) { ... }` loop with:

```perl
    return if defined $self->_existing_merged_ref;
```

Add a write helper and use it in `_cmd_announce_multi` (replace the `_assert_encrypted_write_safe` … `close($fh);` block there with `$self->_write_text_file($out, $text);`, keeping the `print "Wrote $out\n";` line):

```perl
  method _write_text_file ($out, $text) {
    $self->_assert_encrypted_write_safe($out);
    my $dir = dirname($out);
    make_path($dir) unless -d $dir;
    open(my $fh, '>:encoding(UTF-8)', $out) or die "Cannot write $out: $!\n";
    print {$fh} $text;
    close($fh);
    return;
  }
```

- [ ] **Step 4: Branch detection and the sync plan**

After `_overlapping_batches`, add:

```perl
  # CVEs new on this branch: $base_dir/<id>.yaml is in the working tree
  # (committed or not) but not on $ref.
  method _new_on_branch ($ref, $base_dir) {
    return sort_cve_ids(
      grep { !$self->_git_path_exists_at_ref($ref, "$base_dir/$_.yaml") }
      map { m{^\Q$base_dir\E/(CVE-\d{4}-\d{4,19})\.yaml$} ? $1 : () } glob("$base_dir/*.yaml")
    );
  }

  # Load @ids for batching, grouped by primary distribution:
  # ({ dist => [[id, cve5], ...] }, [[id, error], ...]).
  method _load_groups (@ids) {
    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my (%groups, @invalid);
    for my $id (sort_cve_ids(uniq(@ids))) {
      my $cve = eval { $self->_load_multi_cve5($id) };
      my $err = $@;
      my $distribution = $cve ? $multi->primary_distribution($cve) : '';
      if (!length $distribution) {
        ($err ||= 'no primary distribution (affected[0].packageName)') =~ s/\s+\z//;
        push @invalid, [$id, $err];
        next;
      }
      push @{$groups{$distribution}}, [$id, $cve];
    }
    return (\%groups, \@invalid);
  }

  # What --sync does: every distribution with 2+ CVEs (new on the branch, plus
  # @explicit) gets one batch, and the branch's own superseded batches go. A
  # batch is the branch's own when it is unmerged and names a branch CVE;
  # merged batches and batches of already-published CVEs are left alone.
  method _sync_plan ($ref, @explicit) {
    my @branch = $self->_new_on_branch($ref, 'cves');
    my %branch = map { $_ => 1 } @branch;
    my ($groups, $invalid) = $self->_load_groups(@branch, @explicit);
    my %explicit = map { $_ => 1 } @explicit;
    if (my ($bad) = grep { $explicit{$_->[0]} } @$invalid) {
      die "$bad->[0]: $bad->[1]\n";
    }

    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my (@batches, @singles);
    for my $distribution (sort keys %$groups) {
      my @members = $groups->{$distribution}->@*;
      if (@members < 2) {
        push @singles, [$distribution, $members[0][0]];
        next;
      }
      my @ids = map { $_->[0] } @members;
      my $path = File::Spec->catfile('announce-multi', batch_filename($distribution, @ids));
      my $text = $multi->render(map { $_->[1] } @members);
      my $state = $self->_git_path_exists_at_ref($ref, $path) ? 'merged'
        : (-f $path && _read_text_file($path) eq $text) ? 'unchanged'
        : 'write';
      push @batches, { distribution => $distribution, ids => \@ids, path => $path, text => $text, state => $state };
    }

    my %target = map { $_->{path} => 1 } @batches;
    my @removes;
    for my $path (sort glob('announce-multi/*.txt')) {
      next if $target{$path} || $self->_git_path_exists_at_ref($ref, $path);
      my (undef, @covered) = parse_batch_filename(basename($path));
      push @removes, $path if grep { $branch{$_} } @covered;
    }

    return {
      ref     => $ref,
      branch  => \@branch,
      invalid => $invalid,
      groups  => { map { $_ => [map { $_->[0] } $groups->{$_}->@*] } keys %$groups },
      batches => \@batches,
      singles => \@singles,
      removes => \@removes,
    };
  }

  method _sync_plan_lines ($plan) {
    my %verb = (write => 'writes', unchanged => 'unchanged', merged => 'already merged');
    my @lines = map { "$verb{$_->{state}} $_->{path}" } $plan->{batches}->@*;
    push @lines, map { "removes $_" } $plan->{removes}->@*;
    push @lines, map { "skips $_->[0]: only $_->[1] (a batch needs 2+ CVEs)" } $plan->{singles}->@*;
    return @lines ? @lines : ('nothing to batch');
  }

  method _announce_multi_sync ($opt, @explicit) {
    die "--output cannot be combined with --sync (it writes one file per distribution)\n" if defined $opt->{output};
    die "--force cannot be combined with --sync (it never overwrites merged batches)\n" if $opt->{force};
    my $ref = $self->_existing_merged_ref
      // die "Cannot tell which CVEs are new on this branch: neither origin/main nor main exists.\n";
    my $plan = $self->_sync_plan($ref, @explicit);

    if (my @bad = $plan->{invalid}->@*) {
      my $list = join('', map { "  $_->[0]: $_->[1]\n" } @bad);
      die "Cannot sync: these CVEs cannot be loaded:\n$list" if $opt->{write};
      print STDERR "Skipped (cannot be loaded):\n$list";
    }

    if (!$opt->{write}) {
      print "--sync would:\n", map("  $_\n", $self->_sync_plan_lines($plan));
      print "Run with --write to apply.\n";
      return 0;
    }

    for my $batch ($plan->{batches}->@*) {
      if ($batch->{state} eq 'write') {
        $self->_write_text_file($batch->{path}, $batch->{text});
        print "Wrote $batch->{path}\n";
      } elsif ($batch->{state} eq 'unchanged') {
        print "Unchanged $batch->{path}\n";
      } else {
        print "Already merged $batch->{path}\n";
      }
    }
    for my $path ($plan->{removes}->@*) {
      unlink $path or die "Cannot remove $path: $!\n";
      print "Removed $path\n";
    }
    print "Skipped $_->[0]: only $_->[1] (a batch needs 2+ CVEs)\n" for $plan->{singles}->@*;
    return 0;
  }
```

- [ ] **Step 5: Wire `--sync` into the command**

In `_cmd_announce_multi`:
- initialise `%opt` as `(write => 0, force => 0, sync => 0)`;
- in the argument loop, before the `--output` handling, add `if ($a eq '--sync') { $opt{sync} = 1; next; }`;
- directly after the loop (before the single-CVE `die`), add:

```perl
    return $self->_announce_multi_sync(\%opt, @ids) if $opt{sync};
```

- change the usage `die` to:

```perl
    die "Usage: cna announce-multi <CVE-ID> <CVE-ID>... [--write|--output path] [--force]\n"
      . "       cna announce-multi --sync [CVE-ID...] [--write]\n" unless @ids >= 2;
```

In `_usage_text`, after the existing `announce-multi` entry, add:

```
  announce-multi --sync [CVE-ID...] [--write]
                                    Batch this branch's new CVEs per distribution
                                    (--write: write them, replace superseded batches)
```

- [ ] **Step 6: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 7: Document**

In AGENTS.md `### 5b. Multi-CVE Announcements`, after the existing command lines add:

```markdown
- `cpansec-cna announce-multi --sync [CVE...]` (preview) / `--sync --write`
  - Batches the CVEs new on this branch: `cves/<CVE>.yaml` in the working tree (committed
    or not) but not on `origin/main` (else `main`), plus any CVEs named explicitly. One
    batch per primary distribution with 2+ CVEs; a distribution with one is reported.
  - `--write` writes the batches and removes the branch's own superseded batches (unmerged
    files naming a branch CVE that are no longer a target), printing each removal. Merged
    batches and batches of already-published CVEs are never touched.
  - Refuses without `origin/main` or `main`, with `--output` or `--force`, and (with
    `--write`) when a branch CVE cannot be loaded. `encrypted/` drafts are never batched.
```

In Quick Command Reference, after the `announce-multi` line add:

```markdown
- `cpansec-cna announce-multi --sync [CVE...] [--write]`
```

- [ ] **Step 8: Commit**

```bash
git add lib/CPANSec/CNA/App.pm t/50-cna-announce-multi-sync.t AGENTS.md
git commit -m "Add announce-multi --sync

Co-Authored-By: <model> <noreply@anthropic.com>"
```

---

### Task 2: Bare `announce-multi` prints status

**Files:**
- Modify: `lib/CPANSec/CNA/App.pm` (`_cmd_announce_multi`; new methods `_announce_multi_status`; new plain sub `_batch_status`)
- Modify: `t/47-cna-announce-multi.t` (the `'no CVEs'` error case)
- Modify: `AGENTS.md` (5b, Quick Command Reference)
- Test: `t/51-cna-announce-multi-status.t`

**Interfaces:**
- Consumes (Task 1): `_existing_merged_ref`, `_new_on_branch`, `_sync_plan`, `_sync_plan_lines`; `max` from List::Util; existing `_git_current_branch` (dies outside git or on detached HEAD).

Status format (exact):

```
Branch: <branch>                      (omitted when unknown)
Merged ref: <ref>

New CVEs on this branch: none         (or the block below)
New CVEs on this branch:
  <dist padded to longest>  <id>, <id>[ (only one, nothing to batch)]
  <id>: cannot be loaded: <error>
  <N> CVE[s] under encrypted/ skipped (batches are public-only)

Batches:                              (omitted when none)
  <path>
      <state>

Next:
  ...
```

States: `merged (frozen)`, `unmerged, filename does not parse`, `unmerged, not tied to this branch (left alone by --sync)`, `unmerged, out of sync: --sync removes it`, `unmerged, in sync`, `unmerged, stale: content out of date`, `unmerged, out of sync: missing <ids>`, `unmerged, out of sync: --sync replaces it with <path>`. Listed batches: every unmerged batch file, plus merged ones that name a branch CVE.

- [ ] **Step 1: Write the failing test**

Create `t/51-cna-announce-multi-status.t` with the same header (git config block), `$cna`, `$mojo`, and helper subs (`_repo`, `_seed`, `_edit`, `_run`, `_write_raw`, `_commit_all`) as `t/50-cna-announce-multi-sync.t`, and these subtests:

```perl
subtest 'nothing new' => sub {
  my $root = _repo('CVE-1900-9901');
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr/^Branch: work$/m, 'names the branch');
  like($out, qr/^Merged ref: main$/m, 'names the merged ref');
  like($out, qr/^New CVEs on this branch: none$/m, 'nothing new');
  like($out, qr/Nothing to batch from this branch/, 'says so');
  like($out, qr/^  cpansec-cna announce-multi <CVE-ID> <CVE-ID>\.\.\. --write$/m, 'suggests the explicit form');
};

subtest 'new CVEs without a batch' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _seed($root, 'CVE-1900-9905', 't/var/CVE-2025-40906.yaml');
  make_path("$root/encrypted");
  copy('t/var/CVE-2025-40916.yaml', "$root/encrypted/CVE-1900-9908.yaml") or die "copy failed: $!";
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr/^  Mojolicious-Plugin-CaptchaPNG +CVE-1900-9902, CVE-1900-9903$/m, 'groups by distribution');
  like($out, qr/^  BSON-XS +CVE-1900-9905 \(only one, nothing to batch\)$/m, 'notes single CVEs');
  like($out, qr{^  1 CVE under encrypted/ skipped \(batches are public-only\)$}m, 'counts encrypted drafts');
  like($out, qr/^Next:\n  cpansec-cna announce-multi --sync --write\n      writes \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m,
    'suggests the sync');
  like($out, qr/\(batches are optional\)/, 'batches stay optional');
  ok(!-e "$root/announce-multi", 'writes nothing');
};

subtest 'in sync, then stale' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  my $path = "$mojo--CVE-1900-9902+9903.txt";
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^  \Q$path\E\n      unmerged, in sync$/m, 'in sync');
  like($out, qr/^  All batches are in sync\.\n  cpansec-cna check --changed$/m, 'suggests check');

  _edit("$root/cves/CVE-1900-9903.yaml", sub { s/which is insecure\./which is insecure. Edited./ or die 'no match' });
  ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^      unmerged, stale: content out of date$/m, 'stale');
  like($out, qr/^      writes \Q$path\E$/m, 'suggests rewriting it');
};

subtest 'out of sync' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^      unmerged, out of sync: missing CVE-1900-9904$/m, 'names the missing CVE');
  like($out, qr/^      writes \Q$mojo\E--CVE-1900-9902\+9903\+9904\.txt$/m, 'suggests the new batch');
  like($out, qr/^      removes \Q$mojo\E--CVE-1900-9902\+9903\.txt$/m, 'and the removal');
  unlike($out, qr/batches are optional/, 'no optional note when a batch exists');
};

subtest 'published-only batches are listed but left alone' => sub {
  my $root = _repo(qw(CVE-1900-9900 CVE-1900-9901));
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  my ($rc, $out) = _run($root, 'announce-multi');
  like($out, qr/^  \Q$mojo\E--CVE-1900-9900\+9901\.txt\n      unmerged, not tied to this branch \(left alone by --sync\)$/m,
    'explains it is not the branch’s');
};

subtest 'merged batches not touching the branch are not listed' => sub {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'main', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9900 CVE-1900-9901);
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _commit_all($root, 'base with batch');
  system('git', '-C', $root, 'switch', '-q', '-c', 'work') == 0 or die 'git switch failed';
  my ($rc, $out) = _run($root, 'announce-multi');
  unlike($out, qr/CVE-1900-9900\+9901/, 'not listed');
};

subtest 'no merged ref' => sub {
  my $root = tempdir(CLEANUP => 1);
  system('git', 'init', '-q', '-b', 'trunk', $root) == 0 or die 'git init failed';
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _commit_all($root, 'trunk');
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr{neither origin/main nor main exists}, 'explains');
  like($out, qr/^  cpansec-cna announce-multi <CVE-ID> <CVE-ID>\.\.\. --write$/m, 'suggests the explicit form');
};

subtest 'invalid draft' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _write_raw("$root/cves/CVE-1900-9906.yaml", "cpansec: [\n");
  my ($rc, $out) = _run($root, 'announce-multi');
  is($rc, 0, 'exits 0') or diag $out;
  like($out, qr/^  CVE-1900-9906: cannot be loaded: /m, 'lists the broken draft');
  like($out, qr/^  Fix the CVEs that cannot be loaded, then sync\.$/m, 'says to fix it');
};

subtest '--write without CVEs is still a usage error' => sub {
  my $root = _repo();
  my ($rc, $out) = _run($root, 'announce-multi --write');
  isnt($rc, 0, 'refuses');
  like($out, qr/Usage: cna announce-multi/, 'shows usage');
};

done_testing();
```

(The helper subs are copied from `t/50`, unchanged. `_repo`, `_run`, etc. are needed; `_stdout` and `_slurp_raw` are not.)

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/51-cna-announce-multi-status.t`
Expected: FAIL — bare `announce-multi` dies with the usage message.

- [ ] **Step 3: Implement**

In `_cmd_announce_multi`, directly after the `--sync` dispatch line from Task 1, add:

```perl
    return $self->_announce_multi_status
      if !@ids && !$opt{write} && !$opt{force} && !defined $opt{output};
```

After `_announce_multi_sync`, add:

```perl
  # Bare announce-multi: what the branch has, what its batches look like, and
  # what to run next. Changes nothing.
  method _announce_multi_status () {
    my $branch = eval { $self->_git_current_branch };
    print "Branch: $branch\n" if defined $branch;
    my $ref = $self->_existing_merged_ref;
    if (!defined $ref) {
      print "Cannot tell which CVEs are new on this branch: neither origin/main nor main exists.\n\n",
        "Next:\n  cpansec-cna announce-multi <CVE-ID> <CVE-ID>... --write\n";
      return 0;
    }
    print "Merged ref: $ref\n\n";

    my $plan = $self->_sync_plan($ref);
    my %groups = $plan->{groups}->%*;
    my @invalid = $plan->{invalid}->@*;
    my $encrypted = () = $self->_new_on_branch($ref, 'encrypted');

    if (!%groups && !@invalid && !$encrypted) {
      print "New CVEs on this branch: none\n";
    } else {
      print "New CVEs on this branch:\n";
      my $width = max(map { length } keys %groups) // 0;
      for my $distribution (sort keys %groups) {
        my @ids = $groups{$distribution}->@*;
        printf "  %-*s  %s%s\n", $width, $distribution, join(', ', @ids),
          @ids == 1 ? ' (only one, nothing to batch)' : '';
      }
      print "  $_->[0]: cannot be loaded: $_->[1]\n" for @invalid;
      printf "  %d CVE%s under encrypted/ skipped (batches are public-only)\n", $encrypted, $encrypted == 1 ? '' : 's'
        if $encrypted;
    }

    my %branch = map { $_ => 1 } $plan->{branch}->@*;
    my @listed;
    for my $path (sort glob('announce-multi/*.txt')) {
      my $merged = $self->_git_path_exists_at_ref($ref, $path);
      my (undef, @covered) = parse_batch_filename(basename($path));
      next if $merged && !grep { $branch{$_} } @covered;
      push @listed, [$path, _batch_status($path, $plan, $merged, \%branch)];
    }
    if (@listed) {
      print "\nBatches:\n";
      print "  $_->[0]\n      $_->[1]\n" for @listed;
    }

    print "\nNext:\n";
    print "  Fix the CVEs that cannot be loaded, then sync.\n" if @invalid;
    my @changes = grep { /^(?:writes|removes) / } $self->_sync_plan_lines($plan);
    if (@changes) {
      print "  cpansec-cna announce-multi --sync --write\n", map("      $_\n", @changes);
      print "  (batches are optional)\n"
        unless grep { $_->[1] =~ /^unmerged, (?:in sync|stale|out of sync)/ } @listed;
    } elsif (grep { $_->{state} eq 'unchanged' } $plan->{batches}->@*) {
      print "  All batches are in sync.\n  cpansec-cna check --changed\n";
    } else {
      print "  Nothing to batch from this branch. To batch already-published CVEs:\n",
        "  cpansec-cna announce-multi <CVE-ID> <CVE-ID>... --write\n";
    }
    return 0;
  }
```

After the plain sub `_batch_covers`, add:

```perl
sub _batch_status ($path, $plan, $merged, $branch) {
  return 'merged (frozen)' if $merged;
  my ($distribution, @ids) = parse_batch_filename(basename($path));
  return 'unmerged, filename does not parse' unless defined $distribution;
  return 'unmerged, not tied to this branch (left alone by --sync)' unless grep { $branch->{$_} } @ids;
  my ($target) = grep { $_->{distribution} eq $distribution } $plan->{batches}->@*;
  return 'unmerged, out of sync: --sync removes it' unless $target;
  if ($target->{path} eq $path) {
    return $target->{state} eq 'unchanged' ? 'unmerged, in sync' : 'unmerged, stale: content out of date';
  }
  my %have = map { $_ => 1 } @ids;
  my @missing = grep { !$have{$_} } $target->{ids}->@*;
  return @missing
    ? 'unmerged, out of sync: missing ' . join(', ', @missing)
    : "unmerged, out of sync: --sync replaces it with $target->{path}";
}
```

In `t/47-cna-announce-multi.t`, in the `errors` subtest, change the case
`['announce-multi', qr/Usage: cna announce-multi/, 'no CVEs'],`
to
`['announce-multi --write', qr/Usage: cna announce-multi/, 'no CVEs with --write'],`
(bare `announce-multi` is now the status report).

- [ ] **Step 4: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 5: Document**

In AGENTS.md 5b, first in the command list add:

```markdown
- `cpansec-cna announce-multi` (no arguments): status only, changes nothing. Shows the
  branch and merged ref, the CVEs new on the branch grouped by distribution, each batch
  touching the branch with its state (merged/frozen, in sync, stale, out of sync, not tied
  to the branch), and the command to run next.
```

In Quick Command Reference, change the `--sync` line to:

```markdown
- `cpansec-cna announce-multi [--sync [CVE...] [--write]]` (no arguments: status)
```

- [ ] **Step 6: Commit**

```bash
git add lib/CPANSec/CNA/App.pm t/51-cna-announce-multi-status.t t/47-cna-announce-multi.t AGENTS.md
git commit -m "Show announce-multi status when run without arguments

Co-Authored-By: <model> <noreply@anthropic.com>"
```

---

### Task 3: `multi_incomplete` check warning

**Files:**
- Modify: `lib/CPANSec/CNA/App.pm` (`_cmd_check`; new method `_multi_incomplete_findings`)
- Modify: `AGENTS.md` (`### 3. Edit + Validate`)
- Test: `t/52-cna-check-multi-incomplete.t`

**Interfaces:**
- Consumes (Task 1): `_existing_merged_ref`, `_new_on_branch`, `_load_groups`.

- [ ] **Step 1: Write the failing test**

Create `t/52-cna-check-multi-incomplete.t` with the same header and helper subs as `t/50` (`_repo`, `_seed`, `_run`, `_commit_all`, `_write_raw`, `_edit`), plus:

```perl
subtest 'a branch batch missing a branch CVE warns, without blocking' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  my (undef, $in_sync) = _run($root, 'check CVE-1900-9902');
  unlike($in_sync, qr/multi_incomplete/, 'in sync: no warning');

  _seed($root, 'CVE-1900-9904');
  my ($rc, $out) = _run($root, 'check CVE-1900-9902');
  is($rc, 0, 'not blocking') or diag $out;
  like($out, qr/multi_incomplete/, 'warns');
  like($out, qr/leaves out CVE-1900-9904/, 'names the missing CVE');
  is(_warnings($out), _warnings($in_sync) + 1, 'counted as one more warning');
};

subtest 'no batch, no warning' => sub {
  my $root = _repo();
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my (undef, $out) = _run($root, 'check CVE-1900-9902');
  unlike($out, qr/multi_incomplete/, 'batches are optional');
};

subtest 'a batch of published CVEs does not warn' => sub {
  my $root = _repo(qw(CVE-1900-9900 CVE-1900-9901));
  _run($root, 'announce-multi CVE-1900-9900 CVE-1900-9901 --write');
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  my (undef, $out) = _run($root, 'check CVE-1900-9900');
  unlike($out, qr/multi_incomplete/, 'not the branch’s batch');
};

subtest 'under --pr-policy the base is the reference' => sub {
  my $root = _repo();
  my $base = qx(git -C '$root' rev-parse HEAD);
  chomp $base;
  _seed($root, $_) for qw(CVE-1900-9902 CVE-1900-9903);
  _run($root, 'announce-multi --sync --write');
  _seed($root, 'CVE-1900-9904');
  my (undef, $out) = _run($root, "check CVE-1900-9902 --pr-policy --base-sha $base");
  like($out, qr/multi_incomplete/, 'warns against the PR base');
};

done_testing();

sub _warnings ($out) {
  my ($n) = $out =~ /Summary: \d+ error\(s\), (\d+) warning\(s\)/ or die "no summary in:\n$out";
  return $n;
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop --offline -c prove -l t/52-cna-check-multi-incomplete.t`
Expected: FAIL — no `multi_incomplete` finding.

- [ ] **Step 3: Implement**

After `_announce_multi_findings`, add:

```perl
  # Advisory: a batch that is the branch's own (unmerged, naming a branch CVE)
  # should name every branch CVE of its distribution. Batches stay optional, so
  # nothing fires without one.
  method _multi_incomplete_findings ($files, $ref) {
    my @branch = $self->_new_on_branch($ref, 'cves');
    my %branch = map { $_ => 1 } @branch;
    my ($groups) = $self->_load_groups(@branch);
    my %findings_by_file;
    my $warnings = 0;
    for my $path (@$files) {
      next if $self->_git_path_exists_at_ref($ref, $path);
      my ($distribution, @ids) = parse_batch_filename(basename($path));
      next unless defined $distribution && grep { $branch{$_} } @ids;
      my %have = map { $_ => 1 } @ids;
      my @missing = grep { !$have{$_} } map { $_->[0] } @{$groups->{$distribution} // []};
      next unless @missing;
      push @{$findings_by_file{$path}}, {
        severity => 'warning',
        id       => 'multi_incomplete',
        message  => "$path leaves out " . join(', ', @missing)
          . ", new on this branch for $distribution; run announce-multi --sync --write.",
        path     => $path,
        line     => 1,
      };
      $warnings++;
    }
    return (\%findings_by_file, $warnings);
  }
```

In `_cmd_check`, directly after

```perl
    $self->_merge_findings($findings_by_file, $multi_findings);
    $errors += $multi_errors;
```

add:

```perl
    my $incomplete_ref = $opt{pr_policy} ? $opt{base_sha} : $self->_existing_merged_ref;
    if (@multi_files && defined $incomplete_ref) {
      my ($incomplete, $incomplete_warnings) = $self->_multi_incomplete_findings(\@multi_files, $incomplete_ref);
      $self->_merge_findings($findings_by_file, $incomplete);
      $warnings += $incomplete_warnings;
    }
```

- [ ] **Step 4: Run the tests**

Run: `nix develop --offline -c prove -lr t`
Expected: `All tests successful.`

- [ ] **Step 5: Document**

In AGENTS.md `### 3. Edit + Validate`, after the announce-multi bullets, add:

```markdown
  - `multi_incomplete` (warning; blocking only with `--strict`): an unmerged batch that
    names a CVE new on this branch leaves out another branch CVE of the same distribution.
    Fix with `announce-multi --sync --write`. No batch, no warning.
```

- [ ] **Step 6: Commit**

```bash
git add lib/CPANSec/CNA/App.pm t/52-cna-check-multi-incomplete.t AGENTS.md
git commit -m "Warn when a branch batch leaves out a branch CVE

Co-Authored-By: <model> <noreply@anthropic.com>"
```
