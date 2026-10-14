# Handoff: multi-CVE announcements in cna-tool

## Goal and scope

CPANSec publishes announcements to its own list at
`lists.security.metacpan.org` and to `oss-security`. Individual CVE emails
are fine on the CPANSec list, but sending 10+ separate messages to
oss-security can be noisy.

Explore support in cna-tool for one announcement containing multiple CVEs
**from the same Perl distribution**. Cross-distribution batches are out of
scope. Keep the individual-announcement workflow available.

The format is not decided. Inspect the current renderer and representative
announcements, then discuss the alternatives with the maintainer before
implementing. The examples below are starting points, not a specification.

## What should be preserved

The combined email should retain essentially the same advisory text as the
individual announcements, not become a summary with links. Each CVE must
remain clearly identifiable, with its original title, description, affected
versions, and any problem types, workarounds, solutions, references,
timeline, or credits.

Do not assume that CVEs in the same distribution share affected ranges or
fixed releases. Plain-text readability matters, especially in a long batch.

## Subject options

These are illustrative subjects for a fictional distribution:

```text
Example-Dist (Perl): multiple vulnerabilities (4 CVEs)
Example-Dist (Perl) before 2.4: path traversal and DoS (4 CVEs)
```

The first is simple to generate and stays manageable for large batches, but
communicates little beyond the package and count. The second is more useful
to readers, but needs accurate version aggregation and a short issue-type
summary. Review oss-security's subject guidance when comparing them.

Another option is listing CVE IDs for small batches and switching to a count
for larger ones. That improves immediate identifier visibility but adds a
threshold and produces inconsistent subject shapes. A count for every
multi-CVE message is the simpler alternative.

Discuss how much should be mechanical and whether an editable subject or
short issue summary is appropriate. Mixed version ranges need an explicit
fallback rather than a misleading common range.

## Body options

### A. Cover sheet plus complete announcements

Add a short distribution-level introduction and an index containing each
CVE ID and title, then concatenate the existing announcements with clear
separators.

This is the lowest-change approach and preserves each announcement intact.
The downside is repeated banners and package metadata, especially with many
CVEs.

### B. Shared header plus full per-CVE sections

Print common distribution metadata once, followed by an index and the
existing advisory content grouped by CVE:

```text
Distribution and shared metadata
Optional common remediation summary, where accurate

Contents
  CVE-YYYY-NNNNN — issue title
  CVE-YYYY-NNNNN — issue title

======================================================================
CVE-YYYY-NNNNN
Affected versions
Original title and advisory sections

======================================================================
CVE-YYYY-NNNNN
Affected versions
Original title and advisory sections
```

This reduces clutter but requires deciding what is genuinely shared. Keeping
affected versions, fixes, references, timelines, and credits local to each
CVE makes attribution clearer, even when some content repeats. Links to the
individual CPANSec announcements could supplement either layout.

## Discussion before implementation

- Which subject strategy and body layout feel right when rendered with both
  two CVEs and ten or more?
- Should the index reuse full advisory titles, or allow shorter labels?
- Which metadata should be shared, and how should mixed remediation appear?

Start with sample output for that discussion rather than a finished CLI or
schema design. Afterwards, look for opportunities to reuse the existing
single-CVE rendering without maintaining a second copy of advisory prose.

## Starting points

- [cna-tool repository](https://github.com/CPAN-Security/cna-tool)
- [Individual CPANSec announcement](https://lists.security.metacpan.org/cve-announce/msg/43998314/)
- [Earlier grouped CPANSec announcement](https://www.openwall.com/lists/oss-security/2026/06/30/3)
- [oss-security posting guidance](https://oss-security.openwall.org/wiki/mailing-lists/oss-security)

## Decisions (2026-10-14)

Agreed with the maintainer after reviewing mockups and oss-security
precedent (multi-CVE posts from curl, X.Org, rsync, OpenSSL, BIND, and
CPANSec's own Net::BitTorrent and Crypt::OpenSSL::X509 batches).

### Format

```text
Subject: Foo-Bar for Perl: 3 CVEs

Foo-Bar for Perl: 3 CVEs

CVE-2026-1001
  Foo::Bar versions before 2.4 for Perl allow path traversal via crafted
  archive entry names

CVE-2026-1002
  Foo::Bar versions 2.0 through 2.3 for Perl allow denial of service via
  deeply nested input

CVE-2026-1003
  Foo::Bar versions before 2.5 for Perl use a weak random number source
  for session tokens


========================================================================
CVE-2026-1001                                        CPAN Security Group
========================================================================
[... unchanged single announcement, minus its Subject: line ...]
```

- Subject and title are the same string: `<primary distribution> for Perl: N CVEs`.
  Fully mechanical; no hand-written issue summary, no aggregated version range.
- The header is just the title line and an index: CVE ID on its own line,
  full CVE title indented below, wrapped at 72 columns. No underline, no
  intro sentence, no box. The first `====` banner marks the end of the header.
- Titles already carry module and version range, so the index needs no
  version column, grouping, or shortened labels.
- The body is each CVE's existing `announce` output byte-for-byte, with only
  its `Subject:` line dropped. No second copy of advisory rendering.

### Rules

- CVEs are always sorted numerically by CVE ID (year, then number),
  regardless of argument order.
- A batch needs at least 2 CVEs; a single CVE is refused with a pointer to
  `announce`.
- All CVEs must share the same primary distribution: the first entry of
  `CPANSec::CVE::Model::distributions`. Dual-life records are supported;
  their further distributions appear in their own announcement blocks.
- Any CVE resolving to `encrypted/` refuses the whole batch, as `announce` does.

### CLI and files

```text
cpansec-cna announce-multi <CVE> <CVE>...             # stdout
cpansec-cna announce-multi <CVE> <CVE>... --write     # announce-multi/<dist>--<CVE IDs>.txt
cpansec-cna announce-multi <CVE> <CVE>... --output PATH
```

- The filename lists every CVE ID, so tooling can tell which CVEs a batch
  covers from the name alone:

  ```text
  announce-multi/Foo-Bar--CVE-2026-1001+1002+1003.txt
  announce-multi/Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt
  ```

  IDs are sorted numerically and joined with `+`. The year prefix is written
  in full for the first ID of each year; later IDs from the same year are
  just the number. This is reversible: a bare number takes the year of the
  nearest full ID before it.
- No dates: batches are reworked over time and a date would drift.
- `announce-multi/` is separate from `announce/`, so the per-CVE PR policy
  rules are unaffected.
- Re-cutting a batch changes its filename. `--write` should warn about other
  `announce-multi/` files whose names cover any of the same CVEs, and leave
  removal to the user; it never deletes.

### Optional, additive

- A multi-announcement is optional: the operator decides whether to make one.
  Nothing ever requires a batch file, so there is no "missing batch" finding.
- It is always in addition to the normal per-CVE announcements. Every CVE in
  a batch still has its own `announce/<CVE>.txt`, with the existing PR-policy
  rules unchanged.

### `cna check` coverage

Batch files are fully covered by `check`. These findings are blocking errors
in plain `check`, not only under `--pr-policy`, because the file is fully
generated and any mismatch means it is stale:

- `multi_filename`: name parses, lists at least 2 CVEs, and is in canonical
  form (numerically sorted, year-compressed).
- `multi_cve_missing`: every listed CVE resolves under `cves/`; a CVE that
  resolves to `encrypted/` is an error.
- `multi_distribution`: all CVEs share the same primary distribution, and it
  matches the `<dist>` part of the filename.
- `multi_cve_invalid`: a listed CVE's YAML fails to load or render.
- `multi_mismatch`: content equals regenerated `announce-multi` output.

A merged batch (on the PR base under `--pr-policy`; otherwise on `origin/main`
if that ref exists, else `main`) is a record of what was sent, like
`announce/<CVE>.txt`. It only gets the `multi_filename` checks: its CVEs' YAMLs
can still be updated, re-ordered or rejected afterwards without making it fail.

Targeting:

- `check CVE-X` also checks every batch whose filename contains CVE-X, since
  a YAML edit can make a batch stale.
- `check --changed` also covers changed `announce-multi/*.txt` files and
  batches containing any changed CVE.
- The example CI workflow must watch `announce-multi/*.txt` and map batch
  filenames back to their CVE IDs.

PR policy (`--pr-policy --base-sha`):

- Adding a batch file is always allowed, including when all its CVEs already
  exist on the base; batches are often assembled after the single
  announcements are merged.
- A batch file present on the base must not change or be removed, mirroring
  `announce/<CVE>.txt` (`multi_not_allowed`). Re-cutting a batch is therefore only possible before
  it merges; afterwards a different set gets a new file alongside the old one.

### Renderer seam

`CPANSec::CVE::Announce` splits into `subject_line` and `render_cve5_body`
(banner down). `render_cve5_hash` is their concatenation, so single output
is unchanged, and a batch concatenates the bodies.

## Decisions: branch sync and status (2026-10-14)

Use case: a branch drafts several CVEs and the batch should track them
without retyping IDs.

- **New on this branch** means `cves/<CVE>.yaml` exists in the working tree
  (committed or not) but not on the merged ref (`origin/main`, else `main`;
  the PR base under `--pr-policy`). `encrypted/` drafts are never batched;
  they are only counted. Without a merged ref, sync refuses.
- `announce-multi --sync [CVE...]`: the batch is exactly the branch's new
  public CVEs, plus any explicitly named (already merged) ones, grouped by
  primary distribution; each distribution with 2+ CVEs gets one batch, a
  distribution with one is reported and skipped. Without `--write` it only
  prints what it would do.
- `announce-multi --sync --write`: writes the batches and **auto-removes**
  the branch's own superseded batches — unmerged batch files that name a
  branch CVE but are no longer a sync target (a CVE was added or dropped).
  It prints every removal. Merged batches and unmerged batches that name no
  branch CVE (batches of already-published CVEs) are never touched. A target
  that is already merged is reported, not rewritten. `--output` and `--force`
  do not combine with `--sync`. Unloadable branch CVEs block `--write`.
- Bare `announce-multi` prints status and changes nothing: the branch and
  merged ref, new CVEs grouped by distribution (single ones and skipped
  encrypted drafts noted), batch files touching the branch with their state
  (merged/frozen, in sync, stale, out of sync, not tied to the branch), and a
  suggested next command (`--sync --write`, `check --changed`, or the
  explicit-ID form when there is nothing to batch).
- `check` warns (`multi_incomplete`, severity warning, non-blocking unless
  `--strict`) when an unmerged batch naming a branch CVE leaves out another
  CVE new on the branch for the same distribution. Batches stay optional:
  no batch, no warning.
- Amendment: creating a batch is explicit. `--create` starts batches for distributions
  without one; `--sync` only updates existing branch batches and reports the rest as "Not
  batched". Both write without `--write` (the action is the request); `--dry-run` previews.
  Status suggests `--create` or `--sync` accordingly.
