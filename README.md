# CPANSec CNA Tooling (`cna`)

`cna` is a workflow CLI for maintaining CPANSec CNA CVE records.

It helps you:
- initialize CVE YAML records
- validate/lint authoring quality
- generate CVE 5.x JSON
- render announcement text
- import JSON back to YAML with round-trip guard
- reconcile local CNA data with cve.org records

This repository also contains CVE data (`cves/`, `reserved/`, `announce/`, `encrypted/`).

## Requirements

- Perl `v5.42`
- Project dependencies installed in your environment
- Git repository checkout (branch-aware behavior is built in)

## Command

Canonical entrypoint:

```bash
scripts/cna <command> [options]
```

Global option:

```bash
--cpansec-cna-root PATH
```

If set, `cna` runs as if started from that data repo root.

You can also use:

```bash
CPANSEC_CNA_ROOT=/path/to/data-repo
```

## Typical Workflow

### 1. Reserve CVE(s)

Create `reserved/CVE-YYYY-NNNN` on `main`.

### 2. Initialize YAML

```bash
scripts/cna init CVE-2026-12345 Some::Module
```

Sensitive CVEs:

```bash
scripts/cna init --encrypted CVE-2026-12345 Some::Module
```

`init` behavior:
- checks `reserved/<CVE>` unless `--force`
- suggests branch `CVE-YYYY-NNNN--module-slug`
- branch switch prompt is only offered on clean `main`
- on dirty `main`, it asks whether to continue without switching
- can prefill metadata from MetaCPAN (interactive)
- always writes `repo:` in stub (MetaCPAN value or placeholder)

### 3. Edit + Validate

```bash
scripts/cna check CVE-2026-12345
```

Changed files only:

```bash
scripts/cna check --changed --format github
```

Strict mode (lint warnings become blocking):

```bash
scripts/cna check CVE-2026-12345 --strict
```

### 4. Generate JSON

Write JSON next to YAML:

```bash
scripts/cna build CVE-2026-12345
```

Emit to stdout only:

```bash
scripts/cna emit CVE-2026-12345
scripts/cna emit CVE-2026-12345 --cna-only
```

### 5. Announcement Text

Stdout:

```bash
scripts/cna announce CVE-2026-12345
```

Write to default file:

```bash
scripts/cna announce CVE-2026-12345 --write
```

Write to chosen path:

```bash
scripts/cna announce CVE-2026-12345 --output /tmp/CVE-2026-12345.txt
```

### 6. JSON -> YAML Import

```bash
scripts/cna import CVE-2026-12345
# or
scripts/cna import /path/to/CVE-2026-12345.json
```

Disable round-trip guard (not recommended):

```bash
scripts/cna import /path/to/CVE-2026-12345.json --no-guard
```

### 7. Reconcile With cve.org

```bash
scripts/cna reconcile CVE-2026-12345
```

Notes:
- `reconcile` only uses local sources under `cves/`.
- It does not read or operate on `encrypted/`.

With custom API base:

```bash
scripts/cna reconcile CVE-2026-12345 --api-base https://cveawg.mitre.org/api/cve
```

Verbose:

```bash
scripts/cna reconcile --verbose
```

## YAML Authoring Notes

`init` generates a stub with required fields and commented optionals.

Optional sections are shown as comments (not pre-populated), including:
- `cwes`
- `impacts` (CAPEC)
- `solution`
- `mitigation`
- `files`
- `routines`
- `timeline`
- `credits`

### `{{VERSION_RANGE}}` Template Token

`title` and `description` can include `{{VERSION_RANGE}}`.

Example:

```yaml
title: Some::Module {{VERSION_RANGE}} for Perl has an issue
description: |
  Some::Module {{VERSION_RANGE}} for Perl has an issue.
  More details.
```

`{{VERSION_RANGE}}` is derived from `affected`:
- `"<= 1.0"` -> `versions through 1.0`
- `"1.2 <= 1.3"` -> `versions from 1.2 through 1.3`
- `"1.5 < *"` or `"1.5 <= *"` -> `versions from 1.5`
- `"1.5"` -> `versions 1.5`

Multiple ranges are joined with commas, e.g.:

```yaml
affected:
  - "<= 1.0"
  - "1.2 <= 1.3"
  - "1.5 < *"
```

becomes:

`versions through 1.0, from 1.2 through 1.3, from 1.5`

If template syntax is malformed or an unsupported token is used, conversion warns.
Unsupported tokens are left unchanged in output text.

## Timeline Input

`timeline[].time` accepts:
- `YYYY-MM-DD`
- full timestamp (`YYYY-MM-DDTHH:MM:SSZ` or offset form)

Date-only values are normalized in CVE output to midnight UTC (`T00:00:00Z`).

## Lint and Validation Behavior

- Schema/validation errors are blocking.
- Lint findings are advisory by default.
- `--strict` makes lint findings blocking.

There is an additional wording lint to keep title/description lead text aligned with announce-style version phrasing.

## Encrypted CVE Workflow

For embargoed records:
- initialize with `--encrypted`
- data lives under `encrypted/`
- network access is blocked in encrypted context
- encrypted operations are refused on `main`
- writes to `encrypted/` are guarded by git-crypt checks
- `announce` refuses encrypted sources
- `reconcile` ignores `encrypted/` and only works from `cves/`

## Default CVE Resolution

For commands that accept optional CVE (`check/build/emit/announce/reconcile` single target), resolution order is:
1. explicit CLI CVE
2. `CPANSEC_CNA_CVE`
3. branch name prefix (`CVE-...`)

## Quick Command Reference

```bash
scripts/cna init [--force] [--encrypted] <CVE> <Module>
scripts/cna check [CVE] [--changed] [--format text|github] [--strict]
scripts/cna build [CVE] [--strict] [--force]
scripts/cna emit [CVE] [--strict] [--cna-only]
scripts/cna announce [CVE] [--write|--output PATH] [--force]
scripts/cna import <CVE|PATH.json> [--force] [--no-guard]
scripts/cna reconcile [CVE] [--api-base URL] [--verbose]
```
