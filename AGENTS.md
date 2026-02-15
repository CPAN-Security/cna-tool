# CPANSec CNA Agent Guide

## Role

You are maintaining tooling for the CPANSec CNA CVE workflow.
You are expected to operate as a Perl expert and prefer Perl-native, maintainable solutions over cross-language complexity.

Primary goals:
- Keep CVE data valid, reproducible, and reviewable.
- Make editor/terminal/GitHub PR workflows fast and predictable.
- Preserve compatibility with existing data and publication process.
- Prefer explicit, auditable behavior over hidden automation.
- Tools should ask for user consent before internet access or any side-effecting action that is not explicit in the command being run (for example: creating/switching branches, committing, or overwriting files).

## Language and Runtime Standards

- Target runtime is Perl `v5.42`.
- Prefer modern Perl patterns and syntax compatible with `v5.42`.
- Use modern OO (`feature 'class'`) consistently in project modules.
- Avoid introducing legacy Perl idioms when a clear modern equivalent exists.
- Keep dependencies pragmatic; prefer core modules or already-adopted CPAN modules unless new deps are justified.

## Code Style Expectations

- Prefer concise, elegant, readable code.
- Avoid unnecessary abstraction, boilerplate, and verbose defensive fluff.
- Keep functions small and behavior explicit.
- Choose clear names over cleverness.
- Add comments only for non-obvious intent or invariants.

## What This Repository Is

This repository currently contains:
- The CVE data store (`cves/`, `announce/`, `reserved/`, `encrypted/`).
- The workflow CLI (`scripts/cpansec-cna`).
- Conversion/render modules under `lib/`.
- Schemas (`schema/`, plus upstream `cve-schema/` submodule).
- Tests (`t/`) and local fixtures (`t/var/`).

The tooling is being prepared to move to a separate project. This guide is the handoff document for that split.

## TLP and Disclosure Levels

- `TLP:RED`
  - Sensitive vulnerabilities under embargo.
  - Do not include details in PR titles/descriptions/issues.
  - Use `git-crypt` and `encrypted/`.
- `TLP:AMBER+STRICT`
  - Details in issues/PRs are acceptable when disclosure policy allows.

## End-to-End Operational Process

### 1. Triage and verify
- Confirm the report is a vulnerability under CNA rules.
- Confirm it is not already assigned/published as a CVE.
- Confirm reporter/vendor coordination happened (or was attempted).
- Determine correct CVE count (split vs merge).
- Collect public references.

### 2. Reserve CVE IDs
- Use CVE Services tooling to reserve IDs (typically in discovery/report year).
- On `main`, add `reserved/CVE-YYYY-NNNN` file(s) and push.
- Communicate reserved ID(s) back to reporter/vendor.

### 3. Prepare PR branch work
- Create PR branch from `main`.
- Remove corresponding `reserved/` files in the PR that issues the CVE(s).
- Initialize records:
  - Public: `cpansec-cna init CVE-YYYY-NNNN Module::Name`
  - Sensitive: `cpansec-cna init --encrypted CVE-YYYY-NNNN Module::Name`
- Iterate with:
  - `cpansec-cna check`
  - `cpansec-cna build`
  - `cpansec-cna emit`
  - `cpansec-cna import`
  - `cpansec-cna reconcile`
  - `cpansec-cna announce` (public only)

### 4. Publish
- Re-review generated JSON and announcement.
- Merge PR after review/approval.
- Publish JSON to CVE Services.
- Send announce email using generated `announce/<CVE>.txt` content.
- Complete mailing-list moderation/approval steps.

## Core Workflows

### 1. Reserve CVE
- Add file `reserved/CVE-YYYY-NNNN` on `main`.
- That file is the gate for normal `init`.

### 2. Initialize CVE YAML
- Run: `cpansec-cna init CVE-YYYY-NNNN Module::Name`
- Sensitive run: `cpansec-cna init --encrypted CVE-YYYY-NNNN Module::Name`
- Checks:
  - Reserved file exists (unless `--force`).
  - Branch naming recommendation: `CVE-YYYY-NNNN--module-slug`.
  - Interactive branch switch/create prompt.
  - Interactive MetaCPAN metadata fetch prompt.
- Output:
  - Creates `cves/CVE-YYYY-NNNN.yaml` stub with schema header.

### 3. Edit + Validate
- Run: `cpansec-cna check CVE-YYYY-NNNN`
- Or: `cpansec-cna check --changed --format github`
- Behavior:
  - YAML/schema validation + lint rules.
  - Lint is advisory by default.
  - Schema failures are blocking.
  - `--strict` makes lint blocking.

### 4. Build or Emit JSON
- Build/writes file:
  - `cpansec-cna build CVE-YYYY-NNNN`
  - Writes `cves/CVE-YYYY-NNNN.json`.
- Emit/stdout only:
  - `cpansec-cna emit CVE-YYYY-NNNN`
  - `cpansec-cna emit CVE-YYYY-NNNN --cna-container-only`
  - Never writes to `cves/`.

### 5. Announcement Generation
- `cpansec-cna announce CVE-YYYY-NNNN` (stdout)
- `cpansec-cna announce CVE-YYYY-NNNN --write` (to `announce/`)
- `cpansec-cna announce CVE-YYYY-NNNN --output <path>`
- Source of truth for announce rendering is YAML (`cves/*.yaml`).

### 6. JSON -> YAML Import
- `cpansec-cna import CVE-YYYY-NNNN`
- Default includes round-trip guard:
  - JSON -> YAML -> JSON projection must match.
- `--no-guard` disables that check.

### 7. Reconcile Local vs cve.org
- `cpansec-cna reconcile [CVE-ID]`
- Compares local `containers.cna` vs API record.
- Reconcile only considers local records under `cves/` (yaml/json).
- Reconcile does not read from `encrypted/`.
- Ignores provider metadata drift during compare.
- Reports:
  - `OK`
  - `DIFF` (+ unified diff)
  - `MISSING` (remote not found)
  - `ERROR`

## Important CLI Defaults and Context Rules

For commands that accept optional CVE (`check`, `build`, `emit`, `announce`, `reconcile` single target):
- Explicit CVE argument wins.
- Else `CPANSEC_CNA_CVE` if set/valid.
- Else branch prefix `CVE-YYYY-NNNN` if branch matches.

## Running Tooling Outside Data Repo

`cpansec-cna` supports a separate code/data location:

- CLI option:
  - `--cpansec-cna-root /path/to/cna-data-repo`
- Env var:
  - `CPANSEC_CNA_ROOT=/path/to/cna-data-repo`

Resolution:
- CLI option overrides env.
- If set, tool `chdir`s to that root before command execution.
- All existing relative paths (`cves/`, `announce/`, `reserved/`, `schema/`) continue to work unchanged.

## `encrypted/` Handling

Rules:
- `init --encrypted` writes new CVEs to `encrypted/`.
- Most commands auto-detect a CVE in `cves/` vs `encrypted/`.
- `reconcile` is the exception: it only uses `cves/` and never reads `encrypted/`.
- If a CVE resolves to `encrypted/`, print a loud warning in CLI output.
- In encrypted context, network access is always blocked.
- Running encrypted operations from branch `main` is refused; encrypted work must be on a PR branch.
- `announce` is public-only and must not use `encrypted/` sources.
- Any write into `encrypted/` must verify git-crypt safety:
  - target path matches `git-crypt` attributes
  - repository appears unlocked (`git-crypt status -e encrypted` should not report ciphertext files)
- Test shim exists: `CPANSEC_CNA_GIT_CRYPT_SHIM=ok|locked|unprotected|missing`.

## Module Architecture

Main entry:
- `scripts/cpansec-cna` -> `CPANSec::CNA::App`

Key modules:
- `CPANSec::CNA::App`
  - Command routing and workflow orchestration.
  - User prompts.
  - Lint + schema gate behavior.
  - Reconcile network/file fetch and diffing.
- `CPANSec::CNA::Lint`
  - Rule registry/execution.
- `CPANSec::CNA::Lint::Rule::*`
  - Individual lint rules; additive and easy to extend.
- `CPANSec::CNA::Lint::Reporter::Text`
- `CPANSec::CNA::Lint::Reporter::GitHub`
  - Human and CI annotation output formats.
- `CPANSec::CVE`
  - Facade over YAML model and output methods.
- `CPANSec::CVE::Model`
  - Structured CVE macro model.
- `CPANSec::CVE::YAML2CVE`
  - YAML macro -> CVE JSON rendering and schema validation.
- `CPANSec::CVE::CVE2YAML`
  - CVE JSON -> YAML macro conversion with guard support.
- `CPANSec::CVE::Announce`
  - Announcement rendering.

## Schema and Validation

YAML validation:
- Local schema: `schema/cpansec-cna-schema-01.yaml`
- YAML files include language-server hint comment for editor tooling.
- Only `.yaml` source files are supported (`.yml` is intentionally ignored).

JSON validation:
- Prefer upstream schema refs from `cve-schema/schema/`.
- Fallback file: `cve-record-format-5.2.0.json`.

Guideline:
- Keep schema-related behavior deterministic and explicit in errors.

## Linting Philosophy

Lint rules enforce writing quality and consistency while allowing iterative edits.

Current behavior:
- Default: lint non-blocking, schema blocking.
- `--strict`: lint + schema blocking.

Rule design constraints:
- Rule IDs stable and machine-friendly.
- Findings include severity, id, message, path, and optional line.
- Additive architecture: new rules should be isolated modules with tests.

## CI / PR Integration

GitHub Action:
- `.github/workflows/cna-lint.yml`
- Runs `cpansec-cna check --changed --format github`
- Produces inline annotations.

Design intent:
- Fast signal on modified CVE YAMLs.
- Keep CI behavior aligned with local command behavior.

## Testing Rules (Critical)

No test may call the internet.

Enforcement:
- App blocks network when test harness is active (`HARNESS_ACTIVE`) or `CPANSEC_CNA_NO_NETWORK` is set.
- Reconcile tests use `file://` fixtures.

Fixtures:
- Test input fixtures must live under `t/var/`.
- Do not read source fixtures directly from `cves/` or `announce/`.
- If CLI requires canonical locations (like `cves/<CVE>.yaml`), copy fixture from `t/var` into temporary/staged file and clean up.

Current suite:
- `prove -lr t` should pass without network.

## Data/Output Compatibility Notes

- `announce` command is YAML-only source. JSON fallback was intentionally removed.
- Reconcile normalizes/ignores remote provider metadata noise (org/dateUpdated/shortName drift).
- UTF-8 handling in reconcile diff path was hardened; keep all JSON encode/decode paths UTF-8 safe.

## Branch and Naming Conventions

Recommended work branch:
- `CVE-YYYY-NNNN--module-slug`

Slug generation:
- Prefer `Mojo::Util::slugify`.
- Fallback slug sanitizer exists in app.

## Security and Sensitive CVEs

Sensitive workflow:
- Use `encrypted/` with `git-crypt`.
- GitHub PR review may be unsuitable for deeply sensitive details; use secure channels where needed.
- Never include sensitive details in PR titles/descriptions for embargoed issues.
- Never leak embargoed details in PR titles, descriptions, or commit messages.
- Do not include sensitive details in commit messages (they remain plain text metadata).
- Do not generate or commit announcement content for sensitive CVEs before publication.
- Move to `cves/` only when ready for publication.

Publication transition for sensitive CVEs:
- Move final record from `encrypted/` to `cves/` in an unlocked `git-crypt` checkout at publish time.

## Script Inventory

- `scripts/cpansec-cna`: primary workflow CLI (`init`, `check`, `build`, `emit`, `announce`, `import`, `reconcile`)
- `scripts/yaml2cve`: low-level YAML->CVE conversion and schema validation helper
- `scripts/cve2announce`: announcement rendering helper
- `scripts/canonicalize-json`: canonical JSON formatting for deterministic diffs

## Migration Plan: Split Tooling from Data Repo

When moving CLI/modules to a new project:
- Keep this data repo as the `CPANSEC_CNA_ROOT`.
- Ensure tool project can run:
  - `cpansec-cna --cpansec-cna-root /path/to/data ...`
  - or set `CPANSEC_CNA_ROOT`.
- Port/retain:
  - `lib/CPANSec/CNA/*`
  - `lib/CPANSec/CVE/*`
  - `scripts/cpansec-cna`
  - CI workflow and tests.

Recommended follow-ups after split:
- Add integration test that runs tool from an external directory against fixture root.
- Optionally package as installable distribution with stable versioning.
- Keep rule IDs and command semantics backward-compatible.

## Operational Checklist for Agents

Before making behavior changes:
- Confirm command semantics in `CPANSec::CNA::App`.
- Run full tests: `prove -lr t`.
- Ensure no new network path is reachable from tests.
- Verify fixture discipline (`t/var` only as source fixtures).

When adding commands/options:
- Update usage text.
- Add tests for success path and error path.
- Update `AGENTS.md` workflow docs (README may not exist in split repo).
- Preserve non-interactive automation compatibility.

When changing schema/lint:
- Add targeted tests with deterministic fixtures.
- Keep lint output stable for CI annotation consumers.

## Quick Command Reference

- `cpansec-cna init [--force] [--encrypted] <CVE> <Module>`
- `cpansec-cna check [CVE] [--changed] [--format text|github] [--strict]`
- `cpansec-cna build [CVE] [--strict] [--force]`
- `cpansec-cna emit [CVE] [--strict] [--cna-container-only]`
- `cpansec-cna announce [CVE] [--write|--output PATH] [--force]`
- `cpansec-cna import <CVE|PATH.json> [--force] [--no-guard]`
- `cpansec-cna reconcile [CVE] [--api-base URL] [--verbose]`
- Global:
  - `--cpansec-cna-root PATH`
  - `CPANSEC_CNA_ROOT`
  - `CPANSEC_CNA_CVE`
- `CPANSEC_CNA_NO_NETWORK`
- `CPANSEC_CNA_GIT_CRYPT_SHIM`
