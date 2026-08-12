# Executive Summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |

**Overall risk:** MEDIUM  
**Recommendation:** CONDITIONAL — fix the import guard's handling of multi-valued `modules[]` before merging.

**Key metrics:**

- Files analyzed: 17/17 changed files
- Tests: 307 passed across 40 files
- Test coverage gaps: 1 guard case
- Security regressions detected: 0

## What Changed

**Commit range:** `main...2ec947a`  
**Commits:** 20  
**Timeline:** 2026-08-09 to 2026-08-12

The branch upgrades emitted records to CVE 5.2.0, changes CPAN package identification to `collectionURL`/`packageName`/`packageURL` plus `modules[]`, adds a normalized multi-distribution model, updates import and announcement behavior, and adds corresponding tests and documentation. It changes 17 files with 1,226 insertions and 110 deletions.

| Area | Risk | Blast radius |
|---|---|---|
| YAML/JSON conversion and round-trip guard | High | Medium |
| Schema and normalized distribution model | High | Medium |
| Announcement rendering | Medium | Low |
| CLI initialization messaging | Low | Low |
| Tests, Nix environment, documentation | Low | Low |

## Findings

### MEDIUM: Import guard silently drops additional values in an affected entry's `modules[]`

**File:** `lib/CPANSec/CVE/CVE2YAML.pm:222` and `lib/CPANSec/CVE/CVE2YAML.pm:270`  
**Introduced by:** `6afff11` (`Guard the module per affected entry`)  
**Blast radius:** all JSON imports using the default round-trip guard; direct callers are the import command and import tests  
**Test coverage:** partial

The CPAN macro can represent one shared module, while CVE 5.2 permits an affected entry's `modules` array to contain more than one module. `_module_of` returns only `modules->[0]`, and both conversion and `_project_roundtrip_view` use that scalar. Consequently, an input such as `modules: ["Encode", "Encode::Alias"]` is imported as `module: Encode`; rebuilding emits only `["Encode"]`; and the guard nevertheless accepts the result because both projections compare only the first element.

This contradicts the guard's purpose and the nearby fix for divergent modules between affected entries. The same non-representability exists within one entry but is not checked.

**Reproduction:** A focused offline reproduction added `Encode::Alias` to the first affected entry in the dual-life fixture and called `convert_json_file_to_yaml(..., guard => 1)`. The call returned successfully and its YAML contained only `module: Encode`.

**Impact:** A valid imported CVE record can lose an affected module identifier without warning. If the generated YAML is subsequently treated as source of truth, later emitted and published data under-reports the affected module set.

**Recommendation:** Project the full normalized module array for every affected entry and make the guard compare it. Conversion should explicitly reject any entry with more than one effective module unless the macro is extended to represent all of them. Add a regression test beside `divergent per-entry modules cannot be silently lost` using two modules in a single affected entry.

## Test Coverage Analysis

The required offline suite passed:

```text
Files=40, Tests=307
All tests successful.
Result: PASS
```

Existing tests cover multiple distributions and disagreement between the first module of different affected entries. They do not cover multiple module values within one affected entry, which is the finding above.

## Blast Radius Analysis

`CPANSec::CVE::CVE2YAML` is the implementation behind JSON-to-YAML import. The changed normalized-distribution path is also consumed by YAML emission and linting. The identified defect is confined to import/guard behavior, but every default guarded import passes through it.

## Historical Context

The original guard projected only one affected entry. Commit `9deb5ec` expanded it to every distribution, and commit `6afff11` added a per-entry scalar module comparison specifically to prevent silent module loss. No security-related validation was removed. The remaining bug is an incomplete generalization from scalar `product` to array-valued `modules`.

## Recommendations

### Immediate

- Make multi-valued `modules[]` non-lossy or explicitly non-representable in the guard.
- Add the focused regression test described above.

### Follow-up

- Remove the newly packaged `URI::PackageURL` dependency if no validation/parsing use is planned; the branch currently constructs purls directly and never loads the module.

## Analysis Methodology

**Strategy:** focused differential review (54 Perl/test files in the repository; 17 changed files).

Reviewed all changed production code, schema changes, tests, commit history, and relevant one-hop call sites. Compared baseline and branch implementations, inspected the history of the guard logic, ran `git diff --check`, ran the complete mandated offline test suite, and executed a focused adversarial round-trip reproduction.

**Limitations:** External CVE and purl specifications were not re-fetched; schema conformance was exercised through the repository's pinned schema and tests.  
**Confidence:** high for the identified import data-loss bug; medium-high overall.
