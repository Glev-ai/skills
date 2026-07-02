---
name: glev-continuous-autofix
description: >-
  Auto-remediate the security findings raised by a Glev Continuous CI run on a
  pull request. Given a PR reference, it downloads the run's Glev artifact via
  the GitHub CLI, parses the per-finding verdicts + remediation, applies surgical
  fixes to the checked-out branch, and STOPS at a diff for review (never commits).
  Use when the user asks to fix / remediate / address the Glev (Continuous)
  alerts, the security scan, or the failing security check on a PR.
allowed-tools: Bash(bash */scripts/check-requirements.sh*), Bash(bash */scripts/fetch-artifacts.sh*), Bash(bash */scripts/parse-findings.sh*), Bash(gh *), Bash(jq *), Bash(git diff*), Bash(git status*), Bash(git log*), Bash(npm *), Bash(npx *), Bash(ruff *), Read, Edit, Write, Grep, Glob
argument-hint: <pr-number | owner/repo#N | PR URL>
---

# glev-continuous-autofix — remediate Glev Continuous findings on a PR

Glev Continuous runs a diff-aware security scan in CI on every PR and uploads a
single artifact (`glev-continuous-<head_sha>`) containing the verdict, the
annotated findings, and — for findings judged **EXPLOITABLE** — a per-finding
remediation. This skill turns that artifact into reviewed code changes.

**The contract you must honour:**

1. **Diff only, by default.** Apply edits to the working tree, then STOP and show
   the diff. Do **not** `git commit`, `git push`, or open a PR unless the user
   explicitly asks. (Commit/push is an opt-in last step, never the default.)
2. **Every edit traces to a finding.** Only touch code a Continuous finding
   points at. No drive-by refactors, no "while I'm here" cleanups.
3. **The suggested fix is a guide, not a paste.** The artifact's remediation code
   was written against a snapshot; adapt it to the real current code, keep the
   surrounding style, and make sure it still compiles/lints.
4. **You are not the final authority.** Every finding carries "*This fix must be
   validated by one of your engineers before being used in your code.*" Surface
   that. The human merges.

The bundled scripts live in this skill's `scripts/` directory. In the commands
below, **`<skill-dir>` is the absolute directory this `SKILL.md` was loaded from**
(the harness exposes it when the skill is invoked) — substitute it everywhere.
e.g. `bash <skill-dir>/scripts/fetch-artifacts.sh`.
Reference material is in `reference/` — read `output-schema.md` when you need the
exact artifact schema.

---

## Procedure

### 0. Preflight — verify the host can do the job

```bash
bash <skill-dir>/scripts/check-requirements.sh [owner/repo]
```

Confirms `gh` (installed + authenticated), `jq`, `unzip`, and that you're inside
a git repo. If it exits non-zero, fix what it reports **before** continuing —
don't push past a failed preflight.

### 1. Fetch the artifact for the PR

```bash
bash <skill-dir>/scripts/fetch-artifacts.sh "<pr-ref>" [-R owner/repo]
```

`<pr-ref>` is a PR number, `owner/repo#N`, or a PR URL. The script resolves the
PR's head SHA, finds the matching `glev-continuous-*` artifact + its run, and
downloads it. It prints a one-line JSON **manifest** on stdout — capture it:

```json
{ "repo":"…", "pr":1, "state":"OPEN", "branch":"…", "head_sha":"…",
  "run_id":123, "artifact_name":"glev-continuous-…", "expired":false,
  "out_dir":"…", "has_debug":true, "has_report_md":true,
  "counts":{…}, "exit_code":1 }
```

Read these guards from the manifest:

- **`exit_code == 0`**: the check is green — nothing to remediate. Report and stop.
  Gate on `exit_code`, **not** `counts.exploitable == 0` — a run can have zero
  exploitable but nonzero `undefined` findings, which are still actionable (they
  appear in `annotations[]`).
- **`state` not `OPEN`** (MERGED/CLOSED): the head branch may be deleted, so
  `gh pr checkout` can fail — you may need `git fetch origin <head_sha>` first.
- **`has_debug` — `false` is the normal case, not a degraded one.** A standard
  run uploads `response.json` + `report.md`, and their annotations already carry
  the verdict, the CWE, and a full suggested-fix **code block** per finding —
  everything you need to remediate. `has_debug: true` is opt-in (`GLEV_DEBUG` in
  the workflow) and *only adds* planning metadata (`fix_scope`,
  `data_flow_diagram`, structured `vuln_type`/`severity`) that helps you group
  edits. **Never block on debug being off** — design every step around the
  non-debug artifact; treat enrichment as a bonus when it happens to be there.
- **branch/SHA mismatch**: the fix lands on whatever is checked out. Verify the
  PR's branch is checked out at (or near) `head_sha`:
  `git rev-parse HEAD` should match the manifest's `head_sha`. If it doesn't,
  ask the user to `gh pr checkout <pr>` in the target repo first — applying fixes
  against unrelated code is worse than doing nothing.

### 2. Parse the findings

```bash
bash <skill-dir>/scripts/parse-findings.sh "<out_dir>" --summary   # human view
bash <skill-dir>/scripts/parse-findings.sh "<out_dir>"             # full JSON
```

The JSON has `findings[]` (exactly the actionable, annotated set) and
`assessments[]` (all findings incl. NOT_EXPLOITABLE, debug only). Each finding
carries: `path`, `start_line`, `verdict`, `cwes`, `suggested_fix` (the full
remediation prose + code, always present), and — when debug is on — an
`enrichment` block (`exploitability`, `reason`, `data_flow_diagram`,
`clues.fix_scope`/`fix_approach`/`affected_component`, `remediation.severity`/
`vuln_type`/`impacted_files`).

**Ambiguity (debug runs only):** the `enrichment`/`enrichment_candidates` fields
exist only when debug is on. If debug enrichment is present *and* two findings
share a line, the finding has `enrichment: null` + `enrichment_candidates[]` —
pick the candidate whose `remediation.vuln_type` matches that finding's `cwes`,
never apply both. **Without debug there is no join and no ambiguity:** each
annotation is already a standalone finding with its own CWE and its own
`suggested_fix`. The non-debug path is the simpler one.

### 3. Plan before editing

Group findings by `enrichment.clues.fix_scope` and `affected_component` so one
edit can resolve several alerts (e.g. all sinks in one controller). Present a
short plan to the user — a table of `file:line · CWE · verdict · fix approach` —
and the count you intend to fix vs skip. NOT_EXPLOITABLE findings (dead code,
trusted dependencies) are **not** in `findings[]`; mention them as "reviewed, no
action" but don't touch them unless asked.

### 4. Apply the fixes — surgically

For each finding, in `fix_scope` groups:

1. `Read` the target file around `start_line` to see the **actual** current code.
2. Use the finding's `suggested_fix` (the artifact's per-finding remediation,
   with code) as the starting point — it was written against this repo.
3. `Edit` the real code to implement it — minimal change, matching surrounding
   style. Adapt names/imports to what's actually there. If the suggested fix
   removes an endpoint/dead code, do exactly that; if it hardens input handling,
   add the guard without rewriting the function.
4. For multi-file fixes, use `enrichment.files` / `remediation.impacted_files`
   (already stripped to repo-relative paths) to find the other sites.
5. **Hardcoded/leaked secret (CWE-798)?** The code change does not rotate the
   exposed credential — code can't un-leak it. Flag the value as compromised and
   tell the user it must be rotated.

### 5. Verify locally

Run whatever the repo provides, scoped to what you changed:

- Node/TS: `npm run build` or `npx tsc --noEmit`, plus `npm run lint` if present.
- Python: `ruff check <changed files>` and any project test command.

If a fix doesn't compile, iterate until it does — a fix that breaks the build is
not a fix.

### 6. Stop at the diff (default) — then summarise

```bash
git diff --stat
git diff
```

Show the diff and a summary:

- **Fixed:** N findings — list `file:line · CWE`.
- **Skipped:** ambiguous-unresolved, or findings whose code you couldn't safely
  change — say why.
- **Reviewed, no action:** the NOT_EXPLOITABLE set.
- The validation disclaimer, verbatim.

Then offer the opt-in next steps **explicitly** (do not do them unprompted):
"Want me to commit these on `<branch>`, push to update the PR, or open a separate
fix PR?" Re-running the Continuous pipeline on the new commit is how the user
confirms the alerts clear.

---

## Failure modes & what to do

| Symptom | Cause | Action |
|---|---|---|
| `no Glev Continuous artifact found` | workflow hasn't run on this commit, or artifact expired (90 d) | ask the user to re-run the pipeline on the PR |
| `artifact has expired` | older than retention | re-run the pipeline to regenerate |
| manifest `exit_code: 0` | check is green | nothing to fix — stop |
| `has_debug: false` | normal run (debug is opt-in) | proceed — annotations carry verdict + CWE + fix code; debug only adds planning metadata |
| `HEAD != head_sha` | wrong branch checked out | `gh pr checkout <pr>` first |
| finding has `enrichment_candidates` | multiple findings on one line | disambiguate by CWE/vuln_type; never double-apply |

## Hard "don't"s

- Don't commit or push by default. The user reviews the diff first.
- Don't fix NOT_EXPLOITABLE findings (dead code / trusted deps) unless asked.
- Don't paste the suggested code blindly — adapt it and confirm it builds.
- Don't widen scope: no fixes for code no finding points at.
- Don't claim an alert is "resolved" — only a re-run of the pipeline proves that.
