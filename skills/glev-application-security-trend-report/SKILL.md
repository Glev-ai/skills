---
name: glev-application-security-trend-report
description: "Runs a security audit over a git repository's commit history with OpenGrep, isolating the findings newly introduced each month and producing a self-contained HTML report styled to the Glev brand. Triggered by `/glev-application-security-trend-report` or natural-language requests like 'audit my git history for security issues', 'security trend over the last N months', 'when were these vulnerabilities introduced', 'month-by-month opengrep report', 'show me how many new findings we shipped each month'. The skill asks for a start month, start year, and number of months to audit, runs a baseline scan plus one incremental scan per month, deduplicates findings by fingerprint so only newly-introduced issues are counted, and writes the final report to tmp/glev/report.html. OpenGrep runs via Docker — the skill does not assume it is installed on the host. The whole pipeline lives behind a single CLI (`scripts/run_audit.py`), so the orchestrator only needs to issue two commands: one for pre-flight and one for the full audit. Use this whenever the user wants a historical view of security findings, even if they don't explicitly mention OpenGrep, Semgrep, or the report file."
---

# Glev Application Security Trend Report
## Overview

This skill walks a repository's git history month by month, runs OpenGrep at
the right commit each time, and isolates the security findings *newly
introduced* per month. Dedup is two-level: redundant rules that flag the same
(CWE, file, line) collapse to one finding within each scan, and opengrep
fingerprints suppress findings already seen in earlier months. The
final deliverable is `tmp/glev/report.html` — a single self-contained file
with KPI tiles, a trend chart, severity and CWE distributions, and a
collapsible per-month finding table, styled to the Glev brand (logo,
Titillium Web font, and Chart.js are all embedded in the file).

The skill is meant to be invoked **inside the target repo**. Every artifact
is written under `<target-repo>/tmp/glev/`; nothing else in the repo is
touched. Scans run inside a `git worktree` so the user's working tree is
never modified.

## Triggering

```
/glev-application-security-trend-report
```

The current working directory is treated as the target repo.

## Speaker prefix

Prefix every user-facing message with `[glev-application-security-trend-report]` so the user
knows which skill is talking. Drop the prefix only inside fenced code blocks.

## Workflow

The full pipeline (pre-flight → prepare → baseline scan → monthly scans →
aggregate → render) is driven by a **single orchestrator script**,
`scripts/run_audit.py`. The orchestrator runs everything in one Python
process, so there is exactly one Bash invocation for the audit itself — no
per-step subprocesses, no flurry of permission prompts.

Call the orchestrator with `<py> <skill-path>/scripts/run_audit.py --repo
"$PWD" ...`, where `<py>` is the interpreter you pick in Step 0. Always pass
`--repo "$PWD"` — the skill runs as a guest inside the target repo and the
orchestrator needs to know where it lives.

### Step 0 — Choose a Python interpreter (do this first)

**Before running anything, decide which interpreter you'll use for every
invocation below, and reuse that same one throughout.** Do *not* just call
`python`/`python3` off the `PATH`: in many setups that resolves to a pyenv
shim, and if the target repo carries a `.python-version` pointing at a
version that isn't installed, the shim aborts *before the orchestrator even
starts* (`pyenv: version '<x>' is not installed`). Pre-flight never runs, so
the skill can't self-diagnose — you have to pick a good interpreter yourself.

Prefer an **absolute** interpreter path that is not a pyenv shim — e.g.
`/opt/homebrew/bin/python3`, `/usr/local/bin/python3`, or
`/usr/bin/python3`. Confirm a candidate meets the version floor (≥ 3.10)
before committing to it, and take the first one that exits 0:

```bash
/opt/homebrew/bin/python3 -c "import sys; assert sys.version_info >= (3,10)"
```

Use that exact path everywhere this document writes `<py>`.

**Recovery.** If a command still dies with `pyenv: version ... is not
installed` (or a similar shim error), that is *not* a skill failure — retry
the same command immediately with an absolute interpreter as above, or by
setting `PYENV_VERSION` to a version that *is* installed for that one call
(e.g. `PYENV_VERSION=3.11.9 /usr/bin/env python3 ...`). Don't report the
skill as broken over a shim resolution problem.

### Step 1 — Pre-flight

Run pre-flight before asking the user for anything. This catches missing
prerequisites in a few seconds instead of after the user has typed inputs:

```bash
<py> <skill-path>/scripts/run_audit.py --repo "$PWD" --check-only
```

Pre-flight is short (a few seconds) — run it in the **foreground** and read
its output directly.

This verifies:

- The working directory is inside a git repository.
- `git` ≥ 2.5 (needed for worktrees).
- Python ≥ 3.10.
- The `docker` CLI is present **and** the daemon is reachable.
- The OpenGrep image is locally present (informational — it will be built
  on first run from the bundled Dockerfile if missing).

If any check fails, the script exits non-zero and prints a concrete
remediation hint (e.g. *"start Docker Desktop (macOS/Windows) or 'sudo
systemctl start docker' (Linux), then retry"*). Relay the hint to the user
and stop — do not proceed.

If pre-flight passes, briefly explain what's about to happen: ask for three
inputs, run one full baseline scan, then one incremental scan per month,
then aggregate and render. Mention that scans run inside a temporary
worktree so their working tree stays untouched.

### Step 2 — Collect inputs

Ask the user for three values, validating each:

- **Start month** (`1`–`12`)
- **Start year** (4-digit; the start month/year must not be in the future)
- **Number of months to audit** (`1` or more)

There is no hard upper bound on the number of months — the window just can't
extend past the current month. But each audited month is a separate scan, so
a long window is a long run. **If the user asks for more than 12 months,
confirm before proceeding** (e.g. *"that's an N-month audit — N+1 scans
including the baseline, which can take a while on a large repo. Go ahead?"*).
Don't block it; just make sure they meant it.

The audit covers `nb_months` consecutive months *starting from* the start
month. For example, start month `10`, start year `2025`, nb_months `6`
covers Oct 2025 → Mar 2026.

The baseline is the last commit strictly before the first day of the start
month. The "Nth audited month" is the last commit of that calendar month.
Don't over-explain this unless asked — the user typically just wants to
hand off the three numbers.

Use `AskUserQuestion` to collect them. Re-prompt if invalid; the
orchestrator will also validate, but catching errors here is friendlier.

### Step 3 — Full audit (run it as a background job)

Run the orchestrator once. Everything between pre-flight and the final
report happens inside this single invocation:

```bash
<py> <skill-path>/scripts/run_audit.py \
  --repo "$PWD" \
  --start-year <Y> --start-month <M> --nb-months <N>
```

**Always launch the full audit as a detached / background job — never in the
foreground.** This is a binary rule; don't try to estimate the duration and
decide. The reason: each audited month is a separate scan, and the **baseline
scan alone walks the entire tree**, which on a large repo can exceed the
environment's foreground execution ceiling (commonly ~10 minutes) and get the
run killed mid-scan. The total runtime isn't predictable up front, so don't
gamble on the foreground.

The *pattern* to use (stay generic — use whatever your harness provides for
each piece; don't hard-code specific tool names):

1. Start the orchestrator as a **background/detached process** so it isn't
   bound by the foreground time limit.
2. **Stream its progress**: follow stderr and relay it **one `[audit]` line
   at a time** as each step completes — every line is a checkpoint worth
   surfacing.
3. **Notify on completion**: when the process exits, tell the user (success →
   the report path; non-zero → the `[audit] failed: ...` line).

**Set expectations first (cheap duration proxy).** Before launching, sample
two cheap signals — only to *warn* the user, never to change the "always
background" decision:

- repo size: `git ls-files | wc -l` (tracked file count),
- window length: the number of months requested.

A big repo (tens of thousands of tracked files) over many months can take
**several tens of minutes**, dominated by the baseline full-tree scan — say
so plainly (e.g. *"~40k files over 12 months — expect a few tens of minutes,
most of it the baseline scan"*). A small repo over a couple of months is
usually just a few minutes.

If the run is cut off anyway (environment kill, timeout, crash), it is
recoverable — every completed scan is persisted under `tmp/glev/`, so
re-launch with `--resume` (see *Resuming an interrupted run* below) instead
of starting over.

The orchestrator streams a compact, one-line-per-step trace on stderr.
Relay it to the user as it arrives — it's already laid out for reading:

```
[audit] pre-flight OK
[audit] worktree ready at <sha>
[audit] scanning baseline <sha> (full tree, may take minutes)
[audit] baseline: 124 findings on 341 files
[audit] month 1/6 (2025-10): 0 findings on 0 changed files
[audit] month 2/6 (2025-11): 10 findings on 46 changed files
...
[audit] aggregated: 29 new findings across 6 months
[audit] report: <repo>/tmp/glev/report.html
[audit] worktree removed
```

The numbers on the `baseline:` and `month N/M:` lines are per-scan counts
after redundant rules at the same (CWE, file, line) are collapsed — the same
figures the report shows for each scan. A month's *new findings* in the
report can be lower, since aggregate also drops findings already seen in
earlier months. On a large repo the baseline scan can take several minutes;
tell the user to expect that.

If the orchestrator exits non-zero, the last `[audit] failed: ...` line
contains the user-facing error. Relay it as-is and stop. Pass `--debug` if
you need a full traceback for diagnostics.

### Resuming an interrupted run

A long audit that gets killed mid-scan doesn't have to start over. Every scan
is written under `tmp/glev/` the moment it finishes (`baseline.json`,
`month-01.json` … `month-NN.json`, alongside `commits.json`), so
`run_audit.py --resume` reuses everything already done and only rescans
what's missing.

**When to use it.** *Only* to recover a run of the **same window** that never
reached its final `[audit] report:` line (killed, timed out, or crashed),
while `tmp/glev/` still holds `commits.json` (for that window) plus
`baseline.json` and at least one `month-*.json`. It is **not** a way to reuse
artifacts across a *different* window — `--resume` refuses that outright (it
checks the saved `commits.json` window against the arguments you pass and
errors if they differ, so it never mixes scans of different commits).

**Recognizing an interrupted run vs. a real failure:**

- *Interrupted* → eligible for `--resume`: scan artifacts exist under
  `tmp/glev/` but you never saw the closing `[audit] report:` /
  `[audit] worktree removed` lines. The worktree may or may not still be
  there.
- *Business failure* → do **not** resume: the run ended on an
  `[audit] failed: ...` line (e.g. no commits before the baseline date,
  Docker down). That's a real error to fix and relay, not something
  `--resume` papers over.

**How to resume.** Re-issue the *exact same* audit command with the **same**
window arguments plus `--resume`, and launch it the same way as a fresh
audit — **as a background job with line-by-line progress relay** (Step 3):

```bash
<py> <skill-path>/scripts/run_audit.py \
  --repo "$PWD" \
  --start-year <Y> --start-month <M> --nb-months <N> \
  --resume
```

Before launching, sanity-check the preconditions: `tmp/glev/commits.json`
exists and its `window` matches `<Y>/<M>/<N>`, and at least one scan JSON is
present. (If `commits.json` is for another window, `--resume` refuses — either
re-run with that original window, or drop `--resume` for a fresh run.)

The trace looks like a normal run, except already-done steps are logged as
`cached`:

```
[audit] resume: 7 cached scan(s), 2 to run (2025-01 +12mo)
[audit] baseline: cached
[audit] month 1/12 (2025-01): cached
...
[audit] month 8/12 (2025-08): 4 findings on 31 changed files
[audit] month 9/12 (2025-09): 6 findings on 52 changed files
...
[audit] aggregated: 29 new findings across 12 months
[audit] report: <repo>/tmp/glev/report.html
```

Tell the user in those terms: *"resuming from K cached scans; only M scans
are re-run."* The final numbers are **identical** to what an uninterrupted
run would have produced — resume changes *how much is rescanned*, never the
results. It still aggregates, renders, and cleans up the worktree like a
normal run — even in the corner case where the worktree was already deleted
but every `month-*.json` is present (aggregation and rendering don't need the
worktree).

### Step 4 — Hand the report to the user

The report is `$PWD/tmp/glev/report.html`.

**If your environment can surface a file directly to the user** — render or
preview it, attach it, open it in a viewer — do that with the report path so
they can *see* it immediately rather than only reading a path. Keep this
generic: use whatever file-surfacing mechanism your harness provides; don't
assume a specific tool.

**Otherwise (or in addition)**, give them the absolute path and the
platform-appropriate opener:

- macOS: `open tmp/glev/report.html`
- Linux: `xdg-open tmp/glev/report.html`
- Windows (PowerShell): `start tmp/glev/report.html`

**Don't re-type the report's numbers into the chat** — the full analysis
already lives in the HTML. Just briefly describe what they'll see so they know
where to look: KPI tiles (findings at baseline, total new findings, peak
month, top CWE), a trend chart with severity breakdown, a CWE-frequency
chart, and per-month tables they can expand.

Mention that:

- The raw scan JSONs and `summary.json` are left in `tmp/glev/` for
  inspection and reuse by other tools. A plain re-run (without `--resume`)
  re-scans from scratch — it does **not** reuse those scan JSONs; only the
  rule pack, the Docker image, and the Chart.js/font assets are cached
  between runs. To deliberately reuse the existing per-scan JSONs after an
  interrupted run, use `--resume` with the same window (see *Resuming an
  interrupted run*).
- `summary.json` is a stable JSON they can feed into other tools.

### Step 5 — Cleanup

The orchestrator removes the worktree itself once the report is written (the
final `[audit] worktree removed` line confirms it), so there's nothing to do
here on a successful run. The worktree has no reuse value — a re-run recreates
it.

The other artifacts in `tmp/glev/` are deliberately kept: the user may want to
inspect the raw scans or share `summary.json`. Don't delete those.

If a run fails partway, the worktree is left in place to aid debugging. If a
stale worktree ever blocks a later run, the orchestrator surfaces the exact
`git worktree remove --force <path>` to run manually.

## Edge cases to surface to the user

These all bubble up as non-zero exits from the orchestrator with a single
`[audit] failed: ...` line. Your job is to relay them in conversational
form, not to debug.

- **No commits before the baseline date.** Fails with *"no commits in
  <repo> before YYYY-MM-01; pick a later start month"*. Offer to re-run
  with a later start.

- **Month with no commits.** Not an error. A month with no commits of its
  own resolves to the previous commit, so its diff is empty and it shows as
  `0 new · 0 files changed` in the trace and the report (the per-month row
  reads *"No new commits this month — nothing to scan."*). The audit
  continues normally; nothing to surface unless the user asks.

- **Docker missing or daemon down.** Caught in pre-flight. The hint is
  concrete (install link, start command). Don't try to install Docker for
  the user.

- **OpenGrep image.** OpenGrep does not publish a public Docker image, so
  the skill ships a minimal `assets/opengrep.Dockerfile` that downloads the
  official binary from GitHub Releases. On first run, the orchestrator
  builds it locally as
  `glev-application-security-trend-report/opengrep:<version>` — takes about 30 seconds, then
  it's cached for all future audits. Subsequent runs reuse the cached
  image with no network needed.

  Users who already have an opengrep image (a corporate mirror, a custom
  build, or one they pulled manually) can override via env var:

  ```bash
  export OPENGREP_IMAGE=opengrep-test:latest
  export OPENGREP_IMAGE=registry.corp.example/opengrep:1.40
  ```

  When `OPENGREP_IMAGE` is set, the skill skips the build and uses the
  given image directly. If it isn't pullable, pre-flight surfaces that
  before the user provides audit inputs.

- **`[opengrep] note: scan exited N ... but produced valid output`.**
  Informational, **not** an error. OpenGrep exits non-zero (2) whenever a
  rule or target fails to parse — e.g. a malformed rule in the public pack —
  while still writing a complete, valid result set. The skill keys success on
  the output being valid, not on the exit code, so it logs this note and
  continues. Don't relay it as a failure; the audit is fine. (A genuinely
  broken scan produces no valid output and surfaces as `[audit] failed: ...`.)

- **Working tree dirty.** Informational only. The scan uses an isolated
  worktree, so uncommitted changes aren't affected. The orchestrator notes
  it once on stderr.

- **An existing worktree at `tmp/glev/worktree`.** The orchestrator removes
  it before re-adding. If removal fails (e.g. locked), it surfaces the
  exact `git worktree remove --force <path>` to run manually.

- **Findings without `extra.fingerprint`.** Rare, but possible with custom
  rules. The aggregator synthesizes a hash and flags
  `synthetic_fingerprint=true` on the finding. The orchestrator notes the
  count on stderr; mention it to the user if it's nonzero — dedup is
  best-effort for those rows.

- **Multi-CWE findings.** All CWEs are listed in the row, but only the
  first counts toward the CWE distribution to avoid inflating totals.

- **Very large repo / long scans.** Each scan can take minutes; the
  orchestrator streams OpenGrep's progress live. Tell the user to expect
  this, especially for the baseline (it's a full-tree scan).

## Output reference

For machine-readable consumption, the canonical artifact is
`tmp/glev/summary.json`. Key fields:

```jsonc
{
  "repo_name": "...",
  "generated_at": "ISO-8601 UTC",
  "window": { "start_year": 2025, "start_month": 10, "nb_months": 6 },
  "baseline": { "sha": "...", "date": "...", "findings_count": 124 },
  "synthetic_fingerprint_count": 0,
  // display labels (short_name or name from assets/cwe-registry.csv) for
  // every CWE present in the report; finding paths are repo-relative
  // (the /src Docker mount prefix is stripped at aggregation)
  "cwe_labels": { "CWE-79": "XSS", "CWE-94": "Code Injection" },
  "months": [
    {
      "n": 1, "year": 2025, "month": 10, "label": "2025-10",
      "commit": { "sha": "...", "date": "..." },
      "files_changed": 124,
      "new_findings_count": 17,
      "counts_by_severity": { "veryhigh": 3, "medium": 10, "low": 4 },
      "counts_by_cwe": { "CWE-79": 5, "CWE-89": 2 },
      "findings": [ /* ... */ ]
    }
  ],
  "totals": {
    "new_findings": 73,
    "by_severity": { "veryhigh": 9, "medium": 41, "low": 23 },
    // each entry also carries a per-severity split for the distribution chart
    "by_cwe_top10": [
      { "cwe": "CWE-79", "count": 18, "by_severity": { "veryhigh": 4, "medium": 14 } }
    ]
  }
}
```
