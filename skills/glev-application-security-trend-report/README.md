# Glev Application Security Trend Report
An agent skill that runs a month-by-month security audit over a
repository's git history with **OpenGrep**, isolating the findings *newly
introduced* per month and producing a self-contained HTML report styled to
the Glev brand (logo, Titillium Web, brand colors — all embedded in the
single file). Optimized for Claude Code, compatible with most other coding
agents.

## What it does

When you type `/glev-application-security-trend-report` inside a repo, the agent:

1. Runs a pre-flight check (Docker daemon, Python, git, image availability).
2. Asks you for **start month**, **start year**, and **number of months** to
   audit.
3. Hands the inputs to a single orchestrator script (`scripts/run_audit.py`)
   that drives the rest of the pipeline in one Python process:
   - resolves the baseline commit + the month-end commit for each audited
     month,
   - downloads the Semgrep rule pack into `tmp/glev/rules/`,
   - builds (or reuses) the OpenGrep Docker image,
   - creates a temporary `git worktree` so your working tree is never
     touched,
   - runs one full OpenGrep scan at the baseline, then one incremental scan
     per audited month (only the files changed since the previous commit),
   - deduplicates findings two ways: redundant rules flagging the same
     (CWE, file, line) collapse to one within each scan, and opengrep
     fingerprints isolate "newly introduced this month" — anything seen in
     the baseline or an earlier month is excluded,
   - aggregates everything into `tmp/glev/summary.json` and renders
     `tmp/glev/report.html` (a single self-contained file).

A single Bash invocation covers everything between Step 2 and the final
report. The orchestrator streams a compact `[audit] ...` trace on stderr,
one line per step.

## What it produces

- `tmp/glev/baseline.json` — raw OpenGrep output at the baseline commit.
- `tmp/glev/month-NN.json` — one raw output per audited month.
- `tmp/glev/commits.json` — the resolved commit list with dates.
- `tmp/glev/summary.json` — machine-readable summary with per-month
  breakdowns by severity and CWE.
- `tmp/glev/report.html` — the human-facing report. Self-contained: opens
  without internet access.

Sample `summary.json` shape:

```jsonc
{
  "repo_name": "acme-api",
  "window": { "start_year": 2025, "start_month": 10, "nb_months": 6 },
  "baseline": { "sha": "abcd1234...", "date": "2025-09-30T18:42:11+00:00" },
  "totals": {
    "new_findings": 73,
    "by_severity": { "veryhigh": 9, "medium": 41, "low": 23 },
    "by_cwe_top10": [ { "cwe": "CWE-79", "count": 18, "by_severity": { "veryhigh": 4, "medium": 14 } } ]
  },
  "months": [
    {
      "n": 1, "year": 2025, "month": 10, "label": "2025-10",
      "new_findings_count": 17,
      "counts_by_severity": { "veryhigh": 3, "medium": 10, "low": 4 },
      "counts_by_cwe": { "CWE-79": 5, "CWE-89": 2 }
    }
  ]
}
```

The HTML report shows KPI tiles, a stacked-bar trend chart, a severity
doughnut, a top-10 CWE horizontal bar, and one collapsible table per month
with the actual findings.

## Requirements

- **Docker**, with the daemon running. OpenGrep is invoked via
  `docker run` — there is no host install requirement. OpenGrep doesn't
  publish a public Docker image, so the skill ships a tiny
  `assets/opengrep.Dockerfile` that wraps the official binary release.
  On first run the skill builds this image locally (~30 s); subsequent
  runs reuse the cache.
  If you already have an opengrep image you'd rather use, set
  `OPENGREP_IMAGE=<your-image>:tag` and the skill will use it instead of
  building.
- **git ≥ 2.5** (for worktrees).
- **Python ≥ 3.10**.
- **Network access** on first run, to:
  - download the OpenGrep rule pack from `semgrep.dev`
  - pull the OpenGrep Docker image (unless already cached locally)
  - download Chart.js and the Titillium Web font files to inline them into
    the report

After the first run, all of the above are cached under `tmp/glev/rules/` and
Docker's local image store, so subsequent audits can run offline.

## Installation

This skill lives in the [`Glev-ai/skills`](https://github.com/Glev-ai/skills)
repo. Any of the methods below work — the `skills` CLI is the easiest.

### Option 1 — `skills` CLI (recommended)

```bash
# just this skill
npx skills add Glev-ai/skills --skill glev-application-security-trend-report

# …or every Glev skill at once
npx skills add Glev-ai/skills
```

Add `-g` for user scope (available across all your projects). The CLI writes the
files under `.agents/skills/glev-application-security-trend-report/` and
**symlinks them into `.claude/skills/glev-application-security-trend-report/`** —
where Claude Code discovers skills. Start a new Claude Code session to pick it up;
if your project has no `.claude/` directory yet, create one first so the symlink
lands.

### Option 2 — Manual copy (no CLI)

Clone the repo and copy just this skill's folder into your skills directory.
Project scope (this repo only):

```bash
git clone https://github.com/Glev-ai/skills.git /tmp/glev-skills
mkdir -p .claude/skills
cp -r /tmp/glev-skills/skills/glev-application-security-trend-report \
      .claude/skills/glev-application-security-trend-report
```

…or user scope (all your projects) — copy into `~/.claude/skills/` instead:

```bash
mkdir -p ~/.claude/skills
cp -r /tmp/glev-skills/skills/glev-application-security-trend-report \
      ~/.claude/skills/glev-application-security-trend-report
```

### Option 3 — Another coding agent

The pipeline has no agent dependency. Install through your agent's own
skills/plugins mechanism, or simply point it at this folder's `SKILL.md` as
instructions.

### Verify installation

```
/glev-application-security-trend-report
```

If the skill is loaded, the agent runs pre-flight first, then asks for the
three audit inputs.

## Usage

```bash
cd your-repo
# start your coding agent from here
```

```
/glev-application-security-trend-report
```

Then answer:

- **Start month** (1–12)
- **Start year** (4-digit, not in the future)
- **Number of months** (1 or more — the agent confirms before runs longer
  than 12 months, since each month is a separate scan)

Once the report is written, open it:

```bash
# macOS
open tmp/glev/report.html
# Linux
xdg-open tmp/glev/report.html
# Windows (PowerShell)
start tmp/glev/report.html
```

A plain re-run always re-scans from scratch; it only reuses the cached rule
pack, Docker image, and Chart.js/font assets — not the per-scan JSONs. To
force a fresh rule download, pass `--refresh-rules`. To deliberately reuse the
existing scans after an interrupted run, pass `--resume` (same window) — see
[Running it manually](#running-it-manually-without-an-agent) below.

### Running it manually (without an agent)

The audit can also be launched without the agent, by invoking
`scripts/run_audit.py` directly. Point `--repo` at the repo you want to
audit (use `"$PWD"` if you're already inside it):

```bash
# Pre-flight only (no inputs, no artifacts written)
python3 /path/to/glev-application-security-trend-report/scripts/run_audit.py \
  --repo "$PWD" --check-only

# Full audit: Oct 2025 → Mar 2026 (6 months)
python3 /path/to/glev-application-security-trend-report/scripts/run_audit.py \
  --repo "$PWD" \
  --start-year 2025 --start-month 10 --nb-months 6
```

> **Pick the interpreter deliberately.** Use a real Python ≥ 3.10, ideally an
> absolute path (`/opt/homebrew/bin/python3`, `/usr/local/bin/python3`,
> `/usr/bin/python3`) rather than a bare `python`/`python3`. A bare call may
> resolve to a pyenv shim, and if the target repo has a `.python-version`
> pointing at an uninstalled version the shim fails before the script even
> starts (`pyenv: version '<x>' is not installed`). If that happens, retry
> with an absolute interpreter or set `PYENV_VERSION` to an installed one.

The script streams the same `[audit] ...` trace to stderr, writes everything
under `<repo>/tmp/glev/`, and removes its worktree when it's done.

**Resuming an interrupted run.** A long audit that gets killed mid-scan
(timeout, environment kill, crash) can be continued instead of restarted:
each scan is persisted under `tmp/glev/` as it completes, so re-run the
**exact same command with the same window** plus `--resume`. It reuses the
baseline/month scans already on disk (logged as `cached`), rescans only the
missing ones, and produces identical final numbers. `--resume` refuses if the
cached window doesn't match the arguments you pass, so it never mixes scans
from different windows:

```bash
python3 /path/to/glev-application-security-trend-report/scripts/run_audit.py \
  --repo "$PWD" \
  --start-year 2025 --start-month 10 --nb-months 6 \
  --resume
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--check-only` | Run pre-flight checks and exit. |
| `--resume` | Resume an interrupted run of the **same** window: reuse the baseline/month scan JSONs already under `tmp/glev/`, rescan only the missing ones, then aggregate and render. Refuses if the cached `commits.json` window doesn't match the `--start-year/--start-month/--nb-months` you pass. |
| `--refresh-rules` | Re-download the OpenGrep rule pack even if cached. |
| `--cdn` | Reference Chart.js and the Titillium Web font from CDNs instead of inlining them (smaller report, needs network to open). |
| `--debug` | Print a full traceback on failure instead of a one-line message. |

Only `scripts/run_audit.py` is meant to be run directly — the modules under
`scripts/lib/` expose functions, not CLIs.

### Tips

- **Start with a smaller window.** A 2- or 3-month audit on a new repo is a
  fast way to confirm everything works before committing to a 12-month run.
- **Long scans are normal.** The baseline scan is a full-tree pass; on a
  large repo it can take several minutes. The skill streams OpenGrep's
  progress to your terminal.
- **Tag the rule pack version.** `tmp/glev/rules/semgrep-rules.yaml` is
  what was scanned with. Keep it around if you want reproducibility — pass
  `--refresh-rules` to `run_audit.py` only when you explicitly want to update.

## Contributing

Working on the skill itself (not just running it)? See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the architecture, dev workflow, and the
invariants to preserve.

## License

MIT
