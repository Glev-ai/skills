# Contributing — glev-application-security-trend-report

Guidance for **maintaining this skill's code**. For *running* the skill against a
repo, see [`SKILL.md`](SKILL.md) (runtime instructions) and [`README.md`](README.md)
(install / usage). This file is only about working on the code here.

## Confidentiality — no leaking internal repos

This is a shareable/distributable skill. **Never** reference private application
repositories in this skill's code, comments, docstrings, or docs: no repo names,
no source paths, no internal file names, no internal function/symbol names. When
porting a convention from internal code, describe it **generically** — e.g. "the
standard Glev SAST finding identity (one issue per sink line)" — and never point
at where it lives internally. Keep examples synthetic. Assume anything written
here can end up outside Glev.

## What this skill is

A security audit over a git repo's **history**: it scans with OpenGrep at a
baseline commit, then at each month-end commit over a window, and reports the
findings **newly introduced** per month (two-level dedup; see Invariants).
Deliverable is a single self-contained `tmp/glev/report.html`.

## Architecture

- **One executable**: `scripts/run_audit.py`. It orchestrates the whole pipeline
  in a single process and is the only CLI.
- **`scripts/lib/*` are functions, not CLIs** — don't add `__main__` blocks or
  invoke them directly.
- Pipeline order: **pre-flight → prepare → baseline scan → N monthly scans →
  aggregate → render**. Each `lib` module owns one phase; `run_audit.py` only
  wires them and logs one `[audit]`-prefixed line per step on stderr.

Per-module detail is in the module docstrings (each file opens with a clear
summary). **Don't duplicate that here** — read the docstrings.

### Layout

```
glev-application-security-trend-report/
├── SKILL.md                   # Runtime orchestration prompt (how an agent runs the skill)
├── README.md                  # User doc — install / usage
├── CONTRIBUTING.md            # This file — maintainer guide
├── CLAUDE.md                  # Pointer to this file (auto-loaded by Claude Code)
├── scripts/
│   ├── run_audit.py           # SINGLE entry point — drives the full pipeline
│   └── lib/                   # Library modules (not meant to be run directly)
│       ├── paths.py           # Workspace path constants
│       ├── gitops.py          # Commit resolution, worktree management
│       ├── opengrep.py        # Docker wrapper, rules cache
│       ├── findings.py        # Security filter, CWE/severity normalization, redundant-rule collapse
│       ├── preflight.py       # Environment checks
│       ├── prepare.py         # Resolve commits, fetch rules, ready worktree
│       ├── scan.py            # Baseline + monthly scan functions
│       ├── aggregate.py       # Fingerprint dedup + (CWE,file,line) collapse, build summary.json
│       └── render.py          # Render report.html from summary.json
└── assets/
    ├── opengrep.Dockerfile    # Minimal image built locally on first run
    ├── cwe-registry.csv       # CWE-NNN → human label
    └── report_template.html   # Glev-styled report template (with placeholders)
```

## Dev workflow

Use a real Python ≥ 3.10 (ideally an absolute path, not a bare
`python`/`python3` that may resolve to a pyenv shim). `SKILL.md` Step 0 explains
why for the runtime side.

```bash
# Pre-flight only (no inputs, no artifacts) — run this to sanity-check a change
python3 scripts/run_audit.py --repo "$PWD" --check-only

# Full audit (M=start month 1-12, Y=4-digit year, N=number of months)
python3 scripts/run_audit.py --repo "$PWD" --start-year <Y> --start-month <M> --nb-months <N>

# Resume an interrupted run of the SAME window (reuse cached scans, rescan
# only what's missing, then aggregate + render)
python3 scripts/run_audit.py --repo "$PWD" --start-year <Y> --start-month <M> --nb-months <N> --resume

# Useful flags: --refresh-rules (re-download rule pack), --cdn (don't inline
# Chart.js/font), --debug (full tracebacks)
```

There is no test suite. To validate a change, run pre-flight, then a short real
audit (e.g. `--nb-months 2`) against a small git repo and open the report. To
exercise `--resume`, delete a `month-*.json` and re-run with `--resume`: only
that month should rescan, and the final `summary.json` must be identical to the
full run's.

## Invariants — do not break these

- **All output stays under `<repo>/tmp/glev/`.** Every path goes through
  `lib/paths.py`; add new artifacts there, never hard-code paths elsewhere. The
  skill must never write anywhere else in the target repo.
- **The user's working tree is never touched.** Scans run in an isolated
  detached `git worktree` (`lib/gitops.py`). Don't operate on the live tree.
- **OpenGrep runs only via Docker** (`lib/opengrep.py`). Never assume it's
  installed on the host. The default image is *built locally* from
  `assets/opengrep.Dockerfile` on first run; `OPENGREP_IMAGE` can override it
  (then it's pulled). Keep `OPENGREP_VERSION` and the Dockerfile in sync.
- **Success is decided by output validity, not exit code.** OpenGrep exits
  non-zero (2) whenever a rule or target fails to parse — including a malformed
  rule shipped in the public pack — while still writing a complete result set.
  `_docker_run` therefore accepts any run whose output passes
  `opengrep.output_valid` (a dict with a `results` list), regardless of exit
  code, and only falls back to the rootful retry / errors when the output is
  missing or corrupt. Don't "fix" this back to failing on non-zero exit — it
  would make a single bad pack rule fail whole audits (small repos especially,
  where OpenGrep does surface such errors as exit 2). `output_valid` is also the
  single completeness check reused by `--resume` (`scan.scan_json_valid`).
- **Results must be reproducible run-to-run.** Two settings guarantee it, and
  both are easy to regress: (1) month boundaries pin an explicit
  `<date>T00:00:00Z` instant in `gitops.resolve_commit_before` — never pass a
  bare date to `git log --before`, because git's approxidate fills it with the
  *current wall-clock time of day*, so a month would resolve to a different
  commit depending on when the audit runs. (2) OpenGrep runs with `--timeout 60`
  (`opengrep.py` scan args); the 5s default makes heavy files / catastrophic-regex
  rules time out, which silently drops findings and is non-deterministic (a rule
  that times out on one run may not on the next).
- **Monthly scans are incremental — changed files only.** `run_incremental`
  passes just the changed paths as targets (never appends `/src`, which would
  rescan the whole tree every month). This is safe because a newly-introduced
  finding must live in a file that changed; unchanged-file findings are already
  in `seen` from the baseline/earlier months and get deduped. The baseline is the
  only full-tree scan. A resumed or incremental run must yield the same
  `summary.json` "new findings" numbers as a full-tree scan would.
- **The security filter lives in one place**: `findings.is_security` /
  `findings.from_raw`. A finding is kept if category is `security`, or it carries
  a CWE when category is unset; **CWE-798 is dropped**. Change the policy here and
  nowhere else.
- **Dedup is two-level.** (1) *Within each scan*: `findings.collapse_redundant`
  keeps one highest-severity representative per `(CWE, file, line)` — multiple
  rules flagging the same sink collapse to one. This matches the standard Glev
  finding identity for SAST (one issue per sink line). (2) *Across months*:
  `lib/aggregate.py` dedups by **fingerprint** — `seen` starts from baseline
  fingerprints, each month keeps only unseen ones = "newly introduced".
  Fingerprint (not the tuple) is used cross-month on purpose: line numbers drift
  between commits, and the opengrep fingerprint hashes code, so it survives the
  drift. `seen` must hold **every** fingerprint, including ones collapsed away, or
  a collapsed rule firing alone in a later month would resurface. A finding counts
  only under its **first** normalized CWE (`findings.primary_cwe`). Missing
  fingerprints fall back to a synthesized hash (`synthetic_fingerprint=True`).
- **The "eligible" count is a single source of truth.** `scan._count_eligible`
  replays `findings.from_raw` so the numbers in the stderr trace, `summary.json`,
  and the HTML report always match. If you touch the filter, this consistency
  must hold.
- **`--resume` must reproduce a full run exactly.** Resume only skips scans whose
  JSON is already present and valid (`scan.scan_json_valid`: parses as JSON with a
  `results` list — a truncated/partial file is treated as missing and rescanned).
  It **must not** reuse artifacts from a different window: it cross-checks
  `commits.json`'s `window` against the CLI args and errors on a mismatch, so
  scans of different commit sets are never blended. Aggregate and render stay
  idempotent, so a resumed run yields byte-identical `summary.json` numbers to an
  uninterrupted one — keep it that way. Resume lives inside `run_audit.py` (the
  one executable); do **not** add a second CLI for it.
- **The report is self-contained by default**: Chart.js and the Titillium Web
  brand font are inlined (base64) by `lib/render.py`, cached under `tmp/glev/`.
  `--cdn` switches to external references. Keep the offline-by-default behavior.

## Assets the code depends on (`assets/`)

- `opengrep.Dockerfile` — wraps the OpenGrep binary; built locally (`opengrep.py`).
- `cwe-registry.csv` — maps `CWE-NNN` → human label (`aggregate._load_cwe_registry`);
  degrades gracefully if missing.
- `report_template.html` — has `__CHARTJS__`, `__FONT_CSS__`, `__SUMMARY_JSON__`
  placeholders that `render.py` substitutes. If you rename a placeholder, update
  both sides.

## Keep docs in sync

A behavior or flag change usually touches **three places** — update all of them:

1. the `argparse` in `scripts/run_audit.py`,
2. `SKILL.md` (the runtime workflow / Output reference),
3. `README.md` (usage / requirements).

Forgetting 2 or 3 is the most common drift here.
