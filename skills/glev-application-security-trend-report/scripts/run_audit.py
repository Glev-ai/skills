#!/usr/bin/env python3
"""Single entry point for the glev-application-security-trend-report skill.

Drives the full pipeline in one Python process: pre-flight -> prepare ->
baseline scan -> N monthly scans -> aggregate -> render. Every line emitted
on stderr is prefixed with `[audit]` so the orchestrator's trace is
distinguishable from any underlying tool output.

This is the ONLY executable in the skill. The library modules under
`scripts/lib/` aren't designed to be launched directly -- they expose
functions, not CLIs.

Modes:
  --check-only           run pre-flight only, no inputs, no artifacts
  full mode              requires --start-year/--start-month/--nb-months;
                         produces tmp/glev/report.html
  --resume               same window as a prior interrupted run; reuse the
                         per-scan JSONs already under tmp/glev/, rescan only
                         what's missing, then aggregate + render
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

# Make `lib` importable regardless of cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib import gitops, opengrep, paths, preflight  # noqa: E402
from lib import aggregate as agg_mod  # noqa: E402
from lib import prepare as prep_mod  # noqa: E402
from lib import render as render_mod  # noqa: E402
from lib import scan as scan_mod  # noqa: E402


LOG_PREFIX = "[audit]"


def _log(msg: str) -> None:
    print(f"{LOG_PREFIX} {msg}", file=sys.stderr, flush=True)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the full glev-application-security-trend-report pipeline."
    )
    p.add_argument("--repo", required=True, type=Path, help="target repo to audit")
    p.add_argument("--start-year", type=int)
    p.add_argument("--start-month", type=int)
    p.add_argument("--nb-months", type=int)
    p.add_argument(
        "--refresh-rules",
        action="store_true",
        help="re-download the opengrep rule pack even if cached",
    )
    p.add_argument(
        "--check-only",
        action="store_true",
        help="only run pre-flight checks, then exit",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="resume an interrupted run of the SAME window: reuse the "
        "baseline/month scan JSONs already cached under tmp/glev/, rescan "
        "only the missing ones, then aggregate and render. Refuses if the "
        "cached commits.json window doesn't match "
        "--start-year/--start-month/--nb-months.",
    )
    p.add_argument(
        "--cdn",
        action="store_true",
        help="reference Chart.js and the Titillium Web font via CDN "
        "instead of inlining them in the report",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="print full tracebacks on failure instead of a one-line message",
    )
    return p.parse_args()


def _run_preflight(repo: Path) -> bool:
    checks = preflight.run_all_checks(repo)
    rendered = preflight.render(checks)
    if preflight.all_ok(checks):
        _log("pre-flight OK")
        # Keep the detail in stderr but unprefixed -- it's a sub-report.
        print(rendered, file=sys.stderr, flush=True)
        return True
    _log("pre-flight FAILED")
    print(rendered, file=sys.stderr, flush=True)
    return False


def _require_window_args(args: argparse.Namespace) -> prep_mod.Window:
    missing = [
        name
        for name, val in [
            ("--start-year", args.start_year),
            ("--start-month", args.start_month),
            ("--nb-months", args.nb_months),
        ]
        if val is None
    ]
    if missing:
        raise SystemExit(
            f"missing required arguments: {', '.join(missing)} "
            "(only --check-only can omit them)"
        )
    return prep_mod.Window(
        year=args.start_year, month=args.start_month, nb_months=args.nb_months
    )


def _note_working_tree(repo: Path) -> None:
    if gitops.is_working_tree_dirty(repo):
        _log(
            "note: your working tree has uncommitted changes; "
            "scans run in an isolated worktree, so they are untouched"
        )


def _aggregate_and_render(repo: Path, total: int, *, use_cdn: bool) -> Path:
    """Aggregate + render, shared by full and resumed runs.

    Both phases are idempotent: they read the per-scan JSONs and rebuild
    summary.json / report.html from scratch, so a resumed run that reused
    cached scans produces the exact same numbers as an uninterrupted run.
    """
    summary = agg_mod.aggregate(repo)
    new_total = summary["totals"]["new_findings"]
    _log(f"aggregated: {new_total} new findings across {total} months")
    synthetic = summary.get("synthetic_fingerprint_count", 0)
    if synthetic:
        _log(
            f"note: {synthetic} finding(s) lacked an opengrep fingerprint; "
            "dedup falls back to a synthesized hash for those rows"
        )

    report_path = render_mod.render(repo, use_cdn=use_cdn)
    _log(f"report: {report_path}")
    return report_path


def _remove_worktree(repo: Path) -> None:
    """Remove the audit worktree if it's present, logging when it happens.

    The report and JSON artifacts under tmp/glev/ are kept, but the
    checked-out worktree has no reuse value (a re-run recreates it). On
    failure it's left in place to aid debugging.
    """
    wt = paths.worktree(repo)
    if not gitops.worktree_exists(wt):
        return
    gitops.cleanup_worktree(repo, wt)
    _log("worktree removed")


def _run_full_audit(
    repo: Path, window: prep_mod.Window, *, refresh_rules: bool, use_cdn: bool
) -> Path:
    # Prepare
    commits = prep_mod.prepare(repo, window, refresh_rules=refresh_rules)
    baseline_short = commits["baseline"]["sha"][:8]
    _log(f"worktree ready at {baseline_short}")
    _note_working_tree(repo)

    # Baseline scan
    _log(f"scanning baseline {baseline_short} (full tree, may take minutes)")
    baseline = scan_mod.scan_baseline(repo, commits)
    _log(f"baseline: {baseline.eligible} findings on {baseline.files} files")

    # Monthly scans
    total = len(commits["months"])
    for entry in commits["months"]:
        n = entry["n"]
        label = f"{entry['year']}-{entry['month']:02d}"
        result = scan_mod.scan_month(repo, commits, n)
        _log(
            f"month {n}/{total} ({label}): "
            f"{result.eligible} findings on {result.files} changed files"
        )

    report_path = _aggregate_and_render(repo, total, use_cdn=use_cdn)
    _remove_worktree(repo)
    return report_path


def _fmt_window(w: dict) -> str:
    """Human-readable window for error messages; tolerant of partial data."""
    y = w.get("start_year")
    m = w.get("start_month")
    n = w.get("nb_months")
    mm = f"{m:02d}" if isinstance(m, int) else str(m)
    return f"{y}-{mm} +{n}mo"


def _load_commits_for_resume(repo: Path, window: prep_mod.Window) -> dict:
    """Load tmp/glev/commits.json and assert it matches the requested window.

    Resume must never mix scans from a different window: tmp/glev/ can hold
    leftovers from an earlier audit (or unrelated JSON), and blending scans of
    different commit sets would corrupt the dedup. A mismatch is a hard error.
    """
    commits_path = paths.commits_json(repo)
    if not commits_path.exists():
        raise RuntimeError(
            f"cannot resume: no commits.json under {paths.tmp_dir(repo)}. "
            "--resume only reuses artifacts from an earlier run of the same "
            "window; run a fresh audit (drop --resume) to start one."
        )
    try:
        commits = json.loads(commits_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(
            f"cannot resume: commits.json is unreadable ({e}); "
            "run a fresh audit (drop --resume)."
        )

    saved = commits.get("window") or {}
    requested = {
        "start_year": window.year,
        "start_month": window.month,
        "nb_months": window.nb_months,
    }
    if saved != requested:
        raise RuntimeError(
            "cannot resume: the artifacts under tmp/glev/ are for a different "
            f"window ({_fmt_window(saved)}) than requested "
            f"({_fmt_window(requested)}). Re-run --resume with the original "
            f"window (--start-year {saved.get('start_year')} "
            f"--start-month {saved.get('start_month')} "
            f"--nb-months {saved.get('nb_months')}), or run a fresh audit "
            "without --resume to overwrite them."
        )

    if not (commits.get("baseline") or {}).get("sha") or not isinstance(
        commits.get("months"), list
    ):
        raise RuntimeError(
            "cannot resume: commits.json is missing baseline/month data; "
            "run a fresh audit (drop --resume)."
        )
    return commits


def _run_resumed_audit(
    repo: Path, window: prep_mod.Window, *, refresh_rules: bool, use_cdn: bool
) -> Path:
    commits = _load_commits_for_resume(repo, window)
    months = commits["months"]
    total = len(months)
    baseline_sha = commits["baseline"]["sha"]
    baseline_short = baseline_sha[:8]

    # Decide up front what's already done vs. still needed.
    baseline_valid = scan_mod.scan_json_valid(paths.baseline_json(repo))
    month_valid = {
        entry["n"]: scan_mod.scan_json_valid(paths.month_json(repo, entry["n"]))
        for entry in months
    }
    scans_needed = (not baseline_valid) or not all(month_valid.values())
    cached = (1 if baseline_valid else 0) + sum(1 for v in month_valid.values() if v)
    remaining = (0 if baseline_valid else 1) + sum(
        1 for v in month_valid.values() if not v
    )
    _log(
        f"resume: {cached} cached scan(s), {remaining} to run "
        f"({_fmt_window(commits['window'])})"
    )

    wt = paths.worktree(repo)
    # Only touch rules / image / worktree if at least one scan remains -- the
    # aggregate + render path (all scans cached) needs none of them.
    if scans_needed:
        paths.ensure_tmp(repo)
        opengrep.fetch_rules(paths.rules_file(repo), force=refresh_rules)
        opengrep.ensure_image()
        if not gitops.worktree_exists(wt):
            gitops.ensure_worktree(repo, wt, baseline_sha)
            _log(f"worktree ready at {baseline_short}")
        _note_working_tree(repo)

    # Baseline
    if baseline_valid:
        _log("baseline: cached")
    else:
        # scan_baseline scans whatever HEAD the worktree is at, so pin it to
        # the baseline sha first (the interrupted run may have left it on a
        # later month's commit).
        gitops.checkout_in_worktree(wt, baseline_sha)
        _log(f"scanning baseline {baseline_short} (full tree, may take minutes)")
        baseline = scan_mod.scan_baseline(repo, commits)
        _log(f"baseline: {baseline.eligible} findings on {baseline.files} files")

    # Monthly scans
    for entry in months:
        n = entry["n"]
        label = f"{entry['year']}-{entry['month']:02d}"
        if month_valid[n]:
            _log(f"month {n}/{total} ({label}): cached")
            continue
        result = scan_mod.scan_month(repo, commits, n)
        _log(
            f"month {n}/{total} ({label}): "
            f"{result.eligible} findings on {result.files} changed files"
        )

    report_path = _aggregate_and_render(repo, total, use_cdn=use_cdn)
    _remove_worktree(repo)
    return report_path


def main() -> int:
    args = _parse_args()
    repo = args.repo.resolve()

    try:
        if not _run_preflight(repo):
            return 2
        if args.check_only:
            return 0

        window = _require_window_args(args)
        run = _run_resumed_audit if args.resume else _run_full_audit
        run(
            repo,
            window,
            refresh_rules=args.refresh_rules,
            use_cdn=args.cdn,
        )
        return 0
    except (ValueError, RuntimeError) as e:
        if args.debug:
            traceback.print_exc(file=sys.stderr)
        _log(f"failed: {e}")
        return 1
    except KeyboardInterrupt:
        _log("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
