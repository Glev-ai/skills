"""Scan phase: run opengrep at the baseline and at each month-end commit.

Pure functions. Each scan writes its JSON output under tmp/glev/ and returns
a (eligible_findings_count, scanned_files_count) tuple so the orchestrator
can log a single clean line per step.

`eligible_findings_count` is the number of findings that pass the security
filter (findings.from_raw) *after* collapsing redundant rules at the same
(CWE, file, line) -- the same per-scan count the report shows. The per-month
report count can be lower still, since aggregate additionally drops findings
already seen in earlier months (fingerprint dedup).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import findings as fmod
from . import gitops, opengrep, paths


@dataclass
class ScanResult:
    eligible: int  # findings that pass the security filter
    files: int  # files actually scanned (baseline: full tree; month: changed files)


def _count_eligible(out_path: Path) -> int:
    """Count findings that survive the security filter and the within-scan
    collapse of redundant rules at the same (CWE, file, line).

    This matches what the report shows for this scan; the per-month report
    count can be lower still, since aggregate additionally drops findings
    already seen in earlier months.
    """
    eligible = [
        f
        for f in (fmod.from_raw(raw) for raw in opengrep.load_results(out_path))
        if f is not None
    ]
    return len(fmod.collapse_redundant(eligible))


def _scanned_files_from_json(out_path: Path) -> int:
    """OpenGrep records the list of paths it scanned at .paths.scanned."""
    try:
        data = json.loads(out_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    p = data.get("paths") or {}
    scanned = p.get("scanned")
    if isinstance(scanned, list):
        return len(scanned)
    return 0


def scan_json_valid(out_path: Path) -> bool:
    """True when `out_path` is a complete, reusable opengrep scan output.

    Used by ``run_audit --resume`` to decide whether a per-scan JSON already on
    disk can be reused as-is or must be rescanned. Delegates to
    ``opengrep.output_valid`` -- the very same completeness check the scanner
    uses to accept a run whose exit code was non-zero but whose JSON is intact
    -- so "resumable" and "accepted when produced" always mean the same thing.

    A missing, empty, truncated, or structurally-wrong file is treated as "not
    scanned yet" and rescanned. OpenGrep writes its JSON in one shot at the end
    of a scan, so a run killed mid-scan leaves no parseable file; the mere
    presence of a valid file therefore means that scan finished. An
    empty-but-complete scan (``{"results": []}``, e.g. a month with no changed
    files) is intentionally valid -- rescanning it is a no-op.
    """
    return opengrep.output_valid(out_path)


def scan_baseline(repo: Path, commits: dict) -> ScanResult:
    """Full opengrep scan at the baseline commit. Worktree must be at baseline."""
    out_path = paths.baseline_json(repo)
    opengrep.run_full(
        worktree_path=paths.worktree(repo),
        rules_dir=paths.rules_dir(repo),
        out_path=out_path,
    )
    return ScanResult(
        eligible=_count_eligible(out_path),
        files=_scanned_files_from_json(out_path),
    )


def scan_month(repo: Path, commits: dict, n: int) -> ScanResult:
    """Incremental scan of month N. Returns counts that match the report."""
    months = commits["months"]
    if not (1 <= n <= len(months)):
        raise ValueError(f"month index {n} out of range (window has {len(months)})")

    month = months[n - 1]
    prev_sha = commits["baseline"]["sha"] if n == 1 else months[n - 2]["sha"]
    month_sha = month["sha"]

    changed = gitops.changed_files(repo, prev_sha, month_sha)
    gitops.checkout_in_worktree(paths.worktree(repo), month_sha)
    existing = opengrep.filter_existing(paths.worktree(repo), changed)

    out_path = paths.month_json(repo, n)
    opengrep.run_incremental(
        worktree_path=paths.worktree(repo),
        rules_dir=paths.rules_dir(repo),
        out_path=out_path,
        paths=existing,
    )
    return ScanResult(
        eligible=_count_eligible(out_path),
        files=len(existing),
    )
