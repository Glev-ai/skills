"""Prepare phase of the audit pipeline.

Resolves the baseline + monthly commits, downloads the opengrep rule pack,
ensures the docker image is available, and creates the isolated worktree at
the baseline commit. Pure functions only -- the orchestrator drives them.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path

from . import gitops, opengrep, paths


@dataclass
class Window:
    year: int
    month: int
    nb_months: int


def advance_month(year: int, month: int, delta: int) -> tuple[int, int]:
    """(year, month) plus delta months, handling rollover."""
    idx = (year * 12 + (month - 1)) + delta
    return idx // 12, (idx % 12) + 1


def validate_window(window: Window) -> None:
    if not (1 <= window.month <= 12):
        raise ValueError(f"start-month must be 1..12 (got {window.month})")
    if window.nb_months < 1:
        raise ValueError(f"nb-months must be >= 1 (got {window.nb_months})")
    today = dt.date.today()
    if window.year > today.year or (
        window.year == today.year and window.month > today.month
    ):
        raise ValueError(
            f"start date {window.year}-{window.month:02d} is in the future; "
            "pick a past month"
        )
    last_y, last_m = advance_month(window.year, window.month, window.nb_months - 1)
    if last_y > today.year or (last_y == today.year and last_m > today.month):
        raise ValueError(
            f"window extends past today ({last_y}-{last_m:02d}); reduce nb-months"
        )


def resolve_commits(repo: Path, window: Window) -> dict:
    """Resolve the baseline and one commit per audited month.

    Raises RuntimeError with a user-friendly message if the history doesn't
    cover the requested window.
    """
    boundary = f"{window.year}-{window.month:02d}-01"
    baseline_sha = gitops.resolve_commit_before(repo, boundary)
    if not baseline_sha:
        raise RuntimeError(
            f"no commits in {repo} before {boundary}; pick a later start month"
        )

    # Every audited month-end is after the baseline date, and the baseline
    # commit is guaranteed to exist (checked above), so month_end_commit always
    # resolves. A month with no commits of its own simply resolves to the prior
    # commit, yielding an empty diff downstream -- reported as 0, not an error.
    months: list[dict] = []
    for n in range(1, window.nb_months + 1):
        y, m = advance_month(window.year, window.month, n - 1)
        sha = gitops.month_end_commit(repo, y, m)
        months.append(
            {
                "n": n,
                "year": y,
                "month": m,
                "sha": sha,
                "date": gitops.commit_date(repo, sha),
            }
        )

    return {
        "repo_name": gitops.repo_name(repo),
        "window": {
            "start_year": window.year,
            "start_month": window.month,
            "nb_months": window.nb_months,
        },
        "baseline": {
            "sha": baseline_sha,
            "date": gitops.commit_date(repo, baseline_sha),
        },
        "months": months,
    }


def prepare(
    repo: Path,
    window: Window,
    *,
    refresh_rules: bool = False,
) -> dict:
    """Full prepare phase: validate, resolve, fetch rules, image, worktree.

    Returns the commits payload. Side effects:
      - writes tmp/glev/commits.json
      - ensures tmp/glev/rules/semgrep-rules.yaml is present
      - ensures the opengrep image is present (builds it on first run)
      - creates tmp/glev/worktree/ at the baseline commit
    """
    validate_window(window)

    commits_payload = resolve_commits(repo, window)

    paths.ensure_tmp(repo)
    paths.commits_json(repo).write_text(json.dumps(commits_payload, indent=2))

    opengrep.fetch_rules(paths.rules_file(repo), force=refresh_rules)
    opengrep.ensure_image()

    gitops.ensure_worktree(
        repo, paths.worktree(repo), commits_payload["baseline"]["sha"]
    )

    return commits_payload
