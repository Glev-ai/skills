"""Centralized path constants for the glev-application-security-trend-report workspace.

Every artifact produced by the skill lives under <repo>/tmp/glev/. The skill
never writes anywhere else in the target repo. tmp/ is the conventional ignore
target so artifacts don't pollute commits.
"""

from __future__ import annotations

from pathlib import Path


def tmp_dir(repo: Path) -> Path:
    return Path(repo) / "tmp" / "glev"


def worktree(repo: Path) -> Path:
    return tmp_dir(repo) / "worktree"


def rules_dir(repo: Path) -> Path:
    return tmp_dir(repo) / "rules"


def rules_file(repo: Path) -> Path:
    return rules_dir(repo) / "semgrep-rules.yaml"


def chartjs_cache(repo: Path) -> Path:
    return rules_dir(repo) / "chart.umd.min.js"


def font_cache(repo: Path, weight: str) -> Path:
    return rules_dir(repo) / f"titillium-web-{weight}.woff2"


def commits_json(repo: Path) -> Path:
    return tmp_dir(repo) / "commits.json"


def baseline_json(repo: Path) -> Path:
    return tmp_dir(repo) / "baseline.json"


def month_json(repo: Path, n: int) -> Path:
    return tmp_dir(repo) / f"month-{n:02d}.json"


def summary_json(repo: Path) -> Path:
    return tmp_dir(repo) / "summary.json"


def report_html(repo: Path) -> Path:
    return tmp_dir(repo) / "report.html"


def ensure_tmp(repo: Path) -> Path:
    d = tmp_dir(repo)
    d.mkdir(parents=True, exist_ok=True)
    rules_dir(repo).mkdir(parents=True, exist_ok=True)
    return d
