"""Thin wrappers over git for the commit-history audit workflow."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path | None = None) -> str:
    try:
        out = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise GitError(
            f"git command failed: {' '.join(args)}\n{e.stderr.strip()}"
        ) from e
    return out.stdout.strip()


def repo_root(path: Path) -> Path:
    """Return the toplevel of the git repo containing `path`."""
    return Path(_run(["git", "-C", str(path), "rev-parse", "--show-toplevel"]))


def repo_name(repo: Path) -> str:
    return repo_root(repo).name


def resolve_commit_before(repo: Path, iso_date: str) -> str | None:
    """Last commit before midnight UTC of iso_date (a bare ``YYYY-MM-DD``).

    We pin an explicit instant (``<date>T00:00:00Z``) instead of passing the
    bare date to ``git log --before``. Git's approxidate fills a *date-only*
    ``--before`` with the current wall-clock **time of day**, so the month
    boundary -- and therefore which commit a month resolves to -- would depend
    on when the audit runs: a commit made at 15:57 on the boundary day counts
    as "before" it only when the audit runs after 15:57. Pinning midnight UTC
    makes resolution deterministic regardless of run time. Passing the first
    day of the next period gives the "last commit of the previous period".
    """
    out = _run(
        [
            "git",
            "-C",
            str(repo),
            "log",
            f"--before={iso_date}T00:00:00Z",
            "-n",
            "1",
            "--format=%H",
        ]
    )
    return out or None


def commit_date(repo: Path, sha: str) -> str:
    return _run(["git", "-C", str(repo), "show", "-s", "--format=%cI", sha])


def month_end_commit(repo: Path, year: int, month: int) -> str | None:
    """Last commit of (year, month) -- i.e., strictly before the 1st of the next month."""
    if month == 12:
        nxt = f"{year + 1}-01-01"
    else:
        nxt = f"{year}-{month + 1:02d}-01"
    return resolve_commit_before(repo, nxt)


def worktree_exists(worktree_path: Path) -> bool:
    return worktree_path.exists()


def ensure_worktree(repo: Path, worktree_path: Path, sha: str) -> None:
    """Create or refresh an isolated worktree at the given sha.

    The user's working tree is never touched. If a previous worktree exists at
    the same path, we forcefully remove and recreate it -- the audit owns this
    directory.
    """
    if worktree_path.exists():
        # `git worktree remove` is the supported way to clean up. --force
        # handles cases where the worktree has uncommitted changes (it
        # shouldn't, since we only ever check out detached HEADs there).
        try:
            _run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree_path),
                ]
            )
        except GitError:
            # Fallback: prune any stale worktree entries, then nuke the dir.
            _run(["git", "-C", str(repo), "worktree", "prune"])
            import shutil

            shutil.rmtree(worktree_path, ignore_errors=True)

    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            "git",
            "-C",
            str(repo),
            "worktree",
            "add",
            "--detach",
            str(worktree_path),
            sha,
        ]
    )


def checkout_in_worktree(worktree_path: Path, sha: str) -> None:
    _run(["git", "-C", str(worktree_path), "checkout", "--detach", sha])


def changed_files(repo: Path, sha_a: str, sha_b: str) -> list[str]:
    """Files touched between two commits, as repo-relative POSIX paths.

    `git diff --name-only A B` returns added/modified/deleted paths. We do
    not filter for existence here; callers that need to scan the file at
    sha_b should filter against the checked-out worktree.
    """
    out = _run(["git", "-C", str(repo), "diff", "--name-only", sha_a, sha_b])
    if not out:
        return []
    return [line for line in out.splitlines() if line.strip()]


def cleanup_worktree(repo: Path, worktree_path: Path) -> None:
    if not worktree_path.exists():
        return
    try:
        _run(
            [
                "git",
                "-C",
                str(repo),
                "worktree",
                "remove",
                "--force",
                str(worktree_path),
            ]
        )
    except GitError:
        import shutil

        shutil.rmtree(worktree_path, ignore_errors=True)
        _run(["git", "-C", str(repo), "worktree", "prune"])


def is_working_tree_dirty(repo: Path) -> bool:
    """Return True if there are uncommitted/unstaged changes (informational)."""
    try:
        out = _run(["git", "-C", str(repo), "status", "--porcelain"])
    except GitError:
        return False
    return bool(out)


def git_version() -> tuple[int, int, int] | None:
    """Parse `git --version` into a 3-tuple, or None if git is missing/odd.

    Handles vendor suffixes like Apple's `git version 2.39.5 (Apple Git-154)`.
    """
    try:
        raw = _run(["git", "--version"])
    except (GitError, FileNotFoundError):
        return None
    import re

    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", raw)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)
