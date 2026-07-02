"""Pre-flight checks: confirm we can run before doing any expensive work.

Each check returns a status tuple so the caller can render a tidy report.
All hints are concrete remediation commands.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import gitops
from . import opengrep


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    hint: str = ""


def check_git_repo(repo: Path) -> CheckResult:
    try:
        root = gitops.repo_root(repo)
    except gitops.GitError as e:
        return CheckResult(
            "git repo",
            False,
            f"{repo} is not inside a git repo",
            hint=f"cd into a git repository (got: {e})",
        )
    return CheckResult("git repo", True, f"repo root: {root}")


def check_git_version() -> CheckResult:
    v = gitops.git_version()
    if v is None:
        return CheckResult(
            "git",
            False,
            "git not found or version unparseable",
            hint="install git >= 2.5 (https://git-scm.com/downloads)",
        )
    if v < (2, 5, 0):
        return CheckResult(
            "git",
            False,
            f"git {v[0]}.{v[1]}.{v[2]} is too old (need >= 2.5 for worktrees)",
            hint="upgrade git: https://git-scm.com/downloads",
        )
    return CheckResult("git", True, f"git {v[0]}.{v[1]}.{v[2]}")


def check_python_version() -> CheckResult:
    if sys.version_info < (3, 10):
        return CheckResult(
            "python",
            False,
            f"python {sys.version_info.major}.{sys.version_info.minor} is too old",
            hint="upgrade to python 3.10+",
        )
    return CheckResult(
        "python",
        True,
        f"python {sys.version_info.major}.{sys.version_info.minor}",
    )


def check_docker() -> CheckResult:
    if shutil.which("docker") is None:
        return CheckResult(
            "docker",
            False,
            "docker CLI not found on PATH",
            hint="install Docker Desktop: https://docs.docker.com/get-docker/",
        )
    try:
        subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return CheckResult(
            "docker",
            False,
            "docker daemon not reachable",
            hint=(
                "start Docker Desktop (macOS/Windows) or "
                "'sudo systemctl start docker' (Linux), then retry"
            ),
        )
    return CheckResult("docker", True, "docker daemon reachable")


def check_opengrep_image(image: str = opengrep.OPENGREP_IMAGE) -> CheckResult:
    if opengrep.image_present(image):
        return CheckResult("opengrep image", True, f"{image} already present locally")

    # Default image isn't cached: prepare.py will build it from the bundled
    # Dockerfile. That's expected on first run -- not a failure.
    if not opengrep.IS_USER_OVERRIDE and image == opengrep.DEFAULT_LOCAL_TAG:
        return CheckResult(
            "opengrep image",
            True,
            f"{image} will be built locally on first run (~30s)",
        )

    # User supplied an override; probe the registry so we fail here rather
    # than after the user has typed in audit inputs.
    if opengrep.manifest_accessible(image):
        return CheckResult(
            "opengrep image",
            True,
            f"{image} reachable; will be pulled on first scan",
        )
    return CheckResult(
        "opengrep image",
        False,
        f"{image} is not cached locally and the registry refused access",
        hint=(
            "Unset OPENGREP_IMAGE to fall back to the auto-built default, or "
            "point it at an accessible image:\n"
            "           unset OPENGREP_IMAGE                              # use auto-build\n"
            "           export OPENGREP_IMAGE=<your-image>:tag            # custom"
        ),
    )


def run_all_checks(repo: Path) -> list[CheckResult]:
    results = [
        check_python_version(),
        check_git_version(),
        check_git_repo(repo),
        check_docker(),
    ]
    # Only check the image if Docker is healthy; otherwise the inspect call
    # would emit confusing noise.
    if results[-1].ok:
        results.append(check_opengrep_image())
    return results


def render(results: list[CheckResult]) -> str:
    lines = []
    for r in results:
        mark = "OK " if r.ok else "FAIL"
        lines.append(f"  [{mark}] {r.name}: {r.detail}")
        if not r.ok and r.hint:
            lines.append(f"         hint: {r.hint}")
    return "\n".join(lines)


def all_ok(results: list[CheckResult]) -> bool:
    return all(r.ok for r in results)
