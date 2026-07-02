"""Docker-backed opengrep wrapper plus rule fetching.

We never assume opengrep is installed on the host. Every scan is a single
`docker run --rm` invocation against the official Opengrep image. Output is
written to a host-mounted file so the host process can read it back.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# OpenGrep doesn't publish an anonymously-pullable Docker image. Instead the
# project ships precompiled binaries on GitHub Releases. We build a minimal
# image locally that wraps the binary. The build is automatic at first run
# and takes ~30 s; the resulting image is cached locally.
OPENGREP_VERSION = "v1.16.5"
DEFAULT_LOCAL_TAG = f"glev-application-security-trend-report/opengrep:{OPENGREP_VERSION}"

_USER_OVERRIDE = os.environ.get("OPENGREP_IMAGE")
OPENGREP_IMAGE = _USER_OVERRIDE or DEFAULT_LOCAL_TAG
IS_USER_OVERRIDE = _USER_OVERRIDE is not None

# Path to the Dockerfile shipped with the skill (assets/opengrep.Dockerfile).
DOCKERFILE_PATH = (
    Path(__file__).resolve().parents[2] / "assets" / "opengrep.Dockerfile"
)

RULES_URL = "https://semgrep.dev/c/r/all"

# The opengrep binary we ship is `opengrep_manylinux_x86`, so the image is
# inherently linux/amd64. Stating it explicitly on every `docker run` keeps
# Docker quiet on ARM hosts ("requested image's platform ... does not match
# the detected host platform"), which would otherwise fire on every scan.
IMAGE_PLATFORM = "linux/amd64"

# Lines we never want to surface to the user: OpenGrep's terminal-tail "Ran X
# rules on Y files: Z findings." summary doesn't match the count the report
# will actually display (because we apply our own security filter on top).
# Suppressing it avoids two contradictory numbers in the trace. Keeping the
# rest of stderr -- progress bars, rule-loading errors -- intact.
_NOISY_STDERR_RES = [
    re.compile(r"^Ran \d+ rules on \d+ files?: \d+ findings?\.?\s*$"),
]


def _pump_filtered_stderr(stream) -> None:
    """Forward `stream` to our stderr, dropping known-noisy summary lines."""
    try:
        for raw in iter(stream.readline, b""):
            try:
                line = raw.decode("utf-8", errors="replace")
            except Exception:
                line = str(raw)
            if any(rx.match(line) for rx in _NOISY_STDERR_RES):
                continue
            sys.stderr.write(line)
            sys.stderr.flush()
    finally:
        try:
            stream.close()
        except Exception:
            pass


class OpengrepError(RuntimeError):
    pass


# ----------------------------------------------------------------------------
# Rule cache

def fetch_rules(rules_file: Path, force: bool = False) -> None:
    """Download the semgrep registry to `rules_file` (idempotent).

    The downloaded file is a single YAML containing every public rule.
    """
    if rules_file.exists() and not force:
        return
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["curl", "-fL", "--retry", "2", "-o", str(rules_file), RULES_URL]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise OpengrepError(
            f"failed to download opengrep rules from {RULES_URL}: exit {e.returncode}"
        ) from e
    if not rules_file.exists() or rules_file.stat().st_size == 0:
        raise OpengrepError(
            f"rules download produced an empty file at {rules_file}"
        )


# ----------------------------------------------------------------------------
# Image management

def image_present(image: str = OPENGREP_IMAGE) -> bool:
    try:
        subprocess.run(
            ["docker", "image", "inspect", image],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def manifest_accessible(image: str = OPENGREP_IMAGE) -> bool:
    """Cheap registry probe -- no actual pull, just a manifest HEAD-equivalent.

    Useful at pre-flight: if the image isn't cached locally and the registry
    refuses anonymous access (which is what would break us at first scan), we
    want to surface that *before* the user provides audit inputs.
    """
    try:
        subprocess.run(
            ["docker", "manifest", "inspect", image],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def _build_default_image(image: str) -> None:
    """Build the bundled minimal opengrep image.

    The Dockerfile in assets/ doesn't COPY anything from the context, so we
    feed it via stdin (`docker build -`) and avoid sending a real build
    context. Streams build output so the user sees progress.
    """
    if not DOCKERFILE_PATH.exists():
        raise OpengrepError(
            f"bundled Dockerfile missing at {DOCKERFILE_PATH}; "
            "skill installation may be incomplete"
        )
    print(
        f"[opengrep] building {image} from {DOCKERFILE_PATH.name} "
        f"(first-run setup, ~30s) ...",
        file=sys.stderr,
        flush=True,
    )
    cmd = [
        "docker", "build",
        "--build-arg", f"OPENGREP_VERSION={OPENGREP_VERSION}",
        "-t", image,
        "-",
    ]
    with DOCKERFILE_PATH.open("rb") as f:
        proc = subprocess.run(cmd, stdin=f)
    if proc.returncode != 0:
        raise OpengrepError(
            f"docker build of {image} failed (exit {proc.returncode}). "
            "Check the build output above. Common causes: no network access "
            "(needed to fetch the opengrep binary from GitHub Releases) or a "
            "restricted Docker daemon."
        )


def _pull_user_image(image: str) -> None:
    print(f"[opengrep] pulling {image} ...", file=sys.stderr, flush=True)
    try:
        subprocess.run(["docker", "pull", image], check=True)
    except subprocess.CalledProcessError as e:
        raise OpengrepError(
            f"docker pull {image} failed (exit {e.returncode}).\n"
            "The image you set via OPENGREP_IMAGE is not reachable. "
            "Unset OPENGREP_IMAGE to fall back to the auto-built default, or "
            "point it at an accessible image."
        ) from e


def ensure_image(image: str = OPENGREP_IMAGE) -> None:
    """Ensure `image` is available locally, building or pulling as needed.

    Two paths:
      - default image (no OPENGREP_IMAGE override): build it from the bundled
        Dockerfile if missing.
      - user-supplied override: assume it's an externally-published image
        and try to pull it.
    """
    if image_present(image):
        return
    if not IS_USER_OVERRIDE and image == DEFAULT_LOCAL_TAG:
        _build_default_image(image)
    else:
        _pull_user_image(image)


# ----------------------------------------------------------------------------
# Scan invocation

def _user_flag() -> list[str]:
    """Return ['--user', 'UID:GID'] on POSIX so output files are host-owned.

    On Windows / non-POSIX hosts `os.getuid` doesn't exist; let Docker run as
    its default user there.
    """
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        return ["--user", f"{os.getuid()}:{os.getgid()}"]
    return []


def output_valid(json_path: Path) -> bool:
    """True if `json_path` is a complete opengrep scan output.

    Opengrep writes its ``-o`` JSON in one shot at the very end of a scan, so a
    file that exists, is non-empty, parses as JSON, and has the expected shape
    (an object with a ``results`` list) means the scan ran to completion --
    *even if opengrep's exit code was non-zero*. Opengrep exits 2 merely when
    some rule or target fails to parse (e.g. a malformed rule in the public
    pack) while still producing a full, usable result set. A missing, empty, or
    truncated file means the scan did not finish.

    This is the single completeness check used both to accept a fresh scan
    (below) and to decide whether ``--resume`` can reuse a cached scan
    (``scan.scan_json_valid`` delegates here), so the two always agree.
    """
    try:
        text = json_path.read_text()
    except OSError:
        return False
    if not text.strip():
        return False
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(data, dict) and isinstance(data.get("results"), list)


def _docker_run(
    *,
    worktree_path: Path,
    rules_dir: Path,
    out_path: Path,
    container_paths: list[str],
    image: str = OPENGREP_IMAGE,
) -> None:
    """Execute opengrep inside a one-shot container.

    Mounts:
      - worktree -> /src  (read-only)
      - rules_dir -> /rules (read-only)
      - out_path's parent -> /out (read/write, so opengrep can write the JSON)

    `container_paths` is a list of paths relative to /src; an empty list means
    "scan everything under /src" (a full scan).
    """
    out_dir = out_path.parent.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_basename = out_path.name
    container_out = f"/out/{out_basename}"

    # Incremental month scans pass ONLY the changed files. A newly-introduced
    # finding necessarily lives in a file that changed; findings in unchanged
    # files were already captured at the baseline or an earlier month and get
    # dropped by fingerprint dedup, so scanning just the changed paths yields
    # the same "newly introduced" set as a full-tree scan at a fraction of the
    # cost. An empty list means "scan everything under /src" (the baseline).
    # (Appending "/src" here would silently rescan the whole tree every month.)
    targets = container_paths if container_paths else ["/src"]

    # HOME=/tmp gives the non-root --user a writable cache dir. Without it,
    # opengrep tries to write /.cache/opengrep/... (HOME isn't set inside the
    # container under `--user UID:GID`), fails, and the whole scan errors out
    # -- forcing the rootful retry below to do the work a second time.
    base_args = [
        "docker",
        "run",
        "--rm",
        f"--platform={IMAGE_PLATFORM}",
        "-e",
        "HOME=/tmp",
        "-v",
        f"{worktree_path.resolve()}:/src:ro",
        "-v",
        f"{rules_dir.resolve()}:/rules:ro",
        "-v",
        f"{out_dir}:/out",
        "-w",
        "/src",
    ]
    scan_args = [
        image,
        "scan",
        "--json",
        "--use-git-ignore",
        # Per-rule, per-file time budget in seconds (opengrep default is 5s).
        # At 5s, heavy/generated files and catastrophic-regex rules time out,
        # which silently drops those rules' findings from the scan and makes
        # results non-deterministic (a rule that times out on one run may not
        # on the next). 60s lets those rules finish, so scans are reproducible
        # and complete; a file that still exceeds the budget is bounded rather
        # than hanging forever.
        "--timeout",
        "60",
        "-o",
        container_out,
        "--config=/rules",
        *targets,
    ]

    cmd = base_args + _user_flag() + scan_args
    rc = _run_with_filtered_stderr(cmd)

    # The exit code alone doesn't signal failure: opengrep exits non-zero (2)
    # whenever a rule or target fails to parse -- e.g. a malformed rule shipped
    # in the public pack -- while still writing a full, valid JSON result set.
    # So accept the run whenever it produced valid output, regardless of the
    # exit code. This is what keeps a single unparseable pack rule from failing
    # the whole audit (it bites small scans in particular, where opengrep does
    # surface such errors as exit 2).
    if output_valid(out_path):
        if rc != 0:
            print(
                f"[opengrep] note: scan exited {rc} (a rule or target failed to "
                "parse) but produced valid output; continuing.",
                file=sys.stderr,
                flush=True,
            )
        return

    # No usable output. The likeliest cause is a Docker Desktop setup that
    # refuses bind-mount writes under `--user`; retry rootful and chown the
    # result back. With HOME=/tmp above, this path is rarely taken.
    retry_cmd = base_args + scan_args
    rc2 = _run_with_filtered_stderr(retry_cmd)
    if output_valid(out_path):
        if hasattr(os, "getuid"):
            try:
                os.chown(out_path, os.getuid(), os.getgid())
            except (PermissionError, FileNotFoundError, OSError):
                pass
        if rc2 != 0:
            print(
                f"[opengrep] note: scan exited {rc2} but produced valid output; "
                "continuing.",
                file=sys.stderr,
                flush=True,
            )
        return

    raise OpengrepError(
        f"opengrep scan failed (exit {rc2}) with no valid output; "
        f"command: {' '.join(retry_cmd)}"
    )


def _run_with_filtered_stderr(cmd: list[str]) -> int:
    """Run `cmd` streaming stderr through the noisy-line filter. Returns rc."""
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    pump = threading.Thread(
        target=_pump_filtered_stderr, args=(proc.stderr,), daemon=True
    )
    pump.start()
    rc = proc.wait()
    pump.join()
    return rc


def run_full(worktree_path: Path, rules_dir: Path, out_path: Path) -> None:
    """Full-tree scan at the worktree's currently-checked-out commit."""
    _docker_run(
        worktree_path=worktree_path,
        rules_dir=rules_dir,
        out_path=out_path,
        container_paths=[],
    )


def run_incremental(
    worktree_path: Path,
    rules_dir: Path,
    out_path: Path,
    paths: list[str],
) -> None:
    """Scan only `paths` (repo-relative) inside the worktree.

    Empty paths means "no files changed" -- we write an empty result instead
    of invoking opengrep (which would scan everything if given no targets).
    """
    if not paths:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({"results": []}))
        return

    # All paths should already be repo-relative POSIX strings (git emits them
    # that way). They are valid under /src in the container.
    container_paths = [f"/src/{p}" for p in paths if not p.startswith("/")]
    _docker_run(
        worktree_path=worktree_path,
        rules_dir=rules_dir,
        out_path=out_path,
        container_paths=container_paths,
    )


def filter_existing(worktree_path: Path, paths: list[str]) -> list[str]:
    """Drop paths that were deleted between commits -- nothing to scan there."""
    out: list[str] = []
    wt = worktree_path.resolve()
    for p in paths:
        if (wt / p).exists():
            out.append(p)
    return out


# ----------------------------------------------------------------------------
# Result loading

def load_results(json_path: Path) -> list[dict]:
    if not json_path.exists():
        return []
    try:
        data = json.loads(json_path.read_text())
    except json.JSONDecodeError:
        return []
    results = data.get("results")
    if isinstance(results, list):
        return results
    return []
