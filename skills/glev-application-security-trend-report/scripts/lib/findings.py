"""Security-finding normalization for opengrep JSON output."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

SEVERITY_MAP = {
    "ERROR": "veryhigh",
    "WARNING": "medium",
    "INFO": "low",
}

CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def normalize_cwes(raw: Any) -> list[str]:
    """Return a deduped, order-preserving list of canonical 'CWE-NNN' strings.

    Opengrep rules embed CWE identifiers in many shapes: a bare string, a list
    of strings, or a descriptor like 'CWE-601 - open redirect'. We extract
    every match and normalize to uppercase.
    """
    items: list[str] = []
    if raw is None:
        return items
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = [str(x) for x in raw if x is not None]

    out: list[str] = []
    seen: set[str] = set()
    for s in items:
        for m in CWE_RE.findall(s):
            canon = m.upper()
            if canon not in seen:
                seen.add(canon)
                out.append(canon)
    return out


def severity_label(raw: Any) -> str:
    if not isinstance(raw, str):
        return "low"
    return SEVERITY_MAP.get(raw.strip().upper(), "low")


def is_security(metadata: dict | None) -> bool:
    """Return True when a finding is security-relevant.

    Keeps findings whose category is 'security' (case-insensitive), or that
    carry at least one CWE when no category is set. Findings tagged CWE-798
    are dropped.
    """
    if not metadata:
        return False
    cwe_raw = metadata.get("cwe")
    category = (metadata.get("category") or "").strip().lower()

    has_cwe = False
    contains_cwe_798 = False
    if isinstance(cwe_raw, str):
        v = cwe_raw.strip()
        has_cwe = bool(v)
        contains_cwe_798 = "cwe-798" in v.lower()
    elif isinstance(cwe_raw, list):
        has_cwe = len(cwe_raw) > 0
        contains_cwe_798 = any(
            isinstance(item, str) and "cwe-798" in item.lower() for item in cwe_raw
        )

    if contains_cwe_798:
        return False
    if category == "security":
        return True
    if category == "" and has_cwe:
        return True
    return False


def _synthetic_fingerprint(check_id: str, path: str, line: int, snippet: str) -> str:
    payload = f"{check_id}|{path}|{line}|{snippet}".encode("utf-8", errors="replace")
    return "synth_" + hashlib.sha1(payload).hexdigest()


def strip_container_prefix(path: str) -> str:
    """Make a scan path relative to the repo root.

    Scans run in Docker with the worktree mounted at /src, so opengrep
    reports '/src/<repo-relative-path>'. The /src prefix means nothing
    outside the container.
    """
    if path == "/src":
        return ""
    if path.startswith("/src/"):
        return path[len("/src/"):]
    return path


@dataclass
class Finding:
    fingerprint: str
    synthetic_fingerprint: bool
    check_id: str
    path: str
    line: int
    severity: str
    cwes: list[str]
    category: str
    owasp: list[str]
    message: str
    snippet: str

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "synthetic_fingerprint": self.synthetic_fingerprint,
            "check_id": self.check_id,
            "path": self.path,
            "line": self.line,
            "severity": self.severity,
            "cwes": list(self.cwes),
            "category": self.category,
            "owasp": list(self.owasp),
            "message": self.message,
            "snippet": self.snippet,
        }


# Severity ordering, most-severe first (lower rank = more severe). Shared by
# the within-scan collapse below and by aggregate's row sorting.
SEVERITY_RANK = {"veryhigh": 0, "medium": 1, "low": 2}


def primary_cwe(f: "Finding") -> str:
    """The CWE a finding is counted under: its first normalized CWE.

    Multi-CWE findings list every CWE but aggregate only under this one so
    distributions don't double-count.
    """
    return f.cwes[0] if f.cwes else "uncategorized"


def _collapse_key(f: "Finding") -> tuple[str, str, int]:
    """Identity used to collapse redundant rules: (CWE, path, line).

    Matches the standard Glev finding identity for SAST results: one issue per
    sink line. The first component is the finding's first CWE when present,
    else its rule id — so CWE-bearing rules key on the CWE while other rules
    key on the rule string.
    """
    key = f.cwes[0] if f.cwes else (f.check_id or "")
    return (key, f.path, f.line)


def collapse_redundant(items: list["Finding"]) -> list["Finding"]:
    """Drop redundant findings that flag the same issue at the same sink.

    Multiple opengrep rules frequently fire on one underlying problem at the
    same (CWE, file, line). We keep a single highest-severity representative
    per identity. Findings with a different CWE, or the same CWE on a
    different line, are preserved. First-seen order is kept for the survivors.
    """
    best: dict[tuple[str, str, int], Finding] = {}
    for f in items:
        key = _collapse_key(f)
        cur = best.get(key)
        if cur is None or SEVERITY_RANK.get(f.severity, 99) < SEVERITY_RANK.get(
            cur.severity, 99
        ):
            best[key] = f
    return list(best.values())


def _coerce_str_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(x) for x in raw if x is not None]
    return []


def from_raw(raw_result: dict) -> Finding | None:
    """Build a Finding from one entry of opengrep's `results` array.

    Returns None if the result fails the security filter or is malformed.
    """
    extra = raw_result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    if not is_security(metadata):
        return None

    check_id = str(raw_result.get("check_id") or "")
    path = strip_container_prefix(str(raw_result.get("path") or ""))
    start = raw_result.get("start") or {}
    line = int(start.get("line") or 0)
    snippet = str(extra.get("lines") or "")
    message = str(extra.get("message") or "")

    fingerprint = extra.get("fingerprint")
    synthetic = False
    if not fingerprint:
        fingerprint = _synthetic_fingerprint(check_id, path, line, snippet)
        synthetic = True

    return Finding(
        fingerprint=str(fingerprint),
        synthetic_fingerprint=synthetic,
        check_id=check_id,
        path=path,
        line=line,
        severity=severity_label(extra.get("severity")),
        cwes=normalize_cwes(metadata.get("cwe")),
        category=str(metadata.get("category") or "").strip().lower(),
        owasp=_coerce_str_list(metadata.get("owasp")),
        message=message,
        snippet=snippet,
    )
