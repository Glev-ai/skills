"""Aggregate phase: dedup findings by fingerprint, build summary.json.

For each month in order, keep only findings whose fingerprint hasn't been
seen in the baseline or any earlier audited month. This produces the
"newly introduced this month" set. Multi-CWE findings list every CWE in
their row but count only under their first normalized CWE so aggregates
don't double-count.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
from collections import Counter
from pathlib import Path

from . import findings as fmod
from . import gitops, opengrep, paths


TOP_CWE_LIMIT = 10
_SEV_RANK = fmod.SEVERITY_RANK

CWE_REGISTRY_PATH = (
    Path(__file__).resolve().parents[2] / "assets" / "cwe-registry.csv"
)


def _load_cwe_registry() -> dict[str, str]:
    """Map 'CWE-NNN' -> display label (short_name, falling back to name).

    The registry is a bundled asset; a missing or unreadable file degrades
    to an empty map (the report then shows raw CWE ids).
    """
    labels: dict[str, str] = {}
    try:
        with CWE_REGISTRY_PATH.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                cid = (row.get("cwe_id") or "").strip().upper()
                if not cid:
                    continue
                label = (
                    (row.get("short_name") or "").strip()
                    or (row.get("name") or "").strip()
                )
                if label:
                    labels[cid] = label
    except OSError:
        pass
    return labels


def _load_findings(json_path: Path) -> list[fmod.Finding]:
    out: list[fmod.Finding] = []
    for raw in opengrep.load_results(json_path):
        f = fmod.from_raw(raw)
        if f is not None:
            out.append(f)
    return out


_primary_cwe = fmod.primary_cwe


def _count_changed_files(repo: Path, commits: dict, n: int) -> int:
    prev_sha = (
        commits["baseline"]["sha"]
        if n == 1
        else commits["months"][n - 2]["sha"]
    )
    month_sha = commits["months"][n - 1]["sha"]
    try:
        return len(gitops.changed_files(repo, prev_sha, month_sha))
    except gitops.GitError:
        return 0


def aggregate(repo: Path) -> dict:
    """Build and persist the summary, returning the dict for further use."""
    commits_path = paths.commits_json(repo)
    if not commits_path.exists():
        raise RuntimeError(
            f"{commits_path} not found -- the prepare step must run first"
        )
    commits = json.loads(commits_path.read_text())

    baseline_findings = _load_findings(paths.baseline_json(repo))
    # seen tracks every fingerprint (cross-month dedup is fingerprint-based and
    # must remember rules collapsed away below, or a rule firing alone in a
    # later month would resurface). The KPI count, though, is the collapsed set.
    seen: set[str] = {f.fingerprint for f in baseline_findings}
    baseline_count = len(fmod.collapse_redundant(baseline_findings))
    synthetic_count = sum(1 for f in baseline_findings if f.synthetic_fingerprint)

    months_summary: list[dict] = []
    cwe_running_total: Counter[str] = Counter()
    # Per-CWE severity split, so the CWE distribution chart can stack each
    # bar by severity instead of using a flat color.
    cwe_sev_running: dict[str, Counter[str]] = {}
    sev_running_total: Counter[str] = Counter()
    total_new = 0

    for entry in commits["months"]:
        n = entry["n"]
        all_month = _load_findings(paths.month_json(repo, n))
        new_month: list[fmod.Finding] = []
        for f in all_month:
            if f.fingerprint in seen:
                continue
            seen.add(f.fingerprint)
            new_month.append(f)

        # Count synthetic fingerprints on the fingerprint-deduped set (these
        # drove the dedup), then collapse redundant rules for what we emit.
        synthetic_count += sum(1 for f in new_month if f.synthetic_fingerprint)
        new_month = fmod.collapse_redundant(new_month)

        sev_counts = Counter(f.severity for f in new_month)
        cwe_counts = Counter(_primary_cwe(f) for f in new_month)
        cwe_running_total.update(cwe_counts)
        for f in new_month:
            cwe_sev_running.setdefault(_primary_cwe(f), Counter())[f.severity] += 1
        sev_running_total.update(sev_counts)
        total_new += len(new_month)

        new_month.sort(key=lambda f: (_SEV_RANK.get(f.severity, 99), f.path, f.line))

        months_summary.append(
            {
                "n": n,
                "year": entry["year"],
                "month": entry["month"],
                "label": f"{entry['year']}-{entry['month']:02d}",
                "commit": {"sha": entry["sha"], "date": entry["date"]},
                "files_changed": _count_changed_files(repo, commits, n),
                "new_findings_count": len(new_month),
                "counts_by_severity": dict(sev_counts),
                "counts_by_cwe": dict(cwe_counts),
                "findings": [f.to_dict() for f in new_month],
            }
        )

    SEV_KEYS = ("veryhigh", "medium", "low")

    def _sev_dict(counter: Counter) -> dict:
        return {s: counter[s] for s in SEV_KEYS if counter.get(s)}

    top_cwes = cwe_running_total.most_common(TOP_CWE_LIMIT)
    top_keys = {cwe for cwe, _ in top_cwes}
    by_cwe_top10 = [
        {
            "cwe": cwe,
            "count": count,
            "by_severity": _sev_dict(cwe_sev_running.get(cwe, Counter())),
        }
        for cwe, count in top_cwes
    ]
    tail_count = sum(c for cwe, c in cwe_running_total.items() if cwe not in top_keys)
    if tail_count:
        other_sev: Counter[str] = Counter()
        for cwe in cwe_running_total:
            if cwe not in top_keys:
                other_sev.update(cwe_sev_running.get(cwe, Counter()))
        by_cwe_top10.append(
            {"cwe": "Other", "count": tail_count, "by_severity": _sev_dict(other_sev)}
        )

    # Display labels for every CWE present in the report, so the renderer
    # never needs the full registry.
    registry = _load_cwe_registry()
    used_cwes: set[str] = set(cwe_running_total)
    for m in months_summary:
        for f in m["findings"]:
            used_cwes.update(f["cwes"])
    cwe_labels = {c: registry[c] for c in sorted(used_cwes) if c in registry}

    summary = {
        "repo_name": commits["repo_name"],
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "window": commits["window"],
        "baseline": {**commits["baseline"], "findings_count": baseline_count},
        "synthetic_fingerprint_count": synthetic_count,
        "cwe_labels": cwe_labels,
        "months": months_summary,
        "totals": {
            "new_findings": total_new,
            "by_severity": dict(sev_running_total),
            "by_cwe_top10": by_cwe_top10,
        },
    }
    paths.summary_json(repo).write_text(json.dumps(summary, indent=2))
    return summary
