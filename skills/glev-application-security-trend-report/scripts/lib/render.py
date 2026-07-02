"""Render the static HTML report from summary.json.

Output is a single self-contained file with Chart.js and the Titillium Web
brand font inlined so the report can be opened and shared without internet
access. Both are cached after the first download.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

from . import paths


CHARTJS_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"

# Titillium Web (Glev brand font), latin subset, served by Google Fonts.
FONT_WEIGHTS = {
    "400": "https://fonts.gstatic.com/s/titilliumweb/v19/NaPecZTIAOhVxoMyOr9n_E7fdMPmDaZRbrw.woff2",
    "600": "https://fonts.gstatic.com/s/titilliumweb/v19/NaPDcZTIAOhVxoMyOr9n_E7ffBzCGItzY5abuWI.woff2",
    "700": "https://fonts.gstatic.com/s/titilliumweb/v19/NaPDcZTIAOhVxoMyOr9n_E7ffHjDGItzY5abuWI.woff2",
}

FONT_CDN_TAG = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
    '<link href="https://fonts.googleapis.com/css2'
    '?family=Titillium+Web:wght@400;600;700&display=swap" rel="stylesheet">'
)

TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2] / "assets" / "report_template.html"
)


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["curl", "-fL", "--retry", "2", "-o", str(dest), url],
        check=True,
        capture_output=True,
    )


def _load_chartjs(repo: Path) -> str:
    cache = paths.chartjs_cache(repo)
    if not cache.exists():
        try:
            _download(CHARTJS_URL, cache)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"failed to download Chart.js from {CHARTJS_URL}: exit {e.returncode}. "
                "Use --cdn to reference it from the CDN instead."
            ) from e
    return cache.read_text(encoding="utf-8")


def _load_font_css(repo: Path) -> str:
    """Inline @font-face rules with base64 woff2 (~50 KB for 3 weights).

    Falls back to the Google Fonts <link> tags if a download fails -- the
    report still renders (system sans fallback when offline), it just isn't
    fully self-contained.
    """
    faces = []
    for weight, url in FONT_WEIGHTS.items():
        cache = paths.font_cache(repo, weight)
        if not cache.exists():
            try:
                _download(url, cache)
            except subprocess.CalledProcessError:
                print(
                    "[audit] note: could not download Titillium Web "
                    f"(weight {weight}); the report will reference Google "
                    "Fonts instead of embedding the font",
                    file=sys.stderr,
                    flush=True,
                )
                return FONT_CDN_TAG
        b64 = base64.b64encode(cache.read_bytes()).decode("ascii")
        faces.append(
            "@font-face{font-family:'Titillium Web';font-style:normal;"
            f"font-weight:{weight};"
            f"src:url(data:font/woff2;base64,{b64}) format('woff2');}}"
        )
    return "<style>\n" + "\n".join(faces) + "\n</style>"


def render(repo: Path, *, use_cdn: bool = False) -> Path:
    """Build report.html from summary.json. Returns the output path."""
    summary_path = paths.summary_json(repo)
    if not summary_path.exists():
        raise RuntimeError(
            f"{summary_path} not found -- the aggregate step must run first"
        )
    summary = json.loads(summary_path.read_text())

    if not TEMPLATE_PATH.exists():
        raise RuntimeError(f"template not found at {TEMPLATE_PATH}")
    html = TEMPLATE_PATH.read_text(encoding="utf-8")

    if use_cdn:
        chartjs_tag = f'<script src="{CHARTJS_URL}"></script>'
        font_css = FONT_CDN_TAG
    else:
        chartjs_code = _load_chartjs(repo)
        chartjs_tag = "<script>\n" + chartjs_code + "\n</script>"
        font_css = _load_font_css(repo)

    summary_literal = json.dumps(summary).replace("</", "<\\/")

    rendered = html.replace("__CHARTJS__", chartjs_tag)
    rendered = rendered.replace("__FONT_CSS__", font_css)
    rendered = rendered.replace("__SUMMARY_JSON__", summary_literal)

    out_path = paths.report_html(repo)
    out_path.write_text(rendered, encoding="utf-8")
    return out_path
