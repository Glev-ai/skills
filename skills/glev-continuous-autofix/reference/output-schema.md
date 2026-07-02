# Glev Continuous artifact — output schema

The skill consumes the artifact uploaded by the Glev Continuous CI workflow
(`actions/upload-artifact`, named `glev-continuous-<head_sha>`). This is the
exact shape, verified against a live run. **The default (non-debug) artifact is
fully sufficient** — debug only adds the `glev-continuous-debug/` folder.

## What's in the artifact

| File | Present when | Role for the skill |
|---|---|---|
| `glev-continuous-response.json` | **always** | primary source — verdict, counts, `annotations[]` (CWE + fix code) |
| `glev-continuous-report.html` | always (when rendered) | human report (not parsed) |
| `glev-continuous-report.md` | always (when rendered) | human report, GitHub-flavored, with mermaid data-flow (readable fallback) |
| `glev-continuous-debug/` | **only if `GLEV_DEBUG` set** | optional enrichment, see below |

A normal run therefore ships the first three files. Everything the skill needs to
fix a finding is in `glev-continuous-response.json`.

## `glev-continuous-response.json` (always)

```jsonc
{
  "title_md": "🛡️ Glev - Continuous - 6 alerts",
  "summary_md": "…",                 // compact markdown summary
  "text_md": "…",                    // longer markdown body
  "counts": {
    "alerts_total": 13,
    "exploitable": 6,                // ← the actionable count
    "undefined": 0,                  // verdict could not be determined
    "not_exploitable": 7,
    "skipped_by_dedup": 2,
    "failed": 0                      // assessments that errored (auth/LLM)
  },
  "exit_code": 1,                    // 0 = clean, 1 = exploitable/undefined present
  "annotations": [ /* see below — ONLY exploitable/undefined findings */ ],
  "artifact_html": "…",             // == report.html content
  "artifact_md": "…",               // == report.md content
  "debug": [ /* present ONLY when posted with ?debug=true (GLEV_DEBUG) */ ]
}
```

### `annotations[]` — the actionable set

Only **EXPLOITABLE** (and any **UNDEFINED**) findings are annotated.
NOT_EXPLOITABLE findings are never here. So `annotations` *is* the fix list.

```jsonc
{
  "path": "src/glev/glev.controller.ts",   // repo-relative, already editable
  "start_line": 87,
  "end_line": 88,
  "annotation_level": "failure",            // failure = exploitable
  "title": "EXPLOITABLE — CWE-22: Improper Limitation of a Pathname …",
  "message": "The variable `reportPath` originates from …",   // the reason
  "raw_details": "## EXPLOITABLE\n\n…reason…\n\n---\n\n## Suggested fix\n\n### Remediation\n\n```typescript\n…fix code…\n```\n\n**This fix must be validated by one of your engineers before being used in your code**"
}
```

Parse rules:
- **verdict** = leading SCREAMING_CASE word of `title` (`EXPLOITABLE` / `UNDEFINED`).
- **CWEs** = all `CWE-\d+` tokens in `title` (a finding may list several, e.g.
  `CWE-1357 / CWE-353`).
- **fix code** = `raw_details` — contains the full remediation prose **and** a
  fenced code block. This is present without debug.
- `path` is already repo-relative; edit it directly.

## `glev-continuous-debug/` (debug only — optional enrichment)

Created only when the workflow sets `GLEV_DEBUG`. Files: `agent-assessments.json`
(the one the skill reads), plus `scan.json`, `findings-mapped.json`,
`request.json`, `response.json`, `git-diff.patch`, `collector.log`, `meta.txt`.

### `agent-assessments.json` — one entry per finding (ALL findings, incl. not-exploitable)

```jsonc
{
  "alert_id": "<check_id>:<path>:<line>",   // e.g. "…detect-child-process:src/glev/glev.controller.ts:61"
  "assessment": {
    "alert_id": "…",
    "exploitability": {                      // ← NOTE: rich object nested HERE, one level deeper
      "exploitability": "EXPLOITABLE",       // the verdict string
      "likelihood": "HIGH", "impact": "HIGH", "confidence": "HIGH",
      "reason": "…",
      "files": [                             // ⚠ may be "owner/repo:path" prefixed — strip the prefix
        "Glev-ai/brokencrystals:src/glev/glev.controller.ts",
        "src/glev/glev.module.ts"
      ],
      "data_flow_diagram": "graph TB\n …mermaid…",
      "grouping_clues": "fix_approach: …\naffected_component: …\nfix_scope: single-file"  // ⚠ a STRING, newline+colon delimited
    },
    "remediation": {                         // null when not generated (e.g. not-exploitable)
      "title": "Fix Path Traversal in GlevDemoController",
      "description": {
        "repository": "brokencrystals",
        "vuln_type": "CWE-22 - Path Traversal",
        "severity": "Medium",
        "impacted_files": ["src/glev/glev.controller.ts"]
      },
      "content": "### Details…### Remediation…```typescript…```"   // == annotation raw_details
    }
  },
  "error": null                              // non-null if THIS finding's assessment failed
}
```

### Joining annotations ↔ assessments (debug only)

`alert_id` ends with `:<path>:<line>`, so an annotation at `path` + `start_line`
matches the assessment whose `alert_id` has that suffix. When **two findings sit
on the same line** the join is ambiguous — do **not** guess: surface both as
`enrichment_candidates[]` and disambiguate by `remediation.vuln_type` vs the
annotation's CWE. (`parse-findings.sh` does all of this.)

## Two gotchas the parser already handles

1. **`grouping_clues` is a string, not an object** — line-parse `key: value`.
2. **`files[]` paths may be `owner/repo:`-prefixed** — strip to repo-relative
   before editing. (`annotations[].path` is already clean — prefer it.)
