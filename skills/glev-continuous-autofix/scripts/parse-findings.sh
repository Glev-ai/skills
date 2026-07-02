#!/usr/bin/env bash
#
# glev-continuous-autofix — normalise a Glev Continuous artifact bundle into one
# clean, machine-readable findings document.
#
# Two inputs inside the bundle, two fidelity tiers:
#   • glev-continuous-response.json          (ALWAYS) — .annotations[] is the
#       authoritative ACTIONABLE set: only EXPLOITABLE/undefined findings are
#       annotated, each with the verdict + CWE in .title and a full Suggested-fix
#       code block in .raw_details.
#   • glev-continuous-debug/agent-assessments.json  (only if GLEV_DEBUG was on) —
#       per-finding structured enrichment: clean exploitability enum, reason,
#       data_flow_diagram, involved files, and grouping_clues
#       (fix_approach / affected_component / fix_scope).
#
# The join key is the assessment's alert_id, whose tail is ":<path>:<line>", so
# it matches an annotation's path + start_line. When MULTIPLE findings sit on the
# same line (e.g. a command-injection AND a code-injection rule both firing on
# one statement), a path:line join is ambiguous — we DO NOT guess: the finding
# gets enrichment:null + enrichment_candidates[] so the agent disambiguates by
# CWE / sink described in each candidate's reason.
#
# Output (stdout, the only thing on stdout):
#   { summary: {counts, exit_code, has_debug, actionable},
#     findings: [ {path,start_line,end_line,level,verdict,cwes,title,message,
#                  suggested_fix, enrichment|enrichment_candidates} ],
#     assessments: [ normalised all-findings list when debug present, else [] ] }
#
# Usage:
#   parse-findings.sh <bundle-dir>             # emit the normalised JSON
#   parse-findings.sh <bundle-dir> --summary   # human table to stdout instead

set -euo pipefail

die() { printf 'glev-continuous-autofix: %s\n' "$*" >&2; exit 1; }

BUNDLE="${1:-}"
MODE="${2:-json}"
[[ -n "$BUNDLE" ]] || die "usage: parse-findings.sh <bundle-dir> [--summary]"
RESP="$BUNDLE/glev-continuous-response.json"
[[ -f "$RESP" ]] || die "no glev-continuous-response.json in $BUNDLE — is this a Continuous artifact?"

ASSESS="$BUNDLE/glev-continuous-debug/agent-assessments.json"
ASSESS_INPUT="$ASSESS"
[[ -f "$ASSESS" ]] || ASSESS_INPUT=/dev/null   # slurpfile of /dev/null → []

# --- jq program ------------------------------------------------------------
# The $-vars below (resp, assess, ex, a, c, aN, …) are jq variables, NOT shell
# expansions — the single quotes are intentional, so SC2016 is a false positive.
# shellcheck disable=SC2016
JQ_PROG='
  # All "CWE-NNN" tokens in a title, in order.
  def cwes($t): [$t | scan("CWE-[0-9]+")];
  # Verdict = the leading SCREAMING_CASE word (EXPLOITABLE / NOT_EXPLOITABLE / UNDEFINED).
  def verdict($t): ($t | [scan("^[A-Z_]+")] | .[0] // null);
  # Strip an "owner/repo:" prefix from a file path, leaving the editable repo-relative path.
  def strip_repo($f): if ($f | test("^[^:/]+/[^:/]+:")) then ($f | sub("^[^:]+:";"")) else $f end;
  # Parse the newline-delimited grouping_clues STRING into an object.
  def parse_clues($s):
    reduce (($s // "") | split("\n")[]) as $l ({};
      ($l | index(":")) as $i
      | if $i == null then .
        else . + { ($l[0:$i] | gsub("^ +| +$";"")): ($l[$i+1:] | gsub("^ +| +$";"")) }
        end);

  ($resp[0]) as $r
  | ($assess[0] // []) as $raw
  # Normalise every assessment (all findings, exploitable or not).
  | ([ $raw[]
       | .alert_id as $aid | .error as $err
       | (.assessment.exploitability) as $ex   # rich verdict object (nested one deeper)
       | (.assessment.remediation)    as $rem  # structured fix (null when not generated)
       | ($aid | split(":")) as $p
       | { alert_id: $aid,
           path: ($p[-2] // null),
           line: (($p[-1] // "") | tonumber? // null),
           exploitability: ($ex.exploitability),
           confidence: ($ex.confidence),
           likelihood: ($ex.likelihood),
           impact: ($ex.impact),
           reason: ($ex.reason),
           files: ([ $ex.files[]? | strip_repo(.) ] | unique),
           data_flow_diagram: ($ex.data_flow_diagram),
           clues: parse_clues($ex.grouping_clues),
           remediation: (if $rem == null then null else
             { title: $rem.title,
               vuln_type: ($rem.description.vuln_type // null),
               severity:  ($rem.description.severity // null),
               impacted_files: ([ ($rem.description.impacted_files // [])[] | strip_repo(.) ] | unique) }
             end),
           error: $err } ]) as $aN
  # Build the actionable findings list from annotations, enriched where unambiguous.
  | ([ ($r.annotations // [])[]
       | . as $a
       | { path, start_line, end_line,
           level: .annotation_level,
           verdict: verdict(.title),
           cwes: cwes(.title),
           title, message,
           suggested_fix: .raw_details }
       + ( [ $aN[] | select(.path == $a.path and .line == $a.start_line
                             and .error == null
                             and (.exploitability == "EXPLOITABLE" or .exploitability == "UNDEFINED")) ] as $c
           | if   ($c|length) == 1 then { enrichment: $c[0] }
             elif ($c|length) >  1 then { enrichment: null,
                                          enrichment_candidates: $c,
                                          enrich_note: "multiple findings on this line — disambiguate by CWE/sink in each candidate.reason" }
             else { enrichment: null } end ) ]) as $findings
  | { summary: { counts: ($r.counts // {}),
                 exit_code: ($r.exit_code // null),
                 has_debug: (($raw | length) > 0),
                 actionable: ($findings | length) },
      findings: $findings,
      assessments: $aN }
'

RESULT="$(jq -n --slurpfile resp "$RESP" --slurpfile assess "$ASSESS_INPUT" "$JQ_PROG")"

if [[ "$MODE" == "--summary" ]]; then
  jq -r '
    "Glev Continuous — \(.summary.counts.alerts_total // 0) alert(s), " +
    "\(.summary.counts.exploitable // 0) exploitable, " +
    "\(.summary.actionable) actionable (exit_code=\(.summary.exit_code))" +
    (if .summary.has_debug then "  [debug enrichment available]" else "  [no debug bundle — annotations only]" end),
    "",
    (.findings[]
      | "• [\(.verdict)] \(if (.cwes|length)>0 then (.cwes|join("/")) else "?" end)  \(.path):\(.start_line)"
      + (if .enrichment then "\n    scope: \(.enrichment.clues["fix_scope"] // "?")  →  \(.enrichment.clues["fix_approach"] // "?")"
         elif .enrichment_candidates then "\n    (\(.enrichment_candidates|length) findings on this line — see candidates)"
         else "" end))
  ' <<<"$RESULT"
else
  printf '%s\n' "$RESULT"
fi
