#!/usr/bin/env bash
#
# glev-continuous-autofix — resolve a PR reference to its Glev Continuous artifact
# and download it locally.
#
# The Glev Continuous workflow uploads ONE artifact per run, named
#   glev-continuous-<head_sha>
# (see the upload-artifact step: name: glev-continuous-${{ ... head.sha || github.sha }}).
# That makes resolution deterministic: get the PR's head SHA, the artifact name
# follows. During resolution we also fall back to a prefix scan of the head SHA's
# runs for repos whose workflow named the artifact differently; the download then
# uses the resolved artifact's exact name (no download-time retry).
#
# Output: a single-line JSON manifest on stdout (the ONLY thing on stdout — all
# progress goes to stderr) so the caller can `jq` it:
#   {repo, pr, state, branch, head_sha, run_id, artifact_name, expired,
#    out_dir, has_debug, has_report_md, counts, exit_code}
#
# Usage:
#   fetch-artifacts.sh <pr-ref> [-R owner/repo] [-o out-dir] [--run RUN_ID]
#
# <pr-ref> accepts:
#   123                                   (PR number; repo from cwd or -R)
#   owner/repo#123
#   https://github.com/owner/repo/pull/123
#
# Exit: 0 on success (manifest printed). 1 on any resolution/download failure
# (reason printed to stderr).

set -euo pipefail

log() { printf '%s\n' "$*" >&2; }
die() { printf 'glev-continuous-autofix: %s\n' "$*" >&2; exit 1; }

REPO=""
PR=""
OUT=""
RUN_ID=""

# --- Parse args ------------------------------------------------------------
REF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -R|--repo) REPO="$2"; shift 2 ;;
    -o|--out)  OUT="$2";  shift 2 ;;
    --run)     RUN_ID="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*)        die "unknown flag: $1" ;;
    *)         REF="$1"; shift ;;
  esac
done
[[ -n "$REF" ]] || die "missing <pr-ref>. Try: fetch-artifacts.sh 123  (or a PR URL)"

# --- Normalise the reference into REPO + PR --------------------------------
if [[ "$REF" =~ ^https?://github\.com/([^/]+/[^/]+)/pull/([0-9]+) ]]; then
  REPO="${REPO:-${BASH_REMATCH[1]}}"
  PR="${BASH_REMATCH[2]}"
elif [[ "$REF" =~ ^([^/]+/[^/#]+)#([0-9]+)$ ]]; then
  REPO="${REPO:-${BASH_REMATCH[1]}}"
  PR="${BASH_REMATCH[2]}"
elif [[ "$REF" =~ ^[0-9]+$ ]]; then
  PR="$REF"
else
  die "could not parse PR reference '$REF' (expected a number, owner/repo#N, or a PR URL)"
fi

# Repo from cwd if still unknown.
if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)" \
    || die "no -R given and cwd is not a GitHub repo — pass -R owner/repo"
fi

log "→ repo=$REPO pr=#$PR"

# --- Resolve the PR head SHA ----------------------------------------------
pr_json="$(gh pr view "$PR" -R "$REPO" \
  --json number,state,headRefName,headRefOid,url 2>/dev/null)" \
  || die "PR #$PR not found in $REPO (check the number and your access)"

HEAD_SHA="$(jq -r .headRefOid <<<"$pr_json")"
STATE="$(jq -r .state <<<"$pr_json")"
BRANCH="$(jq -r .headRefName <<<"$pr_json")"
[[ -n "$HEAD_SHA" && "$HEAD_SHA" != "null" ]] || die "could not resolve head SHA for PR #$PR"
log "→ head_sha=$HEAD_SHA branch=$BRANCH state=$STATE"
[[ "$STATE" == "OPEN" ]] || log "note: PR #$PR is $STATE — its head branch may be deleted; checking out $HEAD_SHA may need 'git fetch origin $HEAD_SHA'"

EXPECTED_NAME="glev-continuous-$HEAD_SHA"

# --- Find the artifact + its run ------------------------------------------
# Strategy:
#   a) if --run given, look only at that run's artifacts (prefix match);
#   b) else exact-name match across the repo's recent artifacts;
#   c) else prefix scan of runs for this head SHA.
# We need both the artifact's run id (to download) and its expiry flag.
artifact_row=""

pick_from_run() {  # <run-id> -> sets artifact_row (newest glev-continuous* on that run)
  gh api "repos/$REPO/actions/runs/$1/artifacts?per_page=100" \
    --jq '[.artifacts[] | select(.name | startswith("glev-continuous"))]
          | sort_by(.created_at) | reverse | .[0] // empty' 2>/dev/null
}

if [[ -n "$RUN_ID" ]]; then
  log "→ using provided run id $RUN_ID"
  artifact_row="$(pick_from_run "$RUN_ID")"
else
  # (b) exact name match — fast path, one API call.
  artifact_row="$(gh api "repos/$REPO/actions/artifacts?per_page=100" \
    --jq "[.artifacts[] | select(.name==\"$EXPECTED_NAME\")]
          | sort_by(.created_at) | reverse | .[0] // empty" 2>/dev/null || true)"

  # (c) fallback: scan runs for this head SHA, newest first.
  if [[ -z "$artifact_row" ]]; then
    log "→ no exact-name artifact; scanning runs for head SHA…"
    for rid in $(gh run list -R "$REPO" -c "$HEAD_SHA" -L 20 \
                   --json databaseId --jq '.[].databaseId' 2>/dev/null); do
      artifact_row="$(pick_from_run "$rid")"
      [[ -n "$artifact_row" ]] && break
    done
  fi
fi

[[ -n "$artifact_row" ]] || die \
"no Glev Continuous artifact found for PR #$PR (head $HEAD_SHA).
   Looked for an artifact named '$EXPECTED_NAME' (and any 'glev-continuous*').
   Likely causes:
     • the Continuous workflow has not run on this commit yet — push or re-run it;
     • the artifact has expired (default 90 days) — re-run the pipeline;
     • the workflow lives in a different repo — pass -R owner/repo."

RUN_ID="$(jq -r '.workflow_run.id' <<<"$artifact_row")"
ART_NAME="$(jq -r '.name' <<<"$artifact_row")"
EXPIRED="$(jq -r '.expired' <<<"$artifact_row")"
log "→ artifact='$ART_NAME' run_id=$RUN_ID expired=$EXPIRED"

# A null run id means the artifact isn't tied to a workflow run (can't download);
# guard here so the manifest's ($run_id|tonumber) can't abort AFTER a download.
[[ -n "$RUN_ID" && "$RUN_ID" != "null" ]] || die \
  "resolved artifact '$ART_NAME' has no associated workflow run — cannot download it."
# Warn (don't fail) if the resolved artifact isn't the one for this PR's head —
# e.g. when --run points at an older run. Findings would be for another commit.
[[ "$ART_NAME" == "$EXPECTED_NAME" ]] || log \
  "warning: artifact '$ART_NAME' != expected '$EXPECTED_NAME' — findings may be for a different commit"

[[ "$EXPIRED" == "true" ]] && die \
"artifact '$ART_NAME' has expired and can no longer be downloaded — re-run the Continuous pipeline on PR #$PR to regenerate it."

# --- Download -------------------------------------------------------------
if [[ -z "$OUT" ]]; then
  OUT="${TMPDIR:-/tmp}/glev-autofix-${PR}-${HEAD_SHA:0:8}"
fi
rm -rf "$OUT"; mkdir -p "$OUT"
log "→ downloading into $OUT"
gh run download "$RUN_ID" -R "$REPO" -n "$ART_NAME" -D "$OUT" \
  || die "gh run download failed for run $RUN_ID artifact '$ART_NAME'"

# --- Inspect what we got + emit the manifest ------------------------------
resp="$OUT/glev-continuous-response.json"
[[ -f "$resp" ]] || die "downloaded artifact has no glev-continuous-response.json — unexpected bundle shape"
jq empty "$resp" 2>/dev/null || die "glev-continuous-response.json is not valid JSON — corrupt artifact; re-run the pipeline"

has_debug=false
[[ -f "$OUT/glev-continuous-debug/agent-assessments.json" ]] && has_debug=true
has_report_md=false
[[ -f "$OUT/glev-continuous-report.md" ]] && has_report_md=true

counts="$(jq -c '.counts // {}' "$resp" 2>/dev/null || echo '{}')"
exit_code="$(jq -r '.exit_code // empty' "$resp" 2>/dev/null || echo '')"

log "→ has_debug=$has_debug counts=$counts exit_code=$exit_code"

jq -nc \
  --arg repo "$REPO" --arg pr "$PR" --arg state "$STATE" --arg branch "$BRANCH" \
  --arg head_sha "$HEAD_SHA" --arg run_id "$RUN_ID" --arg art "$ART_NAME" \
  --arg out "$OUT" --arg exit_code "$exit_code" \
  --argjson expired "${EXPIRED:-false}" \
  --argjson has_debug "$has_debug" --argjson has_report_md "$has_report_md" \
  --argjson counts "$counts" \
  '{repo:$repo, pr:($pr|tonumber), state:$state, branch:$branch,
    head_sha:$head_sha, run_id:($run_id|tonumber), artifact_name:$art,
    expired:$expired, out_dir:$out, has_debug:$has_debug,
    has_report_md:$has_report_md, counts:$counts,
    exit_code:(if $exit_code=="" then null else ($exit_code|tonumber) end)}'
