#!/usr/bin/env bash
#
# glev-continuous-autofix — requirements preflight
#
# Verifies the host can run the skill end-to-end BEFORE any work starts, so the
# agent fails fast with an actionable message instead of part-way through.
#
# Checks (in order of likelihood to bite):
#   1. gh            — GitHub CLI installed
#   2. gh auth       — authenticated (the Actions-artifact read scope is checked
#                      lazily by fetch-artifacts.sh, which fails clearly if absent)
#   3. jq            — JSON processor (the parser depends on it)
#   4. git repo      — cwd is inside a git work tree (we edit files there)
#   5. unzip         — gh run download needs it to expand the artifact
#
# Exit: 0 = all hard requirements met. 1 = at least one hard requirement failed
# (details printed). Soft notes (e.g. cwd repo != PR repo) are warnings, not
# failures — the caller decides.
#
# Usage:
#   check-requirements.sh                 # generic preflight
#   check-requirements.sh <owner/repo>    # also warn if cwd's origin != that repo

set -uo pipefail

PASS="  \033[32m✓\033[0m"
FAIL="  \033[31m✗\033[0m"
WARN="  \033[33m!\033[0m"

expected_repo="${1:-}"
hard_fail=0

# %b interprets the \033 escapes in the colour vars; keeping the colour OUT of the
# format string avoids the printf-format-from-variable footgun (SC2059).
note_pass() { printf '%b %s\n' "$PASS" "$1"; }
note_fail() { printf '%b %s\n' "$FAIL" "$1"; hard_fail=1; }
note_warn() { printf '%b %s\n' "$WARN" "$1"; }

echo "glev-continuous-autofix — requirements check"
echo "---------------------------------------"

# 1. gh installed -----------------------------------------------------------
if command -v gh >/dev/null 2>&1; then
  note_pass "gh installed ($(gh --version | head -1))"
else
  note_fail "gh (GitHub CLI) not found — install: https://cli.github.com"
  # No point checking auth without the binary.
  echo "---------------------------------------"
  echo "RESULT: FAIL (install gh and re-run)"
  exit 1
fi

# 2. gh authenticated -------------------------------------------------------
if gh auth status >/dev/null 2>&1; then
  account="$(gh api user --jq .login 2>/dev/null || echo '?')"
  note_pass "gh authenticated (account: ${account})"
else
  note_fail "gh not authenticated — run: gh auth login"
fi

# 3. jq ---------------------------------------------------------------------
if command -v jq >/dev/null 2>&1; then
  note_pass "jq installed ($(jq --version))"
else
  note_fail "jq not found — install: https://jqlang.github.io/jq/"
fi

# 4. unzip ------------------------------------------------------------------
if command -v unzip >/dev/null 2>&1; then
  note_pass "unzip installed"
else
  note_fail "unzip not found — gh run download needs it to expand the artifact"
fi

# 5. inside a git work tree -------------------------------------------------
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  cwd_repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || echo '')"
  if [[ -n "$cwd_repo" ]]; then
    note_pass "inside a git repo (origin: ${cwd_repo})"
    if [[ -n "$expected_repo" && "$cwd_repo" != "$expected_repo" ]]; then
      note_warn "cwd repo ($cwd_repo) != target PR repo ($expected_repo)"
      note_warn "  → check out the PR branch in the right repo before applying fixes"
    fi
  else
    note_pass "inside a git repo (no GitHub origin resolved — local edits still work)"
  fi
else
  note_warn "not inside a git repo — fetching/inspecting still works, but you"
  note_warn "  cannot apply fixes until you check out the PR branch"
fi

echo "---------------------------------------"
if [[ "$hard_fail" -eq 0 ]]; then
  echo -e "RESULT: \033[32mOK\033[0m — all hard requirements met"
  exit 0
else
  echo -e "RESULT: \033[31mFAIL\033[0m — fix the ✗ items above and re-run"
  exit 1
fi
