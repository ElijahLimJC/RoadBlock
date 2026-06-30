#!/usr/bin/env bash
set -euo pipefail

INPUT=$(cat)

CMD=$(printf '%s' "$INPUT" | python3 -c 'import sys,json; print(json.loads(sys.stdin.read()).get("tool_input",{}).get("command",""))' 2>/dev/null || true)

[ -z "$CMD" ] && exit 0

CMD_LOWER=$(printf '%s' "$CMD" | tr '[:upper:]' '[:lower:]')

# Safe exceptions: rm -rf of build artifacts
if printf '%s' "$CMD" | grep -qE 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|--recursive\s+)' 2>/dev/null; then
  SAFE_ONLY=true
  RM_ARGS=$(printf '%s' "$CMD" | sed -E 's/.*rm\s+(-[a-zA-Z]+\s+)*//;s/--recursive\s*//')
  for target in $RM_ARGS; do
    case "$target" in
      */__pycache__|__pycache__|*/.pytest_cache|.pytest_cache|*/.hypothesis|.hypothesis|*/.mypy_cache|.mypy_cache|*/.ruff_cache|.ruff_cache) ;;
      -*) ;;
      *) SAFE_ONLY=false; break ;;
    esac
  done
  [ "$SAFE_ONLY" = true ] && exit 0
fi

WARN=""

printf '%s' "$CMD" | grep -qE 'rm\s+(-[a-zA-Z]*r|--recursive)' 2>/dev/null && WARN="BLOCKED: recursive delete (rm -r). Permanently removes files."
[ -z "$WARN" ] && printf '%s' "$CMD_LOWER" | grep -qE 'drop\s+(table|database)' 2>/dev/null && WARN="BLOCKED: SQL DROP detected."
[ -z "$WARN" ] && printf '%s' "$CMD_LOWER" | grep -qE '\btruncate\b' 2>/dev/null && WARN="BLOCKED: SQL TRUNCATE detected."
[ -z "$WARN" ] && printf '%s' "$CMD" | grep -qE 'git\s+push\s+.*(-f\b|--force)' 2>/dev/null && WARN="BLOCKED: git force-push rewrites remote history."
[ -z "$WARN" ] && printf '%s' "$CMD" | grep -qE 'git\s+reset\s+--hard' 2>/dev/null && WARN="BLOCKED: git reset --hard discards all uncommitted changes."
[ -z "$WARN" ] && printf '%s' "$CMD" | grep -qE 'git\s+(checkout|restore)\s+\.' 2>/dev/null && WARN="BLOCKED: discards all uncommitted changes in working tree."

if [ -n "$WARN" ]; then
  echo "[careful] $WARN Ask the user for explicit approval before retrying." >&2
  exit 2
fi

exit 0
