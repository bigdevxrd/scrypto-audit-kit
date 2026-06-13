#!/usr/bin/env bash
#
# scrypto-audit-kit — pre-audit harness for Scrypto blueprints
#
# Usage:
#   ./audit.sh [--model claude|deepseek|both] <path-to-scrypto-package>
#
# Example:
#   ./audit.sh /tmp/ignition/packages/simple-oracle
#   ./audit.sh --model both /path/to/your/scrypto/package
#   ./audit.sh --model deepseek ~/scrypto/my-vault
#
# What it does:
#   1. Validates the target is a scrypto package (has Cargo.toml + src/lib.rs)
#   2. Invokes aider non-interactively with:
#        - the audit prompt (prompts/audit.md) as the user message
#        - the checklist (prompts/checklist.md) and all references/*.md as --read context
#        - the package's source + tests as the editable files (read-only in practice; the
#          aider config disables auto-commits and the prompt forbids edits)
#   3. Writes the model's response to audit-reports/<repo>-<package>-<date>.md
#
# The kit does NOT edit blueprint source. Edits to audit-grade code go through a
# separate, human-driven session.

set -euo pipefail

# ---- API key sourcing -------------------------------------------------------
# Aider needs ANTHROPIC_API_KEY. We support three sources, in order:
#   1. Already exported in the calling shell (preferred for CI)
#   2. AIDER_ENV_FILE pointing at an env file to source
#   3. .env in the kit dir (aider auto-loads it from cwd anyway, but we source
#      it ourselves so this script can detect failure early)
# The key is never echoed.
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  if [[ -n "${AIDER_ENV_FILE:-}" && -f "$AIDER_ENV_FILE" ]]; then
    set -a; . "$AIDER_ENV_FILE"; set +a
  elif [[ -f "$(dirname "$0")/.env" ]]; then
    set -a; . "$(dirname "$0")/.env"; set +a
  fi
fi
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "error: ANTHROPIC_API_KEY not set." >&2
  echo "       Options:" >&2
  echo "         export ANTHROPIC_API_KEY=sk-ant-..." >&2
  echo "         AIDER_ENV_FILE=/path/to/.env ./audit.sh ..." >&2
  echo "         drop a .env file with ANTHROPIC_API_KEY=... in the kit dir" >&2
  exit 1
fi

# ---- arg parsing ------------------------------------------------------------
MODEL="claude"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      echo ""
      echo "Options:"
      echo "  --model <model>    claude (default), deepseek, or both"
      echo "                     both runs DeepSeek first (broad), then Claude"
      echo "                     (deep) and cross-references findings."
      exit 0
      ;;
    --model)
      shift; MODEL="$1"
      if [[ "$MODEL" != "claude" && "$MODEL" != "deepseek" && "$MODEL" != "both" ]]; then
        echo "error: --model must be claude, deepseek, or both" >&2; exit 1
      fi
      ;;
    *) break ;;
  esac
  shift
done
if [[ $# -lt 1 ]]; then
  echo "error: missing target path" >&2
  echo "usage: $0 [--model claude|deepseek|both] <path>" >&2
  exit 1
fi
TARGET="$1"
if [[ ! -d "$TARGET" ]]; then
  echo "error: target is not a directory: $TARGET" >&2
  exit 1
fi
TARGET="$(cd "$TARGET" && pwd)"

# ---- locate the kit (this script's dir) -------------------------------------
KIT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- validate scrypto package shape -----------------------------------------
if [[ ! -f "$TARGET/Cargo.toml" ]]; then
  echo "error: no Cargo.toml at $TARGET — not a scrypto package" >&2
  exit 1
fi
if [[ ! -f "$TARGET/src/lib.rs" ]]; then
  echo "error: no src/lib.rs at $TARGET — not a scrypto blueprint" >&2
  exit 1
fi

# ---- pre-flight: compile check ----------------------------------------------
# Bail early if the code doesn't compile — no point spending LLM time on
# broken code. Uses release wasm target to match actual deploy target.
echo "[pre-flight] cargo check (release wasm)..."
if ! cargo check --manifest-path "$TARGET/Cargo.toml" \
       --release --target wasm32-unknown-unknown 2>/dev/null; then
  echo "error: cargo check failed — fix compile errors before auditing." >&2
  echo "       Run: cd $TARGET && cargo check --release --target wasm32-unknown-unknown" >&2
  exit 1
fi
echo "[pre-flight] compile OK"
echo ""

# ---- derive a report name ---------------------------------------------------
PKG="$(basename "$TARGET")"
PARENT="$(basename "$(dirname "$TARGET")")"
# Look one more level up to find a meaningful repo name (skip generic dirs)
case "$PARENT" in
  scrypto|packages|blueprints|src)
    REPO="$(basename "$(dirname "$(dirname "$TARGET")")")"
    ;;
  *)
    REPO="$PARENT"
    ;;
esac
DATE="$(date +%Y-%m-%d)"
REPORT="$KIT_DIR/audit-reports/${REPO}-${PKG}-${DATE}.md"
mkdir -p "$KIT_DIR/audit-reports"

# ---- collect target files ---------------------------------------------------
# Everything under src/ and tests/ (.rs), plus Cargo.toml for dep awareness.
declare -a TARGET_FILES=()
TARGET_FILES+=("$TARGET/Cargo.toml")
while IFS= read -r f; do TARGET_FILES+=("$f"); done < <(find "$TARGET/src" -name "*.rs" -type f 2>/dev/null | sort)
if [[ -d "$TARGET/tests" ]]; then
  while IFS= read -r f; do TARGET_FILES+=("$f"); done < <(find "$TARGET/tests" -name "*.rs" -type f 2>/dev/null | sort)
fi

# ---- collect read-only reference files --------------------------------------
declare -a READ_FILES=()
READ_FILES+=("$KIT_DIR/prompts/checklist.md")
while IFS= read -r f; do READ_FILES+=("$f"); done < <(find "$KIT_DIR/references" -name "*.md" -type f 2>/dev/null | sort)

# ---- announce ---------------------------------------------------------------
echo "==> scrypto-audit-kit"
echo "    target:    $REPO / $PKG"
echo "    path:      $TARGET"
echo "    model:     $MODEL"
echo "    sources:   ${#TARGET_FILES[@]} files"
echo "    refs:      ${#READ_FILES[@]} files (read-only)"
echo "    report ->  $REPORT"
echo ""

# Aider flags:
#   --no-git, --no-auto-commits, --no-dirty-commits, --no-suggest-shell-commands
#   --no-show-model-warnings, --no-stream, --yes-always
#
# Build --read args (one per reference file)
READ_ARGS=()
for f in "${READ_FILES[@]}"; do READ_ARGS+=("--read" "$f"); done

cd "$KIT_DIR"

# ---- run_single: invoke aider with a given model and message file -----------
run_single() {
  local model="$1" msg_file="$2" out_file="$3" err_file="$4"
  aider \
    --no-git --no-auto-commits --no-dirty-commits \
    --no-suggest-shell-commands --no-show-model-warnings \
    --no-stream --yes-always \
    --model "$model" \
    --message-file "$msg_file" \
    "${READ_ARGS[@]}" \
    "${TARGET_FILES[@]}" \
    > "$out_file" 2> >(tee -a "$err_file" >&2)
  return $?
}

# ---- run --------------------------------------------------------------------
if [[ "$MODEL" == "both" ]]; then
  # Pass 1: DeepSeek — broad, cheap scan
  DEEPSEEK_REPORT="$REPORT.deepseek"
  echo "--- pass 1/2: DeepSeek (broad scan) ---"
  run_single "deepseek/deepseek-chat" "$KIT_DIR/prompts/audit.md" \
    "$DEEPSEEK_REPORT" "$REPORT.stderr"
  echo "--- pass 1 complete ---"

  # Extract findings section from DeepSeek output to use as context for Claude
  FINDINGS_ONLY="$REPORT.deepseek-findings"
  awk '/^### [0-9]\. Findings|^## [0-9]\. Findings|^## Findings/,/^## /' \
    "$DEEPSEEK_REPORT" 2>/dev/null | head -200 > "$FINDINGS_ONLY" || true
  if [[ ! -s "$FINDINGS_ONLY" ]]; then
    # Fallback: last 200 lines if we can't find the section
    tail -200 "$DEEPSEEK_REPORT" > "$FINDINGS_ONLY"
  fi

  # Pass 2: Claude — deep analysis with DeepSeek findings as context
  CLAUDE_REPORT="$REPORT.claude"
  echo "--- pass 2/2: Claude (deep analysis) ---"

  # Create a composite prompt: the base audit prompt plus DeepSeek findings
  COMPOSITE_PROMPT="$KIT_DIR/.prompt-composite-$$.md"
  cat "$KIT_DIR/prompts/audit.md" > "$COMPOSITE_PROMPT"
  cat >> "$COMPOSITE_PROMPT" << PROMPT

## Pre-scan findings (DeepSeek)

The following findings were produced by an automated pre-scan with DeepSeek.
Review each one critically:
- If you AGREE with the finding, include it in your report with its severity.
- If you DISAGREE (false positive), note that and explain why.
- If the pre-scan MISSED an issue, add it to your report.

\`\`\`
$(cat "$FINDINGS_ONLY")
\`\`\`

## Cross-reference instruction

In your report's summary, add a **Cross-reference** section that lists:
1. Findings both models agree on (HIGH confidence)
2. Findings only Claude flagged (MEDIUM)
3. Findings only DeepSeek flagged (LOW — likely false positives)

PROMPT

  run_single "anthropic/claude-sonnet-4-6" "$COMPOSITE_PROMPT" \
    "$CLAUDE_REPORT" "$REPORT.stderr"
  rm -f "$COMPOSITE_PROMPT" 2>/dev/null
  echo "--- pass 2 complete ---"

  # Merge: Claude report is the primary, prepend DeepSeek cross-ref summary
  {
    echo "# Audit Report: $REPO / $PKG (Cross-Model)"
    echo ""
    echo "## Cross-Model Summary"
    echo ""
    DEEPSEEK_FINDINGS=$(grep -cE '^\*\*[Ff]-[0-9]|^### |^#### ' "$DEEPSEEK_REPORT" 2>/dev/null || echo 0)
    CLAUDE_FINDINGS=$(grep -cE '^\*\*[Ff]-[0-9]|^### |^#### ' "$CLAUDE_REPORT" 2>/dev/null || echo 0)
    echo "- **DeepSeek** (pass 1 — broad): ~${DEEPSEEK_FINDINGS} potential findings"
    echo "- **Claude** (pass 2 — deep): detailed findings below"
    echo "- **Confidence**: issues flagged by both models are HIGH confidence"
    echo ""
    echo "---"
    echo ""
    cat "$CLAUDE_REPORT"
  } > "$REPORT"

  # Cleanup intermediate files
  rm -f "$DEEPSEEK_REPORT" "$CLAUDE_REPORT" "$FINDINGS_ONLY" 2>/dev/null

else
  # Single model run
  if [[ "$MODEL" == "deepseek" ]]; then
    AIDER_MODEL="deepseek/deepseek-chat"
  else
    AIDER_MODEL="anthropic/claude-sonnet-4-6"
  fi

  run_single "$AIDER_MODEL" "$KIT_DIR/prompts/audit.md" \
    "$REPORT.raw" "$REPORT.stderr" || {
    echo "==> aider exited non-zero — see $REPORT.stderr" >&2
    exit 1
  }

  # Strip aider's chrome to produce a clean report
  # Recognisable chrome lines start with a fixed banner or a file-add prompt.
  # Everything after the first valid markdown heading (## or ###) is kept.
  awk '
    /^##? / { found=1 }
    found { print }
  ' "$REPORT.raw" > "$REPORT" 2>/dev/null || cp "$REPORT.raw" "$REPORT"
  rm -f "$REPORT.raw" 2>/dev/null
fi

echo ""
echo "==> done. report: $REPORT"
echo "    (raw stderr: $REPORT.stderr)"
