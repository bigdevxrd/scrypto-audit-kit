#!/usr/bin/env bash
#
# scrypto-audit-kit — pre-audit harness for Scrypto blueprints
#
# Usage:
#   ./audit.sh [--model claude|deepseek|both] [--static-only] [--no-static] <package>
#
# Example:
#   ./audit.sh /tmp/ignition/packages/simple-oracle
#   ./audit.sh --static-only ~/scrypto/my-vault        # free, no API key, deterministic
#   ./audit.sh --model both /path/to/your/scrypto/package
#
# What it does:
#   1. Validates the target is a scrypto package (has Cargo.toml + src/lib.rs)
#   2. Runs the LLM pass through an interchangeable BACKEND (see docs/backends.md):
#        - claude-api (default): the Anthropic SDK directly (bin/llm_audit.py), no aider
#        - aider:                the aider harness (keeps --model deepseek|both)
#        - cmd:                  a bring-your-own command (--backend-cmd), for your own agents
#      Every backend is fed the same inputs — the audit prompt (prompts/audit.md), the
#      checklist + all references/*.md as read-only context, and the package source — and
#      returns a markdown findings report ending in the nonce-stamped §7 JSON appendix.
#   3. Writes the model's response to audit-reports/<repo>-<package>-<date>.md
#
# The kit does NOT edit blueprint source. Edits to audit-grade code go through a
# separate, human-driven session.

set -euo pipefail

# ---- arg parsing ------------------------------------------------------------
MODEL="claude"
BACKEND_FLAG=""       # --backend; falls back to $SAK_BACKEND, then the default (claude-api)
BACKEND_CMD_FLAG=""   # --backend-cmd; falls back to $SAK_BACKEND_CMD (only for --backend cmd)
# Compile-check is OFF by default: `cargo check` compiles the TARGET, executing its build.rs
# and proc-macros on this host — arbitrary code from a blueprint you may not trust. Opt in with
# --compile-check only for code you would run anyway (and see the sandbox note at the pre-flight).
COMPILE_CHECK=0
STATIC_ONLY=0
NO_STATIC=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
      echo ""
      echo "Options:"
      echo "  --backend <name>     LLM engine: claude-api (default), aider, or cmd."
      echo "                       Env: SAK_BACKEND. See docs/backends.md."
      echo "  --backend-cmd '<..>'  the command to run for --backend cmd (env: SAK_BACKEND_CMD)"
      echo "  --model <model>      claude (default) or an explicit model id for the backend."
      echo "                       For --backend aider: also deepseek or both (both runs"
      echo "                       DeepSeek broad then Claude deep; these imply --backend aider)."
      echo "  --compile-check      run the cargo wasm pre-flight (OFF by default — it"
      echo "                       COMPILES the target, executing its build scripts on"
      echo "                       this host; only enable for code you trust/would run)"
      echo "  --no-compile-check   (default) skip the cargo pre-flight"
      echo "  --static-only        deterministic static rules only — no LLM, no API key."
      echo "                       Free and instant."
      echo "  --no-static          skip the deterministic static pass (LLM only)"
      exit 0
      ;;
    --backend)
      if [[ $# -lt 2 ]]; then echo "error: --backend needs a value (claude-api|aider|cmd)" >&2; exit 1; fi
      shift; BACKEND_FLAG="$1"
      ;;
    --backend-cmd)
      if [[ $# -lt 2 ]]; then echo "error: --backend-cmd needs a command string" >&2; exit 1; fi
      shift; BACKEND_CMD_FLAG="$1"
      ;;
    --model)
      if [[ $# -lt 2 ]]; then
        echo "error: --model needs a value (claude|deepseek|both, or a model id)" >&2; exit 1
      fi
      shift; MODEL="$1"
      # No fixed whitelist any more: deepseek/both are aider cross-model modes, and any other
      # value is passed through as a model id to the selected backend (resolved below).
      ;;
    --compile-check) COMPILE_CHECK=1 ;;
    --no-compile-check) COMPILE_CHECK=0 ;;  # back-compat; compile is off by default now
    --static-only) STATIC_ONLY=1 ;;
    --no-static) NO_STATIC=1 ;;
    *) break ;;
  esac
  shift
done

# ---- backend resolution -----------------------------------------------------
# Precedence: --backend > $SAK_BACKEND > default (claude-api). deepseek/both are aider-only.
BACKEND="${BACKEND_FLAG:-${SAK_BACKEND:-claude-api}}"
BACKEND_EXPLICIT=0
if [[ -n "$BACKEND_FLAG" || -n "${SAK_BACKEND:-}" ]]; then BACKEND_EXPLICIT=1; fi
if [[ "$MODEL" == "deepseek" || "$MODEL" == "both" ]]; then
  if [[ "$BACKEND_EXPLICIT" == "1" && "$BACKEND" != "aider" ]]; then
    echo "error: --model $MODEL is an aider cross-model mode; it needs --backend aider" >&2
    exit 1
  fi
  BACKEND="aider"
fi
case "$BACKEND" in
  claude-api|aider|cmd) ;;
  *) echo "error: --backend must be claude-api, aider, or cmd (got '$BACKEND')" >&2; exit 1 ;;
esac
BACKEND_CMD="${BACKEND_CMD_FLAG:-${SAK_BACKEND_CMD:-}}"
if [[ "$BACKEND" == "cmd" && "$STATIC_ONLY" != "1" && -z "$BACKEND_CMD" ]]; then
  echo "error: --backend cmd needs --backend-cmd '<command>' (or \$SAK_BACKEND_CMD)" >&2
  echo "       the command is fed the prompt + files and must print the report to stdout." >&2
  echo "       see docs/backends.md for the contract." >&2
  exit 1
fi
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
# Clean up any per-run temp files on exit (message file, composite prompt, static findings).
trap 'rm -f "${MSG_MAIN:-}" "${COMPOSITE_PROMPT:-}" "${STATIC_FINDINGS:-}" 2>/dev/null || true' EXIT

# ---- API key sourcing (skipped for --static-only and the cmd backend) -------
# The claude-api and aider backends need ANTHROPIC_API_KEY; the cmd backend owns its own auth,
# so it's skipped there. Sources, in order: the calling shell, then AIDER_ENV_FILE, then a .env
# in the kit dir. The key is never echoed.
if [[ "$STATIC_ONLY" != "1" && "$BACKEND" != "cmd" ]]; then
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    if [[ -n "${AIDER_ENV_FILE:-}" && -f "$AIDER_ENV_FILE" ]]; then
      set -a
      # shellcheck source=/dev/null
      . "$AIDER_ENV_FILE"
      set +a
    elif [[ -f "$KIT_DIR/.env" ]]; then
      set -a
      # shellcheck source=/dev/null
      . "$KIT_DIR/.env"
      set +a
    fi
  fi
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "error: ANTHROPIC_API_KEY not set (or use --static-only for a free, no-API pass)." >&2
    echo "       export ANTHROPIC_API_KEY=sk-ant-...  |  AIDER_ENV_FILE=/path/.env  |  .env in the kit dir" >&2
    exit 1
  fi
fi

# ---- backend dependency pre-flight ------------------------------------------
if [[ "$STATIC_ONLY" != "1" ]]; then
  case "$BACKEND" in
    claude-api)
      if ! command -v python3 >/dev/null 2>&1; then
        echo "error: the claude-api backend needs python3 (or use --backend aider)." >&2; exit 1
      fi ;;
    aider)
      if ! command -v aider >/dev/null 2>&1; then
        echo "error: --backend aider needs aider on PATH (pip install aider-chat)." >&2; exit 1
      fi ;;
  esac
fi

# ---- validate scrypto package shape -----------------------------------------
if [[ ! -f "$TARGET/Cargo.toml" ]]; then
  echo "error: no Cargo.toml at $TARGET — not a scrypto package" >&2
  exit 1
fi
if [[ ! -f "$TARGET/src/lib.rs" ]]; then
  echo "error: no src/lib.rs at $TARGET — not a scrypto blueprint" >&2
  exit 1
fi

# ---- pre-flight: compile check (opt-in) -------------------------------------
# When enabled with --compile-check, bail early if the code doesn't compile — no point
# spending LLM time on broken code. OFF by default because `cargo check` executes the target's
# build scripts on this host (see the SECURITY note below). The analysis itself never needs a
# successful build, so leaving it off is safe.
if [[ "$STATIC_ONLY" == "1" ]]; then
  : # static-only needs no build
elif [[ "$COMPILE_CHECK" != "1" ]]; then
  echo "[pre-flight] compile check OFF (default; compiling runs the target's build scripts)."
  echo "             opt in with --compile-check for code you trust."
  echo ""
elif ! command -v cargo >/dev/null 2>&1; then
  echo "[pre-flight] cargo not found — skipping compile check" >&2
  echo ""
else
  echo "[pre-flight] cargo check (release wasm)..."
  # SECURITY: 'cargo check' COMPILES the target, which EXECUTES its build.rs and any proc-macros
  # on this host — arbitrary code from a blueprint you may not trust. Two guards here:
  #   (1) scrub API keys from the subprocess env so a hostile build script can't read them;
  #   (2) warn loudly so the operator knows untrusted code is about to run.
  # This does NOT sandbox the execution itself — do not compile-check a blueprint you would not
  # run, or use --no-compile-check. A real sandbox (container/VM, dropped env, no network) is the
  # tracked full fix; until then the code-execution risk remains even with keys scrubbed.
  echo "[pre-flight] note: compiling executes the target's build scripts/proc-macros on this host." >&2
  if ! env -u ANTHROPIC_API_KEY -u DEEPSEEK_API_KEY \
         cargo check --manifest-path "$TARGET/Cargo.toml" \
         --release --target wasm32-unknown-unknown 2>/dev/null; then
    echo "error: cargo check failed — fix compile errors before auditing." >&2
    echo "       (or re-run with --no-compile-check to audit anyway)" >&2
    exit 1
  fi
  echo "[pre-flight] compile OK"
  echo ""
fi

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
# Sanitise the derived names before they become a filename (a hostile package dir name never
# reaches a shell — it's passed as argv — but keep report filenames to a safe character set).
REPO="$(printf '%s' "$REPO" | tr -c 'A-Za-z0-9._-' '_')"
PKG="$(printf '%s' "$PKG" | tr -c 'A-Za-z0-9._-' '_')"
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

# ---- reproducibility metadata -----------------------------------------------
# Stamped into every report (md header + report.json) so a run is reproducible,
# and so an L3 on-chain attestation has a stable code anchor to bind to.
KIT_VERSION="$(cat "$KIT_DIR/VERSION" 2>/dev/null || echo 0.0.0)"
if git -C "$KIT_DIR" rev-parse --short HEAD >/dev/null 2>&1; then
  KIT_VERSION="${KIT_VERSION}+g$(git -C "$KIT_DIR" rev-parse --short HEAD)"
fi
CHECKLIST_VERSION="$(sed -n 's/.*checklist-version:[[:space:]]*\([0-9.]*\).*/\1/p' \
  "$KIT_DIR/prompts/checklist.md" 2>/dev/null | head -1)" || CHECKLIST_VERSION=""
CHECKLIST_VERSION="${CHECKLIST_VERSION:-unknown}"
# sha256 of the concatenated analyzed source — the anchor an attestation binds to.
if command -v sha256sum >/dev/null 2>&1; then
  SOURCE_HASH="$(cat "${TARGET_FILES[@]}" 2>/dev/null | sha256sum | cut -d' ' -f1)" || SOURCE_HASH=""
elif command -v shasum >/dev/null 2>&1; then
  SOURCE_HASH="$(cat "${TARGET_FILES[@]}" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)" || SOURCE_HASH=""
else
  SOURCE_HASH=""
fi
# MODEL_DESC is stamped into the report provenance; make it name what actually ran.
case "$BACKEND" in
  claude-api)
    if [[ "$MODEL" == "claude" ]]; then MODEL_DESC="claude-sonnet-4-6"; else MODEL_DESC="$MODEL"; fi ;;
  aider)
    case "$MODEL" in
      deepseek) MODEL_DESC="deepseek/deepseek-chat" ;;
      both)     MODEL_DESC="deepseek/deepseek-chat + anthropic/claude-sonnet-4-6" ;;
      claude)   MODEL_DESC="anthropic/claude-sonnet-4-6" ;;
      *)        MODEL_DESC="$MODEL" ;;
    esac ;;
  cmd) MODEL_DESC="cmd:${BACKEND_CMD%% *}" ;;   # first word of the BYO command
esac
if [[ "$STATIC_ONLY" == "1" ]]; then MODE_LABEL="static-only (no LLM)"
elif [[ "$NO_STATIC" == "1" ]]; then MODE_LABEL="$BACKEND / $MODEL_DESC (no static)"
else MODE_LABEL="$BACKEND / $MODEL_DESC + static"; fi
REPORT_JSON="${REPORT%.md}.json"

# ---- per-run nonce: authenticates the PROVENANCE of the model's JSON appendix ----
# Defeats the ECHO variant of injection: a blueprint that gets the model to emit a forged JSON
# block can't reproduce this unpredictable nonce, so extract-report.py trusts ONLY the block
# carrying its marker. It does NOT defend against a model PERSUADED by in-source text to report
# a clean result (that's the untrusted-data boundary in prompts/audit.md). Per LLM run only.
NONCE=""
MSG_MAIN=""
if [[ "$STATIC_ONLY" != "1" ]]; then
  NONCE="$(date +%s 2>/dev/null || echo 0)-${RANDOM}${RANDOM}-$$"
  MSG_MAIN="$(mktemp "${TMPDIR:-/tmp}/sak-msg.XXXXXX")"
  {
    cat "$KIT_DIR/prompts/audit.md"
    printf '\n## Run delimiter (required)\n\n'
    printf 'This run'\''s machine-readable marker is exactly:\n\n'
    printf '    <!-- sak:nonce:%s -->\n\n' "$NONCE"
    printf 'Emit that EXACT line immediately before the §7 JSON code fence (in place of the\n'
    printf 'generic "machine-readable" marker). Emit it once, wrapping only your real appendix.\n'
  } > "$MSG_MAIN"
fi

# ---- collect read-only reference files --------------------------------------
declare -a READ_FILES=()
READ_FILES+=("$KIT_DIR/prompts/checklist.md")
while IFS= read -r f; do READ_FILES+=("$f"); done < <(find "$KIT_DIR/references" -name "*.md" -type f 2>/dev/null | sort)

# ---- announce ---------------------------------------------------------------
echo "==> scrypto-audit-kit"
echo "    target:    $REPO / $PKG"
echo "    path:      $TARGET"
echo "    mode:      $MODE_LABEL"
echo "    sources:   ${#TARGET_FILES[@]} files"
echo "    refs:      ${#READ_FILES[@]} files (read-only)"
echo "    report ->  $REPORT"
echo ""

# ---- static analysis pass (deterministic, free, no API) ---------------------
STATIC_FINDINGS=""
if [[ "$STATIC_ONLY" == "1" || "$NO_STATIC" != "1" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    STATIC_FINDINGS="$KIT_DIR/audit-reports/.static-${REPO}-${PKG}-${DATE}.json"
    python3 "$KIT_DIR/bin/static_analysis.py" --out "$STATIC_FINDINGS" "$TARGET" \
      || { echo "warn: static analysis failed — continuing" >&2; STATIC_FINDINGS=""; }
  elif [[ "$STATIC_ONLY" == "1" ]]; then
    echo "error: --static-only needs python3" >&2; exit 1
  fi
fi

# Build --read args (one per reference file) — used by the aider backend.
READ_ARGS=()
for f in "${READ_FILES[@]}"; do READ_ARGS+=("--read" "$f"); done

cd "$KIT_DIR"

# ---- backends ---------------------------------------------------------------
# Each backend takes (model, out_file, err_file) [+ msg_file where it wants the pre-assembled
# prompt], sends the same inputs — audit prompt, checklist + references, target source — to a
# model, and writes the markdown report (ending in the nonce-stamped §7 JSON appendix) to
# out_file. The nonce/extract machinery downstream is backend-agnostic; see docs/backends.md.

# claude-api (default): the Anthropic SDK directly, via bin/llm_audit.py. No aider dependency.
backend_claude_api() {
  local model="$1" out_file="$2" err_file="$3"
  local api_model="$model"
  [[ "$model" == "claude" ]] && api_model="claude-sonnet-4-6"
  local read_args=() f
  for f in "${READ_FILES[@]}"; do read_args+=("--read" "$f"); done
  python3 "$KIT_DIR/bin/llm_audit.py" \
    --model "$api_model" \
    --prompt "$KIT_DIR/prompts/audit.md" \
    --nonce "$NONCE" \
    --pkg-root "$TARGET" \
    "${read_args[@]}" \
    "${TARGET_FILES[@]}" \
    > "$out_file" 2> >(tee -a "$err_file" >&2)
  return $?
}

# aider: the harness the kit originally shipped. Keeps the deepseek/both cross-model modes.
backend_aider() {
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

# cmd: bring-your-own agent. The command (from --backend-cmd / $SAK_BACKEND_CMD) is run via
# `sh -c` with the prompt file as $1 and the target files as $2.. ("$@" = prompt + targets),
# plus SAK_* env vars for everything else, and must print the report to stdout. Contract:
# docs/backends.md. This is how your own agents (bigdev-agents, Claude Code, …) drive the kit.
backend_cmd() {
  local model="$1" msg_file="$2" out_file="$3" err_file="$4"
  local ctx tgt
  ctx="$(printf '%s\n' "${READ_FILES[@]}")"
  tgt="$(printf '%s\n' "${TARGET_FILES[@]}")"
  SAK_MODEL="$model" \
  SAK_NONCE="$NONCE" \
  SAK_PKG_ROOT="$TARGET" \
  SAK_PROMPT_FILE="$msg_file" \
  SAK_AUDIT_PROMPT="$KIT_DIR/prompts/audit.md" \
  SAK_CONTEXT_FILES="$ctx" \
  SAK_TARGET_FILES="$tgt" \
    sh -c "$BACKEND_CMD" sak-backend "$msg_file" "${TARGET_FILES[@]}" \
    > "$out_file" 2> >(tee -a "$err_file" >&2)
  return $?
}

# ---- run_backend: dispatch a single-model run to the selected backend -------
run_backend() {
  local model="$1" out_file="$2" err_file="$3"
  case "$BACKEND" in
    claude-api) backend_claude_api "$model" "$out_file" "$err_file" ;;
    aider)
      local am="$model"
      case "$model" in
        claude)   am="anthropic/claude-sonnet-4-6" ;;
        deepseek) am="deepseek/deepseek-chat" ;;
      esac
      backend_aider "$am" "$MSG_MAIN" "$out_file" "$err_file" ;;
    cmd) backend_cmd "$model" "$MSG_MAIN" "$out_file" "$err_file" ;;
  esac
}

# ---- run --------------------------------------------------------------------
if [[ "$STATIC_ONLY" == "1" ]]; then
  # No LLM pass — the report is built from the static findings in the extract step.
  printf '# Audit: %s\n\n_Static-only pre-audit (deterministic rules; no LLM pass)._\n' "$PKG" > "$REPORT"
elif [[ "$MODEL" == "both" ]]; then
  # (--model both implies --backend aider; enforced during backend resolution.)
  # Pass 1: DeepSeek — broad, cheap scan
  DEEPSEEK_REPORT="$REPORT.deepseek"
  echo "--- pass 1/2: DeepSeek (broad scan) ---"
  backend_aider "deepseek/deepseek-chat" "$KIT_DIR/prompts/audit.md" \
    "$DEEPSEEK_REPORT" "$REPORT.stderr"
  echo "--- pass 1 complete ---"

  # Extract findings section from DeepSeek output to use as context for Claude
  FINDINGS_ONLY="$REPORT.deepseek-findings"
  # From the first "Findings" heading to the end, capped — and neutralise ``` fences so DeepSeek
  # output (which may echo attacker source) can't break out of the wrapper fed to Claude below.
  awk 'tolower($0) ~ /findings/ {f=1} f' "$DEEPSEEK_REPORT" 2>/dev/null \
    | head -200 | sed 's/```/~~~/g' > "$FINDINGS_ONLY" || true
  if [[ ! -s "$FINDINGS_ONLY" ]]; then
    tail -200 "$DEEPSEEK_REPORT" 2>/dev/null | sed 's/```/~~~/g' > "$FINDINGS_ONLY" || true
  fi

  # Pass 2: Claude — deep analysis with DeepSeek findings as context
  CLAUDE_REPORT="$REPORT.claude"
  echo "--- pass 2/2: Claude (deep analysis) ---"

  # Create a composite prompt: the base audit prompt plus DeepSeek findings
  COMPOSITE_PROMPT="$(mktemp "${TMPDIR:-/tmp}/sak-composite.XXXXXX")"
  cat "$MSG_MAIN" > "$COMPOSITE_PROMPT"
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

  backend_aider "anthropic/claude-sonnet-4-6" "$COMPOSITE_PROMPT" \
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
    echo "- **Claude** (pass 2 — deep): ~${CLAUDE_FINDINGS} findings, detailed below"
    echo "- **Confidence**: issues flagged by both models are HIGH confidence"
    echo ""
    echo "---"
    echo ""
    cat "$CLAUDE_REPORT"
  } > "$REPORT"

  # Cleanup intermediate files
  rm -f "$DEEPSEEK_REPORT" "$CLAUDE_REPORT" "$FINDINGS_ONLY" 2>/dev/null

else
  # Single-model run through the selected backend (claude-api default, aider, or cmd).
  run_backend "$MODEL" "$REPORT.raw" "$REPORT.stderr" || {
    echo "==> $BACKEND backend exited non-zero — see $REPORT.stderr" >&2
    exit 1
  }

  if [[ "$BACKEND" == "aider" ]]; then
    # Strip aider's chrome: banner + file-add prompt lines precede the report. Keep
    # everything from the first valid markdown heading (## or ###) onward.
    awk '
      /^##? / { found=1 }
      found { print }
    ' "$REPORT.raw" > "$REPORT" 2>/dev/null || cp "$REPORT.raw" "$REPORT"
  else
    # claude-api / cmd emit a clean report already — no harness chrome to strip.
    cp "$REPORT.raw" "$REPORT"
  fi
  rm -f "$REPORT.raw" 2>/dev/null
fi

# ---- structured output: split report.json out of the markdown ----------------
# Best-effort: if python3 is missing or the model emitted no JSON block, the
# markdown report is still produced and we simply skip report.json.
if command -v python3 >/dev/null 2>&1; then
  REPORT_MODEL="$MODEL_DESC"
  if [[ "$STATIC_ONLY" == "1" ]]; then REPORT_MODEL="static-only"; fi
  extract_rc=0
  python3 "$KIT_DIR/bin/extract-report.py" \
    --raw "$REPORT" --out-json "$REPORT_JSON" --out-md "$REPORT" \
    --kit-version "$KIT_VERSION" --model "$REPORT_MODEL" \
    --checklist-version "$CHECKLIST_VERSION" --reference-set "${#READ_FILES[@]} files" \
    --repo "$REPO" --package "$PKG" --source-hash "$SOURCE_HASH" \
    --files "${#TARGET_FILES[@]}" --generated-at "$DATE" \
    --static-json "$STATIC_FINDINGS" --nonce "$NONCE" \
    --schema "$KIT_DIR/schema/audit-report.schema.json" \
    || extract_rc=$?
  # exit 3 = the JSON appendix failed nonce authentication (possible injection). Do NOT swallow
  # it — fail the whole run non-zero so CI keyed on the exit code, and any operator, sees it.
  if [[ "$extract_rc" == "3" ]]; then
    echo "error: pre-audit REFUSED — the model's JSON appendix was not nonce-authenticated" >&2
    echo "       (possible prompt injection). No report.json written; re-run the audit." >&2
    exit 3
  elif [[ "$extract_rc" != "0" ]]; then
    echo "warn: report.json not produced (extract-report exit $extract_rc)" >&2
  fi
else
  echo "warn: python3 not found — skipping report.json (markdown still written)" >&2
fi
if [[ -n "$STATIC_FINDINGS" ]]; then rm -f "$STATIC_FINDINGS"; fi

echo ""
echo "==> done."
echo "    markdown: $REPORT"
if [[ -f "$REPORT_JSON" ]]; then echo "    json:     $REPORT_JSON"; fi
if [[ -f "$REPORT.stderr" ]]; then echo "    stderr:   $REPORT.stderr"; fi
