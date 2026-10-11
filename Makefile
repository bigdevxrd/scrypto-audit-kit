# scrypto-audit-kit — convenience targets
#
# Examples:
#   make audit TARGET=/tmp/ignition/packages/simple-oracle
#   make lint
#   make help

.PHONY: help audit lint test refresh-refs check-deps scan scan-diff scan-page

help:
	@echo "scrypto-audit-kit"
	@echo ""
	@echo "Targets:"
	@echo "  audit TARGET=<path>    Run a pre-audit pass over a scrypto package."
	@echo "  lint                   Lint the harness (shellcheck) and prompts/refs (markdownlint)."
	@echo "  test                   Run the unit-test suite."
	@echo "  check-deps             Verify anthropic/aider + supporting tools are installed."
	@echo "  refresh-refs           (operator-only) Re-export reference docs from a curator's notes."
	@echo "  scan                   Run the posture scanner: scanner/data/cohort-full.json if present, else the public scanner/data/cohort.json (docs/posture-scanner.md)."
	@echo "  scan-diff OLD= NEW=    Diff two posture-scan report.json files."
	@echo "  scan-page              Re-render latest.json/.md and the public page from the newest scan."
	@echo ""

audit:
	@if [ -z "$(TARGET)" ]; then \
		echo "usage: make audit TARGET=<path-to-scrypto-package>" >&2; \
		exit 2; \
	fi
	./audit.sh "$(TARGET)"

lint:
	@command -v shellcheck >/dev/null || { echo "shellcheck not installed — brew install shellcheck"; exit 1; }
	shellcheck audit.sh
	@if command -v python3 >/dev/null; then python3 -m py_compile bin/*.py scanner/*.py scanner/checks/*.py && echo "python: ok"; else echo "(python3 not installed — skipping py check)"; fi
	@if command -v markdownlint >/dev/null; then \
		markdownlint README.md CHANGELOG.md RELEASING.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md AGENTS.md VISION.md ROADMAP.md docs/ prompts/ references/ examples/ attestation/; \
	else \
		echo "(markdownlint not installed — skipping md lint)"; \
	fi

test:
	@command -v python3 >/dev/null || { echo "python3 required for tests"; exit 1; }
	python3 -m unittest discover -s tests -t .

check-deps:
	@command -v aider     >/dev/null && echo "aider:     $$(aider --version)"        || echo "aider:     absent (only the deepseek/both cross-model modes need it)"
	@command -v bash      >/dev/null && echo "bash:      $$(bash --version | head -1)" || echo "bash:      MISSING"
	@command -v awk       >/dev/null && echo "awk:       present"                    || echo "awk:       MISSING"
	@command -v find      >/dev/null && echo "find:      present"                    || echo "find:      MISSING"
	@command -v python3   >/dev/null && echo "python3:   $$(python3 --version 2>&1)"  || echo "python3:   not found (report.json will be skipped)"
	@python3 -c "import anthropic" >/dev/null 2>&1 && echo "anthropic: $$(python3 -c 'import anthropic; print(anthropic.__version__)')" || echo "anthropic: absent (needed by the default claude-api backend; pip install '.[llm]')"
	@[ -n "$$ANTHROPIC_API_KEY" ] && echo "ANTHROPIC_API_KEY: set" || echo "ANTHROPIC_API_KEY: NOT SET (needed by the default claude-api backend, and by aider's sonnet model)"
	@[ -n "$$DEEPSEEK_API_KEY" ] && echo "DEEPSEEK_API_KEY:  set" || echo "DEEPSEEK_API_KEY:  not set (only needed for --model deepseek/both)"

# Operator-only: re-export reference docs. Contributors don't run this; PRs
# against references/ are reviewed manually.
refresh-refs:
	@echo "Re-exporting references is curator-only. See references/README.md for the procedure."

scan:
	python3 -m scanner.cli scan

scan-diff:
	@if [ -z "$(OLD)" ] || [ -z "$(NEW)" ]; then \
		echo "usage: make scan-diff OLD=<path> NEW=<path>" >&2; \
		exit 2; \
	fi
	python3 -m scanner.cli diff "$(OLD)" "$(NEW)"

scan-page:
	python3 -m scanner.site --sync
