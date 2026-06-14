# scrypto-audit-kit — convenience targets
#
# Examples:
#   make audit TARGET=/tmp/ignition/packages/simple-oracle
#   make lint
#   make help

.PHONY: help audit lint test refresh-refs check-deps

help:
	@echo "scrypto-audit-kit"
	@echo ""
	@echo "Targets:"
	@echo "  audit TARGET=<path>    Run a pre-audit pass over a scrypto package."
	@echo "  lint                   Lint the harness (shellcheck) and prompts/refs (markdownlint)."
	@echo "  check-deps             Verify aider + supporting tools are installed."
	@echo "  refresh-refs           (operator-only) Re-export reference docs from a curator's notes."
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
	@if command -v python3 >/dev/null; then python3 -m py_compile bin/*.py && echo "python: ok"; else echo "(python3 not installed — skipping py check)"; fi
	@if command -v markdownlint >/dev/null; then \
		markdownlint README.md CONTRIBUTING.md CODE_OF_CONDUCT.md AGENTS.md VISION.md ROADMAP.md docs/ prompts/ references/ examples/; \
	else \
		echo "(markdownlint not installed — skipping md lint)"; \
	fi

test:
	@command -v python3 >/dev/null || { echo "python3 required for tests"; exit 1; }
	python3 -m unittest discover -s tests -t .

check-deps:
	@command -v aider     >/dev/null && echo "aider:     $$(aider --version)"        || echo "aider:     MISSING (pip install aider-chat)"
	@command -v bash      >/dev/null && echo "bash:      $$(bash --version | head -1)" || echo "bash:      MISSING"
	@command -v awk       >/dev/null && echo "awk:       present"                    || echo "awk:       MISSING"
	@command -v find      >/dev/null && echo "find:      present"                    || echo "find:      MISSING"
	@command -v python3   >/dev/null && echo "python3:   $$(python3 --version 2>&1)"  || echo "python3:   not found (report.json will be skipped)"
	@[ -n "$$ANTHROPIC_API_KEY" ] && echo "ANTHROPIC_API_KEY: set" || echo "ANTHROPIC_API_KEY: NOT SET (aider needs it for the default sonnet model)"
	@[ -n "$$DEEPSEEK_API_KEY" ] && echo "DEEPSEEK_API_KEY:  set" || echo "DEEPSEEK_API_KEY:  not set (only needed for --model deepseek/both)"

# Operator-only: re-export reference docs. Contributors don't run this; PRs
# against references/ are reviewed manually.
refresh-refs:
	@echo "Re-exporting references is curator-only. See references/README.md for the procedure."
