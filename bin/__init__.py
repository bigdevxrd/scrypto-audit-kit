"""scrypto-audit-kit — the deterministic Python core as an importable library.

`pip install scrypto-audit-kit` makes this package importable:

    from scrypto_audit_kit import static_analysis, sak_lib, attest, gen_tests

    findings = static_analysis.analyze_package("path/to/your/scrypto/package")
    verdict  = sak_lib.gate_verdict({"findings": findings}, fail_on="high")

The deterministic tools (static_analysis, gen_tests, attest) and helpers (sak_lib) need
no API key and no toolchain. The full LLM audit (audit.sh) and the MCP server's
audit_package tool additionally need a kit clone + aider + ANTHROPIC_API_KEY — see
docs/sdk.md for what runs where.

Importing this package is side-effect free: it does NOT touch `sys.path`, so it cannot
shadow a module of your own. Up to and including v0.7.0 it did — the modules here
cross-import by bare name (`import sak_lib`), the historical layout that keeps a bare
`git clone` runnable with no install, and this file put the package directory on
`sys.path` at index 0 so those bare names resolved. That insert was process-global: any
application importing the kit had `attest`, `sak_lib`, `static_analysis`, `gen_tests`,
`llm_audit`, `mcp_server` and `ci_gate` silently redirected to ours for the rest of its
run, including modules sitting in its own working directory (issue #5).

The cross-imports are now guarded — relative when we are a package, bare when a module is
run directly as a script — so both worlds work without a global mutation.
"""
import os as _os

_PKG_DIR = _os.path.dirname(_os.path.abspath(__file__))


def _read_version():
    """Kit version: the VERSION file of a real kit clone, else the installed metadata.

    The VERSION file is only trusted when it sits beside an `audit.sh` — i.e. this really is
    a clone or an editable install, and the file is ours. Installed, `dirname(_PKG_DIR)` is
    site-packages, which we do not own: any package dropping a VERSION file there would
    otherwise be read as the kit's version, and that string is stamped into every report's
    provenance block.
    """
    root = _os.path.dirname(_PKG_DIR)
    if _os.path.isfile(_os.path.join(root, "audit.sh")):
        try:
            with open(_os.path.join(root, "VERSION"), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            pass
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version("scrypto-audit-kit")
        except PackageNotFoundError:
            return "unknown"
    except ImportError:
        return "unknown"


__version__ = _read_version()

# Re-export the deterministic, no-API-key core. Relative, so these bind the same module
# objects the guarded cross-imports resolve to — `scrypto_audit_kit.sak_lib` is the one the
# tools actually call.
from . import sak_lib as sak_lib  # noqa: E402
from . import static_analysis as static_analysis  # noqa: E402
from . import attest as attest  # noqa: E402
from . import gen_tests as gen_tests  # noqa: E402

__all__ = ["sak_lib", "static_analysis", "attest", "gen_tests", "__version__"]
