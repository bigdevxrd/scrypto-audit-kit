"""scrypto-audit-kit — the deterministic Python core as an importable library.

Installing the kit (`pip install .` from a clone — not yet on PyPI) makes this package
importable:

    from scrypto_audit_kit import static_analysis, sak_lib, attest, gen_tests

    findings = static_analysis.analyze_package("path/to/your/scrypto/package")
    verdict  = sak_lib.gate_verdict({"findings": findings}, fail_on="high")

The deterministic tools (static_analysis, gen_tests, attest) and helpers (sak_lib) need
no API key and no toolchain. The full LLM audit (audit.sh) and the MCP server's
audit_package tool additionally need a kit clone + aider + ANTHROPIC_API_KEY — see
docs/sdk.md for what runs where.

Implementation note: the modules in this directory cross-import by bare name
(`import sak_lib`) — the historical layout, which keeps a bare `git clone` runnable with
no install. So that those bare imports resolve when the directory is imported as the
`scrypto_audit_kit` package, we put the package directory on sys.path here. Converting the
cross-imports to relative imports is tracked for a future release (see ROADMAP.md).
"""
import os as _os
import sys as _sys

_PKG_DIR = _os.path.dirname(_os.path.abspath(__file__))
if _PKG_DIR not in _sys.path:
    _sys.path.insert(0, _PKG_DIR)


def _read_version():
    """Kit version: the VERSION file (clone / editable install), else installed metadata."""
    version_file = _os.path.join(_os.path.dirname(_PKG_DIR), "VERSION")
    try:
        with open(version_file, encoding="utf-8") as fh:
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

# Re-export the deterministic, no-API-key core. These bind the same module objects the
# internal cross-imports use, so `scrypto_audit_kit.sak_lib` is the one the tools call.
import sak_lib as sak_lib  # noqa: E402
import static_analysis as static_analysis  # noqa: E402
import attest as attest  # noqa: E402
import gen_tests as gen_tests  # noqa: E402

__all__ = ["sak_lib", "static_analysis", "attest", "gen_tests", "__version__"]
