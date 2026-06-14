"""Tests for the pip-installable packaging layer (pyproject.toml + bin/__init__.py).

These run in the normal bare-clone test context (no install needed): they load the package
`__init__` from its file path under the name `scrypto_audit_kit`, exactly as an install would,
and verify the console entry points and the dynamic version line up with what pyproject declares.
A drift guard — so the packaging config can't silently diverge from the code it points at.
"""
import importlib.util
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(ROOT, "bin")
PKG_INIT = os.path.join(BIN, "__init__.py")
PYPROJECT = os.path.join(ROOT, "pyproject.toml")
VERSION_FILE = os.path.join(ROOT, "VERSION")


def _load_package():
    """Load bin/__init__.py as the `scrypto_audit_kit` package, like an install would."""
    spec = importlib.util.spec_from_file_location(
        "scrypto_audit_kit", PKG_INIT, submodule_search_locations=[BIN])
    module = importlib.util.module_from_spec(spec)
    sys.modules["scrypto_audit_kit"] = module
    spec.loader.exec_module(module)
    return module


def _read_version_file():
    with open(VERSION_FILE, encoding="utf-8") as fh:
        return fh.read().strip()


def _load_pyproject():
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        return None
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


class TestPackaging(unittest.TestCase):
    def test_version_file_is_semver(self):
        self.assertRegex(_read_version_file(), r"^\d+\.\d+\.\d+([-.+].+)?$")

    def test_package_imports_and_exposes_core_api(self):
        pkg = _load_package()
        for name in ("sak_lib", "static_analysis", "attest", "gen_tests"):
            self.assertTrue(hasattr(pkg, name), f"scrypto_audit_kit.{name} not exported")
        # the re-exported modules are usable, not just present
        self.assertTrue(callable(pkg.static_analysis.analyze_package))
        self.assertTrue(callable(pkg.sak_lib.gate_verdict))

    def test_dunder_version_matches_version_file(self):
        pkg = _load_package()
        self.assertEqual(pkg.__version__, _read_version_file())

    def test_pyproject_dynamic_version_reads_version_file(self):
        data = _load_pyproject()
        if data is None:
            self.skipTest("tomllib unavailable (Python < 3.11)")
        self.assertEqual(data["project"]["dynamic"], ["version"])
        self.assertEqual(data["tool"]["setuptools"]["dynamic"]["version"]["file"], "VERSION")

    def test_pyproject_maps_package_to_bin(self):
        data = _load_pyproject()
        if data is None:
            self.skipTest("tomllib unavailable (Python < 3.11)")
        self.assertEqual(
            data["tool"]["setuptools"]["package-dir"]["scrypto_audit_kit"], "bin")
        self.assertIn("scrypto_audit_kit", data["tool"]["setuptools"]["packages"])

    def test_console_entry_points_resolve_to_callables(self):
        """Every `sak-*` script's `module:attr` target must exist and be callable."""
        data = _load_pyproject()
        if data is None:
            self.skipTest("tomllib unavailable (Python < 3.11)")
        sys.path.insert(0, BIN)
        try:
            for script, target in data["project"]["scripts"].items():
                module_path, attr = target.split(":")
                self.assertTrue(module_path.startswith("scrypto_audit_kit."), script)
                mod_name = module_path.split(".", 1)[1]
                mod = importlib.import_module(mod_name)
                self.assertTrue(callable(getattr(mod, attr, None)),
                                f"{script} -> {target} is not callable")
        finally:
            sys.path.remove(BIN)

    def test_ci_gate_shim_matches_real_gate(self):
        """The hyphenated ci-gate.py shim must delegate to ci_gate.main (same object)."""
        sys.path.insert(0, BIN)
        try:
            import ci_gate
            shim_src = open(os.path.join(BIN, "ci-gate.py"), encoding="utf-8").read()
            self.assertIn("from ci_gate import main", shim_src)
            self.assertTrue(callable(ci_gate.main))
        finally:
            sys.path.remove(BIN)


if __name__ == "__main__":
    unittest.main()
