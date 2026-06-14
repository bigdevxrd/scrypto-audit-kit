"""Unit tests for the MCP tool functions in bin/mcp_server.py that don't need an LLM.

audit_package / reaudit_diff make real LLM calls, so they're only smoke-tested for
graceful failure here; the cheap tools are checked against the committed sample.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import mcp_server  # noqa: E402

SAMPLE = os.path.join(ROOT, "examples", "vulnerable-vault.pre-audit.json")
PKG = os.path.join(ROOT, "examples", "vulnerable-vault")


def _have_sdk():
    for mod in ("mcp.server.fastmcp", "fastmcp"):
        try:
            __import__(mod)
            return True
        except ImportError:
            continue
    return False


class TestMcpTools(unittest.TestCase):
    def test_get_findings_filter(self):
        res = mcp_server.get_findings(SAMPLE, severity_min="high")
        self.assertEqual(res["count"], 4)
        self.assertEqual(res["counts"].get("critical"), 2)

    def test_gate(self):
        self.assertFalse(mcp_server.gate(SAMPLE, "high")["passed"])
        self.assertTrue(mcp_server.gate(SAMPLE, "none")["passed"])

    def test_get_checklist(self):
        text = mcp_server.get_checklist()
        self.assertIn("Auth bypass", text)
        self.assertIn("checklist-version", text)

    def test_static_scan(self):
        res = mcp_server.static_scan(PKG)
        self.assertEqual(res["count"], 3)
        self.assertTrue(all(f["source"] == "static" for f in res["findings"]))

    def test_show_finding_source(self):
        res = mcp_server.show_finding_source(SAMPLE, "F-003", package_path=PKG, context=2)
        self.assertEqual(res["finding"]["id"], "F-003")
        self.assertIn("shares", res["source"]["snippet"])

    def test_show_finding_source_unknown(self):
        self.assertIn("error", mcp_server.show_finding_source(SAMPLE, "F-404", package_path=PKG))

    def test_audit_package_graceful_on_bad_path(self):
        # Bogus path (and/or no API key) → audit.sh fails → a graceful error dict, never an exception.
        res = mcp_server.audit_package("/definitely/not/a/real/path/xyzzy", no_compile_check=True)
        self.assertIn("error", res)

    def test_build_server_matches_sdk_availability(self):
        if _have_sdk():
            self.assertIsNotNone(mcp_server.build_server())
        else:
            with self.assertRaises(ImportError):
                mcp_server.build_server()


if __name__ == "__main__":
    unittest.main()
