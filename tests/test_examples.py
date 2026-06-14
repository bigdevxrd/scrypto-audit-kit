"""Smoke tests for examples/agents/* — keep the published example agents runnable.

The runnable, no-API examples are executed against the bundled fixture; mcp_client.py (which
needs the MCP SDK and spawns a server) is byte-compiled only. The audit_fix_verify run has
ANTHROPIC_API_KEY stripped from its environment so the test can never trigger a billed model call.
"""
import os
import py_compile
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENTS = os.path.join(ROOT, "examples", "agents")
FIXTURE = os.path.join(ROOT, "examples", "vulnerable-vault")

STATIC_GATE = os.path.join(AGENTS, "static_gate.py")
AUDIT_FIX_VERIFY = os.path.join(AGENTS, "audit_fix_verify.py")
MCP_CLIENT = os.path.join(AGENTS, "mcp_client.py")


def _run(args, env=None):
    return subprocess.run([sys.executable] + args, capture_output=True, text=True, env=env)


class TestExampleAgents(unittest.TestCase):
    def test_all_examples_byte_compile(self):
        for script in (STATIC_GATE, AUDIT_FIX_VERIFY, MCP_CLIENT):
            with self.subTest(script=os.path.basename(script)):
                py_compile.compile(script, doraise=True)

    def test_static_gate_passes_above_findings_fails_at_them(self):
        # the fixture's static findings top out at medium
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "high"]).returncode, 0)
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "critical"]).returncode, 0)
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "medium"]).returncode, 1)

    def test_static_gate_rejects_bad_threshold(self):
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "bogus"]).returncode, 2)

    def test_static_gate_runs_on_bundled_fixture_by_default(self):
        # no path arg -> uses the bundled fixture; medium findings pass a high gate
        self.assertEqual(_run([STATIC_GATE]).returncode, 0)

    def test_audit_fix_verify_walks_the_free_tier_loop(self):
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        result = _run([AUDIT_FIX_VERIFY, FIXTURE], env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        for marker in ("static_scan", "gate", "attestation_payload"):
            self.assertIn(marker, result.stdout)


if __name__ == "__main__":
    unittest.main()
