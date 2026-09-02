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

    def test_static_gate_fails_the_fixture_at_every_threshold_it_reaches(self):
        # The fixture tops out at CRITICAL, not medium — so every threshold from critical down
        # must fail. The old version of this test asserted the opposite at `high` and `critical`
        # ("the fixture's static findings top out at medium"), which was true only because the
        # ruleset could not see the two worst planted bugs.
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "critical"]).returncode, 1)
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "high"]).returncode, 1)
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "medium"]).returncode, 1)
        # `--fail-on critical` firing here is itself new: before this rule, NO rule in the
        # ruleset emitted `critical`, so that threshold was vacuous by construction and could
        # never fail on any package at all.
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "none"]).returncode, 0)

    def test_static_gate_rejects_bad_threshold(self):
        self.assertEqual(_run([STATIC_GATE, FIXTURE, "--fail-on", "bogus"]).returncode, 2)

    def test_static_gate_runs_on_bundled_fixture_by_default(self):
        # No path arg -> the bundled fixture, which is DELIBERATELY CRITICAL: it plants
        # `emergency_drain => PUBLIC` and `set_oracle_price => PUBLIC`, and its committed
        # reference report rates both Critical.
        #
        # ⚠️ THIS ASSERTION WAS INVERTED (expected 0, "medium findings pass a high gate") until
        # `public-privileged-method` landed. That was the blind spot written down as an
        # expectation: the shipped example agent, run exactly as documented, printed
        # "PASS: nothing at/above 'high'" over a package with a public unbounded drain, and this
        # test asserted that it should. A gate that cannot fail on this fixture is not a gate.
        self.assertEqual(_run([STATIC_GATE]).returncode, 1)

    def test_audit_fix_verify_walks_the_free_tier_loop(self):
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        result = _run([AUDIT_FIX_VERIFY, FIXTURE], env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        for marker in ("static_scan", "gate", "attestation_payload"):
            self.assertIn(marker, result.stdout)


if __name__ == "__main__":
    unittest.main()
