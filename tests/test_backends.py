"""Tests for the interchangeable LLM backends (docs/backends.md).

Two surfaces, both exercised with NO API key and NO model call:
  * bin/llm_audit.py `build_request` — the claude-api backend's request assembly (pure).
  * audit.sh `--backend cmd` — the bring-your-own contract, driven end-to-end by a stub agent
    that emits a nonce-stamped report. Also the backend-selection validation errors.

The `anthropic` package is never imported (build_request and --dry-run don't need it), and
ANTHROPIC_API_KEY is stripped from the cmd-backend run so a test can never bill a model call.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import llm_audit  # noqa: E402

AUDIT_SH = os.path.join(ROOT, "audit.sh")
FIXTURE = os.path.join(ROOT, "examples", "vulnerable-vault")
PROMPT = os.path.join(ROOT, "prompts", "audit.md")
CHECKLIST = os.path.join(ROOT, "prompts", "checklist.md")

# A minimal BYO agent: reads the SAK_* env the kit sets, emits a nonce-stamped report.
STUB = r'''
import json, os, sys
nonce = os.environ["SAK_NONCE"]
assert os.path.exists(os.environ["SAK_PROMPT_FILE"])
assert os.path.exists(os.environ["SAK_AUDIT_PROMPT"])
targets = [t for t in os.environ.get("SAK_TARGET_FILES", "").splitlines() if t]
ctx = [c for c in os.environ.get("SAK_CONTEXT_FILES", "").splitlines() if c]
assert targets and ctx, "stub backend got no files"
rep = {"schema_version": "1.0", "kit": {}, "target": {"repo": "", "package": ""},
       "summary": {"overall_risk": "info", "one_liner": "STUB_BACKEND_RAN",
                   "asset_inventory": [], "trust_boundaries": [], "external_dependencies": []},
       "findings": [],
       "checklist_coverage": [{"class": c, "status": "not_applicable", "findings": []} for c in
           ["Auth bypass", "Reentrancy", "Decimal/rounding", "Resource handling", "Time/epoch",
            "State machine", "External calls", "Upgrade safety", "Oracle", "Slippage", "Allowances"]],
       "pattern_conformance": [], "test_coverage_gaps": [], "open_questions": []}
sys.stdout.write("### 1. Summary\n\nStub agent ran.\n\n### 2. Findings\n\nNone.\n\n")
sys.stdout.write("---\n<!-- machine-readable: do not edit -->\n<!-- sak:nonce:%s -->\n" % nonce)
sys.stdout.write("```json\n%s\n```\n" % json.dumps(rep))
'''


class TestLlmAuditAssembly(unittest.TestCase):
    """The claude-api backend builds a cache-friendly, injection-aware request."""

    def _req(self):
        return llm_audit.build_request(
            prompt_text="AUDITOR ROLE PROMPT",
            context_files=[CHECKLIST],
            target_files=[os.path.join(FIXTURE, "src", "lib.rs")],
            nonce="NONCE_XYZ",
            pkg_root=FIXTURE,
            model="claude-sonnet-4-6",
        )

    def test_default_model_is_the_kits_model(self):
        # The refactor must NOT silently change which model audits code.
        self.assertEqual(llm_audit.DEFAULT_MODEL, "claude-sonnet-4-6")
        self.assertEqual(self._req()["model"], "claude-sonnet-4-6")

    def test_stable_prefix_in_system_with_one_cache_breakpoint(self):
        req = self._req()
        # system = auditor prompt + each context file
        self.assertEqual(len(req["system"]), 2)
        cached = [b for b in req["system"] if "cache_control" in b]
        self.assertEqual(len(cached), 1, "exactly one cache breakpoint")
        self.assertIs(req["system"][-1], cached[0], "breakpoint on the last (stable) block")

    def test_volatile_content_after_the_cache_breakpoint(self):
        # nonce and target source live in the user turn, so they never bust the cached prefix.
        req = self._req()
        user_text = req["messages"][0]["content"][0]["text"]
        self.assertIn("sak:nonce:NONCE_XYZ", user_text)
        self.assertIn("UNTRUSTED BLUEPRINT SOURCE", user_text)
        for block in req["system"]:
            self.assertNotIn("NONCE_XYZ", block["text"], "nonce must not be in the cached prefix")

    def test_target_uses_relative_citations(self):
        req = self._req()
        user_text = req["messages"][0]["content"][0]["text"]
        self.assertIn("FILE: src/lib.rs", user_text)  # relative to pkg root, matches static tier

    def test_dry_run_needs_no_api_key_or_anthropic(self):
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "bin", "llm_audit.py"), "--dry-run",
             "--prompt", PROMPT, "--nonce", "N1", "--pkg-root", FIXTURE,
             "--read", CHECKLIST,
             os.path.join(FIXTURE, "Cargo.toml"), os.path.join(FIXTURE, "src", "lib.rs")],
            capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        manifest = json.loads(out.stdout)
        self.assertEqual(manifest["model"], "claude-sonnet-4-6")
        self.assertTrue(manifest["cache_breakpoint"])
        self.assertTrue(manifest["nonce_in_user_turn"])
        self.assertTrue(manifest["untrusted_banner"])
        self.assertEqual(manifest["target_files"], 2)


class TestCmdBackendEndToEnd(unittest.TestCase):
    """A BYO agent drives the whole kit over the cmd contract — no aider, no API key."""

    def _run_audit(self, extra_args, pkg, env=None):
        run_env = dict(os.environ)
        run_env.pop("ANTHROPIC_API_KEY", None)  # prove the cmd backend needs no key
        if env:
            run_env.update(env)
        return subprocess.run(
            ["bash", AUDIT_SH] + extra_args + [pkg],
            capture_output=True, text=True, env=run_env,
        )

    def test_cmd_backend_produces_authenticated_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = os.path.join(tmp, "stub_agent.py")
            with open(stub, "w") as fh:
                fh.write(STUB)
            out = self._run_audit(
                ["--backend", "cmd", "--backend-cmd", "%s %s" % (sys.executable, stub)],
                FIXTURE,
            )
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            # find the report.json path the harness announced
            json_path = None
            for line in out.stdout.splitlines():
                if line.strip().startswith("json:"):
                    json_path = line.split("json:", 1)[1].strip()
            self.assertTrue(json_path and os.path.exists(json_path), out.stdout)
            with open(json_path) as fh:
                report = json.load(fh)
            # the stub's own summary made it through the nonce-authenticated extract step
            self.assertEqual(report["summary"]["one_liner"], "STUB_BACKEND_RAN")
            # the static pass still merged in (backend-agnostic)
            self.assertTrue(any(f["id"].startswith("S-") for f in report["findings"]))

    def test_cmd_backend_static_only_ignores_backend(self):
        # --static-only never invokes any backend, so it needs neither cmd nor key.
        out = self._run_audit(["--backend", "cmd", "--static-only"], FIXTURE)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


class TestBackendSelectionValidation(unittest.TestCase):
    def _run(self, args):
        return subprocess.run(["bash", AUDIT_SH] + args, capture_output=True, text=True)

    def test_unknown_backend_rejected(self):
        out = self._run(["--backend", "bogus", FIXTURE])
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("backend must be", out.stderr)

    def test_both_mode_conflicts_with_non_aider_backend(self):
        out = self._run(["--backend", "claude-api", "--model", "both", FIXTURE])
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("aider", out.stderr)

    def test_cmd_backend_requires_a_command(self):
        out = self._run(["--backend", "cmd", FIXTURE])
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("--backend-cmd", out.stderr)


if __name__ == "__main__":
    unittest.main()
