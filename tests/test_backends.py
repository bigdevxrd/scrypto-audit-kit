"""Tests for the interchangeable LLM backends (docs/backends.md).

Three surfaces, all exercised with NO API key and NO model call:
  * bin/llm_audit.py `build_request` — the claude-api backend's markdown-mode request
    assembly (pure).
  * bin/llm_audit.py `--structured` — the opt-in structured-output mode (design doc:
    docs/design/structured-output-mode-2026-07-18.md): tool-schema derivation, request
    assembly, and canned-response handling (including the malformed-response error path).
  * audit.sh `--backend cmd` — the bring-your-own contract, driven end-to-end by a stub agent
    that emits a nonce-stamped report. Also the backend-selection validation errors.

The `anthropic` package is never imported (build_request, build_structured_request, and
--dry-run don't need it — nor does feeding a canned response object straight into
extract_tool_input), and ANTHROPIC_API_KEY is stripped from the cmd-backend run so a test can
never bill a model call.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import llm_audit  # noqa: E402

AUDIT_SH = os.path.join(ROOT, "audit.sh")
FIXTURE = os.path.join(ROOT, "examples", "vulnerable-vault")
PROMPT = os.path.join(ROOT, "prompts", "audit.md")
CHECKLIST = os.path.join(ROOT, "prompts", "checklist.md")
REPORT_SCHEMA = os.path.join(ROOT, "schema", "audit-report.schema.json")


def _have_jsonschema():
    try:
        import jsonschema  # noqa: F401
        return True
    except ImportError:
        return False


def _tool_use_block(input_dict, name=llm_audit.TOOL_NAME):
    return SimpleNamespace(type="tool_use", name=name, input=input_dict)


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _canned_message(content, stop_reason="tool_use"):
    """A minimal stand-in for an anthropic.types.Message — only the attributes
    extract_tool_input / _run actually read (.content, .stop_reason)."""
    return SimpleNamespace(content=content, stop_reason=stop_reason)

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
        self.assertEqual(manifest["mode"], "markdown", "default is markdown mode, unchanged")
        self.assertEqual(manifest["model"], "claude-sonnet-4-6")
        self.assertTrue(manifest["cache_breakpoint"])
        self.assertTrue(manifest["nonce_in_user_turn"])
        self.assertTrue(manifest["untrusted_banner"])
        self.assertEqual(manifest["target_files"], 2)


class TestStructuredMode(unittest.TestCase):
    """--structured (docs/design/structured-output-mode-2026-07-18.md): a forced tool call
    replaces the markdown + JSON-appendix contract, opt-in, default off. Every test here is
    either pure request/schema assembly or feeds a hand-built canned response object into the
    response-handling code — no `anthropic` import, no network, no API key, matching
    `test_dry_run_needs_no_api_key_or_anthropic` above."""

    REPORT_SCHEMA_DICT = llm_audit._load_report_schema(REPORT_SCHEMA)

    # A minimal but schema-shaped model-authored subset, reused across several tests.
    MODEL_SUBSET = {
        "summary": {"overall_risk": "medium", "one_liner": "One reentrancy-adjacent finding."},
        "findings": [{
            "id": "F-001", "severity": "medium", "class": "Reentrancy",
            "location": "src/lib.rs:42", "what": "State written after external call.",
            "why": "Reentrancy risk.", "suggested_direction": "Checks-effects-interactions.",
            "confidence": "high",
        }],
        "checklist_coverage": [{"class": "Reentrancy", "status": "findings", "findings": ["F-001"]}],
        "open_questions": ["Unverified: upgrade authority."],
    }

    def _structured_req(self, **overrides):
        kwargs = dict(
            prompt_text="AUDITOR ROLE PROMPT",
            context_files=[CHECKLIST],
            target_files=[os.path.join(FIXTURE, "src", "lib.rs")],
            pkg_root=FIXTURE,
            report_schema=self.REPORT_SCHEMA_DICT,
            model="claude-sonnet-4-6",
        )
        kwargs.update(overrides)
        return llm_audit.build_structured_request(**kwargs)

    # ---- request assembly --------------------------------------------------------------

    def test_forces_the_tool_choice(self):
        req = self._structured_req()
        self.assertEqual(req["tool_choice"], {"type": "tool", "name": "submit_audit_report"})
        self.assertEqual(len(req["tools"]), 1)
        self.assertEqual(req["tools"][0]["name"], "submit_audit_report")

    def test_no_nonce_directive_in_user_turn(self):
        # No markdown appendix to authenticate in structured mode, so no nonce directive.
        req = self._structured_req()
        user_text = req["messages"][0]["content"][0]["text"]
        self.assertNotIn("sak:nonce:", user_text)
        self.assertIn("UNTRUSTED BLUEPRINT SOURCE", user_text)
        self.assertIn("submit_audit_report", user_text)

    def test_cached_system_prefix_is_byte_identical_to_markdown_mode(self):
        # design doc §4: the cache hit must carry across both modes.
        structured = self._structured_req()
        markdown = llm_audit.build_request(
            prompt_text="AUDITOR ROLE PROMPT", context_files=[CHECKLIST],
            target_files=[os.path.join(FIXTURE, "src", "lib.rs")], nonce="N1", pkg_root=FIXTURE,
            model="claude-sonnet-4-6",
        )
        self.assertEqual(structured["system"], markdown["system"])

    # ---- tool-schema derivation (schema-validation) ------------------------------------

    def test_tool_schema_is_subset_of_report_schema(self):
        tool_schema = llm_audit._tool_schema_from_report_schema(self.REPORT_SCHEMA_DICT)
        report_props = set(self.REPORT_SCHEMA_DICT["properties"])
        self.assertTrue(set(tool_schema["properties"]).issubset(report_props))
        self.assertNotIn("kit", tool_schema["properties"], "kit is harness-stamped, never the model")
        self.assertNotIn("target", tool_schema["properties"], "target is harness-stamped, never the model")
        self.assertEqual(sorted(tool_schema["required"]), sorted(llm_audit.MODEL_SUBSET_REQUIRED))
        self.assertFalse(tool_schema["additionalProperties"])

    def test_severity_is_inlined_and_identical_in_both_spots(self):
        tool_schema = llm_audit._tool_schema_from_report_schema(self.REPORT_SCHEMA_DICT)
        self.assertNotIn("$ref", json.dumps(tool_schema), "design doc §3: $ref inlined, not left as a pointer")
        overall_risk = tool_schema["properties"]["summary"]["properties"]["overall_risk"]
        severity = tool_schema["properties"]["findings"]["items"]["properties"]["severity"]
        expected = self.REPORT_SCHEMA_DICT["$defs"]["severity"]
        self.assertEqual(overall_risk, expected)
        self.assertEqual(severity, expected)

    def test_tool_schema_is_well_formed_jsonschema(self):
        if not _have_jsonschema():
            self.skipTest("jsonschema not installed")
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema(llm_audit._tool_schema_from_report_schema(self.REPORT_SCHEMA_DICT))

    def test_model_subset_fixture_validates_against_the_derived_tool_schema(self):
        # Proves MODEL_SUBSET (reused below as a canned tool_use.input) is realistic, not just
        # schema-shaped by construction.
        if not _have_jsonschema():
            self.skipTest("jsonschema not installed")
        from jsonschema import Draft202012Validator
        tool_schema = llm_audit._tool_schema_from_report_schema(self.REPORT_SCHEMA_DICT)
        Draft202012Validator(tool_schema).validate(self.MODEL_SUBSET)

    # ---- --dry-run -----------------------------------------------------------------------

    def test_structured_dry_run(self):
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "bin", "llm_audit.py"), "--structured", "--dry-run",
             "--prompt", PROMPT, "--pkg-root", FIXTURE, "--read", CHECKLIST,
             os.path.join(FIXTURE, "Cargo.toml"), os.path.join(FIXTURE, "src", "lib.rs")],
            capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        manifest = json.loads(out.stdout)
        self.assertEqual(manifest["mode"], "structured")
        self.assertEqual(manifest["tool_name"], "submit_audit_report")
        self.assertTrue(manifest["forced_tool_choice"])
        self.assertEqual(sorted(manifest["tool_schema_required"]), sorted(llm_audit.MODEL_SUBSET_REQUIRED))
        self.assertTrue(manifest["cache_breakpoint"])

    def test_nonce_with_structured_warns_but_still_succeeds(self):
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "bin", "llm_audit.py"), "--structured", "--dry-run",
             "--prompt", PROMPT, "--nonce", "N1", "--pkg-root", FIXTURE, "--read", CHECKLIST,
             os.path.join(FIXTURE, "Cargo.toml"), os.path.join(FIXTURE, "src", "lib.rs")],
            capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("--nonce is ignored", out.stderr)

    # ---- response handling: happy path + the malformed-response error path -------------

    def test_extract_tool_input_returns_the_validated_dict(self):
        message = _canned_message([_tool_use_block(self.MODEL_SUBSET)])
        self.assertIs(llm_audit.extract_tool_input(message), self.MODEL_SUBSET)

    def test_extract_tool_input_ignores_a_differently_named_tool_use(self):
        # Belt-and-braces: tool_choice already forces the name, but don't trust content blindly.
        message = _canned_message([_tool_use_block({"bogus": True}, name="some_other_tool")])
        with self.assertRaises(SystemExit):
            llm_audit.extract_tool_input(message)

    def test_malformed_response_no_tool_use_raises_clean_systemexit(self):
        # The model emitted prose instead of calling the tool. tool_choice forced the call, so
        # this is a real error — must fail loud with an actionable message, not hang or crash
        # with a stack trace, so an operator knows to retry the run.
        message = _canned_message([_text_block("I have some thoughts but no tool call.")],
                                   stop_reason="end_turn")
        with self.assertRaises(SystemExit) as ctx:
            llm_audit.extract_tool_input(message)
        self.assertIn("did not emit", str(ctx.exception))
        self.assertIn("submit_audit_report", str(ctx.exception))

    def test_malformed_response_truncated_at_max_tokens_raises_actionable_systemexit(self):
        message = _canned_message([], stop_reason="max_tokens")
        with self.assertRaises(SystemExit) as ctx:
            llm_audit.extract_tool_input(message)
        self.assertIn("max_tokens", str(ctx.exception))
        self.assertIn("SAK_MAX_TOKENS", str(ctx.exception))

    def test_malformed_response_refusal_raises_actionable_systemexit(self):
        # Adaptation vs. the design doc's sketch (which only handled max_tokens): a forced
        # tool_choice doesn't rule out a safety refusal.
        message = _canned_message([], stop_reason="refusal")
        with self.assertRaises(SystemExit) as ctx:
            llm_audit.extract_tool_input(message)
        self.assertIn("refused", str(ctx.exception))

    # ---- assemble_report: harness stamping building block --------------------------------

    def test_assemble_report_stamps_provenance(self):
        provenance = {
            "kit": {"version": "0.6.0", "model": "claude-sonnet-4-6",
                    "checklist_version": "1.0", "generated_at": "2026-08-13T00:00:00Z"},
            "target": {"repo": "scrypto-audit-kit", "package": "vulnerable-vault"},
        }
        report = llm_audit.assemble_report(self.MODEL_SUBSET, provenance)
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["kit"], provenance["kit"])
        self.assertEqual(report["target"], provenance["target"])
        self.assertEqual(report["findings"], self.MODEL_SUBSET["findings"])
        if not _have_jsonschema():
            self.skipTest("jsonschema not installed — skipping the full-report validation half")
        from jsonschema import Draft202012Validator
        Draft202012Validator(self.REPORT_SCHEMA_DICT).validate(report)


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
