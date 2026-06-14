"""Drift guard for the formal tool contracts (schema/mcp-tools.schema.json).

Two things must stay true or this fails:
  1. Every contract's inputSchema matches the LIVE function signature in bin/mcp_server.py
     (property names == params, required == params-without-defaults, declared types line up).
  2. The cheap, no-API tools' REAL output on the committed fixture validates against the
     documented outputSchema.

So the published contract can't silently drift from the code an agent developer calls.
"""
import inspect
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)

import mcp_server  # noqa: E402

CONTRACTS = os.path.join(ROOT, "schema", "mcp-tools.schema.json")
SAMPLE = os.path.join(ROOT, "examples", "vulnerable-vault.pre-audit.json")
PKG = os.path.join(ROOT, "examples", "vulnerable-vault")

_TYPE = {str: "string", bool: "boolean", int: "integer"}


def _have_jsonschema():
    try:
        import jsonschema  # noqa: F401
        return True
    except ImportError:
        return False


class TestToolContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CONTRACTS, encoding="utf-8") as fh:
            cls.catalog = json.load(fh)
        cls.by_name = {t["name"]: t for t in cls.catalog["tools"]}
        cls.tools = mcp_server.TOOLS

    def test_names_and_order_match_TOOLS(self):
        documented = [t["name"] for t in self.catalog["tools"]]
        live = [fn.__name__ for fn in self.tools]
        self.assertEqual(documented, live,
                         "schema/mcp-tools.schema.json is out of sync with mcp_server.TOOLS")

    def _declared_type(self, prop):
        """A property's JSON type, following one level of $ref into the catalog's $defs."""
        if "$ref" in prop:
            prop = self.catalog["$defs"][prop["$ref"].split("/")[-1]]
        t = prop.get("type")
        if isinstance(t, list):
            non_null = [x for x in t if x != "null"]
            return non_null[0] if non_null else t[0]
        return t

    def test_inputSchema_matches_signature(self):
        for fn in self.tools:
            with self.subTest(tool=fn.__name__):
                schema = self.by_name[fn.__name__]["inputSchema"]
                params = inspect.signature(fn).parameters
                self.assertEqual(schema.get("type"), "object")
                self.assertEqual(set(schema.get("properties", {})), set(params),
                                 "inputSchema properties != function params")
                required = {p for p, par in params.items()
                            if par.default is inspect.Parameter.empty}
                self.assertEqual(set(schema.get("required", [])), required,
                                 "inputSchema required != params without defaults")
                for p, par in params.items():
                    expected = _TYPE.get(par.annotation)
                    if expected:
                        self.assertEqual(self._declared_type(schema["properties"][p]), expected,
                                         f"{p}: declared type should be {expected}")

    def test_every_tool_documents_description_and_output(self):
        for t in self.catalog["tools"]:
            with self.subTest(tool=t["name"]):
                self.assertTrue(t.get("description", "").strip(), "missing description")
                self.assertIn("outputSchema", t)

    def test_schemas_are_well_formed(self):
        if not _have_jsonschema():
            self.skipTest("jsonschema not installed")
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema({"$defs": self.catalog["$defs"]})
        for t in self.catalog["tools"]:
            with self.subTest(tool=t["name"]):
                Draft202012Validator.check_schema(t["inputSchema"])
                Draft202012Validator.check_schema(t["outputSchema"])

    def _validate(self, tool_name, instance):
        from jsonschema import Draft202012Validator
        schema = dict(self.by_name[tool_name]["outputSchema"])
        schema["$defs"] = self.catalog["$defs"]  # attach so #/$defs/... resolves
        Draft202012Validator(schema).validate(instance)

    def test_real_output_matches_contract(self):
        """The cheap, no-API tools' real fixture output validates against the contract."""
        if not _have_jsonschema():
            self.skipTest("jsonschema not installed")
        self._validate("static_scan", mcp_server.static_scan(PKG))
        self._validate("get_findings", mcp_server.get_findings(SAMPLE))
        self._validate("gate", mcp_server.gate(SAMPLE))
        self._validate("propose_tests", mcp_server.propose_tests(PKG))
        self._validate("attestation_payload", mcp_server.attestation_payload(SAMPLE))
        self._validate("get_checklist", mcp_server.get_checklist())
        with open(SAMPLE, encoding="utf-8") as fh:
            first_id = json.load(fh)["findings"][0]["id"]
        self._validate("show_finding_source",
                       mcp_server.show_finding_source(SAMPLE, first_id, PKG))


if __name__ == "__main__":
    unittest.main()
