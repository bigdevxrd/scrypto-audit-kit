"""Importing the package must not mutate the importing process (issue #5).

Up to v0.7.0, `bin/__init__.py` did `sys.path.insert(0, <package dir>)` so the modules' bare
cross-imports (`import sak_lib`) resolved when `bin/` was imported as `scrypto_audit_kit`. That
insert was process-global and at index 0, so any application importing the kit had `attest`,
`sak_lib`, `static_analysis`, `gen_tests`, `llm_audit`, `mcp_server` and `ci_gate` redirected to
ours for the rest of its run — including modules in its own working directory.

These tests run the real failure in a subprocess against a synthesized "consumer app", so they
need no install and fail loudly if the insert ever comes back.
"""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(ROOT, "bin")

# The kit's module names that a consuming application could plausibly also use.
SHADOWABLE = ["sak_lib", "static_analysis", "attest", "gen_tests", "llm_audit", "mcp_server"]


def _consumer_app(tmp, body):
    """A directory that owns modules named like ours, plus a script exercising `body`."""
    for name in SHADOWABLE:
        with open(os.path.join(tmp, name + ".py"), "w", encoding="utf-8") as fh:
            fh.write(f"SENTINEL = {name!r}\n")
    script = os.path.join(tmp, "app.py")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(body))
    return script


def _importable_as_package():
    """A directory on which `import scrypto_audit_kit` resolves to this repo's bin/.

    pyproject maps package-dir {"scrypto_audit_kit" = "bin"}, so only an INSTALL normally
    produces that name. Mirror it with a symlink instead: these tests must run in a bare clone
    with nothing installed, and the property under test (does importing mutate sys.path?) is
    identical either way. Kept out of the consumer's cwd so it does not itself shadow anything.
    """
    link_dir = tempfile.mkdtemp()
    link = os.path.join(link_dir, "scrypto_audit_kit")
    if not os.path.exists(link):
        os.symlink(BIN, link)
    return link_dir


def _run(script, cwd):
    """Run the consumer app with the kit importable as a package, as a pip install would."""
    env = dict(os.environ)
    env["PYTHONPATH"] = _importable_as_package()
    return subprocess.run([sys.executable, script], cwd=cwd, env=env,
                          capture_output=True, text=True)


class TestPackageImportIsSideEffectFree(unittest.TestCase):

    def test_importing_the_package_does_not_touch_sys_path(self):
        tmp = tempfile.mkdtemp()
        script = _consumer_app(tmp, """
            import sys
            before = list(sys.path)
            import scrypto_audit_kit
            after = list(sys.path)
            added = [p for p in after if p not in before]
            print("ADDED:" + repr(added))
            assert added == [], f"import mutated sys.path: {added}"
            print("OK")
        """)
        r = _run(script, tmp)
        self.assertIn("OK", r.stdout, f"stdout={r.stdout} stderr={r.stderr}")

    def test_consumer_modules_are_not_shadowed(self):
        tmp = tempfile.mkdtemp()
        script = _consumer_app(tmp, """
            import scrypto_audit_kit          # the advertised SDK import
            import sak_lib, static_analysis, attest, gen_tests
            for m in (sak_lib, static_analysis, attest, gen_tests):
                assert getattr(m, "SENTINEL", None) is not None, (
                    f"{m.__name__} resolved to the kit's copy at {m.__file__}")
            print("OK")
        """)
        r = _run(script, tmp)
        self.assertIn("OK", r.stdout, f"stdout={r.stdout} stderr={r.stderr}")

    def test_the_kit_still_uses_its_own_modules(self):
        """The flip side: the consumer must not shadow US either."""
        tmp = tempfile.mkdtemp()
        script = _consumer_app(tmp, """
            from scrypto_audit_kit import static_analysis, sak_lib
            assert getattr(static_analysis, "SENTINEL", None) is None, "consumer shadowed the kit"
            assert hasattr(static_analysis, "analyze_package"), "kit module is not the real one"
            assert hasattr(sak_lib, "gate_verdict")
            print("OK")
        """)
        r = _run(script, tmp)
        self.assertIn("OK", r.stdout, f"stdout={r.stdout} stderr={r.stderr}")

    def test_init_contains_no_sys_path_mutation(self):
        with open(os.path.join(BIN, "__init__.py"), encoding="utf-8") as fh:
            src = fh.read()
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        for bad in ("sys.path.insert", "sys.path.append", "sys.path +="):
            self.assertNotIn(bad, code, f"{bad} is back in bin/__init__.py")

    def test_direct_script_execution_still_works(self):
        """The bare-clone path the sys.path insert originally existed to support."""
        r = subprocess.run([sys.executable, os.path.join(BIN, "static_analysis.py"),
                            os.path.join(ROOT, "examples", "vulnerable-vault")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("finding(s)", r.stderr)

    def test_examples_do_not_pollute_sys_path_when_installed(self):
        """The kit's own example agents must not teach the pattern we just removed.

        Every `sys.path.insert` in an example must sit inside an `except ImportError:` handler,
        i.e. it runs only when the package genuinely is not installed. Checked with ast rather
        than by scanning text: a textual "is there an except ImportError above this line?" scan
        matches a handler from an unrelated earlier block and passes on the very code it is
        meant to catch.
        """
        import ast
        for name in ("mcp_client.py", "static_gate.py", "audit_fix_verify.py"):
            path = os.path.join(ROOT, "examples", "agents", name)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)

            guarded = set()
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                names = []
                if isinstance(node.type, ast.Name):
                    names = [node.type.id]
                elif isinstance(node.type, ast.Tuple):
                    names = [e.id for e in node.type.elts if isinstance(e, ast.Name)]
                if "ImportError" in names or "ModuleNotFoundError" in names:
                    for child in ast.walk(node):
                        guarded.add(id(child))

            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "insert"
                        and isinstance(node.func.value, ast.Attribute)
                        and node.func.value.attr == "path"):
                    self.assertIn(id(node), guarded,
                                  f"{name}:{node.lineno}: sys.path.insert outside an "
                                  f"ImportError fallback — it runs even when installed")


if __name__ == "__main__":
    unittest.main()
