"""Regression guard against two kinds of leak into this PUBLIC repo.

1. Private identifiers (names that must never be published). The targets are deliberately NOT
   stored in this file or anywhere else in the tree: a public repo cannot hold the list of
   things it keeps out, and a hash of a short, guessable name is only a dictionary away from the
   name. They are read at run time from a local, gitignored file or from the environment (see
   `_load_local_targets`). With no source configured the check SKIPS, loudly, and
   SAK_REQUIRE_FORBIDDEN_TOKENS=1 turns that skip into a failure for a run that must enforce it.

2. A real third-party project name close enough to a verdict word ("fail", "vulnerable",
   "exploit", ...) that a reader would take it as a disclosed finding about that party. Naming a
   public protocol on its own is not the problem -- references/*.md and the README discuss
   several by name as ordinary technical writing. Only the co-occurrence with a verdict is. This
   mirrors the posture scanner's publication gate (docs/posture-scanner.md): facts about
   entities this project operates are published, facts about named third parties are not.

Everything here operates on `git ls-files`, read straight off disk in the working tree: never on
gitignored files (scanner/data/cohort-full.json, scanner/results-full/) and never on history.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _tracked_files():
    """Every path `git ls-files` reports, i.e. every file actually tracked in the index --
    independent of what a human happens to have open or what's gitignored on disk."""
    result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed (exit {result.returncode}): {result.stderr}")
    return [line for line in result.stdout.splitlines() if line]


def _inside_git_worktree():
    """True when ROOT carries a `.git` entry (a directory, or the file a linked worktree uses).
    An sdist unpacked by a packager has none, and the tests below that read `git ls-files` have
    nothing to look at there; they skip rather than fail so the sdist can run its own suite (the
    release workflow's smoke step does exactly that).

    The check is on the file system ON PURPOSE, not on `git rev-parse` succeeding: when `.git`
    exists but git itself is missing or refuses (PATH, a "dubious ownership" error in container
    CI), this guard must RUN and fail loudly in test_git_is_available_and_this_is_a_repo -- a
    skip there would turn the public-leak guard green without scanning anything."""
    return os.path.exists(os.path.join(ROOT, ".git"))


_GIT_REQUIRED = unittest.skipUnless(
    _inside_git_worktree(), "not a git work tree (e.g. an unpacked sdist): nothing is tracked to scan")


def _read_text(rel_path):
    """Read a tracked file's current working-tree content as text, or None for anything that
    isn't text (there are none of those in this repo today, but a future binary asset -- a
    logo, a PDF -- must not crash this test, just be silently skipped)."""
    try:
        with open(os.path.join(ROOT, rel_path), encoding="utf-8") as fh:
            return fh.read()
    except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
        return None


# ---------------------------------------------------------------------------
# (a) Strings that must never appear in any tracked file.
# ---------------------------------------------------------------------------
# Safe to state openly: generic shapes, not identities.
_FORBIDDEN_LITERAL_PATTERNS = (
    "/Users/",           # a local filesystem path, from anyone's machine
)

# The out-of-band source for everything that is NOT safe to state openly. One entry per line;
# blank lines and `#` comments are ignored.
#
#   some-name              a private identifier, matched case-insensitively. A name shaped like
#                          a repo or service (lowercase alphanumerics joined by hyphens) matches
#                          as a whole token and as a hyphen-delimited prefix, so `some-name` also
#                          catches `some-name-suffix`. Any other shape (it contains a dot, an
#                          at-sign, a space ...) matches as a plain substring.
#   name: Some Project     an extra third-party project name for the co-occurrence, fixture
#                          filename and public-cohort checks in (b)-(d) below.
#
# Looked up, in order: the file named by SAK_FORBIDDEN_TOKENS_FILE (an error if set but
# unreadable), else tests/.forbidden-tokens.local (gitignored); then SAK_FORBIDDEN_TOKENS,
# newline-separated, for a CI secret. All of them are merged.
LOCAL_TARGETS_PATH = os.path.join(HERE, ".forbidden-tokens.local")
_ENV_FILE = "SAK_FORBIDDEN_TOKENS_FILE"
_ENV_INLINE = "SAK_FORBIDDEN_TOKENS"
_ENV_REQUIRE = "SAK_REQUIRE_FORBIDDEN_TOKENS"

# Tokens are lowercase runs of alphanumerics joined by hyphens -- the shape a repo, service or
# account name takes. Splitting this way means `name@example.com` yields `name`, and
# `some-repo/FILE.md` yields `some-repo`, so a match does not depend on surrounding punctuation.
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def _parse_targets(text):
    """(private entries, extra third-party names) from the text of a targets source."""
    entries, names = set(), set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("name:"):
            name = line[len("name:"):].strip()
            if name:
                names.add(name)
        else:
            entries.add(line.lower())
    return entries, names


def _load_local_targets(environ=None, default_path=LOCAL_TARGETS_PATH):
    """Read the out-of-band targets. Returns (private entries, extra third-party names); both
    are empty when nothing is configured."""
    environ = os.environ if environ is None else environ
    chunks = []
    explicit = environ.get(_ENV_FILE)
    path = explicit or default_path
    try:
        with open(path, encoding="utf-8") as fh:
            chunks.append(fh.read())
    except FileNotFoundError:
        if explicit:
            # A mistyped path must not quietly turn the guard off.
            raise RuntimeError(f"{_ENV_FILE} is set but names no readable file")
    inline = environ.get(_ENV_INLINE)
    if inline:
        chunks.append(inline)
    return _parse_targets("\n".join(chunks))


def _tokens_with_prefixes(text):
    """Every token in `text`, plus each of its hyphen-delimited prefixes, so `a-b-c` also yields
    `a-b` and `a`. One entry then covers a name and everything suffixed onto it."""
    seen = set()
    for match in _TOKEN_RE.finditer(text.lower()):
        parts = match.group(0).split("-")
        for i in range(1, len(parts) + 1):
            candidate = "-".join(parts[:i])
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def _matching_lines(text, entries):
    """1-based line numbers of `text` where any private entry appears."""
    token_entries = {e for e in entries if _TOKEN_RE.fullmatch(e)}
    substring_entries = entries - token_entries
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if (token_entries and token_entries & set(_tokens_with_prefixes(line))) or any(
            sub in lowered for sub in substring_entries
        ):
            hits.append(number)
    return hits


def _skip_or_fail_without_targets(testcase, entries):
    if entries:
        return
    message = (
        "no private-identifier targets are configured (set SAK_FORBIDDEN_TOKENS_FILE or "
        "SAK_FORBIDDEN_TOKENS, or create tests/.forbidden-tokens.local), so this guard did NOT "
        "run"
    )
    if os.environ.get(_ENV_REQUIRE) == "1":
        testcase.fail(message + f" and {_ENV_REQUIRE}=1 says it must")
    sys.stderr.write(f"\nWARNING: {message}\n")
    testcase.skipTest(message)


_LOCK_SUFFIX = ".lock"

# This file necessarily CONTAINS every string its literal and co-occurrence layers hunt for --
# that is what a pattern list is -- so both TEXT-MATCHING layers skip this one file, or it would
# fail the moment it is committed. The structural layers (fixture filenames, cohort.json) still
# cover it. The control that replaces the automated one here is review: the lists are short and
# any change to them is visible in a diff.
_SELF = "tests/test_no_forbidden_strings.py"


@_GIT_REQUIRED
class TestNoForbiddenStringsInTrackedFiles(unittest.TestCase):
    def test_git_is_available_and_this_is_a_repo(self):
        # Fails loudly rather than every other test in this file silently reporting "no
        # matches" because git itself isn't there to look.
        result = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "true")

    def test_this_file_exempts_itself_and_nothing_else(self):
        # Pins the exemption's scope: if someone widens _SELF into a general skip-list, this
        # fails. An exemption that can grow silently is how a gate stops being a gate.
        self.assertEqual(_SELF, "tests/test_no_forbidden_strings.py")
        self.assertIn(_SELF, _tracked_files(),
                      "the self-exemption names a path git does not track -- it has gone stale")

    def test_no_forbidden_pattern_appears_in_any_tracked_file(self):
        files = [f for f in _tracked_files()
                 if not f.endswith(_LOCK_SUFFIX) and f != _SELF]
        for pattern in _FORBIDDEN_LITERAL_PATTERNS:
            needle = pattern.lower()
            hits = []
            for path in files:
                text = _read_text(path)
                if text is None:
                    continue
                if needle in text.lower():
                    lines = [i + 1 for i, line in enumerate(text.splitlines()) if needle in line.lower()]
                    hits.append(f"{path}:{','.join(map(str, lines))}")
            with self.subTest(pattern=pattern):
                self.assertEqual(
                    hits, [],
                    f"forbidden pattern {pattern!r} found in tracked file(s):\n" + "\n".join(hits),
                )

    def test_no_local_target_appears_in_any_tracked_file(self):
        """The sensitive half of the guard. Scans THIS file too: it holds none of the targets."""
        entries, _ = _load_local_targets()
        _skip_or_fail_without_targets(self, entries)
        hits = []
        for path in [f for f in _tracked_files() if not f.endswith(_LOCK_SUFFIX)]:
            text = _read_text(path)
            if text is None:
                continue
            lines = _matching_lines(text, entries)
            if lines:
                # Deliberately does NOT print the match: a failure here is readable by whoever
                # can already see the file, without the message itself becoming the disclosure.
                hits.append(f"{path}:{','.join(map(str, lines))}")
        self.assertEqual(
            hits, [],
            "a protected identifier appeared in tracked file(s) (name withheld by design; "
            "open the path and line to see it):\n" + "\n".join(hits),
        )


class TestTargetMachinery(unittest.TestCase):
    """The loader and matcher, proven on meaningless canary strings, so a quietly broken guard
    cannot pass as a clean one."""

    def test_matcher_covers_token_prefix_and_substring_shapes(self):
        entries = {"canary-guard", "canary.two"}
        self.assertEqual(_matching_lines("see canary-guard/SOME-FILE.md\nnothing", entries), [1])
        self.assertEqual(_matching_lines("x\ny canary-guard-selftest z", entries), [2])
        self.assertEqual(_matching_lines("a Canary.Two b", entries), [1])
        self.assertEqual(_matching_lines("canary guard, canaryguard, other", entries), [])

    def test_tokeniser_extracts_a_hyphenated_name_from_a_path(self):
        tokens = set(_tokens_with_prefixes("see canary-guard-selftest/SOME-FILE.md"))
        self.assertIn("canary-guard-selftest", tokens)
        self.assertIn("canary-guard", tokens)
        self.assertIn("canary", tokens)

    def test_parse_targets_handles_comments_names_and_case(self):
        entries, names = _parse_targets(
            "# a comment\n\n  Canary-One  \nname: Example Project\nNAME:Other Example\ncanary.two\n"
        )
        self.assertEqual(entries, {"canary-one", "canary.two"})
        self.assertEqual(names, {"Example Project", "Other Example"})

    def test_loader_merges_file_and_inline_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("canary-file\nname: File Project\n")
            entries, names = _load_local_targets(
                {_ENV_FILE: path, _ENV_INLINE: "canary-inline\nname: Inline Project"}
            )
        self.assertEqual(entries, {"canary-file", "canary-inline"})
        self.assertEqual(names, {"File Project", "Inline Project"})

    def test_loader_returns_nothing_when_nothing_is_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_load_local_targets({}, os.path.join(tmp, "absent")), (set(), set()))

    def test_loader_refuses_an_explicit_path_that_does_not_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                _load_local_targets({_ENV_FILE: os.path.join(tmp, "absent")})

    @_GIT_REQUIRED
    def test_no_targets_file_is_ever_tracked(self):
        self.assertNotIn(os.path.relpath(LOCAL_TARGETS_PATH, ROOT), _tracked_files())


# ---------------------------------------------------------------------------
# (b) Verdict-shaped co-occurrence -- a real third-party name near a verdict word.
# ---------------------------------------------------------------------------
# Public protocols that references/*.md and the README name as technical subjects. Naming one is
# fine; naming one NEXT TO a verdict word reads as a disclosed finding about it. Further names
# to watch belong in the local targets file as `name: <Project>`, not here.
_THIRD_PARTY_NAMES = (
    "Ociswap", "CaviarNine", "DefiPlaza", "Astrolescent", "Weft",
)


def _third_party_names():
    _, extra = _load_local_targets()
    return tuple(_THIRD_PARTY_NAMES) + tuple(sorted(extra))


# Words/phrases that turn a bare mention into a disclosed finding. Deliberately substring-y
# (e.g. "fail" also catches "fails"/"failing"/"failed"): the gate only fires when a verdict is
# ALSO within range of a third-party name, so a wide net here costs no false positives alone.
_VERDICT_WORDS = (
    "fail", "vulnerable", "flaw", "weakness", "does not", "half-pair", "exploit",
    "unrotatable", "missing",
)

_PROXIMITY_WINDOW_CHARS = 250

_VERDICT_RE = re.compile("|".join(re.escape(v) for v in _VERDICT_WORDS), re.IGNORECASE)

# Files that legitimately carry a third-party name within _PROXIMITY_WINDOW_CHARS of a verdict
# word, and why. Keep this small -- every entry is a place a real regression could hide behind
# the exemption, so each one names the specific mechanism that makes it safe. A file NOT on this
# list that starts tripping the gate is doing what this test is for; fix the content.
_CO_OCCURRENCE_ALLOWLIST = {
    # This file defines the name list and the verdict list on adjacent lines, so it matches
    # itself by construction. Not a disclosure: it is the detector, not a finding about anyone.
    _SELF:
        "defines the name and verdict vocabularies this check searches for; it necessarily "
        "contains both and would otherwise flag itself the moment it is committed",
    # Cites this repo's OWN reference-pattern filename (references/caviarnine-hyperstake-
    # patterns.md) as the source of a finding about OUR OWN pre-audited vault -- "missing" is
    # near "caviarnine" only because the filename contains it, not because the finding is about
    # CaviarNine.
    "examples/vulnerable-vault.pre-audit.md":
        "cites references/caviarnine-hyperstake-patterns.md by filename; the finding is about "
        "our own pre-audited vault, not about CaviarNine",
}


@_GIT_REQUIRED
class TestVerdictShapedThirdPartyCoOccurrence(unittest.TestCase):
    """A third-party project name within _PROXIMITY_WINDOW_CHARS characters of a verdict word,
    anywhere in any tracked file, unless that file is on the documented allow-list above.

    This intentionally does NOT ban third-party names outright (see this module's docstring) --
    only their co-occurrence with a verdict, which is what turns a mention into a disclosed
    finding.
    """

    def test_no_unallowed_name_verdict_co_occurrence_in_any_tracked_file(self):
        name_re = re.compile("|".join(re.escape(n) for n in _third_party_names()), re.IGNORECASE)
        violations = []
        for path in _tracked_files():
            if path.endswith(_LOCK_SUFFIX) or path in _CO_OCCURRENCE_ALLOWLIST:
                continue
            text = _read_text(path)
            if text is None:
                continue
            for name_match in name_re.finditer(text):
                start = max(0, name_match.start() - _PROXIMITY_WINDOW_CHARS)
                end = min(len(text), name_match.end() + _PROXIMITY_WINDOW_CHARS)
                verdict_match = _VERDICT_RE.search(text[start:end])
                if verdict_match:
                    line_no = text.count("\n", 0, name_match.start()) + 1
                    violations.append(
                        f"{path}:{line_no}: {name_match.group()!r} near verdict "
                        f"{verdict_match.group()!r}"
                    )
        self.assertEqual(
            violations, [],
            "verdict-shaped third-party co-occurrence found (a real project name near a "
            "verdict word reads as a disclosed finding about that party) -- either the content "
            "is a genuine leak and needs anonymising, or this file belongs on the documented "
            "_CO_OCCURRENCE_ALLOWLIST above with a stated reason:\n" + "\n".join(violations),
        )


# ---------------------------------------------------------------------------
# (c) Third-party names as fixture FILENAMES under examples/posture-scanner/.
# ---------------------------------------------------------------------------
# A fixture filename that pairs a company with a scan fixture already reads as "we scanned this",
# no nearby verdict word required. Scoped to this one directory, not repo-wide: a knowledge-base
# file may be named after its subject (references/caviarnine-hyperstake-patterns.md is exactly
# that, and is fine); a scanner fixture may not.
FIXTURES_DIR = os.path.join(ROOT, "examples", "posture-scanner")


class TestNoThirdPartyNameInFixtureFilenames(unittest.TestCase):
    def test_no_known_third_party_name_in_a_posture_scanner_fixture_filename(self):
        for fname in os.listdir(FIXTURES_DIR):
            for name in _third_party_names():
                with self.subTest(file=fname, name=name):
                    self.assertNotIn(name.lower(), fname.lower())


# ---------------------------------------------------------------------------
# (d) scanner/data/cohort.json -- the public cohort file itself, defense in depth.
# ---------------------------------------------------------------------------
# scanner/data/cohort.json is committed and served raw from GitHub. Naming a third party there
# as a scan target would tell the world who is being scanned while the publication gate withholds
# the results (docs/posture-scanner.md#the-cohort). This duplicates part of what the checks
# above already cover for this file; a bare name ban on the one file GitHub serves raw as "the
# list of what we scan" is cheap insurance.
COHORT_PATH = os.path.join(ROOT, "scanner", "data", "cohort.json")


@_GIT_REQUIRED
class TestPublicCohortNamesNoThirdParty(unittest.TestCase):
    def setUp(self):
        with open(COHORT_PATH, encoding="utf-8") as fh:
            self.raw_text = fh.read()

    def test_no_known_third_party_name_appears_in_the_public_cohort_file(self):
        for name in _third_party_names():
            with self.subTest(name=name):
                self.assertNotIn(name.lower(), self.raw_text.lower())


class TestGitGuardIsFilesystemBased(unittest.TestCase):
    """Regression guard for the skip predicate above: it must key on `.git` existing, never on git
    succeeding. A real checkout with a broken git must FAIL the tracked-files tests, not skip them."""

    def test_guard_is_true_with_a_dot_git_entry_even_with_git_unreachable(self):
        # A scratch ROOT that carries a `.git` entry, so this runs the same way in a checkout and in an
        # unpacked sdist (which has no real `.git` and would otherwise fail the guard's own premise).
        with tempfile.TemporaryDirectory() as fake_root:
            with open(os.path.join(fake_root, ".git"), "w", encoding="utf-8") as fh:
                fh.write("gitdir: /nonexistent\n")
            with mock.patch.dict(globals(), {"ROOT": fake_root}), \
                    mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
                self.assertTrue(_inside_git_worktree())

    def test_guard_is_false_without_a_dot_git_entry(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertFalse(_inside_git_worktree())


if __name__ == "__main__":
    unittest.main()
