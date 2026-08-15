#!/usr/bin/env python3
"""Deterministic static analysis for Scrypto — the free, no-API tier of the pre-audit.

A "Slither for Scrypto": a curated set of high-precision rules over the source that catch
mechanical footguns reliably and reproducibly, with zero model calls. Findings are shaped
like schema/audit-report.schema.json (source="static", S-### ids) so they merge cleanly
with the LLM pass into one report.

Design for precision: the source is first run through a comment/string-aware stripper that
blanks the *contents* of comments and string/char literals while preserving every newline,
so code rules don't match inside a comment or a string (hardcoded-address and
hand-rolled-address-check read string literals, todo-comment reads comments, by design). Rules that
must reason about auth read the enable_method_auth! block via _method_auth_index rather than
guessing from the fn signature. Suppress a single finding with a
`// sak:allow <rule-id>` comment on the offending line or the line above.

Stdlib only. Importable (analyze_package) and a CLI. Unit-tested in tests/test_static_analysis.py.
"""
import argparse
import json
import os
import re
import sys

try:  # installed: real submodules of the scrypto_audit_kit package
    from . import sak_lib
except ImportError:  # bare clone / direct script run: bin/ is itself on sys.path
    import sak_lib

# --------------------------------------------------------------------------- stripper


def strip_comments_and_strings(src, keep_strings=False, keep_comments=False):
    """Blank the contents of comments and string/char literals, preserving every newline.

    Handles nested block comments (`/* /* */ */`) and string line-continuations (`"...\\`+newline).
    - default: blank both — what code rules run over.
    - keep_strings: preserve string/char contents (comments still blanked) — for rules that must
      see string literals (e.g. hardcoded addresses).
    - keep_comments: preserve comment contents (strings still blanked) — to find `// sak:allow`
      suppressions and TODO markers without matching them inside string literals.
    """
    out = []
    i, n = 0, len(src)
    state = "code"
    block_depth = 0
    raw_hashes = 0

    def emit_comment(text):
        out.append(text if keep_comments else " " * len(text))

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"; emit_comment("//"); i += 2; continue
            if c == "/" and nxt == "*":
                state = "block_comment"; block_depth = 1; emit_comment("/*"); i += 2; continue
            if c == '"':
                state = "string"; out.append('"'); i += 1; continue
            if c == "r" and (nxt == '"' or nxt == "#"):
                j = i + 1
                hashes = 0
                while j < n and src[j] == "#":
                    hashes += 1; j += 1
                if j < n and src[j] == '"':
                    state = "raw_string"; raw_hashes = hashes
                    out.append(src[i:j + 1]); i = j + 1; continue
                out.append(c); i += 1; continue
            if c == "'":
                # char literal ('x' or '\n') vs lifetime ('a) — only blank real char literals
                if nxt == "\\" or (i + 2 < n and src[i + 2] == "'"):
                    state = "char"; out.append("'"); i += 1; continue
                out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        if state == "line_comment":
            if c == "\n":
                state = "code"; out.append("\n")
            else:
                emit_comment(c)
            i += 1; continue
        if state == "block_comment":
            if c == "/" and nxt == "*":
                block_depth += 1; emit_comment("/*"); i += 2; continue
            if c == "*" and nxt == "/":
                block_depth -= 1; emit_comment("*/"); i += 2
                if block_depth == 0:
                    state = "code"
                continue
            out.append(c if keep_comments else ("\n" if c == "\n" else "\t" if c == "\t" else " "))
            i += 1; continue
        if state in ("string", "char"):
            closer = '"' if state == "string" else "'"
            if c == "\\":
                if keep_strings:
                    out.append(c); out.append(nxt)
                elif nxt == "\n":        # line-continuation: keep the newline so line numbers hold
                    out.append(" \n")
                else:
                    out.append("  ")
                i += 2; continue
            if c == closer:
                state = "code"; out.append(closer); i += 1; continue
            out.append(c if keep_strings else ("\n" if c == "\n" else " "))
            i += 1; continue
        if state == "raw_string":
            if c == '"' and src[i + 1:i + 1 + raw_hashes] == "#" * raw_hashes:
                state = "code"; out.append('"' + "#" * raw_hashes); i += 1 + raw_hashes; continue
            out.append(c if keep_strings else ("\n" if c == "\n" else " "))
            i += 1; continue
    return "".join(out)


def _line_of(text, offset):
    """1-indexed line number of a character offset in text."""
    return text.count("\n", 0, offset) + 1


# --------------------------------------------------------------------------- rules

RULES = []


def rule(fn):
    RULES.append(fn)
    return fn


def _matches(lines, pattern):
    """Yield (lineno, match) for a compiled-or-string pattern over 1-indexed lines."""
    rx = re.compile(pattern) if isinstance(pattern, str) else pattern
    for lineno, line in enumerate(lines, 1):
        m = rx.search(line)
        if m:
            yield lineno, line, m


def _finditer_lines(text, pattern):
    """Yield (lineno, line_text, match) for a pattern over the WHOLE stripped text.

    Unlike _matches (line-by-line), this catches a construct split across lines — `take_all\\n()`
    or a rustfmt-wrapped role list — because `\\s*` in the pattern spans the newline. Line-scoped
    rules were evadable by exactly this split; prefer this for any rule whose pattern has a `\\s*`
    a hostile author could stuff a newline into. lineno is the 1-indexed line the match STARTS on.
    """
    rx = re.compile(pattern) if isinstance(pattern, str) else pattern
    lines = text.split("\n")
    for m in rx.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        yield lineno, lines[lineno - 1], m


def _f(line, rule_id, severity, klass, title, what, why, fix):
    return {
        "line": line, "rule": rule_id, "severity": severity, "class": klass,
        "title": title, "what": what, "why": why, "suggested_direction": fix,
    }


@rule
def r_float_usage(ctx):
    # Match f32/f64 as a type reference (preceded by a non-word char: `: f64`, `as f64`, `<f64>`)
    # AND as a numeric-literal suffix (`0.05f64`, `3f32`, `1.5_f64`, and exponent form
    # `1e5f64` / `1.5e3f32`) — the leading `\b` in the old pattern skipped suffixed literals,
    # since a digit before `f` is a word char (no boundary); the exponent group was missing
    # entirely, so `1e5f64` fell through both alternatives (BUG-HUNT-2026-07-18 L3).
    pat = re.compile(r"(?<![A-Za-z0-9_])f(?:32|64)\b"
                     r"|\b\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?f(?:32|64)\b")
    for lineno, line, _m in _matches(ctx["stripped_lines"], pat):
        yield _f(lineno, "float-usage", "high", "Integer / decimal arithmetic",
                 "floating-point type in financial code",
                 f"`{line.strip()[:80]}` uses f32/f64.",
                 "Floats are non-deterministic and lossy; they have no place in on-ledger math.",
                 "Replace with Decimal / integer types.")


@rule
def r_hardcoded_address(ctx):
    # addresses live in string literals → scan with strings kept, comments blanked (no FP in docs).
    # Generic `<entity>_rdx1…` shape covers pool/accountlocker/identity/internal_*/etc., not just a few.
    pat = re.compile(r"\b[a-z_]{3,}_(?:rdx|tdx|sim)1[02-9ac-hj-np-z]{20,}")
    for lineno, line, m in _matches(ctx["code_with_strings_lines"], pat):
        yield _f(lineno, "hardcoded-address", "medium", "External calls / composability",
                 "hardcoded on-ledger address",
                 f"hardcoded `{m.group(0)[:24]}…` in source.",
                 "Hardcoded addresses are brittle across networks/redeploys and bypass whitelisting.",
                 "Inject the address at instantiation (and store it) or via env!(), not inline.")


@rule
def r_hand_rolled_address_check(ctx):
    # the HRP lives in a string literal → strings kept, comments blanked. Whole-text so a
    # rustfmt-wrapped `.starts_with(\n    "account_rdx1",\n)` can't evade a line scan.
    #
    # Deliberately narrow: only a `starts_with` against a Radix HRP. In Scrypto an address is a
    # typed ComponentAddress / ResourceAddress that the engine has already decoded; testing a
    # &str prefix instead means the address arrived as an unvalidated String and is being
    # accepted on shape alone.
    #
    # The network part is REQUIRED, exactly as in the sibling r_hardcoded_address: an entity
    # word alone (`starts_with("pool_")`, `starts_with("component_address")`,
    # `starts_with("internal_state_v2")`) is an ordinary metadata/config-key prefix and was
    # over-flagged when the pattern stopped at the entity list. Demanding `_rdx1` / `_sim1` /
    # `_tdx_<n>_1` — the HRP plus bech32's `1` separator — is what makes the literal an address
    # rather than a word. The entity half is left generic ([a-z_]{3,}) like the sibling rule, so
    # locker/identity/internal_* and any future entity type are covered without a hand-kept list.
    # The `(?:r#*)?` allows a raw string: r_hardcoded_address already matches inside one (the
    # stripper preserves raw-string contents under keep_strings), so anchoring on a bare `"` here
    # made `starts_with(r#"account_rdx1"#)` evade this rule alone.
    #
    # One finding per line, not per match: the real shape is a chain of prefix tests for the
    # mainnet and testnet HRPs (`starts_with("account_rdx1") || starts_with("account_tdx_2_1")`),
    # which is one hand-rolled validator, not two findings.
    pat = re.compile(r"\.starts_with\s*\(\s*&?(?:r#*)?\""
                     r"[a-z_]{3,}_(?:rdx1|sim1|tdx_[0-9a-z]+_1)")
    seen = set()
    for lineno, line, _m in _finditer_lines(ctx["code_with_strings"], pat):
        if lineno in seen:
            continue
        seen.add(lineno)
        yield _f(lineno, "hand-rolled-address-check", "medium", "External calls / composability",
                 "address validated by string prefix, not by bech32m decode",
                 f"`{line.strip()[:80]}` accepts an address on its prefix.",
                 "A prefix (or length, or charset) test is not a bech32m decode: it accepts any "
                 "attacker-chosen string of the right shape, checksum unverified — and an "
                 "is_ascii_alphanumeric charset admits b/i/o/1, which bech32 excludes. Garbage that "
                 "passes is then persisted on-ledger and trusted by every off-chain consumer downstream.",
                 "Take the address as a typed ComponentAddress / ResourceAddress so the engine "
                 "decodes and checksums it; if it must stay a String, reject anything that does not "
                 "round-trip through a bech32m decode.")


@rule
def r_unbounded_take_all(ctx):
    # whole-text so `take_all\n(` (a valid-Rust newline split) can't evade a line scan; also catch
    # the semantically identical full drain written as take(<vault>.amount()).
    pat = re.compile(r"\.take_all\s*\(|\.take\s*\(\s*[\w.]*\.amount\s*\(\s*\)\s*\)")
    for lineno, line, _m in _finditer_lines(ctx["stripped"], pat):
        yield _f(lineno, "unbounded-take-all", "medium", "Resource handling",
                 "unbounded vault drain (take_all / take(amount()))",
                 f"`{line.strip()[:80]}` empties the whole vault in one call.",
                 "An unbounded withdrawal is a large blast radius if the method is ever reachable by the wrong caller.",
                 "Prefer a bounded take(amount) with a per-call cap; reserve full drains for fully-trusted paths.")


@rule
def r_owner_role_none(ctx):
    # whole-text so rustfmt line-wrapping (OwnerRole::None on its own line) can't evade it
    for m in re.finditer(r"prepare_to_globalize\s*\(\s*OwnerRole::None", ctx["stripped"]):
        yield _f(_line_of(ctx["stripped"], m.start()), "owner-role-none", "medium", "Upgrade safety",
                 "component globalized with no owner",
                 "`prepare_to_globalize(OwnerRole::None)` globalizes with no owner.",
                 "With no owner there is no authority to rotate roles, pause, or recover if a managing badge is lost or compromised.",
                 "Globalize with an explicit OwnerRole governing the admin role(s).")


@rule
def r_owner_role_fixed(ctx):
    # Sibling of r_owner_role_none; whole-text for the same rustfmt-wrapping reason.
    #
    # `low`, not medium: unlike OwnerRole::None there IS an authority here, so nothing is
    # immediately exploitable — what's lost is recoverability, and pinning the rule can be a
    # legitimate deliberate choice for a component whose administration is meant to be immutable.
    # It sits with panic-macro at low: a real property of the deployment that a reviewer must
    # consciously sign off, not a likely bug. The waiver below is for designs where an unrotatable
    # owner rule is the point — not for ones where it is a side effect. The kit's own attestation
    # registry trips this rule and does NOT waive it; attestation/README.md says why.
    for m in re.finditer(r"prepare_to_globalize\s*\(\s*OwnerRole::Fixed", ctx["stripped"]):
        yield _f(_line_of(ctx["stripped"], m.start()), "owner-role-fixed", "low", "Upgrade safety",
                 "owner rule is fixed and can never be rotated",
                 "`prepare_to_globalize(OwnerRole::Fixed(...))` pins the owner rule for the life of "
                 "the component.",
                 "Fixed makes the rule itself immutable: if the owner badge is lost, burned or "
                 "compromised there is no path to re-point the owner role, so administration is "
                 "permanently stuck in whatever state that badge is in — including in an attacker's hands.",
                 "Use OwnerRole::Updatable so the rule can be re-pointed (to a recovery rule or a "
                 "multi-sig), unless immutable administration is a deliberate and documented property "
                 "of the design — in which case waive this with `// sak:allow owner-role-fixed`.")


@rule
def r_self_updatable_role(ctx):
    # whole-text + `\s` in the updater class so a rustfmt-wrapped list (`[\n  admin\n]`) can't evade.
    pat = re.compile(r"(\w+)\s*=>\s*updatable_by:\s*\[\s*([\w,\s]+?)\s*\]")
    for lineno, line, m in _finditer_lines(ctx["stripped"], pat):
        role = m.group(1)
        updaters = [u for u in re.split(r"[,\s]+", m.group(2)) if u]
        if updaters == [role]:
            yield _f(lineno, "self-updatable-role", "medium", "Upgrade safety",
                     f"role `{role}` can rotate itself",
                     f"`{role} => updatable_by: [{role}]` lets the role rewrite its own rule.",
                     "A compromised role is then permanent — it can lock out any higher authority.",
                     "Make the role updatable_by an equal-or-higher role (e.g. an owner), not itself.")


@rule
def r_unsafe_block(ctx):
    # whole-text so `unsafe\n{` can't evade the line scan. Also catches `unsafe fn` / `unsafe
    # impl` (BUG-HUNT-2026-07-18 L1) — the block-only pattern missed both, even though the same
    # "sidesteps the safety guarantees" rationale applies to them.
    pat = re.compile(r"\bunsafe\s*\{|\bunsafe\s+(?:fn|impl)\b")
    for lineno, line, _m in _finditer_lines(ctx["stripped"], pat):
        yield _f(lineno, "unsafe-block", "medium", "Memory safety",
                 "unsafe block",
                 f"`{line.strip()[:80]}` uses an unsafe block.",
                 "unsafe is highly unusual in Scrypto and sidesteps the safety guarantees auditors rely on.",
                 "Remove it if at all possible; if unavoidable, document the invariant it upholds.")


@rule
def r_panic_macro(ctx):
    pat = re.compile(r"\b(panic|unimplemented|todo|unreachable)\s*!")
    for lineno, line, m in _matches(ctx["stripped_lines"], pat):
        yield _f(lineno, "panic-macro", "low", "Error handling",
                 f"{m.group(1)}!() panic",
                 f"`{line.strip()[:80]}` panics with a generic macro.",
                 "Bare panics give opaque post-mortems; user-reachable ones are a griefing/DoS surface.",
                 "Use define_error!-style descriptive errors and assert! with messages.")


@rule
def r_todo_comment(ctx):
    pat = re.compile(r"//.*\b(TODO|FIXME|XXX|HACK)\b")
    for lineno, line, m in _matches(ctx["comments_lines"], pat):
        yield _f(lineno, "todo-comment", "info", "Maintainability",
                 f"{m.group(1)} marker",
                 f"unresolved `{m.group(1)}` at this line.",
                 "Unresolved markers in audit-grade code often flag known-incomplete logic.",
                 "Resolve it or convert it into a tracked issue before audit.")


_BLUEPRINT_RE = re.compile(r"#\[\s*(?:\w+::)*blueprint\s*\]")  # also matches #[scrypto::blueprint]
_MOD_OPEN_RE = re.compile(r"\bmod\s+\w+\s*\{")


def _brace_span_end(text, open_idx):
    """Index just past the `}` matching the `{` at text[open_idx] (simple depth counter).

    Safe to run on `ctx["stripped"]`: comments and string/char literals are already blanked
    there, so a `{`/`}` inside either can never throw off the count. Returns len(text) if the
    source never closes the brace (truncated/malformed input) — a defensive fallback, not the
    expected case."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


_ENABLE_METHOD_AUTH_RE = re.compile(r"\benable_method_auth!\s*\{")
_METHODS_OPEN_RE = re.compile(r"\bmethods\s*\{")
_AUTH_ENTRY_RE = re.compile(r"(\w+)\s*=>\s*([^;{}]*);")


def _method_auth_index(text):
    """Per-blueprint map of what `enable_method_auth!` declares for each method.

    Returns [(body_start, body_end, {method: "public" | "restricted"}), …] — one tuple per
    `#[blueprint] mod X { … }`, so a rule that matched a method can ask what the SURROUNDING
    blueprint declares about it. Scoped per blueprint for the same reason r_missing_method_auth
    is: one blueprint's `=> PUBLIC` must not speak for a sibling blueprint in the same .rs.

    Only the `methods { … }` sub-block is read. The sibling `roles { … }` block uses the very
    same `name => …;` shape (`admin => updatable_by: [OWNER];`), so parsing the whole macro would
    register roles as methods. Run this on the stripped view — an auth claim written inside a
    comment or a string literal is not auth, and it is already blanked there.
    """
    index = []
    for bp_match in _BLUEPRINT_RE.finditer(text):
        mod_match = _MOD_OPEN_RE.search(text, bp_match.end())
        if not mod_match:
            continue
        body_start = mod_match.start()
        body_end = _brace_span_end(text, mod_match.end() - 1)
        decls = {}
        auth = _ENABLE_METHOD_AUTH_RE.search(text, body_start, body_end)
        if auth:
            methods = _METHODS_OPEN_RE.search(text, auth.end(), _brace_span_end(text, auth.end() - 1))
            if methods:
                block = text[methods.end():_brace_span_end(text, methods.end() - 1) - 1]
                for entry in _AUTH_ENTRY_RE.finditer(block):
                    decls[entry.group(1)] = "restricted" if "restrict_to" in entry.group(2) else "public"
        index.append((body_start, body_end, decls))
    return index


def _declared_auth(index, offset, method):
    """What the blueprint containing `offset` declares for `method`, or None if it says nothing."""
    for start, end, decls in index:
        if start <= offset < end:
            return decls.get(method)
    return None


@rule
def r_missing_method_auth(ctx):
    # Per-blueprint, not per-file (BUG-HUNT-2026-07-18 H2): the old check took only the FIRST
    # #[blueprint] match and tested `"enable_method_auth!" in s` against the WHOLE file, so one
    # authed blueprint silently vouched for every OTHER blueprint in the same .rs — a multi-
    # blueprint file with one gated and one wide-open blueprint reported clean.
    s = ctx["stripped"]
    for bp_match in _BLUEPRINT_RE.finditer(s):
        mod_match = _MOD_OPEN_RE.search(s, bp_match.end())
        if not mod_match:
            continue  # no `mod X { ... }` found after the attribute — malformed/truncated input
        body_end = _brace_span_end(s, mod_match.end() - 1)
        body = s[mod_match.start():body_end]
        if "enable_method_auth!" in body:
            continue
        if not re.search(r"\bpub\s+fn\b", body):
            continue
        yield _f(_line_of(s, bp_match.start()), "missing-method-auth", "high", "Auth bypass",
                 "blueprint has no enable_method_auth!",
                 "a #[blueprint] with public methods declares no enable_method_auth! macro.",
                 "Without it every public method is callable by anyone — there is no role gating at all.",
                 "Add enable_method_auth! and restrict state-changing methods to the least-privileged role.")


@rule
def r_raw_decimal_arith(ctx):
    # raw * and / on a Decimal amount panic on overflow (and / panics on a zero divisor).
    # High-precision: only fire when an `.amount()` or `dec!(...)` operand sits next to the operator.
    # Whole-text (BUG-HUNT-2026-07-18 H1): this rule still used the per-line `_matches` helper
    # after its siblings were migrated to `_finditer_lines` (commit af17dc0) specifically to
    # defeat newline-splitting, so ordinary rustfmt wrapping of a long expression — operator
    # leading the continuation line — evaded it (`\s*` in the pattern spans the newline here).
    pat = re.compile(r"(?:\.amount\s*\(\s*\)|\bdec!\s*\([^)]*\))\s*[*/]"
                     r"|[*/]\s*(?:[\w.]*\.amount\s*\(\s*\)|dec!\s*\()")
    for lineno, line, _m in _finditer_lines(ctx["stripped"], pat):
        yield _f(lineno, "raw-decimal-arith", "medium", "Integer / decimal arithmetic",
                 "raw arithmetic on a Decimal amount",
                 f"`{line.strip()[:80]}` uses raw * or / on a Decimal amount.",
                 "Raw Decimal * and / panic on overflow, and / panics on a zero divisor — with no precision guard.",
                 "Use checked_mul / checked_div (handle the None) and guard divisors against zero.")


@rule
def r_unwrap_expect(ctx):
    for lineno, line, m in _matches(ctx["stripped_lines"], r"\.(unwrap|expect)\s*\("):
        yield _f(lineno, "unwrap-expect", "info", "Error handling",
                 f"{m.group(1)}() can panic",
                 f"`{line.strip()[:80]}` uses .{m.group(1)}().",
                 "unwrap/expect panic on failure; on user-supplied input that's a griefing/DoS surface.",
                 "Handle the Option/Result explicitly, or assert! with a descriptive message.")


@rule
def r_public_mint_burn(ctx):
    # whole-text so `pub\nfn mint_free(` can't evade the line scan.
    #
    # Cross-references enable_method_auth! and stays silent when the method is declared
    # `restrict_to: [...]` — the gate lives in the macro, not on the fn, and `pub fn` is how
    # EVERY Scrypto method is written whether gated or not. Without this the rule flagged a live
    # mainnet component's `mint_manager_badge` as an unrestricted mint while the same file's auth
    # block declared `mint_manager_badge => restrict_to: [admin, OWNER];`. A method declared
    # `=> PUBLIC`, or absent from the macro entirely, still fires.
    pat = re.compile(r"\bpub\s+fn\s+(\w*(mint|burn)\w*)\s*\(")
    index = _method_auth_index(ctx["stripped"])
    for lineno, line, m in _finditer_lines(ctx["stripped"], pat):
        verb = m.group(2)
        declared = _declared_auth(index, m.start(), m.group(1))
        if declared == "restricted":
            continue
        gate = ("declared `=> PUBLIC`" if declared == "public"
                else "absent from the blueprint's enable_method_auth! rules")
        yield _f(lineno, "public-mint-burn", "medium", "Auth bypass",
                 f"{verb} method — confirm it is role-gated",
                 f"`{line.strip()[:80]}` is a public fn that {verb}s, {gate}.",
                 "An unrestricted mint/burn is unbounded supply control.",
                 "Restrict it via enable_method_auth! to a least-privileged role; don't leave it PUBLIC.")


# --------------------------------------------------------------------------- engine

_SUPPRESS_RE = re.compile(r"//\s*sak:allow\s+([\w-]+)")


def _suppressed(comment_lines, code_lines, line, rule_id):
    """True if `// sak:allow <rule-id>` is on this line (1-indexed) or the line above. Operates on
    the comments-visible view, so a token inside a string literal does not suppress.

    The "line above" form is honored ONLY when that line carries no code of its own — checked
    against `code_lines` (the comment-blanked view), i.e. it is a dedicated suppression-comment
    line (BUG-HUNT-2026-07-18 M3). Without that check, an INLINE suppression trailing line N's
    code also leaked onto line N+1: line N+1's "line above" is line N, and line N carries a
    `// sak:allow` even though it was only ever meant to cover its own line.

    A specific rule id is REQUIRED — the blanket `// sak:allow all` is rejected. The suppression
    lives in source authored by the party under audit, so a blanket "hide everything" is a hole:
    each suppression must name its rule and is then visible per-line in review/diff."""
    if 1 <= line <= len(comment_lines):
        m = _SUPPRESS_RE.search(comment_lines[line - 1])
        if m and m.group(1) == rule_id:
            return True
    above = line - 1
    if 1 <= above <= len(comment_lines) and 1 <= above <= len(code_lines) and not code_lines[above - 1].strip():
        m = _SUPPRESS_RE.search(comment_lines[above - 1])
        if m and m.group(1) == rule_id:
            return True
    return False


def analyze_text(rel_path, src):
    """Run all rules over one file's source. Returns raw findings (no ids yet)."""
    stripped = strip_comments_and_strings(src)
    code_with_strings = strip_comments_and_strings(src, keep_strings=True)
    ctx = {
        "rel_path": rel_path,
        "raw": src,
        "raw_lines": src.splitlines(),
        "stripped": stripped,
        "stripped_lines": stripped.splitlines(),
        "comments_lines": strip_comments_and_strings(src, keep_comments=True).splitlines(),
        "code_with_strings": code_with_strings,
        "code_with_strings_lines": code_with_strings.splitlines(),
    }
    found = []
    for fn in RULES:
        for item in fn(ctx):
            if _suppressed(ctx["comments_lines"], ctx["stripped_lines"], item["line"], item["rule"]):
                continue
            item["rel_path"] = rel_path
            found.append(item)
    return found


def _iter_rs_files(pkg_dir):
    # os.walk() on a path that does not exist yields NOTHING and raises nothing, so without this
    # guard a typo'd or renamed package path produced "0 findings", exit 0 — a clean bill of
    # health for a directory we never opened. An analyzer that fails open is worse than no
    # analyzer: the build goes green and the caller believes it was checked. Fail closed, the
    # same way ci-gate.py does on a missing reports dir.
    if not os.path.isdir(pkg_dir):
        raise NotADirectoryError(f"package path is not a directory: {pkg_dir}")
    src_dir = os.path.join(pkg_dir, "src")
    base = src_dir if os.path.isdir(src_dir) else pkg_dir
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            if name.endswith(".rs"):
                yield os.path.join(root, name)


def analyze_package(pkg_dir):
    """Analyze every .rs under <pkg>/src. Returns schema-shaped findings with S-### ids."""
    raw = []
    for path in _iter_rs_files(pkg_dir):
        rel = os.path.relpath(path, pkg_dir)
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw.extend(analyze_text(rel, fh.read()))

    sev_rank = sak_lib.SEV_RANK
    raw.sort(key=lambda f: (-sev_rank.get(f["severity"], 0), f["rel_path"], f["line"], f["rule"]))

    findings = []
    for idx, item in enumerate(raw, 1):
        findings.append({
            "id": f"S-{idx:03d}",
            "severity": item["severity"],
            "class": item["class"],
            "location": f"{item['rel_path']}:{item['line']}",
            "title": item["title"],
            "what": item["what"],
            "why": item["why"],
            "suggested_direction": item["suggested_direction"],
            "confidence": "high",
            "status": "open",
            "source": "static",
            "rule": item["rule"],
        })
    return findings


# --------------------------------------------------------------------------- CLI


def main():
    ap = argparse.ArgumentParser(description="Deterministic Scrypto static analysis.")
    ap.add_argument("package", help="path to the Scrypto package (or a src dir)")
    ap.add_argument("--out", help="write the findings JSON array to this file")
    ap.add_argument("--allow-empty", action="store_true",
                    help="exit 0 when the package contains no .rs files (default: fail closed)")
    args = ap.parse_args()

    # Fail closed on a package we could not read, mirroring ci-gate.py's --allow-missing: a
    # scan that opened nothing must not report a clean bill of health. Both the missing-dir
    # case (raised below) and the no-sources case are silent green builds otherwise.
    try:
        n_files = sum(1 for _ in _iter_rs_files(args.package))
    except NotADirectoryError as exc:
        sys.stderr.write(f"::error::{exc}\n")
        return 2
    if n_files == 0 and not args.allow_empty:
        sys.stderr.write(
            f"::error::no .rs files found under {args.package} — refusing to report a clean "
            f"scan of a package that was never read. Check the path, or pass --allow-empty.\n")
        return 2

    findings = analyze_package(args.package)
    counts = sak_lib.severity_counts(findings)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
            fh.write("\n")
    else:
        json.dump({"count": len(findings), "counts": counts, "findings": findings},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
    sys.stderr.write(f"[static] {len(findings)} finding(s): {sak_lib.counts_summary(counts)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
