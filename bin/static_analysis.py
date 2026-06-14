#!/usr/bin/env python3
"""Deterministic static analysis for Scrypto — the free, no-API tier of the pre-audit.

A "Slither for Scrypto": a curated set of high-precision rules over the source that catch
mechanical footguns reliably and reproducibly, with zero model calls. Findings are shaped
like schema/audit-report.schema.json (source="static", S-### ids) so they merge cleanly
with the LLM pass into one report.

Design for precision: the source is first run through a comment/string-aware stripper that
blanks the *contents* of comments and string/char literals while preserving every newline,
so code rules don't match inside a comment or a string (hardcoded-address reads string literals and
todo-comment reads comments, by design). Suppress a single finding with a
`// sak:allow <rule-id>` comment on the offending line or the line above.

Stdlib only. Importable (analyze_package) and a CLI. Unit-tested in tests/test_static_analysis.py.
"""
import argparse
import json
import os
import re
import sys

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


def _f(line, rule_id, severity, klass, title, what, why, fix):
    return {
        "line": line, "rule": rule_id, "severity": severity, "class": klass,
        "title": title, "what": what, "why": why, "suggested_direction": fix,
    }


@rule
def r_float_usage(ctx):
    for lineno, line, _m in _matches(ctx["stripped_lines"], r"\b(f32|f64)\b"):
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
def r_unbounded_take_all(ctx):
    for lineno, line, _m in _matches(ctx["stripped_lines"], r"\.take_all\s*\("):
        yield _f(lineno, "unbounded-take-all", "medium", "Resource handling",
                 "unbounded vault drain via take_all()",
                 f"`{line.strip()[:80]}` empties the whole vault in one call.",
                 "An unbounded withdrawal is a large blast radius if the method is ever reachable by the wrong caller.",
                 "Prefer a bounded take(amount) with a per-call cap; reserve take_all() for fully-trusted paths.")


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
def r_self_updatable_role(ctx):
    pat = re.compile(r"(\w+)\s*=>\s*updatable_by:\s*\[\s*([\w, ]+?)\s*\]")
    for lineno, line, m in _matches(ctx["stripped_lines"], pat):
        role = m.group(1)
        updaters = [u.strip() for u in m.group(2).split(",") if u.strip()]
        if updaters == [role]:
            yield _f(lineno, "self-updatable-role", "medium", "Upgrade safety",
                     f"role `{role}` can rotate itself",
                     f"`{role} => updatable_by: [{role}]` lets the role rewrite its own rule.",
                     "A compromised role is then permanent — it can lock out any higher authority.",
                     "Make the role updatable_by an equal-or-higher role (e.g. an owner), not itself.")


@rule
def r_unsafe_block(ctx):
    for lineno, line, _m in _matches(ctx["stripped_lines"], r"\bunsafe\s*\{"):
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


@rule
def r_missing_method_auth(ctx):
    s = ctx["stripped"]
    match = _BLUEPRINT_RE.search(s)
    if not match or "enable_method_auth!" in s:
        return
    if not re.search(r"\bpub\s+fn\b", s):
        return
    yield _f(_line_of(s, match.start()), "missing-method-auth", "high", "Auth bypass",
             "blueprint has no enable_method_auth!",
             "a #[blueprint] with public methods declares no enable_method_auth! macro.",
             "Without it every public method is callable by anyone — there is no role gating at all.",
             "Add enable_method_auth! and restrict state-changing methods to the least-privileged role.")


@rule
def r_raw_decimal_arith(ctx):
    # raw * and / on a Decimal amount panic on overflow (and / panics on a zero divisor).
    # High-precision: only fire when an `.amount()` or `dec!(...)` operand sits next to the operator.
    pat = re.compile(r"(?:\.amount\s*\(\s*\)|\bdec!\s*\([^)]*\))\s*[*/]"
                     r"|[*/]\s*(?:[\w.]*\.amount\s*\(\s*\)|dec!\s*\()")
    for lineno, line, _m in _matches(ctx["stripped_lines"], pat):
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
    for lineno, line, m in _matches(ctx["stripped_lines"], r"\bpub\s+fn\s+\w*(mint|burn)\w*\s*\("):
        yield _f(lineno, "public-mint-burn", "medium", "Auth bypass",
                 f"{m.group(1)} method — confirm it is role-gated",
                 f"`{line.strip()[:80]}` is a public fn that {m.group(1)}s.",
                 "An unrestricted mint/burn is unbounded supply control.",
                 "Restrict it via enable_method_auth! to a least-privileged role; don't leave it PUBLIC.")


# --------------------------------------------------------------------------- engine

_SUPPRESS_RE = re.compile(r"//\s*sak:allow\s+([\w-]+)")


def _suppressed(comment_lines, line, rule_id):
    """True if `// sak:allow <rule>` is on this line or the line above (1-indexed). Operates on the
    comments-visible view, so a suppression token inside a string literal does not suppress."""
    for candidate in (line, line - 1):
        if 1 <= candidate <= len(comment_lines):
            m = _SUPPRESS_RE.search(comment_lines[candidate - 1])
            if m and m.group(1) in (rule_id, "all"):
                return True
    return False


def analyze_text(rel_path, src):
    """Run all rules over one file's source. Returns raw findings (no ids yet)."""
    stripped = strip_comments_and_strings(src)
    ctx = {
        "rel_path": rel_path,
        "raw": src,
        "raw_lines": src.splitlines(),
        "stripped": stripped,
        "stripped_lines": stripped.splitlines(),
        "comments_lines": strip_comments_and_strings(src, keep_comments=True).splitlines(),
        "code_with_strings_lines": strip_comments_and_strings(src, keep_strings=True).splitlines(),
    }
    found = []
    for fn in RULES:
        for item in fn(ctx):
            if _suppressed(ctx["comments_lines"], item["line"], item["rule"]):
                continue
            item["rel_path"] = rel_path
            found.append(item)
    return found


def _iter_rs_files(pkg_dir):
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
    args = ap.parse_args()

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
