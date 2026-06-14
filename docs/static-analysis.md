# Static analysis (the deterministic tier)

The kit runs a **deterministic static pass** over the source before (and independently of)
the LLM. It's free, reproducible, needs no API key, and catches mechanical Scrypto footguns
that don't need a model to spot. This is the bottom of the [trust ladder](../VISION.md) — and
the first thing an agent should run.

```bash
./audit.sh --static-only <package>     # free, instant, no API key, no toolchain
```

It also runs as part of every full `./audit.sh` (merged into the report), and is exposed to
agents as the `static_scan` MCP tool. Findings use `S-###` ids and `source: "static"`.

## Precision by design

Rules run over the source **after** a comment/string-aware stripper blanks the *contents* of
comments and string/char literals (it handles nested block comments and string line-continuations,
preserving line numbers). So **code** rules don't match inside a `// comment` or a `"string
literal"`. Two rules intentionally read the other view — `hardcoded-address` checks string literals,
`todo-comment` checks comments. Rules are deliberately **high-precision** (they prefer to miss over
to over-flag); recall is the LLM pass's job.

## Rules

| Rule | Severity | Class | Catches |
|------|----------|-------|---------|
| `float-usage` | high | Integer / decimal arithmetic | `f32`/`f64` types in on-ledger math |
| `missing-method-auth` | high | Auth bypass | a `#[blueprint]` with `pub fn`s but no `enable_method_auth!` |
| `hardcoded-address` | medium | External calls / composability | bech32 address literals (`resource_rdx1…`) in source |
| `unbounded-take-all` | medium | Resource handling | `.take_all()` — a whole-vault drain |
| `owner-role-none` | medium | Upgrade safety | `prepare_to_globalize(OwnerRole::None)` — no owner |
| `self-updatable-role` | medium | Upgrade safety | a role `updatable_by` itself |
| `unsafe-block` | medium | Memory safety | `unsafe { … }` |
| `panic-macro` | low | Error handling | `panic!`/`todo!`/`unimplemented!`/`unreachable!` |
| `raw-decimal-arith` | medium | Integer / decimal arithmetic | raw `*`/`/` on a `.amount()` / `dec!()` Decimal — overflow / div-by-zero |
| `public-mint-burn` | medium | Auth bypass | a `pub fn` named mint/burn — confirm it's role-gated |
| `unwrap-expect` | info | Error handling | `.unwrap()` / `.expect()` — a panic surface |
| `todo-comment` | info | Maintainability | `TODO`/`FIXME`/`XXX`/`HACK` markers |

These are a starting set — high-signal footguns that are unambiguous to detect. The LLM pass
covers the semantic classes (reentrancy, oracle manipulation, state-machine gaps, slippage, …)
that a regex can't judge reliably.

## Suppressing a finding

Put a `// sak:allow <rule-id>` comment on the offending line or the line directly above it:

```rust
self.vault.take_all() // sak:allow unbounded-take-all  (redeem path: caller already gated)
```

Use `// sak:allow all` to suppress every rule on that line. Suppressions are visible in the
diff, so a reviewer can see exactly what was waived and why.

## Adding a rule

Rules live in [`bin/static_analysis.py`](../bin/static_analysis.py) as small functions
registered with `@rule`. A rule reads the per-file context (`stripped_lines` for code,
`raw_lines` when it needs comments) and yields findings via the `_f(...)` helper:

```python
@rule
def r_my_check(ctx):
    for lineno, line, _m in _matches(ctx["stripped_lines"], r"\bsome_pattern\b"):
        yield _f(lineno, "my-check", "medium", "Resource handling",
                 "short title", "what was found", "why it matters", "how to fix")
```

Then add a case to the planted-bug fixture (or a focused snippet) and assert it in
[`tests/test_static_analysis.py`](../tests/test_static_analysis.py) — including a
*negative* test proving it doesn't fire on benign code. Keep precision high: a noisy rule
is worse than no rule. Run `make test`.
