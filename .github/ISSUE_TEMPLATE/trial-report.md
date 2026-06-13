---
name: Trial report
about: Share a report from running scrypto-audit-kit against a public blueprint
title: '[trial] <blueprint name>'
labels: trial-report
---

## Blueprint audited

- **Source repo:** https://github.com/...
- **Path in repo:** `packages/...`
- **Commit:** `abc123`
- **License:** Apache-2.0 / MIT / etc.

## Kit version used

- **Commit:** `abc123` of this repo
- **Model:** sonnet (default)

## Report

<details>
<summary>Full report (paste here, or attach as .md)</summary>

```markdown
# Audit: <blueprint name>

...
```

</details>

## Your assessment

For each finding the kit raised, mark one of:

- ✅ **Confirmed** — real issue, the kit was right.
- ❌ **False positive** — kit was wrong; explain why.
- 🤷 **Unknown** — can't tell without more context.

| F-### | Severity | Class | Verdict | Notes |
|-------|----------|-------|---------|-------|
| F-001 | High | Auth bypass | ✅ Confirmed | — |
| F-002 | Medium | Slippage | ❌ False positive | The blueprint relies on the caller's min_out, which is the documented pattern for this protocol. |

## What the kit missed (false negatives)

If you know of known bugs in this blueprint that the kit did *not* surface, list them here. This is the most valuable feedback we get.

- ...

## Suggested checklist additions

If false-negatives suggest the checklist is missing a class of vulnerability, propose a PR to `prompts/checklist.md`.

- ...
