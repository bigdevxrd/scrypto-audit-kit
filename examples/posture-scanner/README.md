# Posture-scanner fixtures

Captured Gateway responses used by the Check-logic unit tests
(`tests/test_scanner_checks.py`, `tests/test_scanner_report.py`).

## What is real, and what is not

These files are **structural captures of real Gateway responses, with everything that
identifies a third party replaced.**

Real, and load-bearing for the tests:
- the entity/blueprint/package structure;
- the full role and access-rule shape (`owner_role`, `minter`, `burner`, `recaller`,
  each `_updater` counterpart, `dapp_definition` / `claimed_entities` pairing);
- the response envelope as the Gateway actually returns it;
- the three Guild fixtures (`*_guild_*`), which keep their real addresses — those entities are
  the Guild's own and are public.

Replaced:
- in the third-party fixtures (`extern_a` / `extern_b` / `extern_c`): **every entity address**
  and the hex ids derived from keys or code (owner-badge local ids, package code hashes). The
  replacements are synthetic — checksum-valid bech32m addresses derived from a fixed label,
  which name no funded or claimed entity. (A well-formed account address still resolves on the
  Gateway as an empty virtual account, so a placeholder is never evidence that nothing exists
  at that address.) The protocol's own well-known system addresses
  (XRD, the account package, signature badges) are real and unchanged;
- the `name`, `description`, `symbol`, `icon_url` and `info_url` metadata **values**,
  and the filenames themselves.

## Why

The projects these were captured from are real and were never asked. Pairing an identifiable
project with a recorded `fail` in a public repo publishes a finding about them without
coordination — and a real address is as identifying as a name, since anyone can look it up. So
the names *and* the addresses come out, while the on-chain shape, which is what the checks
actually exercise, stays as captured.

The metadata substitutions are deliberately obvious (`example-bridge-b.test`, `Wrapped Token
B`) so no one mistakes a placeholder for a real capture. **Do not cite any string or address in
the `extern_*` files as observed on-chain** — only the role structure is.
