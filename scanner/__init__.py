"""Posture scanner: a read-only pass over a cohort of live Radix mainnet entities.

Distinct from the rest of scrypto-audit-kit (source in, report out, no chain access -- see
docs/architecture.md). This package is the only part of the kit that talks to the Radix Gateway.
See docs/posture-scanner.md for the full design; scanner/README.md for the short version.

Stdlib only, same as the rest of the kit. HTTPS calls shell out to `curl` (scanner/gateway.py)
rather than using `urllib`/`requests`, because this project's local dev environment cannot
verify TLS certificates from Python's own store -- curl's system store works fine. Tests never
make network calls; every check is exercised against fixture JSON captured from real pinned
Gateway reads, third-party identifiers replaced (examples/posture-scanner/).
"""
