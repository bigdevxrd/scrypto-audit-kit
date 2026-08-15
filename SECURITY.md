# Security Policy

The whole subject of this kit is security review, so it should be obvious how to report a hole
in the kit itself — this file says how.

Two different things get called "a security issue" here, so up front:

- **A vulnerability *in* the kit** — the harness, the static analyzer, the MCP server, the CI
  gate, the attestation bridge, the published package. Report it privately, as below.
- **A finding the kit *reports* about your blueprint** — a false positive, a missed bug, a
  hallucinated `file:line`. That's the kit's output, not a hole in the kit. Open an ordinary
  [issue](https://github.com/bigdevxrd/scrypto-audit-kit/issues) or a trial report — see
  [CONTRIBUTING.md](CONTRIBUTING.md), which asks for exactly this.

## Reporting a vulnerability

**Preferred — a GitHub private security advisory:**

**<https://github.com/bigdevxrd/scrypto-audit-kit/security/advisories/new>**

(Same place as the repo's **Security** tab → **Report a vulnerability**.) The report stays
private between you and the maintainer until an advisory is published.

Private vulnerability reporting is enabled on this repo, so that form is open to anyone — you
do not need write access to file. If you ever find it isn't (it is a per-repo GitHub setting,
and a setting can be changed), a policy that names one channel and leaves you guessing whether
it's open isn't a policy, so:

**If the advisory form isn't available to you, either of these works:**

1. **Contact the maintainer, [@bigdevxrd](https://github.com/bigdevxrd), on GitHub** — through
   whatever contact routes that profile lists. Those are the only ones this project claims.
   This repo publishes no security email address; treat any address presented as one, in a
   fork or anywhere else, as not ours.
2. **Open a public issue that asks for a private channel and says nothing else.** Not the file,
   not the rule, not the reproduction, not the severity, not "it's in the gate" — just that you
   have a security report and need somewhere private to send it. That much discloses nothing
   and is a normal, welcome thing to do; the details then go through the channel you get back.

Beyond that request-a-channel note, please don't put the substance of a vulnerability in a
public issue, PR, or discussion before the maintainer has had a chance to respond.

Useful in a report, roughly in order:

- The version — `VERSION` in a clone, or `pip show scrypto-audit-kit` — and how you ran it
  (`./audit.sh`, a `sak-*` script, the SDK, the MCP server, the reusable workflow).
- What the attacker controls (usually: the blueprint package under audit) and what they get.
- A minimal reproduction. A crafted package directory is the natural shape of one, since the
  kit is by design pointed at source it has no reason to trust.
- Whether you want credit, and under what name.

Everything runs on your own machine against your own API key, so there's no hosted service to
probe and nothing to coordinate about downtime.

## Response posture

This is an alpha-stage project maintained by one person alongside other work. These are honest
expectations, not an SLA:

- **Acknowledgement:** within 7 days, usually sooner.
- **Assessment** — in scope, severity, affected versions — within 14 days of acknowledgement.
- **Fix:** paced to severity, with no promised date. Anything that lets a hostile package run
  code on an auditor's machine, or that lets a bad report pass as a good one, gets priority over
  everything else in the repo. A subtler issue may wait for the next release.
- **Disclosure:** coordinated. The advisory publishes when the fix ships, or at 90 days from the
  report, whichever comes first; if there's no fix at 90 days, the advisory says so.
- **Credit:** your name, handle, or anonymous — your call — in the advisory and the
  [CHANGELOG](CHANGELOG.md).

There's no bounty. There's no money in this project.

If you've had no reply after 14 days, assume it was missed rather than ignored: open a public
issue saying only that you filed a private report and got no response — no details, whichever
channel you used — and it'll get picked up.

## Supported versions

| Version | Supported |
|---|---|
| `main` (git clone) | yes |
| 0.7.x — next release | yes |
| ≤ 0.6.x | no |

One known issue is already public rather than embargoed, so it belongs here: the reusable
`pre-audit.yml` shipped in `v0.5.0` and `v0.6.0` interpolates caller-controlled workflow inputs
into `run:` scripts in the job that holds `ANTHROPIC_API_KEY`. The fix is on `main` and ships in
`v0.7.0`; if you call that workflow, `v0.7.0` is a floor, not a preference — and until it is
tagged, pin a commit SHA from `main` rather than an older tag. See the
[CHANGELOG](CHANGELOG.md) and [docs/ci.md](docs/ci.md).

Fixes land on `main` and ship in the next release. There is no LTS and no backporting to older
minors: the kit is pre-1.0 alpha, so "upgrade" is the remediation. Both distribution paths count
as the kit — the PyPI package (`scrypto-audit-kit`) and a git clone, which is how the full
`./audit.sh` runs.

## Scope

### In scope

The kit reads source it doesn't trust and hands it to a model, so most of the real attack
surface is a hostile package under audit. `tests/test_security.py` shows the shape of what
counts — report hijacking, gate bypass, severity bypass all have regression tests already.

- **Code execution or file access beyond the target and the kit**, triggered by the package
  being audited: path traversal in target collection or report writing, a crafted path or file
  name escaping confinement, or anything at all that executes during a default run (that is,
  without `--compile-check`).
- **Prompt injection that changes the verdict** — content in a target package that suppresses
  findings, downgrades severity, or otherwise steers the report. The audit prompt declares
  target source untrusted data and requires steering attempts to be reported as a finding; a way
  around that is a vulnerability, because it turns the report into a lie.
- **Report and gate integrity** — defeating the nonce that authenticates the model's JSON
  appendix, getting a report past `sak-gate` or the CI workflow that its own findings should
  have failed, forging or replaying a provenance block, or binding an attestation to source the
  report wasn't produced from.
- **Secret leakage** — an `ANTHROPIC_API_KEY` or any other credential in the environment ending
  up in a report, a `report.json`, an attestation payload, CI logs, or a subprocess environment
  that had no need for it.
- **Supply chain** — the published PyPI artifact, the release workflow, or the reusable
  `pre-audit.yml` (injection through a workflow input, over-broad token permissions, and so on).

### Out of scope

Real issues, some of them valuable — just not security reports against the kit. File these as
ordinary issues:

- **Findings quality.** False positives, false negatives, hallucinated `file:line` citations,
  and "the kit missed a real bug in my blueprint". The README's
  [limitations](README.md#limitations--read-this-before-relying-on-the-output) state plainly
  that this is a pre-audit rather than an audit and not a deployment gate. A miss is the
  documented behaviour of the tool, not a vulnerability in it. These reports are still wanted —
  CONTRIBUTING.md ranks them as the most useful contribution there is.
- **[`examples/vulnerable-vault`](examples/vulnerable-vault).** Deliberately vulnerable; that's
  its entire purpose. Likewise the deliberately-bad inputs the test suite constructs.
- **`--compile-check` running the target's build scripts.** Documented, off by default, and
  gated on you deciding you trust that code enough to run it. Reaching the same execution
  *without* the flag is very much in scope.
- **The `cmd` backend running the command you passed it.** `--backend cmd` is a
  bring-your-own-agent hook; running your command is the feature.
- **Model nondeterminism, cost, and rate limits.** The LLM tier does not reproduce byte for
  byte — only the static tier does — and the attestation docs say so.
- **Advisories in optional dependencies.** The core is stdlib-only with zero required
  dependencies; `anthropic`, `mcp`, and `jsonschema` are opt-in extras and belong upstream. Do
  report it if the kit's *use* of one turns an upstream issue into an exploitable path here.

## What the kit does not defend against

Written down so nobody has to discover it via an advisory:

- **An LLM can be steered by the text it reads.** The untrusted-data boundary in the prompt is
  mitigation, not a guarantee. Treat a clean report on a package from a stranger with the same
  suspicion you'd give the package.
- **A clean report is not approval.** The badge means the pre-audit passed, nothing stronger,
  and no part of this kit replaces a human audit before mainnet.
- **Reports aren't secret, but they quote your source.** `audit-reports/` is gitignored for that
  reason; decide deliberately before pasting one somewhere public.
