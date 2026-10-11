# Posture scanner

A read-only pass over a cohort of **live Radix mainnet entities**, checking five structural
facts about each one and writing a machine-readable, diffable result file per run. Its gated
output is published as [a public page](https://bigdevxrd.github.io/scrypto-audit-kit/) and under
`scanner/results/`.

**Status (2026-10-11).** In the repository and the v0.8.1 sdist, not in the wheel, so it runs from a
clone (or an unpacked sdist). Scans are run by hand; there is no schedule and nothing refreshes automatically. Two are
committed (2026-09-08 and 2026-09-11). The published scans cover only the entities Radix Guild
operates itself, and the 2026-09-11 scan predates the last two of the five entries in
`scanner/data/cohort.json`. Two of the three scanned entities fail Check 1 — Radix Guild's own
Badge Manager (zero-sided) and Badge Factory (reverse half-pair), both medium — and are
published as found; see the Check 1 table below.

This is a genuinely different surface from the rest of scrypto-audit-kit: everything else in this
repo takes `Cargo.toml + src/ + tests/` on disk and produces a report about *source code*, with no
chain access at all (see [architecture.md](architecture.md)). The posture scanner (`scanner/`)
takes a list of on-chain addresses and produces a report about *what is actually deployed and
configured right now* — no source required, no compilation, nothing that needs to exist on
GitHub. The two are complementary, never merged: this scanner has no `source_hash`, doesn't touch
`report.json`'s schema, and isn't part of the L1–L4 attestation ladder
([attestation-levels.md](attestation-levels.md)).

## Quickstart

```bash
# From the repo root:
python3 -m scanner.cli scan
python3 -m scanner.cli diff scanner/results/2026-09-08.json scanner/results/2026-09-11.json
```

`scan` pins to the Gateway's current `state_version` (or the frozen one, during a halt — see
below), reads a cohort file (`scanner/data/cohort-full.json` if present, else the committed
`scanner/data/cohort.json` — see [The cohort](#the-cohort)), and writes two files: the
full-detail scan to `scanner/results-full/<date>.json` (gitignored — never committed), and the
same scan *gated for publication* to `scanner/results/<date>.json` (committed, served raw from
GitHub — see [Publication gate](#publication-gate), below). It automatically diffs against the
most recent prior file in `scanner/results-full/` unless `--no-baseline` is passed — the full
directory, not the public one, so Check 4's continuity isn't lost for an entity a later scan
withholds from publication. See `python3 -m scanner.cli scan --help`.

## Why curl, not a Python HTTP library

This kit's deterministic core is stdlib-only by design (see `pyproject.toml`). The scanner keeps
that discipline, but the local Mac this was built on cannot verify TLS certificates from
Python's own certificate store — a broken local install, not a Radix or Gateway problem. `curl`
uses the system's own store and works fine, so `scanner/gateway.py` shells out to it via
`subprocess` rather than pulling in `requests` or fighting the local cert store. Node would have
worked equally well; curl was chosen to keep the scanner in the same language and dependency
posture as the rest of the kit. Tests never invoke `curl` for
real — `subprocess.run` is mocked throughout (see `tests/test_scanner_gateway.py`).

## Halt handling

Radix mainnet was halted from 2026-08-31 (frozen at `state_version` **557840622**) to
2026-09-11, and has been producing blocks since. The scanner was built during that halt and
treats one the same way if it recurs: the 2026-09-08 scan ran during it (`gateway.halted:
true`), the 2026-09-11 scan after it (`gateway.halted: false`, `state_version` 557872098). Two
Gateway behaviors, both confirmed live during the halt:

- **`POST /status/gateway-status`** (empty JSON body `{}`) works fine, unpinned, during the halt —
  it returns the frozen `state_version` cleanly. This is the *only* unpinned call the scanner
  makes, and it's how a run discovers what to pin every other read to
  (`scanner/gateway.py:gateway_status`). Confirmed live: this endpoint refuses a plain `GET` with
  HTTP 405 — every Gateway call in this scanner is `POST`, not because of the halt but because
  that's the API's actual contract.
- **`POST /state/entity/details`**, called *unpinned*, is refused with a `NotSyncedUpError` (HTTP
  500) — a stable, parseable shape (`details.type == "NotSyncedUpError"`,
  `current_sync_delay_seconds`, `max_allowed_sync_delay_seconds`), not noise. The scanner makes
  one deliberately-unpinned probe call per run purely to observe this
  (`scanner/gateway.py:probe_halted`) and records it as `gateway.halted` in the report. Every
  *real* read the scanner needs is pinned via `at_ledger_state.state_version`, which works cleanly
  regardless of halt status.

A clean "no changes since last scan" reading during a halt is **not** the same claim as "no
changes are pending" — deferred upgrades or governance actions could land all at once once the
chain resumes. The scanner writes this caveat into `notes` whenever `gateway.halted` is true
rather than leaving it implicit.

The public page carries its own, separate reminder of the same underlying fact: a banner near
the top of `docs/index.html`, rendered by `scanner/site.py:_pinned_snapshot_banner`, always
states the exact `gateway.pinned_state_version` and `gateway.pinned_proposer_round_timestamp`
the scan is pinned to, and — only when `gateway.halted` is the literal `True` — adds that the
network had not produced a newer state when the scan ran. This exists so a reader who opens the page long
after a halt (possibly after it has resumed) cannot mistake a pinned historical snapshot for a
current read; it is purely a projection of fields already in the report, same as every other
line on the page.

`aggregation_level` is always `"Vault"`, never `"Global"` — confirmed that `"Global"` silently
returns empty NFT data on some entities. There is no code path in this scanner that uses
`"Global"`.

## The five checks

Every check is a `check(entity, item, context) -> finding` function in `scanner/checks/`,
returning one dict via `scanner.models.make_finding()`, which enforces the status/severity
contract below before a finding can exist at all (`scanner/models.py`).

### The severity discipline (read this first)

> Every check must emit a severity plus a reason, and a check that cannot determine intent must
> return `informational`, never a red.

`fail` (paired with `low`/`medium`/`high`/`critical` severity) is reserved for shapes a check can
**prove** are wrong from chain data alone. `informational` (paired only with
`informational`/`low`/`medium` — `models.py` refuses to let it carry `high`/`critical`) is for
everything where the correct read genuinely depends on the project's own intent, which the
Gateway's data cannot reveal. `not_applicable` (always severity `none`) is for a check that
doesn't apply to this entity kind at all.

### Check 1 — `dapp_definition_two_way`

Radix's convention: an entity names a dApp Definition account via a `dapp_definition` (singular,
`GlobalAddress`) or `dapp_definitions` (plural, `GlobalAddressArray`) metadata key; that account,
in turn, is expected to list the entity back in its own `claimed_entities`
(`GlobalAddressArray`). **A half-pair is not verification.**

Both key spellings are part of the Radix metadata convention and are entity-kind-dependent: a
component carries the singular form, a fungible resource the plural.

| Shape | Status | Severity | Example |
|---|---|---|---|
| Claims a dApp Definition, and that account claims it back | `pass` | `none` | The third-party-shaped fixtures in [`examples/posture-scanner/`](../examples/posture-scanner/README.md) (identifying details replaced) — not part of the published cohort; see [The cohort](#the-cohort) |
| Claims one, but the account does **not** list it back | `fail` | `medium` | The same fixtures: a pool and its sibling package both name one dApp Definition account that lists neither back |
| Claims none, but a known dApp-Definition account lists it anyway | `fail` | `medium` (reverse half-pair) | The Guild's own Badge Factory: the Guild's hub claims it, it claims nothing back |
| Claims none, and no known hub claims it either | `fail` | `medium` (zero-sided) | The Guild's own Badge Manager |
| The claimed account could not be fetched this run | `informational` | `informational` | (no case in this cohort — code path exists for a partial-fetch failure) |

An account tagged `role: "dapp_definition_hub"` in the cohort config is checked differently: is
`account_type` metadata exactly `"dapp definition"`, and is its own `claimed_entities`
non-empty? Each *claiming* entity's own two-way status is evaluated at that entity's own cohort
row, not repeated at the hub.

**Fields read:** `metadata.items[].key` ∈ `{dapp_definition, dapp_definitions, account_type,
claimed_entities}`, `/state/entity/details`.

### Check 2 — `owner_role`

**The check most prone to a wrong red.** `OwnerRole::None` (`rule.type: "DenyAll"`) is the
*correct*, deliberate design for a permissionless AMM pool, and is structurally
indistinguishable, from Gateway data alone, from "nobody ever set up a recovery path." A naive "no owner ⇒ red" rule would misjudge the
cleanest example this check exists to protect.

| `rule.type` | `updater` | Status | Severity | Rationale |
|---|---|---|---|---|
| `DenyAll` | any | `informational` | `informational` | Permanently ownerless. Correct for a permissionless design; indistinguishable from an oversight using chain data alone. **Never escalated — this is the case the check is built around.** |
| `Protected` | `None` | `informational` | `informational` | Fixed to one requirement forever, no rotation path. Same restraint applied consistently, not just to the `None` case. |
| `Protected` | `Owner` or `Object` | `pass` | `none` | Protected AND rotatable — a badge holder (or the object's own self-securify path) can repoint the rule. The one shape this check calls unambiguously good. |
| `AllowAll` | any | `fail` | `critical` | Owner-gated authority requires no proof from anyone. The one shape this check calls unambiguously bad — provable regardless of intent, which is why it's the sole `fail` path here. |
| anything else | | `informational` | `informational` | Unrecognized shape — refuses to guess. |

Two of these shapes are observed live on the Guild's own entities in the published scan:
`Protected`/`None` (Badge Manager, Badge Factory) and `Protected`/`Object` (the dApp Definition
account). The `DenyAll`/`None` and `Protected`/`Owner` shapes are exercised by the
third-party-shaped fixtures in [`examples/posture-scanner/`](../examples/posture-scanner/README.md).
`AllowAll` has no real example anywhere in the cohorts this scanner has run against — its test
is synthetic, clearly marked as such.

**Fields read:** `details.role_assignments.owner.rule.type`,
`details.role_assignments.owner.updater`.

### Check 3 — `resource_authority`

Only applies to `entity_kind: "resource"` (`not_applicable`/`none` otherwise — a component/
account/package carries no minter/burner/freezer/recaller role keys). Reads
`minter`/`burner`/`freezer`/`recaller` and each one's paired `_updater` — a role being closed
*today* says nothing about whether it can be silently reopened later by whoever holds the
updater. `depositor`/`withdrawer` are recorded as evidence but never scored (`AllowAll` there is
the expected, safe default for a transferable token).

This check's `DenyAll` handling is **deliberately different** from Check 2's: there is no
plausible reading of "this resource can never be minted/burned/frozen by anyone" that is bad for
holders — unlike an absent owner, which can genuinely mean "nobody can ever recover this," an
absent minter only ever means supply cannot inflate. So `DenyAll` on `minter`/`burner`/`freezer`
is `pass`, not `informational`. `recaller` is scored more strictly, since recall pulls funds out
of *someone else's* vault without consent:

| Shape | Status | Severity |
|---|---|---|
| `minter`/`burner`/`freezer` = `AllowAll` | `fail` | `critical` |
| `recaller` = `AllowAll` | `fail` | `critical` |
| `recaller` closed, but `recaller_updater` = `AllowAll` | `fail` | `high` |
| `recaller` = `DenyAll` and `recaller_updater` = `DenyAll` | `pass` | `none` |
| `recaller` = `DenyAll`, updater not `DenyAll` | `informational` | `informational` (could be reopened; who controls that is unknown) |
| otherwise (`Protected`) | `pass` | `none` |

The finding reported per entity is the **worst** across these roles (evidence still records every
role individually). The best-case shape, as exercised by the `resource_extern_b_token.json`
fixture: `minter`/`burner`/`freezer` gated behind an issuer's badge (`Protected`); `recaller`
**and** `recaller_updater` both `DenyAll` — recall is not just off, it can never be turned back
on.

**Fields read:** `details.role_assignments.entries[].role_key.{module,name}`,
`.assignment.{resolution, explicit_rule.type}`.

### Check 4 — `package_upgrade`

Applies to `package` kind (`details.codes.items[].code_hash_hex` + `details.blueprints.items[]`)
and `component` kind (`details.package_address` + `.blueprint_name` + `.blueprint_version`,
present directly on a component's own read — no second Gateway hop needed). Not applicable to
`resource`/`account` (neither carries upgradable code).

| Shape | Status | Severity |
|---|---|---|
| No prior scan to compare against | `informational` | `informational` — this run establishes the baseline; a clean reading is **not** yet a claim of "unchanged" |
| Baseline matches current | `pass` | `none` |
| Baseline differs | `informational` | `medium` — a change is a neutral, noteworthy fact; a routine improvement and a malicious swap look identical in this data, so this is never `fail` |

This check is structurally incapable of reporting "changed" on a first scan — confirmed by
construction, and by `tests/test_scanner_checks.py`'s baseline tests plus the end-to-end second-
scan test in `tests/test_scanner_report.py`.

**Fields read:** `details.vm_type`, `details.codes.items[].code_hash_hex`,
`details.blueprints.items[].{name,version}` (package); `details.package_address`,
`details.blueprint_name`, `details.blueprint_version` (component).

### Check 5 — `metadata_claims`

Validates **internal** consistency only: presence of `name`/`symbol` (entity-kind-dependent) and
whether `icon_url`/`info_url`, if present, are actually typed `Url` by the Gateway rather than a
plain `String`. Scope decision, disclosed rather than silent: this does **not** fetch `icon_url`/
`info_url` over the network to confirm they resolve, and does **not** simulate a swap to check a
claimed fee rate against observed behavior — both were floated as stretch ideas during scoping but
never verified, and this scanner does not ship a check it hasn't verified live. Nothing here is a
provable security fact, so this check never returns `fail` — every non-clean result is
`informational`/`low`.

**Fields read:** `metadata.items[].key` ∈ `{name, symbol, description, icon_url, info_url}`,
`.value.typed.type`.

## Embargo

> Include an `embargo` field on every finding from the first line — public posture facts publish
> immediately; anything describing how to take funds is disclosed privately first and publishes
> on a clock.

Every finding carries `embargo: {status, publish_at, reason}` (`scanner/models.py:public_embargo`/
`embargoed`), enforced by the schema on every single finding, not bolted onto a subset.

**All five checks default to `{"status": "public", "publish_at": null, "reason": null}`,
always**, because all five report **stated configuration** — what a role or metadata field is
currently *set to* — never a *derived exploit path*. "The owner role is `AllowAll`" is a posture
fact, exactly like "the owner role is `DenyAll`"; it is not a working manifest that drains a
vault. The embargo mechanism exists for a future check that *does* derive something like that
(e.g. a confirmed, reproducible drain path) — `models.embargoed()` is there and tested
(`tests/test_scanner_models.py`), but no check calls it with `status: "embargoed"` today. This
is a considered scope line, not an oversight: don't read "no check embargoes anything today" as
"the mechanism is unused" — it's load-bearing for the schema and for every finding's shape, and
ready the moment a check needs it.

## Publication gate

An `embargo` field on a finding is only half of what decides whether something reaches a
reader: the scan is written once by `report.py`, but three things get published from it
(`scanner/results/<date>.json`, `scanner/results/latest.{json,md}`, `docs/index.html`), and
"honour the embargo block" has to be true of every one of them, or the field is decorative.
`scanner/site.py:redact_for_publication(report)` is the one gate all three pass through
(`scanner.cli.cmd_scan` calls it before it ever writes to the public `scanner/results/`
directory; `scanner.cli.cmd_render` calls it too, since `render` accepts any report path
including `results-full/`; `scanner.site.build()` calls it again on whatever it finds in the
public directory, so a raw file that somehow lands there anyway gets corrected by the next
`--sync` rather than staying live). It does three things, all fail-closed:

- **Field-level.** A check whose `embargo.status` isn't `public` (`models.is_public`) has its
  `reason` and `evidence` replaced with a fixed placeholder (`models.HELD_REASON`/
  `HELD_EVIDENCE`), and its own `embargo` block replaced with `models.redact_embargo(...)` --
  `embargo.reason` documents the same sensitive fact one key deeper (the schema's own example:
  "describes a working fund-extraction path") and would otherwise pass through untouched;
  only `status`/`publish_at` survive, since that's all the disclosure-clock line on the page
  needs. The check's name, status and severity are left alone — a finding's *existence* is
  public; the supporting detail is what's held. `render_markdown` also refuses to print a held
  `reason` on its own (see its own defense-in-depth note), belt-and-suspenders alongside this.
- **Entity-level.** An entity whose `project` isn't `Radix Guild` is a third party and is
  dropped from `entities` entirely, not shown with a "held" marker — publicly pairing a named
  third party with a visibly-held finding would insinuate a problem with no evidence behind it,
  which is worse than saying nothing. When this drops at least one row, a note states how many
  entities were scanned in total and how many were withheld this way, without naming them.
- **Note-level.** A cohort or scan note is checked two ways, either of which drops it: it names
  a withheld entity's project, label or address (case-insensitively — catches a note about an
  entity this run actually scanned and withheld), **or** it names anything else that reads as a
  proper noun or organisation/document reference outside a small, explicit allow-list of the
  scanner's own vocabulary and the Guild's own name (`scanner/site.py:_ALLOWED_NOTE_NAMES`) —
  this second rule is what catches a project named only in prose and never a scanned cohort row
  at all, which the first rule structurally cannot see. Deliberately fail-closed: a note wrongly
  withheld costs nothing, a note wrongly published is the whole point of this gate. When this
  drops at least one note, a second, equally honest note states how many, without naming them.
- **Check-text-level.** The field-level rule above only fires when a check's own `embargo`
  isn't `public` — it says nothing about a *published* (Guild) entity's check whose `reason` or
  `evidence` happens to name a withheld third party, which can happen because both fields can
  carry free-text metadata read straight off the ledger. Every public check on a published
  entity is screened for the withheld-entity needles from the entity-level rule; a match
  replaces `reason`/`evidence` with a fixed placeholder and is disclosed by count, the same
  shape as the other three rules.

A silent drop, at any of these four levels, would be exactly the kind of thing this scanner
exists to catch on someone else's project.

The dated report itself is included in what gets gated, not just `latest.json`: it's committed
and served raw from GitHub the same as any other tracked path, so a fix that only covered
`latest.json` would leave the underlying source file as the actual leak.

## The output schema

[`schema/posture-scan-report.schema.json`](../schema/posture-scan-report.schema.json), `1.0`.
Top level: `schema_version`, `scan_id`, `generated_at`, `network`, `gateway` (`url`,
`pinned_state_version`, `pinned_proposer_round_timestamp`, `halted`, `halt_detail`),
`cohort_source`, `notes`, `entities[]`. Each entity: `id` (the stable diff key), `project`,
`category` (`external`|`guild` — provenance only, never a severity input), `address`,
`entity_kind`, `label`, optional `role`, and `checks[]`. Each check: `check`, `status`,
`severity`, `reason`, `evidence` (the exact dotted Gateway field paths read — a reader should be
able to re-derive `reason` from `evidence` alone), `embargo`, `state_version` (recorded per
finding, not just once per run, since a future multi-pass scan could pin different entities at
different moments).

## Diffing two scans

`scanner/diff.py:diff_reports(old, new)` keys on `(entity.id, check.check)` and compares every
field **except** `state_version` (which differs every run even when nothing about the entity
changed, and would otherwise make every finding register as "changed") and reports
`entities_added`/`entities_removed`/`changes`. See `tests/test_scanner_diff.py` for the exact
worked example, including the deliberate "state_version alone moving is not a change" case.

## The cohort

Two files, one convention shared with `scanner/results/` vs `scanner/results-full/`
(`scanner/cohort.py` validates either — fails closed, since a malformed entry must not silently
vanish from a public page):

- [`scanner/data/cohort.json`](../scanner/data/cohort.json) — **committed, public.** Only the
  entities the Guild operates itself (`project: "Radix Guild"`). This is what a clone of this
  repo scans by default, and the only cohort a stranger reading this repo ever sees the shape
  of.
- `scanner/data/cohort-full.json` — **gitignored, never committed.** Adds any external projects
  a given run also wants to cover. `scanner.cli scan` reads this file instead of the public one
  when it's present on disk, falling back to the public cohort otherwise — see the Quickstart
  section above. Its entities and notes can name real third parties and their addresses exactly
  because they never reach a published artefact: the [publication
  gate](#publication-gate) drops every non-Guild entity wholesale, screens every note against an
  allow-list that only clears the Guild's own name, and screens a published check's own
  `reason`/`evidence` for the same withheld names — so naming a third party as a scan target,
  while withholding its results, never happens on a page a stranger can read. Operating this
  file, including deciding which external projects belong in it and disclosing any deviation
  from the intended scope, is a local decision that stays local.

The third-party-shaped examples in the checks above (Check 1's pass/fail rows, Check 2's
`DenyAll`/`Protected`/`Owner` shapes, Check 3's best-case resource) are exercised by the fixtures
in [`examples/posture-scanner/`](../examples/posture-scanner/README.md), with every identifying
detail replaced. They are test inputs, not findings about any project.

## What was verified live, and what wasn't

Re-verified live against `https://mainnet.radixdlt.com` during development (not merely carried
over from an earlier pass): `/status/gateway-status` requires `POST`, not `GET` (405 confirmed);
`/state/entity/details` batches multiple addresses in one call; an unpinned call still returned
the same `NotSyncedUpError` shape hours later; and the Guild's own entities' dApp Definition
back-references, read against the published scans.

**Not verified, disclosed rather than silently assumed:** whether `icon_url`/`info_url` values
actually resolve (Check 5 checks typing only, never fetches); whether a project's claimed fee
rate matches simulated-swap behavior (floated during scoping, never built); whether any
`AllowAll` code path (Check 2's critical fail, Check 3's critical/high fails) ever fires on a
real project — none of the entities scanned to date exercises them, so those tests are
necessarily synthetic.
