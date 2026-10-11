"""Orchestrates one scan run: load cohort -> pin a state_version -> fetch -> run the five checks
per entity -> assemble + write schema/posture-scan-report.schema.json.

The only two-hop fetch in the scanner lives here: after the cohort's own addresses are fetched,
any dApp-Definition account a cohort entity *names* (via `dapp_definition`/`dapp_definitions`
metadata) but that isn't already in the cohort is fetched in a second batched call, so Check 1 can
confirm the back-reference even when the claimed hub itself isn't a first-class cohort row (e.g.
a third party's own dApp Definition account, which this scanner reports ON BEHALF OF
the entity naming it but does not independently grade).
"""
import json
import os

from . import gateway, models, shapes
from .checks import ALL_CHECKS

SCHEMA_VERSION = "1.0"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _repo_relative(path):
    """Repo-root-relative display form of a path, e.g. "scanner/data/cohort.json" regardless of
    whether the caller passed an absolute or a cwd-relative path. Never store an absolute
    filesystem path in a committed report: it would publish the operator's directory layout.
    """
    return os.path.relpath(os.path.abspath(path), _REPO_ROOT)


def _second_hop_addresses(cohort, entity_map):
    """Every dApp-Definition address a cohort entity names that isn't already fetched."""
    wanted = []
    for entity in cohort:
        if entity.get("role") == "dapp_definition_hub":
            continue
        item = entity_map.get(entity["address"])
        if item is None:
            continue
        single = shapes.metadata_single(item, "dapp_definition")
        array = shapes.metadata_array(item, "dapp_definitions") or []
        for addr in ([single] if single else []) + list(array):
            if addr and addr not in entity_map and addr not in wanted:
                wanted.append(addr)
    return wanted


def _known_hubs(entity_map):
    return {
        addr: item for addr, item in entity_map.items()
        if shapes.metadata_single(item, "account_type") == "dapp definition"
    }


def _baseline_evidence_fn(previous_report):
    """Return a function entity_id -> the package_upgrade check's prior evidence (with its own
    nested "baseline" key stripped, since that would be the baseline BEFORE the baseline), or
    None if there's no previous report or no such entity/check in it.
    """
    if not previous_report:
        return lambda entity_id: None

    by_id = {e["id"]: e for e in previous_report.get("entities", [])}

    def lookup(entity_id):
        entity = by_id.get(entity_id)
        if entity is None:
            return None
        for c in entity.get("checks", []):
            if c["check"] == "package_upgrade" and c["status"] != "not_applicable":
                return {k: v for k, v in c["evidence"].items() if k != "baseline"}
        return None

    return lookup


def run_scan(cohort_path, cohort, previous_report=None, base_url=gateway.GATEWAY_URL_MAINNET,
             generated_at=None, network="mainnet", cohort_source=None):
    """Run one full scan. `cohort` is the already-loaded list of entity dicts (see cohort.py);
    `cohort_path` is used to read the file's own notes and, by default, is recorded as
    cohort_source, normalized to a repo-root-relative path (_repo_relative) -- never an
    absolute filesystem path, even if the caller passed one in. Pass `cohort_source` to record
    a different value instead (verbatim, not repo-relativized) -- cli.py's cmd_scan uses this
    when `cohort_path` is the gitignored full-detail cohort, since a published report's
    cohort_source must never name a path a stranger reading the repo could not resolve. Returns
    the assembled report dict -- does not write it; see write_report().
    """
    generated_at = generated_at or models.utcnow_iso()

    status = gateway.gateway_status(base_url=base_url)
    ledger_state = status["ledger_state"]
    state_version = ledger_state["state_version"]

    halted, halt_detail = gateway.probe_halted(base_url=base_url)

    addresses = [e["address"] for e in cohort]
    entity_map = gateway.entity_details_by_address(addresses, state_version, base_url=base_url)

    second_hop = _second_hop_addresses(cohort, entity_map)
    if second_hop:
        entity_map.update(gateway.entity_details_by_address(second_hop, state_version, base_url=base_url))

    known_hubs = _known_hubs(entity_map)
    baseline_evidence = _baseline_evidence_fn(previous_report)

    context = {
        "state_version": state_version,
        "related_lookup": entity_map.get,
        "known_hubs": known_hubs,
        "baseline_evidence": baseline_evidence,
    }

    entity_results = []
    for entity in cohort:
        item = entity_map[entity["address"]]
        checks = [module.check(entity, item, context) for module in ALL_CHECKS]
        entity_results.append({
            "id": entity["id"],
            "project": entity["project"],
            "category": entity["category"],
            "address": entity["address"],
            "entity_kind": entity["entity_kind"],
            "label": entity["label"],
            **({"role": entity["role"]} if "role" in entity else {}),
            "checks": checks,
        })

    notes = []
    if halted:
        notes.append(
            "Mainnet was halted at the time of this scan (unpinned probe returned NotSyncedUpError). "
            "A clean 'no change since last scan' reading during a halt is not the same claim as "
            "'no changes are pending' -- deferred upgrades/governance actions could land all at "
            "once once the chain resumes."
        )
    notes.extend(cohort_notes_from_file(cohort_path))

    compact_ts = generated_at.replace(":", "").replace("-", "")  # "2026-09-08T09:15:00Z" -> "20260908T091500Z"
    scan_id = f"{compact_ts}-sv{state_version}"

    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "generated_at": generated_at,
        "network": network,
        "gateway": {
            "url": base_url,
            "pinned_state_version": state_version,
            "pinned_proposer_round_timestamp": ledger_state.get("proposer_round_timestamp"),
            "halted": halted,
            "halt_detail": halt_detail,
        },
        "cohort_source": cohort_source if cohort_source is not None else _repo_relative(cohort_path),
        "notes": notes,
        "entities": entity_results,
    }


def cohort_notes_from_file(cohort_path):
    """Echo the cohort file's own top-level "notes" (e.g. a cohort-composition disclosure) into
    the report, so a reader of the report alone sees them without also having to open the
    cohort file itself.
    """
    try:
        with open(cohort_path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    return list(raw.get("notes", []))


def dump_report(report):
    """The exact JSON text `write_report` writes to disk, as a string.

    Extracted so any caller that needs report bytes without touching the filesystem --
    `scanner.site.build()`'s gated `latest.json`, tests -- stays byte-identical to what
    `write_report` puts on disk, instead of re-deriving the same `json.dumps(..., indent=2)`
    formatting a second place that could drift from this one.
    """
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def write_report(path, report):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dump_report(report))


def load_report(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --- Human-readable rendering -------------------------------------------------
#
# The scan writes report.json (write_report, above); that is the machine-readable
# artifact the CI gate and any downstream agent consume. render_markdown turns the
# SAME report dict into the page a person reads -- the scanner's public "here is
# what we found" surface -- without a second scan, so it works unchanged during a
# chain halt (it reads the pinned report, never the live Gateway).
#
# render_markdown never prints a held check's real `reason` (models.is_public/HELD_REASON,
# below) even when called on an unredacted report -- see scanner/site.py's
# redact_for_publication for the entity-scope half of the publication gate, which this
# function does not apply on its own (a caller that wants a project's entities withheld
# entirely, not just field-redacted, must gate the report before calling this).

_STATUS_MARK = {
    "pass": "PASS",
    "fail": "FAIL",
    "informational": "info",
    "not_applicable": "n/a",
}

# Only fail carries real weight; everything else is informational-or-better by the
# severity discipline in models.py. Ordered most -> least concerning for the rollup.
_CONCERN_ORDER = ("critical", "high", "medium", "low", "informational", "none")


def _short_addr(addr):
    """`account_rdx1abc...wxyz` -> `account_rdx1abc…wxyz` (first 14 + last 6). Full
    address always stays in the report.json; this is for the readable table only."""
    if not addr or len(addr) <= 24:
        return addr
    return f"{addr[:14]}…{addr[-6:]}"


def _rollup(entities):
    """Count fails by severity across every entity, for the summary line."""
    counts = {sev: 0 for sev in _CONCERN_ORDER}
    fails = 0
    for e in entities:
        for c in e.get("checks", []):
            if c["status"] == "fail":
                fails += 1
                counts[c["severity"]] = counts.get(c["severity"], 0) + 1
    return fails, counts


def render_markdown(report):
    """Render a scan report dict (as produced by run_scan / read by load_report) to a
    Markdown string. Pure function of the report -- no Gateway calls, no clock reads --
    so it is deterministic and halt-safe. Mirrors the JSON exactly; it never
    re-derives a status or softens a `fail`.
    """
    gw = report.get("gateway", {})
    entities = report.get("entities", [])
    fails, counts = _rollup(entities)

    lines = []
    lines.append("# Radix posture scan")
    lines.append("")
    lines.append(
        f"_Scan `{report.get('scan_id', '?')}` · {report.get('network', '?')} · "
        f"generated {report.get('generated_at', '?')}._"
    )
    lines.append("")

    # Halt banner -- the one piece of context a reader must not miss.
    if gw.get("halted"):
        lines.append(
            "> **The network was halted when this scan ran.** Reads are pinned to ledger "
            f"state `{gw.get('pinned_state_version')}` "
            f"(proposer round {gw.get('pinned_proposer_round_timestamp')}). A \"no change "
            "since last scan\" reading during a halt is **not** the same as \"no changes are "
            "pending\" — deferred upgrades or governance actions can land all at once when the "
            "chain resumes. Re-run on resume."
        )
        lines.append("")
    else:
        lines.append(
            f"Reads pinned to ledger state `{gw.get('pinned_state_version')}`."
        )
        lines.append("")

    # Headline.
    if fails == 0:
        headline = "**No failing checks** across the cohort at this state."
    else:
        by_sev = ", ".join(
            f"{counts[s]} {s}" for s in _CONCERN_ORDER if counts.get(s)
        )
        headline = f"**{fails} failing check{'s' if fails != 1 else ''}** across the cohort ({by_sev})."
    lines.append(headline)
    lines.append("")
    lines.append(
        "Only `FAIL` carries weight. `info` marks a configuration whose correctness depends on "
        "the project's own intent (the canonical case: an ownerless AMM pool is both the correct "
        "permissionless design and, from chain data alone, indistinguishable from a missing "
        "recovery path) — the scanner refuses to call that a failure on a stranger's project. "
        "`n/a` means the check does not apply to that entity kind."
    )
    lines.append("")

    # Per-entity summary table.
    check_order = list(models.CHECKS)
    header = "| Entity | Project | Kind | " + " | ".join(_check_col(c) for c in check_order) + " |"
    sep = "|" + "---|" * (3 + len(check_order))
    lines.append(header)
    lines.append(sep)
    for e in entities:
        by_name = {c["check"]: c for c in e.get("checks", [])}
        cells = []
        for c in check_order:
            cr = by_name.get(c)
            cells.append(_STATUS_MARK.get(cr["status"], cr["status"]) if cr else "—")
        lines.append(
            f"| {e.get('label', e['id'])} | {e.get('project', '')} | {e.get('entity_kind', '')} | "
            + " | ".join(cells)
            + " |"
        )
    lines.append("")

    # Detail: every finding that is not a plain pass/na, with its reason.
    lines.append("## Findings")
    lines.append("")
    any_finding = False
    for e in entities:
        notable = [c for c in e.get("checks", []) if c["status"] in ("fail", "informational")]
        if not notable:
            continue
        any_finding = True
        lines.append(f"### {e.get('label', e['id'])}")
        lines.append("")
        lines.append(
            f"`{_short_addr(e['address'])}` · {e.get('entity_kind', '')} · {e.get('project', '')}"
        )
        lines.append("")
        for c in notable:
            mark = _STATUS_MARK.get(c["status"], c["status"])
            sev = "" if c["severity"] in ("none", "informational") else f" ({c['severity']})"
            # Defense in depth: `cli.py`'s `render` subcommand calls this function directly on
            # whatever report.json it is pointed at, unredacted -- the embargo gate cannot live
            # only in site.build(). A held check's real reason never reaches this string, even
            # then; see models.is_public/HELD_REASON, shared with scanner.site so the two
            # renderers can't disagree about which checks are held or what to say instead.
            reason = c["reason"] if models.is_public(c) else models.HELD_REASON
            lines.append(f"- **{_check_col(c['check'])} — {mark}{sev}.** {reason}")
        lines.append("")
    if not any_finding:
        lines.append("_Every check passed or was not applicable — no findings to detail._")
        lines.append("")

    # Cohort notes verbatim -- any cohort-composition disclosure, the halt caveat, the
    # "we hold our own entities to the same standard" note.
    notes = report.get("notes", [])
    if notes:
        lines.append("## Notes recorded with this scan")
        lines.append("")
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("---")
    lines.append(
        f"_Cohort: `{report.get('cohort_source', '?')}`. Generated from the pinned "
        "`report.json` by `python3 -m scanner.cli render` — no live network read, so this "
        "page is reproducible from the committed JSON alone._"
    )
    lines.append("")
    return "\n".join(lines)


def _check_col(check):
    """A short, human column/label name for a check id."""
    return {
        "dapp_definition_two_way": "dApp-def two-way",
        "owner_role": "Owner role",
        "resource_authority": "Resource authority",
        "package_upgrade": "Upgrade",
        "metadata_claims": "Metadata",
    }.get(check, check)
