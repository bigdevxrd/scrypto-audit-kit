"""Render a scan report to the public status page.

The scanner already produces two artefacts: `report.json` (the record) and, via
`report.render_markdown`, a readable `.md` beside it. Both live in the repo tree, which
means the only way a stranger reaches them is by knowing to browse `scanner/results/`.
This module renders the same report to a standalone HTML page that can be served —
GitHub Pages from `docs/`, or copied anywhere — so "check the scanner" is a URL.

Three properties this renderer holds to, in order of importance:

1. **It never softens a `fail`.** Like `render_markdown`, this is a pure projection of
   the JSON. It does not re-derive a status, re-rank a severity, or drop a row.
2. **It honours the embargo block.** A finding whose `embargo.status` is not `public`
   renders as *existence + severity + the publish clock* and nothing else — no reason,
   no evidence. That is the line between an instrument and a zero-day broadcast, and it
   is enforced here rather than left to whoever writes the next check.
3. **It is deterministic.** No clock read, no network, no environment. The same report
   renders byte-identical every time, so `tests/test_scanner_site.py` can assert the
   committed page matches the committed report — a stale page fails CI instead of
   quietly misinforming a reader.
4. **It withholds a third party's entities wholesale, never with a "held" marker.**
   `build()` publishes only the cohort rows we operate ourselves (see
   `redact_for_publication`); every other project's rows are dropped entirely rather
   than shown with their detail redacted, because pairing a named third party with a
   visibly-held finding insinuates a problem with no evidence behind it — worse than
   silence. The page instead states, honestly, how many rows that was.

`build()` is the one function that produces all three published artefacts (`latest.json`,
`latest.md`, `docs/index.html`, and — since the dated report itself is committed and served
raw from GitHub, not just linked from here — the dated `scanner/results/<date>.json` it reads
from), and it always derives them from `redact_for_publication(report)`, never the raw scan.
That gate is the one place both the check-level embargo and the entity-scope withholding are
applied together; see its own docstring.

Usage:

    python3 -m scanner.site scanner/results/latest.json docs/index.html
"""

import copy
import html
import json
import os
import re
import sys

from scanner import models
from scanner import report as report_mod

_STATUS_MARK = {
    "pass": "PASS",
    "fail": "FAIL",
    "informational": "info",
    "not_applicable": "n/a",
    "embargoed": "held",
}

# The order checks appear as columns. Anything not listed is appended, so a new check
# shows up on the page the day it ships rather than silently going missing.
_COLUMN_ORDER = (
    "dapp_definition_two_way",
    "owner_role",
    "resource_authority",
    "package_upgrade",
    "metadata_claims",
)


def _check_columns(entities):
    seen = []
    for entity in entities:
        for check in entity.get("checks", []):
            name = check["check"]
            if name not in seen:
                seen.append(name)
    ordered = [c for c in _COLUMN_ORDER if c in seen]
    ordered += [c for c in seen if c not in _COLUMN_ORDER]
    return ordered


# Shared with scanner.report, not reimplemented here -- see models.is_public's own docstring
# for why one predicate matters more than a locally-obvious one-liner.
_is_public = models.is_public

# The one project whose entities are published. This is a fixed publication policy (see docs/
# posture-scanner.md#publication-gate), not a config knob -- every other `project` value in the
# cohort is a third party and is withheld wholesale by redact_for_publication, below.
OWN_PROJECT = "Radix Guild"


def _withheld_needles(withheld_entities):
    """Lower-cased project/label/address strings identifying the entities `redact_for_publication`
    is about to drop -- the exact vocabulary a cohort note would use to name one of them.
    Collected here, before the entities themselves are discarded, because it's the last point
    the note-gating pass below has anything to match against.
    """
    needles = []
    for entity in withheld_entities:
        for field in ("project", "label", "address"):
            value = entity.get(field)
            if value:
                needles.append(str(value).lower())
    return needles


def _check_text_names_a_withheld_entity(check, needles):
    """True if `check`'s own `reason` or `evidence` (every string leaf, however deeply
    nested -- `evidence` is arbitrary JSON) contains one of `needles`, case-insensitively.
    Shares its vocabulary with the note gate (`_withheld_needles`) because the concern is
    the same: a withheld entity's own name reaching a published artefact through free text
    that isn't itself the withheld entity's row -- see redact_for_publication's rule 4.
    """
    haystack = str(check.get("reason") or "").lower() + " " + _evidence_text(check.get("evidence")).lower()
    return any(needle in haystack for needle in needles)


def _evidence_text(evidence):
    """Flatten every string leaf of an evidence value (dict/list/str, arbitrarily nested,
    per the schema's "non-empty dict of the fields actually read") into one blob the name
    screen can substring-match against. Non-string leaves (numbers, booleans, None) carry
    no name to find and are skipped.
    """
    parts = []

    def _walk(value):
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _walk(v)
        elif isinstance(value, list):
            for v in value:
                _walk(v)

    _walk(evidence)
    return " ".join(parts)


# The only vocabulary a cohort/scan note is allowed to name without the whole note being
# withheld -- see `_note_is_safe`. Deliberately small and reviewed by hand: this project's own
# name (and its short form), the Radix network names this scanner's own halt banner can
# name, and the one technical token that banner also names. This is an ALLOW-LIST, not a
# blocklist scoped to "entities withheld this run" (that's `_withheld_needles`, used
# separately) -- anything not here that looks like a proper noun or organisation/document
# reference is presumed to be a name this report has not cleared for publication.
_ALLOWED_NOTE_NAMES = frozenset(
    name.lower() for name in (
        OWN_PROJECT,  # "Radix Guild"
        "Guild",
        "Radix",
        "Mainnet",
        "Stokenet",
        "Testnet",
        "This",
        "The",
        "Only",
        "NotSyncedUpError",  # the one technical token report.py's own halt banner names
    )
)

# A run of one-or-more capitalized/acronym-shaped words -- the shape a proper noun or an
# organisation/document name takes in English prose -- joined by spaces, hyphens or slashes so a
# multi-word or slash/hyphen-joined name ("Radix Guild", "ExampleCo/ExampleCoAlt",
# "Q3-PLANNING.md") matches as one span rather than as separate, individually-innocuous
# words. An optional trailing filename extension is folded into the same span for the same
# reason.
_NAME_SPAN_RE = re.compile(
    r"[A-Z][A-Za-z0-9]*(?:[-/][A-Z][A-Za-z0-9]*)*(?:\s[A-Z][A-Za-z0-9]*(?:[-/][A-Z][A-Za-z0-9]*)*)*(?:\.[A-Za-z]{2,4})?"
)


def _note_is_safe(note, allowed=_ALLOWED_NOTE_NAMES):
    """True if `note` names nothing that looks like a proper noun or organisation/document
    reference outside `allowed`. A lone capital letter ("A", "I") is never itself a name and
    is always safe; every other capitalized span (`_NAME_SPAN_RE`) must match `allowed`
    exactly, case-insensitively, or the whole note is unsafe.

    This closes the gap in matching only entities withheld THIS run (`_withheld_needles`):
    a project named only in a cohort note's prose, and never itself a scanned cohort entity
    (for example a candidate considered and dropped before a scan ever ran), has no
    entity-derived needle to match against and would otherwise publish verbatim. Deliberately
    fail-closed -- a note wrongly withheld costs nothing; a note wrongly published is the
    whole problem this gate exists to prevent.
    """
    for match in _NAME_SPAN_RE.finditer(str(note)):
        span = match.group(0)
        if len(span) <= 1:
            continue
        if span.lower() not in allowed:
            return False
    return True


def _filter_withheld_notes(notes, withheld_entities):
    """Drop any note that either (a) names a withheld entity's project, label or address
    (case-insensitive substring match against entities withheld THIS run), or (b) fails the
    allow-list name screen (`_note_is_safe`) -- see redact_for_publication's own docstring,
    rule 3, for why both checks exist. Returns (kept_notes, dropped_count). A note that trips
    neither passes through unchanged.
    """
    needles = _withheld_needles(withheld_entities)
    kept = []
    dropped = 0
    for note in notes:
        lowered = str(note).lower()
        names_a_withheld_entity = any(needle in lowered for needle in needles)
        if names_a_withheld_entity or not _note_is_safe(note):
            dropped += 1
            continue
        kept.append(note)
    return kept, dropped


def redact_for_publication(report):
    """Return a deep copy of `report` gated for publication. Never mutates its input.

    Four independent redactions, all fail-closed, all applied before any of the three
    published artefacts are derived from the result (see build()):

    1. **Field-level.** For every check on a published entity whose embargo block is not
       `public` (`_is_public`), `reason` is replaced with `models.HELD_REASON`, `evidence`
       with `models.HELD_EVIDENCE`, and the check's own `embargo` block with
       `models.redact_embargo(...)` -- the block's own `reason` field documents the same
       sensitive fact (the schema's example: "describes a working fund-extraction path"),
       so it cannot pass through deepcopy untouched just because it's nested one level
       down; only `status`/`publish_at` survive, since that's all `render_html`'s
       disclosure-clock line needs. The check's `check` name, `status` and `severity` are
       left untouched — a finding's *existence* is public; only the supporting detail is
       held. (`render_html` and `render_markdown` also refuse to print a held `reason` on
       their own, so this is belt-and-suspenders, not the only layer — but latest.json has
       no renderer standing between it and a reader, so the redaction has to happen at the
       data layer too.)
    2. **Entity-level.** Every entity whose `project` is not OWN_PROJECT is a third
       party and is dropped from `entities` entirely — not kept with a "held" marker,
       because publicly pairing a named third party with a visibly-held finding
       insinuates a problem without evidence, which is worse than saying nothing.
    3. **Note-level.** A withheld entity's project, label or address naming it in the
       report's own top-level `notes` (case-insensitively, via `_filter_withheld_notes`)
       undoes rule 2 just as surely as printing its row would — the entity gate is
       decorative if the two paragraphs below it say the name out loud. Such a note is
       dropped, not edited in place, since there is no way to redact "this note is about
       a withheld project" without either naming it or leaving a conspicuous gap. This is
       NOT the only way a note can name a third party, though: a project mentioned only in
       prose, never a scanned cohort entity this run, has no needle here to match against
       (real example: a candidate project considered and dropped before a scan ever ran) —
       see `_note_is_safe`'s own docstring for the allow-list check that closes that gap.
    4. **Check-text-level.** Rule 1 only fires when a check's own `embargo` isn't `public`
       — it says nothing about a *published* entity's own check whose `reason` or
       `evidence` happens to name a withheld third party, which can happen because both
       are free text and `evidence` in particular can carry Gateway metadata values read
       straight off the ledger. Every check that survives rule 1 on a published entity is
       screened against the same withheld-entity needles rule 3 uses; a match replaces
       `reason`/`evidence` with `models.NAME_SCREEN_REASON`/`NAME_SCREEN_EVIDENCE` and is
       disclosed by count, the same as rules 2 and 3.

    When rule 2 drops at least one entity, a note states how many were scanned in total and
    how many were withheld this way, without naming them. When rule 3 drops at least one
    note, a second note states how many, again without naming them. When rule 4 screens at
    least one check, a third note states how many. The same honesty principle applies to
    all three: a silent drop would be exactly the kind of thing this scanner exists to
    catch on someone else's project.

    Idempotent: gating an already-gated report re-applies all four rules to no further
    effect (no more third-party entities left to identify, so no needles, so no note or
    check-text gets touched and no further disclosure gets appended) -- build() relies on
    this to gate the dated report file itself in place, not just derive latest.json/.md and
    the page from it, without double-counting on a second sync.
    """
    gated = copy.deepcopy(report)

    all_entities = gated.get("entities", [])
    published = [e for e in all_entities if e.get("project") == OWN_PROJECT]
    withheld_entities = [e for e in all_entities if e.get("project") != OWN_PROJECT]
    gated["entities"] = published

    needles = _withheld_needles(withheld_entities)
    checks_screened = 0
    for entity in published:
        for check in entity.get("checks", []):
            if not _is_public(check):
                check["reason"] = models.HELD_REASON
                check["evidence"] = dict(models.HELD_EVIDENCE)
                check["embargo"] = models.redact_embargo(check.get("embargo"))
            elif needles and _check_text_names_a_withheld_entity(check, needles):
                check["reason"] = models.NAME_SCREEN_REASON
                check["evidence"] = dict(models.NAME_SCREEN_EVIDENCE)
                checks_screened += 1

    kept_notes, notes_dropped = _filter_withheld_notes(gated.get("notes", []), withheld_entities)
    gated["notes"] = kept_notes

    if withheld_entities:
        withheld = len(withheld_entities)
        total = len(published) + withheld
        gated["notes"].append(
            f"This scan covered {total} entities; {withheld} third-party "
            f"{'entity is' if withheld == 1 else 'entities are'} withheld from this "
            "published report. Only the entities we operate ourselves are shown here."
        )
    if notes_dropped:
        # Deliberately one reason-agnostic message, not "names a project withheld from this
        # report": that claim is only true for a needle match against an entity withheld THIS
        # run, and would overclaim for a note the allow-list screen caught instead (a name
        # never a scanned entity at all -- see _note_is_safe). "A name this report does not
        # publish" is true either way.
        gated["notes"].append(
            f"{notes_dropped} cohort {'note was' if notes_dropped == 1 else 'notes were'} "
            f"withheld from this published report because {'it referenced' if notes_dropped == 1 else 'they referenced'} "
            "a name this report does not publish."
        )
    if checks_screened:
        gated["notes"].append(
            f"{checks_screened} check finding{'s' if checks_screened != 1 else ''} on our own "
            "published entities had reason/evidence text withheld because it referenced a "
            "project this report does not publish."
        )

    return gated


def _esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def _pill(status):
    return f'<span class="pill s-{_esc(status)}">{_esc(_STATUS_MARK.get(status, status))}</span>'


def _format_state_version(value):
    """Thousands-grouped display form of a state version -- 557840622 -> "557,840,622" --
    for the pinned-snapshot banner only; every other place on the page (the state bar's
    "Ledger state" datum, the halt note's own <code>) keeps printing the plain digits, so
    the exact digit string a reader might grep for still appears unchanged elsewhere.
    Anything that isn't a plain int (a bool, a string, None -- the last being what a
    malformed or partial report would carry) falls back to `_esc`'s own str()-and-escape
    rather than raising: a display nicety must never crash the renderer over a field shape
    it doesn't expect.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    return _esc(value)


def _format_pinned_timestamp(value):
    """"2026-08-31T21:19:06.179Z" -> "2026-08-31 21:19 UTC" -- a friendlier display form of
    the ledger's own proposer-round timestamp for the pinned-snapshot banner, built from a
    fixed-shape regex match rather than a datetime parse. No clock, no timezone/locale
    dependence, so this stays exactly as pure as the rest of the module. Falls back to the
    raw escaped value for any shape this fixed pattern doesn't recognise (a differently
    formatted timestamp, a future schema change) rather than guessing at one; returns ""
    for None, which the banner treats as "nothing to say" and omits the whole clause.
    """
    if value is None:
        return ""
    match = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):\d{2}(?:\.\d+)?Z$", str(value))
    if not match:
        return _esc(value)
    date, hour, minute = match.groups()
    return f"{date} {hour}:{minute} UTC"


def _pinned_snapshot_banner(gateway):
    """The top-of-page banner text stating what ledger snapshot this report is pinned to,
    and -- only when the report's own `gateway.halted` field says so -- that the network
    had not produced a newer state when the scan ran. Never probes, never infers a liveness verdict of
    its own: `halted` must be the literal boolean `True`; anything else (False, missing, a
    malformed report shape) gets the same halt-agnostic fixed sentence instead, because a
    scan is a pinned point-in-time read regardless of whether the network happened to be
    halted when it ran, and a reader opening this page well after the fact (the exact risk
    a long halt creates) must not have to infer that from the "Ledger state" datum in the
    stats bar alone.
    """
    pinned = gateway.get("pinned_state_version")
    pinned_ts = _format_pinned_timestamp(gateway.get("pinned_proposer_round_timestamp"))
    lead = f"Pinned at state version <code>{_format_state_version(pinned)}</code>"
    lead += f" &mdash; ledger last advanced {pinned_ts}." if pinned_ts else "."
    if gateway.get("halted") is True:
        tail = (
            " The network had not produced a newer state when the scan ran; these "
            "results describe that snapshot and are not refreshed automatically."
        )
    else:
        tail = (
            " These results describe that pinned state, not the ledger as it is now; "
            "scans are run by hand and this page is not refreshed automatically."
        )
    return lead + tail


def render_html(report):
    """Render a scan report dict to a complete, self-contained HTML document.

    Pure function of the report: no clock, no network, no filesystem. Mirrors the JSON
    and the Markdown rendering exactly.
    """
    gateway = report.get("gateway", {})
    entities = report.get("entities", [])
    fails, counts = report_mod._rollup(entities)
    columns = _check_columns(entities)
    halted = bool(gateway.get("halted"))
    pinned = gateway.get("pinned_state_version")

    severity_line = ", ".join(
        f"{count} {severity}"
        for severity, count in counts.items()
        if count and severity != "none"
    )

    out = []
    add = out.append
    # No Jekyll front matter and no `.nojekyll`: GitHub Pages serves this file verbatim as
    # the site root while STILL rendering the sibling `docs/*.md` as pages, which is
    # strictly more useful than turning Jekyll off and serving those as raw text.
    add("<!doctype html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width,initial-scale=1">')
    add("<title>Radix posture scan</title>")
    add(
        '<meta name="description" content="A posture scan of the live Radix entities '
        'Radix Guild operates: what each one states about its own ownership, authority '
        'and upgrade path, read straight from the ledger.">'
    )
    add(f"<style>{_CSS}</style>")
    add("</head><body>")
    add('<main class="wrap">')

    # ── Header ────────────────────────────────────────────────────────────────────
    add("<header>")
    add('<p class="eyebrow">Radix · posture scan</p>')
    add("<h1>What the chain says about itself</h1>")
    add(
        '<p class="lede">Five checks, run against a fixed cohort of live entities, '
        "reading only what each one publishes on-ledger. This page covers only the "
        f"entities {_esc(OWN_PROJECT)} operates itself, graded by the same rules as any "
        "other and not exempted from a failing result. Third-party projects are not "
        "listed, scored or named here.</p>"
    )
    add("</header>")

    # ── Pinned-snapshot banner ────────────────────────────────────────────────────
    # Unconditional -- shown whether or not the network was halted -- because every scan is
    # a pinned point-in-time read and a reader arriving well after the fact must not have to
    # infer that from the "Ledger state" datum in the stats bar below. See
    # _pinned_snapshot_banner's own docstring for the halted/non-halted wording split.
    add(f'<section class="pin{" halted" if halted else ""}">')
    add(f"<p>{_pinned_snapshot_banner(gateway)}</p>")
    add("</section>")

    # ── State bar ─────────────────────────────────────────────────────────────────
    add(f'<section class="state {"halted" if halted else "live"}">')
    add(
        f'<div class="datum"><b>{fails}</b><span>Failing checks</span></div>'
        # "Published", not "scanned": `entities` here is whatever redact_for_publication left
        # standing, and a header stat quietly counting fewer than the scan actually covered
        # would be exactly the silent undercount this project's whole thesis is against. The
        # true count, and how many were withheld, is stated in prose below (see the cohort
        # notes section) rather than folded into this number.
        f'<div class="datum"><b>{len(entities)}</b><span>Entities published</span></div>'
        f'<div class="datum"><b>{_esc(pinned)}</b><span>Ledger state</span></div>'
        f'<div class="datum src"><b>{_esc(gateway.get("url", "").replace("https://", ""))}</b>'
        f"<span>Gateway</span></div>"
    )
    if severity_line:
        add(f'<p class="note">Failures by severity: {_esc(severity_line)}.</p>')
    failing = [e for e in entities if any(c.get("status") == "fail" for c in e.get("checks", []))]
    if failing:
        # Plain acknowledgement, derived from the report like everything else on the page: it
        # names the failing entities and says who operates them, so a reader never has to infer
        # from a table of pills that the failures are the publisher's own. It disappears when a
        # later scan stops failing them -- it never states more than the report does.
        own = all(e.get("project") == OWN_PROJECT for e in failing)
        add(
            f'<p class="note own"><strong>{len(failing)} of {len(entities)} published '
            f"entities have a failing check: "
            f'{_esc(", ".join(str(e.get("label")) for e in failing))}.</strong> '
            + (f"All are entities {_esc(OWN_PROJECT)} operates itself. " if own else "")
            + "They are published as found &mdash; not exempted, reclassified or hidden "
            "&mdash; and stay listed as failing until a later scan reads them differently.</p>"
        )
    if halted:
        add(
            '<p class="note halt"><strong>The network was halted when this scan ran.</strong> '
            f"Every read is pinned to ledger state <code>{_esc(pinned)}</code> "
            f'(proposer round {_esc(gateway.get("pinned_proposer_round_timestamp"))}). '
            "A &ldquo;no change since last scan&rdquo; reading during a halt is <em>not</em> the "
            "same claim as &ldquo;no changes are pending&rdquo; &mdash; deferred upgrades or "
            "governance actions can land all at once when the chain resumes.</p>"
        )
    add("</section>")

    # ── The table ─────────────────────────────────────────────────────────────────
    add("<section>")
    add(
        '<div class="sec-head"><h2>The cohort</h2>'
        f'<span class="eyebrow">Scan {_esc(report.get("scan_id"))} · '
        f'{_esc(report.get("network"))} · {_esc(report.get("generated_at"))}</span></div>'
    )
    add('<div class="scroll"><table><thead><tr><th>Entity</th><th>Project</th>')
    for column in columns:
        add(f"<th>{_esc(report_mod._check_col(column))}</th>")
    add("</tr></thead><tbody>")
    for entity in entities:
        by_name = {c["check"]: c for c in entity.get("checks", [])}
        add("<tr>")
        add(
            f'<td class="ent"><b>{_esc(entity.get("label"))}</b>'
            f'<code>{_esc(report_mod._short_addr(entity.get("address")))}</code></td>'
        )
        add(f'<td>{_esc(entity.get("project"))}</td>')
        for column in columns:
            check = by_name.get(column)
            add(f"<td>{_pill(check['status']) if check else '&mdash;'}</td>")
        add("</tr>")
    add("</tbody></table></div>")
    add(
        '<p class="legend">Only <b>FAIL</b> carries weight. <b>info</b> marks a '
        "configuration whose correctness depends on the project&rsquo;s own intent &mdash; an "
        "ownerless AMM pool is both the correct permissionless design and, from chain data "
        "alone, indistinguishable from a missing recovery path, so the scanner refuses to "
        "call it a failure on a stranger&rsquo;s project. <b>n/a</b> means the check does not "
        "apply to that kind of entity.</p>"
    )
    add("</section>")

    # ── Findings ──────────────────────────────────────────────────────────────────
    add("<section>")
    add('<div class="sec-head"><h2>Findings</h2><span class="eyebrow">Every check, in full</span></div>')
    for entity in entities:
        add('<article class="finding">')
        add(
            f'<h3>{_esc(entity.get("label"))}</h3>'
            f'<p class="meta"><code>{_esc(entity.get("address"))}</code> · '
            f'{_esc(entity.get("entity_kind"))} · {_esc(entity.get("project"))}</p>'
        )
        add("<ul>")
        for check in entity.get("checks", []):
            label = report_mod._check_col(check["check"])
            severity = check.get("severity")
            head = (
                f'{_pill(check["status"])} <b>{_esc(label)}</b>'
                f'<span class="sev">{_esc(severity)}</span>'
            )
            if _is_public(check):
                add(f'<li>{head}<p>{_esc(check.get("reason"))}</p></li>')
            else:
                # Same fail-closed shape check as models.is_public -- not `check.get("embargo")
                # or {}`, which only guards a falsy embargo (`None`, `{}`, `""`). A truthy
                # non-dict (a bare string, a non-empty list) is falsy-or-{} 's blind spot: it
                # stays truthy, so `or {}` leaves it as-is and the `.get()` below raises
                # AttributeError. `is_public` already treats that exact shape as held (not
                # public) via `isinstance`; this mirrors it instead of duck-typing the field.
                embargo = check.get("embargo")
                until = embargo.get("publish_at") if isinstance(embargo, dict) else None
                add(
                    f'<li class="held">{head}'
                    "<p>Detail is held. This finding describes a way to take funds, so it "
                    "goes to the project first and publishes on a fixed clock"
                    + (f" &mdash; <b>{_esc(until)}</b>." if until else ".")
                    + " Its existence and severity are stated above; nothing further is "
                    "published here until then.</p></li>"
                )
        add("</ul></article>")
    add("</section>")

    # ── Method / notes ────────────────────────────────────────────────────────────
    notes = report.get("notes") or []
    if notes:
        add("<section>")
        add(
            '<div class="sec-head"><h2>What this scan does and does not claim</h2>'
            '<span class="eyebrow">Recorded with the run</span></div>'
        )
        add('<ul class="notes">')
        for note in notes:
            add(f"<li>{_esc(note)}</li>")
        add("</ul></section>")

    add(
        '<footer><p>Rendered from <code>'
        f'{_esc(report.get("cohort_source", "the committed report"))}</code> and the scan\'s own '
        "<code>report.json</code> by <code>python3 -m scanner.site</code> &mdash; no live network "
        "read, so this page is reproducible from the committed record alone. The JSON, the "
        "Markdown and this page are held in sync by test.</p></footer>"
    )
    add("</main></body></html>")
    return "\n".join(out) + "\n"


_CSS = """
:root{
  --paper:#F3F2EE;--surface:#FFFFFF;--sunk:#E8E7E1;
  --ink:#16181C;--soft:#4C525A;--faint:#7E858D;
  --rule:#D6D5CE;--rule-soft:#E6E5DF;
  --accent:#2F5D50;--pass:#2C6E49;--fail:#A0332A;--info:#8A6A12;--na:#7E858D;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#0F1113;--surface:#181B1F;--sunk:#0B0D0F;
  --ink:#E8EAE7;--soft:#A6ADB4;--faint:#7B838B;
  --rule:#2A2F35;--rule-soft:#1F2429;
  --accent:#79B5A1;--pass:#6BC496;--fail:#EE8C7F;--info:#DDB25C;--na:#7B838B;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:36px 20px 72px;display:flex;flex-direction:column;gap:34px}
h1{font-size:33px;line-height:1.06;letter-spacing:-.025em;margin:6px 0 0;text-wrap:balance}
h2{font-size:19px;letter-spacing:-.012em;margin:0}
h3{font-size:15.5px;margin:0}
p{margin:0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em;
  background:var(--sunk);padding:1px 4px;border-radius:2px;word-break:break-all}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--faint)}
.lede{color:var(--soft);max-width:64ch;margin-top:11px}
.state{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px 24px;
  background:var(--surface);border:1px solid var(--rule);border-left:4px solid var(--accent);
  border-radius:2px;padding:18px 20px}
.state.halted{border-left-color:var(--info)}
.pin{background:var(--surface);border:1px solid var(--rule);border-left:4px solid var(--accent);
  border-radius:2px;padding:14px 18px;color:var(--soft);font-size:13.5px}
.pin p{max-width:80ch}
.pin code{color:var(--ink)}
.pin.halted{border-left-color:var(--info)}
.datum{display:flex;flex-direction:column;gap:2px}
.datum b{font-family:ui-monospace,Menlo,monospace;font-variant-numeric:tabular-nums;
  font-size:20px;letter-spacing:-.02em}
.datum span{font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--faint)}
.datum.src b{font-size:13px;font-weight:500;letter-spacing:0;color:var(--soft);
  word-break:break-all;align-self:end;padding-bottom:3px}
.state .note{grid-column:1/-1;border-top:1px solid var(--rule-soft);padding-top:12px;
  color:var(--soft);font-size:13.5px;max-width:78ch}
section{display:flex;flex-direction:column;gap:14px}
.sec-head{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;
  border-bottom:1px solid var(--rule);padding-bottom:7px}
.sec-head .eyebrow{margin-left:auto}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:.11em;
  text-transform:uppercase;color:var(--faint);font-weight:500;padding:0 12px 7px 0;
  border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:11px 12px 11px 0;border-bottom:1px solid var(--rule-soft);color:var(--soft);
  vertical-align:top}
td.ent{min-width:230px}
td.ent b{display:block;color:var(--ink);font-weight:600}
td.ent code{background:none;padding:0;font-size:11px;color:var(--faint)}
.pill{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;font-weight:700;
  letter-spacing:.06em;padding:2px 6px;border-radius:2px;border:1px solid currentColor}
.s-pass{color:var(--pass)}.s-fail{color:var(--fail)}
.s-informational{color:var(--info)}.s-not_applicable{color:var(--na);border-color:var(--rule)}
.s-embargoed{color:var(--info)}
.legend{color:var(--soft);font-size:13px;max-width:78ch}
.finding{background:var(--surface);border:1px solid var(--rule);border-radius:2px;
  padding:15px 17px;display:flex;flex-direction:column;gap:9px}
.finding .meta{color:var(--faint);font-size:12px}
.finding ul{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:11px}
.finding li{display:flex;flex-direction:column;gap:4px;border-top:1px solid var(--rule-soft);
  padding-top:10px}
.finding li:first-child{border-top:none;padding-top:0}
.finding li p{color:var(--soft);font-size:13.5px;max-width:80ch}
.finding li.held p{color:var(--info)}
.sev{font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--faint);margin-left:auto}
.finding li b{font-weight:600}
.finding li>:first-child{margin-right:8px}
.notes{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:9px;
  color:var(--soft);font-size:13.5px}
.notes li{max-width:80ch}
footer{border-top:1px solid var(--rule);padding-top:14px;color:var(--faint);font-size:12.5px;
  max-width:80ch}
"""


RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner", "results")
PAGE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "index.html")

_DATED = re.compile(r"^\d{4}-\d{2}-\d{2}\.json$")


def newest_dated_report(results_dir=RESULTS_DIR):
    """Path of the most recent `YYYY-MM-DD.json` in the results directory.

    Filenames sort chronologically because the date format is fixed-width, so this is a
    plain max() rather than a clock read — keeping the whole module deterministic.
    """
    dated = sorted(name for name in os.listdir(results_dir) if _DATED.match(name))
    if not dated:
        raise FileNotFoundError(f"no dated scan reports in {results_dir}")
    return os.path.join(results_dir, dated[-1])


def build(results_dir=RESULTS_DIR, page_path=PAGE_PATH):
    """The published artefacts, derived from the newest dated scan -- all of them gated.

    Returns `{path: content}` rather than writing, so `--check` can compare what is on
    disk against what the newest report implies without touching the tree.

    Four paths, not three: the dated source file itself (`results_dir/<date>.json`) is
    included alongside `latest.json`/`latest.md`/the page, because that dated file is
    committed and served raw from GitHub same as any other tracked path -- if a raw,
    ungated scan ever lands there (by mistake, or because a caller resynced before
    scanner.cli's scan step could gate it on write — see cli.py), `--sync` corrects it in
    place instead of leaving the one artefact nobody thought to check. redact_for_publication
    is idempotent, so re-gating an already-gated dated file is a no-op.
    """
    source = newest_dated_report(results_dir)
    with open(source, encoding="utf-8") as handle:
        report = json.load(handle)
    gated = redact_for_publication(report)
    gated_json = report_mod.dump_report(gated)
    return {
        source: gated_json,
        os.path.join(results_dir, "latest.json"): gated_json,
        os.path.join(results_dir, "latest.md"): report_mod.render_markdown(gated),
        page_path: render_html(gated),
    }


def main(argv):
    args = argv[1:]
    if args and args[0] in ("--sync", "--check"):
        wanted = build()
        stale = []
        for path, content in sorted(wanted.items()):
            current = None
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    current = handle.read()
            if current == content:
                continue
            stale.append(path)
            if args[0] == "--sync":
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(content)
        if args[0] == "--check" and stale:
            print(
                "stale, re-run `python3 -m scanner.site --sync`:\n  " + "\n  ".join(stale),
                file=sys.stderr,
            )
            return 1
        for path in stale:
            print(f"wrote {path}")
        return 0
    if len(args) == 2:
        with open(args[0], encoding="utf-8") as handle:
            report = json.load(handle)
        # Gated even in this direct, manual-invocation form -- there is no safe reading of
        # "render this report to an HTML file" that should skip the publication gate just
        # because it didn't go through build().
        with open(args[1], "w", encoding="utf-8") as handle:
            handle.write(render_html(redact_for_publication(report)))
        return 0
    print(
        "usage: python3 -m scanner.site --sync | --check | <report.json> <out.html>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
