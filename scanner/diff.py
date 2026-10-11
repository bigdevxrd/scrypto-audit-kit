"""Diff two posture-scan reports: "what changed since last week."

Keyed on (entity.id, check.check) -- cohort ids must stay stable across scans for this to mean
anything (see cohort.py's uniqueness check and the schema's note on entity_result.id).

Deliberately excludes `state_version` from the equality comparison: every finding's
state_version reflects the pin used for THAT run, so it differs run-to-run even when nothing
about the entity changed -- comparing it would make every finding register as "changed" and
defeat the point. `embargo` IS compared: none of the five shipped checks ever set anything but
public/immediate today, but a future check whose embargo lifts over time should have that show up
as a real change.
"""

_COMPARE_KEYS = ("status", "severity", "reason", "evidence", "embargo")


def diff_reports(old, new):
    """Return a diff dict: entities_added/removed (by cohort id) and a list of per-(entity,
    check) changes, each carrying the old and new {status, severity, reason, evidence, embargo}.
    """
    old_by_id = {e["id"]: e for e in old.get("entities", [])}
    new_by_id = {e["id"]: e for e in new.get("entities", [])}

    added = sorted(set(new_by_id) - set(old_by_id))
    removed = sorted(set(old_by_id) - set(new_by_id))

    changes = []
    for entity_id in sorted(set(old_by_id) & set(new_by_id)):
        old_checks = {c["check"]: c for c in old_by_id[entity_id]["checks"]}
        new_checks = {c["check"]: c for c in new_by_id[entity_id]["checks"]}

        for check_name in sorted(set(old_checks) | set(new_checks)):
            oc, nc = old_checks.get(check_name), new_checks.get(check_name)
            if oc is None:
                changes.append({"entity_id": entity_id, "check": check_name, "old": None, "new": _project(nc)})
                continue
            if nc is None:
                changes.append({"entity_id": entity_id, "check": check_name, "old": _project(oc), "new": None})
                continue
            old_cmp, new_cmp = _project(oc), _project(nc)
            if old_cmp != new_cmp:
                changes.append({"entity_id": entity_id, "check": check_name, "old": old_cmp, "new": new_cmp})

    return {
        "old_scan_id": old.get("scan_id"),
        "new_scan_id": new.get("scan_id"),
        "entities_added": added,
        "entities_removed": removed,
        "changes": changes,
    }


def _project(check_result):
    return {k: check_result[k] for k in _COMPARE_KEYS}


def summarize(diff):
    """One-line-per-change human summary, for the CLI's `diff` subcommand."""
    lines = []
    if diff["entities_added"]:
        lines.append(f"+ {len(diff['entities_added'])} entity(ies) added: {', '.join(diff['entities_added'])}")
    if diff["entities_removed"]:
        lines.append(f"- {len(diff['entities_removed'])} entity(ies) removed: {', '.join(diff['entities_removed'])}")
    if not diff["changes"]:
        lines.append("No check-level changes.")
    for c in diff["changes"]:
        old, new = c["old"], c["new"]
        if old is None:
            lines.append(f"  [{c['entity_id']}] {c['check']}: new check -> {new['status']}/{new['severity']}")
        elif new is None:
            lines.append(f"  [{c['entity_id']}] {c['check']}: check removed (was {old['status']}/{old['severity']})")
        else:
            lines.append(
                f"  [{c['entity_id']}] {c['check']}: {old['status']}/{old['severity']} -> {new['status']}/{new['severity']}"
            )
    return "\n".join(lines)
