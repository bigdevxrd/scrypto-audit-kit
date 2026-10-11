"""Small, shared readers over one /state/entity/details response item.

Every function here takes one `item` -- an entry from entity_details()'s "items" array, i.e.
exactly what gateway.entity_details_by_address() hands back per address -- and returns a plain
value or None. Centralized so the five checks parse the Gateway's metadata/role-assignment shapes
identically; verified against real captured responses (examples/posture-scanner/), not guessed:
see docs/posture-scanner.md for the field-path citations.
"""


def metadata_entry(item, key):
    """Return the raw metadata item dict for `key` (has .value.typed / .is_locked / ...), or None."""
    for entry in item.get("metadata", {}).get("items", []):
        if entry.get("key") == key:
            return entry
    return None


def metadata_typed(item, key):
    """Return the '.value.typed' sub-dict for a metadata key, e.g. {"value": "...", "type":
    "GlobalAddress"} or {"values": [...], "type": "GlobalAddressArray"}. None if absent.
    """
    entry = metadata_entry(item, key)
    if entry is None:
        return None
    return entry.get("value", {}).get("typed")


def metadata_single(item, key):
    """Return a scalar metadata value (typed.value), e.g. the "name" string, or None."""
    typed = metadata_typed(item, key)
    if typed is None:
        return None
    return typed.get("value")


def metadata_array(item, key):
    """Return an array metadata value (typed.values), e.g. "claimed_entities", or None."""
    typed = metadata_typed(item, key)
    if typed is None:
        return None
    return typed.get("values")


def owner_role(item):
    """Return details.role_assignments.owner (the {"rule": {"type": ...}, "updater": ...} dict),
    or None if this entity kind carries no role_assignments (shouldn't happen for the four
    global entity kinds the scanner supports, but never assume).
    """
    return item.get("details", {}).get("role_assignments", {}).get("owner")


def role_entries(item):
    """Return details.role_assignments.entries as a {(module, name): assignment_dict} map, where
    assignment_dict is the raw {"resolution": "Owner"} or {"resolution": "Explicit",
    "explicit_rule": {...}} shape. Empty dict if the entity has no role_assignments at all.
    """
    entries = item.get("details", {}).get("role_assignments", {}).get("entries", [])
    out = {}
    for e in entries:
        rk = e.get("role_key", {})
        out[(rk.get("module"), rk.get("name"))] = e.get("assignment", {})
    return out


def explicit_rule_type(assignment):
    """Given one role_entries() value, return its effective rule 'type' string
    ("AllowAll"/"DenyAll"/"Protected"), or the sentinel "Owner" when the role defers to the
    entity's own owner rule (resolution == "Owner", no explicit_rule of its own -- the caller
    must resolve that against owner_role() itself if it needs the concrete type).
    """
    if assignment.get("resolution") == "Owner":
        return "Owner"
    return assignment.get("explicit_rule", {}).get("type")


def package_address_and_blueprint(item):
    """For a component/resource entity: (package_address, blueprint_name, blueprint_version),
    each None if absent. These sit directly on `details` for anything INSTANTIATED from a
    package -- seen on both a component and an account (native Account blueprint) during
    development.
    """
    details = item.get("details", {})
    return details.get("package_address"), details.get("blueprint_name"), details.get("blueprint_version")


def package_codes_and_blueprints(item):
    """For a package entity itself: (code_hash_hexes: list[str], blueprints: {name: version}).
    Deliberately does NOT return code_hex (the WASM itself) -- multi-MB, never needed by any
    check, and never something this scanner should hold in memory or write to a report.
    """
    details = item.get("details", {})
    codes = [c.get("code_hash_hex") for c in details.get("codes", {}).get("items", [])]
    blueprints = {
        b.get("name"): b.get("version")
        for b in details.get("blueprints", {}).get("items", [])
    }
    return codes, blueprints
