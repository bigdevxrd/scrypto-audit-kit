"""Load and validate the cohort config: the list of Radix mainnet entities a scan run covers.

Deliberately a flat JSON file of plain dicts (schema/posture-scan-cohort.schema.json), not a
Python module or a database -- adding a project to the next scan is a one-line PR to
scanner/data/cohort.json, reviewable by anyone, no code change required.
"""
import json
import re

_ADDRESS_RE = re.compile(r"^(account|component|resource|package)_(rdx|tdx)1[a-zA-Z0-9]+$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_REQUIRED_FIELDS = ("id", "project", "category", "address", "entity_kind", "label")
_VALID_CATEGORIES = ("external", "guild")
_VALID_KINDS = ("account", "component", "resource", "package")


class CohortError(Exception):
    """The cohort config file itself is malformed -- not a finding about any entity in it."""


def load_cohort(path):
    """Read + validate a cohort JSON file. Returns the list of entity dicts (the "entities" key).

    Validation is intentionally strict and fails closed: a malformed cohort entry could otherwise
    silently drop an entity from a public transparency page with nobody noticing.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise CohortError(f"cannot read cohort file at {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CohortError(f"cohort file at {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or "entities" not in data:
        raise CohortError(f"cohort file at {path} must be an object with an 'entities' array")

    entities = data["entities"]
    if not isinstance(entities, list) or not entities:
        raise CohortError(f"cohort file at {path}: 'entities' must be a non-empty array")

    seen_ids = set()
    seen_addresses = set()
    for i, entity in enumerate(entities):
        _validate_entity(entity, i, path)
        if entity["id"] in seen_ids:
            raise CohortError(f"cohort file at {path}: duplicate id {entity['id']!r}")
        if entity["address"] in seen_addresses:
            raise CohortError(f"cohort file at {path}: duplicate address {entity['address']!r}")
        seen_ids.add(entity["id"])
        seen_addresses.add(entity["address"])

    return entities


def _validate_entity(entity, index, path):
    if not isinstance(entity, dict):
        raise CohortError(f"cohort file at {path}: entities[{index}] must be an object")

    missing = [f for f in _REQUIRED_FIELDS if f not in entity]
    if missing:
        raise CohortError(f"cohort file at {path}: entities[{index}] missing required field(s): {missing}")

    if not _ID_RE.match(entity["id"]):
        raise CohortError(f"cohort file at {path}: entities[{index}].id {entity['id']!r} must match {_ID_RE.pattern}")

    if entity["category"] not in _VALID_CATEGORIES:
        raise CohortError(
            f"cohort file at {path}: entities[{index}].category {entity['category']!r} "
            f"must be one of {_VALID_CATEGORIES}"
        )

    if entity["entity_kind"] not in _VALID_KINDS:
        raise CohortError(
            f"cohort file at {path}: entities[{index}].entity_kind {entity['entity_kind']!r} "
            f"must be one of {_VALID_KINDS}"
        )

    if not _ADDRESS_RE.match(entity["address"]):
        raise CohortError(
            f"cohort file at {path}: entities[{index}].address {entity['address']!r} "
            f"does not look like a Bech32m Radix address"
        )

    kind_prefix = entity["address"].split("_", 1)[0]
    if kind_prefix != entity["entity_kind"]:
        raise CohortError(
            f"cohort file at {path}: entities[{index}] address prefix {kind_prefix!r} "
            f"does not match declared entity_kind {entity['entity_kind']!r}"
        )
