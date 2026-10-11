"""The five posture checks. Each module exposes one `check(entity, item, context)` function
returning one finding dict built via scanner.models.make_finding() -- see report.py for how
they're wired together and docs/posture-scanner.md for the severity rationale behind each.
"""
from . import dapp_definition, owner_role, resource_authority, upgrade, metadata

ALL_CHECKS = (dapp_definition, owner_role, resource_authority, upgrade, metadata)
