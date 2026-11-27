# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which portal role holds which authority, and how the portal's facts are presented to the core.

The authorization rules themselves are in ``portal_api/registration_core.py``
and are not repeated here. This module only translates:

- a portal principal (role, groups) into the core's principal (one authority, one tenant);
- the portal's six actions into the core's four;
- an agent record's approved references into the core's three reference slots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from portal_api import authorities
from portal_api import registration_core as core
from portal_api.authorities import APPROVER_ROLES, REGISTRAR_ROLES
from portal_api.config import ActionSettings
from portal_api.identity.provider import Principal

REGISTRAR_ACTIONS = ("create", "update", "submit", "delete")
APPROVER_ACTIONS = ("approve", "reject")

# The core has no "submit" or "reject". Submitting is a registrar change to a record, so it is
# evaluated as "update" with no reference change. Rejecting is an approver's decision on a
# submitted record, so it is evaluated as "approve" and gets the same separation of duties.
CORE_ACTION = {
    "create": "create",
    "update": "update",
    "submit": "update",
    "delete": "delete",
    "approve": "approve",
    "reject": "approve",
}

NO_TENANT = "(none)"


def holds_all_tenants(principal: Principal) -> bool:
    """The platform role acts for every tenant."""
    return authorities.holds_all_tenants(principal.role)


def tenants_of(principal: Principal, settings: ActionSettings) -> tuple[str, ...]:
    """Tenant ids the caller holds through its groups (``PORTAL_GROUP_TENANT_MAP``)."""
    return authorities.tenants_of(principal.groups, settings.group_tenant_map)


def holds_tenant(principal: Principal, settings: ActionSettings, tenant_id: str) -> bool:
    return holds_all_tenants(principal) or tenant_id in tenants_of(principal, settings)


def core_role(principal: Principal, action: str) -> str:
    """The single authority presented to the core for this action.

    A principal that holds both authorities (the platform role) presents the
    one the action needs. A principal that holds only the other one presents
    that, so the core's deny reason names what the caller actually holds.
    """
    registrar = principal.role in REGISTRAR_ROLES
    approver = principal.role in APPROVER_ROLES
    if action in APPROVER_ACTIONS:
        return core.APPROVER if approver else (core.REGISTRAR if registrar else core.OTHER)
    return core.REGISTRAR if registrar else (core.APPROVER if approver else core.OTHER)


def has_authority(principal: Principal, action: str) -> bool:
    wanted = core.APPROVER if action in APPROVER_ACTIONS else core.REGISTRAR
    return core_role(principal, action) == wanted


def core_principal(principal: Principal, settings: ActionSettings, action: str, tenant_id: str) -> dict[str, str]:
    """The core's principal: the target tenant when the caller holds it, otherwise one it does hold."""
    if holds_tenant(principal, settings, tenant_id):
        tenant = tenant_id
    else:
        held = tenants_of(principal, settings)
        tenant = held[0] if held else NO_TENANT
    return {"principalId": principal.subject, "role": core_role(principal, action), "tenantId": tenant}


def approved_references(document: Mapping[str, Any]) -> dict[str, str]:
    """An agent record's approved references, placed in the core's three slots.

    For an agent record the approved references are ``runtimeArn``,
    ``gatewayArn``, ``subscribedToolIds``, ``riskClass`` and
    ``dataClassification``. The core compares three named slots, so the five
    fields are projected onto them; a change to any field changes a slot.
    """
    tools = ",".join(sorted(str(tool) for tool in document.get("subscribedToolIds") or []))
    return {
        "inferenceTargetArn": str(document.get("runtimeArn") or ""),
        "modelId": f"{document.get('gatewayArn') or ''}|{tools}",
        "rateProfile": f"{document.get('riskClass') or ''}|{document.get('dataClassification') or ''}",
    }
