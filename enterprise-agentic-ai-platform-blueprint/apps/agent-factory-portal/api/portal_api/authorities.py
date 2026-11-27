# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which portal role holds the registrar and the approver authority, and for which tenants.

Shared by the read API (to tell the front end what to offer) and the action
functions (which enforce it through the authorization core).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

REGISTRAR_ROLES = frozenset({"platform", "developer"})
APPROVER_ROLES = frozenset({"platform", "approver", "security"})
CONTAIN_ROLES = frozenset({"security", "platform", "sre"})
RELEASE_ROLES = frozenset({"security", "platform"})
ALL_TENANTS = "*"


def holds_all_tenants(role: str) -> bool:
    """The platform role acts for every tenant."""
    return role == "platform"


def tenants_of(groups: Iterable[str], tenant_map: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Tenant ids held through the caller's groups, in first-seen order."""
    held: list[str] = []
    for group in groups:
        for tenant in tenant_map.get(group, ()):
            if tenant != ALL_TENANTS and tenant not in held:
                held.append(tenant)
    return tuple(held)
