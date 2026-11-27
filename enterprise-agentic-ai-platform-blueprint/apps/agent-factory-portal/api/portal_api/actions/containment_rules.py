# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Who may contain and release an agent. Pure rules, no AWS calls.

- Contain needs the ``security``, ``platform`` or ``sre`` role.
- Release needs the ``security`` or ``platform`` role, and a different person
  from the one who contained the agent (two-person rule). The ``platform`` role
  does not bypass it.
- The caller must hold the agent's tenant. ``platform`` holds every tenant. An
  agent with no known tenant can be acted on only by ``platform`` and ``security``.

The rules are evaluated in that order and the first that fails decides.
"""

from __future__ import annotations

from dataclasses import dataclass

from portal_api.authorities import CONTAIN_ROLES, RELEASE_ROLES

TENANTLESS_ROLES = frozenset({"security", "platform"})
ACTIONS = ("contain", "release")


@dataclass(frozen=True)
class ContainmentDecision:
    allowed: bool
    reason: str


def _deny(reason: str) -> ContainmentDecision:
    return ContainmentDecision(False, reason)


def evaluate(
    *,
    action: str,
    role: str,
    principal_id: str,
    agent_tenant: str | None,
    held_tenants: tuple[str, ...],
    holds_all_tenants: bool,
    contained_by: str | None,
) -> ContainmentDecision:
    """Decide one containment request. Fails closed on anything unexpected."""
    if action not in ACTIONS:
        return _deny(f"unknown action '{action}' - fail closed")
    if not principal_id or not role:
        return _deny("missing or incomplete principal - fail closed")
    if action == "contain" and role not in CONTAIN_ROLES:
        return _deny(f"contain requires the security, platform or sre role; principal holds '{role}' (CON-01-N)")
    if action == "release" and role not in RELEASE_ROLES:
        return _deny(f"release requires the security or platform role; principal holds '{role}' (CON-02-N)")
    if agent_tenant is None:
        if role not in TENANTLESS_ROLES:
            return _deny(
                "an agent with no known tenant can be contained only by the platform or security role (CON-05-N)"
            )
    elif not holds_all_tenants and agent_tenant not in held_tenants:
        return _deny("the agent belongs to a tenant the principal does not hold (CON-04-N)")
    if action == "release" and contained_by and contained_by == principal_id:
        return _deny("the person who contained the agent cannot release it - two-person rule (CON-03-N)")
    if action == "release":
        return ContainmentDecision(True, "a different person releases the contained agent (CON-03-P)")
    return ContainmentDecision(True, "containment of the agent's Runtime (CON-01-P)")
