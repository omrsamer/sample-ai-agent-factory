# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Who may contain and release an agent. Pure rules, no AWS calls.

- Contain needs the ``security``, ``platform`` or ``sre`` role.
- Release needs the ``security`` or ``platform`` role, and a different person
  from the one who contained the agent (two-person rule). The ``platform`` role
  does not bypass it.
- The caller must hold the agent's tenant. ``platform`` holds every tenant. An
  agent whose tenant cannot be determined can be acted on only by ``platform``.
- The tenant is decided by where the Runtime runs (the cells configured for its
  account and Region) and, in an account that several tenants share, by the
  Runtime's own ``tenant-id`` tag. It is never decided by what a registration
  claims (``tenant_for``).
- A release needs the Runtime's tenant to be the one it was contained under
  (CON-06-N). In a shared account the tenant comes from a tag, and whoever
  can change the tag could otherwise move a contained Runtime into their own
  tenant and release it there. Only ``platform`` releases a Runtime whose
  tenant changed, or whose tenant was not known when it was contained.

The rules are evaluated in that order and the first that fails decides.

``access_refusal`` holds the first part: the role and the tenant. A caller it
refuses has no part in the Runtime, and nothing is read or written about the
Runtime for such a caller. ``evaluate`` adds the two-person rule, which needs
the Runtime's history.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from portal_api.authorities import CONTAIN_ROLES, RELEASE_ROLES

# Only the role that holds every tenant may act when the tenant cannot be determined.
TENANTLESS_ROLES = frozenset({"platform"})
ACTIONS = ("contain", "release")


@dataclass(frozen=True)
class ContainmentDecision:
    allowed: bool
    reason: str


def _deny(reason: str) -> ContainmentDecision:
    return ContainmentDecision(False, reason)


def tenant_for(cell_tenants: Iterable[str], runtime_tenant_tag: str | None = None) -> str | None:
    """The tenant that decides who may act on a Runtime, or ``None`` when it cannot be determined.

    ``cell_tenants`` are the tenants of the cells configured for the Runtime's
    account and Region. That configuration is the operator's, so it is the
    authority. A registration plays no part: it is written by the people it
    governs, approved or not, and cannot move a Runtime into their tenant.

    - One tenant there: that tenant.
    - Several (a shared account): the value of the Runtime's own ``tenant-id``
      tag, when it is one of those tenants. Only the cell's pipeline changes a
      Runtime, so the tag is set by the cell, not by a registration.
    - Otherwise unknown, which only the ``platform`` role may act on. That
      includes a Runtime with no such tag, a tag that names a tenant the
      account does not host, and a tag that could not be read.
    """
    tenants = set(cell_tenants)
    if len(tenants) == 1:
        return next(iter(tenants))
    if runtime_tenant_tag and runtime_tenant_tag in tenants:
        return runtime_tenant_tag
    return None


def access_refusal(
    *,
    action: str,
    role: str,
    principal_id: str,
    agent_tenant: str | None,
    held_tenants: tuple[str, ...],
    holds_all_tenants: bool,
) -> ContainmentDecision | None:
    """The refusal for a caller who has no part in this Runtime, or ``None`` for one who has.

    A caller has a part in a Runtime when the role may take the action and
    the caller holds the Runtime's tenant. Fails closed on anything unexpected.
    """
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
                "an agent whose tenant cannot be determined can be acted on only by the platform role (CON-05-N)"
            )
    elif not holds_all_tenants and agent_tenant not in held_tenants:
        return _deny("the agent belongs to a tenant the principal does not hold (CON-04-N)")
    return None


def evaluate(
    *,
    action: str,
    role: str,
    principal_id: str,
    agent_tenant: str | None,
    held_tenants: tuple[str, ...],
    holds_all_tenants: bool,
    contained_by: str | None,
    contained_tenant: str | None = None,
) -> ContainmentDecision:
    """Decide one containment request. Fails closed on anything unexpected.

    ``contained_by`` is the subject of whoever holds the containment, and
    ``contained_tenant`` the tenant the Runtime had when that person
    contained it. Both are ``None`` when nobody holds it.
    """
    refusal = access_refusal(
        action=action,
        role=role,
        principal_id=principal_id,
        agent_tenant=agent_tenant,
        held_tenants=held_tenants,
        holds_all_tenants=holds_all_tenants,
    )
    if refusal is not None:
        return refusal
    if action == "release" and contained_by and role not in TENANTLESS_ROLES:
        if agent_tenant is None or contained_tenant is None or agent_tenant != contained_tenant:
            return _deny(
                "the Runtime's tenant changed since it was contained; only the platform role can release it (CON-06-N)"
            )
    if action == "release" and contained_by and contained_by == principal_id:
        return _deny("the person who contained the agent cannot release it - two-person rule (CON-03-N)")
    if action == "release":
        return ContainmentDecision(True, "a different person releases the contained agent (CON-03-P)")
    return ContainmentDecision(True, "containment of the agent's Runtime (CON-01-P)")
