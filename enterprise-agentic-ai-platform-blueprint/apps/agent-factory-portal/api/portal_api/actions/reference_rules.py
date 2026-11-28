# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A registration may not name another tenant's resources. Pure rule, no AWS call.

A registration is written by the people it governs. Its tenant is checked
against the tenants the caller holds, but its references (the Runtime, the
Tool Gateway, the policy engine) are only shapes: without this rule a
registrar of one tenant could register another tenant's Runtime as its own,
and the inventory would then show that Runtime under the wrong tenant, owner
and risk class.

The operator's cell configuration says where each tenant runs. A reference
that points into an account and Region where the portal has cells must point
into a cell of the registration's own tenant. A reference into an account and
Region with no configured cell is allowed: that is how an agent detected in
an account the portal does not manage gets registered.

In an account and Region that several tenants share, the place alone does not
say whose a Runtime is: a registration of one tenant could name another
tenant's Runtime there. So a reference into such a place also needs the
caller to hold every tenant that is hosted there. The ``platform`` role holds
every tenant.

The registrar function applies the rule on create and on update, and the
approver function applies it again on approve, so that a record written
before the rule existed, or by other means, is not approved either.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from portal_api.config import Cell
from portal_api.mappers.common import arn_parts

RULE = "REG-13-N"
# The document's references that name a resource of a cell, and what each is called in a refusal.
REFERENCES: tuple[tuple[str, str], ...] = (
    ("runtimeArn", "Runtime"),
    ("gatewayArn", "Tool Gateway"),
    ("policyEngineArn", "policy engine"),
)
HINT = (
    "A registration can name a Runtime, a Tool Gateway and a policy engine of its own tenant's cells, "
    "or of an account and Region in which the portal has no cell. In an account that several tenants "
    "share, only someone who holds every tenant there can name one."
)


def foreign_reference(
    document: Mapping[str, Any],
    cells: Iterable[Cell],
    held_tenants: Iterable[str] = (),
    holds_all_tenants: bool = False,
) -> str | None:
    """Why this registration cannot stand for this caller, or ``None`` when every reference may be named.

    ``held_tenants`` and ``holds_all_tenants`` say which tenants the caller
    holds: the registrar on create and update, the approver on approve.
    """
    tenant = document.get("tenantId")
    cells = tuple(cells)
    held = set(held_tenants)
    for field, what in REFERENCES:
        parts = arn_parts(document.get(field))
        if not parts:
            continue
        hosted = {c.tenant_id for c in cells if (c.account_id, c.region) == (parts["account"], parts["region"])}
        if hosted and tenant not in hosted:
            return f"the registration names a {what} that runs in a cell of another tenant ({RULE})"
        if len(hosted) > 1 and not holds_all_tenants and not hosted <= held:
            return (
                f"the registration names a {what} in an account that several tenants share, "
                f"and the principal does not hold every one of them ({RULE})"
            )
    return None
