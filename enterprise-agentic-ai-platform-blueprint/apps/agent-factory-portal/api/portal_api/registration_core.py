# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Pure authorization core for registry record actions.

A rule-for-rule Python port of ``evaluateRegistrationRequest`` in
``packages/agent-registry/src/agent-registration-api.ts``. It takes and returns
the same shapes (camelCase keys), evaluates the rules in the same order and
returns the same reasons, including the REG-07..REG-12 identifiers. Both
implementations are run against the shared vectors in
``packages/agent-registry/vectors/registration-decisions.json``.

Do not add portal-specific behaviour here. Anything the portal needs on top
(which portal role holds which authority, record status rules, how an agent
record's fields map onto the approved references) lives in the shell,
``portal_api/actions``.

The core is fail-closed: an unknown action, a missing principal or a malformed
request denies.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

APPROVED_REFERENCE_KEYS: tuple[str, ...] = ("inferenceTargetArn", "modelId", "rateProfile")

REGISTRAR = "registry_admin"
APPROVER = "registry_approver"
OTHER = "other"


@dataclass(frozen=True)
class RegistrationDecision:
    decision: str  # "allow" | "deny"
    reason: str
    http_status: int | None = None  # 403 on deny, as in the TypeScript core

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


def _deny(reason: str) -> RegistrationDecision:
    return RegistrationDecision("deny", reason, 403)


def _allow(reason: str) -> RegistrationDecision:
    return RegistrationDecision("allow", reason)


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, Mapping) else None


def evaluate_registration_request(req: Any, current_state: Mapping[str, Any] | None = None) -> RegistrationDecision:
    """Evaluate one request against the authorization contract.

    ``current_state`` is the existing record for update, approve and delete
    (``None`` for create, or when the target record does not exist).
    """
    if not req or not isinstance(req, Mapping):
        return _deny("malformed request")
    p = req.get("principal")
    if not p or not _field(p, "principalId") or not _field(p, "role") or not _field(p, "tenantId"):
        return _deny("missing or incomplete principal — fail closed")
    if not req.get("tenantId"):
        return _deny("missing tenantId — fail closed")

    action = req.get("action")
    role = p["role"]

    if action == "create":
        if role != REGISTRAR:
            return _deny(f"create requires the registrar role; principal holds '{role}' (REG-07-N)")
        if p["tenantId"] != req["tenantId"]:
            return _deny("registrar may only create records in its own tenant")
        return _allow("registrar create of a new record (REG-07-P)")

    if action == "update":
        if role != REGISTRAR:
            return _deny(f"update requires the registrar role; principal holds '{role}' (REG-08-N)")
        if not current_state:
            return _deny("update target record does not exist")
        if current_state.get("tenantId") != p["tenantId"] or req["tenantId"] != p["tenantId"]:
            return _deny("cross-tenant update is denied")
        # Approved-reference immutability (REG-12-N): once APPROVED, changing a
        # bound reference requires re-approval, so deny the in-place update.
        if current_state.get("status") == "APPROVED" and changes_approved_reference(req, current_state):
            return _deny(
                "update of an approved record’s inferenceTarget/modelId/rateProfile requires re-approval (REG-12-N)"
            )
        return _allow("registrar update of a record")

    if action == "delete":
        if role != REGISTRAR:
            return _deny(f"delete requires the registrar role; principal holds '{role}' (REG-10-N)")
        if not current_state:
            return _deny("delete target record does not exist")
        if current_state.get("tenantId") != p["tenantId"]:
            return _deny("cross-tenant delete is denied")
        return _allow("registrar delete of a record")

    if action == "approve":
        if role != APPROVER:
            return _deny(f"approve requires the approver role; principal holds '{role}' (REG-09-N)")
        if not current_state:
            return _deny("approve target record does not exist")
        # Separation of duties (REG-11-N): the approver must not be the submitter.
        submitted_by = current_state.get("submittedBy")
        if submitted_by and submitted_by == p["principalId"]:
            return _deny("the submitter cannot approve its own record — separation of duties (REG-11-N)")
        if current_state.get("tenantId") != p["tenantId"]:
            return _deny("cross-tenant approve is denied")
        return _allow("separate approver approves the submitted record (REG-11-P)")

    return _deny(f"unknown action '{action}' — fail closed")


def changes_approved_reference(req: Mapping[str, Any], current_state: Mapping[str, Any]) -> bool:
    """True if the update proposes a change to any approved-bound reference."""
    proposed = req.get("proposedReferences")
    if not proposed:
        return False
    current = current_state.get("references")
    if not current:
        return False
    return any(
        proposed.get(key) is not None and proposed.get(key) != current.get(key) for key in APPROVED_REFERENCE_KEYS
    )
