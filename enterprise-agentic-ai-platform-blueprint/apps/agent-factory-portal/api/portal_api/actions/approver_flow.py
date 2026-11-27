# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Approver actions: approve or reject a record that was submitted for approval."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from portal_api import registrations
from portal_api.actions import approver, authority
from portal_api.actions.engine import ActionEngine, ActionError, Target
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import error_code
from portal_api.models.portal import ActionResult, DecisionInput, Registration

_STATUS = {"approve": "APPROVED", "reject": "REJECTED"}


def _registration(record: dict[str, Any]) -> Registration:
    document = registrations.agent_document(record)
    if document is None:
        raise ActionError(404, "Registration not found")
    return registrations.to_registration(record, document)


def decide(engine: ActionEngine, action: str, record_id: str, body: DecisionInput) -> ActionResult:
    if not authority.has_authority(engine.principal, action):
        # Refused before the record is read, so the answer does not reveal whether it exists.
        blind = Target(action=action, tenant_id=authority.NO_TENANT, record_name="", record_id=record_id)
        engine.authorize(blind, {"recordId": record_id}, None)
    try:
        record = approver.get_record(engine.registry, engine.settings.registry_id, record_id)
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            raise ActionError(404, "Registration not found") from exc
        raise ActionError(502, f"An AWS service call failed ({error_code(exc)})") from exc
    document = registrations.agent_document(record)
    if document is None:
        raise ActionError(404, "Registration not found")

    target = Target(
        action=action,
        tenant_id=str(document.get("tenantId")),
        record_name=str(record.get("name")),
        record_id=record_id,
        status_before=str(record.get("status")),
        document_sha256=registrations.sha256(registrations.canonical(document)),
    )
    # The submitter is whoever the audit trail says submitted the record last.
    submitted = audit_reader.submitter(engine.events(record_id))
    state: dict[str, Any] = {
        "recordId": record_id,
        "tenantId": document.get("tenantId"),
        "status": record.get("status"),
        "references": authority.approved_references(document),
    }
    if submitted is not None:
        state["submittedBy"] = submitted.actor_subject
    allow_reason = engine.authorize(target, {"recordId": record_id, "tenantId": target.tenant_id}, state)

    if target.status_before != "PENDING_APPROVAL":
        raise engine.deny(
            target, 409, f"Only a record that is pending approval can be decided; this one is {target.status_before}"
        )
    if body.document_sha256 and body.document_sha256 != target.document_sha256:
        raise engine.deny(target, 409, "The record changed since it was read; review it again")

    def call() -> dict[str, Any]:
        approver.set_status(engine.registry, engine.settings.registry_id, record_id, _STATUS[action], body.reason)
        return approver.get_record(engine.registry, engine.settings.registry_id, record_id)

    # An approval keeps the approved document with its event, so a later change can be compared with it.
    attributes = {audit_reader.DOCUMENT_ATTRIBUTE: registrations.canonical(document)} if action == "approve" else None
    return engine.perform(
        target, allow_reason, call, _registration, result_reason=body.reason, result_attributes=attributes
    )
