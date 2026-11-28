# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Approver actions: approve or reject a record that was submitted for approval.

An approval counts as a review. Every approval is also recorded as an
attestation, so the one rule "the latest attestation wins" gives the
effective review date: a re-approval moves it, and so does a later review.
The date recorded is the approved document's ``reviewBy``, and never more
than a year from the approval; a document that names no date gets the day a
year from the approval, so that every approved registration is due at some
point (``reviews.approval_date``).
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from botocore.exceptions import ClientError

from portal_api import registrations, reviews
from portal_api.actions import approver, audit_writer, authority, lifecycle_rules, reference_rules
from portal_api.actions.engine import ActionEngine, ActionError, Target, record_state
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import error_code
from portal_api.models.portal import ActionResult, DecisionInput, Registration

logger = logging.getLogger(__name__)

_STATUS = {"approve": "APPROVED", "reject": "REJECTED"}
REVIEW_NOT_RECORDED = "The approval stands, but its review date could not be recorded."


def _registration(record: dict[str, Any]) -> Registration:
    document = registrations.agent_document(record)
    if document is None:
        raise ActionError(404, "Registration not found")
    return registrations.to_registration(record, document)


def decide(engine: ActionEngine, action: str, record_id: str, body: DecisionInput) -> ActionResult:
    if not authority.has_authority(engine.principal, action):
        # Refused before the record is read, so the answer does not reveal whether it exists. Logged,
        # not written to the record's history: nothing is resolved and the id is the caller's.
        blind = Target(action=action, tenant_id=authority.NO_TENANT, record_name="", record_id=record_id)
        engine.authorize(blind, {"recordId": record_id}, None, resolved=False)
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
    target.state = record_state(target.status_before, target.document_sha256)
    state: dict[str, Any] = {
        "recordId": record_id,
        "tenantId": document.get("tenantId"),
        "status": record.get("status"),
        "references": authority.approved_references(document),
    }
    # The submitter is whoever the audit trail says submitted the record last. The record's history
    # is read only for a caller who holds its tenant: anyone else is refused for the tenant, and
    # that refusal is logged, not written into a history the caller has no part in.
    if authority.holds_tenant(engine.principal, engine.settings, target.tenant_id):
        submitted = engine.submitter(record_id)
        if submitted is not None:
            state["submittedBy"] = submitted.actor_subject
    allow_reason = engine.authorize(target, {"recordId": record_id, "tenantId": target.tenant_id}, state)
    if action == "approve":
        # Checked again here, so that a record written before the rule, or by other means, is not approved.
        foreign = reference_rules.foreign_reference(
            document,
            engine.settings.cells,
            authority.tenants_of(engine.principal, engine.settings),
            authority.holds_all_tenants(engine.principal),
        )
        if foreign is not None:
            error = engine.deny(target, 403, foreign)
            error.extra["hint"] = reference_rules.HINT
            raise error

    retired = lifecycle_rules.retired_refusal(action, target.status_before)
    if retired is not None:
        raise engine.deny(target, 409, retired)
    if target.status_before != "PENDING_APPROVAL":
        raise engine.deny(
            target, 409, f"Only a record that is pending approval can be decided; this one is {target.status_before}"
        )
    if body.document_sha256 and body.document_sha256 != target.document_sha256:
        raise engine.deny(target, 409, "The record changed since it was read; review it again")

    request_id = audit_writer.new_request_id()
    # An approval keeps the approved document with its event, so a later change can be compared with it.
    # When it also records a review date, the event names that attestation.
    attributes: dict[str, str] = (
        {audit_reader.DOCUMENT_ATTRIBUTE: registrations.canonical(document)} if action == "approve" else {}
    )
    review_by = document.get("reviewBy") if action == "approve" else None
    recorded = True

    def call() -> dict[str, Any]:
        nonlocal recorded
        status = _STATUS[action]
        approver.set_status(engine.registry, engine.settings.registry_id, record_id, status, body.reason)
        if action == "approve":
            # The document's date, or a year from now if the document names a later one or none.
            attested = reviews.approval_date(review_by, dt.datetime.now(dt.UTC).date())
            recorded = _attest_approval(engine, target, attested, body.reason, request_id, attributes)
        try:
            return approver.get_record(engine.registry, engine.settings.registry_id, record_id)
        except ClientError as exc:
            # The registry accepted the decision, so it is reported as taken even though the record
            # could not be read back.
            logger.warning("The decided record could not be read back: %s", error_code(exc))
            return {**record, "status": status, "statusReason": body.reason[: approver.STATUS_REASON_MAX]}

    result = engine.perform(
        target,
        allow_reason,
        call,
        _registration,
        result_reason=body.reason,
        result_attributes=attributes,
        request_id=request_id,
    )
    if not recorded:
        result.audit_complete = False
    return result


def _attest_approval(
    engine: ActionEngine, target: Target, review_by: str, reason: str, request_id: str, attributes: dict[str, str]
) -> bool:
    """Record the approval as an attestation with the review date it sets (``reviews.approval_date``).

    Called after the registry accepted the approval, which cannot be taken
    back, so a failed write does not fail the approval: the result event says
    that the review date was not recorded and the response is marked
    ``audit_complete: false``. Until the next attestation the date shown is
    then the one that held before.
    """
    principal = engine.principal
    at = audit_writer.now_stamp()
    try:
        latest = audit_writer.put_attestation(
            engine.dynamodb,
            engine.settings.audit_table,
            at=at,
            record_id=str(target.record_id),
            next_review_by=review_by,
            reviewed_by=principal.subject,
            reviewed_by_label=principal.label,
            reviewed_by_role=principal.role,
            reason=reviews.approval_reason(reason),
            request_id=request_id,
            record_name=target.record_name,
            tenant_id=target.tenant_id,
            kind=reviews.KIND_APPROVAL,
        )
    except Exception as exc:  # noqa: BLE001 - the approval itself is not in question
        logger.error("The approval's review date could not be recorded: %s", error_code(exc))
        attributes["detail"] = REVIEW_NOT_RECORDED
        return False
    if not latest:
        # As for a review: the stored attestation is this one, sent twice, or one attested later.
        logger.warning(audit_writer.LATER_ATTESTATION_STORED)
    attributes["attested_at"] = at
    attributes["next_review_by"] = review_by
    return True
