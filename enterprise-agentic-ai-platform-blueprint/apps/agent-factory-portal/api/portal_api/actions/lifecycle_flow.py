# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""An agent's life after approval: retire a registration, attest its periodic review.

Both are served by the approver function and decided by the pure rules in
``portal_api/actions/lifecycle_rules.py``.

Retire sets the record's status to DEPRECATED. The registry never undoes that,
and the portal does not remove anything that is deployed: a Runtime stays
until its pipeline removes it.

A review attestation changes no record, because any update of a record returns
it to DRAFT. It is written to the audit trail only: the usual intent and
result events in the record's own partition, and one item in the partition
that holds every attestation, which is what the read API reads.

A review is a second pair of eyes, so the record's submitter cannot attest it,
and it can be attested once in 24 hours: the partition of attestations is one
for every record, and its read is bounded.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from botocore.exceptions import ClientError

from portal_api import registrations, reviews
from portal_api.actions import approver, audit_writer, authority
from portal_api.actions import lifecycle_rules as rules
from portal_api.actions.engine import ActionEngine, ActionError, Target, record_state
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import error_code
from portal_api.mappers.common import parse_instant
from portal_api.models.portal import ActionResult, Registration, RetireInput, ReviewInput

logger = logging.getLogger(__name__)

RETIREMENT_IS_PERMANENT = (
    "Retirement is permanent: the record can no longer be approved, rejected, updated or submitted. "
    "The agent's Runtime, if it has one, is still deployed until its pipeline removes it."
)
RETIRED = f"The registration is retired. {RETIREMENT_IS_PERMANENT}"
ALREADY_RETIRED = f"The registration was already retired; nothing was changed. {RETIREMENT_IS_PERMANENT}"


def _registration(record: dict[str, Any]) -> Registration:
    document = registrations.agent_document(record)
    if document is None:
        raise ActionError(404, "Registration not found")
    return registrations.to_registration(record, document)


def _load(engine: ActionEngine, action: str, record_id: str) -> tuple[dict[str, Any], Target]:
    """The settled record and what the action is about, or the refusal.

    A caller without the approver authority is refused before the record is
    read, so the answer does not reveal whether the record exists. That
    refusal is logged, not written to the record's history: nothing has been
    resolved, and the id is whatever the caller sent.
    """
    principal = engine.principal
    refusal = rules.authority_refusal(action, principal.role, principal.subject)
    if refusal is not None:
        blind = Target(action=action, tenant_id=authority.NO_TENANT, record_name="", record_id=record_id)
        raise engine.refuse_unrecorded(blind, 403, refusal.reason)
    try:
        record = approver.wait_until_settled(engine.registry, engine.settings.registry_id, record_id)
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            raise ActionError(404, "Registration not found") from exc
        raise ActionError(502, f"An AWS service call failed ({error_code(exc)})") from exc
    document = registrations.agent_document(record)
    if document is None:
        # Not an agent governance record: the portal does not touch it.
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
    return record, target


def _decide(engine: ActionEngine, target: Target) -> rules.LifecycleDecision:
    """The rules' decision. A refusal is written to the audit trail and raised."""
    principal = engine.principal
    decision = rules.evaluate(
        action=target.action,
        role=principal.role,
        principal_id=principal.subject,
        record_tenant=target.tenant_id,
        held_tenants=authority.tenants_of(principal, engine.settings),
        holds_all_tenants=authority.holds_all_tenants(principal),
        record_status=target.status_before,
    )
    status = decision.http_status
    if status is not None:
        raise engine.deny(target, status, decision.reason)
    return decision


def retire(engine: ActionEngine, record_id: str, body: RetireInput) -> ActionResult:
    record, target = _load(engine, "retire", record_id)
    decision = _decide(engine, target)
    if decision.outcome == rules.UNCHANGED:
        return engine.unchanged(target, ALREADY_RETIRED, _registration(record))

    def call() -> dict[str, Any]:
        approver.set_status(engine.registry, engine.settings.registry_id, record_id, rules.RETIRED, body.reason)
        try:
            return approver.wait_until_settled(engine.registry, engine.settings.registry_id, record_id)
        except ClientError as exc:
            # The registry accepted the retirement, which cannot be undone, so it is reported as done
            # even though the record could not be read back.
            logger.warning("The retired record could not be read back: %s", error_code(exc))
            return {**record, "status": rules.RETIRED, "statusReason": body.reason[: approver.STATUS_REASON_MAX]}

    # The person's reason is the result event's reason; what retirement means is kept beside it.
    return engine.perform(
        target,
        decision.reason,
        call,
        _registration,
        result_reason=body.reason,
        result_attributes={"detail": RETIREMENT_IS_PERMANENT},
        response_reason=RETIRED,
    )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _spaced_and_separate(engine: ActionEngine, target: Target, record_id: str, now: dt.datetime) -> None:
    """Refuse a review by the record's submitter (REV-05-N) and one within 24 hours of the last (REV-06-N).

    Both are read from the record's own history, for a caller who has
    already passed the authority, the tenant and the status. Each refusal is
    written once for each person while the record stays as it is, and logged
    after that (``ActionEngine.deny``).
    """
    events = engine.history_for_review(record_id, now)
    submitted = audit_reader.submitter(events)
    refusal = rules.submitter_refusal(engine.principal.subject, submitted.actor_subject if submitted else None)
    if refusal is not None:
        raise engine.deny(target, 403, refusal.reason)
    last = audit_reader.last_review_attempt(events)
    refusal = rules.recent_review_refusal(parse_instant((last.attested_at or last.at) if last else None), now)
    if refusal is not None:
        raise engine.deny(target, 409, refusal.reason)


def review(engine: ActionEngine, record_id: str, body: ReviewInput) -> ActionResult:
    record, target = _load(engine, "review", record_id)
    target.next_review_by = body.next_review_by
    decision = _decide(engine, target)
    now = _now()
    problem = reviews.date_error(body.next_review_by, now.date())
    if problem is not None:
        raise ActionError(422, [{"loc": ["body", "next_review_by"], "msg": problem, "type": "review_date"}])
    _spaced_and_separate(engine, target, record_id, now)

    principal = engine.principal
    request_id = audit_writer.new_request_id()
    # Filled in when the attestation is written, so the result event names the attestation's own time.
    attested: dict[str, str] = {}

    def call() -> dict[str, Any]:
        at = audit_writer.now_stamp()
        try:
            latest = audit_writer.put_attestation(
                engine.dynamodb,
                engine.settings.audit_table,
                at=at,
                record_id=record_id,
                next_review_by=body.next_review_by,
                reviewed_by=principal.subject,
                reviewed_by_label=principal.label,
                reviewed_by_role=principal.role,
                reason=body.reason,
                request_id=request_id,
                record_name=target.record_name,
                tenant_id=target.tenant_id,
            )
        except Exception as exc:  # noqa: BLE001 - whatever the cause, nothing was attested
            logger.error("The review attestation could not be written: %s", error_code(exc))
            raise ActionError(503, "The review could not be recorded, so nothing was attested") from exc
        if not latest:
            # The attestation that is stored for this record is as new as this one: this very
            # write, sent again by the SDK after an answer that never arrived, or one that was
            # attested later at nearly the same moment. It stays the latest. This review is
            # attested all the same: its result event, which follows, is where it is on record.
            logger.warning(audit_writer.LATER_ATTESTATION_STORED)
        attested["attested_at"] = at
        return record

    return engine.perform(
        target,
        decision.reason,
        call,
        _registration,
        result_reason=body.reason,
        result_attributes=attested,
        request_id=request_id,
    )
