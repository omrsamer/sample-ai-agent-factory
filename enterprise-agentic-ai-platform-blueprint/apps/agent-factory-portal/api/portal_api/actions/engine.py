# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The decision and audit sequence every action goes through.

For one action on one record:

1. The authorization core decides. A deny is answered with 403. It is written to the audit
   trail only when the caller has a part in the record: the authority the action needs, and
   the record's tenant. Every other deny is logged instead, with its request id: one that
   comes before a record is resolved (the key of its event would be an id or a name the
   caller chose), and one from a caller who does not hold the record's tenant (anyone could
   otherwise fill another tenant's history, which is never shortened).
2. The record's status is checked. A status that does not permit the action is written to the
   audit trail as denied and answered with 409.

   A refusal of either kind is written once for each person, rule and state of the record
   (its status and the document it holds), and so is an answer that nothing was changed.
   Repeated, it is logged. A person who has a part in a record could otherwise lengthen its
   history with every request, and the decisions that read the history back to the record's
   last submit would fail closed (``ActionEngine.deny``).
3. An ``intent`` event is written. If that write fails, nothing is done and the answer is 503.
4. The registry call is made.
5. A ``result`` event is written: ``allowed`` with the new status, or ``failed`` with the error
   code if the registry refused. If this last write fails after a successful call, the action
   stands (the intent event already records it) and the response says ``audit_complete: false``.

Retire and review are decided by ``portal_api/actions/lifecycle_rules.py`` instead of the
authorization core and then follow steps 2 to 5. A review attestation changes no record: its
step 4 is the write of the attestation itself.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from portal_api import registration_core as core
from portal_api.actions import audit_writer, authority, lifecycle_rules
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import error_code
from portal_api.config import ActionSettings
from portal_api.identity.provider import Principal
from portal_api.models.portal import ActionResult, AuditEvent, Registration

logger = logging.getLogger(__name__)

_STATE_ERRORS = ("ConflictException", "ValidationException")
_NOT_FOUND = "ResourceNotFoundException"
HISTORY_NOT_READ_FAR_ENOUGH = (
    f"The record's history holds more than {audit_reader.MAX_DECISION_EVENTS} events since it was last "
    "submitted or in the last 24 hours, so who submitted it and when it was last reviewed could not be "
    "established. Nothing was attested."
)
SUBMITTER_NOT_FOUND = (
    f"The record's history holds more than {audit_reader.MAX_DECISION_EVENTS} events since it was last "
    "submitted, so who submitted it could not be established and no decision was taken. "
    "Update the record and submit it again."
)


# A rule's id as the refusals carry it, for example REG-11-N or REV-06-N.
_RULE_ID = re.compile(r"\b[A-Z]{2,5}-[0-9]{2}-[A-Z]\b", re.ASCII)
FIRST, REPEATED, NOT_KNOWN = "first", "repeated", "not_known"


def rule_of(reason: str) -> str:
    """What a refusal is filed under when it is recorded once: its rule.

    The rule's id when the reason carries one, so that two refusals by the
    same rule count as one whatever else their sentences say (a time, a
    status). A reason with no id is the portal's own fixed sentence, and a
    hash of it stands for the rule.
    """
    found = _RULE_ID.search(reason)
    return found.group(0) if found else hashlib.sha256(reason.encode()).hexdigest()[:20]


def record_state(status: Any, document_sha256: str | None) -> str:
    """The state of a record that "once" is counted in: its status and the document it holds.

    Both are read from the registry, never from the request: an update is
    refused for the document the record holds, not for the one the caller
    proposes, or every new proposal would be a new state.
    """
    return f"{status}:{document_sha256 or ''}"


class ActionError(Exception):
    """An action was refused or failed; carries the HTTP status and a safe message."""

    def __init__(self, status: int, detail: str | list[dict[str, Any]], **extra: Any) -> None:
        super().__init__(str(detail))
        self.status = status
        self.detail = detail
        self.extra = extra


@dataclass
class Target:
    """What an action is about."""

    action: str
    tenant_id: str
    record_name: str
    record_id: str | None = None
    status_before: str | None = None
    document_sha256: str | None = None
    next_review_by: str | None = None  # a review attestation only
    # The record as the registry holds it when the action is decided (``record_state``). Empty
    # for a create, which has no record yet. A refusal is recorded once per person in one state.
    state: str = ""

    @property
    def partition(self) -> str:
        if self.record_id:
            return audit_reader.record_key(self.record_id)
        return audit_reader.name_key(self.record_name)


class ActionEngine:
    def __init__(self, settings: ActionSettings, registry: Any, dynamodb: Any, principal: Principal) -> None:
        self.settings = settings
        self.registry = registry
        self.dynamodb = dynamodb
        self.principal = principal

    # --- audit ---------------------------------------------------------------

    def _event(
        self, target: Target, request_id: str, phase: str, outcome: str, reason: str, status_after: str | None = None
    ) -> AuditEvent:
        return AuditEvent(
            event_id=str(uuid.uuid4()),
            request_id=request_id,
            at=audit_writer.now_stamp(),
            phase=phase,
            action=target.action,
            outcome=outcome,
            reason=reason[:1000],
            actor_subject=self.principal.subject,
            actor_label=self.principal.label,
            actor_role=self.principal.role,
            tenant_id=target.tenant_id,
            record_id=target.record_id,
            record_name=target.record_name,
            document_sha256=target.document_sha256,
            status_before=target.status_before,
            status_after=status_after,
            next_review_by=target.next_review_by,
        )

    def _write(self, target: Target, event: AuditEvent, attributes: dict[str, str] | None = None) -> bool:
        try:
            audit_writer.put_event(self.dynamodb, self.settings.audit_table, target.partition, event, attributes)
            return True
        except Exception as exc:  # noqa: BLE001 - the caller decides what a failed write means
            logger.error("Audit write failed (%s %s %s): %s", event.action, event.phase, event.outcome, error_code(exc))
            return False

    def _once(self, target: Target, rule: str, request_id: str) -> str:
        """Whether this is the first time this person meets this rule on the record as it stands.

        ``FIRST``: it is, and it is now marked, so the event that follows is
        the one on record. ``REPEATED``: it was marked before. ``NOT_KNOWN``:
        the mark could not be written. Nothing is written into the history
        then either: without the mark a repeated request would add an event
        each time.
        """
        try:
            first = audit_writer.mark_once(
                self.dynamodb,
                self.settings.audit_table,
                target.partition,
                target.state,
                self.principal.subject,
                target.action,
                rule,
                request_id,
            )
        except Exception as exc:  # noqa: BLE001 - logged; the caller's answer does not depend on it
            logger.error("Audit mark failed (%s %s): %s", target.action, rule, error_code(exc))
            return NOT_KNOWN
        return FIRST if first else REPEATED

    def deny(self, target: Target, status: int, reason: str) -> ActionError:
        """Record a denied decision and return the error to raise.

        This is the only place a refusal is written, and it writes only for
        a caller who has a part in the record (``authority.has_part``). A
        refusal of anyone else is logged (``refuse_unrecorded``), whatever
        the flow that asked for it to be recorded.

        Such a caller's refusal is written once for each person, rule and
        state of the record, and logged after that (``_once``). Otherwise an
        approver of the record's own tenant could repeat a refused approval
        two thousand times in little more than a minute, and approve, reject
        and review, which read the history back to the record's last
        submit, would fail closed until it is submitted again.
        """
        if not authority.has_part(self.principal, self.settings, target.action, target.tenant_id):
            return self.refuse_unrecorded(target, status, reason)
        request_id = audit_writer.new_request_id()
        if self._once(target, rule_of(reason), request_id) != FIRST:
            return self.refuse_unrecorded(target, status, reason, request_id=request_id)
        self._write(target, self._event(target, request_id, "result", "denied", reason))
        return ActionError(status, reason, action=target.action, request_id=request_id)

    def refuse_unrecorded(
        self, target: Target, status: int, reason: str, *, request_id: str | None = None
    ) -> ActionError:
        """A refusal that is logged, not written to the audit trail, and the error to raise.

        For a refusal that comes before any record is resolved, for one of
        a caller who has no part in the record, and for one that is on
        record already. The first would be keyed by an id or a name the
        caller chose; the second would let any signed-in user fill the
        history of another tenant's record; the third would add an event
        with every repeat. The function's log keeps the attempt, and the
        answer carries the same ``request_id``.
        """
        request_id = request_id or audit_writer.new_request_id()
        logger.warning(
            "Refusal logged, not written to the audit trail: action=%s role=%s subject=%s record=%s "
            "request_id=%s reason=%s",
            target.action,
            self.principal.role,
            self.principal.subject,
            target.record_id or "-",
            request_id,
            reason,
        )
        return ActionError(status, reason, action=target.action, request_id=request_id)

    def unchanged(self, target: Target, reason: str, registration: Registration | None) -> ActionResult:
        """Record that an allowed action found nothing to change, and answer without a registry call.

        Recorded once for each person and state of the record, like a
        refusal (``_once``): the answer is the same every time, and a
        retirement asked for again and again would otherwise add an event
        each time. Repeated, it is logged, and the trail is complete as it
        stands.
        """
        request_id = audit_writer.new_request_id()
        seen = self._once(target, "unchanged", request_id)
        if seen == FIRST:
            complete = self._write(
                target, self._event(target, request_id, "result", "unchanged", reason, target.status_before)
            )
        else:
            logger.warning(
                "Unchanged answer logged, not written to the audit trail again: action=%s subject=%s record=%s "
                "request_id=%s",
                target.action,
                self.principal.subject,
                target.record_id or "-",
                request_id,
            )
            complete = seen == REPEATED
        return ActionResult(
            action=target.action,
            outcome="unchanged",
            reason=reason,
            request_id=request_id,
            registration=registration,
            audit_complete=complete,
        )

    def submitter(self, record_id: str) -> AuditEvent | None:
        """The event that names the record's current submitter, or ``None`` when the portal has none.

        Fails closed twice over. No trail, no decision. And the record's
        history is read back only as far as ``audit.MAX_DECISION_EVENTS``: if
        its latest submit is not among them, who submitted it is not known,
        and that must not read as "nobody did".
        """
        try:
            found, settled = audit_reader.read_submitter(self.dynamodb, self.settings.audit_table, record_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Audit trail could not be read: %s", error_code(exc))
            raise ActionError(503, "The audit trail could not be read, so no decision was taken") from exc
        if not settled:
            logger.error("The submitter of %s is not among the newest events of its history", record_id)
            raise ActionError(409, SUBMITTER_NOT_FOUND)
        return found

    def history_for_review(self, record_id: str, now: dt.datetime) -> list[AuditEvent]:
        """The record's events a review is decided on, newest first: back to its latest submit and 24 hours.

        Fails closed like ``submitter``: no trail, no decision, and a history
        that could not be read that far back within the bound is not taken
        for one with no submit and no review in it.
        """
        since = now - dt.timedelta(hours=lifecycle_rules.REVIEW_INTERVAL_HOURS)
        try:
            trail, settled = audit_reader.read_for_review(self.dynamodb, self.settings.audit_table, record_id, since)
        except Exception as exc:  # noqa: BLE001
            logger.error("Audit trail could not be read: %s", error_code(exc))
            raise ActionError(503, "The audit trail could not be read, so no decision was taken") from exc
        if not settled:
            logger.error("The history of %s could not be read far enough back to decide a review", record_id)
            raise ActionError(409, HISTORY_NOT_READ_FAR_ENOUGH)
        return trail.events

    # --- the sequence -------------------------------------------------------------

    def authorize(
        self,
        target: Target,
        request: dict[str, Any],
        current_state: dict[str, Any] | None,
        *,
        resolved: bool = True,
    ) -> str:
        """Step 1. Returns the core's allow reason or raises the 403.

        ``resolved`` is false when the decision is taken before the record it
        concerns has been read (or, for a create, before one exists): a deny
        is then logged, not written to the audit trail (``refuse_unrecorded``).
        A deny about a resolved record is written only for a caller who has
        a part in it (``deny``).
        """
        core_request = {
            **request,
            "action": authority.CORE_ACTION.get(target.action, target.action),
            "principal": authority.core_principal(self.principal, self.settings, target.action, target.tenant_id),
            "tenantId": request.get("tenantId", target.tenant_id),
        }
        decision = core.evaluate_registration_request(core_request, current_state)
        if not decision.allowed:
            refuse = self.deny if resolved else self.refuse_unrecorded
            error = refuse(target, 403, decision.reason)
            if "REG-12-N" in decision.reason:
                # The core names its own reference slots; say what that means for an agent record.
                error.extra["hint"] = (
                    "On an approved agent record the runtime ARN, gateway ARN, subscribed tools, risk class and "
                    "data classification cannot be changed. Register a new record instead."
                )
            raise error
        return decision.reason

    def perform(
        self,
        target: Target,
        allow_reason: str,
        call: Callable[[], dict[str, Any] | None],
        to_registration: Callable[[dict[str, Any]], Registration],
        result_reason: str | None = None,
        result_attributes: dict[str, str] | None = None,
        *,
        response_reason: str | None = None,
        request_id: str | None = None,
    ) -> ActionResult:
        """Steps 3 to 5. ``call`` makes the registry call and returns the record afterwards (or None).

        ``result_reason`` is recorded with the result event (the person's own reason, when the
        action takes one). ``response_reason`` is what the response says instead, when that
        differs. ``request_id`` lets the caller name the id that ``call`` also uses.
        """
        request_id = request_id or audit_writer.new_request_id()
        if not self._write(target, self._event(target, request_id, "intent", "allowed", allow_reason)):
            raise ActionError(503, "The audit trail could not be written, so the action was not performed")
        try:
            record = call()
        except ActionError as exc:
            # The call says itself what went wrong; record that and pass it on with the request id.
            self._write(target, self._event(target, request_id, "result", "failed", str(exc.detail)))
            exc.extra.setdefault("action", target.action)
            exc.extra.setdefault("request_id", request_id)
            raise
        except ClientError as exc:
            code = error_code(exc)
            self._write(target, self._event(target, request_id, "result", "failed", f"The registry refused ({code})"))
            if code in _STATE_ERRORS:
                raise ActionError(409, "The registry refused the action for the record's current state") from exc
            if code == _NOT_FOUND:
                raise ActionError(404, "Registration not found") from exc
            raise ActionError(502, f"An AWS service call failed ({code})") from exc
        except Exception as exc:
            self._write(
                target, self._event(target, request_id, "result", "failed", f"The action failed ({error_code(exc)})")
            )
            raise
        if record is not None:
            target.record_id = target.record_id or str(record["recordId"])
        status_after = str(record.get("status")) if record is not None else "DELETED"
        reason = result_reason or allow_reason
        complete = self._write(
            target, self._event(target, request_id, "result", "allowed", reason, status_after), result_attributes
        )
        return ActionResult(
            action=target.action,
            reason=response_reason or reason,
            request_id=request_id,
            registration=to_registration(record) if record is not None else None,
            audit_complete=complete,
        )
