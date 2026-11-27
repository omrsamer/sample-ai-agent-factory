# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The decision and audit sequence every action goes through.

For one action on one record:

1. The authorization core decides. A deny is written to the audit trail and answered with 403.
2. The record's status is checked. A status that does not permit the action is written to the
   audit trail as denied and answered with 409.
3. An ``intent`` event is written. If that write fails, nothing is done and the answer is 503.
4. The registry call is made.
5. A ``result`` event is written: ``allowed`` with the new status, or ``failed`` with the error
   code if the registry refused. If this last write fails after a successful call, the action
   stands (the intent event already records it) and the response says ``audit_complete: false``.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from portal_api import registration_core as core
from portal_api.actions import audit_writer, authority
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import error_code
from portal_api.config import ActionSettings
from portal_api.identity.provider import Principal
from portal_api.models.portal import ActionResult, AuditEvent, Registration

logger = logging.getLogger(__name__)

_STATE_ERRORS = ("ConflictException", "ValidationException")
_NOT_FOUND = "ResourceNotFoundException"


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
        )

    def _write(self, target: Target, event: AuditEvent, attributes: dict[str, str] | None = None) -> bool:
        try:
            audit_writer.put_event(self.dynamodb, self.settings.audit_table, target.partition, event, attributes)
            return True
        except Exception as exc:  # noqa: BLE001 - the caller decides what a failed write means
            logger.error("Audit write failed (%s %s %s): %s", event.action, event.phase, event.outcome, error_code(exc))
            return False

    def deny(self, target: Target, status: int, reason: str) -> ActionError:
        """Record a denied decision and return the error to raise."""
        request_id = audit_writer.new_request_id()
        self._write(target, self._event(target, request_id, "result", "denied", reason))
        return ActionError(status, reason, action=target.action, request_id=request_id)

    def events(self, record_id: str) -> list[AuditEvent]:
        """The record's events, newest first. Fails closed: no trail, no decision."""
        try:
            return audit_reader.query_events(
                self.dynamodb, self.settings.audit_table, audit_reader.record_key(record_id)
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Audit trail could not be read: %s", error_code(exc))
            raise ActionError(503, "The audit trail could not be read, so no decision was taken") from exc

    # --- the sequence -------------------------------------------------------------

    def authorize(self, target: Target, request: dict[str, Any], current_state: dict[str, Any] | None) -> str:
        """Step 1. Returns the core's allow reason or raises the 403."""
        core_request = {
            **request,
            "action": authority.CORE_ACTION.get(target.action, target.action),
            "principal": authority.core_principal(self.principal, self.settings, target.action, target.tenant_id),
            "tenantId": request.get("tenantId", target.tenant_id),
        }
        decision = core.evaluate_registration_request(core_request, current_state)
        if not decision.allowed:
            error = self.deny(target, 403, decision.reason)
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
    ) -> ActionResult:
        """Steps 3 to 5. ``call`` makes the registry call and returns the record afterwards (or None)."""
        request_id = audit_writer.new_request_id()
        if not self._write(target, self._event(target, request_id, "intent", "allowed", allow_reason)):
            raise ActionError(503, "The audit trail could not be written, so the action was not performed")
        try:
            record = call()
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
            reason=reason,
            request_id=request_id,
            registration=to_registration(record) if record is not None else None,
            audit_complete=complete,
        )
