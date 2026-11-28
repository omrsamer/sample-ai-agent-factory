# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Contain and release an agent's Runtime.

Contain, in the agent's cell and with the cell's containment role:
  1. read the Runtime's resource policy;
  2. add the one containment statement, keeping every other statement as it is, and write the policy;
  3. read the policy back to verify;
  4. find the Runtime's recent sessions in its spans and stop them, bounded in number and time.
Release removes exactly that statement (the policy is deleted only when nothing
else remains) and verifies. Both are idempotent and never touch a statement the
portal did not write.

The function never invokes the Runtime to test the block: its role must not be
able to. A change to the policy is not enforced instantly: the service applies
it host by host. Every response says how long to allow
(``portal_api/containment_timing.py``, measured on a live Runtime).

Audit follows the same discipline as registrations: an intent event before
anything is changed, and a result event that says what was and was not done.
The policy is read, changed and written without a lock; two simultaneous
changes to the same policy from different tools could overwrite each other.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from portal_api import authorities, containment_policy, registrations
from portal_api.actions import audit_writer, containment
from portal_api.actions import containment_rules as rules
from portal_api.actions.engine import ActionError
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import AwsClients, error_code
from portal_api.config import ActionSettings, Cell
from portal_api.containment_timing import CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS, delay_words
from portal_api.identity.provider import Principal
from portal_api.mappers.common import arn_parts
from portal_api.models.portal import (
    AuditEvent,
    ContainmentInput,
    ContainmentResult,
    ContainmentStep,
    SessionsStopped,
)

logger = logging.getLogger(__name__)

CONTAINED, NOT_CONTAINED = "contained", "not_contained"
NOT_ENABLED = "containment is not enabled for this cell"
_RUNTIME_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,99}-[A-Za-z0-9]{1,20}$")
_RUNTIME_ARN = re.compile(
    r"^arn:aws[a-z-]{0,10}:bedrock-agentcore:[a-z0-9-]{1,30}:\d{12}:runtime/[A-Za-z][A-Za-z0-9_]{0,99}-[A-Za-z0-9]{1,20}$"
)
_LABELS = {
    "policy": "Deny invocation in the Runtime's resource policy",
    "verify": "Read the policy back to confirm the deny statement",
    "sessions": "Stop the Runtime's running sessions",
    "release": "Remove the deny statement from the Runtime's resource policy",
    "verify_release": "Read the policy back to confirm the statement is gone",
}


@dataclass
class Target:
    agent_id: str
    runtime_arn: str
    tenant_id: str | None
    cell: Cell


class _Failed(Exception):
    """The action stopped part-way. ``done`` says what was and was not done."""

    def __init__(
        self,
        status: int,
        done: str,
        steps: list[ContainmentStep],
        before: str | None = None,
        after: str | None = None,
    ) -> None:
        super().__init__(done)
        self.status = status
        self.done = done
        self.steps = steps
        self.before = before
        self.after = after if after is not None else before


class ContainmentService:
    def __init__(
        self, settings: ActionSettings, clients: AwsClients, registry: Any, dynamodb: Any, principal: Principal
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.registry = registry
        self.dynamodb = dynamodb
        self.principal = principal

    # --- resolving the agent -------------------------------------------------

    def _cells_for(self, runtime_arn: str) -> list[Cell]:
        parts = arn_parts(runtime_arn) or {}
        scope = (parts.get("account"), parts.get("region"))
        return [c for c in self.settings.cells if (c.account_id, c.region) == scope]

    def resolve(self, agent_id: str, body: ContainmentInput) -> tuple[str, str | None, list[Cell]]:
        """The agent's Runtime ARN, its tenant and the cells of its account and Region.

        A registered agent (its id is a registry record id) is resolved from
        its record; an agent with no registration is addressed by its Runtime
        id. Either way the tenant is decided by where the Runtime runs
        (``containment_rules.tenant_for``), never by what the record claims:
        a record is written by the people it governs, and a draft naming
        another tenant's Runtime must not put that Runtime in their reach.
        """
        if registrations.RECORD_ID.fullmatch(agent_id):
            try:
                record = containment.get_record(self.registry, self.settings.registry_id, agent_id)
            except ClientError as exc:
                if error_code(exc) == "ResourceNotFoundException":
                    raise ActionError(404, "Agent not found") from exc
                raise ActionError(502, f"An AWS service call failed ({error_code(exc)})") from exc
            document = registrations.agent_document(record)
            if document is None:
                raise ActionError(404, "Agent not found")
            runtime_arn = document.get("runtimeArn")
            if not runtime_arn:
                raise ActionError(409, "This registration names no Runtime, so there is nothing to contain")
            if body.runtime_arn and body.runtime_arn != runtime_arn:
                raise ActionError(422, [_field_error("runtime_arn", "runtime_arn is not this agent's Runtime")])
            if not _RUNTIME_ARN.fullmatch(runtime_arn):
                raise ActionError(409, "This registration does not name a Runtime, so there is nothing to contain")
            cells = self._cells_for(runtime_arn)
            tenant = rules.tenant_for(
                {c.tenant_id for c in cells},
                record_tenant=document.get("tenantId"),
                record_approved=record.get("status") == "APPROVED",
            )
            return runtime_arn, tenant, cells

        if not _RUNTIME_ID.fullmatch(agent_id):
            raise ActionError(404, "Agent not found")
        if body.runtime_arn:
            if not body.runtime_arn.endswith(f":runtime/{agent_id}"):
                raise ActionError(422, [_field_error("runtime_arn", "runtime_arn is not this agent's Runtime")])
            runtime_arn = body.runtime_arn
        else:
            scopes = sorted({(c.account_id, c.region) for c in self.settings.cells if c.containment_role_arn})
            if not scopes:
                raise ActionError(409, NOT_ENABLED)
            if len(scopes) > 1:
                message = "runtime_arn is required to act on an agent that has no registration"
                raise ActionError(422, [_field_error("runtime_arn", message)])
            account, region = scopes[0]
            runtime_arn = f"arn:aws:bedrock-agentcore:{region}:{account}:runtime/{agent_id}"
        cells = self._cells_for(runtime_arn)
        return runtime_arn, rules.tenant_for({c.tenant_id for c in cells}), cells

    # --- audit ---------------------------------------------------------------------

    def _events(self, runtime_arn: str) -> list[AuditEvent]:
        try:
            return audit_reader.query_events(
                self.dynamodb, self.settings.audit_table, audit_reader.containment_key(runtime_arn)
            )
        except Exception as exc:  # noqa: BLE001 - no trail, no decision
            logger.error("Audit trail could not be read: %s", error_code(exc))
            raise ActionError(503, "The audit trail could not be read, so no decision was taken") from exc

    def _write(self, runtime_arn: str, event: AuditEvent) -> bool:
        """Append to the Runtime's containment history. The key is the resolved Runtime, never a caller's id."""
        try:
            audit_writer.put_event(
                self.dynamodb, self.settings.audit_table, audit_reader.containment_key(runtime_arn), event
            )
            return True
        except Exception as exc:  # noqa: BLE001 - the caller decides what a failed write means
            logger.error("Audit write failed (%s %s %s): %s", event.action, event.phase, event.outcome, error_code(exc))
            return False

    def _event(
        self,
        action: str,
        agent_id: str,
        runtime_arn: str | None,
        tenant: str | None,
        request_id: str,
        phase: str,
        outcome: str,
        reason: str,
        **extra: Any,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=str(uuid.uuid4()),
            request_id=request_id,
            at=audit_writer.now_stamp(),
            phase=phase,
            action=action,
            outcome=outcome,
            reason=reason[:1000],
            actor_subject=self.principal.subject,
            actor_label=self.principal.label,
            actor_role=self.principal.role,
            tenant_id=tenant,
            agent_id=agent_id,
            runtime_arn=runtime_arn,
            **extra,
        )

    def _deny(
        self, status: int, action: str, agent_id: str, runtime_arn: str, tenant: str | None, reason: str
    ) -> ActionError:
        """A refusal about a Runtime that was resolved: recorded in that Runtime's history."""
        request_id = audit_writer.new_request_id()
        denied = self._event(action, agent_id, runtime_arn, tenant, request_id, "result", "denied", reason)
        self._write(runtime_arn, denied)
        return ActionError(status, reason, action=action, request_id=request_id)

    # --- the action -------------------------------------------------------------------

    def run(self, action: str, agent_id: str, body: ContainmentInput) -> ContainmentResult:
        role = self.principal.role
        allowed_roles = rules.CONTAIN_ROLES if action == "contain" else rules.RELEASE_ROLES
        if role not in allowed_roles:
            # Refused before anything is looked up, so the answer does not reveal whether the agent exists.
            decision = rules.evaluate(
                action=action,
                role=role,
                principal_id=self.principal.subject,
                agent_tenant=None,
                held_tenants=(),
                holds_all_tenants=False,
                contained_by=None,
            )
            # Not written to the audit table: nothing has been resolved, so the key would be the
            # caller's own choice, and any signed-in user could fill any agent's history. The
            # function's log keeps the attempt.
            request_id = audit_writer.new_request_id()
            logger.warning(
                "Containment refused before resolution: action=%s role=%s subject=%s request_id=%s",
                action,
                role,
                self.principal.subject,
                request_id,
            )
            raise ActionError(403, decision.reason, action=action, request_id=request_id)

        runtime_arn, tenant, cells = self.resolve(agent_id, body)
        contained_by = audit_reader.container(self._events(runtime_arn))
        decision = rules.evaluate(
            action=action,
            role=role,
            principal_id=self.principal.subject,
            agent_tenant=tenant,
            held_tenants=authorities.tenants_of(self.principal.groups, self.settings.group_tenant_map),
            holds_all_tenants=authorities.holds_all_tenants(role),
            contained_by=contained_by.actor_subject if contained_by else None,
        )
        if not decision.allowed:
            raise self._deny(403, action, agent_id, runtime_arn, tenant, decision.reason)

        cell = next((c for c in cells if c.containment_role_arn), None)
        if cell is None:
            raise self._deny(409, action, agent_id, runtime_arn, tenant, NOT_ENABLED)
        target = Target(agent_id, runtime_arn, tenant, cell)

        request_id = audit_writer.new_request_id()
        intent = self._event(action, agent_id, runtime_arn, tenant, request_id, "intent", "allowed", decision.reason)
        if not self._write(runtime_arn, intent):
            raise ActionError(503, "The audit trail could not be written, so the action was not performed")

        try:
            if action == "contain":
                result = self._contain(target, body.reason, request_id)
            else:
                result = self._release(target, body.reason, request_id)
        except _Failed as failure:
            failed = self._event(
                action,
                agent_id,
                runtime_arn,
                tenant,
                request_id,
                "result",
                "failed",
                failure.done,
                status_before=failure.before,
                status_after=failure.after,
            )
            self._write(runtime_arn, failed)
            raise ActionError(
                failure.status,
                failure.done,
                action=action,
                request_id=request_id,
                steps=[step.model_dump() for step in failure.steps],
            ) from failure

        sessions = result.sessions
        event = self._event(
            action,
            agent_id,
            runtime_arn,
            tenant,
            request_id,
            "result",
            result.outcome,
            result.reason,
            status_before=result.state if not result.changed else _other(result.state),
            status_after=result.state,
            sessions_found=sessions.found if sessions else None,
            sessions_stopped=sessions.stopped if sessions else None,
            sessions_failed=(sessions.failed + sessions.not_attempted) if sessions else None,
            detail=sessions.discovery if sessions else None,
        )
        result.audit_complete = self._write(runtime_arn, event)
        return result

    def _client(self, cell: Cell, service: str) -> Any:
        """A client in the cell, through the cell's containment role and external id."""
        return self.clients.assumed(cell.containment_role_arn or "", cell.external_id, cell.region, service)

    def _open(self, target: Target, step: ContainmentStep, steps: list[ContainmentStep]) -> tuple[Any, str | None]:
        """Assume the containment role and read the Runtime's policy. Nothing has been changed if this fails."""
        try:
            control = self._client(target.cell, "bedrock-agentcore-control")
        except Exception as exc:  # noqa: BLE001
            step.detail = f"The cell's containment role could not be assumed ({error_code(exc)})."
            raise _Failed(502, f"{step.detail} Nothing was changed.", steps) from exc
        try:
            return control, containment.get_policy(control, target.runtime_arn)
        except ClientError as exc:
            step.detail = f"The Runtime's resource policy could not be read ({error_code(exc)})."
            raise _Failed(502, f"Nothing was changed. {step.detail}", steps) from exc

    def _contain(self, target: Target, reason: str, request_id: str) -> ContainmentResult:
        policy_step = ContainmentStep(id="policy", label=_LABELS["policy"], status="failed")
        verify_step = ContainmentStep(id="verify", label=_LABELS["verify"], status="skipped")
        sessions_step = ContainmentStep(id="sessions", label=_LABELS["sessions"], status="skipped")
        steps = [policy_step, verify_step, sessions_step]

        control, policy = self._open(target, policy_step, steps)
        try:
            already = containment_policy.is_contained(policy)
            kept = len(containment_policy.statements(containment_policy.parse(policy))) - (1 if already else 0)
            denied = containment_policy.denied_actions(policy)
        except containment_policy.PolicyError as exc:
            policy_step.detail = f"{exc}."
            raise _Failed(409, f"Nothing was changed: {exc}.", steps) from exc
        before = CONTAINED if already else NOT_CONTAINED

        if already:
            policy_step.status, policy_step.detail = "unchanged", "The Runtime was already contained."
            verify_step.status = "done"
        else:
            denied = self._put_statement(control, target, policy, policy_step, steps, before)
            verify_step.status = "failed"
            try:
                verified = containment.get_policy(control, target.runtime_arn)
            except ClientError as exc:
                verify_step.detail = f"The policy could not be read back ({error_code(exc)})."
                done = f"The deny statement was written but could not be verified. {verify_step.detail}"
                raise _Failed(502, f"{done} Sessions were not stopped.", steps, before, "unknown") from exc
            if not containment_policy.is_contained(verified):
                verify_step.detail = "The statement was not found when the policy was read back."
                done = "The deny statement was written but was not found when the policy was read back."
                raise _Failed(502, f"{done} Sessions were not stopped.", steps, before, "unknown")
            verify_step.status = "done"

        sessions = self._stop_sessions(target)
        sessions_step.status, sessions_step.detail = _sessions_status(sessions), _sessions_sentence(sessions)
        if already:
            done = "The Runtime was already contained; its policy was not changed."
        else:
            done = (
                "Invocation of the Runtime is denied (statement written and verified; "
                f"enforced everywhere within {delay_words(CONTAIN_DELAY_SECONDS)})."
            )
            if tuple(denied) != containment_policy.ALL_INVOKE_ACTIONS:
                done += " The service accepted only the core invoke actions in the statement."
        summary = f"{done} {sessions_step.detail}"
        return ContainmentResult(
            action="contain",
            outcome="unchanged" if already else "allowed",
            reason=summary if already else f"{reason} [{summary}]",
            request_id=request_id,
            agent_id=target.agent_id,
            runtime_arn=target.runtime_arn,
            state=CONTAINED,
            changed=not already,
            other_statements_kept=kept,
            sessions=sessions,
            steps=steps,
            partial=sessions_step.status != "done",
            denied_actions=denied,
            enforcement_delay_seconds=CONTAIN_DELAY_SECONDS,
        )

    def _put_statement(
        self,
        control: Any,
        target: Target,
        policy: str | None,
        step: ContainmentStep,
        steps: list[ContainmentStep],
        before: str,
    ) -> list[str]:
        """Write the deny statement and return the actions it denies.

        The statement first names every invoke action the service documents for
        a Runtime policy. If the service rejects that list, the statement with
        the two core invoke actions is written instead, and the response says so.
        """
        attempts = (containment_policy.ALL_INVOKE_ACTIONS, containment_policy.CORE_INVOKE_ACTIONS)
        for index, actions in enumerate(attempts):
            updated = containment_policy.with_containment(policy, target.runtime_arn, actions)
            try:
                containment.put_policy(control, target.runtime_arn, updated)
            except ClientError as exc:
                code = error_code(exc)
                if code == "ValidationException" and index + 1 < len(attempts):
                    logger.warning("The full invoke action list was rejected; writing the core actions instead")
                    continue
                step.detail = f"The deny statement could not be written ({code})."
                raise _Failed(502, f"{step.detail} Nothing was changed.", steps, before, before) from exc
            step.status = "done"
            if index == 0:
                step.detail = "Every documented invoke action is denied."
            else:
                step.detail = (
                    "The service rejected the full list of invoke actions, so the two core invoke actions are denied."
                )
            return list(actions)
        raise _Failed(502, "The deny statement could not be written. Nothing was changed.", steps, before, before)

    def _stop_sessions(self, target: Target) -> SessionsStopped:
        """Stop the Runtime's recent sessions. Best effort: the deny statement is already in place."""
        use_spans = target.cell.containment_spans
        nothing = {"spans": 0, "log_streams": 0} if use_spans else {"log_streams": 0}
        try:
            control = self._client(target.cell, "bedrock-agentcore-control")
            found = containment.discover_sessions(
                control, self._client(target.cell, "logs"), target.runtime_arn, use_spans=use_spans
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Runtime sessions could not be listed: %s", error_code(exc))
            return SessionsStopped(discovery=f"sessions could not be listed ({error_code(exc)})", sources=nothing)
        if found.failed or not found.sessions:
            return SessionsStopped(discovery=found.note, sources=found.sources)
        try:
            data = self._client(target.cell, "bedrock-agentcore")
        except Exception as exc:  # noqa: BLE001
            return SessionsStopped(
                discovery=f"sessions could not be stopped ({error_code(exc)})",
                found=len(found.sessions),
                failed=len(found.sessions),
                sources=found.sources,
            )
        stopped = containment.stop_sessions(data, target.runtime_arn, found.sessions)
        return SessionsStopped(
            discovery=found.note,
            found=stopped.found,
            stopped=stopped.stopped,
            not_active=stopped.not_active,
            failed=stopped.failed,
            not_attempted=stopped.not_attempted,
            stop_errors=stopped.failures,
            sources=found.sources,
        )

    def _release(self, target: Target, reason: str, request_id: str) -> ContainmentResult:
        policy_step = ContainmentStep(id="policy", label=_LABELS["release"], status="failed")
        verify_step = ContainmentStep(id="verify", label=_LABELS["verify_release"], status="skipped")
        steps = [policy_step, verify_step]

        control, policy = self._open(target, policy_step, steps)
        try:
            contained = containment_policy.is_contained(policy)
            remaining = containment_policy.without_containment(policy)
        except containment_policy.PolicyError as exc:
            policy_step.detail = f"{exc}."
            raise _Failed(409, f"Nothing was changed: {exc}.", steps) from exc
        kept = len(containment_policy.statements(containment_policy.parse(remaining)))
        common = {
            "action": "release",
            "request_id": request_id,
            "agent_id": target.agent_id,
            "runtime_arn": target.runtime_arn,
            "state": NOT_CONTAINED,
            "other_statements_kept": kept,
            "steps": steps,
            "enforcement_delay_seconds": RELEASE_DELAY_SECONDS,
        }
        if not contained:
            policy_step.status, policy_step.detail = "unchanged", "The Runtime was not contained."
            verify_step.status = "done"
            return ContainmentResult(
                outcome="unchanged",
                reason="The Runtime was not contained; its policy was not changed.",
                changed=False,
                **common,
            )
        try:
            if remaining is None:
                containment.delete_policy(control, target.runtime_arn)
            else:
                containment.put_policy(control, target.runtime_arn, remaining)
        except ClientError as exc:
            policy_step.detail = f"The deny statement could not be removed ({error_code(exc)})."
            done = f"{policy_step.detail} The Runtime is still contained."
            raise _Failed(502, done, steps, CONTAINED, CONTAINED) from exc
        done = (
            "the policy held nothing else and was deleted" if remaining is None else f"{kept} other statement(s) kept"
        )
        policy_step.status, policy_step.detail = "done", f"The deny statement was removed; {done}."
        verify_step.status = "failed"
        try:
            verified = containment.get_policy(control, target.runtime_arn)
        except ClientError as exc:
            verify_step.detail = f"The policy could not be read back ({error_code(exc)})."
            failure = f"The deny statement was removed but this could not be verified. {verify_step.detail}"
            raise _Failed(502, failure, steps, CONTAINED, "unknown") from exc
        if containment_policy.is_contained(verified):
            verify_step.detail = "The statement was still present when the policy was read back."
            failure = (
                "The deny statement was still present when the policy was read back. The Runtime is still contained."
            )
            raise _Failed(502, failure, steps, CONTAINED, CONTAINED)
        verify_step.status = "done"
        after = (
            "Invocation is allowed again; some calls can still be refused for "
            f"{delay_words(RELEASE_DELAY_SECONDS)} while the change spreads."
        )
        return ContainmentResult(
            outcome="allowed",
            reason=f"{reason} [The deny statement was removed and verified; {done}. {after}]",
            changed=True,
            policy_deleted=remaining is None,
            **common,
        )


def _other(state: str) -> str:
    return NOT_CONTAINED if state == CONTAINED else CONTAINED


def _field_error(field_name: str, message: str) -> dict[str, Any]:
    return {"loc": ["body", field_name], "msg": message, "type": "containment"}


def _sessions_status(sessions: SessionsStopped) -> str:
    if not sessions.discovery.startswith("ok"):
        return "failed"
    # Anything short of a clean discovery and a clean stop is partial: a source could not be read,
    # a session could not be stopped, or the time limit ran out.
    return "partial" if sessions.failed or sessions.not_attempted or sessions.discovery != "ok" else "done"


def _sessions_sentence(sessions: SessionsStopped) -> str:
    if not sessions.discovery.startswith("ok"):
        return f"Running sessions were not stopped: {sessions.discovery}."
    if sessions.found == 0:
        sentence = "No recent session was found to stop."
    else:
        sentence = (
            f"{sessions.stopped} of {sessions.found} recent session(s) stopped, {sessions.not_active} had already ended"
        )
        if sessions.failed:
            sentence += f", {sessions.failed} could not be stopped ({', '.join(sessions.stop_errors)})"
        if sessions.not_attempted:
            sentence += f", {sessions.not_attempted} were not attempted before the time limit"
        streams = sessions.sources.get("log_streams", 0)
        if "spans" in sessions.sources:
            sentence += f" (found {sessions.sources['spans']} in traces, {streams} in logs)."
        else:
            sentence += f" (found {streams} in logs)."
    if sessions.discovery != "ok":
        sentence += f" Session discovery was incomplete: {sessions.discovery.removeprefix('ok; ')}."
    return sentence
