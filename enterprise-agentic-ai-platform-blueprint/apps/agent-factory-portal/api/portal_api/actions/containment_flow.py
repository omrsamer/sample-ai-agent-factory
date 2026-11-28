# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Contain and release an agent's Runtime.

Contain, in the agent's cell and with the cell's containment role:
  1. read the Runtime's resource policy;
  2. add the one containment statement, keeping every other statement as it is, and write the policy;
  3. read the policy back to verify;
  4. find the Runtime's recent sessions in its spans and stop them, bounded in number and time;
  5. when a sweep queue is configured, leave messages on it for the sweeper function, which
     finishes the job in the background (``portal_api/actions/sweeper.py``).
Release removes exactly that statement (the policy is deleted only when nothing
else remains) and verifies. Both are idempotent and never touch a statement
that does not carry the portal's Sid.

Three things hold for every request, whatever it asks for:

- The Runtime's ARN is the one the function builds from the cell's
  configuration (``portal_api/arns.py``). Every AWS call and the key of the
  history use that ARN and no other spelling of it.
- A Runtime is contained only when its policy holds the statement the portal
  writes, recognised by its whole shape (``containment_policy.state``).
- Only a caller who has a part in the Runtime (the role, and the Runtime's
  tenant) writes into its history, and only for a Runtime of a cell that has a
  containment role. Every other refusal is logged with its request id.

The function never invokes the Runtime to test the block: its role must not be
able to. A change to the policy is not enforced instantly: the service applies
it host by host. Every response says how long to allow
(``portal_api/containment_timing.py``, measured on a live Runtime).

Audit follows the same discipline as registrations: an intent event before
anything is changed, and a result event that says what was and was not done.
The policy is read, changed and written without a lock; two simultaneous
changes to the same policy from different tools could overwrite each other.

The Runtime's policy is read before the intent is written: reading it changes
nothing, and it says what the request can change. That decides which of the
two ranges of the Runtime's history the request's events are written into
(``portal_api/aws/audit.py``), all of them into the same one and each of
them once:

- a contain that writes the statement, a release that removes it, and a
  contain that finds the statement in place with nobody on record as holding
  it can change who holds the containment. Their events are the ones a
  release reads to find that person;
- a contain of a Runtime that is already contained and held, a release of
  one that is not contained, a refusal, and an attempt that could not read
  the policy change nothing about it. Their events, like the sweeps', are
  kept out of that read, so that it does not grow with them.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from portal_api import arns, authorities, containment_policy, registrations, sweeps
from portal_api.actions import audit_writer, containment, sweep_queue
from portal_api.actions import containment_rules as rules
from portal_api.actions.engine import ActionError, rule_of
from portal_api.aws import audit as audit_reader
from portal_api.aws.session import AwsClients, error_code
from portal_api.config import ActionSettings, Cell
from portal_api.containment_timing import (
    CONTAIN_DELAY_SECONDS,
    RELEASE_DELAY_SECONDS,
    REPEAT_AFTER_SECONDS,
    REPEAT_RECHECK_SECONDS,
    SWEEP_DELAYS_SECONDS,
    SWEEPS_OVER_AFTER_SECONDS,
    delay_words,
)
from portal_api.identity.provider import Principal
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
NOT_CANONICAL = (
    "runtime_arn is not this Runtime's ARN as the portal writes it: its partition, Region and account "
    "must be those of the Runtime's cell"
)
RECORD_NOT_CANONICAL = (
    "This registration names its Runtime by an ARN whose partition is not the one of the Runtime's cell, "
    "so the portal does not act on it. Correct the registration, or address the agent by its Runtime id."
)
# Since there are two ranges this can only come about by attempts that failed at the write of the
# policy, two events each and none of them at anyone's will, or in a history that was written
# before there were two.
HOLDER_NOT_FOUND = (
    f"The Runtime's containment history holds more than {audit_reader.MAX_DECISION_EVENTS} events since its "
    "last contain or release, so who contained it could not be established. The Runtime was not released."
)
NOT_KNOWN_WHETHER_WRITTEN = "It is not known whether the statement was written. Sessions were not stopped."
ALREADY_CONTAINED = "The Runtime was already contained; its policy was not changed."
NOT_THE_PORTALS = "The statement the portal writes was not in the Runtime's policy, so there was nothing to remove."
REPLACED_FOREIGN = (
    "A statement with the portal's identifier that the portal had not written was in the policy and was replaced."
)
_LABELS = {
    "policy": "Deny invocation in the Runtime's resource policy",
    "verify": "Read the policy back to confirm the deny statement",
    "sessions": "Stop the Runtime's running sessions",
    "background": "Stop remaining sessions in the background",
    "release": "Remove the deny statement from the Runtime's resource policy",
    "verify_release": "Read the policy back to confirm the statement is gone",
}


@dataclass
class _Resolved:
    """What a request resolved to, before anyone has been allowed anything."""

    runtime_arn: str  # the ARN the portal built when ``cell`` is set; otherwise as it was named
    cells: list[Cell]  # the cells configured for the Runtime's account and Region
    cell: Cell | None  # the one among them that has a containment role


@dataclass
class Target:
    """The Runtime an action is about, once the caller is known to have a part in it.

    A target exists only for a Runtime of a cell that has a containment role,
    and ``runtime_arn`` is the ARN the portal built for it
    (``arns.canonical_runtime_arn``). Every AWS call about the Runtime and
    every write to its history takes the ARN from here, so neither can use a
    spelling a caller chose.
    """

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


@dataclass
class _Opened:
    """The Runtime's policy as it was read before anything was written, and what the request can do to it."""

    control: Any  # the client in the cell
    policy: str | None
    found: str  # ``containment_policy.CONTAINED``, ``NOT_CONTAINED`` or ``FOREIGN``
    kept: int  # the statements that are not the portal's
    denied: list[str]  # contain: the actions the statement in place denies
    remaining: str | None  # release: the policy without the portal's statement, ``None`` when nothing is left
    steps: list[ContainmentStep]


@dataclass
class _Background:
    """The background sweeps a contain scheduled: the step that says so, and their delays in seconds."""

    step: ContainmentStep
    delays: list[int]


class ContainmentService:
    def __init__(
        self,
        settings: ActionSettings,
        clients: AwsClients,
        registry: Any,
        dynamodb: Any,
        principal: Principal,
        sqs: Any = None,
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.registry = registry
        self.dynamodb = dynamodb
        self.principal = principal
        self.sqs = sqs  # the queue client; None when background sweeps are not configured

    # --- resolving the agent -------------------------------------------------

    def _locate(self, parsed: arns.RuntimeArn, named: str, *, from_body: bool) -> _Resolved:
        """The cells of the account and Region ``named`` points into, and the ARN the portal uses for it.

        When one of those cells has a containment role, the ARN is built from
        that cell and ``named`` must be equal to it. The service answers for
        another spelling of the same Runtime (another partition string), and
        a second spelling would be a second history.
        """
        scope = (parsed.account, parsed.region)
        cells = [c for c in self.settings.cells if (c.account_id, c.region) == scope]
        cell = next((c for c in cells if c.containment_role_arn), None)
        if cell is None:
            # Nothing is read or written about a Runtime the portal cannot contain.
            return _Resolved(named, cells, None)
        canonical = arns.canonical_runtime_arn(cell, parsed.runtime_id)
        if named != canonical:
            if from_body:
                raise ActionError(422, [_field_error("runtime_arn", NOT_CANONICAL)])
            raise ActionError(409, RECORD_NOT_CANONICAL)
        return _Resolved(canonical, cells, cell)

    def resolve(self, agent_id: str, body: ContainmentInput) -> _Resolved:
        """The agent's Runtime ARN and the cells of its account and Region.

        A registered agent (its id is a registry record id) is resolved from
        its record; an agent with no registration is addressed by its Runtime
        id. Either way the ARN that is used afterwards is the one the portal
        builds from the cell (``_locate``), and the tenant is decided by where
        the Runtime runs (``_tenant``), never by what the record claims: a
        record is written by the people it governs, and a record naming
        another tenant's Runtime must not put that Runtime in their reach.

        Nothing is read from the cell or from the audit trail here.
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
            named = document.get("runtimeArn")
            if not named:
                raise ActionError(409, "This registration names no Runtime, so there is nothing to contain")
            if body.runtime_arn and body.runtime_arn != named:
                raise ActionError(422, [_field_error("runtime_arn", "runtime_arn is not this agent's Runtime")])
            parsed = arns.parse_runtime_arn(named)
            if parsed is None:
                raise ActionError(409, "This registration does not name a Runtime, so there is nothing to contain")
            return self._locate(parsed, named, from_body=False)

        if not arns.is_runtime_id(agent_id):
            raise ActionError(404, "Agent not found")
        if body.runtime_arn:
            parsed = arns.parse_runtime_arn(body.runtime_arn)
            if parsed is None or parsed.runtime_id != agent_id:
                raise ActionError(422, [_field_error("runtime_arn", "runtime_arn is not this agent's Runtime")])
            return self._locate(parsed, body.runtime_arn, from_body=True)
        scopes = sorted({(c.account_id, c.region) for c in self.settings.cells if c.containment_role_arn})
        if not scopes:
            raise ActionError(409, NOT_ENABLED)
        if len(scopes) > 1:
            message = "runtime_arn is required to act on an agent that has no registration"
            raise ActionError(422, [_field_error("runtime_arn", message)])
        cells = [c for c in self.settings.cells if (c.account_id, c.region) == scopes[0]]
        cell = next(c for c in cells if c.containment_role_arn)
        return _Resolved(arns.canonical_runtime_arn(cell, agent_id), cells, cell)

    def _tenant(self, resolved: _Resolved) -> str | None:
        """The tenant that decides who may act on this Runtime (``containment_rules.tenant_for``).

        With one tenant among the cells of the Runtime's account and Region
        nothing is read. In an account that several tenants share, the
        Runtime's own ``tenant-id`` tag is read with the cell's containment
        role, under the ARN the portal built. If it cannot be read, the
        tenant is undetermined. This runs only after the caller's role has
        passed (``run``).
        """
        tenants = {c.tenant_id for c in resolved.cells}
        if len(tenants) <= 1:
            return rules.tenant_for(tenants)
        if resolved.cell is None:
            return None
        try:
            control = self._client(resolved.cell, "bedrock-agentcore-control")
            tag = containment.get_tenant_tag(control, resolved.runtime_arn)
        except Exception as exc:  # noqa: BLE001 - undetermined, which only the platform role may act on
            logger.warning("The Runtime's tenant tag could not be read: %s", error_code(exc))
            return None
        return rules.tenant_for(tenants, tag)

    # --- audit ---------------------------------------------------------------------

    def _holder(self, target: Target) -> AuditEvent | None:
        """The event that names who holds the containment of the target, or ``None`` when nobody does.

        Only the events that can settle it are read, back to the one that
        does (``audit.read_holder``): the sweeps and the repeated contains
        recorded since are not among them, whatever their number. Fails
        closed twice over: no trail, no decision; and a history in which
        that event is not among the newest ``audit.MAX_DECISION_EVENTS`` of
        those does not say who contained the Runtime, which must not read as
        "nobody did".
        """
        try:
            trail, found = audit_reader.read_holder(self.dynamodb, self.settings.audit_table, target.runtime_arn)
        except Exception as exc:  # noqa: BLE001 - no trail, no decision
            logger.error("Audit trail could not be read: %s", error_code(exc))
            raise ActionError(503, "The audit trail could not be read, so no decision was taken") from exc
        if not (found.decided or trail.ended):
            # Not written to the history: one more event there would only lengthen the read.
            raise self._refuse(409, "release", target.agent_id, target.runtime_arn, HOLDER_NOT_FOUND)
        return found.event

    def _seen(self, target: Target) -> audit_reader.History | None:
        """The newest events of the target's history before a contain, or ``None`` when they cannot be read.

        One request for each range and no more (``audit.read_newest``). A
        contain never fails or waits for its history: if the read fails the
        contain goes on as if it knew nothing.
        """
        try:
            return audit_reader.read_newest(self.dynamodb, self.settings.audit_table, target.runtime_arn)
        except Exception as exc:  # noqa: BLE001 - the contain does its work
            logger.warning("The history could not be read before a contain: %s", error_code(exc))
            return None

    def _nobody_on_record(self, target: Target, seen: audit_reader.History | None) -> bool:
        """Whether a contain that finds the statement in place may be the one that names the holder.

        It is when the history says that nobody holds the containment (the
        Runtime was contained by other means, or by a request whose events
        were lost): the first person to assert it holds it, so this contain
        is written where a release looks for that person. It also is when
        the history cannot be read, for the same reason.

        The newest events usually say it. When they do not (a history from
        before there were two ranges can hold more sweeps than that at its
        top), it is read as a release reads it, so that the answer is the
        one a release would get. If that does not settle it either, a
        release is refused whatever is written here, and this contain adds
        nothing to the events it reads.
        """
        if seen is None:
            return True
        if seen.settled:
            return seen.holder.event is None
        try:
            trail, found = audit_reader.read_holder(self.dynamodb, self.settings.audit_table, target.runtime_arn)
        except Exception as exc:  # noqa: BLE001 - the contain does its work
            logger.warning("The history could not be read before a contain: %s", error_code(exc))
            return True
        return (found.decided or trail.ended) and found.event is None

    def _write(self, target: Target, event: AuditEvent, settles: bool) -> bool:
        """Append to the target's containment history. The key is the ARN the portal built, never a caller's.

        ``settles`` says which range the event belongs to: true for an event
        of a request that can change who holds the containment, false for
        every other. One write either way.
        """
        prefix = audit_reader.EVENT_PREFIX if settles else audit_reader.OTHER_PREFIX
        try:
            audit_writer.put_event(
                self.dynamodb,
                self.settings.audit_table,
                audit_reader.containment_key(target.runtime_arn),
                event,
                prefix=prefix,
            )
            return True
        except Exception as exc:  # noqa: BLE001 - the caller decides what a failed write means
            logger.error("Audit write failed (%s %s %s): %s", event.action, event.phase, event.outcome, error_code(exc))
            return False

    def _event(
        self, action: str, target: Target, request_id: str, phase: str, outcome: str, reason: str, **extra: Any
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
            tenant_id=target.tenant_id,
            agent_id=target.agent_id,
            runtime_arn=target.runtime_arn,
            **extra,
        )

    def _refuse(self, status: int, action: str, agent_id: str, runtime_arn: str | None, reason: str) -> ActionError:
        """A refusal that is logged, not written to the audit trail, and the error to raise.

        For a caller who has no part in the Runtime (the role, or the
        Runtime's tenant) and for a Runtime that is not in a cell with a
        containment role. Such a refusal written into a history would let
        any signed-in responder of one tenant fill the history of another
        tenant's Runtime, or a history under a name of their own choosing,
        and a history is never shortened. The function's log keeps the
        attempt, and the answer carries the same ``request_id``.
        """
        request_id = audit_writer.new_request_id()
        logger.warning(
            "Containment refusal logged, not written to the audit trail: action=%s role=%s subject=%s "
            "agent=%s runtime=%s request_id=%s reason=%s",
            action,
            self.principal.role,
            self.principal.subject,
            agent_id,
            runtime_arn or "-",
            request_id,
            reason,
        )
        return ActionError(status, reason, action=action, request_id=request_id)

    def _deny(self, status: int, action: str, target: Target, reason: str, holder: AuditEvent | None) -> ActionError:
        """A refusal of a caller who has a part in the Runtime: recorded in the Runtime's history, once.

        Once for each person, rule and containment, and logged after that.
        ``holder`` is the event that names who holds the containment: its id
        stands for the containment. What makes the "once" hold is a mark
        written with the condition that it does not exist
        (``audit_writer.mark_once``), so it needs no read and holds however
        long the containment lasts and however fast the request is repeated.
        If the mark cannot be written, nothing is written into the history
        either: without it a repeated request would add an event each time.
        """
        request_id = audit_writer.new_request_id()
        try:
            first = audit_writer.mark_once(
                self.dynamodb,
                self.settings.audit_table,
                audit_reader.containment_key(target.runtime_arn),
                holder.event_id if holder is not None else "",
                self.principal.subject,
                action,
                rule_of(reason),
                request_id,
            )
        except Exception as exc:  # noqa: BLE001 - logged; the refusal stands either way
            logger.error("Audit mark failed (%s): %s", action, error_code(exc))
            first = None
        if first:
            self._write(target, self._event(action, target, request_id, "result", "denied", reason), settles=False)
        else:
            logger.warning(
                "Containment refusal %s: action=%s subject=%s runtime=%s request_id=%s reason=%s",
                "logged, not written to the audit trail" if first is None else "already on record, not written again",
                action,
                self.principal.subject,
                target.runtime_arn,
                request_id,
                reason,
            )
        return ActionError(status, reason, action=action, request_id=request_id)

    # --- the action -------------------------------------------------------------------

    def run(self, action: str, agent_id: str, body: ContainmentInput) -> ContainmentResult:
        role = self.principal.role
        caller = {
            "action": action,
            "role": role,
            "principal_id": self.principal.subject,
            "held_tenants": authorities.tenants_of(self.principal.groups, self.settings.group_tenant_map),
            "holds_all_tenants": authorities.holds_all_tenants(role),
        }
        allowed_roles = rules.CONTAIN_ROLES if action == "contain" else rules.RELEASE_ROLES
        if role not in allowed_roles:
            # Refused before anything is looked up, so the answer does not reveal whether the agent exists.
            blind = rules.access_refusal(
                action=action,
                role=role,
                principal_id=self.principal.subject,
                agent_tenant=None,
                held_tenants=(),
                holds_all_tenants=False,
            )
            raise self._refuse(403, action, agent_id, None, blind.reason if blind else "refused - fail closed")

        resolved = self.resolve(agent_id, body)
        tenant = self._tenant(resolved)
        refusal = rules.access_refusal(**caller, agent_tenant=tenant)
        if refusal is not None:
            # The caller does not hold the Runtime's tenant, so has no part in it. Nothing has been
            # read of its history, and nothing is written into it.
            raise self._refuse(403, action, agent_id, resolved.runtime_arn, refusal.reason)
        if resolved.cell is None:
            raise self._refuse(409, action, agent_id, resolved.runtime_arn, NOT_ENABLED)
        target = Target(agent_id, resolved.runtime_arn, tenant, resolved.cell)

        # What the history says. Only a release depends on who contained the Runtime, and fails
        # closed when that is not known. A contain never fails or waits for its history, however
        # long it is: it looks at the newest events, one request for each range.
        contained_by: AuditEvent | None = None
        seen: audit_reader.History | None = None
        if action == "release":
            contained_by = self._holder(target)
        else:
            seen = self._seen(target)
        decision = rules.evaluate(
            **caller,
            agent_tenant=tenant,
            contained_by=contained_by.actor_subject if contained_by else None,
            # The tenant the Runtime had when it was contained: its contain event carries it.
            contained_tenant=contained_by.tenant_id if contained_by else None,
        )
        if not decision.allowed:
            raise self._deny(403, action, target, decision.reason, contained_by)

        # The Runtime's policy says what this request can change. Reading it changes nothing, so
        # it is read before the intent is written, and the intent goes where its events belong.
        request_id = audit_writer.new_request_id()
        try:
            opened = self._open(target, action)
        except _Failed as failure:
            # Nothing was changed and nothing could have been: one event says so, and there was
            # no intent to write.
            raise self._failed(action, target, request_id, failure, settles=False) from failure

        if action == "contain":
            # A contain of an agent that was contained a moment ago adds nothing: when the policy
            # still holds the portal's statement it is answered at once, with no intent.
            repeat, current = self._repeat_too_soon(seen)
            if repeat is not None and opened.found == containment_policy.CONTAINED:
                return self._answer_at_once(target, repeat, current, opened, request_id)
            # It can change who holds the containment when it writes the statement, and when the
            # statement is in place with nobody on record as holding it: the first to assert a
            # containment holds it.
            settles = opened.found != containment_policy.CONTAINED or self._nobody_on_record(target, seen)
        else:
            # A release changes it when there is a statement of the portal's to remove.
            settles = opened.found == containment_policy.CONTAINED

        intent = self._event(action, target, request_id, "intent", "allowed", decision.reason)
        if not self._write(target, intent, settles):
            raise ActionError(503, "The audit trail could not be written, so the action was not performed")

        try:
            if action == "contain":
                result = self._contain(target, body.reason, request_id, opened)
            else:
                result = self._release(target, body.reason, request_id, opened)
        except _Failed as failure:
            raise self._failed(action, target, request_id, failure, settles) from failure

        sessions = result.sessions
        event = self._event(
            action,
            target,
            request_id,
            "result",
            result.outcome,
            result.reason,
            status_before=result.state if not result.changed else _other(result.state),
            status_after=result.state,
            sessions_found=sessions.found if sessions else None,
            sessions_stopped=sessions.stopped if sessions else None,
            sessions_failed=(sessions.failed + sessions.not_attempted) if sessions else None,
            sweeps_scheduled=len(result.sweeps_scheduled_in_seconds) or None,
            # Which sweeps: the sweeper admits no other number for this contain.
            sweeps_scheduled_numbers=sweeps.encode_numbers(
                SWEEP_DELAYS_SECONDS.index(delay) + 1 for delay in result.sweeps_scheduled_in_seconds
            ),
            detail=sessions.discovery if sessions else None,
        )
        # The result goes where its intent went: the two are read together.
        result.audit_complete = self._write(target, event, settles)
        return result

    def _failed(self, action: str, target: Target, request_id: str, failure: _Failed, settles: bool) -> ActionError:
        """Record an action that stopped part-way, and the error to raise for it."""
        failed = self._event(
            action,
            target,
            request_id,
            "result",
            "failed",
            failure.done,
            status_before=failure.before,
            status_after=failure.after,
        )
        self._write(target, failed, settles)
        return ActionError(
            failure.status,
            failure.done,
            action=action,
            request_id=request_id,
            steps=[step.model_dump() for step in failure.steps],
        )

    # --- a contain repeated too soon ------------------------------------------------------------

    def _repeat_too_soon(self, seen: audit_reader.History | None) -> tuple[sweeps.Repeat | None, list[AuditEvent]]:
        """Whether a contain comes too soon after the last one, whose background sweeps are still at work.

        The newest events of the history say it (``_seen``). A contain never
        fails for its history: if that read failed, or says nothing, the
        contain goes on as it always did. Without a sweep queue no contain
        schedules a sweep, so none is ever too soon. Also returns the events
        of the containment that holds, as far as they were read.
        """
        if seen is None:
            return None, []
        current = seen.events[: seen.holder.current]
        repeat = sweeps.repeat_too_soon(
            current,
            _now(),
            repeat_after_seconds=REPEAT_AFTER_SECONDS,
            sweeps_over_after_seconds=SWEEPS_OVER_AFTER_SECONDS,
            recheck_seconds=REPEAT_RECHECK_SECONDS,
        )
        return repeat, current

    def _answer_at_once(
        self,
        target: Target,
        repeat: sweeps.Repeat,
        current: list[AuditEvent],
        opened: _Opened,
        request_id: str,
    ) -> ContainmentResult:
        """The answer to a contain that comes too soon after the last one.

        The history says that the agent was contained a moment ago, and the
        policy, which has the last word, still holds the portal's statement
        (``run`` asks both before it comes here). No session is stopped and
        nothing is scheduled.

        The request changed nothing, so there is no intent. Its result is
        written once for each person since the last contain that did its
        work, and logged after that: the history says who asked again, and a
        request repeated every second adds one event, not one each time.
        """
        policy_step, verify_step, sessions_step = opened.steps
        policy_step.status, policy_step.detail = "unchanged", "The Runtime was already contained."
        verify_step.status = "done"
        wait = delay_words(repeat.wait_seconds)
        if repeat.sweeps_pending:
            sessions_step.detail = (
                "The background sweeps of this containment are still running, so nothing more was done. "
                f"A contain stops sessions again once they have run: ask again in {wait}."
            )
        else:
            sessions_step.detail = (
                "The background sweeps of this containment ran less than "
                f"{delay_words(REPEAT_AFTER_SECONDS)} ago, so nothing more was done. "
                f"A contain stops sessions again in {wait}."
            )
        result = ContainmentResult(
            action="contain",
            outcome="unchanged",
            reason=f"{ALREADY_CONTAINED} {sessions_step.detail}",
            request_id=request_id,
            agent_id=target.agent_id,
            runtime_arn=target.runtime_arn,
            state=CONTAINED,
            changed=False,
            other_statements_kept=opened.kept,
            steps=opened.steps,
            denied_actions=opened.denied,
            enforcement_delay_seconds=CONTAIN_DELAY_SECONDS,
            retry_after_seconds=repeat.wait_seconds,
        )
        # A result with no session counts: that is how it differs from a contain that did its work.
        on_record = any(
            event.action == "contain"
            and event.phase == "result"
            and event.outcome == "unchanged"
            and event.sessions_found is None
            and event.actor_subject == self.principal.subject
            and event.at > repeat.since
            for event in current
        )
        if on_record:
            logger.info(
                "Contain repeated too soon, answered at once and not written again: subject=%s runtime=%s "
                "request_id=%s wait_seconds=%s",
                self.principal.subject,
                target.runtime_arn,
                request_id,
                repeat.wait_seconds,
            )
        else:
            event = self._event(
                "contain",
                target,
                request_id,
                "result",
                "unchanged",
                result.reason,
                status_before=CONTAINED,
                status_after=CONTAINED,
            )
            result.audit_complete = self._write(target, event, settles=False)
        return result

    def _client(self, cell: Cell, service: str) -> Any:
        """A client in the cell, through the cell's containment role and external id."""
        return self.clients.assumed(cell.containment_role_arn or "", cell.external_id, cell.region, service)

    def _open(self, target: Target, action: str) -> _Opened:
        """Assume the containment role, read the Runtime's policy and say what the action can do to it.

        This is the one read of the policy before anything is written, to
        the policy or to the history. Nothing has been changed if it fails.
        """
        steps = _steps(action)
        step = steps[0]
        arn = target.runtime_arn
        try:
            control = self._client(target.cell, "bedrock-agentcore-control")
        except Exception as exc:  # noqa: BLE001
            step.detail = f"The cell's containment role could not be assumed ({error_code(exc)})."
            raise _Failed(502, f"{step.detail} Nothing was changed.", steps) from exc
        try:
            policy = containment.get_policy(control, arn)
        except ClientError as exc:
            step.detail = f"The Runtime's resource policy could not be read ({error_code(exc)})."
            raise _Failed(502, f"Nothing was changed. {step.detail}", steps) from exc
        try:
            return _Opened(
                control=control,
                policy=policy,
                found=containment_policy.state(policy, arn),
                kept=containment_policy.other_statements(policy),
                denied=containment_policy.denied_actions(policy, arn) if action == "contain" else [],
                remaining=containment_policy.without_containment(policy) if action == "release" else None,
                steps=steps,
            )
        except containment_policy.PolicyError as exc:
            step.detail = f"{exc}."
            raise _Failed(409, f"Nothing was changed: {exc}.", steps) from exc

    def _contain(self, target: Target, reason: str, request_id: str, opened: _Opened) -> ContainmentResult:
        steps = opened.steps
        policy_step, verify_step, sessions_step = steps
        control, policy, found, kept, denied = opened.control, opened.policy, opened.found, opened.kept, opened.denied
        # Contained means the statement the portal writes is there. A statement that only carries
        # the portal's Sid denies nothing that can be relied on: it is replaced, and the result says so.
        already = found == containment_policy.CONTAINED
        replaced = found == containment_policy.FOREIGN
        before = CONTAINED if already else NOT_CONTAINED

        if already:
            policy_step.status, policy_step.detail = "unchanged", "The Runtime was already contained."
            verify_step.status = "done"
        else:
            denied = self._put_statement(control, target, policy, policy_step, steps, before)
            if replaced:
                policy_step.detail = f"{policy_step.detail} {REPLACED_FOREIGN}"
            verify_step.status = "failed"
            try:
                verified = containment.get_policy(control, target.runtime_arn)
            except ClientError as exc:
                verify_step.detail = f"The policy could not be read back ({error_code(exc)})."
                done = f"The deny statement was written but could not be verified. {verify_step.detail}"
                raise _Failed(502, f"{done} Sessions were not stopped.", steps, before, "unknown") from exc
            if not containment_policy.is_contained(verified, target.runtime_arn):
                verify_step.detail = "The statement was not found when the policy was read back."
                done = "The deny statement was written but was not found when the policy was read back."
                raise _Failed(502, f"{done} Sessions were not stopped.", steps, before, "unknown")
            verify_step.status = "done"

        sessions = self._stop_sessions(target)
        sessions_step.status, sessions_step.detail = _sessions_status(sessions), _sessions_sentence(sessions)
        background = self._schedule_sweeps(target, request_id, sessions_step.status == "done")
        if background is not None:
            steps.append(background.step)
        if already:
            done = ALREADY_CONTAINED
        else:
            done = (
                "Invocation of the Runtime is denied (statement written and verified; "
                f"enforced everywhere within {delay_words(CONTAIN_DELAY_SECONDS)})."
            )
            if tuple(denied) != containment_policy.ALL_INVOKE_ACTIONS:
                done += " The service accepted only the core invoke actions in the statement."
            if replaced:
                done += f" {REPLACED_FOREIGN}"
        summary = f"{done} {sessions_step.detail}"
        if background is not None:
            summary += f" {background.step.detail}"
        return ContainmentResult(
            action="contain",
            outcome="unchanged" if already else "allowed",
            reason=summary if already else f"{reason} [{summary}]",
            request_id=request_id,
            agent_id=target.agent_id,
            runtime_arn=target.runtime_arn,
            state=CONTAINED,
            changed=not already,
            replaced_foreign_statement=replaced,
            other_statements_kept=kept,
            sessions=sessions,
            steps=steps,
            partial=sessions_step.status != "done" or (background is not None and background.step.status == "failed"),
            denied_actions=denied,
            enforcement_delay_seconds=CONTAIN_DELAY_SECONDS,
            sweeps_scheduled_in_seconds=background.delays if background is not None else [],
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

        A write that the service refused changed nothing. A write whose
        answer never came, or came as a server error or as throttling after
        the SDK's own retries, may have been applied all the same. That one
        is recorded as ``unknown``, so that the person who asked for it is on
        record as the holder: if the statement is in place, they must not be
        the one to remove it.
        """
        attempts = (containment_policy.ALL_INVOKE_ACTIONS, containment_policy.CORE_INVOKE_ACTIONS)
        for index, actions in enumerate(attempts):
            updated = containment_policy.with_containment(policy, target.runtime_arn, actions)
            try:
                containment.put_policy(control, target.runtime_arn, updated)
            except Exception as exc:  # noqa: BLE001 - every failure of the write is reported, none is raised raw
                code = error_code(exc)
                if code == "ValidationException" and index + 1 < len(attempts):
                    logger.warning("The full invoke action list was rejected; writing the core actions instead")
                    continue
                step.detail = f"The deny statement could not be written ({code})."
                if containment.may_have_been_applied(exc):
                    done = f"{step.detail} {NOT_KNOWN_WHETHER_WRITTEN}"
                    raise _Failed(502, done, steps, before, "unknown") from exc
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

    def _schedule_sweeps(self, target: Target, request_id: str, complete: bool) -> _Background | None:
        """Leave the background sweeps of this containment on the queue.

        ``complete`` says whether the sweep inside this request dealt with
        every session it found. If it did, no sweep is needed now, and only
        the later ones are scheduled. Returns ``None`` when no queue is
        configured: the contain is then exactly what it was without sweeps.

        A queue setting that is not a queue address does not stop the
        contain: the step fails and says which setting is wrong.
        """
        step = ContainmentStep(id="background", label=_LABELS["background"], status="failed")
        if self.settings.sweep_queue_error:
            logger.error("Background sweeps cannot be scheduled: %s", self.settings.sweep_queue_error)
            step.detail = (
                f"Background sweeps could not be scheduled: {self.settings.sweep_queue_error}. "
                "Contain again once it is corrected."
            )
            return _Background(step, [])
        queue_url = self.settings.sweep_queue_url
        if not queue_url or self.sqs is None:
            return None
        numbers = sweeps.sweeps_to_schedule(first_needed=not complete)
        delays: list[int] = []
        try:
            for number in numbers:
                delay = SWEEP_DELAYS_SECONDS[number - 1]
                message = sweeps.SweepMessage(number, target.runtime_arn, target.agent_id, request_id)
                sweep_queue.send(self.sqs, queue_url, sweeps.encode(message), delay)
                delays.append(delay)
        except Exception as exc:  # noqa: BLE001 - the deny statement is in place either way
            logger.error("Background sweeps could not be scheduled: %s", error_code(exc))
            # With none scheduled, the next contain does its work at once and schedules them. With
            # some scheduled, it does so once those have run or the pause between two contains is over.
            again = "Contain again" if not delays else f"Contain again in {delay_words(REPEAT_AFTER_SECONDS)}"
            step.detail = (
                f"Background sweeps could not be scheduled ({error_code(exc)}): {len(delays)} of "
                f"{len(numbers)} were. {again} to schedule them."
            )
            return _Background(step, delays)
        step.status = "scheduled"
        later = " and ".join(f"in {delay_words(delay)}" for delay in delays if delay)
        if complete:
            step.detail = f"No background sweep is needed now. Later sweeps are scheduled {later}."
        else:
            step.detail = f"Background sweeps are scheduled: now, {later}."
        return _Background(step, delays)

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

    def _release(self, target: Target, reason: str, request_id: str, opened: _Opened) -> ContainmentResult:
        steps = opened.steps
        policy_step, verify_step = steps
        control, found, kept, remaining = opened.control, opened.found, opened.kept, opened.remaining
        contained = found == containment_policy.CONTAINED
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
            unchanged = "The Runtime was not contained; its policy was not changed."
            if found == containment_policy.FOREIGN:
                # Not the portal's statement, so a release leaves it where it is and says that it is
                # there. It does not say "not contained": that statement may deny invocation.
                policy_step.detail = f"{NOT_THE_PORTALS} {containment_policy.FOREIGN_STATEMENT}"
                unchanged = f"{NOT_THE_PORTALS} Its policy was not changed. {containment_policy.FOREIGN_STATEMENT}"
            return ContainmentResult(outcome="unchanged", reason=unchanged, changed=False, **common)
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
        if containment_policy.is_contained(verified, target.runtime_arn):
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


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _steps(action: str) -> list[ContainmentStep]:
    """The steps of an answer, as they stand before anything is done."""
    if action == "contain":
        return [
            ContainmentStep(id="policy", label=_LABELS["policy"], status="failed"),
            ContainmentStep(id="verify", label=_LABELS["verify"], status="skipped"),
            ContainmentStep(id="sessions", label=_LABELS["sessions"], status="skipped"),
        ]
    return [
        ContainmentStep(id="policy", label=_LABELS["release"], status="failed"),
        ContainmentStep(id="verify", label=_LABELS["verify_release"], status="skipped"),
    ]


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
