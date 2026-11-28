# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The background sweep of a contained Runtime: what the sweeper function does with one message.

The sweeper serves no route and answers no caller of the portal. The queue
invokes it, and so can whoever may invoke the function directly, so nothing
in a message is trusted. For one message it:

  1. validates the message as untrusted input, finds the Runtime's cell in
     its own configuration, never in the message, and accepts the Runtime's
     ARN only in the spelling the portal builds for that cell;
  2. reads the Runtime's containment history, back to the contain the message
     names. The sweep is run only when that contain is on record and got as
     far as scheduling sweeps, when this sweep is due and has not left its
     event yet, and when no later containment has taken that contain's
     place. It then claims the sweep with a conditional write, so that a
     second delivery, a replay or a second invocation at the same moment
     cannot run it again;
  3. reads the Runtime's resource policy with the cell's containment role. If
     the statement the portal writes is not there (the agent was released
     meanwhile, or a statement that only carries the portal's Sid stands in
     its place) it stops nothing. A release cancels nothing in the queue;
     this check is what makes a late sweep harmless;
  4. lists the Runtime's sessions of the lookback window, with no limit on
     their number, only on the time the function has;
  5. stops them, most recent first, at a capped rate, reading the policy again
     every half minute and ending early if the agent was released meanwhile;
  6. writes one audit event (action ``sweep``) in the Runtime's containment
     history: what it found, what it stopped, and how long it took.

A history is never shortened, and a release reads it back to the contain it
undoes. So the sweeper writes into it only for a sweep that a contain on
record scheduled, and once: at most three events for one contain, whoever
sends or replays messages or invokes the function. A message that fails
step 1 or step 2 goes to the function's log and nowhere else.

It decides nothing about who may contain an agent: the contain that left the
message was authorised. It can only ever stop sessions of a Runtime that the
portal's own statement contains at that moment, in a cell that opted in.

It parses input that anyone who can reach the queue or the function chose, so
it does not hold the authority the containment function holds. It assumes the
cell's containment role with a session policy (``session_policy``) that
allows only what a sweep does: read the policy, list sessions, stop them.
Writing or deleting a resource policy is not among it, whatever this code or
a later change to it does.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import time
import uuid
from collections import deque
from collections.abc import Callable
from typing import Any

from portal_api import arns, containment_policy, sweeps
from portal_api.actions import audit_writer, containment
from portal_api.actions import containment_rules as rules
from portal_api.aws import audit as audit_reader
from portal_api.aws.parallel import pmap
from portal_api.aws.session import SESSION_SWEEPER, AwsClients, error_code
from portal_api.config import Cell, SweeperSettings
from portal_api.containment_timing import (
    SWEEP_DELAYS_SECONDS,
    SWEEP_EARLY_TOLERANCE_SECONDS,
    SWEEP_STOPS_PER_SECOND,
)
from portal_api.mappers.common import arn_parts
from portal_api.models.portal import AuditEvent

logger = logging.getLogger(__name__)

INVALID = "invalid"
# What ``handle`` returns for a valid message whose sweep is not run and leaves no event.
NO_CONTAIN = "no_contain"  # no contain that scheduled sweeps is on record under its request id
REPEATED = "repeated"  # this sweep has already left its event
SUPERSEDED = "superseded"  # its contain belongs to an earlier containment, and a later one holds
CONTAINED, NOT_CONTAINED, UNKNOWN = "contained", "not_contained", "unknown"
# Time kept back at the end of an invocation to write the audit event.
RESERVE_SECONDS = 30.0
# Codes the service uses for "try again"; such a stop is tried again, a few times.
RETRYABLE = frozenset(
    {"ThrottlingException", "ServiceQuotaExceededException", "RetryableConflictException", "InternalServerException"}
)
MAX_RETRIES_PER_SESSION = 3
MAX_PAUSE_SECONDS = 8.0
# How long a sweep waits for the spans query of a cell that opted in to spans. A request waits 8 seconds.
SPANS_WAIT_SECONDS = 60.0
# How often a sweep that is stopping sessions reads the policy again, so that a release ends it.
RECHECK_SECONDS = 30.0


# What a sweep does in a cell, and nothing more. The first three are always needed; the last two
# only in a cell that opted in to finding sessions in its spans.
SWEEP_ACTIONS: tuple[str, ...] = (
    "bedrock-agentcore:GetResourcePolicy",
    "bedrock-agentcore:StopRuntimeSession",
    "bedrock-agentcore:ListAgentRuntimeEndpoints",
    "logs:DescribeLogStreams",
)
SWEEP_SPANS_ACTIONS: tuple[str, ...] = ("logs:StartQuery", "logs:GetQueryResults")


def session_policy(cell: Cell) -> str:
    """The session policy the sweeper assumes a cell's containment role with.

    A session can do only what both the role and this document allow, so the
    sweeper's session cannot write or delete a resource policy although the
    role it assumes can. ``Resource`` is ``*`` because the role's own policy
    already names the resources; this document only takes actions away.
    """
    actions = [*SWEEP_ACTIONS, *(SWEEP_SPANS_ACTIONS if cell.containment_spans else ())]
    document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
    return json.dumps(document, separators=(",", ":"))


class SweepNotRecorded(Exception):
    """The sweep ran but its audit event could not be written. The message must come back."""


class SweepNotVerified(Exception):
    """The history or the claim could not be read or written, so it is not known whether the sweep may run.

    Nothing was run. The message must come back, and it is tried again.
    """


class SweepNotDue(Exception):
    """The message came before its sweep is due. Nothing was run and nothing written.

    The queue holds every message back for its delay, so this is not a
    message the contain sent through the queue at that moment: it was handed
    to the function directly, or the clocks of two hosts disagree. Either
    way the sweep is not used up. The message must come back, and a real
    one is run when it is due.
    """


class SweepNotFinished(Exception):
    """Another delivery of this message claimed the sweep and has left no event.

    It is still running, or it was cut short. This delivery runs nothing
    and writes nothing. The message must come back: if the other one
    finishes, the next delivery finds its event and is done; if it never
    does, the message ends in the dead-letter queue, where it is noticed.
    """


class _Current:
    """A client that is looked up again at every call.

    A sweep can outlast the credentials it started with: a cell's role is
    assumed for 15 minutes, credentials handed out by an earlier invocation
    can be most of the way through that, and a sweep can run for nearly as
    long. Asking the client factory at each call lets it assume the role
    again when the credentials are near their end.
    """

    def __init__(self, lookup: Callable[[], Any]) -> None:
        self._lookup = lookup

    def __getattr__(self, name: str) -> Any:
        return getattr(self._lookup(), name)


class Sweeper:
    def __init__(
        self,
        settings: SweeperSettings,
        clients: AwsClients,
        dynamodb: Any,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        stops_per_second: int = SWEEP_STOPS_PER_SECOND,
        now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.dynamodb = dynamodb
        self.sleep = sleep
        self.clock = clock  # for durations
        self.stops_per_second = stops_per_second
        self.now = now  # the time of day, to tell whether a sweep is due

    # --- one message ---------------------------------------------------------------

    def handle(self, body: Any, remaining_seconds: Callable[[], float]) -> str:
        """Run the sweep one message asks for, and return what became of it.

        ``allowed``, ``failed`` and ``skipped`` are the outcomes of a sweep
        that left its one event. ``invalid``, ``no_contain``, ``repeated``
        and ``superseded`` are messages that were not run and left nothing
        but a line in the function's log.

        Returning means the message is done with and can be deleted. Four
        things raise, so that the queue delivers the message again: a
        history or a claim that could not be read or written
        (``SweepNotVerified``), a sweep that is not due yet
        (``SweepNotDue``), a sweep that another delivery claimed and has not
        finished (``SweepNotFinished``), and a sweep whose event could not
        be written (``SweepNotRecorded``). None of them leaves an event.
        """
        started = self.clock()
        try:
            message = sweeps.decode(body)
        except sweeps.InvalidMessage as exc:
            return self._refuse(exc.reason)
        cells = self._cells(message.runtime_arn)
        cell = next((c for c in cells if c.containment_role_arn), None)
        if cell is None:
            return self._refuse("its Runtime is not in a configured cell with a containment role")
        if arns.canonical_in(cell, message.runtime_arn) is None:
            # Another spelling of the ARN would be another history. Nothing is read or written under it.
            return self._refuse("its Runtime ARN is not written the way the portal writes it for that cell")
        left_out, held = self._admit(message)
        if left_out is not None:
            return left_out
        return self._sweep(message, cell, cells, started, remaining_seconds, held)

    def _cells(self, runtime_arn: str) -> list[Cell]:
        parts = arn_parts(runtime_arn) or {}
        scope = (parts.get("account"), parts.get("region"))
        return [c for c in self.settings.cells if (c.account_id, c.region) == scope]

    def _refuse(self, reason: str) -> str:
        """A message that is not a valid sweep request: logged, never written, never retried.

        Nothing is written to the audit table for it, also when its Runtime
        is one the portal may contain: whoever can invoke the function could
        otherwise add an event to that Runtime's history with every message,
        and a history is never shortened. ``reason`` is the sweeper's own
        text; nothing the message said goes to the log.
        """
        logger.error("Sweep message refused, nothing written: %s", reason)
        return INVALID

    # --- whether the sweep belongs to a contain on record, once --------------------------------

    def _admit(self, message: sweeps.SweepMessage) -> tuple[str | None, bool]:
        """Whether this message's sweep is run, decided on the Runtime's own history.

        Returns what became of a message that is not run (see ``handle``),
        or ``None`` for one that is; and whether a contain holds the Runtime
        according to the history.

        A valid message proves nothing: its request id and sweep number are
        whatever its sender wrote. The history says whether a contain with
        that id scheduled sweeps, whether this one has already left its
        event, whether it is due, and whether that contain is part of the
        containment that holds. A sweep that passes is claimed before
        anything is done in the cell.
        """
        arn, number, request_id = message.runtime_arn, message.sweep, message.request_id
        try:
            trail = audit_reader.read_for_sweep(self.dynamodb, self.settings.audit_table, arn, request_id)
        except Exception as exc:  # noqa: BLE001 - no history, no sweep; the message comes back
            logger.error(
                "Sweep %s of contain %s: the history could not be read: %s", number, request_id, error_code(exc)
            )
            raise SweepNotVerified(error_code(exc)) from exc
        events = trail.events

        def left_out(outcome: str, why: str) -> tuple[str, bool]:
            logger.warning("Sweep %s of contain %s not run, nothing written (%s): %s", number, request_id, outcome, why)
            return outcome, False

        contain = sweeps.scheduler(events, request_id)
        if contain is None:
            return left_out(NO_CONTAIN, "the Runtime's history holds no contain with that id that scheduled sweeps")
        if sweeps.recorded(events, request_id, number):
            return left_out(REPEATED, "this sweep has already left its event")
        wait = sweeps.seconds_until_due(contain.began, number, self.now(), SWEEP_DELAYS_SECONDS)
        if wait > SWEEP_EARLY_TOLERANCE_SECONDS:
            logger.warning(
                "Sweep %s of contain %s not run, nothing written: it is not due for another %.0f seconds",
                number,
                request_id,
                wait,
            )
            raise SweepNotDue(f"sweep {number} of contain {request_id}")
        holder = audit_reader.holder(events)
        held = holder.event is not None
        if held and contain.position >= holder.current:
            # Released since, and contained again: the sweeps of the contain that holds do the work.
            return left_out(SUPERSEDED, "its contain belongs to an earlier containment of the Runtime")
        try:
            claimed = audit_writer.claim_sweep(self.dynamodb, self.settings.audit_table, arn, request_id, number)
        except Exception as exc:  # noqa: BLE001 - not known whether it may run; the message comes back
            logger.error("Sweep %s of contain %s: it could not be claimed: %s", number, request_id, error_code(exc))
            raise SweepNotVerified(error_code(exc)) from exc
        if not claimed:
            logger.warning(
                "Sweep %s of contain %s not run, nothing written: another delivery claimed it and has left no event",
                number,
                request_id,
            )
            raise SweepNotFinished(f"sweep {number} of contain {request_id}")
        return None, held

    # --- the sweep -----------------------------------------------------------------

    def _client(self, cell: Cell, service: str) -> Any:
        """A client in the cell, through the cell's containment role, narrowed to what a sweep does.

        Raises now when the role cannot be assumed. After that the client is
        looked up again at every call (see ``_Current``).
        """
        narrowed = session_policy(cell)

        def lookup() -> Any:
            return self.clients.assumed(
                cell.containment_role_arn or "", cell.external_id, cell.region, service, session_policy=narrowed
            )

        lookup()
        return _Current(lookup)

    def _sweep(
        self,
        message: sweeps.SweepMessage,
        cell: Cell,
        cells: list[Cell],
        started: float,
        remaining_seconds: Callable[[], float],
        held: bool,
    ) -> str:
        """The sweep itself, for a message that ``_admit`` let through. It leaves exactly one event.

        ``held`` says whether a contain holds the Runtime according to its
        history. When none does, the Runtime was released after the contain
        that scheduled this sweep, and nothing is stopped.
        """
        arn, number = message.runtime_arn, message.sweep

        def record(outcome: str, reason: str, state: str, after: str | None = None, **counts: Any) -> str:
            event = self._event(
                runtime_arn=arn,
                agent_id=message.agent_id,
                request_id=message.request_id,
                cells=cells,
                outcome=outcome,
                reason=reason,
                sweep=number,
                status_before=state,
                status_after=after or state,
                duration_ms=int((self.clock() - started) * 1000),
                **counts,
            )
            self._write(arn, event)
            logger.info("Sweep %s of contain %s: %s. %s", number, message.request_id, outcome, reason)
            return outcome

        # 3. Check first: only a Runtime that the portal's statement contains right now is swept.
        try:
            control = self._client(cell, "bedrock-agentcore-control")
            found = containment_policy.state(containment.get_policy(control, arn), arn)
        except Exception as exc:  # noqa: BLE001 - recorded as a failed sweep
            logger.warning("Sweep %s: the resource policy could not be read: %s", number, error_code(exc))
            reason = (
                f"Background sweep {number} stopped nothing: the Runtime's resource policy could not be "
                f"read ({error_code(exc)}), so it is not known whether the Runtime is still contained."
            )
            return record(sweeps.FAILED, reason, UNKNOWN)
        if found != containment_policy.CONTAINED:
            reason = f"Background sweep {number} stopped nothing: the Runtime is no longer contained."
            if found == containment_policy.FOREIGN:
                reason = f"{reason} {containment_policy.FOREIGN_STATEMENT}"
            return record(sweeps.SKIPPED, reason, NOT_CONTAINED)
        if not held:
            # The history says released, the policy does not yet (a release that is under way), or
            # not any more (the statement was put back by other means). Either way this sweep's
            # contain no longer holds the Runtime.
            reason = (
                f"Background sweep {number} stopped nothing: the Runtime's history says that it was "
                "released after the contain that scheduled this sweep."
            )
            return record(sweeps.SKIPPED, reason, CONTAINED)

        # 4. Every session of the lookback window, for as long as there is time.
        def time_left() -> bool:
            return remaining_seconds() > RESERVE_SECONDS

        try:
            found = containment.discover_sessions(
                control,
                self._client(cell, "logs"),
                arn,
                use_spans=cell.containment_spans,
                limit=None,
                keep_going=time_left,
                spans_wait_seconds=max(1.0, min(SPANS_WAIT_SECONDS, remaining_seconds() - RESERVE_SECONDS)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sweep %s: sessions could not be listed: %s", number, error_code(exc))
            reason = f"Background sweep {number} stopped nothing: sessions could not be listed ({error_code(exc)})."
            return record(sweeps.FAILED, reason, CONTAINED, detail=f"sessions could not be listed ({error_code(exc)})")
        if found.failed:
            reason = f"Background sweep {number} stopped nothing: {found.note}."
            return record(sweeps.FAILED, reason, CONTAINED, detail=found.note)

        # 5. Stop them, most recent first, at a capped rate. A release ends the sweep.
        def still_contained() -> bool:
            try:
                return containment_policy.is_contained(containment.get_policy(control, arn), arn)
            except Exception as exc:  # noqa: BLE001 - it was contained when the sweep began, so the sweep goes on
                logger.warning("Sweep %s: the policy could not be read again: %s", number, error_code(exc))
                return True

        stopped = containment.SessionStop(found=len(found.sessions))
        released = False
        if found.sessions:
            try:
                data = self._client(cell, "bedrock-agentcore")
            except Exception as exc:  # noqa: BLE001
                reason = (
                    f"Background sweep {number} found {len(found.sessions)} session(s) and stopped none: "
                    f"the cell's containment role could not be used ({error_code(exc)})."
                )
                counts = {"sessions_found": len(found.sessions), "sessions_stopped": 0, "sessions_not_active": 0}
                return record(
                    sweeps.FAILED, reason, CONTAINED, sessions_failed=len(found.sessions), detail=found.note, **counts
                )
            stopped, released = self._stop(data, arn, found.sessions, time_left, still_contained)

        if released:
            reason = (
                f"Background sweep {number} ended early: the Runtime was released while the sweep ran. "
                f"{stopped.stopped} session(s) had been stopped, {stopped.not_active} had already ended "
                f"and {stopped.not_attempted} were left as they were."
            )
            return record(
                sweeps.SKIPPED,
                reason,
                CONTAINED,
                NOT_CONTAINED,
                sessions_found=stopped.found,
                sessions_stopped=stopped.stopped,
                sessions_not_active=stopped.not_active,
                sessions_failed=stopped.failed,
                detail=found.note,
            )
        complete = found.note == "ok" and not stopped.failed and not stopped.not_attempted
        return record(
            sweeps.ALLOWED if complete else sweeps.FAILED,
            _sentence(number, stopped, found.note),
            CONTAINED,
            sessions_found=stopped.found,
            sessions_stopped=stopped.stopped,
            sessions_not_active=stopped.not_active,
            sessions_failed=stopped.failed + stopped.not_attempted,
            detail=found.note,
        )

    def _stop(
        self,
        client: Any,
        runtime_arn: str,
        sessions: list[containment.Session],
        time_left: Callable[[], bool],
        still_contained: Callable[[], bool],
    ) -> tuple[containment.SessionStop, bool]:
        """Stop every session at no more than ``stops_per_second``, until done or out of time.

        A stop the service asks to retry is tried again a few times, with a
        longer pause after each such batch. A session that is unknown or has
        already ended needs no stop.

        Every ``RECHECK_SECONDS`` the policy is read again. If the agent was
        released meanwhile the sweep ends there, and the second value
        returned is true: a release must not be followed by minutes of stops.
        """
        outcome = containment.SessionStop(found=len(sessions))
        pending = deque(sessions)
        tries: dict[tuple[str, str], int] = {}
        pause = 0.0
        checked = self.clock()
        while pending:
            if not time_left():
                outcome.not_attempted = len(pending)
                break
            if self.clock() - checked >= RECHECK_SECONDS:
                checked = self.clock()
                if not still_contained():
                    outcome.not_attempted = len(pending)
                    return outcome, True
            slot_started = self.clock()
            batch = [pending.popleft() for _ in range(min(self.stops_per_second, len(pending)))]

            def stop(session: containment.Session) -> str:
                return containment.stop_session(client, runtime_arn, session)

            again = False
            for session, result in zip(batch, pmap(stop, batch, max_workers=8), strict=True):
                code = error_code(result) if isinstance(result, BaseException) else str(result)
                key = (session.session_id, session.qualifier)
                if code == "stopped":
                    outcome.stopped += 1
                elif code == "not_active":
                    outcome.not_active += 1
                elif code in RETRYABLE and tries.get(key, 0) < MAX_RETRIES_PER_SESSION:
                    tries[key] = tries.get(key, 0) + 1
                    pending.append(session)
                    again = True
                else:
                    outcome.failed += 1
                    if code not in outcome.failures:
                        outcome.failures.append(code)
            if not pending:
                break
            # One batch per second. After a batch the service pushed back on, wait longer each time.
            pause = min(pause * 2 or 1.0, MAX_PAUSE_SECONDS) if again else 0.0
            self.sleep(max(0.0, 1.0 - (self.clock() - slot_started)) + pause)
        return outcome, False

    # --- audit ---------------------------------------------------------------------

    def _event(
        self,
        *,
        runtime_arn: str,
        agent_id: str,
        request_id: str,
        cells: list[Cell],
        outcome: str,
        reason: str,
        **extra: Any,
    ) -> AuditEvent:
        """One sweep event. Its actor is the portal: a sweep is nobody's contain or release."""
        return AuditEvent(
            event_id=str(uuid.uuid4()),
            request_id=request_id,
            at=audit_writer.now_stamp(),
            phase="result",
            action="sweep",
            outcome=outcome,
            reason=reason[:1000],
            actor_subject=sweeps.ACTOR_SUBJECT,
            actor_label=sweeps.ACTOR_LABEL,
            actor_role=sweeps.ACTOR_ROLE,
            tenant_id=rules.tenant_for({c.tenant_id for c in cells}),
            agent_id=agent_id,
            runtime_arn=runtime_arn,
            **extra,
        )

    def _write(self, runtime_arn: str, event: AuditEvent) -> None:
        """Append the sweep's one event to the Runtime's containment history, under the Runtime's own key."""
        try:
            audit_writer.put_event(
                self.dynamodb, self.settings.audit_table, audit_reader.containment_key(runtime_arn), event
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Sweep event could not be written (%s): %s", event.outcome, error_code(exc))
            raise SweepNotRecorded(error_code(exc)) from exc


def _sentence(number: int, stopped: containment.SessionStop, discovery: str) -> str:
    """What one sweep found and did, in a sentence."""
    if stopped.found == 0:
        sentence = f"Background sweep {number} found no session of the lookback window."
    else:
        sentence = (
            f"Background sweep {number}: {stopped.found} session(s) found, {stopped.stopped} stopped, "
            f"{stopped.not_active} had already ended"
        )
        if stopped.failed:
            sentence += f", {stopped.failed} could not be stopped ({', '.join(stopped.failures)})"
        if stopped.not_attempted:
            sentence += f", {stopped.not_attempted} were not attempted before the function's time ran out"
        sentence += "."
    if discovery != "ok":
        sentence += f" Session discovery was incomplete: {discovery.removeprefix('ok; ')}."
    elif not stopped.failed and not stopped.not_attempted:
        sentence += " No session was left running." if stopped.stopped else " No session was running."
    return sentence


# --- the function's entry point ---------------------------------------------------------

_clients: AwsClients | None = None


def lambda_handler(event: Any, context: Any) -> dict[str, int]:
    """Entry point of the sweeper function: one sweep per queue message.

    A function whose ``PORTAL_ACTION_ROLE`` is not ``sweeper``, or whose
    configuration is malformed, raises before doing anything: the message goes
    back to the queue and ends in the dead-letter queue, where it is noticed.
    So does a message whose sweep keeps failing in one of the ways
    ``Sweeper.handle`` raises for.
    """
    from portal_api.config import load_sweeper_settings

    global _clients
    settings = load_sweeper_settings()
    if _clients is None:
        _clients = AwsClients(home_region=settings.registry_region, session_name=SESSION_SWEEPER)
    sweeper = Sweeper(settings, _clients, _clients.platform("dynamodb", settings.registry_region))

    def remaining_seconds() -> float:
        return context.get_remaining_time_in_millis() / 1000

    records = event.get("Records") if isinstance(event, dict) else None
    # Whoever can invoke the function chooses the event: anything that is not a record with a body is invalid.
    bodies = [r.get("body") if isinstance(r, dict) else None for r in (records if isinstance(records, list) else [])]
    outcomes = [sweeper.handle(body, remaining_seconds) for body in bodies]
    logger.info("Sweeps handled: %s", ", ".join(outcomes) or "none")
    return {"handled": len(outcomes)}
