# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Background sweeps of a contained Runtime: the queue message, and how sweeps read back. Pure.

A contain denies new invocations and stops the sessions it finds inside the
request. It then leaves messages on a queue, and a sweeper function reads each
one later and stops whatever sessions the Runtime still has. This module holds
what the containment function, the sweeper and the read API share. It makes no
AWS call.

- The message, and its validation. The sweeper treats every message as
  untrusted input: anyone who can write to the queue, or invoke the sweeper,
  chooses its content.
- Which contain a message belongs to, as the Runtime's history holds it:
  whether that contain can have scheduled a sweep, whether this sweep has
  already left its event, and when it is due. A message proves none of that.
- What the sweeps of a containment add up to when read back from the audit
  trail: how many were scheduled, how many have run, and since when the agent
  is known to be quiet.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from portal_api import arns
from portal_api.mappers.common import parse_instant

KIND = "containment_sweep"
VERSION = 1
SWEEP_NUMBERS = (1, 2, 3)
MAX_BODY_CHARACTERS = 2048

# Who a sweep is recorded as. A sweep is the portal's own act, not a person's.
ACTOR_SUBJECT = "agent-factory-portal"
ACTOR_LABEL = "Agent Factory Portal (background sweep)"
ACTOR_ROLE = "system"

ALLOWED, FAILED, SKIPPED = "allowed", "failed", "skipped"

# The same shape the containment function accepts for a Runtime. Whether it is the spelling the
# portal uses for that Runtime is the sweeper's to check, against its own configuration.
RUNTIME_ARN = arns.RUNTIME_ARN
# ASCII only, and applied with ``fullmatch``.
_RECORD_ID = re.compile(r"[A-Za-z0-9]{12}", re.ASCII)
_REQUEST_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.ASCII)
_KEYS = frozenset({"version", "kind", "sweep", "runtime_arn", "agent_id", "request_id"})


class InvalidMessage(ValueError):
    """The message is not a sweep request. Nothing in it is used: only ``reason`` goes to the log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SweepMessage:
    """One sweep to run. The Runtime ARN is the identity of what is swept; the agent id is informational."""

    sweep: int  # 1, 2 or 3
    runtime_arn: str
    agent_id: str  # the id the contain was addressed with: a registry record id or the Runtime id
    request_id: str  # the contain's request id, which the sweep's audit event carries

    @property
    def runtime_id(self) -> str:
        return self.runtime_arn.rsplit("/", 1)[-1]


def encode(message: SweepMessage) -> str:
    """The message body. Small, and it holds no secret and no role."""
    return json.dumps(
        {
            "version": VERSION,
            "kind": KIND,
            "sweep": message.sweep,
            "runtime_arn": message.runtime_arn,
            "agent_id": message.agent_id,
            "request_id": message.request_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def decode(body: Any) -> SweepMessage:
    """The sweep a message body asks for, or ``InvalidMessage``. Nothing in the body is trusted.

    Whether the Runtime's account and Region are a configured cell is not known
    here; the sweeper checks that against its own configuration.
    """
    if not isinstance(body, str) or len(body) > MAX_BODY_CHARACTERS:
        raise InvalidMessage("the body is not a short text")
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise InvalidMessage("the body is not JSON") from exc
    if not isinstance(data, dict):
        raise InvalidMessage("the body is not a JSON object")

    runtime_arn = data.get("runtime_arn")
    if not isinstance(runtime_arn, str) or not RUNTIME_ARN.fullmatch(runtime_arn):
        raise InvalidMessage("runtime_arn is not a Runtime ARN")
    if set(data) != _KEYS:
        raise InvalidMessage("the body does not hold exactly the expected fields")
    if data["version"] != VERSION or isinstance(data["version"], bool) or data["kind"] != KIND:
        raise InvalidMessage("the version or kind is not one this sweeper knows")
    sweep = data["sweep"]
    if isinstance(sweep, bool) or not isinstance(sweep, int) or sweep not in SWEEP_NUMBERS:
        raise InvalidMessage("sweep is not 1, 2 or 3")
    agent_id = data["agent_id"]
    runtime_id = runtime_arn.rsplit("/", 1)[-1]
    # An agent with no registration is addressed by its Runtime id, which must be this Runtime's.
    if not isinstance(agent_id, str) or not (_RECORD_ID.fullmatch(agent_id) or agent_id == runtime_id):
        raise InvalidMessage("agent_id is neither a registration id nor this Runtime's id")
    request_id = data["request_id"]
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise InvalidMessage("request_id is not a request id")
    return SweepMessage(sweep=sweep, runtime_arn=runtime_arn, agent_id=agent_id, request_id=request_id)


def sweeps_to_schedule(first_needed: bool) -> tuple[int, ...]:
    """The sweep numbers a contain schedules: the first only when the request left something undone."""
    return SWEEP_NUMBERS if first_needed else SWEEP_NUMBERS[1:]


# --- the contain a sweep belongs to, as the history holds it -----------------------------------


@dataclass(frozen=True)
class Scheduler:
    """The contain a sweep message names, found in the Runtime's containment history."""

    position: int  # where its newest event is among the events that were given (newest first)
    began: dt.datetime  # the time of its oldest event among them: its intent, when that was read


def scheduler(events: Sequence[Any], request_id: str) -> Scheduler | None:
    """The contain with this request id, when the history says that it can have scheduled a sweep.

    ``events`` are the Runtime's containment events, newest first. A message
    names the contain that scheduled it by that contain's request id, and
    anyone who can invoke the sweeper can write any id there. So the id
    counts only when the history holds a contain under it that got as far as
    scheduling:

    - its result says ``allowed`` or ``unchanged`` and counts the sweeps it
      scheduled. A contain that failed, one that scheduled nothing (no
      queue), and one that was answered at once because it came too soon
      scheduled none; or
    - it has no result yet and its intent was allowed. The first sweep can
      arrive before the contain has written its result, and a result can be
      lost; the intent is written before anything is done.

    ``None`` means that no sweep belongs to that id: nothing is run and
    nothing is written for it.
    """
    own = [(index, event) for index, event in enumerate(events) if _is_contain(event, request_id)]
    result = next((event for _, event in own if event.phase == "result"), None)
    if result is not None:
        if result.outcome not in (ALLOWED, "unchanged") or not result.sweeps_scheduled:
            return None
    elif not any(event.phase == "intent" and event.outcome == ALLOWED for _, event in own):
        return None
    times = [at for _, event in own if (at := parse_instant(event.at)) is not None]
    if not times:
        return None
    return Scheduler(position=own[0][0], began=min(times))


def _is_contain(event: Any, request_id: str) -> bool:
    return event.action == "contain" and event.request_id == request_id


def intent_read(events: Iterable[Any], request_id: str) -> bool:
    """Whether the intent of the contain with this request id is among these events.

    Everything else that carries that id (the contain's result, its sweeps)
    is newer than the intent, so a history read back as far as the intent
    holds all of it.
    """
    return any(_is_contain(event, request_id) and event.phase == "intent" for event in events)


def recorded(events: Iterable[Any], request_id: str, number: int) -> bool:
    """Whether sweep ``number`` of the contain with this request id has left its event, whatever its outcome."""
    return any(event.action == "sweep" and event.request_id == request_id and event.sweep == number for event in events)


def seconds_until_due(began: dt.datetime, number: int, now: dt.datetime, delays: Sequence[int]) -> float:
    """How long from ``now`` until sweep ``number`` of a contain that began at ``began`` is due.

    Zero or less means that it is due. A contain sends its messages last,
    after the events that ``began`` is taken from, and the queue holds each
    one back for its delay: so a message from the queue never arrives before
    this moment. One that does was not sent by the contain.
    """
    return (began + dt.timedelta(seconds=delays[number - 1]) - now).total_seconds()


# --- a contain repeated while the last one is still at work ---------------------------------


@dataclass(frozen=True)
class Repeat:
    """Why a contain of an already contained agent would add nothing now."""

    # When to ask again. Without a pending sweep that is when a contain does its work again. With
    # one it is the earliest that can be: the contain also waits for that sweep to report.
    wait_seconds: int
    sweeps_pending: bool  # background sweeps of this containment have not all reported yet
    since: str = ""  # the time of the last contain that did its work, as its event carries it


def repeat_too_soon(
    events: Iterable[Any],
    now: dt.datetime,
    *,
    repeat_after_seconds: int,
    sweeps_over_after_seconds: int,
    recheck_seconds: int,
) -> Repeat | None:
    """Whether a contain repeated now comes too soon after the last one, whose sweeps are still at work.

    ``events`` are the Runtime's events of the containment that holds (the
    one that began it and everything since), in any order. A contain did its
    work when its result is ``allowed`` or ``unchanged`` and carries session
    counts: it stopped the sessions it found and scheduled its sweeps. A
    contain that was answered at once because it came too soon leaves a
    result too, with no session counts; it is not one that did its work, or
    every repeat would start the pause anew.

    The repeat is too soon when the last such contain scheduled sweeps and
    is less than ``repeat_after_seconds`` old, or when a sweep of this
    containment has not left its event yet and can still be running (less
    than ``sweeps_over_after_seconds`` since the contain that scheduled it,
    not since the last one: a sweep that was lost long ago holds nothing
    back). Whatever the request left undone, those sweeps do.

    ``None`` means: do the work. That is always the answer when the last
    contain scheduled no sweep (no queue is configured, or the sweeps could
    not be scheduled): containing again is then the only way to go on.
    """
    events = list(events)
    worked = [
        (at, event)
        for event in events
        if event.action == "contain" and event.phase == "result" and event.outcome in (ALLOWED, "unchanged")
        if event.sessions_found is not None and (at := parse_instant(event.at)) is not None
    ]
    if not worked:
        return None
    last_at, last = max(worked, key=lambda pair: pair[0])
    if not last.sweeps_scheduled:
        return None
    age = (now - last_at).total_seconds()
    done = {(e.request_id, e.sweep) for e in events if e.action == "sweep" and e.sweep}
    # For each contain with a sweep that has not reported: how much longer that sweep can be running.
    unreported = [
        sweeps_over_after_seconds - (now - at).total_seconds()
        for at, event in worked
        if event.sweeps_scheduled
        and len({sweep for request_id, sweep in done if request_id == event.request_id}) < int(event.sweeps_scheduled)
    ]
    given_up_in = max((left for left in unreported if left > 0), default=0.0)
    pending = given_up_in > 0
    if age < repeat_after_seconds:
        return Repeat(math.ceil(repeat_after_seconds - age), pending, last.at)
    if pending:
        # The pause is over and a sweep is due or running. It usually reports within seconds, so
        # the answer is to ask again soon, and never later than the moment that sweep is given up.
        return Repeat(math.ceil(min(recheck_seconds, given_up_in)), True, last.at)
    return None


# --- reading the sweeps of a containment back from its events -----------------------------


@dataclass(frozen=True)
class SweepSummary:
    scheduled: int = 0  # sweeps the containment that holds has scheduled
    done: int = 0  # of those, how many have left their event (whatever its outcome)
    # When the agent was first known to be quiet: the end of the first sweep that started after
    # every host applies the deny, read every session source completely, and left nothing running.
    quiet_at: str | None = None


def summary(events: Iterable[Any], contained_at: str | None, contain_delay_seconds: int) -> SweepSummary:
    """What the audit events say about the sweeps of the containment that began at ``contained_at``.

    ``events`` are the Runtime's containment events, in any order.

    ``scheduled`` and ``done`` count the sweeps of the contains of this
    containment (the one that holds it, and any repeated since). A sweep is
    matched to its contain by request id, so one that an earlier containment
    scheduled is not counted, and it counts once. The sweeper leaves one
    event for a sweep and runs none of an earlier containment; a history
    written before it did can hold both, and is read the same way.

    ``quiet_at`` takes every sweep that ran since the containment began,
    whoever scheduled it: what a sweep found is true whichever contain asked
    for it. A sweep is proof of quiet only when its outcome is ``allowed`` (it
    listed every session and nothing was left unstopped) and it started at
    least ``contain_delay_seconds`` after the containment began: before that,
    a host that has not applied the deny yet can still start a session.
    """
    began = parse_instant(contained_at)
    if began is None:
        return SweepSummary()
    events = list(events)
    scheduled = 0
    contains: set[str] = set()  # request ids of the contains that scheduled sweeps
    for event in events:
        if event.action != "contain" or event.phase != "result" or not event.sweeps_scheduled:
            continue
        at = parse_instant(event.at)
        if at is not None and at >= began:
            scheduled += int(event.sweeps_scheduled)
            contains.add(event.request_id)
    swept = [event for event in events if event.action == "sweep"]
    done = len({(event.request_id, event.sweep) for event in swept if event.sweep and event.request_id in contains})
    earliest = began + dt.timedelta(seconds=contain_delay_seconds)
    proofs = []
    for event in swept:
        at = parse_instant(event.at)
        if at is None or event.outcome != ALLOWED:
            continue
        if at - dt.timedelta(milliseconds=int(event.duration_ms or 0)) >= earliest:
            proofs.append((at, event.at))
    return SweepSummary(
        scheduled=scheduled,
        done=min(done, scheduled),
        quiet_at=min(proofs)[1] if proofs else None,
    )
