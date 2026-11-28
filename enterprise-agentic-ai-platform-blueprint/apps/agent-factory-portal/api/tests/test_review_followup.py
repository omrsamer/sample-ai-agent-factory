# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The two items that followed the security review of wave 2: the attack or the fault, and what must still work.

S16 The page of one agent reflects a decision about that agent that was taken a moment ago.
S17 The sweeper writes an event only for a sweep that belongs to a contain on record, and once.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from portal_api import containment_timing, sweeps
from portal_api import service as service_module
from portal_api.actions import audit_writer, containment, sweeper
from portal_api.aws import audit as audit_reader
from portal_api.aws import registry
from portal_api.models.portal import AuditEvent
from tests import test_api, test_containment, test_sweeps
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    ORPHAN_RUNTIME_ARN,
    RUNTIME_ARN,
    agent_record,
    make_service,
    tool_record,
)
from tests.fakes import FakeDynamo, client_error
from tests.test_api import PLATFORM_CLAIMS, VIEWER_CLAIMS, raw
from tests.test_containment import PAT, SEC, SRE, log_group, session_stream, sid
from tests.test_evidence import NOTHING_CHANGED, decided, evidence, registry_holds, stale_notes
from tests.test_sweeps import (
    KEY,
    REQUEST_ID,
    Context,
    Run,
    SweepWorld,
    again,
    contained,
    message,
    on_record,
    stamp,
)

backend = test_api.backend  # the read API's fake backend
read = test_containment.read  # the read API over the same cell, record and audit table as the action functions
entry = test_sweeps.entry  # the sweeper function's handler

TABLE = BASE_ENV["PORTAL_AUDIT_TABLE"]
FORGED = "f0f0f0f0-4e5f-4a6b-8c7d-9e0f1a2b3c4d"  # a request id that is well formed and nobody's


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SweepWorld:
    return SweepWorld(monkeypatch)


def body_of(sweep: int = 2, request_id: str = REQUEST_ID) -> str:
    return sweeps.encode(message(sweep=sweep, request_id=request_id))


def put(world: SweepWorld, event: AuditEvent, key: str = KEY) -> None:
    """Put one event straight into the table, as it would be stored."""
    item = {"pk": {"S": key}, "sk": {"S": f"EVENT#{event.at}#{event.event_id}"}}
    item.update({name: {"S": str(value)} for name, value in event.model_dump().items() if value not in (None, "")})
    world.dynamo.items[(key, item["sk"]["S"])] = item


def minutes_ago(minutes: float) -> str:
    return test_sweeps.at(test_sweeps.time_of_day() - dt.timedelta(minutes=minutes))


def sweep_event(request_id: str, number: int, minutes: float = 1.0) -> AuditEvent:
    return AuditEvent(
        event_id=f"sweep-{request_id}-{number}",
        request_id=request_id,
        at=minutes_ago(minutes),
        phase="result",
        action="sweep",
        outcome="allowed",
        reason="x",
        actor_subject=sweeps.ACTOR_SUBJECT,
        actor_label=sweeps.ACTOR_LABEL,
        actor_role=sweeps.ACTOR_ROLE,
        sweep=number,
    )


# === S17: a sweep that belongs to a contain on record, once ============================================
#
# A history is never shortened, and a release reads it back to the contain it undoes: 2,000 events
# since that contain and the release is refused. So nobody who has no part in the Runtime may be
# able to lengthen it. The sweeper was the one writer left that a message could drive.


# --- the rule (pure) ----------------------------------------------------------------------------


def contain_event(phase: str, outcome: str = "allowed", request_id: str = "c-1", at: float = 0.0, **extra: Any):
    values = {
        "event_id": f"{phase}-{request_id}-{at}",
        "request_id": request_id,
        "at": stamp(at),
        "phase": phase,
        "action": "contain",
        "outcome": outcome,
        "reason": "x",
        "actor_subject": "sec-1",
        "actor_label": "l",
        "actor_role": "security",
    }
    return AuditEvent(**{**values, **extra})


def test_which_contain_can_have_scheduled_a_sweep():
    intent = contain_event("intent")
    result = contain_event("result", at=4.0, sweeps_scheduled=2, sessions_found=0)
    # Newest first, as a history is read. The contain began with its intent.
    found = sweeps.scheduler([result, intent], "c-1")
    assert found == sweeps.Scheduler(position=0, began=dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC))
    # Below newer events it is found where it is.
    newer = contain_event("result", "denied", request_id="c-2", at=9.0)
    assert sweeps.scheduler([newer, result, intent], "c-1").position == 1
    # A repeated contain that did its work schedules sweeps of its own.
    assert sweeps.scheduler([contain_event("result", "unchanged", sweeps_scheduled=3), intent], "c-1") is not None
    # No result yet, or a result that was lost: the intent is enough. The first sweep can arrive
    # before the contain has written its result.
    assert sweeps.scheduler([intent], "c-1") == sweeps.Scheduler(0, found.began)
    # The result alone (its intent lies further back than was read): it began no later than that.
    assert sweeps.scheduler([result], "c-1").began == found.began + dt.timedelta(seconds=4)


@pytest.mark.parametrize(
    "events",
    [
        [],
        [contain_event("result", "failed", at=4.0), contain_event("intent")],  # it failed before it scheduled
        [contain_event("result", "failed", at=4.0, sweeps_scheduled=3), contain_event("intent")],
        [contain_event("result", "allowed", at=4.0, sessions_found=0), contain_event("intent")],  # no queue
        [contain_event("result", "allowed", at=4.0, sweeps_scheduled=0), contain_event("intent")],
        [contain_event("result", "unchanged", at=4.0)],  # answered at once: it came too soon
        [contain_event("result", "denied", at=4.0)],  # refused
        [contain_event("intent", "denied")],
        [
            contain_event("result", "allowed", request_id="c-2", sweeps_scheduled=3),
            contain_event("intent", request_id="c-2"),
        ],
        [contain_event("result", sweeps_scheduled=3, action="release"), contain_event("intent", action="release")],
        [contain_event("result", sweeps_scheduled=3, action="sweep", sweep=2)],  # a sweep carries its contain's id
        [contain_event("result", sweeps_scheduled=3, at=4.0).model_copy(update={"at": "not a time"})],
    ],
    ids=[
        "nothing",
        "a contain that failed",
        "a contain that failed, whatever it counts",
        "a contain that scheduled nothing",
        "a contain that scheduled none",
        "a contain that was answered at once",
        "a refused contain",
        "a refused intent",
        "another contain",
        "a release",
        "a sweep",
        "an unreadable time",
    ],
)
def test_what_is_not_a_contain_that_scheduled_sweeps(events):
    assert sweeps.scheduler(events, "c-1") is None


def test_whether_a_sweep_has_left_its_event_and_when_it_is_due():
    events = [sweep_event("c-1", 2), contain_event("result", sweeps_scheduled=2), contain_event("intent")]
    assert sweeps.recorded(events, "c-1", 2) is True
    assert sweeps.recorded(events, "c-1", 3) is False and sweeps.recorded(events, "c-2", 2) is False
    # A contain's own result is not a sweep, whatever number it carries.
    assert sweeps.recorded([contain_event("result", sweep=2)], "c-1", 2) is False
    assert sweeps.intent_read(events, "c-1") is True and sweeps.intent_read(events[:2], "c-1") is False
    assert sweeps.intent_read(events, "c-2") is False

    began = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
    delays = containment_timing.SWEEP_DELAYS_SECONDS

    def wait(number: int, seconds_later: float) -> float:
        return sweeps.seconds_until_due(began, number, began + dt.timedelta(seconds=seconds_later), delays)

    assert (wait(1, 0), wait(2, 0), wait(3, 0)) == (0, 120, 900)
    assert (wait(2, 100), wait(2, 120), wait(2, 500)) == (20, 0, -380)
    # The allowance leaves the second sweep later than the time every host needs to apply the deny.
    assert containment_timing.SWEEP_EARLY_TOLERANCE_SECONDS == 30
    assert (
        containment_timing.SECOND_SWEEP_DELAY_SECONDS - containment_timing.SWEEP_EARLY_TOLERANCE_SECONDS
        >= containment_timing.CONTAIN_DELAY_SECONDS
    )


# --- a message that names no contain on record ------------------------------------------------------


def a_sweep_under_that_id(world: SweepWorld) -> None:
    put(world, sweep_event(FORGED, 1))


NO_SUCH_CONTAIN = {
    "nothing under that id": lambda world: None,
    "a contain that failed": lambda world: on_record(world, FORGED, outcome="failed", scheduled=None),
    "a contain that scheduled no sweep": lambda world: on_record(world, FORGED, scheduled=None),
    "a contain that was refused": lambda world: on_record(
        world, FORGED, outcome="denied", scheduled=None, intent=False
    ),
    "a contain that was answered at once": lambda world: on_record(
        world, FORGED, outcome="unchanged", scheduled=None, intent=False
    ),
    "a release": lambda world: on_record(world, FORGED, action="release"),
    "a sweep that carries the id": a_sweep_under_that_id,
    "a contain of another Runtime": lambda world: on_record(world, FORGED, arn=ORPHAN_RUNTIME_ARN),
}


@pytest.mark.parametrize("on_file", NO_SUCH_CONTAIN.values(), ids=NO_SUCH_CONTAIN.keys())
def test_a_message_whose_request_id_no_contain_scheduled_sweeps_under_is_not_run_and_writes_nothing(
    world, on_file, caplog
):
    """The attack: invoke the sweeper with well formed messages. Each one used to run a sweep and leave an event."""
    contained(world)  # a real containment, with its statement in the policy
    on_file(world)
    world.cell.streams[log_group()] = [session_stream("running")]
    before = dict(world.dynamo.items)
    run = Run(world)
    with caplog.at_level("WARNING", logger="portal_api.actions.sweeper"):
        for number in (1, 2, 3):
            for _ in range(10):
                assert run.handle(body_of(number, FORGED)) == "no_contain"
    # Nothing was done in the cell: no role assumed, no policy read, no session stopped.
    assert world.cell.calls == [] and world.cell.assumed == [] and world.cell.stopped == []
    # Nothing was written: no event, no claim. The table was only read, under the Runtime's own key.
    assert world.dynamo.items == before and set(world.dynamo.calls) == {"query"}
    assert set(world.dynamo.queried) == {KEY}
    # The function's log has it.
    assert len(caplog.messages) == 30
    assert caplog.messages[0] == (
        f"Sweep 1 of contain {FORGED} not run, nothing written (no_contain): "
        "the Runtime's history holds no contain with that id that scheduled sweeps"
    )


def test_a_contain_that_has_only_its_intent_on_record_still_has_its_sweeps(world):
    """The first sweep can arrive before the contain has written its result, and a result can be lost."""
    contained(world, result=False)
    world.cell.streams[log_group()] = [session_stream("a")]
    run = Run(world)
    assert run.handle(body_of(1)) == "allowed"
    assert world.cell.stopped == [(sid("a"), "DEFAULT")] and len(run.sweep_events()) == 1


# --- once -------------------------------------------------------------------------------------------


def test_a_sweep_is_run_once_however_often_its_message_arrives(world, caplog):
    """A redelivery, a replay, or the same payload sent to the function by hand."""
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    world.cell.stop_errors[sid("b")] = "ThrottlingException"  # the request leaves one, so sweep 1 is scheduled too
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.stop_errors.clear()
    bodies = [sent["MessageBody"] for sent in world.queue.messages]
    assert [json.loads(b)["sweep"] for b in bodies] == [1, 2, 3]
    run = Run(world)
    assert [run.handle(b) for b in bodies] == ["allowed"] * 3

    stored, stopped = dict(world.dynamo.items), list(world.cell.stopped)
    world.cell.calls.clear()
    world.cell.streams[log_group()].append(session_stream("started-later", 1))
    with caplog.at_level("WARNING", logger="portal_api.actions.sweeper"):
        for _ in range(20):
            assert [run.handle(b) for b in bodies] == ["repeated"] * 3
    # Not run again: nothing read or stopped in the cell. And nothing written, not even a claim.
    assert world.cell.calls == [] and world.cell.stopped == stopped
    assert world.dynamo.items == stored
    assert [e["sweep"] for e in run.sweep_events()] == ["1", "2", "3"] and len(world.dynamo.claims()) == 3
    assert (
        caplog.messages.count(
            f"Sweep 2 of contain {json.loads(bodies[0])['request_id']} not run, nothing written (repeated): "
            "this sweep has already left its event"
        )
        == 20
    )


def test_whatever_is_sent_the_sweeps_of_one_contain_leave_at_most_three_events(world):
    """Send and replay everything a sender can think of: the history grows by three events and stops."""
    world.cell.streams[log_group()] = [session_stream("a")]
    code, response = world.post("contain", claims=SEC)
    assert code == 200 and response["sweeps_scheduled_in_seconds"] == [120, 900]  # the contain scheduled two
    request_id = response["request_id"]
    events_before = len(world.dynamo.events())
    run = Run(world)
    outcomes: set[str] = set()
    for _ in range(25):
        for number in (3, 1, 2):
            outcomes.add(run.handle(body_of(number, request_id)))
        outcomes.add(run.handle(body_of(2, FORGED)))
        outcomes.add(run.handle(test_sweeps.body(sweep=4, request_id=request_id)))
        outcomes.add(run.handle(test_sweeps.body(sweep=0, request_id=request_id)))
        outcomes.add(run.handle(sweeps.encode(message(request_id=str(uuid.uuid4())))))
    assert outcomes == {"allowed", "repeated", "no_contain", "invalid"}
    # Three, although the contain scheduled two: a first sweep that nobody scheduled is run once too.
    assert len(world.dynamo.events()) == events_before + 3
    assert sorted(e["sweep"] for e in run.sweep_events()) == ["1", "2", "3"]
    assert {e["request_id"] for e in run.sweep_events()} == {request_id}
    # The release is not held up: the person who did not contain it releases it.
    assert world.post("release", claims=PAT)[0] == 200


def test_a_second_delivery_while_the_first_is_at_work_runs_nothing_and_comes_back(world, monkeypatch):
    """Two invocations with one message at the same moment: both read the history before either has an event."""
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    first, second = Run(world), Run(world)
    real, interrupted = containment.get_policy, []

    def get_policy(client: Any, arn: str) -> Any:
        if not interrupted:
            interrupted.append(True)
            # The first delivery has claimed the sweep and is about to read the policy. The second arrives.
            with pytest.raises(sweeper.SweepNotFinished, match=f"sweep 2 of contain {REQUEST_ID}"):
                second.handle(body_of())
        return real(client, arn)

    monkeypatch.setattr(containment, "get_policy", get_policy)
    assert first.handle(body_of()) == "allowed"
    assert interrupted == [True]
    # One sweep ran, and there is one event and one claim.
    assert world.cell.calls.count("get_resource_policy") == 1 and world.cell.stopped == [(sid("a"), "DEFAULT")]
    assert len(first.sweep_events()) == 1 and len(world.dynamo.claims()) == 1
    # The message of the second comes back. By then the first has left its event, and it is done with.
    assert second.handle(body_of()) == "repeated"
    assert len(first.sweep_events()) == 1


def test_a_sweep_that_was_claimed_and_never_finished_is_not_run_again_and_keeps_failing(world, entry):
    """Its first run was cut short. The redelivery fails, so the message ends in the dead-letter queue."""
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    assert audit_writer.claim_sweep(world.dynamo, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is True  # the run that died
    before = dict(world.dynamo.items)
    for _ in range(3):
        # Through the function's own entry point: the error reaches the queue, which delivers again.
        with pytest.raises(sweeper.SweepNotFinished):
            entry({"Records": [{"body": body_of()}]}, Context())
    assert world.cell.calls == [] and world.cell.stopped == [] and world.dynamo.items == before
    # Another sweep of the same contain is not held up by it.
    assert Run(world).handle(body_of(3)) == "allowed"


def test_the_claim_is_one_conditional_write_in_the_runtimes_own_partition():
    table = FakeDynamo()
    assert audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is True
    assert audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is False
    # Another sweep, another contain and another Runtime are other claims.
    assert audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, REQUEST_ID, 3) is True
    assert audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, FORGED, 2) is True
    assert audit_writer.claim_sweep(table, TABLE, ORPHAN_RUNTIME_ARN, REQUEST_ID, 2) is True
    assert sorted(table.items) == [
        (f"CONTAINMENT#{ORPHAN_RUNTIME_ARN}", f"SWEEP#{REQUEST_ID}#2"),
        (KEY, f"SWEEP#{REQUEST_ID}#2"),
        (KEY, f"SWEEP#{REQUEST_ID}#3"),
        (KEY, f"SWEEP#{FORGED}#2"),
    ]
    assert audit_reader.sweep_claim_sort_key(REQUEST_ID, 2) == f"SWEEP#{REQUEST_ID}#2"
    # Each attempt writes an id of its own, which is how a refused attempt knows the claim is not its own.
    ids = {item["claim_id"]["S"] for item in table.items.values()}
    assert len(ids) == 4 and audit_reader.sweep_claim_id(table, TABLE, RUNTIME_ARN, REQUEST_ID, 2) in ids
    assert audit_reader.sweep_claim_id(table, TABLE, RUNTIME_ARN, REQUEST_ID, 1) is None
    # Any other failure of the write is raised: whether the sweep may run is then not known.
    table.fail_put_numbers = {table._puts + 1}
    with pytest.raises(ClientError):
        audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, REQUEST_ID, 1)
    assert (KEY, f"SWEEP#{REQUEST_ID}#1") not in table.items


class LostAnswer(FakeDynamo):
    """A table that applies the first claim it is sent and loses the answer.

    The SDK then sends the same write again, and the condition refuses that
    second try: the caller sees a refusal for a write that went through.
    """

    def __init__(self) -> None:
        super().__init__()
        self.lost = 0

    def put_item(self, TableName: str, Item: dict, ConditionExpression: str) -> dict[str, Any]:  # noqa: N803
        if Item["sk"]["S"].startswith("SWEEP#") and not self.lost:
            self.lost += 1
            super().put_item(TableName=TableName, Item=Item, ConditionExpression=ConditionExpression)
            raise client_error("ConditionalCheckFailedException", "PutItem")
        return super().put_item(TableName=TableName, Item=Item, ConditionExpression=ConditionExpression)


def test_a_claim_whose_answer_was_lost_is_still_this_attempts_claim(world):
    """Otherwise the sweep would count as claimed by another delivery, and would never be run."""
    table = LostAnswer()
    assert audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is True
    assert table.lost == 1 and table.queried == [KEY] and table.pages_read == 1
    # The next attempt finds a claim that is not its own.
    assert audit_writer.claim_sweep(table, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is False

    # Through the sweeper: the sweep is run, once.
    world.dynamo = LostAnswer()
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    run = Run(world)
    assert run.handle(body_of()) == "allowed"
    assert world.dynamo.lost == 1 and world.cell.stopped == [(sid("a"), "DEFAULT")]
    assert len(run.sweep_events()) == 1 and len(world.dynamo.claims()) == 1
    assert run.handle(body_of()) == "repeated"


def test_a_refused_claim_that_cannot_be_looked_at_stops_the_sweep(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    assert audit_writer.claim_sweep(world.dynamo, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is True  # someone else's
    run = Run(world)
    real = audit_reader.sweep_claim_id

    def unreadable(*args: Any, **kwargs: Any) -> Any:
        raise client_error("InternalServerError", "Query")

    world.monkeypatch.setattr(audit_reader, "sweep_claim_id", unreadable)
    with pytest.raises(sweeper.SweepNotVerified):
        run.handle(body_of())
    assert world.cell.calls == [] and run.sweep_events() == []
    world.monkeypatch.setattr(audit_reader, "sweep_claim_id", real)
    with pytest.raises(sweeper.SweepNotFinished):
        run.handle(body_of())


def test_the_claim_as_the_service_receives_it():
    """The request against the service's own model: one put, with the condition that the item is not there."""
    client = boto3.client("dynamodb", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test")
    with Stubber(client) as stub:
        stub.add_response("put_item", {})
        assert audit_writer.claim_sweep(client, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is True
        stub.add_client_error("put_item", "ConditionalCheckFailedException", "The conditional request failed", 400)
        # Refused: one look at the item that is there, by its whole key, with a consistent read.
        stub.add_response(
            "query",
            {"Items": [{"pk": {"S": KEY}, "sk": {"S": f"SWEEP#{REQUEST_ID}#2"}, "claim_id": {"S": "someone-else"}}]},
            {
                "TableName": TABLE,
                "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
                "ExpressionAttributeValues": {":pk": {"S": KEY}, ":prefix": {"S": f"SWEEP#{REQUEST_ID}#2"}},
                "ConsistentRead": True,
                "ScanIndexForward": False,
                "Limit": 1,
            },
        )
        assert audit_writer.claim_sweep(client, TABLE, RUNTIME_ARN, REQUEST_ID, 2) is False
        stub.add_client_error("put_item", "ProvisionedThroughputExceededException", "x", 400)
        with pytest.raises(ClientError):
            audit_writer.claim_sweep(client, TABLE, RUNTIME_ARN, REQUEST_ID, 2)
        stub.assert_no_pending_responses()
    captured: list[dict[str, Any]] = []
    with Stubber(client) as stub:
        stub.add_response("put_item", {})
        client.meta.events.register(
            "provide-client-params.dynamodb.PutItem", lambda params, **_: captured.append(params)
        )
        audit_writer.claim_sweep(client, TABLE, RUNTIME_ARN, REQUEST_ID, 2)
    (sent,) = captured
    assert sent["TableName"] == TABLE and sent["ConditionExpression"] == "attribute_not_exists(pk)"
    assert (sent["Item"]["pk"], sent["Item"]["sk"]) == ({"S": KEY}, {"S": f"SWEEP#{REQUEST_ID}#2"})
    assert set(sent) == {"TableName", "Item", "ConditionExpression"}
    assert set(sent["Item"]) == {"pk", "sk", "kind", "claim_id", "at", "request_id", "sweep", "runtime_arn"}


def test_a_claim_is_in_no_history_and_changes_no_decision(world, read):
    """It lies in the Runtime's partition, and nothing that reads a history returns it."""
    world.cell.streams[log_group()] = [session_stream("a")]
    assert world.post("contain", claims=SEC)[0] == 200
    run = Run(world)
    for sent in world.queue.messages:
        assert run.handle(sent["MessageBody"]) == "allowed"
    assert len(world.dynamo.claims()) == 2
    assert {claim["pk"] for claim in world.dynamo.claims()} == {KEY}
    # A read of the history: four events (intent, result, two sweeps), and no claim.
    trail = audit_reader.read_back(world.dynamo, TABLE, KEY)
    assert [(e.action, e.phase) for e in trail.events] == [
        ("sweep", "result"),
        ("sweep", "result"),
        ("contain", "result"),
        ("contain", "intent"),
    ]
    assert trail.ended is True and len(trail.items) == 4
    # The view lists the same four and counts the sweeps.
    view = read(world.record_id, SRE)[1]
    assert [e["action"] for e in view["events"]] == ["sweep", "sweep", "contain", "contain"]
    assert view["sweeps"] == {"scheduled": 2, "done": 2} and view["contained_by"] == "sec-1"
    # The two-person rule reads the same history.
    code, refused = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in refused["detail"]
    assert world.post("release", claims=PAT)[0] == 200


# --- a sweep of a Runtime that was released, or contained again ---------------------------------------


def test_a_sweep_of_a_released_runtime_records_skipped_once(world):
    world.cell.streams[log_group()] = [session_stream("a")]
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.streams[log_group()].append(session_stream("started-after-the-release"))
    assert world.post("release", claims=PAT)[0] == 200
    stopped = list(world.cell.stopped)
    bodies = [sent["MessageBody"] for sent in world.queue.messages]
    run = Run(world)
    assert [run.handle(b) for b in bodies] == ["skipped", "skipped"]
    stored = dict(world.dynamo.items)
    for _ in range(10):
        assert [run.handle(b) for b in bodies] == ["repeated", "repeated"]
    assert world.dynamo.items == stored and world.cell.stopped == stopped
    assert [(e["sweep"], e["outcome"]) for e in run.sweep_events()] == [("2", "skipped"), ("3", "skipped")]
    assert run.sweep_events()[0]["reason"] == "Background sweep 2 stopped nothing: the Runtime is no longer contained."


def test_a_sweep_of_an_earlier_containment_is_not_run_once_the_runtime_is_contained_again(world, caplog):
    """Released and contained again: the sweeps of the contain that holds do the work, and only they are recorded."""
    world.cell.streams[log_group()] = [session_stream("a")]
    earlier = world.post("contain", claims=SEC)[1]["request_id"]
    assert world.post("release", claims=PAT)[0] == 200
    current = world.post("contain", claims=PAT)[1]["request_id"]
    of_earlier = [
        m["MessageBody"] for m in world.queue.messages if json.loads(m["MessageBody"])["request_id"] == earlier
    ]
    of_current = [
        m["MessageBody"] for m in world.queue.messages if json.loads(m["MessageBody"])["request_id"] == current
    ]
    assert len(of_earlier) == len(of_current) == 2
    stored, stopped = dict(world.dynamo.items), list(world.cell.stopped)
    world.cell.calls.clear()
    world.cell.streams[log_group()].append(session_stream("started-later", 1))
    run = Run(world)
    with caplog.at_level("WARNING", logger="portal_api.actions.sweeper"):
        assert [run.handle(b) for b in of_earlier] == ["superseded", "superseded"]
    assert world.cell.calls == [] and world.cell.stopped == stopped and world.dynamo.items == stored
    assert "its contain belongs to an earlier containment of the Runtime" in caplog.text
    # The sweeps of the contain that holds run, and stop the session that started since.
    assert [run.handle(b) for b in of_current] == ["allowed", "allowed"]
    assert (sid("started-later"), "DEFAULT") in world.cell.stopped
    assert {e["request_id"] for e in run.sweep_events()} == {current}


def test_a_repeated_contain_of_the_containment_that_holds_has_its_sweeps_run(world):
    contained(world)
    repeat = again(world)  # an ``unchanged`` contain, by someone else, with sweeps of its own
    world.cell.streams[log_group()] = [session_stream("a")]
    run = Run(world)
    assert run.handle(body_of(2, repeat)) == "allowed" and run.handle(body_of(2)) == "allowed"
    assert [e["request_id"] for e in run.sweep_events()] == [repeat, REQUEST_ID]


def test_when_the_history_says_released_and_the_statement_is_still_there_nothing_is_stopped(world):
    """A release that is under way: its intent is written, the statement is not removed yet."""
    contained(world)
    on_record(
        world, "0e1ea5ed-4e5f-4a6b-8c7d-9e0f1a2b3c4d", action="release", minutes_ago=1, result=False, subject="pat-1"
    )
    world.cell.streams[log_group()] = [session_stream("a")]
    run = Run(world)
    assert run.handle(body_of()) == "skipped"
    assert world.cell.stopped == [] and "describe_log_streams" not in world.cell.calls
    (event,) = run.sweep_events()
    assert (event["outcome"], event["status_before"], event["status_after"]) == ("skipped", "contained", "contained")
    assert event["reason"] == (
        "Background sweep 2 stopped nothing: the Runtime's history says that it was released after the "
        "contain that scheduled this sweep."
    )
    assert run.handle(body_of()) == "repeated"  # once


# --- not before it is due ----------------------------------------------------------------------------


def test_a_sweep_is_not_run_before_it_is_due_and_running_it_early_uses_nothing_up(world, monkeypatch, caplog):
    """The attack that "once" would otherwise open: send the last sweep's message right after the
    contain. It would run at once, when the sessions it is there to catch have not started yet,
    and the real one, fifteen minutes later, would then count as a repeat."""
    clock = {"t": 0.0}
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: stamp(clock["t"]))
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    world.cell.stop_errors[sid("b")] = "ThrottlingException"  # so that the first sweep is scheduled as well
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.stop_errors.clear()
    first, second, third = (sent["MessageBody"] for sent in world.queue.messages)
    run = Run(world, minutes_later=0)  # the sweeper's time of day is the test's

    clock["t"] = 2.0
    stored = dict(world.dynamo.items)
    world.cell.calls.clear()
    with caplog.at_level("WARNING", logger="portal_api.actions.sweeper"):
        for early in (second, third):
            # It fails, so a message that did come from the queue would be delivered again.
            with pytest.raises(sweeper.SweepNotDue):
                run.handle(early)
    assert world.cell.calls == [] and world.dynamo.items == stored  # nothing run, no claim, no event
    assert "not run, nothing written: it is not due for another 118 seconds" in caplog.text
    assert "not run, nothing written: it is not due for another 898 seconds" in caplog.text
    # The first sweep is due at once.
    assert run.handle(first) == "allowed"

    # Thirty seconds before its time is the earliest a sweep is run.
    clock["t"] = 89.9
    with pytest.raises(sweeper.SweepNotDue, match="sweep 2 of contain"):
        run.handle(second)
    clock["t"] = 90.0
    assert run.handle(second) == "allowed"
    clock["t"] = 869.9
    with pytest.raises(sweeper.SweepNotDue):
        run.handle(third)
    assert len(world.dynamo.claims()) == 2  # the two that ran
    # The real message arrives when it is due, and is run: the early ones used nothing up.
    clock["t"] = 900.5
    world.cell.streams[log_group()].append(session_stream("started-late", 1))
    assert run.handle(third) == "allowed"
    assert (sid("started-late"), "DEFAULT") in world.cell.stopped
    assert [(e["sweep"], e["at"]) for e in run.sweep_events()] == [
        ("1", stamp(2)),
        ("2", stamp(90)),
        ("3", stamp(900.5)),
    ]


# --- the read is bounded -------------------------------------------------------------------------------


def test_the_history_is_read_back_to_the_contain_and_never_further_than_the_bound(world):
    contained(world, minutes_ago=600)  # ten hours ago
    for n in range(2_500):  # and 2,500 events since: refusals, each one second after the last
        put(
            world,
            AuditEvent(
                event_id=f"refusal-{n:05d}",
                request_id=str(uuid.uuid4()),
                at=minutes_ago(500 - n / 60),
                phase="result",
                action="release",
                outcome="denied",
                reason="x",
                actor_subject=f"person-{n}",
                actor_label="l",
                actor_role="security",
            ),
        )
    recent = again(world, minutes_ago=30)
    run = Run(world)
    # A contain near the top: one request of one page.
    assert run.handle(body_of(2, recent)) == "allowed"
    assert (world.dynamo.pages_read, world.dynamo.items_read) == (1, audit_reader.PAGE_SIZE)
    # A contain further back than the bound is not found, and an id that nobody has costs the same.
    for request_id in (REQUEST_ID, FORGED):
        world.dynamo.pages_read = world.dynamo.items_read = 0
        assert run.handle(body_of(2, request_id)) == "no_contain"
        assert world.dynamo.items_read == audit_reader.MAX_DECISION_EVENTS == 2000
        assert world.dynamo.pages_read == 10
    assert len(run.sweep_events()) == 1 and len(world.dynamo.claims()) == 1


# --- the documents ---------------------------------------------------------------------------------------


def test_the_documents_say_what_the_sweeper_writes_and_when():
    root = Path(__file__).resolve().parent.parent
    contract = " ".join((root / "CONTAINMENT_CONTRACT.md").read_text().split())
    for said in (
        "A message that is not valid leaves no event",
        "at most three events for one contain",
        "is not run a second time",
        f"no earlier than {containment_timing.SWEEP_EARLY_TOLERANCE_SECONDS} seconds before it is due",
        "`SWEEP#<request id>#<sweep number>`",
        "belongs to an earlier containment",
    ):
        assert said in contract, said
    assert "leaves a second event" not in contract and "recorded as `failed`, and never retried" not in contract
    iam = " ".join((root / "IAM_ACTIONS.md").read_text().split())
    for said in ("`SWEEP#<request id>#<sweep number>`", "`dynamodb:Query`", "`CONTAINMENT#*`"):
        assert said in iam, said
    readme = " ".join((root / "README.md").read_text().split())
    assert "at most three events for one contain" in readme


# === S16: the page of one agent after a decision ========================================================
#
# The list of agents is served from the inventory as it was last assessed. Right after a decision
# that inventory is from before it: the page of the agent said "Approved" while the registration
# on the same page, which is read from the registry, said "Retired".

AGENT = "recAgent0001"
RECORD_KEY = audit_reader.record_key(AGENT)
RUNTIME_KEY = audit_reader.containment_key(RUNTIME_ARN)


def page(backend_: Any, agent_id: str = AGENT, claims: dict | None = PLATFORM_CLAIMS) -> tuple[int, Any]:
    status, body, _ = raw(backend_, f"/agents/{agent_id}", claims=claims)
    return status, json.loads(body)


def listed(backend_: Any, agent_id: str = AGENT) -> dict[str, Any]:
    status, body, _ = raw(backend_, "/agents")
    assert status == 200
    return next(agent for agent in json.loads(body) if agent["id"] == agent_id)


def warm(backend_: Any, monkeypatch: pytest.MonkeyPatch, status: str = "APPROVED") -> tuple[Any, FakeDynamo]:
    """A cached inventory in which the registration has this status. Returns the service and the audit table."""
    service, clients = backend_
    registry_holds(monkeypatch, tool_record("tool-echo"), agent_record(status))
    service.cache.clear()
    assert page(backend_)[1]["registry_status"] == status
    return service, clients.clients[("platform", "dynamodb")]


@pytest.mark.parametrize("claims", [PLATFORM_CLAIMS, VIEWER_CLAIMS])
def test_the_page_of_an_agent_reflects_a_retirement_decided_a_moment_ago(backend, monkeypatch, claims):
    service, table = warm(backend, monkeypatch)
    before = page(backend, claims=claims)[1]
    assert (before["registry_status"], before["lifecycle_state"]) == ("APPROVED", "approved")
    assessed_before = service.inventory().assessed_at

    # Retired on the registration's page. The inventory in the cache is from before.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    retired_at = decided(table, "retire", "DEPRECATED")
    status, after = page(backend, claims=claims)
    assert status == 200
    assert (after["registry_status"], after["lifecycle_state"]) == ("DEPRECATED", "deprecated")
    assert service.inventory().assessed_at > retired_at > assessed_before
    assert len(reads) == 1  # the inventory was loaded again, once
    # That inventory is the cached one now: the page again, and the list, need no load.
    assert page(backend, claims=claims)[1]["registry_status"] == "DEPRECATED"
    assert listed(backend)["registry_status"] == "DEPRECATED" and len(reads) == 1


def test_the_list_of_agents_stays_as_it_was_cached(backend, monkeypatch):
    service, table = warm(backend, monkeypatch, "PENDING_APPROVAL")
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    decided(table, "approve", "APPROVED")
    asked = len(table.queried)
    # The list does not ask the audit trail, and does not load anything again.
    assert listed(backend)["registry_status"] == "PENDING_APPROVAL"
    assert reads == [] and len(table.queried) == asked
    # Nor do the other reads about the one agent.
    for path in ("runtime", "deployments", "mcp-grants"):
        assert raw(backend, f"/agents/{AGENT}/{path}")[0] == 200
    assert reads == [] and len(table.queried) == asked
    # The page of the agent does.
    assert page(backend)[1]["registry_status"] == "APPROVED" and len(reads) == 1


def test_the_check_is_one_request_for_each_of_the_agents_two_histories(backend, monkeypatch):
    service, table = warm(backend, monkeypatch)
    # Two long histories, with nothing in them that is newer than the inventory.
    for partition in (RECORD_KEY, RUNTIME_KEY):
        for n in range(300):
            event = AuditEvent(
                event_id=f"old-{n:04d}",
                request_id=str(uuid.uuid4()),
                at=f"2026-01-01T00:{n // 60:02d}:{n % 60:02d}.000000Z",
                phase="result",
                action="approve" if partition == RECORD_KEY else "contain",
                outcome="allowed",
                reason="x",
                actor_subject="s",
                actor_label="l",
                actor_role="approver",
            )
            audit_writer.put_event(table, TABLE, partition, event)
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    asked, pages, items = len(table.queried), table.pages_read, table.items_read
    assert page(backend)[0] == 200
    # One request each, for the newest twenty events: never a read of a history.
    assert table.queried[asked:] == [RECORD_KEY, RUNTIME_KEY]
    assert table.pages_read == pages + 2
    assert table.items_read == items + 2 * service_module.DECISION_CHECK_EVENTS == items + 40
    assert reads == []  # and nothing in them was decided since


@pytest.mark.parametrize("event", NOTHING_CHANGED.values(), ids=NOTHING_CHANGED.keys())
def test_an_event_that_changed_nothing_does_not_load_the_inventory_again_for_the_page(backend, monkeypatch, event):
    service, table = warm(backend, monkeypatch)
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    extra = {name: value for name, value in event.items() if name != "action"}
    for _ in range(5):
        decided(table, event["action"], "APPROVED", **extra)
        assert page(backend)[1]["registry_status"] == "APPROVED"
    assert reads == []


def test_a_decision_is_found_below_newer_events_that_changed_nothing(backend, monkeypatch):
    """A contain is followed by its sweeps and by refusals. The newest event alone would not say."""
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    control = clients.clients[(CELL_ACCOUNT, "bedrock-agentcore-control")]
    control.runtimes[0]["detail"]["contained"] = False
    service.cache.clear()
    assert page(backend)[1]["flags"]["contained"] is False

    control.runtimes[0]["detail"]["contained"] = True  # what the next read of the Runtime's policy finds
    decided(table, "contain", "contained", partition=RUNTIME_KEY, agent_id=AGENT)
    for n in range(service_module.DECISION_CHECK_EVENTS - 1):
        decided(
            table,
            "sweep" if n % 2 else "release",
            "contained",
            partition=RUNTIME_KEY,
            outcome="skipped" if n % 2 else "denied",
        )
    assert page(backend)[1]["flags"]["contained"] is True


def test_a_decision_further_down_than_the_newest_twenty_events_is_not_looked_for(backend, monkeypatch):
    """The bound of the check, stated: the answer is then the cached one, as it was before this rule."""
    service, table = warm(backend, monkeypatch)
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    decided(table, "retire", "DEPRECATED")
    for _ in range(service_module.DECISION_CHECK_EVENTS):
        decided(table, "review", "DEPRECATED", outcome="denied")
    assert page(backend)[1]["registry_status"] == "APPROVED" and reads == []


def test_a_containment_decided_a_moment_ago_shows_on_the_page(backend, monkeypatch):
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    control = clients.clients[(CELL_ACCOUNT, "bedrock-agentcore-control")]
    control.runtimes[0]["detail"]["contained"] = False
    service.cache.clear()
    assert page(backend)[1]["flags"]["contained"] is False
    control.runtimes[0]["detail"]["contained"] = True
    # Nothing in the registration's history: the Runtime's containment history says it.
    decided(table, "contain", "contained", partition=RUNTIME_KEY, agent_id=AGENT)
    assert page(backend)[1]["flags"]["contained"] is True
    # And the release.
    monkeypatch.setattr(service, "_clock", lambda: 10_000_000.0)  # the limit of the next test is not this one's
    control.runtimes[0]["detail"]["contained"] = False
    decided(table, "release", "not_contained", partition=RUNTIME_KEY, agent_id=AGENT)
    assert page(backend)[1]["flags"]["contained"] is False


def test_the_inventory_is_loaded_again_for_a_page_at_most_once_in_fifteen_seconds(backend, monkeypatch):
    """Loading it reads every cell. The limit is one, shared with the evidence document."""
    assert service_module.DECISION_RELOAD_SECONDS == 15
    service, table = warm(backend, monkeypatch, "PENDING_APPROVAL")
    now = [1_000.0]
    monkeypatch.setattr(service, "_clock", lambda: now[0])

    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    decided(table, "approve", "APPROVED")
    assert page(backend)[1]["registry_status"] == "APPROVED" and len(reads) == 1

    # Another decision a moment later. For the next fifteen seconds the page is the cached one, as
    # it was before this rule, and the audit trail is not even asked.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    decided(table, "retire", "DEPRECATED")
    asked = len(table.queried)
    for seconds in (0.0, 5.0, 14.9):
        now[0] = 1_000.0 + seconds
        assert page(backend)[1]["registry_status"] == "APPROVED"
    assert reads == [] and len(table.queried) == asked
    # The evidence document is under the same limit: it lists the decision and says that it lags.
    lagging = evidence(backend)[1]
    assert lagging["registration"]["status"] == "APPROVED" and len(stale_notes(lagging)) == 1 and reads == []
    # After that the page loads it again.
    now[0] = 1_015.0
    assert page(backend)[1]["registry_status"] == "DEPRECATED" and len(reads) == 1
    # And a load for the evidence document counts against the page in the same way.
    now[0] = 1_100.0
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    decided(table, "approve", "APPROVED")
    assert evidence(backend)[1]["registration"]["status"] == "APPROVED" and len(reads) == 1
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    decided(table, "retire", "DEPRECATED")
    now[0] = 1_110.0
    assert page(backend)[1]["registry_status"] == "APPROVED" and reads == []
    now[0] = 1_115.0
    assert page(backend)[1]["registry_status"] == "DEPRECATED" and len(reads) == 1


def test_a_load_that_fails_leaves_the_page_as_it_was_cached(backend, monkeypatch):
    service, table = warm(backend, monkeypatch)
    decided(table, "retire", "DEPRECATED")

    def unavailable(client: Any, registry_id: str) -> list[dict[str, Any]]:
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "x"}}, "ListRegistryRecords")

    monkeypatch.setattr(registry, "list_records", unavailable)
    status, agent = page(backend)
    assert (status, agent["registry_status"]) == (200, "APPROVED")
    # The attempt counts against the limit, so a registry that is failing is not asked with every request.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    assert page(backend)[1]["registry_status"] == "APPROVED" and reads == []


def test_a_trail_that_cannot_be_read_leaves_the_page_as_it_was_cached(backend, monkeypatch, caplog):
    service, table = warm(backend, monkeypatch)
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    decided(table, "retire", "DEPRECATED")
    table.fail_query = True
    with caplog.at_level("WARNING", logger="portal_api.service"):
        status, agent = page(backend)
    assert (status, agent["registry_status"]) == (200, "APPROVED") and reads == []
    assert "The newest events of a history could not be read: InternalServerError" in caplog.text
    # Nothing was used up: once the trail answers, the page follows the decision.
    table.fail_query = False
    assert page(backend)[1]["registry_status"] == "DEPRECATED" and len(reads) == 1


def test_without_an_audit_table_the_page_is_the_cached_one(backend, monkeypatch):
    service, clients = backend
    monkeypatch.delenv("PORTAL_AUDIT_TABLE")
    from portal_api.config import get_settings

    bare = make_service(get_settings(), clients)
    table = clients.clients[("platform", "dynamodb")]
    assert bare.agent_current(AGENT).agent.registry_status == "APPROVED"
    assert bare.agent_current(AGENT).agent.registry_status == "APPROVED"
    assert table.calls == []


def test_an_agent_with_no_registration_is_asked_about_by_its_runtime_alone(backend, monkeypatch):
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    control = clients.clients[(CELL_ACCOUNT, "bedrock-agentcore-control")]
    control.runtimes[1]["detail"]["contained"] = False
    service.cache.clear()
    orphan = next(entry for entry in service.agents() if entry.record is None)
    assert orphan.runtime_arn == ORPHAN_RUNTIME_ARN and orphan.agent.flags.contained is False
    asked = len(table.queried)
    assert page(backend, orphan.agent.id)[0] == 200
    assert table.queried[asked:] == [audit_reader.containment_key(ORPHAN_RUNTIME_ARN)]
    # Contained a moment ago: the page says so.
    control.runtimes[1]["detail"]["contained"] = True
    decided(table, "contain", "contained", partition=audit_reader.containment_key(ORPHAN_RUNTIME_ARN))
    assert page(backend, orphan.agent.id)[1]["flags"]["contained"] is True


def test_a_runtime_that_a_registration_spells_another_way_is_not_asked_about_under_that_spelling(backend, monkeypatch):
    """The portal reads a history only under the ARN it builds itself. A registration is written by
    the people it governs, and the service answers for other spellings of the same Runtime."""
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    other = RUNTIME_ARN.replace("arn:aws:", "arn:aws-cn:", 1)
    registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED", runtimeArn=other))
    service.cache.clear()
    assert page(backend)[1]["registry_status"] == "APPROVED"
    asked = len(table.queried)
    assert page(backend)[0] == 200
    assert table.queried[asked:] == [RECORD_KEY]  # the registration's history, and no history under that spelling
    # Whatever lies under that spelling's key was not written by the portal, and loads nothing.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED", runtimeArn=other))
    decided(table, "contain", "contained", partition=audit_reader.containment_key(other))
    assert page(backend)[0] == 200 and reads == []
    assert audit_reader.containment_key(other) not in table.queried


def test_a_registration_made_a_moment_ago_has_a_page_at_once(backend, monkeypatch):
    """Its id is not in the cached inventory yet. Its own history says that it was just created."""
    service, table = warm(backend, monkeypatch)
    new = agent_record("DRAFT", "recAgent0002", agentId="second-agent", runtimeArn=None, gatewayArn=None)
    new["name"] = "agent-ws1-second-agent-nonprod"
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"), new)
    # Before anything is on record under that id: not found, and nothing is loaded for the asking.
    asked = len(table.queried)
    assert page(backend, "recAgent0002") == (404, {"detail": "Agent not found"})
    assert table.queried[asked:] == [audit_reader.record_key("recAgent0002")] and reads == []
    # The create's result is filed under the record's id.
    decided(table, "create", "DRAFT", partition=audit_reader.record_key("recAgent0002"))
    status, agent = page(backend, "recAgent0002")
    assert (status, agent["id"], agent["registry_status"]) == (200, "recAgent0002", "DRAFT") and len(reads) == 1


def test_an_id_that_names_no_history_is_not_asked_about(backend, monkeypatch):
    service, table = warm(backend, monkeypatch)
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    asked = len(table.queried)
    # Not a registration's id: there is no history it could name, so the trail is not asked.
    for unknown in ("no_such_agent-AbCdEf1234", "x", "rec-Agent-0003", "recAgent00020"):
        assert page(backend, unknown) == (404, {"detail": "Agent not found"})
    assert len(table.queried) == asked and reads == []


def test_an_agent_that_is_gone_after_the_load_is_not_found(backend, monkeypatch):
    service, table = warm(backend, monkeypatch)
    # The registration was deleted. Its Runtime is still there, as an agent with no registration.
    registry_holds(monkeypatch, tool_record("tool-echo"))
    decided(table, "delete", "DELETED")
    assert page(backend) == (404, {"detail": "Agent not found"})
    assert any(entry.record is None and entry.runtime_arn == RUNTIME_ARN for entry in service.agents())


def test_the_documents_say_what_the_page_of_an_agent_reflects():
    root = Path(__file__).resolve().parent.parent
    readme = " ".join((root / "README.md").read_text().split())
    for said in (
        "`GET /agents/{agent_id}` reflects a decision about that agent",
        f"at most once in {service_module.DECISION_RELOAD_SECONDS:g} seconds",
        f"the newest {service_module.DECISION_CHECK_EVENTS} events",
        "The list of agents stays as it was cached",
    ):
        assert said in readme, said
