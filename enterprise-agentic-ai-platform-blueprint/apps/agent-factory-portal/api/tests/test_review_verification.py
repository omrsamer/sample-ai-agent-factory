# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""What the verification of the security fixes left to do, first part: the attack or the gap, and what must still work.

T1  A refusal of someone who has a part in a record is written once per person, rule and state of the record.
T2  The sweeper takes one message per invocation, admits only the sweeps a contain scheduled, and takes the
    agent id of its event from the contain.
T3  The sentence about a statement with the portal's identifier in another shape claims nothing about what it denies.
T4  The limit on the sweeper's session is the sweeper's own request, and the documents say so.
T5  Every approval records a review date.
T6  A registration names a resource of a cell with the cell's partition.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import portal_api
from portal_api import containment_policy, containment_timing, reviews, sweeps
from portal_api.actions import audit_writer, containment_flow, engine, reference_rules, sweeper
from portal_api.aws import audit as audit_reader
from portal_api.config import load_settings
from tests import test_containment, test_sweeps
from tests.conftest import BASE_ENV, CELL_ACCOUNT, CELLS, GATEWAY_ARN, OTHER_ACCOUNT, REGION, RUNTIME_ARN
from tests.fakes import FakeDynamo
from tests.test_actions import ANN, ANN2, DEV, PAT, UNMANAGED_RUNTIME
from tests.test_actions import SEC as RECORD_SEC
from tests.test_actions import World as RecordWorld
from tests.test_containment import PAT as RESPONDER_PAT
from tests.test_containment import RUNTIME_ID, SEC, SRE, log_group, session_stream, sid
from tests.test_lifecycle import attestation_items, day, events_of, retire, review
from tests.test_review_wave2 import policy_of, portal_statement
from tests.test_sweeps import (
    KEY,
    REQUEST_ID,
    Context,
    Run,
    SweepWorld,
    contained,
    later,
    message,
    on_record,
    stamp,
)

read = test_containment.read  # the read API over the same cell, record and audit table as the action functions
entry = test_sweeps.entry  # the sweeper function's handler

TABLE = BASE_ENV["PORTAL_AUDIT_TABLE"]
ROOT = Path(__file__).resolve().parent.parent
SOURCES = sorted(Path(portal_api.__file__).resolve().parent.rglob("*.py"))
DOCUMENTS = ("README.md", "CONTAINMENT_CONTRACT.md", "ACTIONS_CONTRACT.md", "IAM_ACTIONS.md")


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> RecordWorld:
    return RecordWorld(monkeypatch)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SweepWorld:
    return SweepWorld(monkeypatch)


def document(name: str) -> str:
    return " ".join((ROOT / name).read_text().split())


def history(records: RecordWorld, record_id: str) -> list[dict[str, str]]:
    """The record's own events, oldest first."""
    return [e for e in records.dynamo.events() if e["pk"] == f"RECORD#{record_id}"]


def refusals(records: RecordWorld, record_id: str) -> list[tuple[str, str, str]]:
    """(action, who, rule) of every refusal in the record's history, oldest first."""
    return [
        (e["action"], e["actor_subject"], engine.rule_of(e["reason"]))
        for e in history(records, record_id)
        if e["outcome"] == "denied"
    ]


def marks(records: RecordWorld) -> list[dict[str, str]]:
    return [item for item in records.dynamo.claims() if item["sk"].startswith("ONCE#")]


# === T1: a refusal is on record once ====================================================================
#
# The attack: an approver of the record's own tenant asks 2,000 times to approve a record that is
# already approved. Each refusal was written. Approve, reject and review read the history back to
# the record's last submit, and after 2,000 events they failed closed until it was submitted again.


def test_a_refused_approval_repeated_two_thousand_times_is_on_record_once(records, caplog):
    record_id = records.new_record("APPROVED")
    before = len(history(records, record_id))
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        answers = [records.decide("approve", record_id, ANN) for _ in range(2000)]
    assert {code for code, _ in answers} == {409}
    assert {body["detail"] for _, body in answers} == {
        "Only a record that is pending approval can be decided; this one is APPROVED"
    }
    # Every answer names its own request, and the function's log has each of them.
    assert len({body["request_id"] for _, body in answers}) == 2000
    assert len([m for m in caplog.messages if "not written to the audit trail" in m]) == 1999
    # One event, and one mark that says so.
    assert len(history(records, record_id)) == before + 1 and len(marks(records)) == 1
    (denied,) = [e for e in history(records, record_id) if e["outcome"] == "denied"]
    assert denied["request_id"] == answers[0][1]["request_id"]
    # So the decisions that read the history still work: a review, and after a new submit an approval.
    assert review(records, record_id, RECORD_SEC)[0] == 200
    assert records.update(record_id, business_purpose="Changed.")[0] == 200
    assert records.submit(record_id)[0] == 200 and records.decide("approve", record_id, ANN)[0] == 200


def test_once_is_for_each_person_each_rule_and_each_state_of_the_record(records):
    record_id = records.new_record("APPROVED")
    other_runtime = RUNTIME_ARN.replace("travel_agent", "other_agent")

    def round_of_refusals(**held: Any) -> None:
        """``held`` is what the record's document holds beyond the first one."""
        for _ in range(5):
            assert records.decide("approve", record_id, ANN)[0] == 409  # not pending
            assert records.decide("approve", record_id, RECORD_SEC)[0] == 409  # another person
            assert records.decide("reject", record_id, ANN)[0] == 409  # another action
            assert records.update(record_id, **held)[0] == 409  # the registrar: it already holds this document
            assert records.update(record_id, runtime_arn=other_runtime, **held)[0] == 403  # another rule: REG-12-N
            assert records.submit(record_id)[0] == 409
            assert records.delete(record_id)[0] == 409

    round_of_refusals()
    first = refusals(records, record_id)
    assert len(first) == 7 and len(set(first)) == 7
    assert {(action, who) for action, who, _ in first} == {
        ("approve", "ann-1"),
        ("approve", "sec-1"),
        ("reject", "ann-1"),
        ("update", "dev-1"),
        ("submit", "dev-1"),
        ("delete", "dev-1"),
    }
    assert "REG-12-N" in {rule for action, _, rule in first if action == "update"}

    # The record changes (a new document, approved again): the same refusals are written once more.
    assert records.update(record_id, business_purpose="Changed.")[0] == 200
    assert records.submit(record_id)[0] == 200 and records.decide("approve", record_id, ANN)[0] == 200
    round_of_refusals(business_purpose="Changed.")
    assert len(refusals(records, record_id)) == 14
    # Each state has its own marks, and nothing but the marks and the events was written.
    assert len(marks(records)) == 14
    assert {mark["pk"] for mark in marks(records)} == {f"RECORD#{record_id}"}


def test_a_new_proposal_is_not_a_new_state(records):
    """The attack on the count: change the body with every request. The state is the record's, not the request's."""
    record_id = records.new_record("APPROVED")
    before = len(history(records, record_id))
    for n in range(60):
        proposed = RUNTIME_ARN.replace("travel_agent-AbCdEf1234", f"other_agent-Xy{n:04d}")
        code, body = records.update(record_id, runtime_arn=proposed, business_purpose=f"Purpose {n}.")
        assert code == 403 and "REG-12-N" in body["detail"], body
    assert len(history(records, record_id)) == before + 1
    assert refusals(records, record_id) == [("update", "dev-1", "REG-12-N")]


def test_the_registrar_function_writes_once_without_reading(records):
    """Its role may put an item and nothing else: the mark is one conditional write, and no query is made."""
    record_id = records.new_record("APPROVED")
    assert records.create()[0] == 409  # the name is taken
    records.dynamo.calls.clear()
    for _ in range(10):
        assert records.create()[0] == 409
        assert records.update(record_id)[0] == 409
        assert records.submit(record_id)[0] == 409
        assert records.delete(record_id)[0] == 409
    assert set(records.dynamo.calls) == {"put_item"}
    # A refused create is filed under the name, once for each person who asks.
    named = [e for e in records.dynamo.events() if e["pk"] == "RECORD#NAME#agent-ws1-travel-agent-nonprod"]
    assert [(e["action"], e["outcome"]) for e in named] == [("create", "allowed"), ("create", "denied")]
    assert len(refusals(records, record_id)) == 3
    assert {mark["pk"] for mark in marks(records)} == {
        f"RECORD#{record_id}",
        "RECORD#NAME#agent-ws1-travel-agent-nonprod",
    }


def test_a_retirement_asked_for_again_is_on_record_once_for_each_person(records, caplog):
    record_id = records.new_record("APPROVED")
    assert retire(records, record_id, ANN)[0] == 200
    before = len(history(records, record_id))
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        answers = [retire(records, record_id, claims) for claims in [ANN] * 50 + [RECORD_SEC] * 50]
    for code, body in answers:
        assert (code, body["outcome"], body["audit_complete"]) == (200, "unchanged", True), body
        assert body["registration"]["status"] == "DEPRECATED"
    added = history(records, record_id)[before:]
    assert [(e["action"], e["outcome"], e["actor_subject"]) for e in added] == [
        ("retire", "unchanged", "ann-1"),
        ("retire", "unchanged", "sec-1"),
    ]
    assert (
        len([m for m in caplog.messages if "Unchanged answer logged, not written to the audit trail again" in m]) == 98
    )


def test_a_refusal_of_someone_with_no_part_in_the_record_leaves_no_mark_either(records):
    record_id = records.new_record("APPROVED")
    stored = dict(records.dynamo.items)
    for _ in range(5):
        assert records.decide("approve", record_id, ANN2)[0] == 403  # an approver of another tenant
        assert review(records, record_id, ANN2)[0] == 403
        assert retire(records, record_id, DEV)[0] == 403  # no approver authority
    assert records.dynamo.items == stored


def test_a_mark_that_cannot_be_written_leaves_nothing_in_the_history(records):
    """Without the mark a repeated request would add an event each time, so then nothing is written."""
    record_id = records.new_record("APPROVED")
    before = len(history(records, record_id))
    records.dynamo.fail_put_numbers = {records.dynamo._puts + 1}
    code, body = records.decide("approve", record_id, ANN)
    assert code == 409 and body["request_id"]  # the answer does not depend on it
    assert len(history(records, record_id)) == before and marks(records) == []
    # The next refusal is the one on record.
    assert records.decide("approve", record_id, ANN)[0] == 409
    assert len(history(records, record_id)) == before + 1 and len(marks(records)) == 1
    # An answer that nothing was changed says that the trail is not complete when its mark fails.
    assert retire(records, record_id, ANN)[0] == 200
    records.dynamo.fail_put_numbers = {records.dynamo._puts + 1}
    code, body = retire(records, record_id, ANN)
    assert (code, body["outcome"], body["audit_complete"]) == (200, "unchanged", False)
    assert [e["outcome"] for e in history(records, record_id)][-1] == "allowed"


def test_what_a_refusal_is_filed_under():
    assert engine.rule_of("the submitter cannot approve its own record - separation of duties (REG-11-N)") == "REG-11-N"
    # The rule decides, whatever else the sentence says.
    one = "a review can be attested once in 24 hours; this one was attested at 2026-05-31T12:01:00Z (REV-06-N)"
    other = one.replace("2026-05-31T12:01:00Z", "2026-06-02T08:00:00Z")
    assert engine.rule_of(one) == engine.rule_of(other) == "REV-06-N"
    # A sentence with no rule id stands for itself.
    plain = engine.rule_of("The record already holds this document")
    assert re.fullmatch(r"[0-9a-f]{20}", plain) and plain != engine.rule_of("An approved record cannot be deleted")
    assert engine.rule_of("The record already holds this document") == plain
    # Not an id: lower case, other digits.
    assert re.fullmatch(r"[0-9a-f]{20}", engine.rule_of("see reg-11-n"))
    assert re.fullmatch(r"[0-9a-f]{20}", engine.rule_of("REG-١١-N"))
    # The state is the record's status and the document it holds.
    assert engine.record_state("APPROVED", "ab" * 32) == "APPROVED:" + "ab" * 32
    assert engine.record_state("DRAFT", None) == "DRAFT:"


def test_the_mark_is_one_conditional_write_that_no_history_returns(records):
    table = FakeDynamo()
    args = (table, TABLE, "RECORD#rec000000001", "APPROVED:abc", "ann-1", "approve", "REG-11-N", "req-1")
    assert audit_writer.mark_once(*args) is True
    assert audit_writer.mark_once(*args) is False
    # Another state, person, action or rule is another mark.
    for change in ({1 + 2: "DRAFT:abc"}, {1 + 3: "sec-1"}, {1 + 4: "reject"}, {1 + 5: "REG-13-N"}):
        changed = list(args)
        for position, value in change.items():
            changed[position] = value
        assert audit_writer.mark_once(*changed) is True
    assert len(table.items) == 5 and {sk for _, sk in table.items} == {item["sk"]["S"] for item in table.items.values()}
    key = audit_reader.once_sort_key("APPROVED:abc", "ann-1", "approve", "REG-11-N")
    (first,) = [item for item in table.claims() if item["sk"] == key]
    assert first == {
        "pk": "RECORD#rec000000001",
        "sk": key,
        "kind": "once",
        "at": first["at"],
        "state": "APPROVED:abc",
        "actor_subject": "ann-1",
        "action": "approve",
        "rule": "REG-11-N",
        "request_id": "req-1",
    }
    assert re.fullmatch(r"ONCE#[0-9a-f]{64}", first["sk"])
    # The parts cannot run into one another.
    assert audit_reader.once_sort_key("a", "b#c", "d", "e") != audit_reader.once_sort_key("a#b", "c", "d", "e")
    # Any other failure of the write is raised.
    table.fail_put_numbers = {table._puts + 1}
    with pytest.raises(ClientError):
        audit_writer.mark_once(table, TABLE, "RECORD#rec000000001", "s", "p", "approve", "r", "req-2")
    # No read of a history returns a mark: the registration's history lists events only.
    record_id = records.new_record("APPROVED")
    assert records.decide("approve", record_id, ANN)[0] == 409 and len(marks(records)) == 1
    listed = records.call("read", "GET", f"/registrations/{record_id}/history", ANN)[1]["events"]
    assert len(listed) == len(history(records, record_id)) + 1  # and the create's intent, filed under the name
    assert audit_reader.read_back(records.dynamo, TABLE, f"RECORD#{record_id}").items == [
        records.dynamo.items[(e["pk"], e["sk"])] for e in reversed(history(records, record_id))
    ]


def test_the_mark_as_the_service_receives_it():
    client = boto3.client("dynamodb", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test")
    sent: list[dict[str, Any]] = []
    client.meta.events.register("provide-client-params.dynamodb.PutItem", lambda params, **_: sent.append(params))
    with Stubber(client) as stub:
        stub.add_response("put_item", {})
        assert audit_writer.mark_once(client, TABLE, "RECORD#rec000000001", "s", "p", "approve", "r", "req") is True
        stub.add_client_error("put_item", "ConditionalCheckFailedException", "The conditional request failed", 400)
        # Refused by the condition: it is on record. No read follows, so a role that may only write can do this.
        assert audit_writer.mark_once(client, TABLE, "RECORD#rec000000001", "s", "p", "approve", "r", "req") is False
        stub.assert_no_pending_responses()
    assert {params["ConditionExpression"] for params in sent} == {"attribute_not_exists(pk)"}
    assert sent[0]["Item"]["pk"] == {"S": "RECORD#rec000000001"} and sent[0]["Item"]["sk"]["S"].startswith("ONCE#")


# === T2: the sweeper =======================================================================================


def body_of(sweep: int = 2, request_id: str = REQUEST_ID, **changes: Any) -> str:
    return sweeps.encode(message(sweep=sweep, request_id=request_id, **changes))


def test_a_contains_result_lists_the_sweeps_it_scheduled(world, monkeypatch):
    world.cell.streams[log_group()] = [session_stream("a")]
    assert world.post("contain", claims=SEC)[1]["sweeps_scheduled_in_seconds"] == [120, 900]
    result = [e for e in world.dynamo.events() if e["phase"] == "result"][-1]
    assert (result["sweeps_scheduled"], result["sweeps_scheduled_numbers"]) == ("2", "2,3")
    assert world.post("release", claims=RESPONDER_PAT)[0] == 200
    # A contain that left a session running schedules the first as well.
    world.queue.messages.clear()
    world.cell.streams[log_group()] = [session_stream("b")]
    world.cell.stop_errors[sid("b")] = "ThrottlingException"
    assert world.post("contain", claims=SEC)[1]["sweeps_scheduled_in_seconds"] == [0, 120, 900]
    result = [e for e in world.dynamo.events() if e["phase"] == "result"][-1]
    assert (result["sweeps_scheduled"], result["sweeps_scheduled_numbers"]) == ("3", "1,2,3")
    assert world.post("release", claims=RESPONDER_PAT)[0] == 200
    # One that could schedule only some lists those.
    world.queue.messages.clear()
    world.queue.sends, world.queue.fail_on = 0, {2}
    world.cell.stop_errors.clear()
    response = world.post("contain", claims=SEC)[1]
    assert response["sweeps_scheduled_in_seconds"] == [120] and response["partial"] is True
    result = [e for e in world.dynamo.events() if e["phase"] == "result"][-1]
    assert (result["sweeps_scheduled"], result["sweeps_scheduled_numbers"]) == ("1", "2")
    # The read API passes the list on with the event.
    listed = [e for e in read_events(world) if e["action"] == "contain" and e["phase"] == "result"]
    assert listed[0]["sweeps_scheduled_numbers"] == "2"


def read_events(world: SweepWorld) -> list[dict[str, Any]]:
    trail = audit_reader.read_back(world.dynamo, TABLE, KEY)
    return [event.model_dump() for event in trail.events]


def test_without_a_queue_a_result_lists_no_sweep(monkeypatch):
    plain = test_containment.World(monkeypatch)  # PORTAL_SWEEP_QUEUE_URL is not set
    assert plain.post("contain")[0] == 200
    result = [e for e in plain.dynamo.events() if e["phase"] == "result"][-1]
    assert "sweeps_scheduled" not in result and "sweeps_scheduled_numbers" not in result


def test_only_the_sweeps_a_contain_scheduled_are_admitted(world, read, monkeypatch, caplog):
    """A first sweep for a contain that needed none ran at once and counted as one of its sweeps:
    after the real second sweep the view said two of two were done while the third had not run."""
    world.cell.streams[log_group()] = [session_stream("a")]
    request_id = world.post("contain", claims=SEC)[1]["request_id"]
    second, third = (sent["MessageBody"] for sent in world.queue.messages)
    stored = dict(world.dynamo.items)
    world.cell.calls.clear()
    run = Run(world)
    with caplog.at_level("WARNING", logger="portal_api.actions.sweeper"):
        for _ in range(5):
            assert run.handle(body_of(1, request_id)) == "not_scheduled"
    # Not run, not claimed, not recorded.
    assert world.cell.calls == [] and world.dynamo.items == stored
    assert [m for m in caplog.messages if "not_scheduled" in m] == [
        f"Sweep 1 of contain {request_id} not run, nothing written (not_scheduled): "
        "the contain with that id did not schedule it"
    ] * 5
    assert run.handle(second) == "allowed"
    view = read(world.record_id, SRE)[1]
    assert view["sweeps"] == {"scheduled": 2, "done": 1}
    # The third is still to come, so a contain repeated after the pause waits for it.
    later(monkeypatch, 16)
    waiting = world.post("contain", claims=RESPONDER_PAT)[1]
    assert (waiting["outcome"], waiting["retry_after_seconds"]) == ("unchanged", 60)
    assert run.handle(third) == "allowed"
    assert read(world.record_id, SRE)[1]["sweeps"] == {"scheduled": 2, "done": 2}


def test_a_contain_that_scheduled_only_one_sweep_admits_only_that_one(world):
    world.queue.fail_on = {2}  # the message for the third sweep cannot be sent
    request_id = world.post("contain", claims=SEC)[1]["request_id"]
    run = Run(world)
    assert run.handle(body_of(3, request_id)) == "not_scheduled"
    assert run.handle(body_of(1, request_id)) == "not_scheduled"
    assert run.handle(body_of(2, request_id)) == "allowed"
    assert [e["sweep"] for e in run.sweep_events()] == ["2"]


def test_what_a_contain_admits():
    began = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)

    def contain(numbers: frozenset[int] | None, has_result: bool) -> sweeps.Scheduler:
        return sweeps.Scheduler(0, began, numbers, has_result, "rec1")

    listed = contain(frozenset({2, 3}), True)
    assert [sweeps.admits(listed, n) for n in (1, 2, 3)] == [False, True, True]
    assert [sweeps.admits(contain(frozenset({1, 2, 3}), True), n) for n in (1, 2, 3)] == [True, True, True]
    assert [sweeps.admits(contain(frozenset(), True), n) for n in (1, 2, 3)] == [False, False, False]
    # No result yet, or a result that was lost: the two every contain schedules, and the first is not known.
    assert [sweeps.admits(contain(None, False), n) for n in (1, 2, 3)] == [None, True, True]
    # A result from before results listed their sweeps admits every number, as the sweeper did then.
    assert [sweeps.admits(contain(None, True), n) for n in (1, 2, 3)] == [True, True, True]

    assert sweeps.encode_numbers([3, 2]) == "2,3" and sweeps.encode_numbers([1, 2, 3, 3]) == "1,2,3"
    assert sweeps.encode_numbers([]) is None
    assert sweeps.decode_numbers("2,3") == {2, 3} and sweeps.decode_numbers("1") == {1}
    # Anything that is not such a list lists nothing, so nothing is admitted on its word.
    for odd in ("", "4", "2,3,", "1,2,3,1", "2;3", " 2,3", "2,3\n", "٢,٣", None, 23, ["2", "3"]):
        assert sweeps.decode_numbers(odd) == frozenset(), odd


def test_a_result_from_before_results_listed_their_sweeps_admits_every_number(world):
    contained(world, numbers=None)  # as a contain recorded it before this rule
    run = Run(world)
    assert [run.handle(body_of(n)) for n in (1, 2, 3)] == ["allowed"] * 3


def test_a_result_whose_list_is_not_one_admits_nothing(world):
    contained(world, numbers="2;3")
    run = Run(world)
    assert [run.handle(body_of(n)) for n in (1, 2, 3)] == ["not_scheduled"] * 3
    assert run.sweep_events() == [] and world.dynamo.claims() == []


@pytest.fixture
def ticking(world, monkeypatch):
    """A sweeper whose time of day is the test's clock, which sleeping advances: for the wait of a first sweep."""
    clock = {"t": 0.0}
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: stamp(clock["t"]))
    run = Run(world, minutes_later=0)
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["t"] += seconds
        for at_sleep, arrive in list(run.arrivals):
            if len(slept) == at_sleep:
                arrive()

    run.arrivals = []
    run.sweeper.sleep = sleep
    return run, clock, slept


def test_a_first_sweep_that_is_here_before_its_contains_result_waits_for_it(world, ticking):
    """The first sweep is sent with no delay. The contain writes its result a moment after sending it."""
    run, clock, slept = ticking
    contained(world, minutes_ago=0, result=False)  # the intent, a moment ago; the request is still running
    world.cell.streams[log_group()] = [session_stream("a")]
    run.arrivals.append((3, lambda: on_record(world, minutes_ago=0, intent=False, numbers="1,2,3")))
    assert run.handle(body_of(1)) == "allowed"
    # Four looks at the history, each one request for each of its two ranges.
    assert slept == [1.0, 1.0, 1.0] and world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#")] * 4
    assert world.cell.stopped == [(sid("a"), "DEFAULT")]


def test_a_first_sweep_whose_contain_then_says_it_scheduled_none_is_not_run(world, ticking):
    run, clock, slept = ticking
    contained(world, minutes_ago=0, result=False)
    run.arrivals.append((2, lambda: on_record(world, minutes_ago=0, intent=False, scheduled=2)))
    assert run.handle(body_of(1)) == "not_scheduled"
    assert slept == [1.0, 1.0] and world.cell.calls == [] and world.dynamo.claims() == []


def test_a_first_sweep_whose_contain_then_fails_is_not_run(world, ticking):
    run, clock, slept = ticking
    contained(world, minutes_ago=0, result=False)
    run.arrivals.append((1, lambda: on_record(world, minutes_ago=0, intent=False, outcome="failed", scheduled=None)))
    assert run.handle(body_of(1)) == "no_contain"
    assert slept == [1.0] and world.cell.calls == []


def test_the_wait_for_a_result_ends_when_the_containment_function_cannot_still_be_running(world, ticking, caplog):
    run, clock, slept = ticking
    contained(world, minutes_ago=0, result=False)
    world.cell.streams[log_group()] = [session_stream("a")]
    with caplog.at_level("WARNING", logger="portal_api.actions.sweeper"):
        assert run.handle(body_of(1)) == "not_scheduled"
    # Forty seconds from the contain's intent, and no longer. The result was lost.
    assert containment_timing.CONTAIN_RESULT_WAIT_SECONDS == 40 > 29
    assert sum(slept) == 40.0 and len(slept) == 40
    assert world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#")] * 41
    assert world.cell.calls == [] and world.dynamo.claims() == []
    assert "the contain with that id has left no result that lists it" in caplog.text
    # The second and the third sweep of that contain are admitted when they are due.
    clock["t"] = 125.0
    assert run.handle(body_of(2)) == "allowed"
    # A first sweep for a contain whose intent is older than that is not waited for at all.
    slept.clear()
    assert run.handle(body_of(1)) == "not_scheduled" and slept == []


def test_the_second_and_third_sweep_never_wait(world, ticking):
    run, clock, slept = ticking
    contained(world, minutes_ago=0, result=False)
    clock["t"] = 95.0  # within the allowance of the second sweep
    assert run.handle(body_of(2)) == "allowed" and slept == []


def test_the_sweeps_event_carries_the_agent_id_of_its_contain_not_of_the_message(world):
    """A message's agent id is whatever its sender wrote. The contain's own events say what it was addressed with."""
    world.cell.streams[log_group()] = [session_stream("a")]
    request_id = world.post("contain", claims=SEC)[1]["request_id"]  # addressed by its registration
    run = Run(world)
    # The same sweep, named by the Runtime's own id: a valid message.
    assert run.handle(body_of(2, request_id, agent_id=RUNTIME_ID)) == "allowed"
    (event,) = run.sweep_events()
    assert event["agent_id"] == world.record_id != RUNTIME_ID
    # And the other way round: a contain addressed by the Runtime id, a message that names a registration.
    assert world.post("release", claims=RESPONDER_PAT)[0] == 200
    world.queue.messages.clear()
    by_runtime = world.post(
        "contain", agent_id=RUNTIME_ID, claims=SEC, body={"reason": "x", "runtime_arn": RUNTIME_ARN}
    )
    assert by_runtime[0] == 200
    assert run.handle(body_of(3, by_runtime[1]["request_id"], agent_id="recZZZZZZZZZ")) == "allowed"
    assert run.sweep_events()[-1]["agent_id"] == RUNTIME_ID


def test_through_the_function_one_long_sweep_cannot_be_put_before_another_runtimes_due_sweep(world, entry):
    """The attack: two records in one invocation. The first runs long, the second is claimed with no
    time left and recorded as failed, and the real message then finds it done."""
    contained(world)
    world.cell.streams[log_group()] = [session_stream("victim")]
    own = sweeps.encode(message(sweep=3))
    victim = sweeps.encode(message(sweep=2))
    assert entry({"Records": [{"body": own}, {"body": victim}]}, Context()) == {"handled": 0}
    assert world.dynamo.claims() == [] and world.cell.stopped == []
    # The real message for the second sweep, alone, is run in full.
    assert entry({"Records": [{"body": victim}]}, Context()) == {"handled": 1}
    assert world.cell.stopped == [(sid("victim"), "DEFAULT")]


# === T3: a statement with the portal's identifier in another shape =========================================


def test_the_sentence_claims_nothing_about_what_such_a_statement_denies():
    sentence = containment_policy.FOREIGN_STATEMENT
    assert sentence == (
        "A statement with the portal's identifier is in the Runtime's resource policy, but it is not the "
        "statement the portal writes and may or may not deny invocation; contain the agent to replace it."
    )
    assert "does not deny" not in sentence and "denies nothing" not in sentence


# A deny that is not the portal's statement and does deny: every AWS principal, or actions in another case.
DENIES_ANYWAY = {
    "every AWS principal": portal_statement(Principal={"AWS": "*"}),
    "action names in another case": portal_statement(
        Action=[action.lower() for action in containment_policy.CORE_INVOKE_ACTIONS]
    ),
}


@pytest.mark.parametrize("name", DENIES_ANYWAY)
def test_a_statement_that_denies_in_another_shape_is_never_said_not_to_deny(world, read, name):
    world.cell.policies[RUNTIME_ARN] = policy_of(DENIES_ANYWAY[name])
    assert containment_policy.state(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN) == containment_policy.FOREIGN
    view = read(world.record_id, SRE)[1]
    assert (view["state"], view["detail"]) == ("not_contained", containment_policy.FOREIGN_STATEMENT)
    # A release leaves it, and does not say that the Runtime was not contained.
    code, body = world.post("release", claims=RESPONDER_PAT)
    assert code == 200 and body["outcome"] == "unchanged"
    assert body["reason"] == (
        f"{containment_flow.NOT_THE_PORTALS} Its policy was not changed. {containment_policy.FOREIGN_STATEMENT}"
    )
    assert body["steps"][0]["detail"] == f"{containment_flow.NOT_THE_PORTALS} {containment_policy.FOREIGN_STATEMENT}"
    for said in (body["reason"], body["steps"][0]["detail"], view["detail"]):
        assert "was not contained" not in said and "does not deny" not in said
    # A sweep stops nothing and says the same.
    contained_before = world.cell.policies[RUNTIME_ARN]
    on_record(world)
    run = Run(world)
    assert run.handle(body_of()) == "skipped"
    (event,) = run.sweep_events()
    assert event["reason"] == (
        "Background sweep 2 stopped nothing: the statement the portal writes is no longer in the Runtime's policy. "
        f"{containment_policy.FOREIGN_STATEMENT}"
    )
    assert "no longer contained" not in event["reason"] and world.cell.policies[RUNTIME_ARN] == contained_before
    # A contain replaces it.
    assert world.post("contain", claims=SEC)[1]["replaced_foreign_statement"] is True


def test_a_release_of_a_runtime_with_no_such_statement_still_says_that_it_was_not_contained(world):
    code, body = world.post("release", claims=RESPONDER_PAT)
    assert code == 200 and body["reason"] == "The Runtime was not contained; its policy was not changed."


# === T4: the limit on the sweeper's session ==================================================================


def test_nothing_says_that_the_sweepers_session_is_limited_whatever_its_code_does():
    """The session policy is asked for by the code it limits, under a role that may ask for more."""
    stronger = ("whatever its code does", "whatever this code", "even if its code did", "whatever the code does")
    for path in [*SOURCES, *(ROOT / name for name in DOCUMENTS)]:
        text = " ".join(path.read_text().split())
        for phrase in stronger:
            assert phrase not in text, (path.name, phrase)
    source = " ".join((Path(sweeper.__file__)).read_text().split())
    assert "That is a restraint this code puts on itself, not a limit on the role." in source
    iam = document("IAM_ACTIONS.md")
    for said in (
        "**The session its code asks for cannot either.**",
        "It is a restraint the sweeper's code puts on itself, not a limit on the role",
        "may assume a cell's role without a session policy",
    ):
        assert said in iam, said
    readme = document("README.md")
    assert "The sweeper's own code asks for that session" in readme
    # What the wording rests on is still pinned: every assumption the sweeper makes carries the policy.
    assert Path(sweeper.__file__).read_text().count("session_policy=narrowed") == 1
    assert Path(sweeper.__file__).read_text().count(".assumed(") == 1


# === T5: every approval records a review date ================================================================


def test_the_review_date_an_approval_records():
    today = dt.date(2026, 6, 1)
    latest = "2027-06-02"  # 366 days on
    assert reviews.approval_date("2026-12-01", today) == "2026-12-01"
    assert reviews.approval_date("2027-06-02", today) == latest
    assert reviews.approval_date("2020-01-01", today) == "2020-01-01"  # due at once: the registrant's to give
    # A later date, and no date at all: a year from the approval.
    assert reviews.approval_date("2027-06-03", today) == latest
    for nothing in (None, "", "next spring", "2026-02-30", 20261201, "2026-12-01\n"):
        assert reviews.approval_date(nothing, today) == latest, nothing


def test_an_approved_registration_that_names_no_date_becomes_overdue(records, monkeypatch):
    """Before, it never did: leaving the field empty gave what a date in the far future used to give."""
    record_id = records.new_record("APPROVED")
    (item,) = attestation_items(records)
    assert (item["kind"], item["next_review_by"]) == ("approval", day(366))
    result = events_of(records, record_id, "approve")[-1]
    assert (result["next_review_by"], result["attested_at"]) == (day(366), item["at"])
    agent = records.call("read", "GET", f"/agents/{record_id}", ANN)[1]
    assert (agent["review_by"], agent["flags"]["review_overdue"]) == (day(366), False)
    # A year and a day later it is.
    assert reviews.overdue(agent["review_by"], dt.date.fromisoformat(day(367))) is True
    assert reviews.overdue(agent["review_by"], dt.date.fromisoformat(day(366))) is False
    # A rejection records nothing, as before.
    other = records.create(agent_id="other-agent")[1]["registration"]["record_id"]
    assert records.submit(other)[0] == 200 and records.decide("reject", other, ANN)[0] == 200
    assert len(attestation_items(records)) == 1


# === T6: a reference into a cell carries the cell's partition ================================================

OTHER_SPELLINGS = [f"arn:{partition}:" for partition in ("aws-cn", "aws-us-gov", "aws-xyz")]


@pytest.mark.parametrize("prefix", OTHER_SPELLINGS)
@pytest.mark.parametrize(
    ("field", "arn", "what"),
    [
        ("runtime_arn", RUNTIME_ARN, "Runtime"),
        ("gateway_arn", GATEWAY_ARN, "Tool Gateway"),
    ],
)
def test_a_reference_into_a_cell_in_another_partition_is_refused_on_create_and_update(
    records, prefix, field, arn, what
):
    """The service answers for such a spelling. The portal acts on a Runtime only under the ARN it
    builds, so the registration would look registered and could not be contained by its id."""
    misspelled = arn.replace("arn:aws:", prefix, 1)
    expected = [
        {
            "loc": ["body", field],
            "msg": (
                f"{field} names a {what} in the account and Region of a configured cell, "
                "so it must begin with arn:aws: as the ARNs of that cell do"
            ),
            "type": "document",
        }
    ]
    code, body = records.create(**{field: misspelled})
    assert (code, body["detail"]) == (422, expected), body
    assert records.registry.records == {} and records.dynamo.items == {}
    # The same on an update, and nothing is written into the record's history for it.
    record_id = records.new_record("DRAFT")
    stored = dict(records.dynamo.items)
    code, body = records.update(record_id, **{field: misspelled}, business_purpose="Changed.")
    assert (code, body["detail"]) == (422, expected), body
    assert records.dynamo.items == stored and records.status(record_id) == "DRAFT"
    # Written as the cell's ARNs are, it is accepted.
    assert records.update(record_id, business_purpose="Changed.")[0] == 200


def test_the_spelling_rule_is_about_configured_cells_only(records):
    cells = load_settings(BASE_ENV).cells
    # An account and Region with no cell: nothing is known about it, so nothing is refused.
    far = UNMANAGED_RUNTIME.replace("arn:aws:", "arn:aws-cn:", 1)
    assert reference_rules.misspelled_reference({"runtimeArn": far}, cells) is None
    assert records.create(agent_id="far-agent", runtime_arn=far)[0] == 201
    # Another Region of a cell's account is no cell either.
    elsewhere = RUNTIME_ARN.replace(REGION, "us-east-1").replace("arn:aws:", "arn:aws-cn:", 1)
    assert reference_rules.misspelled_reference({"runtimeArn": elsewhere}, cells) is None
    # No reference, or something that is not an ARN: not this rule's.
    assert reference_rules.misspelled_reference({}, cells) is None
    assert reference_rules.misspelled_reference({"runtimeArn": "not an arn", "gatewayArn": None}, cells) is None
    # Every reference is looked at, in the order of the document's fields.
    found = reference_rules.misspelled_reference(
        {"runtimeArn": RUNTIME_ARN, "policyEngineArn": RUNTIME_ARN.replace("arn:aws:", "arn:aws-us-gov:", 1)}, cells
    )
    assert found is not None and found[0] == "policyEngineArn" and "policy engine" in found[1]
    # A cell of another partition: its own spelling is the right one, and "aws" the wrong one.
    china = {
        **CELLS[0],
        "readerRoleArn": CELLS[0]["readerRoleArn"].replace("arn:aws:", "arn:aws-cn:"),
        "containmentRoleArn": CELLS[0]["containmentRoleArn"].replace("arn:aws:", "arn:aws-cn:"),
    }
    there = load_settings({**BASE_ENV, "PORTAL_CELLS": json.dumps([china])}).cells
    assert reference_rules.misspelled_reference({"runtimeArn": RUNTIME_ARN}, there) == (
        "runtimeArn",
        "document.runtimeArn names a Runtime in the account and Region of a configured cell, "
        "so it must begin with arn:aws-cn: as the ARNs of that cell do",
    )
    assert (
        reference_rules.misspelled_reference({"runtimeArn": RUNTIME_ARN.replace("arn:aws:", "arn:aws-cn:")}, there)
        is None
    )


def test_the_spelling_is_said_only_to_someone_who_may_register_there(records):
    """Otherwise the answer would tell anyone who can sign in which accounts and Regions hold a cell."""
    misspelled = RUNTIME_ARN.replace("arn:aws:", "arn:aws-cn:", 1)
    # No registrar authority, and a registrar of another tenant: refused as before, for that.
    assert records.create(ANN, runtime_arn=misspelled)[0] == 403
    in_other_cell = f"arn:aws-cn:bedrock-agentcore:{REGION}:{OTHER_ACCOUNT}:runtime/claims_agent-QqQqQq1111"
    code, body = records.create(runtime_arn=in_other_cell)
    assert code == 403 and "REG-13-N" in body["detail"]  # another tenant's cell, whatever the spelling
    assert records.create(runtime_arn=misspelled)[0] == 422
    assert CELL_ACCOUNT in misspelled and records.registry.records == {}
    # The platform role may register for every tenant and is told the same.
    assert records.create(PAT, runtime_arn=misspelled)[0] == 422


# === the documents ==============================================================================================


def test_the_documents_say_what_the_first_part_does():
    actions = document("ACTIONS_CONTRACT.md")
    for said in (
        "once for each person, rule and state of the record",
        "Every approval records a review date",
        "the approval date plus 366 days",
        "must begin with the partition of that cell",
    ):
        assert said in actions, said
    assert "records nothing, so the earlier date stays" not in actions
    contract = document("CONTAINMENT_CONTRACT.md")
    for said in (
        f'"{containment_policy.FOREIGN_STATEMENT}"',
        "`sweeps_scheduled_numbers`",
        "exactly one message",
        "only the sweeps that the contain's result lists",
        f"waits for that result for up to {containment_timing.CONTAIN_RESULT_WAIT_SECONDS} seconds",
        "the agent id of the contain",
    ):
        assert said in contract, said
    for gone in ("is still run once", "does not deny invocation", "at most three events for one contain"):
        assert gone not in contract, gone
    readme = document("README.md")
    for said in (
        "once for each person, rule and state of the record",
        "`mark_once`",
        "one event for each sweep that the contain scheduled",
        "a year from the approval",
    ):
        assert said in readme, said
    iam = document("IAM_ACTIONS.md")
    for said in ("`ONCE#<hash>`", "exactly one record"):
        assert said in iam, said
