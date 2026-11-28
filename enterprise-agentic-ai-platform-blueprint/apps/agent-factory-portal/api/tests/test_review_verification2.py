# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""What the verification of the security fixes left to do, second part: the attack or the gap, and what must still work.

T7  The partition the inventory reads holds one attestation for a record, the latest. The history of
    attestations is the record's own.
T8  A release finds who holds a containment whatever number of sweeps and repeated contains were
    recorded since: every event is written once, and the ones that cannot change who holds it are
    kept out of the read that finds that person.
T9  The read API verifies the caller's token itself, so no function takes a role from the invocation event.
"""

from __future__ import annotations

import datetime as dt
import inspect
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from mangum import Mangum

import portal_api
from portal_api import containment_policy, deps, reviews
from portal_api import service as service_module
from portal_api.actions import audit_writer, containment_flow
from portal_api.actions import engine as engine_module
from portal_api.actions.engine import rule_of as engine_rule
from portal_api.app import create_app
from portal_api.aws import agentcore, registry
from portal_api.aws import audit as audit_reader
from portal_api.config import ConfigError, get_settings, load_settings
from portal_api.identity import deps as identity_deps
from portal_api.models.portal import AuditEvent
from portal_api.service import HOLDER_NOT_FOUND
from tests import test_api, test_containment, tokens
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    CELLS,
    ORPHAN_RUNTIME_ARN,
    RUNTIME_ARN,
    FakeClient,
    FakeClients,
    agent_document,
    make_service,
)
from tests.fakes import APPEND_ONLY, KEEP_LATEST, client_error
from tests.test_actions import ANN, VIEW
from tests.test_actions import PAT as RECORD_PAT
from tests.test_actions import SEC as RECORD_SEC
from tests.test_actions import World as RecordWorld
from tests.test_api import PLATFORM_CLAIMS, event, raw
from tests.test_containment import PAT, SEC, SRE, log_group, runtime_bundle, session_stream
from tests.test_evidence import decided
from tests.test_lifecycle import (
    a_day_later,
    attestation_items,
    attested,
    day,
    detail_of,
    events_of,
    kinds,
    review,
    review_state,
)
from tests.test_review_followup import FORGED, body_of, put, sweep_event
from tests.test_review_wave2 import forget, move_clock, refusals_logged, seed, stored
from tests.test_sweeps import KEY, Run, SweepWorld, again, contained, on_record

backend = test_api.backend  # the read API's fake backend
read = test_containment.read  # the read API over the same cell, record and audit table as the action functions

TABLE = BASE_ENV["PORTAL_AUDIT_TABLE"]
ROOT = Path(__file__).resolve().parent.parent
PACKAGE = Path(portal_api.__file__).resolve().parent
SOURCES = sorted(PACKAGE.rglob("*.py"))
DOCUMENTS = ("README.md", "CONTAINMENT_CONTRACT.md", "ACTIONS_CONTRACT.md", "IAM_ACTIONS.md")
PAT2 = {"sub": "pat-2", "cognito:groups": "[platform-admins]"}


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> RecordWorld:
    return RecordWorld(monkeypatch)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SweepWorld:
    return SweepWorld(monkeypatch)


def document(name: str) -> str:
    return " ".join((ROOT / name).read_text().split())


def source(relative: str) -> str:
    return (PACKAGE / relative).read_text()


# === T7: one attestation for a record where the inventory reads them ====================================
#
# The attack: a registrar and an approver of one tenant repeat update, submit, approve on one
# record, each approval with a review date and a reason of 1,000 characters. Every approval wrote
# one more item into the one partition the inventory reads, which stops after 20 pages: in hours
# the attestations of every other tenant fell outside that read, and their agents went back to the
# registration's own date, or to none.


def cycle(records: RecordWorld, record_id: str, n: int) -> None:
    """One more round on the record: the document is changed, submitted and approved."""
    assert records.update(record_id, business_purpose=f"Round {n}.", review_by=day(100 + n))[0] == 200
    assert records.submit(record_id)[0] == 200
    code, body = records.decide("approve", record_id, ANN, f"{n:04d} " + "x" * 995)
    assert code == 200 and body["audit_complete"] is True, body


def test_cycling_approvals_of_one_record_leaves_one_item_for_the_inventory_to_read(records):
    # Another tenant's record, attested once, long before.
    other = records.create(RECORD_PAT, tenant_id="ws2", agent_id="claims-agent", runtime_arn=None, review_by=day(50))
    other_id = other[1]["registration"]["record_id"]
    assert records.submit(other_id, RECORD_PAT)[0] == 200 and records.decide("approve", other_id, RECORD_SEC)[0] == 200
    record_id = records.new_record("APPROVED")
    stored_before = len(attestation_items(records))
    assert stored_before == 2

    for n in range(40):
        cycle(records, record_id, n)

    # Forty more approvals, each one an attestation in the record's own history...
    assert len(attested(records, record_id)) == 41
    # ...and still one item for the record where the inventory reads: the latest.
    items = attestation_items(records)
    assert len(items) == stored_before
    assert sorted(item["sk"] for item in items) == sorted(f"RECORD#{rid}" for rid in (record_id, other_id))
    latest = next(item for item in items if item["record_id"] == record_id)
    assert (latest["next_review_by"], latest["reason"][:14]) == (day(139), "Approved: 0039")
    assert len(latest["reason"]) == reviews.REASON_MAX == 1000
    # Nothing but that item was ever replaced, and it was replaced every time.
    assert records.dynamo.replaced == [("REVIEWS", f"RECORD#{record_id}")] * 40
    # The inventory's read is what it was before the forty: two requests, two items.
    forget(records.dynamo)
    agents = {a["id"]: a for a in records.call("read", "GET", "/agents", VIEW)[1]}
    assert records.dynamo.prefixes == [("REVIEWS", "RECORD#"), ("REVIEWS", "EVENT#")]
    assert (records.dynamo.pages_read, records.dynamo.items_read) == (2, 2)
    # And the other tenant's agent still has the date its approval recorded.
    assert agents[other_id]["review_by"] == day(50) and agents[record_id]["review_by"] == day(139)
    assert review_state(records, record_id) == (day(139), "ann@example.com")


def test_an_attestation_that_was_attested_earlier_never_takes_the_place_of_a_later_one(records, monkeypatch):
    """Two attestations at nearly the same moment can reach the table in the other order."""
    record_id = records.new_record("APPROVED")
    (approval,) = attestation_items(records)
    real = audit_writer.now_stamp
    # The review is stamped a moment before the approval was, and written after it.
    earlier = (dt.datetime.fromisoformat(approval["at"].replace("Z", "+00:00")) - dt.timedelta(seconds=1)).isoformat(
        timespec="microseconds"
    )
    stamps = iter([real(), earlier.replace("+00:00", "Z")])  # the intent, then the attestation
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: next(stamps, None) or real())
    code, body = review(records, record_id, RECORD_SEC, day(30))
    # The review is attested: its result names it, and it is in the record's history.
    assert code == 200 and body["audit_complete"] is True
    result = events_of(records, record_id, "review")[-1]
    assert (result["outcome"], result["attested_at"], result["next_review_by"]) == (
        "allowed",
        earlier.replace("+00:00", "Z"),
        day(30),
    )
    # The partition the inventory reads still holds the later one, and nothing was replaced.
    assert attestation_items(records) == [approval] and records.dynamo.replaced == []
    # Both read paths say the same: the latest attestation is the approval.
    assert kinds(records) == ["review", "approval"]  # in the order they were attested
    assert review_state(records, record_id)[1] == "ann@example.com"
    assert detail_of(records, record_id)["last_reviewed_at"] == approval["at"]


def test_an_approval_whose_attestation_is_not_the_latest_is_still_an_attestation_of_its_own(records, monkeypatch):
    record_id = records.new_record("APPROVED")
    assert review(records, record_id, RECORD_SEC, day(30))[0] == 200
    (stored_review,) = attestation_items(records)
    assert records.update(record_id, business_purpose="Changed.", review_by=day(200))[0] == 200
    assert records.submit(record_id)[0] == 200
    real = audit_writer.now_stamp
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: "2020-01-01T00:00:00.000000Z")
    code, body = records.decide("approve", record_id, ANN)
    monkeypatch.setattr(audit_writer, "now_stamp", real)
    # The approval stands and is complete: its attestation is on record in the record's history.
    assert code == 200 and body["audit_complete"] is True and records.status(record_id) == "APPROVED"
    (result,) = [
        e
        for e in events_of(records, record_id, "approve")
        if (e["request_id"], e["phase"]) == (body["request_id"], "result")
    ]
    assert (result["attested_at"], result["next_review_by"]) == ("2020-01-01T00:00:00.000000Z", day(200))
    assert "detail" not in result  # nothing failed
    assert attestation_items(records) == [stored_review]


@pytest.mark.parametrize("action", ["review", "approve"])
def test_a_write_that_failed_is_not_taken_for_a_later_attestation_being_stored(records, action):
    """Only the condition's refusal means "a later one is stored". Any other failure is a failure."""
    record_id = records.new_record("APPROVED" if action == "review" else "PENDING_APPROVAL")
    before = attestation_items(records)
    records.dynamo.fail_put_numbers = {records.dynamo._puts + 2}  # the intent, then the attestation
    if action == "review":
        code, body = review(records, record_id, RECORD_SEC)
        assert code == 503 and body["detail"] == "The review could not be recorded, so nothing was attested"
        assert events_of(records, record_id, "review")[-1]["outcome"] == "failed"
    else:
        code, body = records.decide("approve", record_id, ANN)
        assert code == 200 and body["audit_complete"] is False
        result = events_of(records, record_id, "approve")[-1]
        assert result["detail"] == "The approval stands, but its review date could not be recorded."
        assert "attested_at" not in result
    assert attestation_items(records) == before


def test_the_evidence_lists_the_attestations_of_the_records_history_and_takes_the_date_from_the_inventory(
    records, monkeypatch
):
    record_id = records.new_record("APPROVED")
    assert review(records, record_id, RECORD_SEC, day(30), "First review.")[0] == 200
    a_day_later(monkeypatch)
    assert review(records, record_id, RECORD_PAT, day(60), "Second review.")[0] == 200
    code, body = records.call("read", "GET", f"/agents/{record_id}/evidence", VIEW)
    assert code == 200, body
    listed = body["reviews"]["attestations"]
    # Every attestation, oldest first, each once: the two that the partition no longer holds as well.
    assert [(a["kind"], a["reviewed_by"], a["next_review_by"]) for a in listed] == [
        ("approval", "ann-1", day(366)),
        ("review", "sec-1", day(30)),
        ("review", "pat-1", day(60)),
    ]
    assert [a["reason"] for a in listed] == ["Approved: Reviewed and fine.", "First review.", "Second review."]
    assert [a["at"] for a in listed] == [e["attested_at"] for e in attested(records, record_id)]
    assert [a["request_id"] for a in listed] == [e["request_id"] for e in attested(records, record_id)]
    (stored_item,) = attestation_items(records)
    assert listed[-1] == {
        "kind": "review",
        "at": stored_item["at"],
        "reviewed_by": "pat-1",
        "reviewed_by_label": "pat-1",  # its email is not verified, so the subject is what is recorded
        "reviewed_by_role": "platform",
        "next_review_by": day(60),
        "reason": "Second review.",
        "request_id": stored_item["request_id"],
    }
    assert (body["reviews"]["effective_review_by"], body["reviews"]["source"]) == (day(60), "attestation")


def test_attestations_from_several_sources_are_listed_once_each():
    def one(at: str, request_id: str | None, who: str = "ann-1") -> reviews.Attestation:
        return reviews.Attestation("rec1", at, "2027-01-01", who, who, request_id=request_id)

    stored_item = one("2026-03-01T10:00:00.000000Z", "r3", "as stored")
    from_events = [
        one("2026-03-01T10:00:00.000000Z", "r3", "from its event"),
        one("2026-02-01T10:00:00.000000Z", "r2"),
        one("2026-01-01T10:00:00.000000Z", "r1"),
    ]
    merged = reviews.merged([stored_item], from_events)
    assert [(a.request_id, a.reviewed_by) for a in merged] == [("r3", "as stored"), ("r2", "ann-1"), ("r1", "ann-1")]
    # The first source that names one has it; the order is by the time of attestation, newest first.
    assert reviews.merged(from_events, [stored_item])[0].reviewed_by == "from its event"
    assert reviews.merged([], []) == [] and reviews.merged(from_events) == from_events
    # One with no request id is told apart by its time.
    assert (
        len(reviews.merged([one("2026-01-01T10:00:00.000000Z", None)], [one("2026-01-02T10:00:00.000000Z", None)])) == 2
    )
    assert (
        len(reviews.merged([one("2026-01-01T10:00:00.000000Z", None)], [one("2026-01-01T10:00:00.000000Z", None)])) == 1
    )


def reviewed_daily(records: RecordWorld, days: int) -> str:
    """A record that was submitted and approved long ago and has had its review attested every day since.

    Its history holds the submit, the approval, and for each of the last
    ``days`` days the intent and the result of a review, the latest 25
    hours ago. Returns the record's id.
    """
    document_ = json.dumps(agent_document(agentId="reviewed-daily"))
    record_id = records.registry.seed("agent-ws1-reviewed-daily-nonprod", document_, "APPROVED")
    now = dt.datetime.now(dt.UTC)

    def at(moment: dt.datetime) -> str:
        return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")

    long_before = now - dt.timedelta(days=days + 10)
    events = []
    for n, (action, who) in enumerate((("submit", "dev-1"), ("approve", "ann-1"))):
        request = {"record_id": record_id, "request_id": str(uuid.uuid4())}
        events.append(
            stored(at(long_before + dt.timedelta(hours=n)), action, "allowed", who, phase="intent", **request)
        )
        events.append(stored(at(long_before + dt.timedelta(hours=n, seconds=1)), action, "allowed", who, **request))
    for n in range(days):
        attested_at = now - dt.timedelta(days=n, hours=25)
        request = {"record_id": record_id, "request_id": str(uuid.uuid4()), "next_review_by": day(300)}
        events.append(stored(at(attested_at), "review", "allowed", "sec-1", phase="intent", **request))
        events.append(
            stored(
                at(attested_at + dt.timedelta(seconds=1)),
                "review",
                "allowed",
                "sec-1",
                attested_at=at(attested_at),
                **request,
            )
        )
    seed(records.dynamo, f"RECORD#{record_id}", events)
    return record_id


@pytest.mark.parametrize(("days", "code"), [(998, 200), (999, 409)])
def test_what_is_left_of_the_bound_on_a_records_history_is_a_review_every_day_for_years(records, days, code):
    """Since its last submit a record's history grows by two events for each review, at most one a day.

    Everything else a person can repeat without changing the record is on record once. So the
    2,000 events after which a review answers that it could not read far enough are a review on
    every single day for about two years and nine months, with no new submit in all that time.
    """
    record_id = reviewed_daily(records, days)
    answer, body = review(records, record_id, ANN)
    assert answer == code, body
    if code == 409:
        assert body["detail"] == engine_module.HISTORY_NOT_READ_FAR_ENOUGH
        assert str(audit_reader.MAX_DECISION_EVENTS) in body["detail"] and audit_reader.MAX_DECISION_EVENTS == 2000
        assert records.dynamo.items_read == audit_reader.MAX_DECISION_EVENTS


def test_one_item_and_no_other_is_ever_replaced():
    """Every other write is append-only. This is the one place a second condition is written."""
    writer = source("actions/audit_writer.py")
    assert writer.count("ConditionExpression=") == 2
    assert writer.count(f'ConditionExpression="{APPEND_ONLY}"') == 1
    assert writer.count(f'ConditionExpression="{KEEP_LATEST}"') == 1
    assert writer.count("client.put_item(") == 2 and "update_item" not in writer and "delete_item" not in writer
    # The second condition is used by one function, for one key: the latest attestation of a record.
    assert writer.count("_keep_latest(") == 2  # its definition and its one use
    body = inspect.getsource(audit_writer.put_attestation)
    assert "_keep_latest(client, table, item)" in body and "_append(" not in body
    assert '"pk": {"S": audit.REVIEWS_KEY}, "sk": {"S": audit.latest_attestation_sort_key(record_id)}' in body
    assert audit_reader.latest_attestation_sort_key("rec1") == "RECORD#rec1"
    # The value the stored time is compared with is the item's own, never one handed in beside it.
    keep = inspect.getsource(audit_writer._keep_latest)
    assert 'ExpressionAttributeNames={"#at": "at"}' in keep and 'ExpressionAttributeValues={":at": item["at"]}' in keep
    # No other module writes to the table.
    for path in SOURCES:
        if path.name != "audit_writer.py":
            assert "put_item(" not in path.read_text(), path.name


def test_what_the_documents_say_about_the_attestations():
    readme = document("README.md")
    for said in (
        "pk = REVIEWS",
        "sk = RECORD#<record id>",
        "one item for a record",
        "attribute_not_exists(#at) OR #at < :at",
        "the only item of the table that a later write may replace",
        "bounded to 20 pages",
    ):
        assert said in readme, said
    # What was true before is not said any more.
    for name in DOCUMENTS:
        text = document(name)
        assert "sk = EVENT#<UTC timestamp>#<record id>" not in text or "before" in text, name
        assert "Only the newest review attestations were read" not in text, name
        assert "An approval is not a review attestation and is not counted" not in text, name
    assert "Not every review attestation was read." in readme
    contract = document("ACTIONS_CONTRACT.md")
    assert "the latest attestation of the record" in contract
    iam = document("IAM_ACTIONS.md")
    assert "replace" in iam and "RECORD#<record id>" in iam


# === T8: who holds a containment, whatever was recorded since ============================================
#
# The gap: a release reads the Runtime's history back to the contain it undoes, and stops after
# 2,000 events. One responder who repeats a contain every sixteen minutes adds four or five events
# each time (an intent, a result, two or three sweeps), none of which says anything about who holds
# the containment. After five and a half days nobody could release the Runtime through the portal
# any more. No misuse is needed for that: an automation during a long incident does it.


def settling(world: SweepWorld) -> list[tuple[str, str, str]]:
    """(action, phase, outcome) of the events a release reads to find who holds the containment."""
    return [(e["action"], e["phase"], e["outcome"]) for e in world.dynamo.settling() if e["pk"] == KEY]


def others(world: SweepWorld) -> list[tuple[str, str, str]]:
    """(action, phase, outcome) of every other event of the Runtime's history."""
    return [(e["action"], e["phase"], e["outcome"]) for e in world.dynamo.others() if e["pk"] == KEY]


def marks(world: SweepWorld) -> list[dict[str, str]]:
    return [item for item in world.dynamo.claims() if item["sk"].startswith("ONCE#")]


def long_incident(world: SweepWorld, cycles: int, prefix: str | None = None) -> None:
    """A containment that has lasted for days.

    One contain by ``sec-1`` that holds the Runtime, and since then a
    contain repeated every sixteen minutes by ``sre-1``, each with its
    intent, its result and its two sweeps: four events a time.
    """
    contained(world, minutes_ago=16 * (cycles + 1), scheduled=2)
    for n in range(cycles):
        ago = 16 * (cycles - n)
        request_id = f"{n + 1:08x}-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
        on_record(world, request_id, minutes_ago=ago, outcome="unchanged", subject="sre-1", scheduled=2, prefix=prefix)
        for number, delay in ((2, 2), (3, 15)):
            put(world, sweep_event(request_id, number, ago - delay), prefix=prefix)


def test_a_release_finds_the_holder_after_days_of_repeated_contains_and_their_sweeps(world, caplog):
    long_incident(world, 520)  # five days and eighteen hours
    assert len(others(world)) == 2080 > audit_reader.MAX_DECISION_EVENTS and len(settling(world)) == 2
    # One more contain of it: one look at each range, one page each, however long the incident.
    forget(world.dynamo)
    assert world.post("contain", claims=PAT)[1]["outcome"] == "unchanged"
    assert world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#")]
    assert (world.dynamo.pages_read, world.dynamo.items_read) == (2, 2 + audit_reader.PAGE_SIZE)
    assert len(settling(world)) == 2
    # The person who contained it is still known, and still cannot release it.
    forget(world.dynamo)
    code, body = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in body["detail"]
    # A second person can. What that read cost: one request, for the two events of the contain.
    forget(world.dynamo)
    code, body = world.post("release", claims=PAT)
    assert (code, body["outcome"], body["state"]) == (200, "allowed", "not_contained"), body
    assert world.dynamo.prefixes == [(KEY, "EVENT#")]
    assert (world.dynamo.pages_read, world.dynamo.items_read) == (1, 2)
    assert RUNTIME_ARN not in world.cell.policies
    assert settling(world)[2:] == [("release", "intent", "allowed"), ("release", "result", "allowed")]


def test_the_same_days_in_a_history_written_before_there_were_two_ranges_still_fail_closed(world):
    """Nothing is moved: what was written into the one range stays there, and is read as it was."""
    long_incident(world, 520, prefix=audit_reader.EVENT_PREFIX)
    for claims in (PAT, SEC):
        code, body = world.post("release", claims=claims)
        assert code == 409 and body["detail"] == containment_flow.HOLDER_NOT_FOUND
    # The remedy is the documented one: the statement is removed in the cell account, and the next
    # contain is the newest event a release reads.
    del world.cell.policies[RUNTIME_ARN]
    assert world.post("contain", claims=SEC)[1]["outcome"] == "allowed"
    assert world.post("release", claims=SEC)[0] == 403
    forget(world.dynamo)
    assert world.post("release", claims=PAT)[0] == 200
    assert (world.dynamo.pages_read, world.dynamo.items_read) == (1, audit_reader.PAGE_SIZE)


def test_every_event_is_written_once_into_the_range_it_belongs_to(world, monkeypatch, caplog):
    """The whole life of one containment through the functions themselves."""
    world.cell.streams[log_group()] = [session_stream("running")]
    assert world.post("contain", claims=SEC)[1]["outcome"] == "allowed"
    run = Run(world)
    for sent in list(world.queue.messages):
        assert run.handle(sent["MessageBody"]) == "allowed"
    # Asked again at once: answered at once, with no intent.
    assert world.post("contain", claims=PAT)[1]["retry_after_seconds"] is not None
    # Asked again after the pause: it stops sessions and schedules sweeps again.
    move_clock(monkeypatch, 16)
    code, body = world.post("contain", claims=SRE)
    assert (code, body["outcome"], body["retry_after_seconds"]) == (200, "unchanged", None)
    assert body["sweeps_scheduled_in_seconds"] == [120, 900]
    # The person who contained it asks for its release, twice.
    assert world.post("release", claims=SEC)[0] == 403 and world.post("release", claims=SEC)[0] == 403
    # Someone else releases it, and then asks again.
    assert world.post("release", claims=PAT)[1]["outcome"] == "allowed"
    assert world.post("release", claims=PAT)[1]["outcome"] == "unchanged"

    assert settling(world) == [
        ("contain", "intent", "allowed"),
        ("contain", "result", "allowed"),
        ("release", "intent", "allowed"),
        ("release", "result", "allowed"),
    ]
    assert others(world) == [
        ("sweep", "result", "allowed"),
        ("sweep", "result", "allowed"),
        ("contain", "result", "unchanged"),  # answered at once
        ("contain", "intent", "allowed"),  # the contain that did its work again
        ("contain", "result", "unchanged"),
        ("release", "result", "denied"),  # once
        ("release", "intent", "allowed"),  # of a Runtime that was not contained
        ("release", "result", "unchanged"),
    ]
    # Every event is one item, under one key: nothing is written twice.
    events = [e for e in world.dynamo.events() if e["pk"] == KEY]
    assert len({e["event_id"] for e in events}) == len(events) == 12
    assert len({(e["pk"], e["sk"]) for e in events}) == 12
    for e in events:
        assert e["sk"].split("#", 1)[1] == f"{e['at']}#{e['event_id']}"
    # An intent and its result are always in the same range.
    by_request: dict[str, set[str]] = {}
    for e in events:
        if e["action"] != "sweep":
            by_request.setdefault(e["request_id"], set()).add(e["sk"].split("#", 1)[0])
    assert all(len(ranges) == 1 for ranges in by_request.values())


def test_an_attempt_that_cannot_read_the_policy_leaves_one_event_that_no_release_reads(world):
    assert world.post("contain", claims=SEC)[0] == 200
    before = len(settling(world))
    failures = {
        "the policy cannot be read": lambda: world.cell.fail.update(get_resource_policy="ThrottlingException"),
        "the role cannot be assumed": lambda: setattr(
            world.assumed, "error", client_error("AccessDenied", "AssumeRole")
        ),
    }
    for action, claims in (("contain", SRE), ("release", PAT)):
        for arrange in failures.values():
            arrange()
            written = len(world.dynamo.events())
            code, body = world.post(action, claims=claims)
            world.assumed.error = None
            assert code == 502 and "Nothing was changed" in body["detail"], body
            (event_,) = world.dynamo.events()[written:]  # one event, and no intent: nothing was about to change
            assert (event_["action"], event_["phase"], event_["outcome"]) == (action, "result", "failed")
            assert (event_["reason"], event_["request_id"]) == (body["detail"], body["request_id"])
            assert event_["sk"].startswith("OTHER#")
    # A policy that cannot be understood: the same.
    kept = world.cell.policies[RUNTIME_ARN]
    world.cell.policies[RUNTIME_ARN] = "{not json"
    for action, claims in (("contain", SRE), ("release", PAT)):
        code, body = world.post(action, claims=claims)
        assert code == 409 and "Nothing was changed" in body["detail"]
    world.cell.policies[RUNTIME_ARN] = kept
    assert len(settling(world)) == before and len(others(world)) == 6
    # None of them changed who holds the containment.
    assert world.post("release", claims=SEC)[0] == 403 and world.post("release", claims=PAT)[0] == 200


def test_an_attempt_that_fails_at_the_write_of_the_policy_is_among_the_events_a_release_reads(world, read):
    """It was about to change who holds the containment, so its intent is written where a release looks.

    What it adds there is two events for each failure, and a failure is the service's, not a choice of
    the caller's. This is what is left of the bound: a thousand such failures in a row.
    """
    world.cell.fail["put_resource_policy"] = "AccessDeniedException"
    assert world.post("contain", claims=SEC)[0] == 502
    assert settling(world) == [("contain", "intent", "allowed"), ("contain", "result", "failed")]
    assert read(world.record_id, SEC)[1]["contained_by"] is None  # nothing was written, so nobody holds anything
    assert world.post("contain", claims=SEC)[0] == 200
    # Three releases that the service refuses, then one that it accepts.
    for _ in range(3):
        world.cell.fail["delete_resource_policy"] = "AccessDeniedException"
        code, body = world.post("release", claims=PAT)
        assert code == 502 and body["detail"].endswith("The Runtime is still contained.")
    assert settling(world)[4:] == [("release", "intent", "allowed"), ("release", "result", "failed")] * 3
    assert others(world) == []
    view = read(world.record_id, SEC)[1]
    assert (view["state"], view["contained_by"]) == ("contained", "sec-1")
    assert world.post("release", claims=SEC)[0] == 403
    forget(world.dynamo)
    assert world.post("release", claims=PAT)[0] == 200
    assert world.dynamo.items_read == 10  # all of them, back to the contain: one page


def by_other_means(world: SweepWorld) -> None:
    """The portal's statement put into the Runtime's policy in the cell account, not through the portal."""
    world.cell.policies[RUNTIME_ARN] = containment_policy.with_containment(
        None, RUNTIME_ARN, containment_policy.ALL_INVOKE_ACTIONS
    )


def test_the_first_to_assert_a_containment_holds_it_and_is_on_record_where_a_release_looks(world, monkeypatch, read):
    """A Runtime contained by other means, with nobody on record as holding it."""
    by_other_means(world)
    code, body = world.post("contain", claims=SEC)
    assert (code, body["outcome"], body["changed"]) == (200, "unchanged", False)
    # This contain changed nothing in the policy, and it is the one that names the holder.
    assert settling(world) == [("contain", "intent", "allowed"), ("contain", "result", "unchanged")]
    assert others(world) == []
    view = read(world.record_id, PAT)[1]
    assert (view["state"], view["contained_by"]) == ("contained", "sec-1")
    # Whoever contains it again, at once or after the pause, changes nothing about that.
    assert world.post("contain", claims=PAT)[1]["retry_after_seconds"] is not None
    move_clock(monkeypatch, 47)
    assert world.post("contain", claims=PAT)[1]["outcome"] == "unchanged"
    assert len(settling(world)) == 2
    assert others(world) == [
        ("contain", "result", "unchanged"),
        ("contain", "intent", "allowed"),
        ("contain", "result", "unchanged"),
    ]
    assert world.post("release", claims=SEC)[0] == 403
    assert world.post("release", claims=PAT)[0] == 200
    # Released, and put back by other means: the next to assert it holds it.
    by_other_means(world)
    assert world.post("contain", claims=PAT)[1]["outcome"] == "unchanged"
    assert settling(world)[4:] == [("contain", "intent", "allowed"), ("contain", "result", "unchanged")]
    assert world.post("release", claims=PAT)[0] == 403
    assert world.post("release", claims=SEC)[0] == 200


def before_two_ranges(world: SweepWorld, first: AuditEvent, sweeps_since: int) -> None:
    """A history written before there were two ranges: one event, and sweeps on top of it in the same range."""
    seed(
        world.dynamo,
        KEY,
        [first, *[stored(long_ago_plus(n), "sweep", "skipped", "agent-factory-portal") for n in range(sweeps_since)]],
    )


def long_ago_plus(n: int) -> str:
    return f"2025-03-02T{n // 3600:02d}:{n // 60 % 60:02d}:{n % 60:02d}.000000Z"


def test_when_the_newest_events_do_not_say_who_holds_it_the_contain_reads_as_a_release_would(world):
    """More sweeps at the top of an old history than the contain's one look takes in."""
    # Released long ago, 250 sweeps recorded after that, and the statement is back by other means.
    before_two_ranges(world, stored("2025-03-01T00:00:00.000000Z", "release", "allowed", "old-timer"), 250)
    by_other_means(world)
    forget(world.dynamo)
    assert world.post("contain", claims=SEC)[1]["outcome"] == "unchanged"
    # One look at each range, which did not settle it, and then the read a release makes: two pages.
    assert world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#"), (KEY, "EVENT#")]
    assert world.dynamo.pages_read == 4 and world.dynamo.items_read == 200 + 251
    # Nobody held it, so this person does, on record where a release looks.
    assert settling(world)[-2:] == [("contain", "intent", "allowed"), ("contain", "result", "unchanged")]
    assert world.post("release", claims=SEC)[0] == 403 and world.post("release", claims=PAT)[0] == 200


def test_when_someone_older_holds_it_a_contain_of_the_contained_runtime_adds_nothing_a_release_reads(world):
    held = stored("2025-03-01T00:00:00.000000Z", "contain", "allowed", "old-timer", tenant_id="ws1")
    before_two_ranges(world, held, 250)
    by_other_means(world)
    written = len(settling(world))
    assert world.post("contain", claims=SEC)[1]["outcome"] == "unchanged"
    assert len(settling(world)) == written and others(world) == [
        ("contain", "intent", "allowed"),
        ("contain", "result", "unchanged"),
    ]
    # The holder is who it was, so the person who contained it again may release it.
    assert world.post("release", claims=SEC)[0] == 200


def test_a_history_that_settles_nothing_gets_no_longer_by_contains_of_a_contained_runtime(world):
    """Past the bound a release is refused whatever is written, so nothing is added to what it reads."""
    before_two_ranges(world, stored("2025-03-01T00:00:00.000000Z", "release", "allowed", "old-timer"), 2100)
    by_other_means(world)
    written = len(settling(world))
    for claims in (SEC, PAT, SRE):
        assert world.post("contain", claims=claims)[1]["outcome"] == "unchanged"
    assert len(settling(world)) == written
    assert world.post("release", claims=PAT)[1]["detail"] == containment_flow.HOLDER_NOT_FOUND
    # A contain that writes the statement is another matter: it is what a release looks for.
    del world.cell.policies[RUNTIME_ARN]
    assert world.post("contain", claims=SEC)[1]["outcome"] == "allowed"
    assert len(settling(world)) == written + 2


def test_a_contain_that_cannot_read_the_history_is_on_record_where_a_release_looks(world, monkeypatch):
    by_other_means(world)
    world.dynamo.fail_query = True
    assert world.post("contain", claims=SEC)[1]["outcome"] == "unchanged"
    world.dynamo.fail_query = False
    assert settling(world) == [("contain", "intent", "allowed"), ("contain", "result", "unchanged")]
    assert world.post("release", claims=SEC)[0] == 403
    # The second look failing is the same: the first did not settle it, and the read a release makes failed.
    world.dynamo.items.clear()
    before_two_ranges(world, stored("2025-03-01T00:00:00.000000Z", "release", "allowed", "old-timer"), 250)
    real = audit_reader.read_holder

    def unreadable(*args: Any, **kwargs: Any) -> Any:
        raise client_error("InternalServerError", "Query")

    monkeypatch.setattr(audit_reader, "read_holder", unreadable)
    assert world.post("contain", claims=PAT)[1]["outcome"] == "unchanged"
    monkeypatch.setattr(audit_reader, "read_holder", real)
    assert settling(world)[-2:] == [("contain", "intent", "allowed"), ("contain", "result", "unchanged")]
    assert world.post("release", claims=PAT)[0] == 403


def test_an_intent_among_the_other_events_neither_names_nor_clears_a_holder(world, monkeypatch, read):
    """An intent whose result was lost counts as its result would have, where a release reads.

    Among the other events it counts for nothing: a contain of a contained Runtime never replaces
    the holder, and a release of a Runtime that is not contained releases nothing.
    """
    assert world.post("contain", claims=SEC)[0] == 200
    move_clock(monkeypatch, 47)
    # A repeated contain whose result is lost.
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 2}
    code, body = world.post("contain", claims=PAT)
    assert (code, body["outcome"], body["audit_complete"]) == (200, "unchanged", False)
    assert others(world) == [("contain", "intent", "allowed")]
    assert read(world.record_id, PAT)[1]["contained_by"] == "sec-1"
    assert world.post("release", claims=SEC)[0] == 403
    # The statement is removed by other means, and a release that finds nothing loses its result.
    del world.cell.policies[RUNTIME_ARN]
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 2}
    code, body = world.post("release", claims=PAT)
    assert (code, body["outcome"], body["audit_complete"]) == (200, "unchanged", False)
    assert others(world)[-1] == ("release", "intent", "allowed")
    # The statement comes back by other means. The person who contained the Runtime is still its holder.
    by_other_means(world)
    assert read(world.record_id, PAT)[1]["contained_by"] == "sec-1"
    assert world.post("release", claims=SEC)[0] == 403
    # Read as one list, as a history from before the two ranges would be, the same events say otherwise:
    # which is why who holds a containment is decided on the first range alone.
    history = audit_reader.read_history(world.dynamo, TABLE, RUNTIME_ARN)
    assert history.holder.event is not None and history.holder.event.actor_subject == "sec-1"
    assert audit_reader.container(history.events) is None
    assert world.post("release", claims=PAT)[0] == 200


def test_a_refused_release_is_on_record_once_for_each_person_rule_and_containment(world, caplog):
    assert world.post("contain", claims=SEC)[0] == 200
    with caplog.at_level("WARNING", logger="portal_api.actions.containment_flow"):
        answers = [world.post("release", claims=SEC) for _ in range(50)]
    assert {code for code, _ in answers} == {403} and len({body["request_id"] for _, body in answers}) == 50
    assert others(world) == [("release", "result", "denied")] and len(marks(world)) == 1
    assert len([m for m in caplog.messages if "already on record, not written again" in m]) == 49
    (mark,) = marks(world)
    holder = world.dynamo.settling()[-1]
    assert (mark["pk"], mark["kind"], mark["state"]) == (KEY, "once", holder["event_id"])
    assert (mark["actor_subject"], mark["action"], mark["rule"]) == ("sec-1", "release", "CON-03-N")
    assert mark["request_id"] == answers[0][1]["request_id"] == world.dynamo.others()[-1]["request_id"]
    # It needs no read of what was recorded since: a refusal reads what a release reads, and no more.
    forget(world.dynamo)
    assert world.post("release", claims=SEC)[0] == 403
    assert world.dynamo.prefixes == [(KEY, "EVENT#")] and world.dynamo.calls == ["query", "put_item"]
    # Another containment of the same Runtime by the same person is another matter: once again.
    assert world.post("release", claims=PAT)[0] == 200 and world.post("contain", claims=SEC)[0] == 200
    for _ in range(5):
        assert world.post("release", claims=SEC)[0] == 403
    assert [o for o in others(world) if o == ("release", "result", "denied")] == [("release", "result", "denied")] * 2
    assert len(marks(world)) == 2


def test_once_is_for_each_rule_as_well(world, monkeypatch):
    """One person, one containment, two rules: each refusal is on record once."""
    shared = {**CELLS[0], "tenantId": "ws9", "agentId": "second-agent"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([CELLS[0], CELLS[1], shared]))
    roles = {**json.loads(BASE_ENV["PORTAL_GROUP_ROLE_MAP"]), "sec19": "security"}
    tenants = {**json.loads(BASE_ENV["PORTAL_GROUP_TENANT_MAP"]), "sec19": ["ws1", "ws9"]}
    monkeypatch.setenv("PORTAL_GROUP_ROLE_MAP", json.dumps(roles))
    monkeypatch.setenv("PORTAL_GROUP_TENANT_MAP", json.dumps(tenants))
    both = {"sub": "sec-both", "cognito:groups": "[sec19]"}
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws1"}
    assert world.post("contain", claims=both)[0] == 200
    for tenant, rule in (("ws9", "CON-06-N"), ("ws1", "CON-03-N"), ("ws9", "CON-06-N"), ("ws1", "CON-03-N")):
        world.cell.tags[RUNTIME_ARN] = {"tenant-id": tenant}
        code, body = world.post("release", claims=both)
        assert code == 403 and rule in body["detail"]
    denied = [e for e in world.dynamo.others() if e["outcome"] == "denied"]
    assert [engine_rule(e["reason"]) for e in denied] == ["CON-06-N", "CON-03-N"]
    assert sorted(mark["rule"] for mark in marks(world)) == ["CON-03-N", "CON-06-N"]


def test_a_refusal_whose_mark_cannot_be_written_is_logged_and_not_recorded(world, caplog):
    assert world.post("contain", claims=SEC)[0] == 200
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 1}
    with caplog.at_level("WARNING", logger="portal_api.actions.containment_flow"):
        code, body = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in body["detail"] and body["request_id"]
    assert others(world) == [] and marks(world) == []
    assert len(refusals_logged(caplog)) == 1 and body["request_id"] in caplog.text
    # The next one is recorded.
    assert world.post("release", claims=SEC)[0] == 403
    assert others(world) == [("release", "result", "denied")] and len(marks(world)) == 1


def test_the_view_names_the_holder_and_lists_the_newest_events_of_both_ranges(world, read):
    long_incident(world, 520)
    forget(world.dynamo)
    code, view = read(world.record_id, PAT)
    assert code == 200
    # Before, this said that who contained the agent could not be established.
    assert (view["state"], view["contained_by"], view["contained_by_me"], view["detail"]) == (
        "contained",
        "sec-1",
        False,
        None,
    )
    assert view["contained_at"] == world.dynamo.settling()[-1]["at"]
    # The newest 200 events of the two ranges together, newest first.
    limit = audit_reader.MAX_VIEW_EVENTS
    assert len(view["events"]) == limit and view["events_truncated"] is True
    newest = sorted(world.dynamo.events(), key=lambda e: (e["at"], e["event_id"]), reverse=True)[:limit]
    assert [e["event_id"] for e in view["events"]] == [e["event_id"] for e in newest]
    assert {e["action"] for e in view["events"]} == {"contain", "sweep"}
    # Both reads are bounded: the two events of the contain, and no more of the others than a decision reads.
    assert world.dynamo.prefixes[-2:] == [(KEY, "EVENT#"), (KEY, "OTHER#")]
    page_size = limit + 1
    assert world.dynamo.items_read == 2 + page_size * 10  # ten pages of the others, to the bound
    # The sweeps counted are those of the events that were read, and never more done than scheduled.
    assert 0 < view["sweeps"]["done"] <= view["sweeps"]["scheduled"] <= 2 * 520
    assert read(world.record_id, SEC)[1]["contained_by_me"] is True
    # A role that is not shown the incident record still sees the state and since when.
    other = read(world.record_id, VIEW)[1]
    assert (other["state"], other["contained_by"], other["events"], other["contained_at"]) == (
        "contained",
        None,
        [],
        view["contained_at"],
    )


def test_the_view_reads_the_other_events_back_to_the_containment_that_holds_and_no_further(world, read):
    """An earlier containment left hundreds of sweeps behind. The one that holds began a moment ago."""
    earlier = contained(world, minutes_ago=3000, scheduled=2)
    for n in range(300):
        request_id = f"{n + 1:08x}-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
        on_record(world, request_id, minutes_ago=2990 - n, outcome="unchanged", subject="sre-1", scheduled=2)
    on_record(world, FORGED, minutes_ago=100, action="release", subject="pat-1")
    del world.cell.policies[RUNTIME_ARN]
    assert world.post("contain", claims=SEC)[0] == 200
    assert world.post("contain", claims=PAT)[1]["retry_after_seconds"] is not None  # one event among the others
    forget(world.dynamo)
    view = read(world.record_id, PAT)[1]
    assert (view["contained_by"], view["sweeps"], view["events_truncated"]) == (
        "sec-1",
        {"scheduled": 2, "done": 0},
        True,
    )
    assert earlier not in {e["request_id"] for e in view["events"][:3]}
    # Of the other events it read one page: far enough to list the newest 200 of the two ranges
    # together, and past the event that began this containment. Not the 600 of the earlier one.
    limit = audit_reader.MAX_VIEW_EVENTS
    assert world.dynamo.prefixes[-2:] == [(KEY, "EVENT#"), (KEY, "OTHER#")]
    assert world.dynamo.pages_read == 2 + 2  # two of the attestations, one of each range of the history
    assert world.dynamo.items_read == 6 + (limit + 1)  # the six events a release reads, and one page of the others


def test_the_view_of_a_short_containment_is_whole_and_in_order(world, read, monkeypatch):
    world.cell.streams[log_group()] = [session_stream("running")]
    assert world.post("contain", claims=SEC)[0] == 200
    run = Run(world)
    for sent in list(world.queue.messages):
        assert run.handle(sent["MessageBody"]) == "allowed"
    assert world.post("release", claims=SEC)[0] == 403
    view = read(world.record_id, PAT)[1]
    assert [(e["action"], e["phase"], e["outcome"]) for e in view["events"]] == [
        ("release", "result", "denied"),
        ("sweep", "result", "allowed"),
        ("sweep", "result", "allowed"),
        ("contain", "result", "allowed"),
        ("contain", "intent", "allowed"),
    ]
    assert view["events_truncated"] is False and view["sweeps"] == {"scheduled": 2, "done": 2}
    assert view["partial"] is False and view["contained_by"] == "sec-1"
    # After a release the earlier containment's sweeps are not counted for the next one.
    assert world.post("release", claims=PAT)[0] == 200
    assert world.post("contain", claims=PAT)[0] == 200
    view = read(world.record_id, SEC)[1]
    assert (view["contained_by"], view["sweeps"], view["quiet_at"]) == ("pat-1", {"scheduled": 2, "done": 0}, None)
    assert len(view["events"]) == 9


def test_what_reads_both_ranges_never_decides_the_holder_on_them_together():
    """``holder`` takes the events that can settle it and no others. One place puts the two ranges together."""
    audit = source("aws/audit.py")
    # Inside the reader: on the first range's own events, never on the merged list.
    uses = [use for use in re.findall(r"\bholder\(([^)]*)\)", audit) if ":" not in use]  # not its own definition
    assert uses == ["events", "events", "trail.events", "settling.events"]
    assert "found = holder(settling.events)" in inspect.getsource(audit_reader._history)
    # Outside it nobody works out a holder from events: they ask for a history, or for the holder.
    for path in SOURCES:
        text = path.read_text()
        if path.name == "audit.py":
            continue
        assert not re.search(r"audit_reader\.(holder|container)\(", text), path.name
        assert not re.search(r"\baudit\.(holder|container)\(", text), path.name
    # A release decides on the first range alone, and the others are read only where a list is needed.
    flow = source("actions/containment_flow.py")
    assert flow.count("audit_reader.read_holder(") == 2 and flow.count("audit_reader.read_newest(") == 1
    assert "read_history" not in flow and "read_for_sweep" not in flow
    assert inspect.getsource(audit_reader.read_holder).count("prefix=") == 0  # the default: the first range
    for reader in (audit_reader.read_history, audit_reader.read_newest, audit_reader.read_for_sweep):
        assert inspect.getsource(reader).count("prefix=OTHER_PREFIX") == 1
    # And every read of either range still goes through the one bounded function.
    assert audit.count("_pages(") == 4 and audit.count("for page in _pages(") == 3


def test_every_event_of_the_containment_function_and_of_the_sweeper_names_its_range():
    flow = source("actions/containment_flow.py")
    # One place writes, and every caller says which range.
    assert flow.count("audit_writer.put_event(") == 1 and flow.count("audit_writer.mark_once(") == 1
    # A refusal, an intent, a result, a failure, and a contain that is answered at once.
    calls = re.findall(r"self\._write\(target, [^\n]*", flow)
    assert len(calls) == 5
    assert all(call.rstrip().endswith(("settles)", "settles=False)", "settles):")) for call in calls), calls
    assert "prefix = audit_reader.EVENT_PREFIX if settles else audit_reader.OTHER_PREFIX" in flow
    # The sweeper writes into the second range only.
    swept = source("actions/sweeper.py")
    assert swept.count("audit_writer.put_event(") == 1 and "prefix=audit_reader.OTHER_PREFIX" in swept
    # A record's history has one range: the registration functions name none.
    assert "prefix=" not in source("actions/engine.py")
    assert (audit_reader.EVENT_PREFIX, audit_reader.OTHER_PREFIX) == ("EVENT#", "OTHER#")
    event_ = AuditEvent(
        event_id="e1",
        request_id="r1",
        at="2026-01-01T00:00:00.000000Z",
        phase="result",
        action="sweep",
        outcome="allowed",
        reason="x",
        actor_subject="s",
        actor_label="l",
        actor_role="system",
    )
    assert audit_reader.event_sort_key(event_) == "EVENT#2026-01-01T00:00:00.000000Z#e1"
    assert audit_reader.event_sort_key(event_, audit_reader.OTHER_PREFIX) == "OTHER#2026-01-01T00:00:00.000000Z#e1"


# --- the sweeper over two ranges ------------------------------------------------------------------------


def test_a_sweep_finds_its_contain_in_either_range_and_writes_among_the_other_events(world):
    world.cell.streams[log_group()] = [session_stream("a")]
    first = contained(world, minutes_ago=60)
    repeated = again(world, minutes_ago=30)
    run = Run(world)
    forget(world.dynamo)
    # The contain that holds the Runtime: found among the events a release reads.
    assert run.handle(body_of(2, first)) == "allowed"
    assert world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#")]
    # A contain of the contained Runtime: found among the others.
    assert run.handle(body_of(2, repeated)) == "allowed"
    assert [e["request_id"] for e in run.sweep_events()] == [first, repeated]
    assert all(e["sk"].startswith("OTHER#") for e in run.sweep_events())
    assert len(settling(world)) == 2  # nothing was added to what a release reads
    # Each is found again by the next delivery, and not run twice.
    assert run.handle(body_of(2, first)) == "repeated" and run.handle(body_of(2, repeated)) == "repeated"


def test_a_sweep_of_a_contain_whose_holder_cannot_be_told_is_run_and_the_policy_has_the_last_word(world):
    """More events that settle nothing than a sweep reads: nothing read says the contain was undone."""
    seed(
        world.dynamo,
        KEY,
        [stored(long_ago_plus(n), "release", "failed", "someone", status_after="contained") for n in range(2100)],
    )
    by_other_means(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    repeated = again(world, minutes_ago=30)
    run = Run(world)
    assert run.handle(body_of(2, repeated)) == "allowed"
    assert len(world.cell.stopped) == 1
    # With the statement gone it stops nothing, as ever.
    del world.cell.policies[RUNTIME_ARN]
    assert run.handle(body_of(3, repeated)) == "skipped"
    assert len(world.cell.stopped) == 1


def test_an_intent_among_the_other_events_is_not_taken_by_the_sweeper_for_a_release_or_a_contain(world):
    world.cell.streams[log_group()] = [session_stream("a")]
    first = contained(world, minutes_ago=60)
    # A release of the Runtime while its statement was gone, whose result was lost: an intent, and nothing after it.
    on_record(world, FORGED, minutes_ago=20, action="release", result=False, prefix=audit_reader.OTHER_PREFIX)
    run = Run(world)
    assert run.handle(body_of(3, first)) == "allowed"  # not "skipped": the Runtime was not released
    assert len(world.cell.stopped) == 1


# --- the page of one agent ------------------------------------------------------------------------------


def test_the_page_of_an_agent_finds_a_contain_under_any_number_of_sweeps(backend, monkeypatch):
    """It asks for the newest events that can change what the page shows: the sweeps are not among them."""
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    control = clients.clients[(CELL_ACCOUNT, "bedrock-agentcore-control")]
    key = audit_reader.containment_key(RUNTIME_ARN)
    control.runtimes[0]["detail"]["contained"] = False
    service.cache.clear()

    def page() -> dict[str, Any]:
        status, body, _ = raw(backend, "/agents/recAgent0001", claims=PLATFORM_CLAIMS)
        assert status == 200
        return json.loads(body)

    assert page()["flags"]["contained"] is False
    control.runtimes[0]["detail"]["contained"] = True  # what the next read of the Runtime's policy finds
    decided(table, "contain", "contained", partition=key, agent_id="recAgent0001")
    for n in range(300):
        swept = AuditEvent(
            event_id=f"sweep-{n:04d}",
            request_id=str(uuid.uuid4()),
            at=audit_writer.now_stamp(),
            phase="result",
            action="sweep",
            outcome="allowed",
            reason="x",
            actor_subject="s",
            actor_label="l",
            actor_role="system",
        )
        audit_writer.put_event(table, TABLE, key, swept, prefix=audit_reader.OTHER_PREFIX)
    asked = len(table.prefixes)
    assert page()["flags"]["contained"] is True
    assert (key, "OTHER#") not in table.prefixes[asked:] and (key, "EVENT#") in table.prefixes[asked:]
    assert service_module.DECISION_CHECK_EVENTS == 20


def test_what_the_documents_say_about_the_two_ranges():
    contract = document("CONTAINMENT_CONTRACT.md")
    for said in (
        "`EVENT#`",
        "`OTHER#`",
        "Every event is written once",
        "whatever number of sweeps and repeated contains",
        "two events for each such failure",
        "written before there were two ranges",
        "once for each person, rule and containment",
    ):
        assert said in contract, said
    assert containment_flow.HOLDER_NOT_FOUND in contract and HOLDER_NOT_FOUND in contract
    readme = document("README.md")
    for said in ("`OTHER#`", "sk = OTHER#<UTC timestamp>#<event id>", "does not grow with the sweeps"):
        assert said in readme, said
    iam = document("IAM_ACTIONS.md")
    assert "`OTHER#`" in iam and "`ONCE#" in iam
    # The arithmetic that was wrong is gone from every document.
    for name in DOCUMENTS:
        assert "adds one per person in fifteen minutes" not in document(name), name


# === T9: no function takes a role from the invocation event =============================================
#
# The gap: the read API took the caller from the claims Amazon API Gateway puts into the event. A
# principal that can invoke the read function directly writes the whole event, so it could claim
# the security role and be shown an incident record: who contained an agent, why, and the events.


@pytest.fixture
def reader(world, monkeypatch):
    """The read function over the containment world, with the event's claims and the token set apart."""
    record = {**world.registry.records[world.record_id]}
    monkeypatch.setattr(registry, "list_records", lambda client, registry_id: [record])
    monkeypatch.setattr(
        agentcore, "list_runtimes", lambda client: [runtime_bundle(), runtime_bundle(ORPHAN_RUNTIME_ARN, tags={})]
    )
    monkeypatch.setattr(agentcore, "list_gateways", lambda client: [])
    clients = FakeClients(
        {
            ("platform", "agent-registry-control"): FakeClient(),
            ("platform", "dynamodb"): world.dynamo,
            (CELL_ACCOUNT, "bedrock-agentcore-control"): world.cell,
        }
    )
    application = create_app()
    application.dependency_overrides[deps.get_service] = lambda: make_service(get_settings(), clients)
    handler = Mangum(application, lifespan="off")

    def send(
        path: str,
        *,
        context_claims: dict[str, Any] | None = None,
        authorization: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        request = event(path, "GET", None, headers=headers)
        if context_claims is not None:
            request["requestContext"]["authorizer"] = {"jwt": {"claims": context_claims, "scopes": []}}
        if authorization is not None:
            request["headers"]["authorization"] = authorization
        response = handler(request, None)
        try:
            return response["statusCode"], json.loads(response["body"])
        except ValueError:
            return response["statusCode"], response["body"]

    send.application = application  # type: ignore[attr-defined]
    return send


def bearer(claims: dict[str, Any], **changes: Any) -> str:
    return f"Bearer {tokens.sign(claims, **changes)}"


def test_a_role_claimed_in_the_event_is_shown_no_incident_record(world, reader):
    assert world.post("contain", claims=SEC, body={"reason": "Suspected prompt injection."})[0] == 200
    incident = f"/agents/{world.record_id}/containment"
    world.dynamo.calls.clear()
    world.cell.calls.clear()
    # What a principal that invokes the function directly sends: claims of its own making, and no token.
    for forged in (SEC, PAT, {"sub": "anyone", "cognito:groups": "[sec]"}):
        for path in (incident, f"/agents/{world.record_id}/evidence", "/agents", "/registrations", "/users/me"):
            assert reader(path, context_claims=forged) == (401, {"detail": "Not authenticated"}), path
    assert world.dynamo.calls == [] and world.cell.calls == []  # and nothing was read for it
    # The same claims beside a viewer's genuine token: the token decides, and a viewer is not shown the record.
    code, view = reader(incident, context_claims=SEC, authorization=bearer(VIEW))
    assert code == 200 and view["state"] == "contained"
    assert (view["contained_by"], view["contained_by_label"], view["reason"], view["events"]) == (None, None, None, [])
    code, me = reader("/users/me", context_claims=PAT, authorization=bearer(VIEW))
    assert code == 200 and (me["oid"], me["portal_role"]) == ("view-1", "readonly")
    code, document_ = reader(f"/agents/{world.record_id}/evidence", context_claims=SEC, authorization=bearer(VIEW))
    assert code == 200 and document_["containment"]["details_shown"] is False
    assert document_["containment"]["contained_by"] is None and document_["containment"]["events"] == []
    assert document_["generated_by"]["role"] == "readonly"
    # And the other way round: a responder's own token, whatever the event says about it.
    code, view = reader(incident, context_claims=VIEW, authorization=bearer(SEC))
    assert code == 200 and (view["contained_by"], view["contained_by_me"]) == ("sec-1", True)
    assert view["reason"].startswith("Suspected prompt injection.") and len(view["events"]) == 2


def test_every_route_of_the_read_api_but_the_liveness_probe_asks_for_the_token(reader):
    paths = sorted(reader.application.openapi()["paths"])
    assert len(paths) > 25 and "/api/v1/health" in paths
    forged = {"sub": "pat-1", "cognito:groups": "[platform-admins]"}
    for template in paths:
        path = re.sub(r"\{[a-z_]+\}", "recAgent0001", template.removeprefix("/api/v1"))
        code, body = reader(path, context_claims=forged)
        if template == "/api/v1/health":
            assert (code, body) == (200, {"status": "ok"})
        else:
            assert (code, body) == (401, {"detail": "Not authenticated"}), template


def test_a_token_the_read_api_cannot_accept_is_401_whatever_the_event_claims(world, reader, caplog):
    now = int(time.time())
    bad = {
        "signed by another key": tokens.sign(SEC, key=tokens.private_key("attacker")),
        "expired": tokens.sign(SEC, exp=now - 3600),
        "for another audience": tokens.sign(SEC, aud="another-client"),
        "from another issuer": tokens.sign(SEC, iss="https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHERPOOL"),
        "an access token": tokens.sign(SEC, token_use="access"),
        "no subject": tokens.sign(SEC, sub=...),
        "unknown key": tokens.sign(SEC, kid="invented", key=tokens.private_key("attacker")),
    }
    path = f"/agents/{world.record_id}/containment"
    for token in bad.values():
        with caplog.at_level("WARNING", logger="portal_api.identity.deps"):
            caplog.clear()
            answer = reader(path, context_claims=SEC, authorization=f"Bearer {token}")
        assert answer == (401, {"detail": "Not authenticated"})  # the caller is told nothing more
        logged = " ".join(record.getMessage() for record in caplog.records)
        assert "Bearer token not accepted" in logged and token not in logged
    for header in ("", "Bearer", "Basic dXNlcjpwYXNz", "Bearer a b", "Token abc"):
        assert reader(path, context_claims=SEC, authorization=header)[0] == 401
    assert reader(path, authorization=bearer(SEC).replace("Bearer", "bearer"))[0] == 200  # the scheme's case


def test_when_the_issuers_keys_cannot_be_had_the_read_api_answers_503_and_reads_nothing(world, reader, issuer_keys):
    def unreachable(url: str) -> dict[str, Any]:
        raise OSError("no route to the issuer")

    issuer_keys.answer[0] = unreachable
    code, body = reader(f"/agents/{world.record_id}/containment", context_claims=SEC, authorization=bearer(SEC))
    assert (code, body) == (503, {"detail": identity_deps.KEYS_UNAVAILABLE})
    assert world.dynamo.calls == [] and world.cell.calls == []
    assert reader("/health") == (200, {"status": "ok"})


def read_env(**changes: Any) -> dict[str, str]:
    env = {**BASE_ENV, **{k: v for k, v in changes.items() if v is not None}}
    return {k: v for k, v in env.items() if changes.get(k, "") is not None}


def test_the_read_function_needs_the_token_settings_and_fails_closed_without_them(world, reader, monkeypatch):
    token = load_settings(read_env()).token
    assert token is not None and (token.issuer, token.audiences, token.token_use) == (
        tokens.ISSUER,
        (tokens.AUDIENCE,),
        "id",
    )
    lambda_env = {"AWS_LAMBDA_FUNCTION_NAME": "portal-read", "PORTAL_DEV_AUTH": "1"}
    for name in ("PORTAL_JWT_ISSUER", "PORTAL_JWT_AUDIENCE"):
        for extra in ({}, lambda_env):  # the development switch does not lift it inside AWS Lambda
            with pytest.raises(ConfigError, match=name):
                load_settings(read_env(**{name: None}, **extra))
    # With Microsoft Entra ID the address of the key set is needed as well.
    tenant = "00000000-0000-0000-0000-000000000000"
    entra = {
        "PORTAL_IDENTITY_PROVIDER": "entra",
        "PORTAL_JWT_ISSUER": f"https://login.microsoftonline.com/{tenant}/v2.0",
        "PORTAL_JWT_AUDIENCE": '["api://portal"]',
    }
    with pytest.raises(ConfigError, match="PORTAL_JWKS_URL"):
        load_settings(read_env(**entra))
    jwks = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
    assert load_settings(read_env(**entra, PORTAL_JWKS_URL=jwks)).token.jwks_url == jwks
    # Through the function: every data route refuses, with a genuine token and with none, and nothing is read.
    monkeypatch.delenv("PORTAL_JWT_ISSUER")
    world.dynamo.calls.clear()
    for path in (f"/agents/{world.record_id}/containment", "/agents", "/users/me"):
        for authorization in (bearer(SEC), None):
            code, body = reader(path, context_claims=SEC, authorization=authorization)
            assert code == 500 and "PORTAL_JWT_ISSUER" in body["detail"], body
    assert world.dynamo.calls == [] and world.cell.calls == []
    assert reader("/health") == (200, {"status": "ok"})  # the probe touches no configuration


def test_the_header_identity_of_local_development_is_never_taken_inside_lambda_by_the_read_api(reader, monkeypatch):
    monkeypatch.setenv("PORTAL_DEV_AUTH", "1")
    headers = {"x-portal-dev-user": "sec@example.com", "x-portal-dev-groups": "sec"}
    code, me = reader("/users/me", headers=headers)
    assert code == 200 and me["portal_role"] == "security"
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "portal-read")
    assert reader("/users/me", headers=headers) == (401, {"detail": "Not authenticated"})
    # Local development needs no token settings, as long as none is set; half set is a mistake.
    env = {k: v for k, v in BASE_ENV.items() if not k.startswith(("PORTAL_JWT", "PORTAL_JWKS"))}
    assert load_settings({**env, "PORTAL_DEV_AUTH": "1"}).token is None
    with pytest.raises(ConfigError, match="PORTAL_JWT_AUDIENCE"):
        load_settings({**env, "PORTAL_DEV_AUTH": "1", "PORTAL_JWT_ISSUER": tokens.ISSUER})


def test_an_app_only_token_of_microsoft_entra_id_is_no_caller_of_the_read_api(reader, monkeypatch):
    tenant = "00000000-0000-0000-0000-000000000000"
    issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
    monkeypatch.setenv("PORTAL_IDENTITY_PROVIDER", "entra")
    monkeypatch.setenv("PORTAL_JWT_ISSUER", issuer)
    monkeypatch.setenv("PORTAL_JWT_AUDIENCE", '["api://portal"]')
    monkeypatch.setenv("PORTAL_JWKS_URL", f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys")
    person = {"oid": "oid-1", "preferred_username": "sec@example.com", "name": "Sec", "roles": ["sec"]}
    signed = {"iss": issuer, "aud": "api://portal", "token_use": ...}
    code, me = reader("/users/me", authorization=bearer(person, **signed))
    assert code == 200 and me["portal_role"] == "security"
    # A token an application got for itself names no person, whatever roles it carries.
    for app_only in ({"idtyp": "app"}, {"azp": "client-1", "azpacr": "1"}, {"azp": "client-1", "scp": ""}):
        token = bearer({**person, **app_only}, **signed)
        assert reader("/users/me", authorization=token) == (401, {"detail": "Not authenticated"})


def test_no_source_reads_who_the_caller_is_from_the_event():
    for path in SOURCES:
        text = path.read_text()
        for trace in ('"authorizer"', "jwt_claims", '["claims"]', '.get("claims")'):
            assert trace not in text, (path.name, trace)
        # The event itself is looked at in one place, for one thing that is not about the caller: the
        # account the function runs in, and only when the Lambda context, which no caller writes,
        # does not say it.
        if path.name != "omni.py":
            assert "requestContext" not in text and "aws.event" not in text, path.name
    omni = source("routes/omni.py")
    assert omni.count("requestContext") == 1 and omni.count("aws.event") == 1
    assert '(event.get("requestContext") or {}).get("accountId")' in omni
    assert omni.index("invoked_function_arn") < omni.index("requestContext")
    # One function says who the caller is, for the read API and for the action functions.
    identity = source("identity/deps.py")
    assert identity.count("def principal_from_request(") == 1
    assert "return principal_from_request(request, settings)" in inspect.getsource(identity_deps.current_principal)
    assert "principal_from_request(request, settings)" in source("actions/app.py")
    assert "tokens.verify(token, settings.token, tokens.keys_for(settings.token.jwks_url))" in identity
    # Without the settings there is no way in but local development, which is impossible inside AWS Lambda.
    assert "if token is None or settings.token is None:" in identity
    callers = [p.name for p in SOURCES if "provider.principal(" in p.read_text()]
    assert callers == ["deps.py"]


def test_what_the_documents_say_about_the_read_apis_caller():
    readme = document("README.md")
    for said in (
        "The read API verifies the caller's bearer token itself",
        "`PORTAL_JWT_ISSUER`",
        "`PORTAL_JWT_AUDIENCE`",
        "`PORTAL_JWKS_URL`",
        "No function takes the caller from the invocation event",
    ):
        assert said in readme, said
    for name in DOCUMENTS:
        text = document(name)
        for gone in (
            "The read API trusts the claims",
            "the read API relies on that",
            "The read API takes the caller from the context",
            "the read API still trusts",
        ):
            assert gone not in text, (name, gone)
