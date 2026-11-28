# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""An agent's life after approval: retire and review, through the approver function's handler."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
from typing import Any

import pytest

from portal_api import reviews
from portal_api.actions import approver, audit_writer, lifecycle_flow
from portal_api.aws import audit as audit_reader
from portal_api.models.portal import AuditEvent
from tests.conftest import BASE_ENV, agent_document
from tests.fakes import FakeDynamo, client_error
from tests.test_actions import ANN, ANN2, DEV, PAT, SEC, VIEW, World
from tests.test_inventory import Backend, benign, rich_bundle

SRE = {"sub": "sre-1", "cognito:groups": "[sre-team]"}  # sre, tenant ws1: neither registrar nor approver
TABLE = BASE_ENV["PORTAL_AUDIT_TABLE"]
TODAY = dt.datetime.now(dt.UTC).date()


def day(offset: int) -> str:
    return (TODAY + dt.timedelta(days=offset)).isoformat()


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return World(monkeypatch)


def retire(world: World, record_id: str, claims: dict = ANN, reason: Any = "The agent was replaced.", **extra: Any):
    return world.call("approver", "POST", f"/registrations/{record_id}/retire", claims, {"reason": reason, **extra})


def review(
    world: World,
    record_id: str,
    claims: dict = ANN,
    next_review_by: Any = None,
    reason: Any = "Reviewed with the owner; still needed.",
    **extra: Any,
):
    body = {"reason": reason, "next_review_by": day(180) if next_review_by is None else next_review_by, **extra}
    return world.call("approver", "POST", f"/registrations/{record_id}/review", claims, body)


def a_day_later(monkeypatch: pytest.MonkeyPatch, hours: float = 24) -> None:
    """From now on the approver function decides a review as if this many hours had passed.

    A record's review can be attested once in 24 hours. What is written keeps the real time.
    """
    moment = dt.datetime.now(dt.UTC) + dt.timedelta(hours=hours)
    monkeypatch.setattr(lifecycle_flow, "_now", lambda: moment)


def attestation_items(world: World) -> list[dict[str, str]]:
    """What the ``REVIEWS`` partition holds, oldest first: for each record its latest attestation, of either kind."""
    return world.dynamo.attestations()


def reviews_items(world: World) -> list[dict[str, str]]:
    """Of those, the ones a review made. An approval's is of its own kind, until a review replaces it."""
    return [item for item in attestation_items(world) if item["kind"] == "review"]


def attested(world: World, record_id: str | None = None) -> list[dict[str, str]]:
    """Every attestation on record, oldest first: the result events that name one, in the records' own histories."""
    found = [
        event
        for event in world.dynamo.events()
        if event.get("attested_at") and (event["phase"], event["outcome"]) == ("result", "allowed")
    ]
    return sorted(
        (event for event in found if record_id is None or event["pk"] == f"RECORD#{record_id}"),
        key=lambda event: event["attested_at"],
    )


def events_of(world: World, record_id: str, action: str) -> list[dict[str, str]]:
    return [e for e in world.dynamo.events() if e["pk"] == f"RECORD#{record_id}" and e.get("action") == action]


# --- retire --------------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED"])
@pytest.mark.parametrize("claims", [ANN, SEC, PAT])
def test_an_approver_retires_a_record_from_any_settled_status(world, status, claims):
    record_id = world.new_record(status)
    code, body = retire(world, record_id, claims)
    assert code == 200, body
    assert (body["action"], body["outcome"], body["audit_complete"]) == ("retire", "allowed", True)
    registration = body["registration"]
    assert (registration["status"], registration["lifecycle_state"]) == ("DEPRECATED", "deprecated")
    assert registration["status_reason"] == "The agent was replaced."
    # The response says what retirement means.
    assert body["reason"] == lifecycle_flow.RETIRED
    assert "permanent" in body["reason"] and "still deployed until its pipeline removes it" in body["reason"]
    assert world.status(record_id) == "DEPRECATED"

    intent, result = events_of(world, record_id, "retire")
    assert (intent["phase"], intent["outcome"], intent["reason"]) == (
        "intent",
        "allowed",
        "approver retires the record (RET-01-P)",
    )
    assert (result["phase"], result["outcome"], result["reason"]) == ("result", "allowed", "The agent was replaced.")
    assert (result["status_before"], result["status_after"]) == (status, "DEPRECATED")
    assert result["detail"] == lifecycle_flow.RETIREMENT_IS_PERMANENT
    assert intent["request_id"] == result["request_id"] == body["request_id"]
    assert result["actor_subject"] == claims["sub"] and result["tenant_id"] == "ws1"
    assert result["document_sha256"] == registration["document_sha256"]


def test_the_person_who_registered_or_approved_a_record_may_retire_it(world):
    # No two-person rule: Pat registered and submitted this record, Ann approved it.
    code, body = world.create(PAT)
    by_pat = body["registration"]["record_id"]
    assert world.submit(by_pat, PAT)[0] == 200 and world.decide("approve", by_pat, ANN)[0] == 200
    assert retire(world, by_pat, PAT)[0] == 200

    code, body = world.create(agent_id="other-agent")
    by_ann = body["registration"]["record_id"]
    assert world.submit(by_ann)[0] == 200 and world.decide("approve", by_ann, ANN)[0] == 200
    assert retire(world, by_ann, ANN)[0] == 200
    assert world.status(by_pat) == world.status(by_ann) == "DEPRECATED"


def test_retiring_a_retired_record_answers_unchanged_and_calls_nothing(world):
    record_id = world.new_record("APPROVED")
    assert retire(world, record_id)[0] == 200
    calls_before = world.registry.calls.count("update_registry_record_status")
    code, body = retire(world, record_id, SEC, "Again, to be sure.")
    assert code == 200
    assert (body["action"], body["outcome"]) == ("retire", "unchanged")
    assert body["reason"] == lifecycle_flow.ALREADY_RETIRED and "nothing was changed" in body["reason"]
    assert body["registration"]["status"] == "DEPRECATED"
    # The first retirement's reason stays on the record.
    assert body["registration"]["status_reason"] == "The agent was replaced."
    assert world.registry.calls.count("update_registry_record_status") == calls_before
    last = events_of(world, record_id, "retire")[-1]
    assert (last["phase"], last["outcome"], last["actor_subject"]) == ("result", "unchanged", "sec-1")
    assert (last["status_before"], last["status_after"]) == ("DEPRECATED", "DEPRECATED")


@pytest.mark.parametrize(("claims", "role"), [(DEV, "developer"), (VIEW, "readonly"), (SRE, "sre")])
def test_retire_without_the_approver_authority_is_403_before_the_record_is_read(world, claims, role):
    record_id = world.new_record("APPROVED")
    world.registry.calls.clear()
    for target in (record_id, "recMissing00"):
        code, body = retire(world, target, claims)
        assert code == 403
        assert body["detail"] == f"retire requires the approver authority; principal holds the '{role}' role (RET-01-N)"
        assert body["action"] == "retire" and body["request_id"]
    assert world.registry.calls == []  # the answer does not reveal whether the record exists
    assert world.status(record_id) == "APPROVED"
    # Nothing was resolved, so nothing is written under an id the caller chose: neither in the
    # history of the record that exists nor under the id that does not.
    assert events_of(world, record_id, "retire") == []
    assert not [e for e in world.dynamo.events() if e["pk"] == "RECORD#recMissing00"]


def test_retire_needs_the_records_tenant(world, caplog):
    record_id = world.new_record("APPROVED")
    recorded = len(world.dynamo.events())
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        code, body = retire(world, record_id, ANN2)
    assert code == 403 and body["detail"] == "the record belongs to a tenant the principal does not hold (RET-02-N)"
    assert world.status(record_id) == "APPROVED"
    # An approver of another tenant has no part in this record: the refusal is in the function's
    # log, under the request id of the answer, and not in the record's history.
    assert events_of(world, record_id, "retire") == [] and len(world.dynamo.events()) == recorded
    (logged,) = [r.getMessage() for r in caplog.records if "not written to the audit trail" in r.getMessage()]
    assert body["request_id"] in logged and "RET-02-N" in logged and f"record={record_id}" in logged
    # Security holds both tenants here; platform holds every tenant.
    assert retire(world, record_id, SEC)[0] == 200


@pytest.mark.parametrize("body", [{}, {"reason": ""}, {"reason": None}, {"reason": "x" * 1001}, {"reason": 5}])
def test_retire_needs_a_reason(world, body):
    record_id = world.new_record("APPROVED")
    assert world.call("approver", "POST", f"/registrations/{record_id}/retire", ANN, body)[0] == 422
    assert world.status(record_id) == "APPROVED" and events_of(world, record_id, "retire") == []


def test_retire_accepts_no_other_field(world):
    record_id = world.new_record("APPROVED")
    assert retire(world, record_id, document_sha256="0" * 64)[0] == 422
    assert world.status(record_id) == "APPROVED"


def test_a_long_retirement_reason_is_kept_in_full_in_the_trail_and_cut_for_the_registry(world):
    record_id = world.new_record("APPROVED")
    reason = "r" * 1000
    assert retire(world, record_id, reason=reason)[0] == 200
    assert len(world.registry.records[record_id]["statusReason"]) == 255
    assert events_of(world, record_id, "retire")[-1]["reason"] == reason


def test_retire_of_a_missing_or_foreign_record_is_404(world):
    assert retire(world, "recMissing00")[0] == 404
    tool = world.registry.seed("tool-echo", '{"schemaVersion": "agenticai.tool-governance/1.0"}', "APPROVED")
    code, body = retire(world, tool)
    assert code == 404 and body["detail"] == "Registration not found"
    assert world.status(tool) == "APPROVED" and world.dynamo.items == {}


def test_retire_does_nothing_when_the_intent_cannot_be_written(world):
    record_id = world.new_record("APPROVED")
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 1}
    code, body = retire(world, record_id)
    assert code == 503 and "not performed" in body["detail"]
    assert world.status(record_id) == "APPROVED"


def test_a_failed_result_write_leaves_the_retirement_done_and_says_so(world):
    record_id = world.new_record("APPROVED")
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 2}
    code, body = retire(world, record_id)
    assert code == 200 and body["audit_complete"] is False
    assert world.status(record_id) == "DEPRECATED"
    assert [(e["phase"], e["outcome"]) for e in events_of(world, record_id, "retire")] == [("intent", "allowed")]


@pytest.mark.parametrize(("error", "status"), [("ValidationException", 409), ("ThrottlingException", 502)])
def test_a_registry_refusal_of_a_retirement_is_recorded_as_failed(world, error, status):
    record_id = world.new_record("APPROVED")
    world.registry.fail["update_registry_record_status"] = error
    code, body = retire(world, record_id)
    assert code == status
    assert world.status(record_id) == "APPROVED"
    failed = events_of(world, record_id, "retire")[-1]
    assert (failed["phase"], failed["outcome"]) == ("result", "failed") and error in failed["reason"]


def test_a_retirement_the_registry_accepted_is_reported_even_if_the_record_cannot_be_read_back(world, monkeypatch):
    record_id = world.new_record("APPROVED")
    real = approver.wait_until_settled
    reads = {"n": 0}

    def flaky(client: Any, registry_id: str, wanted: str, **kwargs: Any) -> dict[str, Any]:
        reads["n"] += 1
        if reads["n"] == 2:  # the read after the status change
            raise client_error("ThrottlingException", "GetRegistryRecord")
        return real(client, registry_id, wanted, **kwargs)

    monkeypatch.setattr(approver, "wait_until_settled", flaky)
    code, body = retire(world, record_id)
    assert code == 200 and body["registration"]["status"] == "DEPRECATED"
    assert body["registration"]["status_reason"] == "The agent was replaced."
    assert world.status(record_id) == "DEPRECATED"
    assert events_of(world, record_id, "retire")[-1]["status_after"] == "DEPRECATED"


def test_retire_waits_for_a_record_that_is_settling(world):
    record_id = world.new_record("APPROVED")
    world.registry.records[record_id]["status"] = "UPDATING"  # settles in DRAFT at the next read
    code, body = retire(world, record_id)
    assert code == 200 and body["registration"]["status"] == "DEPRECATED"
    assert events_of(world, record_id, "retire")[-1]["status_before"] == "DRAFT"


def test_retire_of_a_record_that_does_not_settle_is_409(world, monkeypatch):
    record_id = world.new_record("APPROVED")
    stuck = {**world.registry.records[record_id], "status": "UPDATING"}
    monkeypatch.setattr(approver, "wait_until_settled", lambda *args, **kwargs: dict(stuck))
    code, body = retire(world, record_id)
    assert code == 409 and "RET-04-N" in body["detail"]
    assert world.status(record_id) == "APPROVED"
    assert events_of(world, record_id, "retire")[-1]["outcome"] == "denied"


def test_the_wait_is_bounded():
    class Stuck:
        def __init__(self) -> None:
            self.reads = 0

        def get_registry_record(self, registryId: str, recordId: str) -> dict[str, Any]:  # noqa: N803
            self.reads += 1
            return {"recordId": recordId, "status": "UPDATING", "ResponseMetadata": {}}

    clock = iter(range(100))
    client = Stuck()
    record = approver.wait_until_settled(
        client, "REG", "rec000000001", timeout=3, interval=1, sleep=lambda seconds: None, clock=lambda: next(clock)
    )
    assert record == {"recordId": "rec000000001", "status": "UPDATING"} and client.reads == 3


# --- a retired record is final -------------------------------------------------------------


def test_a_retired_record_cannot_be_approved_rejected_updated_or_submitted(world):
    record_id = world.new_record("PENDING_APPROVAL")
    assert retire(world, record_id)[0] == 200
    calls = len(world.registry.calls)
    refusals = {
        "approve": world.decide("approve", record_id, SEC),
        "reject": world.decide("reject", record_id, SEC),
        "update": world.update(record_id, contact="x@example.com"),
        "submit": world.submit(record_id),
    }
    words = {"approve": "approved", "reject": "rejected", "update": "updated", "submit": "submitted"}
    for action, (code, body) in refusals.items():
        assert code == 409, (action, body)
        assert body["detail"] == f"a retired record cannot be {words[action]}: retirement is permanent (RET-03-N)"
        assert body["action"] == action and body["request_id"]
        assert events_of(world, record_id, action)[-1]["outcome"] == "denied"
    # Refused by rule: no write reached the registry.
    assert not {"update_registry_record", "update_registry_record_status", "submit_registry_record_for_approval"} & set(
        world.registry.calls[calls:]
    )
    assert world.status(record_id) == "DEPRECATED"


def test_a_retired_record_refuses_an_update_before_its_document_is_checked(world):
    record_id = world.new_record("APPROVED")
    assert retire(world, record_id)[0] == 200
    code, body = world.update(record_id, risk_class="extreme")  # a value the schema would reject
    assert code == 409 and "RET-03-N" in body["detail"]
    # A body that is malformed in itself never reaches the rules: that is a 422 on every route.
    assert world.update(record_id, unknown_field="x")[0] == 422


def test_authority_is_still_checked_first_on_a_retired_record(world):
    record_id = world.new_record("PENDING_APPROVAL")
    assert retire(world, record_id)[0] == 200
    assert world.decide("approve", record_id, DEV)[0] == 403
    assert world.update(record_id, ANN)[0] == 403
    assert world.submit(record_id, VIEW)[0] == 403


def test_a_retired_record_can_still_be_deleted_and_its_history_survives(world):
    record_id = world.new_record("APPROVED")
    assert retire(world, record_id)[0] == 200
    code, body = world.delete(record_id)
    assert code == 200 and body["registration"] is None
    code, history = world.call("read", "GET", f"/registrations/{record_id}/history", VIEW)
    assert code == 200
    actions = [(e["action"], e["phase"], e["outcome"]) for e in reversed(history["events"])]
    assert actions[-4:] == [
        ("retire", "intent", "allowed"),
        ("retire", "result", "allowed"),
        ("delete", "intent", "allowed"),
        ("delete", "result", "allowed"),
    ]
    retired = next(e for e in history["events"] if e["action"] == "retire" and e["phase"] == "result")
    assert retired["detail"] == lifecycle_flow.RETIREMENT_IS_PERMANENT and retired["status_after"] == "DEPRECATED"


def test_the_read_api_shows_a_retired_registration(world):
    record_id = world.new_record("APPROVED")
    assert retire(world, record_id)[0] == 200
    code, detail = world.call("read", "GET", f"/registrations/{record_id}", VIEW)
    assert code == 200
    assert (detail["status"], detail["lifecycle_state"]) == ("DEPRECATED", "deprecated")
    assert detail["status_reason"] == "The agent was replaced."


# --- review attestation --------------------------------------------------------------------


@pytest.mark.parametrize("claims", [ANN, SEC, PAT])
def test_an_approver_attests_the_review_of_an_approved_record(world, claims):
    record_id = world.new_record("APPROVED")
    updated_before = world.registry.records[record_id]["updatedAt"]
    world.registry.calls.clear()
    code, body = review(world, record_id, claims, day(90))
    assert code == 200, body
    assert (body["action"], body["outcome"], body["audit_complete"]) == ("review", "allowed", True)
    assert body["reason"] == "Reviewed with the owner; still needed."
    assert body["registration"]["status"] == "APPROVED"
    # The record is only read: updating it would return it to DRAFT.
    assert set(world.registry.calls) == {"get_registry_record"}
    assert world.status(record_id) == "APPROVED"
    assert world.registry.records[record_id]["updatedAt"] == updated_before

    intent, result = events_of(world, record_id, "review")
    assert (intent["phase"], intent["outcome"], intent["reason"]) == (
        "intent",
        "allowed",
        "approver attests the review of the approved record (REV-01-P)",
    )
    assert (result["phase"], result["outcome"], result["reason"]) == (
        "result",
        "allowed",
        "Reviewed with the owner; still needed.",
    )
    assert intent["next_review_by"] == result["next_review_by"] == day(90)
    assert (result["status_before"], result["status_after"]) == ("APPROVED", "APPROVED")

    # One item for the record: the review took the place of the approval's attestation.
    (item,) = attestation_items(world)
    assert item["sk"] == f"RECORD#{record_id}" and kinds(world) == ["approval", "review"]
    # Written in this order: the intent, the attestation, the result that names it.
    assert intent["at"] <= item["at"] <= result["at"] and result["attested_at"] == item["at"]
    assert "attested_at" not in intent
    assert item == {
        "pk": "REVIEWS",
        "sk": item["sk"],
        "kind": "review",
        "at": item["at"],
        "record_id": record_id,
        "next_review_by": day(90),
        "reviewed_by": claims["sub"],
        # ANN's email is verified; SEC has none and PAT's is not verified, so their subject is recorded.
        "reviewed_by_label": {"ann-1": "ann@example.com", "sec-1": "sec-1", "pat-1": "pat-1"}[claims["sub"]],
        "reviewed_by_role": {"ann-1": "approver", "sec-1": "security", "pat-1": "platform"}[claims["sub"]],
        "reason": "Reviewed with the owner; still needed.",
        "request_id": body["request_id"],
        "record_name": "agent-ws1-travel-agent-nonprod",
        "tenant_id": "ws1",
    }
    assert intent["request_id"] == result["request_id"] == body["request_id"]


@pytest.mark.parametrize("status", ["DRAFT", "PENDING_APPROVAL", "REJECTED", "DEPRECATED"])
def test_only_an_approved_record_can_be_attested(world, status):
    record_id = world.new_record(status if status != "DEPRECATED" else "APPROVED")
    if status == "DEPRECATED":
        assert retire(world, record_id)[0] == 200
    code, body = review(world, record_id)
    assert code == 409
    assert body["detail"] == f"only an approved registration can be attested; this one is {status} (REV-03-N)"
    assert body["action"] == "review" and body["request_id"]
    assert reviews_items(world) == []
    denied = events_of(world, record_id, "review")
    assert [(e["phase"], e["outcome"]) for e in denied] == [("result", "denied")]
    assert denied[0]["next_review_by"] == day(180)


@pytest.mark.parametrize(("claims", "role"), [(DEV, "developer"), (VIEW, "readonly"), (SRE, "sre")])
def test_review_without_the_approver_authority_is_403_before_the_record_is_read(world, claims, role):
    record_id = world.new_record("APPROVED")
    world.registry.calls.clear()
    for target in (record_id, "recMissing00"):
        code, body = review(world, target, claims)
        assert code == 403
        assert body["detail"] == (
            f"a review attestation requires the approver authority; principal holds the '{role}' role (REV-01-N)"
        )
    assert world.registry.calls == [] and reviews_items(world) == []


def test_review_needs_the_records_tenant(world, caplog):
    record_id = world.new_record("APPROVED")
    recorded = len(world.dynamo.events())
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        code, body = review(world, record_id, ANN2)
    assert code == 403 and body["detail"] == "the record belongs to a tenant the principal does not hold (REV-02-N)"
    assert reviews_items(world) == []
    # Logged, not written into the history of a record the caller has no part in.
    assert events_of(world, record_id, "review") == [] and len(world.dynamo.events()) == recorded
    (logged,) = [r.getMessage() for r in caplog.records if "not written to the audit trail" in r.getMessage()]
    assert body["request_id"] in logged and "REV-02-N" in logged


@pytest.mark.parametrize(
    ("offset", "message"),
    [(0, "must be after today"), (-1, "must be after today"), (-400, "must be after today"), (367, "at most 366 days")],
)
def test_the_next_review_date_must_be_after_today_and_within_366_days(world, offset, message):
    record_id = world.new_record("APPROVED")
    code, body = review(world, record_id, next_review_by=day(offset))
    assert code == 422
    (error,) = body["detail"]
    assert error["loc"] == ["body", "next_review_by"] and error["type"] == "review_date"
    assert message in error["msg"] and "REV-04-N" in error["msg"]
    # A 422 is not a decision: nothing is attested and nothing is written.
    assert reviews_items(world) == [] and events_of(world, record_id, "review") == []


@pytest.mark.parametrize("offset", [1, 366])
def test_the_bounds_of_the_next_review_date_are_accepted(world, offset):
    record_id = world.new_record("APPROVED")
    assert review(world, record_id, next_review_by=day(offset))[0] == 200
    assert reviews_items(world)[0]["next_review_by"] == day(offset)


@pytest.mark.parametrize(
    "body",
    [
        {"reason": "ok"},
        {"next_review_by": "2099-01-01"},
        {"reason": "", "next_review_by": "2099-01-01"},
        {"reason": "x" * 1001, "next_review_by": "2099-01-01"},
        {"reason": "ok", "next_review_by": "27-1-1"},
        {"reason": "ok", "next_review_by": "\u0662\u0660\u0669\u0669-\u0660\u0661-\u0660\u0661"},
        {"reason": "ok", "next_review_by": "2099-01-01\n"},
        {"reason": "ok", "next_review_by": "next year"},
        {"reason": "ok", "next_review_by": None},
        {"reason": "ok", "next_review_by": 20990101},
        {"reason": "ok", "next_review_by": "2099-01-01", "status": "APPROVED"},
    ],
)
def test_a_malformed_review_body_is_422(world, body):
    record_id = world.new_record("APPROVED")
    code, answer = world.call("approver", "POST", f"/registrations/{record_id}/review", ANN, body)
    assert code == 422 and isinstance(answer["detail"], list)
    assert reviews_items(world) == [] and events_of(world, record_id, "review") == []


def test_a_date_that_is_not_a_calendar_date_is_422(world):
    record_id = world.new_record("APPROVED")
    code, body = review(world, record_id, next_review_by="2027-02-30")
    assert code == 422 and "not a calendar date" in body["detail"][0]["msg"]


def test_authority_and_status_are_decided_before_the_date_is_looked_at(world):
    draft = world.new_record()
    assert review(world, draft, DEV, next_review_by=day(-5))[0] == 403
    assert review(world, draft, ANN, next_review_by=day(-5))[0] == 409


def test_the_latest_attestation_takes_the_place_of_the_one_before_and_the_history_keeps_every_one(world, monkeypatch):
    record_id = world.new_record("APPROVED")
    assert review(world, record_id, ANN, day(30), "First review.")[0] == 200
    a_day_later(monkeypatch)
    assert review(world, record_id, SEC, day(200), "Second review.")[0] == 200
    # One item for the record, whatever number of times it was attested: the latest.
    (stored,) = attestation_items(world)
    assert (stored["sk"], stored["reason"], stored["next_review_by"], stored["reviewed_by"]) == (
        f"RECORD#{record_id}",
        "Second review.",
        day(200),
        "sec-1",
    )
    # The history of attestations is the record's own: the approval and both reviews, each named by its result.
    approval, first, second = attested(world, record_id)
    assert (approval["action"], first["action"], second["action"]) == ("approve", "review", "review")
    assert (first["reason"], first["next_review_by"], first["actor_subject"]) == ("First review.", day(30), "ann-1")
    assert (second["reason"], second["next_review_by"], second["actor_subject"]) == (
        "Second review.",
        day(200),
        "sec-1",
    )
    assert approval["attested_at"] < first["attested_at"] < second["attested_at"] == stored["at"]
    # That one item is the only thing a write ever replaced: every other write was a new item.
    assert world.dynamo.replaced == [("REVIEWS", f"RECORD#{record_id}")] * 2
    assert world.dynamo.calls.count("put_item") == len(world.dynamo.items) + 2


def test_review_does_nothing_when_the_intent_cannot_be_written(world):
    record_id = world.new_record("APPROVED")
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 1}
    code, body = review(world, record_id)
    assert code == 503 and "not performed" in body["detail"]
    assert reviews_items(world) == []


def test_a_failed_attestation_write_is_503_and_recorded_as_failed(world):
    record_id = world.new_record("APPROVED")
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 2}  # intent, then the attestation itself
    code, body = review(world, record_id)
    assert code == 503
    assert body["detail"] == "The review could not be recorded, so nothing was attested"
    assert body["action"] == "review" and body["request_id"]
    assert reviews_items(world) == []
    intent, failed = events_of(world, record_id, "review")
    assert (failed["phase"], failed["outcome"], failed["request_id"]) == ("result", "failed", body["request_id"])
    assert failed["reason"] == body["detail"] and intent["request_id"] == body["request_id"]
    # The read side does not count it: the last review is still the approval.
    (approval,) = attestation_items(world)
    detail = world.call("read", "GET", f"/registrations/{record_id}", VIEW)[1]
    assert (approval["kind"], detail["last_reviewed_at"]) == ("approval", approval["at"])


def test_an_attestation_the_sdk_sent_twice_counts_once(world, monkeypatch):
    """A write that succeeded but whose answer was lost is retried by the SDK and then refused: it is not newer."""
    record_id = world.new_record("APPROVED")
    stamp = "2099-11-27T10:00:00.000000Z"  # after the approval's own attestation, as a review's always is
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: stamp)
    real_put = world.dynamo.put_item

    def put_twice(**kwargs: Any) -> dict[str, Any]:
        result = real_put(**kwargs)
        if kwargs["Item"]["pk"]["S"] == "REVIEWS":
            return real_put(**kwargs)  # the retry: the item is already there
        return result

    monkeypatch.setattr(world.dynamo, "put_item", put_twice)
    code, body = review(world, record_id)
    assert code == 200 and body["audit_complete"] is True
    (item,) = reviews_items(world)
    assert (item["sk"], item["at"], item["request_id"]) == (f"RECORD#{record_id}", stamp, body["request_id"])
    # Every event of this call carries the same fixed time, so the result is found by its phase.
    (result,) = [e for e in events_of(world, record_id, "review") if e["phase"] == "result"]
    assert (result["outcome"], result["attested_at"]) == ("allowed", stamp)


def test_a_failed_result_write_leaves_the_attestation_standing_and_says_so(world):
    record_id = world.new_record("APPROVED")
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 3}
    code, body = review(world, record_id)
    assert code == 200 and body["audit_complete"] is False
    assert len(reviews_items(world)) == 1
    assert [(e["phase"], e["outcome"]) for e in events_of(world, record_id, "review")] == [("intent", "allowed")]


def test_review_of_a_missing_or_foreign_record_is_404(world):
    assert review(world, "recMissing00")[0] == 404
    tool = world.registry.seed("tool-echo", '{"schemaVersion": "agenticai.tool-governance/1.0"}', "APPROVED")
    assert review(world, tool)[0] == 404
    assert world.dynamo.items == {}


# --- an approval counts as a review -----------------------------------------------------------


def agent_of(world: World, record_id: str) -> dict[str, Any]:
    """The agent as the inventory shows it: its review date comes from the partition of attestations."""
    code, agent = world.call("read", "GET", f"/agents/{record_id}", VIEW)
    assert code == 200, agent
    return agent


def detail_of(world: World, record_id: str) -> dict[str, Any]:
    """The registration detail: its review date comes from the record's own events."""
    code, detail = world.call("read", "GET", f"/registrations/{record_id}", VIEW)
    assert code == 200, detail
    return detail


def review_state(world: World, record_id: str) -> tuple[str | None, str | None]:
    """The effective review date and who reviewed last. Both read paths must agree on it."""
    agent, detail = agent_of(world, record_id), detail_of(world, record_id)
    assert (agent["review_by"], agent["last_reviewed_at"], agent["last_reviewed_by"]) == (
        detail["effective_review_by"],
        detail["last_reviewed_at"],
        detail["last_reviewed_by"],
    )
    return agent["review_by"], agent["last_reviewed_by"]


def approved_with(world: World, review_by: str | None, approver: dict = ANN) -> str:
    """A record Dev registered and submitted and an approver approved, with this review date in its document."""
    code, body = world.create(review_by=review_by) if review_by else world.create()
    assert code == 201, body
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200
    assert world.decide("approve", record_id, approver)[0] == 200
    return record_id


def re_approve(world: World, record_id: str, review_by: str | None, approver: dict = SEC) -> None:
    """Dev changes the document's review date, submits again, and another approver approves."""
    code, body = world.update(record_id, **({"review_by": review_by} if review_by else {}))
    assert code == 200 and body["registration"]["status"] == "DRAFT", body
    assert world.submit(record_id)[0] == 200
    assert world.decide("approve", record_id, approver)[0] == 200


def kinds(world: World) -> list[str]:
    """The kind of every attestation on record, oldest first, as the records' own histories name them."""
    return [{"approve": "approval", "review": "review"}[event["action"]] for event in attested(world)]


def test_an_approval_of_a_document_with_a_review_date_is_recorded_as_a_review(world):
    code, body = world.create(review_by=day(300))
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200
    assert attestation_items(world) == []  # registering and submitting attest nothing
    code, approved = world.decide("approve", record_id, ANN, "Checked against the policy.")
    assert code == 200 and approved["audit_complete"] is True
    assert approved["reason"] == "Checked against the policy."

    (item,) = attestation_items(world)
    assert item == {
        "pk": "REVIEWS",
        "sk": f"RECORD#{record_id}",
        "kind": "approval",
        "at": item["at"],
        "record_id": record_id,
        "next_review_by": day(300),
        "reviewed_by": "ann-1",
        "reviewed_by_label": "ann@example.com",
        "reviewed_by_role": "approver",
        "reason": "Approved: Checked against the policy.",
        "request_id": approved["request_id"],
        "record_name": "agent-ws1-travel-agent-nonprod",
        "tenant_id": "ws1",
    }
    intent, result = events_of(world, record_id, "approve")
    assert (result["attested_at"], result["next_review_by"]) == (item["at"], day(300))
    assert "attested_at" not in intent and "next_review_by" not in intent
    assert result["status_after"] == "APPROVED" and result["reason"] == "Checked against the policy."
    assert review_state(world, record_id) == (day(300), "ann@example.com")
    assert detail_of(world, record_id)["last_reviewed_at"] == item["at"]


def test_an_approval_of_a_document_without_a_review_date_records_a_year_from_the_approval(world):
    """Otherwise a registration that names no date would never be due, whatever the limit on dates."""
    record_id = approved_with(world, None)
    (item,) = attestation_items(world)
    assert (item["kind"], item["next_review_by"], item["reviewed_by"]) == ("approval", day(366), "ann-1")
    result = events_of(world, record_id, "approve")[-1]
    assert (result["attested_at"], result["next_review_by"]) == (item["at"], day(366))
    assert review_state(world, record_id) == (day(366), "ann@example.com")
    # The document still names no date of its own; only the effective date is set.
    assert "review_by" not in detail_of(world, record_id)["document"]


def test_a_rejection_attests_nothing(world):
    code, body = world.create(review_by=day(100))
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200
    assert world.decide("reject", record_id, ANN)[0] == 200
    assert attestation_items(world) == []
    # The date shown is the registration's own, and nobody has reviewed it.
    assert review_state(world, record_id) == (day(100), None)


def test_approve_with_a_date_then_attest_later_the_attestation_wins(world):
    record_id = approved_with(world, day(300), ANN)
    assert review_state(world, record_id) == (day(300), "ann@example.com")
    assert review(world, record_id, SEC, day(90))[0] == 200
    assert kinds(world) == ["approval", "review"]
    assert review_state(world, record_id) == (day(90), "sec-1")
    # The document keeps its own date; only the effective one moved.
    assert detail_of(world, record_id)["document"]["review_by"] == day(300)


def test_attest_then_re_approve_with_a_new_date_the_approval_wins(world):
    record_id = approved_with(world, day(300), ANN)
    assert review(world, record_id, ANN, day(90))[0] == 200
    assert review_state(world, record_id) == (day(90), "ann@example.com")

    code, body = world.update(record_id, review_by=day(350))
    assert code == 200 and body["registration"]["status"] == "DRAFT"
    # Until the changed document is approved, the attestation still decides.
    assert review_state(world, record_id) == (day(90), "ann@example.com")
    assert world.submit(record_id)[0] == 200
    assert world.decide("approve", record_id, SEC)[0] == 200
    assert kinds(world) == ["approval", "review", "approval"]
    assert review_state(world, record_id) == (day(350), "sec-1")
    assert attestation_items(world)[-1]["next_review_by"] == day(350)


def test_re_approve_with_no_date_records_a_year_from_that_approval(world):
    record_id = approved_with(world, day(300), ANN)
    assert review(world, record_id, ANN, day(90))[0] == 200
    re_approve(world, record_id, None, SEC)  # the new document names no review date
    # Every approval is a review: this one moves the date to a year from itself.
    assert kinds(world) == ["approval", "review", "approval"]
    assert review_state(world, record_id) == (day(366), "sec-1")
    detail = detail_of(world, record_id)
    assert detail["status"] == "APPROVED" and "review_by" not in detail["document"]


def test_a_re_approval_moves_the_date_also_without_a_review_in_between(world):
    record_id = approved_with(world, day(300), ANN)
    re_approve(world, record_id, day(200), SEC)
    assert kinds(world) == ["approval", "approval"]
    assert review_state(world, record_id) == (day(200), "sec-1")


@pytest.mark.parametrize("offset", [-300, 0, 1, 366])
def test_an_approval_records_the_documents_date_when_it_is_within_a_year(world, offset):
    record_id = approved_with(world, day(offset))
    (item,) = attestation_items(world)
    assert (item["kind"], item["next_review_by"]) == ("approval", day(offset))
    assert review_state(world, record_id)[0] == day(offset)
    assert agent_of(world, record_id)["flags"]["review_overdue"] is (offset < 0)


@pytest.mark.parametrize("offset", [367, 2000, 355_000])
def test_a_registration_cannot_name_a_review_date_more_than_a_year_ahead(world, offset):
    """The attack: register with a date in the far future, have it approved, and never be due for review."""
    far = day(offset)
    code, body = world.create(review_by=far)
    assert code == 422, body
    assert body["detail"] == [
        {
            "loc": ["body", "review_by"],
            "msg": f"review_by may be at most 366 days ahead, so no later than {day(366)}",
            "type": "document",
        }
    ]
    assert world.registry.records == {} and world.dynamo.items == {}
    # The same on an update, of a draft and of an approved record alike.
    record_id = approved_with(world, day(366))
    before = len(world.dynamo.events())
    code, body = world.update(record_id, review_by=far)
    assert code == 422 and body["detail"][0]["loc"] == ["body", "review_by"], body
    assert world.status(record_id) == "APPROVED" and len(world.dynamo.events()) == before
    assert world.update(record_id, review_by=day(365))[0] == 200


def with_review_date(world: World, record_id: str, review_by: str) -> None:
    """Give a stored record a review date as no request could: written before the limit, or by other means."""
    record = world.registry.records[record_id]
    document = json.loads(record["descriptors"]["custom"]["data"])
    record["descriptors"] = {"custom": {"data": json.dumps({**document, "reviewBy": review_by})}}


@pytest.mark.parametrize("offset", [367, 2000, 355_000])
def test_an_approval_of_a_document_with_a_later_date_records_a_year_from_the_approval(world, offset):
    record_id = world.new_record("PENDING_APPROVAL")
    with_review_date(world, record_id, day(offset))
    code, approved = world.decide("approve", record_id, ANN)
    assert code == 200 and approved["audit_complete"] is True, approved
    (item,) = attestation_items(world)
    # Not the document's date: a year from the approval, which is the furthest any date gets.
    assert (item["kind"], item["next_review_by"]) == ("approval", day(366))
    assert events_of(world, record_id, "approve")[-1]["next_review_by"] == day(366)
    assert review_state(world, record_id) == (day(366), "ann@example.com")
    # The document itself is the registrant's and is not rewritten by an approval.
    assert detail_of(world, record_id)["document"]["review_by"] == day(offset)
    # A record that names such a date can be updated only to a date within the limit.
    code, body = world.update(record_id, review_by=day(offset))
    assert code == 422 and body["detail"][0]["loc"] == ["body", "review_by"]


def test_an_approval_stands_when_its_review_date_cannot_be_recorded(world):
    code, body = world.create(review_by=day(300))
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 2}  # the intent, then the attestation
    code, approved = world.decide("approve", record_id, ANN)
    assert code == 200 and approved["registration"]["status"] == "APPROVED"
    assert approved["audit_complete"] is False
    assert world.status(record_id) == "APPROVED" and attestation_items(world) == []
    result = events_of(world, record_id, "approve")[-1]
    assert (result["phase"], result["outcome"]) == ("result", "allowed")
    assert result["detail"] == "The approval stands, but its review date could not be recorded."
    assert "attested_at" not in result and "next_review_by" not in result
    # Nothing is attested, so the date shown is the registration's own and nobody has reviewed it.
    assert review_state(world, record_id) == (day(300), None)


def test_an_approval_attestation_the_sdk_sent_twice_counts_once(world, monkeypatch):
    code, body = world.create(review_by=day(300))
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200
    real_put = world.dynamo.put_item

    def put_twice(**kwargs: Any) -> dict[str, Any]:
        result = real_put(**kwargs)
        if kwargs["Item"]["pk"]["S"] == "REVIEWS":
            return real_put(**kwargs)  # the retry: the item is already there
        return result

    monkeypatch.setattr(world.dynamo, "put_item", put_twice)
    code, approved = world.decide("approve", record_id, ANN)
    assert code == 200 and approved["audit_complete"] is True
    (item,) = attestation_items(world)
    assert events_of(world, record_id, "approve")[-1]["attested_at"] == item["at"]


@pytest.mark.parametrize("action", ["approve", "reject"])
def test_a_decision_the_registry_accepted_is_reported_even_if_the_record_cannot_be_read_back(
    world, monkeypatch, action
):
    code, body = world.create(review_by=day(300))
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200
    real = approver.get_record
    reads = {"n": 0}

    def flaky(client: Any, registry_id: str, wanted: str) -> dict[str, Any]:
        reads["n"] += 1
        if reads["n"] == 2:  # the read after the status change
            raise client_error("ThrottlingException", "GetRegistryRecord")
        return real(client, registry_id, wanted)

    monkeypatch.setattr(approver, "get_record", flaky)
    code, decided = world.decide(action, record_id, ANN)
    status = {"approve": "APPROVED", "reject": "REJECTED"}[action]
    assert code == 200 and decided["registration"]["status"] == status
    assert decided["registration"]["status_reason"] == "Reviewed and fine."
    assert world.status(record_id) == status
    result = events_of(world, record_id, action)[-1]
    assert (result["outcome"], result["status_after"]) == ("allowed", status)
    assert len(attestation_items(world)) == (1 if action == "approve" else 0)


def test_a_record_published_with_a_malformed_review_date_is_due_a_year_from_its_approval(world):
    """A record written outside the portal can hold anything; only a calendar date is carried into the trail."""
    record_id = world.new_record("PENDING_APPROVAL")
    record = world.registry.records[record_id]
    document = json.loads(record["descriptors"]["custom"]["data"])
    document["reviewBy"] = "next spring"
    record["descriptors"]["custom"]["data"] = json.dumps(document, sort_keys=True, separators=(",", ":"))
    assert world.decide("approve", record_id, ANN)[0] == 200
    (item,) = attestation_items(world)
    assert (item["kind"], item["next_review_by"]) == ("approval", day(366))


def test_an_approval_counts_as_the_last_review_only_when_it_recorded_a_date():
    approval = _event(action="approve", attested_at="2026-06-01T09:59:59.900000Z")
    found = audit_reader.last_review([approval])
    assert found is not None
    assert (found.kind, found.at, found.next_review_by) == ("approval", "2026-06-01T09:59:59.900000Z", "2027-06-01")
    # An approval whose attestation was not written, or one recorded before every approval attested.
    assert audit_reader.last_review([_event(action="approve")]) is None
    assert audit_reader.last_review([_event(action="approve", next_review_by=None, attested_at="x")]) is None
    # A rejection never counts, and the newest attestation of either kind is the one returned.
    assert audit_reader.last_review([_event(action="reject", attested_at="x")]) is None
    newest_first = [_event(at="2026-07-01T10:00:00.000000Z", next_review_by="2027-07-01"), approval]
    assert audit_reader.last_review(newest_first).kind == "review"
    # Newest by the time it was attested, which is what the REVIEWS partition keeps for the record: two
    # attestations made at nearly the same moment can leave their result events in the other order.
    assert audit_reader.last_review(list(reversed(newest_first))).kind == "review"
    late_result = _event(at="2026-06-01T10:00:05.000000Z", attested_at="2026-06-01T09:59:59.800000Z")
    assert audit_reader.last_review([late_result, approval]).kind == "approval"


def test_the_history_of_attestations_is_read_from_the_records_own_events():
    approval = _event(action="approve", attested_at="2026-06-01T09:59:59.900000Z", reason="Checked.", request_id="a1")
    review = _event(at="2026-07-01T10:00:00.000000Z", next_review_by="2027-07-01", request_id="r2")
    others = [
        _event(action="approve", phase="intent", request_id="a1"),
        _event(phase="intent", request_id="r2"),
        _event(outcome="failed", request_id="r3"),
        _event(outcome="denied", request_id="r4"),
        _event(action="approve", request_id="a5"),  # an approval whose attestation was not written
        _event(action="retire", attested_at="x"),
        _event(action="submit"),
    ]
    found = audit_reader.attestations_in([review, *others, approval])
    assert [(a.kind, a.at, a.request_id) for a in found] == [
        ("review", "2026-07-01T10:00:00.000000Z", "r2"),
        ("approval", "2026-06-01T09:59:59.900000Z", "a1"),
    ]
    # An approval's attestation says its reason as the stored one does.
    assert (found[1].reason, found[0].reason) == ("Approved: Checked.", review.reason)
    assert found[1].reason == reviews.approval_reason("Checked.")
    assert audit_reader.attestations_in(others) == [] and audit_reader.attestations_in([]) == []
    # The same order whatever order the events come in.
    assert audit_reader.attestations_in([approval, *others, review]) == found


# --- routing -------------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["retire", "review"])
def test_only_the_approver_function_serves_retire_and_review(world, action):
    record_id = world.new_record("APPROVED")
    body = {"reason": "x", "next_review_by": day(10)} if action == "review" else {"reason": "x"}
    path = f"/registrations/{record_id}/{action}"
    assert world.call("registrar", "POST", path, PAT, body) == (404, {"detail": "Not found"})
    assert world.call("read", "POST", path, PAT, body)[0] == 405
    assert world.call("approver", "POST", path, PAT, body, role_env="registrar") == (404, {"detail": "Not found"})
    assert world.call("approver", "GET", path, PAT) == (404, {"detail": "Not found"})
    assert world.call("approver", "POST", path, None, body)[0] == 401
    assert world.status(record_id) == "APPROVED" and world.dynamo.events()[-1]["action"] == "approve"


# --- read side: the registration detail ------------------------------------------------------


def test_the_registration_detail_shows_the_last_review_and_the_effective_date(world, monkeypatch):
    code, body = world.create(review_by=day(250))
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id)[0] == 200 and world.decide("approve", record_id)[0] == 200
    before = world.call("read", "GET", f"/registrations/{record_id}", VIEW)[1]
    # The approval itself counts as a review, with the date the approved document names.
    (approval,) = attestation_items(world)
    assert (before["last_reviewed_at"], before["last_reviewed_by"]) == (approval["at"], "ann@example.com")
    assert before["effective_review_by"] == before["document"]["review_by"] == day(250)

    assert review(world, record_id, ANN, day(30))[0] == 200
    a_day_later(monkeypatch)
    assert review(world, record_id, SEC, day(200))[0] == 200
    after = world.call("read", "GET", f"/registrations/{record_id}", VIEW)[1]
    latest = reviews_items(world)[-1]
    # The time is the attestation's own, so the agent list and this page show the same instant.
    assert after["last_reviewed_at"] == latest["at"] and after["last_reviewed_by"] == "sec-1"
    assert latest["reviewed_by"] == "sec-1"
    # The attestation decides; the registration's own date is unchanged and still shown as stored.
    assert after["effective_review_by"] == day(200)
    assert after["document"]["review_by"] == day(250) and after["status"] == "APPROVED"


def test_a_registration_without_a_review_date_has_none_until_it_is_approved_through_the_portal(world):
    # Not approved yet: no date of its own and nothing attested.
    pending = world.new_record("PENDING_APPROVAL")
    detail = world.call("read", "GET", f"/registrations/{pending}", VIEW)[1]
    assert (detail["effective_review_by"], detail["last_reviewed_at"]) == (None, None)
    # Approved through the portal: due a year from the approval.
    assert world.decide("approve", pending, ANN)[0] == 200
    detail = world.call("read", "GET", f"/registrations/{pending}", VIEW)[1]
    assert detail["effective_review_by"] == day(366) and detail["last_reviewed_at"] is not None
    # Approved by other means, with no date in its document: the portal has recorded nothing for it.
    document = {k: v for k, v in agent_document(agentId="piped").items() if k != "reviewBy"}
    elsewhere = world.registry.seed("agent-ws1-piped-nonprod", json.dumps(document), "APPROVED")
    detail = world.call("read", "GET", f"/registrations/{elsewhere}", VIEW)[1]
    assert (detail["effective_review_by"], detail["last_reviewed_at"]) == (None, None)


def test_the_effective_date_is_the_registrations_own_without_an_audit_table(world, monkeypatch):
    code, body = world.create(review_by=day(250))
    record_id = body["registration"]["record_id"]
    monkeypatch.delenv("PORTAL_AUDIT_TABLE")
    detail = world.call("read", "GET", f"/registrations/{record_id}", VIEW)[1]
    assert (detail["effective_review_by"], detail["last_reviewed_at"]) == (day(250), None)


def test_review_events_are_part_of_the_history(world):
    record_id = world.new_record("APPROVED")
    assert review(world, record_id, ANN, day(45))[0] == 200
    history = world.call("read", "GET", f"/registrations/{record_id}/history", VIEW)[1]
    newest = history["events"][0]
    assert (newest["action"], newest["phase"], newest["outcome"], newest["next_review_by"]) == (
        "review",
        "result",
        "allowed",
        day(45),
    )


# --- reading the trail -----------------------------------------------------------------------


def _event(**overrides: Any) -> AuditEvent:
    values = {
        "event_id": "e",
        "request_id": "r1",
        "at": "2026-06-01T10:00:00.000000Z",
        "phase": "result",
        "action": "review",
        "outcome": "allowed",
        "reason": "Reviewed.",
        "actor_subject": "ann-1",
        "actor_label": "Ann Approver",
        "actor_role": "approver",
        "record_id": "recAgent0001",
        "next_review_by": "2027-06-01",
    }
    return AuditEvent(**{**values, **overrides})


def test_only_a_completed_review_counts_as_the_last_review():
    newest_first = [
        _event(at="2026-09-01T10:00:00.000000Z", phase="intent", request_id="r4"),  # no result: does not count
        _event(at="2026-08-01T10:00:00.000000Z", outcome="failed", request_id="r3"),
        _event(at="2026-07-01T10:00:00.000000Z", outcome="denied", request_id="r2"),
        _event(at="2026-06-15T10:00:00.000000Z", action="approve", request_id="r0"),
        _event(),
        _event(at="2026-01-01T10:00:00.000000Z", next_review_by="2026-07-01", request_id="r-old"),
    ]
    found = audit_reader.last_review(newest_first)
    assert found is not None
    assert (found.at, found.next_review_by, found.reviewed_by, found.reviewed_by_label, found.reviewed_by_role) == (
        "2026-06-01T10:00:00.000000Z",
        "2027-06-01",
        "ann-1",
        "Ann Approver",
        "approver",
    )
    assert audit_reader.last_review(newest_first[:4]) is None
    assert audit_reader.last_review([_event(next_review_by=None)]) is None
    # The time of the review is the attestation's own, which its result event names.
    named = audit_reader.last_review([_event(attested_at="2026-06-01T09:59:59.900000Z")])
    assert named is not None and named.at == "2026-06-01T09:59:59.900000Z"


def _item(**overrides: Any) -> dict[str, Any]:
    values = {
        "pk": "REVIEWS",
        "sk": "EVENT#2026-06-01T10:00:00.000000Z#recAgent0001",
        "record_id": "recAgent0001",
        "at": "2026-06-01T10:00:00.000000Z",
        "next_review_by": "2027-06-01",
        "reviewed_by": "ann-1",
        "reviewed_by_label": "Ann Approver",
        "reviewed_by_role": "approver",
        "reason": "Reviewed.",
        "request_id": "r1",
    }
    values.update(overrides)
    return {name: {"S": value} for name, value in values.items() if value is not None}


def test_a_stored_attestation_is_read_back():
    attestation = audit_reader.attestation_from_item(_item())
    assert attestation is not None
    assert (attestation.record_id, attestation.next_review_by, attestation.reviewed_by_label, attestation.reason) == (
        "recAgent0001",
        "2027-06-01",
        "Ann Approver",
        "Reviewed.",
    )
    # The label falls back to the subject id.
    assert audit_reader.attestation_from_item(_item(reviewed_by_label=None)).reviewed_by_label == "ann-1"


@pytest.mark.parametrize(
    "broken",
    [
        {"record_id": None},
        {"at": None},
        {"reviewed_by": None},
        {"next_review_by": None},
        {"next_review_by": "soon"},
        {"next_review_by": "2027-02-30"},
    ],
)
def test_an_incomplete_item_is_not_an_attestation(broken):
    assert audit_reader.attestation_from_item(_item(**broken)) is None
    assert audit_reader.attestation_from_item({"pk": {"S": "REVIEWS"}, "record_id": "not-an-attribute"}) is None


class PagedTable:
    """A table whose REVIEWS partition spans several pages, for each of the two reads of it."""

    def __init__(self, latest: list[dict[str, Any]], earlier: list[dict[str, Any]]) -> None:
        self.pages = {"RECORD#": latest, "EVENT#": earlier}
        self.requests: list[dict[str, Any]] = []
        self.served: list[str] = []  # the prefix of every page that was handed out

    def get_paginator(self, operation: str) -> Any:
        assert operation == "query"
        table = self

        class Pages:
            def paginate(self, **kwargs: Any) -> Any:
                table.requests.append(kwargs)
                assert kwargs["ExpressionAttributeValues"][":pk"] == {"S": "REVIEWS"}
                prefix = kwargs["ExpressionAttributeValues"][":prefix"]["S"]
                for page in table.pages[prefix]:
                    table.served.append(prefix)
                    yield page

        return Pages()


def _page(sort_key: str, at: str, more: bool, record_id: str = "recAgent0001") -> dict[str, Any]:
    """One page: an attestation, and an item that is not one. ``more`` says that another page follows."""
    result: dict[str, Any] = {"Items": [_item(at=at, sk=sort_key, record_id=record_id), {"pk": {"S": "REVIEWS"}}]}
    if more:
        result["LastEvaluatedKey"] = {"pk": {"S": "REVIEWS"}}
    return result


def test_the_attestations_are_read_with_two_bounded_queries():
    """The latest attestation of every record, then the ones written before there was one item for a record."""

    def earlier(n: int, more: bool) -> dict[str, Any]:
        at = f"2026-0{9 - n}-01T10:00:00.000000Z"
        return _page(f"EVENT#{at}#recAgent0001", at, more)

    latest = [
        _page("RECORD#recAgent0002", "2026-10-02T10:00:00.000000Z", True, "recAgent0002"),
        _page("RECORD#recAgent0001", "2026-10-01T10:00:00.000000Z", False),
    ]
    table = PagedTable(latest, [earlier(1, True), earlier(2, True), earlier(3, False)])
    found, truncated = audit_reader.query_attestations(table, TABLE)
    assert [a.at[:7] for a in found] == ["2026-10", "2026-10", "2026-08", "2026-07", "2026-06"] and truncated is False
    first, second = table.requests
    for request in table.requests:
        assert request["TableName"] == TABLE and request["ConsistentRead"] is True
        assert request["KeyConditionExpression"] == "pk = :pk AND begins_with(sk, :prefix)"
    assert first["ExpressionAttributeValues"] == {":pk": {"S": "REVIEWS"}, ":prefix": {"S": "RECORD#"}}
    assert second["ExpressionAttributeValues"] == {":pk": {"S": "REVIEWS"}, ":prefix": {"S": "EVENT#"}}
    assert second["ScanIndexForward"] is False  # the earlier ones newest first: a cut leaves out the oldest
    # The latest of a record is the one the inventory takes, whichever read returned it.
    grouped = reviews.by_record(found)
    assert [a.at[:7] for a in grouped["recAgent0001"]] == ["2026-10", "2026-08", "2026-07", "2026-06"]
    assert [a.at[:10] for a in grouped["recAgent0002"]] == ["2026-10-02"]

    # Bounded: each read stops after max_pages pages, and the answer says that something was left unread.
    table.served.clear()
    found, truncated = audit_reader.query_attestations(table, TABLE, max_pages=2)
    assert [a.at[:7] for a in found] == ["2026-10", "2026-10", "2026-08", "2026-07"] and truncated is True
    assert table.served == ["RECORD#", "RECORD#", "EVENT#", "EVENT#"]
    # Reading exactly as many pages as there are is not a truncation.
    found, truncated = audit_reader.query_attestations(table, TABLE, max_pages=3)
    assert len(found) == 5 and truncated is False
    # A cut of the first read is said as well, and the second read is still made.
    table.served.clear()
    found, truncated = audit_reader.query_attestations(table, TABLE, max_pages=1)
    assert [a.at[:10] for a in found] == ["2026-10-02", "2026-08-01"] and truncated is True
    assert table.served == ["RECORD#", "EVENT#"]
    # A table that holds none of the earlier ones: one page of each, nothing cut.
    found, truncated = audit_reader.query_attestations(PagedTable(latest[1:], [{"Items": []}]), TABLE, max_pages=1)
    assert len(found) == 1 and truncated is False


ATTESTED = {
    "record_id": "recAgent0001",
    "next_review_by": "2027-06-01",
    "reviewed_by": "ann-1",
    "reviewed_by_label": "Ann Approver",
    "reviewed_by_role": "approver",
    "reason": "Reviewed.",
    "request_id": "r1",
}


def test_the_writer_stores_what_the_reader_reads():
    table = FakeDynamo()
    assert audit_writer.put_attestation(table, TABLE, at="2026-06-01T10:00:00.000000Z", **ATTESTED) is True
    found, truncated = audit_reader.query_attestations(table, TABLE)
    assert truncated is False and len(found) == 1
    assert found[0] == audit_reader.attestation_from_item(_item(sk="RECORD#recAgent0001"))
    assert list(table.items) == [("REVIEWS", "RECORD#recAgent0001")]


def test_the_stored_attestation_of_a_record_is_replaced_only_by_one_attested_later():
    table = FakeDynamo()
    later = {**ATTESTED, "next_review_by": "2028-06-01", "reviewed_by": "sec-1", "request_id": "r2"}

    def stored() -> tuple[str, str, str | None]:
        (found,) = audit_reader.query_attestations(table, TABLE)[0]
        return found.at, found.next_review_by, found.request_id

    assert audit_writer.put_attestation(table, TABLE, at="2026-06-01T10:00:00.000000Z", **ATTESTED) is True
    # One attested at the same instant (the same write, sent again) or before it changes nothing.
    assert audit_writer.put_attestation(table, TABLE, at="2026-06-01T10:00:00.000000Z", **later) is False
    assert audit_writer.put_attestation(table, TABLE, at="2026-06-01T09:59:59.999999Z", **later) is False
    assert audit_writer.put_attestation(table, TABLE, at="2025-12-31T23:59:59.999999Z", **later) is False
    assert stored() == ("2026-06-01T10:00:00.000000Z", "2027-06-01", "r1") and table.replaced == []
    # One attested later takes its place, by a microsecond or by a year.
    assert audit_writer.put_attestation(table, TABLE, at="2026-06-01T10:00:00.000001Z", **later) is True
    assert stored() == ("2026-06-01T10:00:00.000001Z", "2028-06-01", "r2")
    assert audit_writer.put_attestation(table, TABLE, at="2027-06-01T10:00:00.000000Z", **ATTESTED) is True
    assert stored() == ("2027-06-01T10:00:00.000000Z", "2027-06-01", "r1")
    assert table.replaced == [("REVIEWS", "RECORD#recAgent0001")] * 2 and len(table.items) == 1
    # Another record has an item of its own, and a record id that begins like another's does not share one.
    other = {**ATTESTED, "record_id": "recAgent00011"}
    assert audit_writer.put_attestation(table, TABLE, at="2020-01-01T00:00:00.000000Z", **other) is True
    assert sorted(table.items) == [("REVIEWS", "RECORD#recAgent0001"), ("REVIEWS", "RECORD#recAgent00011")]
    # Any other failure of the write is raised, never taken for "a newer one is stored".
    table.fail_put_numbers = {table._puts + 1}
    with pytest.raises(Exception, match="ProvisionedThroughputExceeded"):
        audit_writer.put_attestation(table, TABLE, at="2029-01-01T00:00:00.000000Z", **ATTESTED)
    assert stored_of(table, "recAgent0001") == "2027-06-01T10:00:00.000000Z"


def stored_of(table: FakeDynamo, record_id: str) -> str:
    return table.items[("REVIEWS", f"RECORD#{record_id}")]["at"]["S"]


def test_an_item_that_is_not_an_attestation_does_not_stand_in_the_way_of_one():
    """Only an attestation that was attested later keeps a write out. An item with no time is not one."""
    table = FakeDynamo()
    table.items[("REVIEWS", "RECORD#recAgent0001")] = {"pk": {"S": "REVIEWS"}, "sk": {"S": "RECORD#recAgent0001"}}
    assert audit_reader.query_attestations(table, TABLE) == ([], False)
    assert audit_writer.put_attestation(table, TABLE, at="2026-06-01T10:00:00.000000Z", **ATTESTED) is True
    assert stored_of(table, "recAgent0001") == "2026-06-01T10:00:00.000000Z"


def test_the_time_an_attestation_is_compared_by_is_the_functions_own_and_sorts_as_text():
    """The condition compares two stamps as text, so every stamp has one form and the same length."""
    stamps = [audit_writer.now_stamp() for _ in range(50)]
    assert all(len(stamp) == len("2026-06-01T10:00:00.000000Z") and stamp.endswith("Z") for stamp in stamps)
    assert stamps == sorted(stamps)
    # No request carries a time: the two callers stamp the attestation themselves.
    for flow in ("approver_flow.py", "lifecycle_flow.py"):
        source = (pathlib.Path(audit_writer.__file__).parent / flow).read_text()
        assert source.count("put_attestation(") == 1 and source.count("at = audit_writer.now_stamp()") == 1
        assert "at=at," in source


# --- read side: the inventory ------------------------------------------------------------------


@pytest.fixture
def fleet(monkeypatch: pytest.MonkeyPatch) -> Backend:
    backend = Backend(monkeypatch)
    backend.control.runtimes = [rich_bundle()]
    backend.records = [benign()]
    backend.dynamo = backend.clients.clients[("platform", "dynamodb")]
    return backend


def attest(backend: Backend, next_review_by: str, at: str, record_id: str = "recAgent0001", who: str = "Ann") -> None:
    audit_writer.put_attestation(
        backend.dynamo,
        TABLE,
        at=at,
        record_id=record_id,
        next_review_by=next_review_by,
        reviewed_by="ann-1",
        reviewed_by_label=who,
        reviewed_by_role="approver",
        reason="Reviewed.",
        request_id="r1",
    )


def codes(agent: Any) -> list[str]:
    return [reason.code for reason in agent.risk.reasons]


def test_without_an_attestation_the_agent_shows_the_registrations_own_date(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    agent = fleet.agents()["recAgent0001"]
    assert (agent.review_by, agent.last_reviewed_at, agent.last_reviewed_by) == ("2020-01-31", None, None)
    assert agent.flags.review_overdue is True and "REVIEW_OVERDUE" in codes(agent)
    assert fleet.service.inventory().review_attestations == "ok"


def test_an_attestation_moves_the_effective_review_date_and_clears_the_overdue_flag(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    attest(fleet, day(-200), "2026-01-01T09:00:00.000000Z", who="Old Reviewer")
    attest(fleet, day(120), "2026-06-01T09:00:00.000000Z")
    agent = fleet.agents()["recAgent0001"]
    assert (agent.review_by, agent.last_reviewed_at, agent.last_reviewed_by) == (
        day(120),
        "2026-06-01T09:00:00.000000Z",
        "Ann",
    )
    assert agent.flags.review_overdue is False and "REVIEW_OVERDUE" not in codes(agent)
    # The registration's own date is still reported as stored.
    assert agent.governance.review_by == "2020-01-31"


def test_an_attestation_whose_date_has_passed_makes_the_agent_overdue(fleet):
    fleet.records = [benign(reviewBy="2099-12-31")]  # the registration's own date is far ahead
    attest(fleet, day(-1), "2026-01-01T09:00:00.000000Z")
    agent = fleet.agents()["recAgent0001"]
    assert agent.review_by == day(-1) and agent.flags.review_overdue is True
    overdue = next(r for r in agent.risk.reasons if r.code == "REVIEW_OVERDUE")
    assert (overdue.severity, overdue.detail) == ("medium", "The agent's review date has passed.")


def test_a_retired_registration_is_never_overdue_for_review(fleet):
    """It cannot be attested, updated or approved again, so the flag would be a demand nobody can meet."""
    fleet.records = [benign("DEPRECATED", reviewBy="2020-01-31")]
    attest(fleet, day(-30), "2026-01-01T09:00:00.000000Z")
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.review_overdue is False and "REVIEW_OVERDUE" not in codes(agent)
    assert agent.review_by == day(-30)  # the date is still reported
    # What is true of it is said instead: it is retired and its Runtime is still deployed.
    retired = next(r for r in agent.risk.reasons if r.code == "REGISTRATION_DEPRECATED")
    assert (retired.severity, retired.detail) == (
        "high",
        "The agent's registration is retired (DEPRECATED) and its Runtime is still deployed.",
    )
    assert (agent.lifecycle_state, agent.flags.unmanaged) == ("deprecated", True)
    # The same dates on a registration that is not retired are overdue.
    fleet.records = [benign("APPROVED", reviewBy="2020-01-31")]
    assert fleet.agents()["recAgent0001"].flags.review_overdue is True


def test_an_attestation_for_a_record_that_no_longer_exists_is_ignored(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    attest(fleet, day(120), "2026-06-01T09:00:00.000000Z", record_id="recDeleted01")
    agents = fleet.agents()
    assert list(agents) == ["recAgent0001"]
    assert (agents["recAgent0001"].review_by, agents["recAgent0001"].last_reviewed_at) == ("2020-01-31", None)
    assert fleet.service.fleet_summary().warnings == ["1 cell account(s) could not be read."]


def test_an_agent_with_no_registration_has_no_review_date(fleet):
    fleet.records = []
    attest(fleet, day(120), "2026-06-01T09:00:00.000000Z", record_id="travel_agent-AbCdEf1234")
    agent = fleet.agents()["travel_agent-AbCdEf1234"]
    assert (agent.review_by, agent.last_reviewed_at, agent.flags.review_overdue) == (None, None, None)


def test_unreadable_attestations_fall_back_to_the_registration_and_warn(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    attest(fleet, day(120), "2026-06-01T09:00:00.000000Z")
    fleet.dynamo.fail_query = True
    agent = fleet.agents()["recAgent0001"]  # the inventory is still served
    assert (agent.review_by, agent.last_reviewed_at, agent.flags.review_overdue) == ("2020-01-31", None, True)
    summary = fleet.service.fleet_summary()
    assert summary.review_attestations == "InternalServerError"
    assert summary.warnings[-1] == (
        "Review attestations could not be read (InternalServerError), "
        "so every review date shown is the registration's own."
    )
    assert summary.agents_total == 1


def test_no_audit_table_means_no_attestations_and_no_warning(monkeypatch):
    backend = Backend(monkeypatch, {"PORTAL_AUDIT_TABLE": ""})
    backend.records = [benign(reviewBy="2020-01-31")]
    backend.control.runtimes = [rich_bundle()]
    assert backend.agents()["recAgent0001"].review_by == "2020-01-31"
    summary = backend.service.fleet_summary()
    assert summary.review_attestations == "disabled"
    assert not [w for w in summary.warnings if "attestation" in w]
    assert backend.clients.clients[("platform", "dynamodb")].calls == []


def test_a_truncated_read_is_reported(fleet, monkeypatch):
    monkeypatch.setattr(audit_reader, "query_attestations", lambda client, table: ([], True))
    summary = fleet.service.fleet_summary()
    assert summary.review_attestations == "ok"
    assert summary.warnings[-1] == (
        "Not every review attestation was read. For an agent whose latest attestation was "
        "left out, the review date shown is an earlier one or the registration's own."
    )


def test_the_attestations_cost_two_queries_per_inventory_load_whatever_the_number_of_agents(fleet):
    fleet.records = [benign(), benign(record_id="recAgent0002", agentId="second-agent", runtimeArn=None)]
    attest(fleet, day(100), "2026-06-01T09:00:00.000000Z")
    attest(fleet, day(200), "2026-06-02T09:00:00.000000Z", record_id="recAgent0002")
    fleet.dynamo.calls.clear()
    agents = fleet.agents()
    assert (agents["recAgent0001"].review_by, agents["recAgent0002"].review_by) == (day(100), day(200))
    assert fleet.dynamo.calls == ["query", "query"]
    assert fleet.dynamo.prefixes == [("REVIEWS", "RECORD#"), ("REVIEWS", "EVENT#")]


def earlier_item(
    fleet: Backend, next_review_by: str, at: str, who: str = "Ann", record_id: str = "recAgent0001"
) -> None:
    """An attestation as it was stored before there was one item for a record."""
    item = _item(sk=f"EVENT#{at}#{record_id}", at=at, record_id=record_id, next_review_by=next_review_by)
    item["reviewed_by_label"] = {"S": who}
    fleet.dynamo.items[("REVIEWS", item["sk"]["S"])] = item


def test_attestations_stored_before_there_was_one_item_for_a_record_still_count(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    earlier_item(fleet, day(40), "2026-01-01T09:00:00.000000Z", who="Old Reviewer")
    earlier_item(fleet, day(80), "2026-03-01T09:00:00.000000Z", who="Later Reviewer")
    agent = fleet.agents()["recAgent0001"]
    assert (agent.review_by, agent.last_reviewed_at, agent.last_reviewed_by) == (
        day(80),
        "2026-03-01T09:00:00.000000Z",
        "Later Reviewer",
    )
    # The next attestation is stored as the record's one item, and wins because it is the latest.
    attest(fleet, day(300), "2026-06-01T09:00:00.000000Z")
    fleet.service.cache.clear()
    agent = fleet.agents()["recAgent0001"]
    assert (agent.review_by, agent.last_reviewed_by) == (day(300), "Ann")
    # The latest wins whichever of the two it is: an earlier-style item that is newer still decides.
    earlier_item(fleet, day(20), "2026-09-01T09:00:00.000000Z", who="Newest Reviewer")
    fleet.service.cache.clear()
    agent = fleet.agents()["recAgent0001"]
    assert (agent.review_by, agent.last_reviewed_by) == (day(20), "Newest Reviewer")


def test_the_export_carries_the_effective_review_date_and_the_last_review(fleet):
    from portal_api import export

    assert export.COLUMNS[-2:] == ("review_by", "last_reviewed_at")  # added at the end: positions stay
    fleet.records = [benign(reviewBy="2020-01-31"), benign(record_id="recAgent0002", agentId="second", runtimeArn=None)]
    attest(fleet, day(120), "2026-06-01T09:00:00.000000Z")
    fleet.service.cache.clear()
    rows = {row["agent_id"]: row for row in fleet.service.export_rows()}
    assert (rows["recAgent0001"]["review_by"], rows["recAgent0001"]["last_reviewed_at"]) == (
        day(120),
        "2026-06-01T09:00:00.000000Z",
    )
    # Never attested: the registration's own date, and no last review.
    assert (rows["recAgent0002"]["review_by"], rows["recAgent0002"]["last_reviewed_at"]) == ("2099-12-31", None)
    header, *lines = export.to_csv(list(rows.values())).splitlines()
    assert header.endswith(",review_by,last_reviewed_at")
    by_id = {line.split(",", 1)[0]: line for line in lines}
    assert by_id["recAgent0001"].endswith(f",{day(120)},2026-06-01T09:00:00.000000Z")
    assert by_id["recAgent0002"].endswith(",2099-12-31,")  # an unknown last review is an empty cell
    assert rows["recAgent0002"]["review_overdue"] is False and rows["recAgent0001"]["review_overdue"] is False


def test_the_summary_counts_the_effective_date(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    assert fleet.service.fleet_summary().flags["review_overdue"] == 1
    attest(fleet, day(120), "2026-06-01T09:00:00.000000Z")
    fleet.service.cache.clear()
    summary = fleet.service.fleet_summary()
    assert (summary.flags["review_overdue"], summary.review_attestations) == (0, "ok")


# --- the contract says what the code sends ---------------------------------------------------------


def test_the_contract_quotes_the_sentences_and_rule_identifiers_the_code_sends():
    from pathlib import Path

    from portal_api import reviews as review_rules
    from portal_api.actions import lifecycle_rules as rules

    root = Path(__file__).resolve().parent.parent
    contract = " ".join((root / "ACTIONS_CONTRACT.md").read_text().split())
    assert lifecycle_flow.RETIRED in contract
    assert "The registration was already retired; nothing was changed." in contract
    assert lifecycle_flow.ALREADY_RETIRED.startswith("The registration was already retired; nothing was changed.")

    def decide(action: str, **changes: Any) -> str:
        request = {
            "action": action,
            "role": "approver",
            "principal_id": "p",
            "record_tenant": "ws1",
            "held_tenants": ("ws1",),
            "holds_all_tenants": False,
            "record_status": "APPROVED",
            **changes,
        }
        return rules.evaluate(**request).reason

    sent = [
        decide("retire", role="developer").replace("'developer'", "'<role>'"),
        decide("retire", held_tenants=()),
        decide("retire", record_status="UPDATING"),
        decide("review", role="developer").replace("'developer'", "'<role>'"),
        decide("review", held_tenants=()),
        decide("review", record_status="DRAFT").replace("DRAFT", "<STATUS>"),
        decide("review", record_status="DEPRECATED"),
        *(rules.retired_refusal(action, "DEPRECATED") for action in ("approve", "reject", "update", "submit")),
        review_rules.date_error("2026-11-27", dt.date(2026, 11, 27)),
        "The review could not be recorded, so nothing was attested",
    ]
    for sentence in sent:
        assert sentence and sentence in contract, sentence
    for identifier in ("RET-01-P", "REV-01-P", "RET-04-N", "REV-04-N"):
        assert identifier in contract
    # The README names the same rules and the partition the attestations are kept in.
    readme = " ".join((root / "README.md").read_text().split())
    assert "pk = REVIEWS" in readme and "sk = RECORD#<record id>" in readme
    assert audit_reader.REVIEWS_KEY == "REVIEWS" and audit_reader.MAX_ATTESTATION_PAGES == 20
    assert "bounded to 20 pages" in readme and str(review_rules.MAX_INTERVAL_DAYS) in readme
