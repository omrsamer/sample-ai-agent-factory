# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""What the security review of wave 2 found, finding by finding: the attack, and what must still work.

S1  A statement that only carries the portal's Sid is not containment.
S2  Only a caller who has a part in a record or a Runtime writes into its history, and no read
    follows a history to its end.
S3  A Runtime has one ARN: the one the portal builds from the cell.
S4  A contain repeated while its sweeps are at work is answered at once.
S5  A release needs the tenant the Runtime was contained under.
S6  A reference into an account that several tenants share needs every one of them.
S7  The sweeper's session cannot write a policy, and each function has a session name of its own.
S9  The submitter cannot attest the review of its own record.
S10 A record's review is attested once in 24 hours.
S13 A write of the statement that may have been applied names a holder.

S8 (a registration's review date) is in ``test_lifecycle.py``, S11 (the evidence reload) in
``test_evidence.py``, S12 (a detected gateway) in ``test_detected_gateways.py`` and S14 (the
issuer's keys and app-only tokens) in ``test_token_verification.py``.
"""

from __future__ import annotations

import datetime as dt
import inspect
import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

import portal_api
from portal_api import arns, containment_policy, containment_timing, registrations, sweeps
from portal_api.actions import audit_writer, authority, containment_flow, engine, lifecycle_rules
from portal_api.actions import containment as containment_calls
from portal_api.actions import containment_rules as rules
from portal_api.actions import sweeper as sweeper_module
from portal_api.aws import agentcore
from portal_api.aws import audit as audit_reader
from portal_api.config import ConfigError, load_action_settings, load_settings
from portal_api.identity.provider import Principal
from portal_api.mappers.common import arn_parts
from portal_api.models.portal import AuditEvent, ContainmentInput
from tests import test_containment
from tests.conftest import BASE_ENV, CELL_ACCOUNT, CELLS, OTHER_ACCOUNT, REGION, RUNTIME_ARN, agent_document
from tests.fakes import FakeDynamo, client_error
from tests.test_actions import ANN, ANN2, DEV, DEV2
from tests.test_actions import SEC as RECORD_SEC
from tests.test_actions import World as RecordWorld
from tests.test_containment import (
    OTHER_STATEMENTS,
    PAT,
    PAT2,
    RUNTIME_ID,
    SEC,
    SRE,
    SRE2,
    VIEW,
    FakeCell,
    World,
    log_group,
    refusals_logged,
    session_stream,
    sid,
)
from tests.test_lifecycle import (
    a_day_later,
    attestation_items,
    attested,
    day,
    events_of,
    kinds,
    retire,
    review,
    reviews_items,
)
from tests.test_sweeps import KEY, SWEEPER_ENV, Run, SweepWorld, contained

read = test_containment.read  # the read API over the same cell, record and audit table

TABLE = BASE_ENV["PORTAL_AUDIT_TABLE"]
SID = containment_policy.CONTAINMENT_SID
CORE = list(containment_policy.CORE_INVOKE_ACTIONS)
ALL = list(containment_policy.ALL_INVOKE_ACTIONS)
SOURCES = sorted((Path(portal_api.__file__).resolve().parent).rglob("*.py"))


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SweepWorld:
    return SweepWorld(monkeypatch)


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> RecordWorld:
    return RecordWorld(monkeypatch)


def portal_statement(**changes: Any) -> dict[str, Any]:
    """The statement the portal writes, with one thing changed."""
    statement = containment_policy.containment_statement(RUNTIME_ARN)
    for name, value in changes.items():
        if value is None:
            statement.pop(name, None)
        else:
            statement[name] = value
    return statement


def policy_of(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


# What someone who can write the Runtime's policy can put under the portal's Sid. None of them
# denies invocation to everyone, or none of them is what the portal wrote.
DECOYS: dict[str, dict[str, Any]] = {
    "one harmless action": portal_statement(Action="bedrock-agentcore:GetAgentCard"),
    "an allow": portal_statement(Effect="Allow"),
    "a condition that never holds": portal_statement(Condition={"StringEquals": {"aws:PrincipalTag/none": "x"}}),
    "an empty condition": portal_statement(Condition={}),
    "one named principal": portal_statement(Principal={"AWS": "arn:aws:iam::111111111111:role/someone"}),
    "every AWS principal, which leaves out a Runtime that takes OAuth tokens": portal_statement(Principal={"AWS": "*"}),
    "a list of principals": portal_statement(Principal={"AWS": ["*"]}),
    "another Runtime": portal_statement(Resource=RUNTIME_ARN.replace("travel_agent", "other_agent")),
    "another spelling of the Runtime": portal_statement(Resource=RUNTIME_ARN.replace("arn:aws:", "arn:aws-cn:")),
    "two resources": portal_statement(Resource=[RUNTIME_ARN, RUNTIME_ARN + "x"]),
    "every resource": portal_statement(Resource="*"),
    "only one of the two core actions": portal_statement(Action=[CORE[0]]),
    "the core actions as one string": portal_statement(Action=",".join(CORE)),
    "a wildcard action": portal_statement(Action=["bedrock-agentcore:*"]),
    "the stop action as well, so that sessions could not be stopped": portal_statement(
        Action=[*ALL, "bedrock-agentcore:StopRuntimeSession"]
    ),
    "everything but invocation": portal_statement(Action=None, NotAction=CORE),
    "everyone but one principal": portal_statement(Principal=None, NotPrincipal={"AWS": "*"}),
    "every resource but this one": portal_statement(Resource=None, NotResource=RUNTIME_ARN),
    "a not-action beside the action": portal_statement(NotAction=["bedrock-agentcore:GetAgentCard"]),
    "an element the portal does not write": portal_statement(Comment="looks official"),
    "no effect": portal_statement(Effect=None),
    "an effect in another case": portal_statement(Effect="deny"),
}


# --- S1: the statement is recognised by its whole shape ------------------------------------------------


@pytest.mark.parametrize("actions", [ALL, CORE, [*CORE, ALL[1]]])
@pytest.mark.parametrize("resource", [RUNTIME_ARN, [RUNTIME_ARN]])
def test_the_statement_the_portal_writes_is_containment(actions, resource):
    statement = portal_statement(Action=actions, Resource=resource)
    assert containment_policy.is_containment(statement, RUNTIME_ARN)
    policy = policy_of(*OTHER_STATEMENTS, statement)
    assert containment_policy.state(policy, RUNTIME_ARN) == containment_policy.CONTAINED
    assert containment_policy.is_contained(policy, RUNTIME_ARN) is True
    assert containment_policy.denied_actions(policy, RUNTIME_ARN) == actions


@pytest.mark.parametrize("decoy", DECOYS.values(), ids=DECOYS.keys())
def test_a_statement_that_only_carries_the_portals_sid_is_not_containment(decoy):
    assert decoy.get("Sid") == SID
    assert containment_policy.is_containment(decoy, RUNTIME_ARN) is False
    policy = policy_of(*OTHER_STATEMENTS, decoy)
    assert containment_policy.state(policy, RUNTIME_ARN) == containment_policy.FOREIGN
    assert containment_policy.is_contained(policy, RUNTIME_ARN) is False
    assert containment_policy.denied_actions(policy, RUNTIME_ARN) == []
    # The statements that are not the portal's are counted as before, and a contain keeps them.
    assert containment_policy.other_statements(policy) == len(OTHER_STATEMENTS)


def test_what_a_policy_says_about_containment():
    state = containment_policy.state
    assert state(None, RUNTIME_ARN) == state("  ", RUNTIME_ARN) == containment_policy.ABSENT
    assert state(policy_of(*OTHER_STATEMENTS), RUNTIME_ARN) == containment_policy.ABSENT
    # The same deny without the portal's Sid is someone else's statement, not containment by the portal.
    assert state(policy_of(portal_statement(Sid="TeamDeny")), RUNTIME_ARN) == containment_policy.ABSENT
    assert state(policy_of(portal_statement(Sid=None)), RUNTIME_ARN) == containment_policy.ABSENT
    # The statement is about one Runtime: it is not containment of another.
    other = RUNTIME_ARN.replace("travel_agent", "other_agent")
    assert state(policy_of(portal_statement()), other) == containment_policy.FOREIGN
    # A decoy beside the real statement changes nothing: invocation is denied.
    both = policy_of(DECOYS["an allow"], portal_statement())
    assert state(both, RUNTIME_ARN) == containment_policy.CONTAINED
    # Things that are not statements at all.
    assert state(json.dumps({"Statement": ["text", 5, None]}), RUNTIME_ARN) == containment_policy.ABSENT
    assert containment_policy.is_containment("text", RUNTIME_ARN) is False
    assert containment_policy.is_containment(None, RUNTIME_ARN) is False


@pytest.mark.parametrize("decoy", DECOYS.values(), ids=DECOYS.keys())
def test_a_contain_replaces_a_decoy_and_says_so(world, read, decoy):
    """The attack: a decoy under the portal's Sid, so that a contain finds the Runtime "already contained"."""
    world.cell.policies[RUNTIME_ARN] = policy_of(*OTHER_STATEMENTS, decoy)
    world.cell.streams[log_group()] = [session_stream("running")]
    # Before: not contained, and the read side says what is in the policy.
    view = read(world.record_id, SEC)[1]
    assert (view["state"], view["detail"]) == ("not_contained", containment_policy.FOREIGN_STATEMENT)
    assert view["contained_by"] is None and view["contained_at"] is None

    code, body = world.post("contain", claims=SEC)
    assert code == 200, body
    # The policy was rewritten: it was not "already contained".
    assert (body["outcome"], body["changed"], body["state"]) == ("allowed", True, "contained")
    assert body["replaced_foreign_statement"] is True
    assert body["other_statements_kept"] == len(OTHER_STATEMENTS)
    assert containment_flow.REPLACED_FOREIGN in body["reason"]
    assert containment_flow.REPLACED_FOREIGN in body["steps"][0]["detail"]
    assert world.statements() == [*OTHER_STATEMENTS, containment_policy.containment_statement(RUNTIME_ARN)]
    assert body["denied_actions"] == ALL
    # Its sessions were stopped in the request, not left to a sweep that would find them later.
    assert world.cell.stopped == [(sid("running"), "DEFAULT")]
    # The history says that a statement the portal had not written was replaced.
    result = world.dynamo.events()[-1]
    assert (result["outcome"], result["status_before"], result["status_after"]) == (
        "allowed",
        "not_contained",
        "contained",
    )
    assert containment_flow.REPLACED_FOREIGN in result["reason"]
    view = read(world.record_id, SEC)[1]
    assert (view["state"], view["detail"], view["contained_by_me"]) == ("contained", None, True)


def test_a_contain_of_a_runtime_that_has_no_decoy_does_not_say_that_it_replaced_one(world):
    world.cell.policies[RUNTIME_ARN] = policy_of(*OTHER_STATEMENTS)
    body = world.post("contain", claims=SEC)[1]
    assert body["replaced_foreign_statement"] is False and containment_flow.REPLACED_FOREIGN not in body["reason"]
    again = world.post("contain", claims=PAT)[1]
    assert (again["outcome"], again["replaced_foreign_statement"]) == ("unchanged", False)


@pytest.mark.parametrize("name", ["an allow", "a condition that never holds", "one harmless action"])
def test_a_release_leaves_a_decoy_where_it_is_and_says_that_it_is_there(world, name):
    before = policy_of(*OTHER_STATEMENTS, DECOYS[name])
    world.cell.policies[RUNTIME_ARN] = before
    code, body = world.post("release", claims=PAT)
    assert code == 200, body
    assert (body["outcome"], body["changed"], body["state"]) == ("unchanged", False, "not_contained")
    assert containment_policy.FOREIGN_STATEMENT in body["reason"]
    assert containment_policy.FOREIGN_STATEMENT in body["steps"][0]["detail"]
    assert body["other_statements_kept"] == len(OTHER_STATEMENTS)
    # Not the portal's statement, so the release wrote nothing.
    assert world.cell.policies[RUNTIME_ARN] == before
    assert "put_resource_policy" not in world.cell.calls and "delete_resource_policy" not in world.cell.calls


def test_a_statement_changed_into_a_decoy_after_the_contain_no_longer_reads_as_contained(world, read):
    """Contained by the portal, then someone adds a condition to the statement."""
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.policies[RUNTIME_ARN] = policy_of(DECOYS["a condition that never holds"])
    view = read(world.record_id, PAT)[1]
    assert (view["state"], view["detail"]) == ("not_contained", containment_policy.FOREIGN_STATEMENT)
    assert view["contained_by"] is None and view["contained_at"] is None and view["contained_by_me"] is False
    # A sweep of that contain stops nothing: the Runtime is not contained.
    world.cell.streams[log_group()] = [session_stream("running")]
    run = Run(world)
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "skipped"
    assert world.cell.stopped == []
    (event,) = run.sweep_events()
    assert (event["outcome"], event["status_before"]) == ("skipped", "not_contained")
    assert containment_policy.FOREIGN_STATEMENT in event["reason"]
    # Containing again puts the portal's statement back.
    body = world.post("contain", claims=PAT)[1]
    assert (body["outcome"], body["replaced_foreign_statement"]) == ("allowed", True)
    assert world.statements() == [containment_policy.containment_statement(RUNTIME_ARN)]


def test_a_decoy_shows_as_not_contained_in_the_inventory_and_in_the_evidence(world, monkeypatch):
    class Reader:
        def get_resource_policy(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
            return {"policy": policy_of(DECOYS["an allow"])}

    assert agentcore.contained(Reader(), RUNTIME_ARN) is False
    assert agentcore.containment_state(Reader(), RUNTIME_ARN) == containment_policy.FOREIGN

    class Broken:
        def get_resource_policy(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
            raise RuntimeError("no access")

    assert agentcore.contained(Broken(), RUNTIME_ARN) is None
    assert agentcore.containment_state(Broken(), RUNTIME_ARN) is None


def test_a_decoy_is_in_the_evidence_document_as_not_contained_with_the_sentence(world, read, monkeypatch):
    from mangum import Mangum

    from portal_api import deps
    from portal_api.app import create_app
    from portal_api.aws import registry
    from portal_api.config import get_settings
    from tests.conftest import FakeClient, FakeClients, make_service, runtime_bundle
    from tests.test_api import event

    world.cell.policies[RUNTIME_ARN] = policy_of(DECOYS["one harmless action"])
    record = {**world.registry.records[world.record_id]}
    monkeypatch.setattr(registry, "list_records", lambda client, registry_id: [record])
    monkeypatch.setattr(agentcore, "list_runtimes", lambda client: [runtime_bundle()])
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
    response = Mangum(application, lifespan="off")(event(f"/agents/{world.record_id}/evidence", "GET", SEC), None)
    document = json.loads(response["body"])
    assert response["statusCode"] == 200, document
    section = document["containment"]
    assert (section["state"], section["detail"]) == ("not_contained", containment_policy.FOREIGN_STATEMENT)
    assert section["contained_by"] is None and section["contained_at"] is None
    # It is a fact about the agent, not something the document could not read.
    assert containment_policy.FOREIGN_STATEMENT not in document["limitations"]


def test_one_function_reads_a_policy_for_containment_and_every_user_goes_through_it():
    """Contain, release, the read API, the sweeper and the evidence all ask ``containment_policy``."""
    for path in SOURCES:
        text = path.read_text()
        if path.name == "containment_policy.py":
            continue
        # Nobody else looks at a statement's Sid, or names the portal's.
        assert "CONTAINMENT_SID" not in text, path.name
        assert '.get("Sid")' not in text and '["Sid"]' not in text, path.name
    signature = inspect.signature(containment_policy.is_contained)
    assert list(signature.parameters) == ["policy", "runtime_arn"]  # never the Sid alone
    assert list(inspect.signature(containment_policy.denied_actions).parameters) == ["policy", "runtime_arn"]
    # Where each user asks.
    package = Path(portal_api.__file__).resolve().parent
    flow = (package / "actions" / "containment_flow.py").read_text()
    # One place for a contain, a release, and a contain that is answered at once because it comes
    # too soon: the policy is read once, before anything is written, and everything follows from it.
    assert flow.count("found=containment_policy.state(policy, arn),") == 1
    assert flow.count("containment_policy.state(") == 1 and flow.count("containment.get_policy(") == 3
    assert flow.count("self._open(target, action)") == 1
    assert flow.count("containment_policy.is_contained(verified, target.runtime_arn)") == 2  # both read-backs
    sweeper_source = (package / "actions" / "sweeper.py").read_text()
    assert "containment_policy.state(containment.get_policy(control, arn), arn)" in sweeper_source
    assert "containment_policy.is_contained(containment.get_policy(control, arn), arn)" in sweeper_source
    assert (
        "containment_policy.state(resource_policy(client, runtime_arn), runtime_arn)"
        in (package / "aws" / "agentcore.py").read_text()
    )
    assert "agentcore.containment_state(" in (package / "service.py").read_text()


# --- S2: who writes into a history, and how far a read goes ------------------------------------------------


def stored(at: str, action: str, outcome: str, who: str = "someone", phase: str = "result", **extra: Any) -> AuditEvent:
    """An event as it is stored, for a history written straight into the table."""
    values = {
        "event_id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "at": at,
        "phase": phase,
        "action": action,
        "outcome": outcome,
        "reason": "seeded",
        "actor_subject": who,
        "actor_label": who,
        "actor_role": "security",
    }
    return AuditEvent(**{**values, **extra})


def long_ago(n: int) -> str:
    """A time before anything a test does now, later for a larger ``n``."""
    return f"2025-03-01T{n // 3600:02d}:{n // 60 % 60:02d}:{n % 60:02d}.000000Z"


def later(n: int) -> str:
    """A time after anything a test does now, later for a larger ``n``."""
    return f"2099-03-01T{n // 3600:02d}:{n // 60 % 60:02d}:{n % 60:02d}.000000Z"


def seed(dynamo: FakeDynamo, key: str, events: list[AuditEvent]) -> None:
    for event in events:
        audit_writer.put_event(dynamo, TABLE, key, event)
    forget(dynamo)


def forget(dynamo: FakeDynamo) -> None:
    """Start counting the table's reads and writes afresh."""
    dynamo.calls.clear()
    dynamo.queried.clear()
    dynamo.prefixes.clear()
    dynamo.pages_read = dynamo.items_read = 0


def security_of_ws2_only(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """A responder who may contain and release, and holds tenant ws2 only: not the Runtime's tenant."""
    roles = {**json.loads(BASE_ENV["PORTAL_GROUP_ROLE_MAP"]), "sec2": "security"}
    tenants = {**json.loads(BASE_ENV["PORTAL_GROUP_TENANT_MAP"]), "sec2": ["ws2"]}
    monkeypatch.setenv("PORTAL_GROUP_ROLE_MAP", json.dumps(roles))
    monkeypatch.setenv("PORTAL_GROUP_TENANT_MAP", json.dumps(tenants))
    return {"sub": "sec-ws2", "cognito:groups": "[sec2]"}


def test_a_responder_of_another_tenant_cannot_write_into_a_runtimes_history(world, monkeypatch, caplog):
    """The attack: repeat a contain or a release of another tenant's Runtime; each refusal was one more event."""
    outsider = security_of_ws2_only(monkeypatch)
    by_runtime_id = {"reason": "x", "runtime_arn": RUNTIME_ARN}
    with caplog.at_level("WARNING"):
        answers = []
        for _ in range(10):
            answers.append(world.post("contain", claims=outsider))
            answers.append(world.post("release", claims=outsider))
            answers.append(world.post("contain", agent_id=RUNTIME_ID, claims=SRE2, body=by_runtime_id))
            answers.append(world.post("release", agent_id=RUNTIME_ID, claims=outsider, body=by_runtime_id))
    assert {code for code, _ in answers} == {403}
    assert all("CON-04-N" in body["detail"] for _, body in answers)
    # Not one item, and not one read: the caller has no part in this Runtime.
    assert world.dynamo.items == {} and world.dynamo.calls == []
    assert world.cell.calls == [] and RUNTIME_ARN not in world.cell.policies
    # Every attempt is in the function's log, under the request id its answer carries.
    logged = refusals_logged(caplog)
    assert len(logged) == len(answers) == 40
    for (_, body), line in zip(answers, logged, strict=True):
        assert body["request_id"] in line and "CON-04-N" in line and RUNTIME_ARN in line
    assert len({body["request_id"] for _, body in answers}) == 40

    # The Runtime's own tenant is not affected: it contains and releases as before.
    assert world.post("contain", claims=SEC)[0] == 200
    assert world.post("release", claims=PAT)[0] == 200
    assert {e["pk"] for e in world.dynamo.events()} == {KEY}


@pytest.mark.parametrize(
    ("runtime_arn", "claims", "status", "said"),
    [
        # An account and Region in which the portal has no cell: the tenant cannot be determined.
        (f"arn:aws:bedrock-agentcore:{REGION}:999999999999:runtime/{RUNTIME_ID}", SRE, 403, "CON-05-N"),
        (f"arn:aws:bedrock-agentcore:us-east-1:{CELL_ACCOUNT}:runtime/{RUNTIME_ID}", SEC, 403, "CON-05-N"),
        # The platform role holds every tenant, but there is no cell to contain the Runtime in.
        (f"arn:aws:bedrock-agentcore:{REGION}:999999999999:runtime/{RUNTIME_ID}", PAT, 409, "not enabled"),
        # A cell that did not opt in to containment.
        (f"arn:aws:bedrock-agentcore:{REGION}:{OTHER_ACCOUNT}:runtime/{RUNTIME_ID}", PAT, 409, "not enabled"),
        (f"arn:aws:bedrock-agentcore:{REGION}:{OTHER_ACCOUNT}:runtime/{RUNTIME_ID}", SRE, 403, "CON-04-N"),
    ],
)
def test_nothing_is_written_under_a_name_the_caller_chose(world, caplog, runtime_arn, claims, status, said):
    """A refusal about a Runtime that is in no cell the portal can contain was a new partition each time."""
    body = {"reason": "x", "runtime_arn": runtime_arn}
    with caplog.at_level("WARNING"):
        for action in ("contain", "release", "contain"):
            code, answer = world.post(action, agent_id=RUNTIME_ID, claims=claims, body=body)
            if action == "release" and claims is SRE:
                assert code == 403 and "CON-02-N" in answer["detail"]  # an sre never releases
            else:
                assert code == status and said in answer["detail"], answer
            assert answer["request_id"]
    assert world.dynamo.items == {} and world.dynamo.calls == [] and world.cell.calls == []
    assert len(refusals_logged(caplog)) == 3


def test_the_holders_own_refused_release_is_recorded_once(world, caplog):
    """The person a release must not come from could add an event to the history with every attempt."""
    assert world.post("contain", claims=SEC)[0] == 200
    recorded = len(world.dynamo.events())
    with caplog.at_level("WARNING"):
        answers = [world.post("release", claims=SEC) for _ in range(6)]
    assert all(code == 403 and "CON-03-N" in body["detail"] for code, body in answers)
    assert len({body["request_id"] for _, body in answers}) == 6
    # One refusal on record, by the person and under the request id of the first attempt.
    denied = [e for e in world.dynamo.events() if e["outcome"] == "denied"]
    assert len(denied) == 1 and len(world.dynamo.events()) == recorded + 1
    assert (denied[0]["actor_subject"], denied[0]["request_id"]) == ("sec-1", answers[0][1]["request_id"])
    repeats = [r.getMessage() for r in caplog.records if "already on record" in r.getMessage()]
    assert len(repeats) == 5
    assert all(body["request_id"] in line for (_, body), line in zip(answers[1:], repeats, strict=True))
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)

    # Someone else's refusal is not that one: a second person who contains again and is the holder
    # of the next containment gets a refusal of their own on record.
    assert world.post("release", claims=PAT)[0] == 200
    assert world.post("contain", claims=PAT)[0] == 200
    assert world.post("release", claims=PAT)[0] == 403
    assert world.post("release", claims=PAT)[0] == 403
    denied = [e for e in world.dynamo.events() if e["outcome"] == "denied"]
    assert [e["actor_subject"] for e in denied] == ["sec-1", "pat-1"]
    # And the first person's refusal in the next containment is recorded again, once.
    assert world.post("release", claims=SEC)[0] == 200
    assert world.post("contain", claims=SEC)[0] == 200
    assert [world.post("release", claims=SEC)[0] for _ in range(3)] == [403, 403, 403]
    denied = [e for e in world.dynamo.events() if e["outcome"] == "denied"]
    assert [e["actor_subject"] for e in denied] == ["sec-1", "pat-1", "sec-1"]


def test_a_release_reads_back_only_to_the_contain_it_is_about(world):
    """Years of history under a Runtime do not make a release slower: the read stops at the holder."""
    old = []
    for n in range(0, 3000, 2):
        old.append(stored(long_ago(n), "contain", "allowed", "old-timer"))
        old.append(stored(long_ago(n + 1), "release", "allowed", "another"))
    seed(world.dynamo, KEY, old)
    assert world.post("contain", claims=SEC)[0] == 200
    forget(world.dynamo)

    code, body = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in body["detail"]
    # One page, and it holds the contain: the 3,000 older events were never asked for.
    assert (world.dynamo.pages_read, world.dynamo.calls.count("query")) == (1, 1)
    assert world.dynamo.items_read == audit_reader.PAGE_SIZE
    forget(world.dynamo)
    assert world.post("release", claims=PAT)[0] == 200
    assert world.dynamo.pages_read == 1 and world.dynamo.items_read == audit_reader.PAGE_SIZE


def test_a_contain_never_waits_or_fails_for_the_history(world):
    """An emergency action does not depend on how long the Runtime's history is, or on reading it."""
    # A history written before there were two ranges: its sweeps lie among the events a release reads.
    seed(world.dynamo, KEY, [stored(later(n), "sweep", "skipped", "agent-factory-portal") for n in range(2500)])
    # It looks at the newest events once, to see whether it was contained a moment ago: one request
    # for each range of the history, one page each.
    code, body = world.post("contain", claims=SEC)
    assert code == 200 and body["state"] == "contained", body
    assert (world.dynamo.calls.count("query"), world.dynamo.pages_read) == (2, 2)
    assert world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#")]
    assert world.dynamo.items_read == audit_reader.PAGE_SIZE
    assert world.post("release", claims=PAT)[0] == 409  # the holder is too far back: see the next test
    # And when the trail cannot be read at all, it goes on as it always did.
    world.cell.policies.clear()
    world.dynamo.fail_query = True
    code, body = world.post("contain", claims=SEC)
    assert (code, body["outcome"], body["state"]) == (200, "allowed", "contained"), body
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)


def test_a_release_fails_closed_when_the_holder_is_not_among_the_newest_events(world, caplog):
    """More events since the contain than a decision reads: who contained it is not known, so nobody releases."""
    assert world.post("contain", claims=SEC)[0] == 200
    flood = [stored(later(n), "sweep", "skipped", "agent-factory-portal") for n in range(2100)]
    seed(world.dynamo, KEY, flood)
    stored_before = len(world.dynamo.items)

    for claims in (PAT, SEC):  # neither a second person nor the holder
        with caplog.at_level("WARNING"):
            code, body = world.post("release", claims=claims)
        assert code == 409 and body["detail"] == containment_flow.HOLDER_NOT_FOUND, body
        assert body["request_id"] and body["action"] == "release"
    assert str(audit_reader.MAX_DECISION_EVENTS) in containment_flow.HOLDER_NOT_FOUND
    # Still contained, nothing written, and the read was bounded.
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    assert len(world.dynamo.items) == stored_before and "put_item" not in world.dynamo.calls
    assert world.dynamo.items_read == 2 * audit_reader.MAX_DECISION_EVENTS
    assert world.dynamo.pages_read == 2 * (audit_reader.MAX_DECISION_EVENTS // audit_reader.PAGE_SIZE)
    assert len(refusals_logged(caplog)) == 2
    # It does not read as "nobody contained it": that would let the person who did release it.
    assert audit_reader.holder(audit_reader.read_back(world.dynamo, TABLE, KEY).events).decided is False


def test_reading_a_history_back_stops_as_soon_as_it_can():
    dynamo = FakeDynamo()
    seed(dynamo, "RECORD#x", [stored(long_ago(n), "update", "denied", reason=f"n{n}") for n in range(1000)])

    def reasons(trail: audit_reader.Trail) -> list[str]:
        return [e.reason for e in trail.events]

    # To the end of a short history: one page, which says that nothing older exists.
    whole = audit_reader.read_back(dynamo, TABLE, "RECORD#x", max_events=5000, page_size=2000)
    assert (len(whole.events), whole.ended, dynamo.pages_read) == (1000, True, 1)
    assert reasons(whole)[:2] == ["n999", "n998"] and len(whole.items) == 1000  # newest first, raw items too
    # Until the caller has enough.
    forget(dynamo)
    some = audit_reader.read_back(dynamo, TABLE, "RECORD#x", lambda events: len(events) >= 250, page_size=100)
    assert (len(some.events), some.ended, dynamo.pages_read, dynamo.items_read) == (300, False, 3, 300)
    # Never more than the bound, whatever the caller says.
    forget(dynamo)
    capped = audit_reader.read_back(dynamo, TABLE, "RECORD#x", lambda events: False, max_events=400, page_size=100)
    assert (len(capped.events), capped.ended, dynamo.pages_read) == (400, False, 4)
    # A history that ends exactly at a page's end is read to its end, one empty page later.
    forget(dynamo)
    exact = audit_reader.read_back(dynamo, TABLE, "RECORD#x", max_events=5000, page_size=500)
    assert (len(exact.events), exact.ended, dynamo.pages_read) == (1000, True, 3)
    # From the other end.
    forget(dynamo)
    first = audit_reader.read_back(dynamo, TABLE, "RECORD#x", max_events=5, page_size=5, oldest_first=True)
    assert reasons(first) == ["n0", "n1", "n2", "n3", "n4"] and dynamo.items_read == 5
    # The newest of a history, and whether there is more.
    forget(dynamo)
    shown, more = audit_reader.newest(dynamo, TABLE, "RECORD#x", 200)
    assert (len(shown), more, shown[0].reason, dynamo.pages_read, dynamo.items_read) == (200, True, "n999", 1, 201)
    assert audit_reader.newest(dynamo, TABLE, "RECORD#x", 1000) == (whole.events, False)
    assert audit_reader.newest(dynamo, TABLE, "RECORD#none", 200) == ([], False)
    empty = audit_reader.read_back(dynamo, TABLE, "RECORD#none")
    assert (empty.events, empty.items, empty.ended) == ([], [], True)


def test_a_bounded_read_is_a_real_query_that_asks_for_one_page_at_a_time():
    """Against the service's own model of the request: the page size is sent, and no page is asked for in vain."""
    import boto3
    from botocore.stub import Stubber

    client = boto3.client("dynamodb", region_name=REGION, aws_access_key_id="test", aws_secret_access_key="test")
    request = {
        "TableName": TABLE,
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":pk": {"S": KEY}, ":prefix": {"S": "EVENT#"}},
        "ConsistentRead": True,
        "ScanIndexForward": False,
        "Limit": audit_reader.PAGE_SIZE,
    }

    def item(event: AuditEvent) -> dict[str, Any]:
        values = {name: {"S": str(value)} for name, value in event.model_dump().items() if value is not None}
        return {"pk": {"S": KEY}, "sk": {"S": f"EVENT#{event.at}#{event.event_id}"}, **values}

    sweep = item(stored(long_ago(30), "sweep", "allowed", "agent-factory-portal"))
    contain = item(stored(long_ago(20), "contain", "allowed", "sam"))
    older = item(stored(long_ago(10), "release", "allowed", "pat"))
    last_key = {"pk": contain["pk"], "sk": contain["sk"]}

    # The first page settles who holds the containment: the second is never requested.
    with Stubber(client) as stub:
        stub.add_response("query", {"Items": [sweep, contain], "LastEvaluatedKey": last_key}, request)
        trail, found = audit_reader.read_holder(client, TABLE, RUNTIME_ARN)
        stub.assert_no_pending_responses()
    assert (found.event.actor_subject, found.decided, trail.ended, len(trail.events)) == ("sam", True, False, 2)

    # A page that settles nothing is followed by the next one, from where the first ended.
    with Stubber(client) as stub:
        stub.add_response("query", {"Items": [sweep], "LastEvaluatedKey": last_key}, request)
        stub.add_response("query", {"Items": [older]}, {**request, "ExclusiveStartKey": last_key})
        trail, found = audit_reader.read_holder(client, TABLE, RUNTIME_ARN)
        stub.assert_no_pending_responses()
    assert (found.event, found.decided, trail.ended) == (None, True, True)

    # A view asks for one more event than it shows, in one request, and reads from the newest.
    with Stubber(client) as stub:
        stub.add_response("query", {"Items": [sweep, contain], "LastEvaluatedKey": last_key}, {**request, "Limit": 2})
        shown, more = audit_reader.newest(client, TABLE, KEY, 1)
        stub.assert_no_pending_responses()
    assert ([e.action for e in shown], more) == (["sweep"], True)

    # The oldest events are asked for from the other end.
    with Stubber(client) as stub:
        stub.add_response("query", {"Items": [older]}, {**request, "ScanIndexForward": True, "Limit": 5})
        first = audit_reader.read_back(client, TABLE, KEY, max_events=5, page_size=5, oldest_first=True)
        stub.assert_no_pending_responses()
    assert [e.action for e in first.events] == ["release"] and first.ended is True


def test_who_holds_a_containment_is_settled_by_the_newest_part_of_its_history():
    def scan(*newest_first: AuditEvent) -> tuple[str | None, bool]:
        found = audit_reader.holder(list(newest_first))
        return (found.event.actor_subject if found.event else None), found.decided

    contain = stored(long_ago(10), "contain", "allowed", "sam")
    release = stored(long_ago(20), "release", "allowed", "pat")
    again = stored(long_ago(30), "contain", "unchanged", "cy")
    refused = stored(long_ago(40), "release", "denied", "sam")
    sweep = stored(long_ago(50), "sweep", "allowed", "agent-factory-portal")
    # Settled by a contain or a release that was allowed: nothing older can change it.
    assert scan(sweep, refused, contain) == ("sam", True)
    assert scan(sweep, release, contain) == (None, True)
    assert scan(again, release, contain) == ("cy", True)
    # Not settled: these events alone do not say who holds it, and older ones could.
    assert scan() == (None, False)
    assert scan(sweep, refused) == (None, False)
    assert scan(again) == ("cy", False)
    assert scan(again, contain) == ("sam", True)
    # A contain that may have written its statement settles it; one that wrote nothing does not.
    assert scan(stored(long_ago(60), "contain", "failed", "sam", status_after="unknown")) == ("sam", True)
    assert scan(stored(long_ago(60), "contain", "failed", "sam", status_after="not_contained")) == (None, False)
    # An intent with no result settles it; one whose result is there leaves it to the result.
    intent = stored(long_ago(5), "contain", "allowed", "sam", phase="intent", request_id="r-1")
    assert scan(intent) == ("sam", True)
    lost = stored(long_ago(6), "contain", "failed", "sam", request_id="r-1", status_after="not_contained")
    assert scan(lost, intent) == (None, False)
    # The same answer as the function every caller used before, which returns the event alone.
    for events in ([sweep, refused, contain], [again, release, contain], [again], []):
        assert audit_reader.container(events) is audit_reader.holder(events).event


# --- S2: records ---------------------------------------------------------------------------------------


def record_events(world: RecordWorld, record_id: str) -> list[dict[str, str]]:
    return [e for e in world.dynamo.events() if e["pk"] == f"RECORD#{record_id}"]


OUTSIDERS = {
    "update": lambda w, r: w.update(r, DEV2),
    "submit": lambda w, r: w.submit(r, DEV2),
    "delete": lambda w, r: w.delete(r, DEV2),
    "approve": lambda w, r: w.decide("approve", r, ANN2),
    "reject": lambda w, r: w.decide("reject", r, ANN2),
    "retire": lambda w, r: retire(w, r, ANN2),
    "review": lambda w, r: review(w, r, ANN2),
}


@pytest.mark.parametrize("action", OUTSIDERS)
def test_someone_of_another_tenant_cannot_write_into_a_records_history(records, caplog, action):
    """The attack: an approver or a registrar of tenant ws2 repeats an action on a record of tenant ws1."""
    record_id = records.new_record("APPROVED" if action in ("retire", "review") else "PENDING_APPROVAL")
    before = record_events(records, record_id)
    status = records.status(record_id)
    forget(records.dynamo)
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        answers = [OUTSIDERS[action](records, record_id) for _ in range(25)]
    assert {code for code, _ in answers} == {403}
    assert all("tenant" in body["detail"] and body["request_id"] for _, body in answers)
    # Not one event, in this record's history or anywhere else, and the record's history was not read.
    assert record_events(records, record_id) == before
    assert records.dynamo.calls == []
    assert records.status(record_id) == status
    logged = [r.getMessage() for r in caplog.records if "not written to the audit trail" in r.getMessage()]
    assert len(logged) == 25
    for (_, body), line in zip(answers, logged, strict=True):
        assert body["request_id"] in line and f"action={action}" in line and f"record={record_id}" in line


def test_a_refusal_of_someone_who_has_a_part_in_the_record_is_still_in_its_history(records):
    record_id = records.new_record("PENDING_APPROVAL")
    # A status conflict, from the tenant's own registrar.
    assert records.submit(record_id, DEV)[0] == 409
    assert record_events(records, record_id)[-1]["outcome"] == "denied"
    # Separation of duties: the platform role holds both authorities and every tenant.
    own = records.create(PAT, agent_id="pats-agent")[1]["registration"]["record_id"]
    assert records.submit(own, PAT)[0] == 200
    code, body = records.decide("approve", own, PAT)
    assert code == 403 and "REG-11-N" in body["detail"]
    last = record_events(records, own)[-1]
    assert (last["outcome"], last["actor_subject"], last["request_id"]) == ("denied", "pat-1", body["request_id"])
    # A retired record refuses an approval, and says so in its history.
    assert retire(records, record_id, ANN)[0] == 200
    assert records.decide("approve", record_id, ANN)[0] == 409
    assert record_events(records, record_id)[-1]["outcome"] == "denied"


def principal(role: str, groups: tuple[str, ...], subject: str = "p-1") -> Principal:
    return Principal(subject=subject, email=None, display_name=None, groups=groups, role=role)


@pytest.mark.parametrize(
    ("role", "groups", "action", "tenant", "written"),
    [
        ("developer", ("devs",), "update", "ws1", True),
        ("developer", ("devs",), "update", "ws2", False),  # the authority, not the tenant
        ("developer", ("devs",), "approve", "ws1", False),  # the tenant, not the authority
        ("approver", ("approvers",), "approve", "ws1", True),
        ("approver", ("approvers",), "retire", "ws1", True),
        ("approver", ("approvers",), "review", "ws2", False),
        ("approver", ("approvers",), "submit", "ws1", False),
        ("security", ("sec",), "reject", "ws2", True),
        ("platform", ("platform-admins",), "delete", "ws9", True),  # every tenant, both authorities
        ("readonly", ("viewers",), "update", "ws1", False),
        ("sre", ("sre-team",), "retire", "ws1", False),
        ("developer", ("devs",), "contain", "ws1", False),  # not an action of a record
        ("developer", ("devs",), "update", None, False),
        ("developer", ("devs",), "update", "", False),
    ],
)
def test_only_a_caller_with_a_part_in_the_record_gets_a_refusal_written(role, groups, action, tenant, written):
    """The one place a refusal is written decides this itself, whatever the flow that called it."""
    settings = load_action_settings({**BASE_ENV, "PORTAL_ACTION_ROLE": "registrar"})
    caller = principal(role, groups)
    assert authority.has_part(caller, settings, action, tenant) is written
    dynamo = FakeDynamo()
    target = engine.Target(action=action, tenant_id=tenant, record_name="agent-x", record_id="rec000000042")
    error = engine.ActionEngine(settings, None, dynamo, caller).deny(target, 409, "refused for a reason")
    assert (error.status, error.detail, bool(error.extra["request_id"])) == (409, "refused for a reason", True)
    assert bool(dynamo.items) is written
    if written:
        (item,) = dynamo.events()
        assert (item["pk"], item["outcome"], item["request_id"]) == (
            "RECORD#rec000000042",
            "denied",
            error.extra["request_id"],
        )


def test_an_approval_reads_back_only_to_the_submit_it_is_about(records):
    record_id = records.new_record("PENDING_APPROVAL")
    key = f"RECORD#{record_id}"
    seed(records.dynamo, key, [stored(long_ago(n), "update", "allowed", "dev-0") for n in range(3000)])
    code, body = records.decide("approve", record_id, ANN)
    assert code == 200, body
    assert records.dynamo.queried == [key] and records.dynamo.pages_read == 1
    assert records.dynamo.items_read == audit_reader.PAGE_SIZE
    # The submitter is found there, so separation of duties holds as before.
    record_two = records.create(PAT, agent_id="pats-agent")[1]["registration"]["record_id"]
    assert records.submit(record_two, PAT)[0] == 200
    seed(records.dynamo, f"RECORD#{record_two}", [stored(long_ago(n), "update", "allowed") for n in range(3000)])
    assert "REG-11-N" in records.decide("approve", record_two, PAT)[1]["detail"]


@pytest.mark.parametrize("action", ["approve", "reject"])
def test_an_approval_fails_closed_when_the_submit_is_not_among_the_newest_events(records, action):
    """Who submitted the record is not known, and that must not read as "nobody the portal knows"."""
    record_id = records.create(PAT, agent_id="pats-agent")[1]["registration"]["record_id"]
    assert records.submit(record_id, PAT)[0] == 200
    key = f"RECORD#{record_id}"
    seed(records.dynamo, key, [stored(later(n), "update", "denied", "dev-1") for n in range(2100)])
    stored_before = len(records.dynamo.items)
    # The submitter itself, who would otherwise decide its own record, and anyone else.
    for claims in (PAT, ANN):
        code, body = records.decide(action, record_id, claims)
        assert code == 409 and body["detail"] == engine.SUBMITTER_NOT_FOUND, body
    assert records.status(record_id) == "PENDING_APPROVAL"
    assert len(records.dynamo.items) == stored_before  # nothing written either
    assert records.dynamo.items_read == 2 * audit_reader.MAX_DECISION_EVENTS
    found, settled = audit_reader.read_submitter(records.dynamo, TABLE, record_id)
    assert (found, settled) == (None, False)
    # A record with no submit at all, read to its end, has no submitter, and that is settled.
    assert audit_reader.read_submitter(records.dynamo, TABLE, "rec000000404") == (None, True)


# --- S2: what a view shows of a long history ---------------------------------------------------------------


def test_the_containment_view_shows_the_newest_events_and_says_when_there_are_more(world, read):
    old = []
    for n in range(0, 500, 2):
        old.append(stored(long_ago(n), "contain", "allowed", "old-timer"))
        old.append(stored(long_ago(n + 1), "release", "allowed", "another"))
    seed(world.dynamo, KEY, old)
    assert world.post("contain", claims=SEC)[0] == 200
    forget(world.dynamo)

    view = read(world.record_id, PAT)[1]
    limit = audit_reader.MAX_VIEW_EVENTS
    assert len(view["events"]) == limit == 200 and view["events_truncated"] is True
    assert [(e["action"], e["phase"]) for e in view["events"][:2]] == [("contain", "result"), ("contain", "intent")]
    # Who holds it, and the sweeps of this containment, are right although the history was cut.
    assert (view["state"], view["contained_by"], view["detail"]) == ("contained", "sec-1", None)
    assert view["sweeps"] == {"scheduled": 2, "done": 0}
    # One request for each range of the Runtime's history, for one more event than is shown. (The
    # other two requests are the inventory's, for the review attestations.)
    assert world.dynamo.prefixes == [("REVIEWS", "RECORD#"), ("REVIEWS", "EVENT#"), (KEY, "EVENT#"), (KEY, "OTHER#")]
    assert (world.dynamo.pages_read, world.dynamo.items_read) == (4, limit + 1)
    # A role that is not shown the incident record is not told anything about its length either.
    other = read(world.record_id, VIEW)[1]
    assert (other["events"], other["events_truncated"], other["state"]) == ([], False, "contained")


def test_a_short_history_is_shown_whole(world, read):
    assert world.post("contain", claims=SEC)[0] == 200
    view = read(world.record_id, PAT)[1]
    assert len(view["events"]) == 2 and view["events_truncated"] is False


def test_the_view_says_when_the_holder_is_not_among_the_newest_events(world, read):
    assert world.post("contain", claims=SEC)[0] == 200
    seed(world.dynamo, KEY, [stored(later(n), "sweep", "skipped", "agent-factory-portal") for n in range(2100)])
    view = read(world.record_id, PAT)[1]
    assert (view["state"], view["contained_by"], view["contained_at"]) == ("contained", None, None)
    assert view["detail"].startswith("Who contained the agent could not be established")
    assert len(view["events"]) == 200 and view["events_truncated"] is True
    assert world.dynamo.items_read <= audit_reader.MAX_DECISION_EVENTS + audit_reader.MAX_VIEW_EVENTS + 1


def test_a_registrations_history_shows_the_newest_events_and_says_when_there_are_more(records):
    record_id = records.new_record("PENDING_APPROVAL")
    name = "agent-ws1-travel-agent-nonprod"
    whole = records.call("read", "GET", f"/registrations/{record_id}/history", ANN)[1]
    assert whole["events_truncated"] is False and [e["action"] for e in whole["events"]][-1] == "create"
    extra = [stored(later(n), "update", "denied", "dev-1", record_name=name) for n in range(450)]
    seed(records.dynamo, f"RECORD#{record_id}", extra)

    code, history = records.call("read", "GET", f"/registrations/{record_id}/history", ANN)
    assert code == 200 and len(history["events"]) == 200 and history["events_truncated"] is True
    # Newest first, and the newest of them.
    assert history["events"] == sorted(history["events"], key=lambda e: (e["at"], e["event_id"]), reverse=True)
    assert history["events"][0]["at"] == later(449) and history["events"][-1]["at"] == later(250)
    # Two bounded requests: the record's own history, and the one filed under its name.
    assert records.dynamo.queried == [f"RECORD#{record_id}", f"RECORD#NAME#{name}"]
    assert records.dynamo.items_read <= 2 * 201

    # The detail reads a bounded part of the history too. Who created the record is its oldest
    # event, which is looked up from the other end.
    seed(records.dynamo, f"RECORD#{record_id}", [stored(later(1000 + n), "update", "denied") for n in range(1700)])
    code, detail = records.call("read", "GET", f"/registrations/{record_id}", ANN)
    assert code == 200, detail
    assert (detail["created_by"], detail["created_by_label"]) == ("dev-1", "dev@example.com")
    # The submit is further back than a read goes, so the detail does not name the submitter.
    # (The approver function then refuses to decide the record, for the same reason.)
    assert detail["submitted_by"] is None and detail["submitted_by_me"] is False
    assert records.dynamo.queried == [f"RECORD#{record_id}"] * 2
    assert records.dynamo.items_read == audit_reader.MAX_DECISION_EVENTS + 5


def test_the_evidence_document_shows_the_newest_events_and_says_when_there_are_more(world, monkeypatch):
    old = []
    for n in range(0, 500, 2):
        old.append(stored(long_ago(n), "contain", "allowed", "old-timer"))
        old.append(stored(long_ago(n + 1), "release", "allowed", "another"))
    seed(world.dynamo, KEY, old)
    past = [stored(long_ago(n), "update", "denied", "dev-1") for n in range(450)]
    seed(world.dynamo, f"RECORD#{world.record_id}", past)
    assert world.post("contain", claims=SEC)[0] == 200
    get = read_api(world, monkeypatch)

    code, document = get(f"/agents/{world.record_id}/evidence", PAT)
    assert code == 200, document
    limit = audit_reader.MAX_VIEW_EVENTS
    # The registration's events: the newest 200, oldest first, and the document says that there are more.
    assert len(document["decisions"]) == limit and document["decisions_truncated"] is True
    assert document["decisions"][-1]["at"] == long_ago(449) and document["decisions"][0]["at"] == long_ago(250)
    # The containment events likewise, and who holds the containment is right although they were cut.
    section = document["containment"]
    assert len(section["events"]) == limit and section["events_truncated"] is True
    assert (section["state"], section["contained_by"]) == ("contained", "sec-1")
    assert section["events"][-1]["action"] == "contain" and section["events"][-1]["actor_subject"] == "sec-1"
    said = [line for line in document["limitations"] if "holds more events than the 200 newest" in line]
    assert said == [
        "The registration's history holds more events than the 200 newest, which are the ones listed here.",
        "The containment history holds more events than the 200 newest, which are the ones listed here.",
    ]
    # A caller who is not shown the incident record is told nothing about its length.
    other = get(f"/agents/{world.record_id}/evidence", VIEW)[1]
    assert (other["containment"]["events"], other["containment"]["events_truncated"]) == ([], False)
    assert other["decisions_truncated"] is True

    # Short histories are whole, and the document says nothing.
    world.dynamo.items.clear()
    assert world.post("contain", claims=PAT)[0] == 200
    short = read_api(world, monkeypatch)(f"/agents/{world.record_id}/evidence", PAT)[1]
    assert (short["decisions_truncated"], short["containment"]["events_truncated"]) == (False, False)
    assert not [line for line in short["limitations"] if "holds more events" in line]


def test_the_documents_say_what_the_code_does_about_statements_histories_and_arns():
    root = Path(portal_api.__file__).resolve().parent.parent

    def text(name: str) -> str:
        return " ".join((root / name).read_text().split())

    containment, actions, readme = text("CONTAINMENT_CONTRACT.md"), text("ACTIONS_CONTRACT.md"), text("README.md")
    view, decision = audit_reader.MAX_VIEW_EVENTS, audit_reader.MAX_DECISION_EVENTS
    for said in (
        # S1
        "**Contained means the portal's statement, whole.**",
        f'"{containment_policy.FOREIGN_STATEMENT}"',
        f'"{containment_flow.REPLACED_FOREIGN}"',
        "replaced_foreign_statement: boolean;",
        # S2
        "**Who writes into a Runtime's history.** Only a caller who has a part in the Runtime",
        "A refusal is written once for each person, rule and containment, and logged after that.",
        f"events: AuditEvent[]; // the newest {view} events of the Runtime's history, newest first",
        "events_truncated: boolean;",
        f"at most {decision} events",
        f"A contain looks at the newest {audit_reader.PAGE_SIZE} events of each range of the Runtime's history, "
        "one request each",
        # S3
        "**One ARN per Runtime.**",
        "refused with 422 before anything is read",
        "so can any principal of the Platform account that holds `lambda:InvokeFunction` on it",
    ):
        assert said in containment, said
    assert "only the sweep queue invokes it" not in containment
    for said in (
        f"events: AuditEvent[]; // the newest {view} events of the record's history, newest first",
        "events_truncated: boolean; // true: the history holds older events that are not listed",
        "decisions_truncated: boolean;",
        "events_truncated: boolean; // true: the Runtime's history holds older events that are not listed",
        f"and at most {decision} events",
        '(`"cross-tenant update is denied"`, `RET-02-N`, `REV-02-N` and the like)',
    ):
        assert said in actions, said
    for said in (
        "**What counts as contained.**",
        "**One ARN per Runtime.**",
        "`portal_api/arns.py`, pure",
        "**Who writes into a Runtime's history.**",
        "**How far a read of the history goes.**",
        "**How far a read of a history goes.**",
        f"and at most {decision} events",
        f"show the newest {view} events",
    ):
        assert said in readme, said
    # The sentences the functions answer with name the bound the code has.
    assert str(decision) in containment_flow.HOLDER_NOT_FOUND and str(decision) in engine.SUBMITTER_NOT_FOUND
    for document in (containment, actions, readme):
        assert "\u2013" not in document and "\u2014" not in document


def test_no_function_reads_a_history_without_a_bound():
    source = inspect.getsource(audit_reader)
    # The two that read a whole partition are gone, and nothing else took their place.
    assert not hasattr(audit_reader, "query_events") and not hasattr(audit_reader, "query_items")
    # Its definition, ``read_back``, the attestations, and the look at the one item that claims a sweep.
    assert source.count("_pages(") == 4
    claim = inspect.getsource(audit_reader.sweep_claim_id)
    assert "page_size=1" in claim and "break" in claim  # one request, for one item
    assert "MAX_ATTESTATION_PAGES" in inspect.getsource(audit_reader.query_attestations)
    assert "max_events" in inspect.getsource(audit_reader.read_back)
    assert (audit_reader.MAX_VIEW_EVENTS, audit_reader.MAX_DECISION_EVENTS) == (200, 2000)
    for path in SOURCES:
        text = path.read_text()
        assert "query_events" not in text and "query_items" not in text, path.name
        if path.name != "audit.py":
            # Nobody builds a query of the audit table of their own.
            assert 'get_paginator("query")' not in text and ".query(" not in text, path.name


# --- S3: a Runtime has one ARN ------------------------------------------------------------------------------

# What the service was measured to accept for the same Runtime: another partition string.
SPELLINGS = [RUNTIME_ARN.replace("arn:aws:", f"arn:{other}:", 1) for other in ("aws-cn", "aws-us-gov", "aws-xyz")]
ARABIC_FOUR, FULLWIDTH_FOUR = "٤", "４"  # digits of other scripts, which ``\d`` matches
NOT_AN_ARN = [
    RUNTIME_ARN + "\n",  # ``$`` matches before a final line feed
    " " + RUNTIME_ARN,
    RUNTIME_ARN.replace(CELL_ACCOUNT, ARABIC_FOUR * 12),
    RUNTIME_ARN.replace(CELL_ACCOUNT, FULLWIDTH_FOUR * 12),
    RUNTIME_ARN.replace(CELL_ACCOUNT, CELL_ACCOUNT[:11]),
    RUNTIME_ARN.replace(CELL_ACCOUNT, CELL_ACCOUNT + "4"),
    RUNTIME_ARN.replace(REGION, REGION.upper()),
    RUNTIME_ARN.replace("arn:aws:", "arn:AWS:"),
    RUNTIME_ARN.replace("arn:aws:", "arn:"),
    RUNTIME_ARN.replace(":runtime/", ":Runtime/"),
    RUNTIME_ARN.replace("bedrock-agentcore", "bedrock"),
    RUNTIME_ARN + "/runtime-endpoint/DEFAULT",
    RUNTIME_ARN.replace(RUNTIME_ID, "travel agent-AbCdEf1234"),
]


class LenientCell(FakeCell):
    """A cell that, like the service, answers for another partition string as for the Runtime itself."""

    def __init__(self) -> None:
        super().__init__()
        self.arns_seen: set[str] = set()

    def _real(self, arn: str) -> str:
        self.arns_seen.add(arn)
        return re.sub(r"^arn:aws[a-z-]*:", "arn:aws:", arn)

    def get_resource_policy(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
        return super().get_resource_policy(self._real(resourceArn))

    def put_resource_policy(self, resourceArn: str, policy: str) -> dict[str, Any]:  # noqa: N803
        return super().put_resource_policy(self._real(resourceArn), policy)

    def delete_resource_policy(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
        return super().delete_resource_policy(self._real(resourceArn))

    def list_tags_for_resource(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
        return super().list_tags_for_resource(self._real(resourceArn))

    def stop_runtime_session(self, runtimeSessionId: str, agentRuntimeArn: str, qualifier: str) -> dict[str, Any]:  # noqa: N803
        return super().stop_runtime_session(runtimeSessionId, self._real(agentRuntimeArn), qualifier)


@pytest.fixture
def lenient(world: SweepWorld) -> LenientCell:
    world.cell = world.assumed.cell = LenientCell()
    return world.cell


def by_arn(runtime_arn: str, reason: str = "By the Runtime's own id.") -> dict[str, str]:
    return {"reason": reason, "runtime_arn": runtime_arn}


def test_a_runtime_arn_is_recognised_only_in_full_and_only_in_ascii():
    assert arns.parse_runtime_arn(RUNTIME_ARN) == arns.RuntimeArn("aws", REGION, CELL_ACCOUNT, RUNTIME_ID)
    # Another partition is well formed. Whether it is the right one is for the cell to say.
    assert arns.parse_runtime_arn(SPELLINGS[0]).partition == "aws-cn"
    for value in [*NOT_AN_ARN, None, 5, RUNTIME_ARN.encode(), ["x"]]:
        assert arns.parse_runtime_arn(value) is None, value
    # The general ARN parser, which the registration rules use, is as strict about digits and the end.
    assert arn_parts(RUNTIME_ARN)["account"] == CELL_ACCOUNT
    assert arn_parts(RUNTIME_ARN + "\n") is None
    assert arn_parts(RUNTIME_ARN.replace(CELL_ACCOUNT, ARABIC_FOUR * 12)) is None
    assert arns.is_runtime_id(RUNTIME_ID) and not arns.is_runtime_id(RUNTIME_ID + "\n")
    assert not arns.is_runtime_id(RUNTIME_ID.replace("1234", ARABIC_FOUR * 4)) and not arns.is_runtime_id(None)


def test_the_portal_builds_the_arn_from_the_cell():
    cell = load_settings(BASE_ENV).cells[0]
    assert cell.partition == "aws"
    assert arns.canonical_runtime_arn(cell, RUNTIME_ID) == RUNTIME_ARN
    assert arns.canonical_in(cell, RUNTIME_ARN) == RUNTIME_ARN
    for spelling in [*SPELLINGS, *NOT_AN_ARN]:
        assert arns.canonical_in(cell, spelling) is None, spelling
    assert arns.canonical_in(None, RUNTIME_ARN) is None
    assert arns.canonical_in(cell, RUNTIME_ARN.replace(CELL_ACCOUNT, OTHER_ACCOUNT)) is None
    assert arns.canonical_in(cell, RUNTIME_ARN.replace(REGION, "us-east-1")) is None
    # The id is the Runtime's own and is case sensitive: another case is another Runtime, not another spelling.
    assert arns.canonical_in(cell, RUNTIME_ARN.lower()) == RUNTIME_ARN.lower() != RUNTIME_ARN
    # A cell of another partition: the partition is the one of the cell's roles, with or without a containment role.
    china = [
        {
            **CELLS[0],
            "readerRoleArn": CELLS[0]["readerRoleArn"].replace("arn:aws:", "arn:aws-cn:"),
            "containmentRoleArn": CELLS[0]["containmentRoleArn"].replace("arn:aws:", "arn:aws-cn:"),
        },
        {**CELLS[1], "readerRoleArn": CELLS[1]["readerRoleArn"].replace("arn:aws:", "arn:aws-us-gov:")},
    ]
    first, second = load_settings({**BASE_ENV, "PORTAL_CELLS": json.dumps(china)}).cells
    assert (first.partition, second.partition) == ("aws-cn", "aws-us-gov")
    assert arns.canonical_runtime_arn(first, RUNTIME_ID) == SPELLINGS[0]
    assert arns.canonical_in(first, RUNTIME_ARN) is None  # there, "aws" is the other spelling


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_another_spelling_of_the_arn_is_refused_before_anything_is_read(world, lenient, read, spelling):
    """The attack: contain under one spelling, release under another, whose history is empty."""
    assert world.post("contain", agent_id=RUNTIME_ID, claims=SEC, body=by_arn(RUNTIME_ARN))[0] == 200
    stored_before, policy = dict(world.dynamo.items), world.cell.policies[RUNTIME_ARN]
    forget(world.dynamo)
    world.cell.calls.clear()

    # The person who contained it, a second person, and a contain: none gets anywhere under that name.
    for action, claims in (("release", SEC), ("release", PAT), ("contain", PAT), ("contain", SEC)):
        code, body = world.post(action, agent_id=RUNTIME_ID, claims=claims, body=by_arn(spelling))
        assert code == 422, (action, body)
        assert body["detail"] == [
            {"loc": ["body", "runtime_arn"], "msg": containment_flow.NOT_CANONICAL, "type": "containment"}
        ]
    # Refused before anything was read: not the cell, not the audit trail.
    assert world.cell.calls == [] and world.dynamo.calls == []
    assert world.dynamo.items == stored_before and world.cell.policies[RUNTIME_ARN] == policy
    assert lenient.arns_seen == {RUNTIME_ARN}

    # Under the Runtime's one name the rule holds: not the person who contained it, but a second person.
    code, body = world.post("release", agent_id=RUNTIME_ID, claims=SEC, body=by_arn(RUNTIME_ARN))
    assert code == 403 and "CON-03-N" in body["detail"]
    assert read(world.record_id, SEC)[1]["contained_by_me"] is True  # the Runtime's history, whatever the id
    assert world.post("release", agent_id=RUNTIME_ID, claims=PAT, body=by_arn(RUNTIME_ARN))[0] == 200
    assert {e["pk"] for e in world.dynamo.events()} == {KEY}
    assert lenient.arns_seen == {RUNTIME_ARN}


@pytest.mark.parametrize("value", NOT_AN_ARN)
def test_something_that_is_not_exactly_a_runtime_arn_is_refused(world, value):
    code, body = world.post("contain", agent_id=RUNTIME_ID, claims=PAT, body=by_arn(value))
    assert code == 422 and body["detail"][0]["loc"] == ["body", "runtime_arn"], body
    assert world.cell.calls == [] and world.dynamo.calls == [] and world.dynamo.items == {}
    with pytest.raises(ValueError, match="runtime_arn"):
        ContainmentInput(reason="x", runtime_arn=value)


def test_every_call_and_the_history_use_the_arn_the_portal_built(world, lenient, monkeypatch):
    """Contain, the tag read, the stops, the sweep and the release: one ARN throughout."""
    shared = {**CELLS[0], "tenantId": "ws9", "agentId": "second-agent"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([CELLS[0], CELLS[1], shared]))
    lenient.tags[RUNTIME_ARN] = {"tenant-id": "ws1"}
    lenient.streams[log_group()] = [session_stream("running")]
    body = world.post("contain", claims=SEC)[1]
    assert (body["runtime_arn"], body["sessions"]["stopped"]) == (RUNTIME_ARN, 1)
    run = Run(world, {**SWEEPER_ENV, "PORTAL_CELLS": json.dumps([CELLS[0], CELLS[1], shared])})
    for sent in world.queue.messages:
        assert json.loads(sent["MessageBody"])["runtime_arn"] == RUNTIME_ARN
        assert run.handle(sent["MessageBody"]) == "allowed"
    assert world.post("release", claims=PAT)[0] == 200
    assert lenient.arns_seen == {RUNTIME_ARN}
    assert {e["pk"] for e in world.dynamo.events()} == {KEY}
    assert {e["runtime_arn"] for e in world.dynamo.events()} == {RUNTIME_ARN}


def test_a_registration_that_spells_the_arn_another_way_is_not_acted_on(world, lenient):
    """A record is written by the people it governs: it must not open a second history either."""
    twin = world.registry.seed(
        "agent-ws1-twin-nonprod", json.dumps(agent_document(agentId="twin", runtimeArn=SPELLINGS[0])), "APPROVED"
    )
    assert world.post("contain", claims=SEC)[0] == 200
    forget(world.dynamo)
    world.cell.calls.clear()
    for action, claims in (("release", SEC), ("release", PAT), ("contain", PAT)):
        code, body = world.post(action, agent_id=twin, claims=claims)
        assert (code, body["detail"]) == (409, containment_flow.RECORD_NOT_CANONICAL), body
    assert world.cell.calls == [] and world.dynamo.calls == []
    assert lenient.arns_seen == {RUNTIME_ARN}
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    # The body cannot name a spelling the record does not hold either.
    code, body = world.post("release", claims=SEC, body=by_arn(SPELLINGS[0]))
    assert code == 422 and body["detail"][0]["msg"] == "runtime_arn is not this agent's Runtime"


def test_in_a_cell_of_another_partition_the_arn_carries_that_partition(world, monkeypatch):
    """Nothing is hard-wired to "aws": the partition is the cell's, and there "aws" is the wrong spelling."""
    china = {
        **CELLS[0],
        "readerRoleArn": CELLS[0]["readerRoleArn"].replace("arn:aws:", "arn:aws-cn:"),
        "containmentRoleArn": CELLS[0]["containmentRoleArn"].replace("arn:aws:", "arn:aws-cn:"),
    }
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([china]))
    expected = SPELLINGS[0]  # arn:aws-cn:...
    # Addressed by its Runtime id alone: the one cell that can be contained names the rest.
    code, body = world.post("contain", agent_id=RUNTIME_ID, claims=PAT, body={"reason": "x"})
    assert code == 200 and body["runtime_arn"] == expected, body
    assert set(world.cell.policies) == {expected}  # this cell answers only for the ARN it was called with
    assert {e["pk"] for e in world.dynamo.events()} == {f"CONTAINMENT#{expected}"}
    assert world.statements(expected) == [containment_policy.containment_statement(expected)]
    code, body = world.post("release", agent_id=RUNTIME_ID, claims=PAT, body=by_arn(RUNTIME_ARN))
    assert code == 422 and body["detail"][0]["msg"] == containment_flow.NOT_CANONICAL
    assert world.post("release", agent_id=RUNTIME_ID, claims=PAT, body=by_arn(expected))[0] == 403  # the same person
    assert world.post("release", agent_id=RUNTIME_ID, claims=PAT2, body=by_arn(expected))[0] == 200


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_sweep_message_under_another_spelling_is_not_run_and_writes_nothing(world, lenient, spelling, caplog):
    request_id = contained(world)  # the contain is on record under the Runtime's own ARN
    world.cell.streams[log_group()] = [session_stream("running")]
    before = dict(world.dynamo.items)
    message = sweeps.SweepMessage(2, spelling, RUNTIME_ID, request_id)
    run = Run(world)
    with caplog.at_level("ERROR"):
        assert run.handle(sweeps.encode(message)) == "invalid"
        # A message that is invalid for another reason, about that spelling, is not recorded under it either.
        assert run.handle(json.dumps({"runtime_arn": spelling, "sweep": 9})) == "invalid"
    assert world.cell.calls == [] and world.cell.stopped == [] and lenient.arns_seen == set()
    # Not read either: the history that would be read is the one under that spelling.
    assert world.dynamo.items == before and world.dynamo.calls == []
    assert "is not written the way the portal writes it" in caplog.text
    # The same two messages under the Runtime's own ARN: the first is run, the second is refused and logged.
    assert run.handle(sweeps.encode(sweeps.SweepMessage(2, RUNTIME_ARN, RUNTIME_ID, request_id))) == "allowed"
    assert run.handle(json.dumps({"runtime_arn": RUNTIME_ARN, "sweep": 9})) == "invalid"
    assert [e["outcome"] for e in run.sweep_events()] == ["allowed"]
    assert world.dynamo.prefixes == [(KEY, "EVENT#"), (KEY, "OTHER#")]  # the one history that was read


@pytest.mark.parametrize(
    "field",
    [
        {"request_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4" + ARABIC_FOUR},
        {"request_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d\n"},
        {"agent_id": "rec00000000" + FULLWIDTH_FOUR},
        {"agent_id": "rec000000001\n"},
        {"runtime_arn": RUNTIME_ARN.replace(CELL_ACCOUNT, ARABIC_FOUR * 12)},
        {"runtime_arn": RUNTIME_ARN + "\n"},
    ],
)
def test_a_sweep_message_is_validated_in_ascii_and_in_full(field):
    body = {
        "version": 1,
        "kind": "containment_sweep",
        "sweep": 2,
        "runtime_arn": RUNTIME_ARN,
        "agent_id": "rec000000001",
        "request_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    }
    assert sweeps.decode(json.dumps(body)).runtime_arn == RUNTIME_ARN
    with pytest.raises(sweeps.InvalidMessage):
        sweeps.decode(json.dumps({**body, **field}))


def read_api(world: World, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The read API over the world's cell, audit table and registry records as they are now."""
    from mangum import Mangum

    from portal_api import deps
    from portal_api.app import create_app
    from portal_api.aws import registry
    from portal_api.config import get_settings
    from tests.conftest import FakeClient, FakeClients, make_service, runtime_bundle
    from tests.test_api import event

    found = [{**record} for record in world.registry.records.values()]
    monkeypatch.setattr(registry, "list_records", lambda client, registry_id: found)
    monkeypatch.setattr(agentcore, "list_runtimes", lambda client: [runtime_bundle()])
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

    def get(path: str, claims: dict | None = SEC) -> tuple[int, Any]:
        response = handler(event(path, "GET", claims), None)
        return response["statusCode"], json.loads(response["body"])

    return get


def test_the_read_side_reads_a_policy_and_a_history_only_under_the_arn_the_portal_builds(world, lenient, monkeypatch):
    twin = world.registry.seed(
        "agent-ws1-twin-nonprod", json.dumps(agent_document(agentId="twin", runtimeArn=SPELLINGS[0])), "APPROVED"
    )
    assert world.post("contain", claims=SEC)[0] == 200
    get = read_api(world, monkeypatch)
    forget(world.dynamo)
    world.cell.calls.clear()
    lenient.arns_seen.clear()

    code, view = get(f"/agents/{twin}/containment", PAT)
    assert code == 200, view
    assert (view["state"], view["runtime_arn"], view["events"]) == ("unknown", SPELLINGS[0], [])
    assert view["detail"].startswith("The registration names its Runtime by an ARN whose partition is not")
    assert view["contained_by"] is None and view["contained_at"] is None
    assert view["enabled"] is False  # both actions refuse this registration, so neither is offered
    # Neither the policy nor a history was read under that spelling.
    assert lenient.arns_seen == set() and "get_resource_policy" not in world.cell.calls
    assert not [key for key in world.dynamo.queried if key.startswith("CONTAINMENT#")]
    # The evidence document says the same, and why.
    document = get(f"/agents/{twin}/evidence", PAT)[1]
    assert document["containment"]["state"] == "unknown" and document["containment"]["events"] == []
    assert view["detail"] in document["limitations"]
    assert lenient.arns_seen == set()
    assert not [key for key in world.dynamo.queried if key.startswith("CONTAINMENT#")]
    # The genuine registration reads as before.
    view = get(f"/agents/{world.record_id}/containment", PAT)[1]
    assert (view["state"], view["contained_by"]) == ("contained", "sec-1") and lenient.arns_seen == {RUNTIME_ARN}
    assert view["enabled"] is True


def cells_with(**changes: Any) -> dict[str, str]:
    return {**BASE_ENV, "PORTAL_CELLS": json.dumps([{**CELLS[0], **changes}, CELLS[1]])}


@pytest.mark.parametrize(
    ("changes", "said"),
    [
        ({"accountId": ARABIC_FOUR * 12}, "accountId"),
        ({"accountId": CELL_ACCOUNT + "\n"}, "accountId"),
        ({"region": "eu-west-" + ARABIC_FOUR}, "region"),
        ({"region": REGION + "\n"}, "region"),
        ({"readerRoleArn": CELLS[0]["readerRoleArn"] + "\n"}, "readerRoleArn"),
        ({"readerRoleArn": CELLS[0]["readerRoleArn"].replace(CELL_ACCOUNT, FULLWIDTH_FOUR * 12)}, "readerRoleArn"),
        ({"readerRoleArn": CELLS[0]["readerRoleArn"] + "é"}, "readerRoleArn"),  # a letter ``\w`` matches
        ({"containmentRoleArn": CELLS[0]["containmentRoleArn"] + "\n"}, "containmentRoleArn"),
        # Both roles are in the cell account, so in one partition. The ARN is built from it.
        (
            {"containmentRoleArn": CELLS[0]["containmentRoleArn"].replace("arn:aws:", "arn:aws-cn:")},
            "containmentRoleArn is not in the partition of readerRoleArn",
        ),
        ({"externalId": "portal-ext-id\n"}, "externalId"),
        ({"tenantId": "ws1\n"}, "tenantId"),
    ],
)
def test_the_configuration_is_validated_in_ascii_and_in_full(changes, said):
    for load in (load_settings, lambda env: load_action_settings({**env, "PORTAL_ACTION_ROLE": "containment"})):
        with pytest.raises(ConfigError, match=said):
            load(cells_with(**changes))


def test_no_pattern_matches_digits_or_letters_of_other_scripts():
    """``\\d`` and ``\\w`` match more than ASCII in a text pattern, and ``$`` matches before a final line feed."""
    import importlib
    import pkgutil

    compiled = []
    for module_info in pkgutil.walk_packages(portal_api.__path__, "portal_api."):
        module = importlib.import_module(module_info.name)
        compiled += [(module_info.name, name, v) for name, v in vars(module).items() if isinstance(v, re.Pattern)]
    assert len(compiled) > 25
    for module_name, name, pattern in compiled:
        assert "\\d" not in pattern.pattern and "\\w" not in pattern.pattern, (module_name, name)
    # The patterns that validate an ARN, an account id, a record id or a request id are ASCII only by flag
    # as well, and carry no "$": they are applied with ``fullmatch``.
    strict = {name for _, name, _ in compiled} & {
        "RUNTIME_ARN",
        "RUNTIME_ID",
        "RECORD_ID",
        "_RECORD_ID",
        "_REQUEST_ID",
        "_ACCOUNT_ID",
        "_ACCOUNT",
        "_ROLE_ARN",
        "_REGION",
        "_ARN",
        "_RUNTIME_ARN",
    }
    assert len(strict) == 11
    for _, name, pattern in compiled:
        if name in strict:
            assert pattern.flags & re.ASCII and not pattern.pattern.endswith("$"), name
    # The request models and the route parameters: no ``\d`` there either.
    for path in SOURCES:
        for line in path.read_text().splitlines():
            if "pattern=" in line or "Field(pattern" in line:
                assert "\\d" not in line and "\\w" not in line, (path.name, line.strip())
    for model in (ContainmentInput,):
        assert issubclass(model, BaseModel)
        assert "[0-9]{12}" in str(model.model_fields["runtime_arn"].metadata)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_arn", RUNTIME_ARN + "\n"),
        ("runtime_arn", RUNTIME_ARN.replace(CELL_ACCOUNT, ARABIC_FOUR * 12)),
        ("gateway_arn", f"arn:aws:bedrock-agentcore:{REGION}:{CELL_ACCOUNT}:gateway/ws1-tools-abcdefghij\n"),
        ("tenant_id", "ws1\n"),
        ("agent_id", "travel-agent\n"),
        ("record_version", "1.0.0\n"),
        ("record_version", f"1.0.{ARABIC_FOUR}"),
        ("review_by", "2099-12-31\n"),
    ],
)
def test_a_registration_is_validated_in_ascii_and_in_full(records, field, value):
    code, body = records.create(DEV, **{field: value})
    assert code in (403, 422), body  # a tenant with a line feed is no tenant the caller holds
    assert records.registry.records == {} and records.dynamo.items == {}
    if field != "tenant_id":
        assert code == 422 and body["detail"][0]["loc"][-1] == field, body
    assert registrations.parse_version("1.0.0\n") is None and registrations.parse_version("1.2.3") == (1, 2, 3)
    assert registrations.RECORD_ID.fullmatch("rec000000001") and not registrations.RECORD_ID.fullmatch("rec000000001\n")


# --- S4: a contain repeated while its sweeps are at work ---------------------------------------------------

NOW = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)


def at(minutes_ago: float) -> str:
    moment = NOW - dt.timedelta(minutes=minutes_ago)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def too_soon(*events: AuditEvent) -> sweeps.Repeat | None:
    return sweeps.repeat_too_soon(
        events,
        NOW,
        repeat_after_seconds=containment_timing.REPEAT_AFTER_SECONDS,
        sweeps_over_after_seconds=containment_timing.SWEEPS_OVER_AFTER_SECONDS,
        recheck_seconds=containment_timing.REPEAT_RECHECK_SECONDS,
    )


def worked(minutes_ago: float, who: str = "sam", outcome: str = "allowed", **extra: Any) -> AuditEvent:
    """The result of a contain that did its work: it carries the counts of the sessions it dealt with."""
    values = {"request_id": "c-1", "sweeps_scheduled": 2, "sessions_found": 0, **extra}
    return stored(at(minutes_ago), "contain", outcome, who, **values)


def test_when_a_repeated_contain_comes_too_soon():
    assert (containment_timing.REPEAT_AFTER_SECONDS, containment_timing.SWEEPS_OVER_AFTER_SECONDS) == (900, 1800)
    assert containment_timing.REPEAT_RECHECK_SECONDS == 60
    contain = worked(5)
    second = stored(at(3), "sweep", "allowed", "portal", request_id="c-1", sweep=2)
    third = stored(at(1), "sweep", "allowed", "portal", request_id="c-1", sweep=3)
    # Nothing recorded: do the work.
    assert too_soon() is None
    # Five minutes after a contain that scheduled sweeps: ten more to wait, whatever the sweeps did.
    assert too_soon(contain) == sweeps.Repeat(600, True, at(5))
    assert too_soon(contain, second) == sweeps.Repeat(600, True, at(5))
    assert too_soon(contain, second, third) == sweeps.Repeat(600, False, at(5))
    # A repeated contain that did its work counts like the first.
    again = worked(2, "pat", "unchanged", request_id="c-2", sweeps_scheduled=3, sessions_found=4)
    assert too_soon(contain, second, third, again) == sweeps.Repeat(780, True, at(2))

    old = worked(16)
    # After the pause, with every sweep reported: do the work again.
    assert too_soon(old, second, third) is None
    # After the pause, with a sweep that has not reported and can still be running: wait for it,
    # and ask again in a minute, since a sweep that is due usually reports within seconds.
    assert too_soon(old, second) == sweeps.Repeat(60, True, at(16))
    # A sweep that has left no event half an hour after its contain is given up, and the answer
    # never says to ask later than that.
    assert too_soon(worked(31), second) is None
    assert too_soon(worked(29.5)) == sweeps.Repeat(30, True, at(29.5))

    # A sweep of another contain is not one of this contain's sweeps, and a message delivered twice is one sweep.
    foreign = stored(at(1), "sweep", "allowed", "portal", request_id="c-9", sweep=3)
    twice = stored(at(2), "sweep", "allowed", "portal", request_id="c-1", sweep=2)
    assert too_soon(old, second, twice, foreign) == sweeps.Repeat(60, True, at(16))
    # What is not a contain that did its work: a failure, a refusal, an intent, a release.
    for other in (
        worked(1, outcome="failed"),
        worked(1, outcome="denied"),
        worked(1, phase="intent"),
        stored(at(1), "release", "allowed", "pat", sweeps_scheduled=2, sessions_found=0),
    ):
        assert too_soon(other) is None


def test_a_contain_that_was_answered_at_once_does_not_start_the_pause_anew():
    """It leaves a result with no session counts. If that counted as work done, every repeat would
    either push the pause out again, or (having scheduled nothing) let the next one through."""
    contain = worked(14)
    answered = stored(at(1), "contain", "unchanged", "pat", request_id="c-2")
    assert answered.sessions_found is None
    assert too_soon(contain, answered) == too_soon(contain) == sweeps.Repeat(60, True, at(14))
    done = [stored(at(n), "sweep", "allowed", "portal", request_id="c-1", sweep=n) for n in (2, 3)]
    assert too_soon(worked(16), *done, stored(at(1), "contain", "unchanged", "pat", request_id="c-2")) is None
    assert too_soon(answered) is None


def test_a_sweep_is_given_up_by_the_age_of_its_own_contain_not_of_the_last_one():
    """A sweep that was lost three quarters of an hour ago must not hold back the contain after next."""
    first = worked(47)  # it scheduled two sweeps, and one of them never reported
    reported = stored(at(45), "sweep", "allowed", "portal", request_id="c-1", sweep=2)
    second = worked(16, "pat", "unchanged", request_id="c-2", sweeps_scheduled=2, sessions_found=1)
    done = [
        stored(at(16 - minutes), "sweep", "allowed", "portal", request_id="c-2", sweep=n)
        for n, minutes in ((2, 2), (3, 15))
    ]
    # Sixteen minutes after the second contain, whose own sweeps have both reported: do the work.
    assert too_soon(first, reported, second, *done) is None
    # A sweep of the second contain that has not reported does hold the next one back ...
    assert too_soon(first, reported, second, done[0]) == sweeps.Repeat(60, True, at(16))
    # ... until that contain is half an hour old, and the answer never says to ask later than that.
    late = worked(29.5, "pat", "unchanged", request_id="c-2", sweeps_scheduled=2, sessions_found=1)
    assert too_soon(worked(60), reported, late, done[0]) == sweeps.Repeat(30, True, at(29.5))
    assert too_soon(worked(60), reported, worked(31, "pat", "unchanged", request_id="c-2"), done[0]) is None
    # Inside the pause the lost sweep of the first contain is not what "still running" refers to.
    fresh = worked(5, "pat", "unchanged", request_id="c-2", sweeps_scheduled=2, sessions_found=1)
    both = [stored(at(n), "sweep", "allowed", "portal", request_id="c-2", sweep=n) for n in (2, 3)]
    assert too_soon(first, reported, fresh, *both) == sweeps.Repeat(600, False, at(5))


def test_a_contain_that_scheduled_no_sweep_is_never_too_soon_to_repeat():
    """Without a queue, or when the sweeps could not be scheduled, containing again is the only way to go on."""
    assert too_soon(worked(1, sweeps_scheduled=None)) is None
    assert too_soon(worked(1, outcome="unchanged", sweeps_scheduled=None)) is None
    # The newest one decides: an earlier contain's sweeps do not cover what the last one left undone.
    assert too_soon(worked(5), worked(1, "pat", "unchanged", request_id="c-2", sweeps_scheduled=None)) is None


def move_clock(monkeypatch: pytest.MonkeyPatch, minutes: float) -> None:
    """From now on the containment function decides as if this many minutes had passed."""
    moment = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=minutes)
    monkeypatch.setattr(containment_flow, "_now", lambda: moment)


def test_a_contain_repeated_at_once_does_nothing_and_says_so(world, read, caplog):
    world.cell.streams[log_group()] = [session_stream("running")]
    first = world.post("contain", claims=SEC)[1]
    assert first["sweeps_scheduled_in_seconds"] == [120, 900] and first["retry_after_seconds"] is None
    stored_before, sent, stopped = len(world.dynamo.items), len(world.queue.messages), list(world.cell.stopped)
    world.cell.calls.clear()
    world.cell.streams[log_group()].append(session_stream("started-later", 1))

    with caplog.at_level("INFO"):
        code, body = world.post("contain", claims=PAT)
    assert code == 200, body
    assert (body["outcome"], body["changed"], body["state"]) == ("unchanged", False, "contained")
    assert 0 < body["retry_after_seconds"] <= containment_timing.REPEAT_AFTER_SECONDS
    assert body["sessions"] is None and body["sweeps_scheduled_in_seconds"] == [] and body["partial"] is False
    assert body["denied_actions"] == ALL and body["audit_complete"] is True
    assert [(step["id"], step["status"]) for step in body["steps"]] == [
        ("policy", "unchanged"),
        ("verify", "done"),
        ("sessions", "skipped"),
    ]
    said = "The background sweeps of this containment are still running, so nothing more was done."
    assert said in body["steps"][2]["detail"]
    assert "A contain stops sessions again once they have run: ask again in about 15 minutes." in body["reason"]
    assert body["reason"].startswith("The Runtime was already contained; its policy was not changed.")
    # It read the policy, to be sure, and did nothing else: no session listed or stopped, no sweep scheduled.
    assert world.cell.calls == ["get_resource_policy"] and world.cell.stopped == stopped
    assert len(world.queue.messages) == sent
    # The history says that this person asked again, in one result with no intent and no session counts.
    assert len(world.dynamo.items) == stored_before + 1
    event = world.dynamo.events()[-1]
    assert (event["action"], event["phase"], event["outcome"], event["actor_subject"]) == (
        "contain",
        "result",
        "unchanged",
        "pat-1",
    )
    assert (event["request_id"], event["reason"]) == (body["request_id"], body["reason"])
    assert (event["status_before"], event["status_after"]) == ("contained", "contained")
    assert "sessions_found" not in event and "sweeps_scheduled" not in event
    # Asked again by the same person: the same answer, and nothing more is written.
    with caplog.at_level("INFO"):
        again = world.post("contain", claims=PAT)[1]
    assert again["retry_after_seconds"] and again["request_id"] != body["request_id"]
    assert len(world.dynamo.items) == stored_before + 1
    assert again["request_id"] in caplog.text  # that answer can still be found, in the function's log
    # The person who contained it is still the one on record, and the sweeps of that contain are the ones counted.
    view = read(world.record_id, SEC)[1]
    assert (view["contained_by"], view["contained_by_me"], view["sweeps"]) == (
        "sec-1",
        True,
        {"scheduled": 2, "done": 0},
    )
    assert [(e["actor_subject"], e["outcome"]) for e in view["events"][:2]] == [
        ("pat-1", "unchanged"),
        ("sec-1", "allowed"),
    ]
    assert "CON-03-N" in world.post("release", claims=SEC)[1]["detail"]


def test_repeating_a_contain_takes_no_slot_and_fills_no_queue(world):
    """The attack: one request a second on a Runtime of one's own that is already contained.

    Each one listed and stopped sessions for up to twenty seconds and put up to three sweeps on
    the queue, so the containment function's slots and the sweeper were taken from every tenant.
    """
    world.cell.streams[log_group()] = [session_stream(f"s{n}") for n in range(40)]
    assert world.post("contain", claims=SRE)[0] == 200
    stored_before, sent = len(world.dynamo.items), len(world.queue.messages)
    world.cell.calls.clear()
    world.cell.stopped.clear()
    answers = [world.post("contain", claims=SRE)[1] for _ in range(30)]
    assert {a["outcome"] for a in answers} == {"unchanged"} and all(a["retry_after_seconds"] for a in answers)
    assert world.cell.calls == ["get_resource_policy"] * 30  # one cheap read each
    assert world.cell.stopped == [] and len(world.queue.messages) == sent == 2
    assert len(world.dynamo.items) == stored_before + 1  # one event for the thirty of them
    # Someone else who asks again is on record once as well.
    assert [world.post("contain", claims=SEC)[1]["outcome"] for _ in range(5)] == ["unchanged"] * 5
    assert len(world.dynamo.items) == stored_before + 2
    # A release is not held up by any of it.
    assert world.post("release", claims=PAT)[0] == 200


def test_after_the_pause_a_repeated_contain_does_its_work_again(world, monkeypatch):
    world.cell.streams[log_group()] = [session_stream("first")]
    assert world.post("contain", claims=SEC)[0] == 200
    run = Run(world)
    # Sixteen minutes later, with a sweep that has not reported yet: it can still be running.
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "allowed"
    move_clock(monkeypatch, 16)
    waiting = world.post("contain", claims=PAT)[1]
    # The pause is over; the one sweep that is due is what it waits for, so it says to ask again soon.
    assert (waiting["outcome"], waiting["retry_after_seconds"]) == ("unchanged", 60)
    assert "ask again in about 60 seconds" in waiting["reason"]
    # Once it has reported, the "Stop remaining sessions" case works as before.
    assert run.handle(world.queue.messages[1]["MessageBody"]) == "allowed"
    world.cell.streams[log_group()].append(session_stream("started-later", 1))
    world.cell.stopped.clear()
    stored_before = len(world.dynamo.items)
    code, body = world.post("contain", claims=PAT)
    assert (code, body["outcome"], body["retry_after_seconds"]) == (200, "unchanged", None)
    assert body["sessions"]["found"] == 2 and (sid("started-later"), "DEFAULT") in world.cell.stopped
    assert body["sweeps_scheduled_in_seconds"] == [120, 900]
    assert len(world.dynamo.items) == stored_before + 2  # its intent and its result
    # And that contain starts the pause anew.
    assert world.post("contain", claims=PAT)[1]["retry_after_seconds"] is not None
    # A person who asked again in two pauses is on record once for each.
    asked_again = [
        e
        for e in world.dynamo.events()
        if (e["action"], e["outcome"]) == ("contain", "unchanged") and "sessions_found" not in e
    ]
    assert [e["actor_subject"] for e in asked_again] == ["pat-1", "pat-1"]
    # Half an hour after a contain whose sweeps never reported, they are given up.
    move_clock(monkeypatch, 16 + 31)
    assert world.post("contain", claims=PAT)[1]["retry_after_seconds"] is None


def test_a_repeated_contain_does_its_work_at_once_when_the_statement_is_not_there(world, lenient):
    """The history says "contained a moment ago". The policy has the last word."""
    assert world.post("contain", claims=SEC)[0] == 200
    # Removed by other means.
    del world.cell.policies[RUNTIME_ARN]
    body = world.post("contain", claims=PAT)[1]
    assert (body["outcome"], body["changed"], body["retry_after_seconds"]) == ("allowed", True, None)
    # Turned into a decoy.
    world.cell.policies[RUNTIME_ARN] = policy_of(DECOYS["a condition that never holds"])
    body = world.post("contain", claims=SEC)[1]
    assert (body["outcome"], body["replaced_foreign_statement"]) == ("allowed", True)
    # Not readable: the contain is not answered at once. It says itself what is wrong, and that nothing
    # was changed. The policy is read once for a request, so the next request reads it again.
    events_before = len(world.dynamo.events())
    world.cell.fail["get_resource_policy"] = "AccessDeniedException"
    code, body = world.post("contain", claims=SEC)
    assert code == 502 and body["detail"] == (
        "Nothing was changed. The Runtime's resource policy could not be read (AccessDeniedException)."
    )
    (failed,) = world.dynamo.events()[events_before:]
    assert (failed["phase"], failed["outcome"], failed["reason"]) == ("result", "failed", body["detail"])
    assert failed["sk"].startswith("OTHER#") and failed["request_id"] == body["request_id"]
    world.assumed.error = client_error("AccessDenied", "AssumeRole")
    code, body = world.post("contain", claims=SEC)
    assert code == 502 and "could not be assumed" in body["detail"]
    assert lenient.arns_seen == {RUNTIME_ARN}


def test_a_release_ends_the_pause(world):
    assert world.post("contain", claims=SEC)[0] == 200
    assert world.post("release", claims=PAT)[0] == 200
    body = world.post("contain", claims=PAT)[1]
    assert (body["outcome"], body["changed"], body["retry_after_seconds"]) == ("allowed", True, None)
    # A Runtime contained by other means, with no contain of the portal on record: the first contain works.
    assert world.post("release", claims=SEC)[0] == 200
    contained(world)
    body = world.post("contain", claims=SRE)[1]
    assert (body["outcome"], body["retry_after_seconds"]) == ("unchanged", None) and body["sessions"] is not None
    assert world.post("contain", claims=SRE)[1]["retry_after_seconds"] is not None


def test_without_a_sweep_queue_a_repeated_contain_works_as_it_always_did(monkeypatch):
    plain = World(monkeypatch)
    plain.cell.streams[log_group()] = [session_stream("first")]
    assert plain.post("contain", claims=SEC)[0] == 200
    plain.cell.streams[log_group()].append(session_stream("started-later", 1))
    body = plain.post("contain", claims=PAT)[1]
    assert (body["outcome"], body["retry_after_seconds"]) == ("unchanged", None)
    assert body["sessions"]["found"] == 2 and (sid("started-later"), "DEFAULT") in plain.cell.stopped


# --- S5: a release needs the tenant the Runtime was contained under ---------------------------------------


def decide(**overrides: Any) -> rules.ContainmentDecision:
    values = {
        "action": "release",
        "role": "security",
        "principal_id": "p-1",
        "agent_tenant": "ws1",
        "held_tenants": ("ws1", "ws9"),
        "holds_all_tenants": False,
        "contained_by": "p-2",
        "contained_tenant": "ws1",
    }
    return rules.evaluate(**{**values, **overrides})


def test_the_rule_about_a_tenant_that_changed():
    assert decide().allowed
    changed = decide(agent_tenant="ws9")
    assert not changed.allowed and "CON-06-N" in changed.reason
    # Not known when it was contained: nobody but the platform role can say whose it was.
    assert "CON-06-N" in decide(contained_tenant=None).reason
    # Not known now: that is refused before, for the tenant.
    assert "CON-05-N" in decide(agent_tenant=None).reason
    # The platform role holds every tenant and releases, but not what it contained itself.
    platform = {"role": "platform", "holds_all_tenants": True, "held_tenants": ()}
    assert decide(**platform, agent_tenant="ws9").allowed
    assert decide(**platform, contained_tenant=None).allowed and decide(**platform, agent_tenant=None).allowed
    assert "CON-03-N" in decide(**platform, agent_tenant="ws9", contained_by="p-1").reason
    # Nobody holds it: there is no tenant to compare with.
    assert decide(contained_by=None, contained_tenant=None).allowed
    # Order: the role, the tenant, the tenant that changed, the two-person rule.
    assert "CON-04-N" in decide(agent_tenant="ws3").reason
    assert "CON-06-N" in decide(agent_tenant="ws9", contained_by="p-1").reason
    assert "CON-03-N" in decide(contained_by="p-1").reason
    # A contain is not a release.
    assert decide(action="contain", agent_tenant="ws9").allowed


def shared_account(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict[str, str]]:
    """The cell account hosts ws1 and ws9, and each has responders who hold only their own tenant."""
    shared = {**CELLS[0], "tenantId": "ws9", "agentId": "second-agent"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([CELLS[0], CELLS[1], shared]))
    roles = {**json.loads(BASE_ENV["PORTAL_GROUP_ROLE_MAP"]), "sec9": "security", "sec1": "security"}
    tenants = {**json.loads(BASE_ENV["PORTAL_GROUP_TENANT_MAP"]), "sec9": ["ws9"], "sec1": ["ws1"]}
    monkeypatch.setenv("PORTAL_GROUP_ROLE_MAP", json.dumps(roles))
    monkeypatch.setenv("PORTAL_GROUP_TENANT_MAP", json.dumps(tenants))
    return {
        "ws9": {"sub": "sec-ws9", "cognito:groups": "[sec9]"},
        "ws9-too": {"sub": "sec-ws9-b", "cognito:groups": "[sec9]"},
        "ws1": {"sub": "sec-ws1", "cognito:groups": "[sec1]"},
    }


def test_retagging_a_contained_runtime_does_not_put_its_release_in_another_tenants_hands(world, monkeypatch, caplog):
    """The attack: tenant ws1 contains its Runtime; tenant ws9 sets the tag to ws9 and releases it."""
    people = shared_account(monkeypatch)
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws1"}
    assert world.post("contain", claims=people["ws1"])[0] == 200
    recorded = len(world.dynamo.events())

    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws9"}
    with caplog.at_level("WARNING"):
        answers = [world.post("release", claims=people["ws9"]) for _ in range(4)]
    for code, body in answers:
        assert code == 403 and body["detail"] == (
            "the Runtime's tenant changed since it was contained; only the platform role can release it (CON-06-N)"
        )
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    # Recorded, because this caller holds a tenant of the account, and once.
    denied = world.dynamo.events()[recorded:]
    assert [(e["outcome"], e["actor_subject"], e["tenant_id"]) for e in denied] == [("denied", "sec-ws9", "ws9")]
    assert len([r for r in caplog.records if "already on record" in r.getMessage()]) == 3
    # A second person of that tenant: recorded once as well.
    assert world.post("release", claims=people["ws9-too"])[0] == 403
    assert world.post("release", claims=people["ws9-too"])[0] == 403
    assert [e["actor_subject"] for e in world.dynamo.events()[recorded:]] == ["sec-ws9", "sec-ws9-b"]
    # The tenant it was contained under no longer holds it either, and neither can say whose it is now.
    code, body = world.post("release", claims=people["ws1"])
    assert code == 403 and "CON-04-N" in body["detail"]
    # The platform role releases it.
    assert world.post("release", claims=PAT)[0] == 200


def test_a_runtime_whose_tag_was_removed_is_released_by_the_platform_role_only(world, monkeypatch):
    people = shared_account(monkeypatch)
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws1"}
    assert world.post("contain", claims=people["ws1"])[0] == 200
    world.cell.tags[RUNTIME_ARN] = {}
    for who in ("ws1", "ws9"):
        code, body = world.post("release", claims=people[who])
        assert code == 403 and "CON-05-N" in body["detail"]
    assert world.post("release", claims=SEC)[0] == 403  # holding every tenant of the account is not enough
    assert world.post("release", claims=PAT)[0] == 200


def test_a_runtime_contained_while_its_tenant_was_not_known_is_released_by_the_platform_role_only(world, monkeypatch):
    people = shared_account(monkeypatch)
    assert world.post("contain", claims=PAT)[0] == 200  # no tag: only the platform role can contain it
    assert world.dynamo.events()[-1].get("tenant_id") is None
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws9"}  # then it is tagged
    code, body = world.post("release", claims=people["ws9"])
    assert code == 403 and "CON-06-N" in body["detail"]
    assert world.post("release", claims=PAT2)[0] == 200


def test_in_an_account_of_one_tenant_and_with_an_unchanged_tag_a_release_is_as_before(world, monkeypatch):
    assert world.post("contain", claims=SEC)[0] == 200
    assert world.post("release", claims=PAT)[0] == 200
    people = shared_account(monkeypatch)
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws9"}
    assert world.post("contain", claims=people["ws9"])[0] == 200
    assert world.post("release", claims=people["ws9"])[0] == 403  # the two-person rule, as ever
    assert world.post("release", claims=people["ws9-too"])[0] == 200


# --- S6: a reference into an account that several tenants share ----------------------------------------------

SHARED_REFUSAL = (
    "the registration names a Runtime in an account that several tenants share, and the principal does not "
    "hold every one of them (REG-13-N)"
)


def shared_records(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict[str, str]]:
    """The first cell's account hosts ws1 and ws9. Some people hold one of them, some both."""
    shared = {**CELLS[0], "tenantId": "ws9", "agentId": "second-agent"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([CELLS[0], CELLS[1], shared]))
    roles = {**json.loads(BASE_ENV["PORTAL_GROUP_ROLE_MAP"]), "devs-both": "developer", "approvers-both": "approver"}
    tenants = {
        **json.loads(BASE_ENV["PORTAL_GROUP_TENANT_MAP"]),
        "devs-both": ["ws1", "ws9"],
        "approvers-both": ["ws1", "ws9"],
    }
    monkeypatch.setenv("PORTAL_GROUP_ROLE_MAP", json.dumps(roles))
    monkeypatch.setenv("PORTAL_GROUP_TENANT_MAP", json.dumps(tenants))
    return {
        "registrar of both": {"sub": "dev-both", "cognito:groups": "[devs-both]"},
        "approver of both": {"sub": "ann-both", "cognito:groups": "[approvers-both]"},
    }


def test_a_registration_cannot_name_a_runtime_in_a_shared_account_unless_its_people_hold_every_tenant_there(
    records, monkeypatch, caplog
):
    """The attack: a registrar and an approver of ws1 register ws9's Runtime, which runs in the same account."""
    people = shared_records(monkeypatch)
    # Create: refused for a registrar of one tenant, and logged, since no record exists yet.
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        code, body = records.create(DEV)
    assert (code, body["detail"]) == (403, SHARED_REFUSAL) and "several tenants" in body["hint"]
    assert records.registry.records == {} and records.dynamo.items == {}
    assert body["request_id"] in caplog.text
    # Someone who holds both, and the platform role, can.
    code, body = records.create(people["registrar of both"])
    assert code == 201, body
    record_id = body["registration"]["record_id"]
    assert records.create(PAT, agent_id="platform-registered")[0] == 201

    # Update: a registrar of one tenant cannot bring such a reference in, or keep one.
    code, body = records.update(record_id, DEV, business_purpose="Changed.")
    assert (code, body["detail"]) == (403, SHARED_REFUSAL)
    assert record_events(records, record_id)[-1]["outcome"] == "denied"  # this caller has a part in the record
    assert records.submit(record_id, people["registrar of both"])[0] == 200

    # Approve: an approver of one tenant cannot approve it; one who holds both can.
    for claims in (ANN, RECORD_SEC):  # ws1 only, and ws1 with ws2
        code, body = records.decide("approve", record_id, claims)
        assert (code, body["detail"]) == (403, SHARED_REFUSAL), claims
    assert records.status(record_id) == "PENDING_APPROVAL"
    assert records.decide("approve", record_id, people["approver of both"])[0] == 200
    # A reject is a refusal of the registration and needs no more than the record's tenant.
    other = records.create(people["registrar of both"], agent_id="second")[1]["registration"]["record_id"]
    assert records.submit(other, people["registrar of both"])[0] == 200
    assert records.decide("reject", other, ANN)[0] == 200


def test_in_an_account_of_one_tenant_the_reference_rule_asks_no_more_than_before(records):
    record_id = records.new_record("PENDING_APPROVAL")
    assert records.decide("approve", record_id, ANN)[0] == 200


# --- S7: the sweeper's session ---------------------------------------------------------------------------------


def test_the_sweepers_session_can_do_what_a_sweep_does_and_nothing_else():
    cell, plain = load_settings(BASE_ENV).cells
    assert cell.containment_spans is True and plain.containment_spans is False
    with_spans = json.loads(sweeper_module.session_policy(cell))
    without = json.loads(sweeper_module.session_policy(plain))
    assert without == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetResourcePolicy",
                    "bedrock-agentcore:StopRuntimeSession",
                    "bedrock-agentcore:ListAgentRuntimeEndpoints",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            }
        ],
    }
    # The query actions only where the cell opted in to finding sessions in its spans.
    assert with_spans["Statement"][0]["Action"] == [
        *without["Statement"][0]["Action"],
        "logs:StartQuery",
        "logs:GetQueryResults",
    ]
    for document in (with_spans, without):
        (statement,) = document["Statement"]
        allowed = " ".join(statement["Action"])
        # Whatever the sweeper's code does, its session cannot change or remove a policy, or read a tag.
        for forbidden in ("PutResourcePolicy", "DeleteResourcePolicy", "ListTagsForResource", "*", "Invoke"):
            assert forbidden not in allowed, forbidden
        assert len(sweeper_module.session_policy(cell)) < 2048  # the most a session policy may hold


def test_the_sweeper_assumes_the_cells_role_with_that_session_policy_and_the_containment_function_without(world):
    world.cell.streams[log_group()] = [session_stream("running")]
    assert world.post("contain", claims=SEC)[0] == 200
    # The containment function writes the policy: its session is not narrowed.
    assert world.assumed.session_policies and set(world.assumed.session_policies) == {None}
    world.assumed.session_policies.clear()
    world.cell.assumed.clear()
    run = Run(world)
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "allowed"
    cell = load_settings(BASE_ENV).cells[0]
    assert world.assumed.session_policies and set(world.assumed.session_policies) == {
        sweeper_module.session_policy(cell)
    }
    # The same role and external id as the containment function, so the cell trusts one role.
    assert {(role, external) for role, external, _, _ in world.cell.assumed} == {
        (cell.containment_role_arn, "portal-ext-id")
    }


def test_each_function_assumes_a_cells_role_under_a_name_of_its_own():
    import boto3
    from botocore.stub import Stubber

    from portal_api.aws import session as aws_session

    assert (aws_session.SESSION_READER, aws_session.SESSION_CONTAINMENT, aws_session.SESSION_SWEEPER) == (
        "portal-reader",
        "portal-containment",
        "portal-sweeper",
    )
    package = Path(portal_api.__file__).resolve().parent
    assert "session_name=SESSION_READER" in (package / "service.py").read_text()
    assert "session_name=SESSION_CONTAINMENT" in (package / "actions" / "app.py").read_text()
    assert "session_name=SESSION_SWEEPER" in (package / "actions" / "sweeper.py").read_text()

    role = CELLS[0]["containmentRoleArn"]
    policy = sweeper_module.session_policy(load_settings(BASE_ENV).cells[0])
    credentials = {
        "AccessKeyId": "ASIAEXAMPLEEXAMPLE00",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15),
    }
    boto = boto3.session.Session(region_name=REGION, aws_access_key_id="test", aws_secret_access_key="test")
    clients = aws_session.AwsClients(session=boto, home_region=REGION, session_name=aws_session.SESSION_SWEEPER)
    request = {
        "RoleArn": role,
        "RoleSessionName": "portal-sweeper",
        "DurationSeconds": 900,
        "ExternalId": "portal-ext-id",
    }
    with Stubber(clients.platform("sts", REGION)) as stub:
        # The session policy travels with the request that assumes the role.
        stub.add_response("assume_role", {"Credentials": credentials}, {**request, "Policy": policy})
        narrowed = clients.assumed(role, "portal-ext-id", REGION, "logs", session_policy=policy)
        # Credentials that were narrowed are never handed out for a request that is not, or the reverse.
        wide = {**credentials, "AccessKeyId": "ASIAEXAMPLEEXAMPLE01"}
        stub.add_response("assume_role", {"Credentials": wide}, request)
        unnarrowed = clients.assumed(role, "portal-ext-id", REGION, "logs")
        assert clients.assumed(role, "portal-ext-id", REGION, "logs", session_policy=policy) is narrowed
        assert clients.assumed(role, "portal-ext-id", REGION, "logs") is unnarrowed
        stub.assert_no_pending_responses()
    assert narrowed is not unnarrowed


# --- S9 and S10: who attests a review, and how often --------------------------------------------------------


def test_the_rules_about_who_attests_a_review_and_how_often():
    refusal = lifecycle_rules.submitter_refusal
    assert refusal("ann-1", "dev-1") is None and refusal("ann-1", None) is None and refusal("ann-1", "") is None
    own = refusal("pat-1", "pat-1")
    assert (own.outcome, own.http_status) == ("deny", 403) and "REV-05-N" in own.reason

    spaced = lifecycle_rules.recent_review_refusal
    assert lifecycle_rules.REVIEW_INTERVAL_HOURS == 24
    assert spaced(None, NOW) is None
    assert spaced(NOW - dt.timedelta(hours=24), NOW) is None
    assert spaced(NOW - dt.timedelta(hours=24, seconds=1), NOW) is None
    soon = spaced(NOW - dt.timedelta(hours=23, minutes=59), NOW)
    assert (soon.outcome, soon.http_status) == ("conflict", 409)
    assert soon.reason == (
        "a registration's review can be attested once in 24 hours; this one was attested at "
        "2026-05-31T12:01:00Z (REV-06-N)"
    )
    assert spaced(NOW + dt.timedelta(minutes=5), NOW) is not None  # a clock that runs ahead does not open a gap


def test_the_submitter_cannot_attest_the_review_of_its_own_record(records, caplog):
    """The platform role holds both authorities. It registered and submitted this record."""
    record_id = records.create(PAT, agent_id="pats-agent")[1]["registration"]["record_id"]
    assert records.submit(record_id, PAT)[0] == 200
    assert records.decide("approve", record_id, ANN)[0] == 200
    recorded = len(record_events(records, record_id))
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        answers = [review(records, record_id, PAT) for _ in range(4)]
    for code, body in answers:
        assert code == 403 and body["detail"] == (
            "the submitter cannot attest the review of its own record - separation of duties (REV-05-N)"
        )
    assert reviews_items(records) == []
    # In the record's history, once: this caller has a part in the record.
    denied = record_events(records, record_id)[recorded:]
    assert [(e["action"], e["outcome"], e["actor_subject"]) for e in denied] == [("review", "denied", "pat-1")]
    assert len([r for r in caplog.records if "not written to the audit trail" in r.getMessage()]) == 3
    # A second pair of eyes attests it.
    assert review(records, record_id, ANN)[0] == 200
    assert [item["reviewed_by"] for item in reviews_items(records)] == ["ann-1"]


def test_a_record_with_another_submitter_or_with_none_is_attested_by_any_approver(records, monkeypatch):
    # Submitted by a registrar: the platform role is not its submitter.
    record_id = records.new_record("APPROVED")
    assert review(records, record_id, PAT)[0] == 200
    # A record the portal knows no submitter of (published by a pipeline, approved elsewhere).
    seeded = records.registry.seed("agent-ws1-piped-nonprod", json.dumps(agent_document(agentId="piped")), "APPROVED")
    assert review(records, seeded, PAT)[0] == 200 and review(records, seeded, ANN)[0] == 409  # the next rule
    # The submitter is whoever submitted last: after a new submit by someone else, the earlier one may attest.
    own = records.create(PAT, agent_id="pats-agent")[1]["registration"]["record_id"]
    assert records.submit(own, PAT)[0] == 200 and records.decide("approve", own, ANN)[0] == 200
    assert review(records, own, PAT)[0] == 403
    assert records.update(own, DEV, agent_id="pats-agent", business_purpose="Changed by the team.")[0] == 200
    assert records.submit(own, DEV)[0] == 200 and records.decide("approve", own, ANN)[0] == 200
    assert review(records, own, PAT)[0] == 200


def test_a_records_review_is_attested_once_in_24_hours(records, monkeypatch, caplog):
    """The attack was: attest one's own approved record thousands of times, so that the one partition
    the inventory reads is read only as far as those, and other tenants' reviews drop out. The rule
    spaces the attestations of a record out, and the partition holds one item for a record whatever
    their number, so even the ones the rule lets through add nothing to that read."""
    record_id = records.new_record("APPROVED")
    assert review(records, record_id, ANN, day(90))[0] == 200
    recorded = len(record_events(records, record_id))
    with caplog.at_level("WARNING", logger="portal_api.actions.engine"):
        answers = [review(records, record_id, claims, day(120)) for claims in (ANN, ANN, RECORD_SEC, ANN, RECORD_SEC)]
    for code, body in answers:
        assert code == 409 and "REV-06-N" in body["detail"] and "once in 24 hours" in body["detail"], body
    # One attestation, and one refusal on record for each person who was refused.
    assert [item["next_review_by"] for item in reviews_items(records)] == [day(90)]
    denied = record_events(records, record_id)[recorded:]
    assert [(e["outcome"], e["actor_subject"]) for e in denied] == [("denied", "ann-1"), ("denied", "sec-1")]
    assert len([r for r in caplog.records if "not written to the audit trail" in r.getMessage()]) == 3
    # A day later it can be attested again.
    a_day_later(monkeypatch, 23.9)
    assert review(records, record_id, ANN, day(120))[0] == 409
    a_day_later(monkeypatch, 24.1)
    assert review(records, record_id, RECORD_SEC, day(120))[0] == 200
    # Both reviews are in the record's history. The partition the inventory reads holds the latest.
    assert [e["next_review_by"] for e in attested(records, record_id) if e["action"] == "review"] == [day(90), day(120)]
    assert [item["next_review_by"] for item in attestation_items(records)] == [day(120)]


def test_an_approval_is_not_counted_as_a_review_attestation(records):
    """Approving a document with a review date records an attestation too, of another kind."""
    code, body = records.create(review_by=day(200))
    record_id = body["registration"]["record_id"]
    assert records.submit(record_id)[0] == 200 and records.decide("approve", record_id, ANN)[0] == 200
    assert [item["kind"] for item in attestation_items(records)] == ["approval"]
    assert review(records, record_id, RECORD_SEC, day(100))[0] == 200  # at once
    # And a review does not hold up a later approval.
    assert records.update(record_id, DEV, review_by=day(150))[0] == 200
    assert records.submit(record_id)[0] == 200 and records.decide("approve", record_id, ANN)[0] == 200
    assert kinds(records) == ["approval", "review", "approval"]
    assert [item["kind"] for item in attestation_items(records)] == ["approval"]  # the latest one
    # The review of a moment ago still counts after the re-approval: one attestation of a review in 24 hours.
    assert review(records, record_id, RECORD_SEC, day(100))[0] == 409


def test_a_review_that_may_have_attested_counts_and_one_that_did_not_does_not(records):
    record_id = records.new_record("APPROVED")
    # The attestation could not be written: nothing was attested, so the next attempt is not too soon.
    records.dynamo.fail_put_numbers = {records.dynamo._puts + 2}  # the intent, then the attestation
    assert review(records, record_id, ANN)[0] == 503 and reviews_items(records) == []
    # The attestation was written and the result event was not: it attested, and that counts.
    records.dynamo.fail_put_numbers = {records.dynamo._puts + 3}  # intent, attestation, then the result
    code, body = review(records, record_id, ANN)
    assert code == 200 and body["audit_complete"] is False and len(reviews_items(records)) == 1
    assert events_of(records, record_id, "review")[-1]["phase"] == "intent"
    code, body = review(records, record_id, RECORD_SEC)
    assert code == 409 and "REV-06-N" in body["detail"]
    assert len(reviews_items(records)) == 1


def test_a_review_reads_the_records_history_only_as_far_as_it_needs_and_fails_closed(records):
    record_id = records.new_record("APPROVED")
    key = f"RECORD#{record_id}"
    seed(records.dynamo, key, [stored(long_ago(n), "update", "denied", "dev-0") for n in range(3000)])
    assert review(records, record_id, ANN)[0] == 200
    assert records.dynamo.queried == [key] and records.dynamo.pages_read == 1
    # More events in the last day, or since the submit, than a decision reads: nothing is attested.
    seed(records.dynamo, key, [stored(later(n), "update", "denied", "dev-1") for n in range(2100)])
    stored_before = len(records.dynamo.items)
    code, body = review(records, record_id, RECORD_SEC)
    assert (code, body["detail"]) == (409, engine.HISTORY_NOT_READ_FAR_ENOUGH)
    assert len(records.dynamo.items) == stored_before and len(reviews_items(records)) == 1
    assert records.dynamo.items_read == audit_reader.MAX_DECISION_EVENTS


def test_a_review_by_someone_of_another_tenant_is_refused_before_the_history_is_read(records):
    record_id = records.new_record("APPROVED")
    forget(records.dynamo)
    assert review(records, record_id, ANN2)[0] == 403
    assert records.dynamo.calls == []
    # And a date that is not allowed is refused before it as well.
    assert review(records, record_id, ANN, day(400))[0] == 422
    assert records.dynamo.calls == []


# --- S13: a write of the statement that may have been applied -----------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        client_error("InternalServerException", "PutResourcePolicy"),
        client_error("ServiceUnavailableException", "PutResourcePolicy"),
        client_error("ThrottlingException", "PutResourcePolicy"),
        client_error("TooManyRequestsException", "PutResourcePolicy", 429),
        client_error("SomethingNew", "PutResourcePolicy", 503),
        TimeoutError("no answer from the service"),
        ConnectionError("the connection broke"),
    ],
    ids=lambda failure: getattr(failure, "response", {}).get("Error", {}).get("Code") or type(failure).__name__,
)
def test_a_write_that_may_have_been_applied_names_a_holder(world, failure, read):
    """The service may have written the statement although the answer was an error, or never came."""
    assert containment_calls.may_have_been_applied(failure) is True
    real_put = world.cell.put_resource_policy

    def applied_then_failed(resourceArn: str, policy: str) -> dict[str, Any]:  # noqa: N803
        real_put(resourceArn, policy)  # the service did write it
        raise failure

    world.cell.put_resource_policy = applied_then_failed
    code, body = world.post("contain", claims=SEC)
    assert code == 502, body
    assert "could not be written" in body["detail"] and containment_flow.NOT_KNOWN_WHETHER_WRITTEN in body["detail"]
    assert "Nothing was changed" not in body["detail"]
    failed = world.dynamo.events()[-1]
    assert (failed["outcome"], failed["status_before"], failed["status_after"]) == (
        "failed",
        "not_contained",
        "unknown",
    )
    # The Runtime is contained, and the person who asked for it is on record: they cannot release it.
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    view = read(world.record_id, SEC)[1]
    assert (view["state"], view["contained_by"], view["contained_by_me"]) == ("contained", "sec-1", True)
    world.cell.put_resource_policy = real_put
    code, body = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in body["detail"]
    assert world.post("release", claims=PAT)[0] == 200


@pytest.mark.parametrize("code", ["AccessDeniedException", "ValidationException", "ResourceNotFoundException"])
def test_a_write_that_the_service_refused_changed_nothing_and_names_nobody(world, code):
    assert containment_calls.may_have_been_applied(client_error(code, "PutResourcePolicy")) is False
    if code == "ValidationException":
        world.cell.reject_actions = {"bedrock-agentcore:InvokeAgentRuntime"}  # both lists are refused
    else:
        world.cell.fail["put_resource_policy"] = code
    status, body = world.post("contain", claims=SEC)
    assert status == 502 and body["detail"].endswith("Nothing was changed.")
    failed = world.dynamo.events()[-1]
    assert (failed["status_before"], failed["status_after"]) == ("not_contained", "not_contained")
    assert audit_reader.container(audit_reader.read_back(world.dynamo, TABLE, KEY).events) is None
    # An error with no status at all is not taken for a refusal.
    bare = client_error(code, "PutResourcePolicy")
    bare.response.pop("ResponseMetadata")
    assert containment_calls.may_have_been_applied(bare) is True


# --- the documents say what the code does, for S4 to S15 ---------------------------------------------------


def test_the_documents_say_what_the_code_does_about_the_rest_of_the_review():
    root = Path(portal_api.__file__).resolve().parent.parent

    def text(name: str) -> str:
        return " ".join((root / name).read_text().split())

    containment, actions = text("CONTAINMENT_CONTRACT.md"), text("ACTIONS_CONTRACT.md")
    readme, iam = text("README.md"), text("IAM_ACTIONS.md")
    minutes = containment_timing.REPEAT_AFTER_SECONDS // 60
    given_up = containment_timing.SWEEPS_OVER_AFTER_SECONDS // 60
    assert (minutes, given_up, lifecycle_rules.REVIEW_INTERVAL_HOURS) == (15, 30, 24)
    for said in (
        # S4
        "**A contain repeated while its sweeps are at work does nothing.**",
        f"no sooner than {minutes} minutes after the last contain that scheduled sweeps",
        f"a sweep that has not reported {given_up} minutes after its contain is given up",
        "retry_after_seconds: number | null;",
        "The history gets one `result` event for it",
        "once for each person who asks again during that time",
        "is never too soon to repeat",
        # S5
        "`CON-06-N` (release: the Runtime's tenant changed since it was contained",
        "**A tenant that changed.**",
        # S7
        "a session policy that leaves out writing and deleting a resource policy",
        # S13
        f"{containment_flow.NOT_KNOWN_WHETHER_WRITTEN}",
    ):
        assert said in containment, said
    for said in (
        # S6
        "to hold every tenant hosted there (`REG-13-N` as well",
        # S8
        "`review_by` may be at most 366 days ahead when a registration is created or updated",
        "or the approval date plus 366 days when the document names a later date",
        # S9 and S10
        "| `REV-05-N` | 403 | Review by the record's submitter |",
        "| `REV-06-N` | 409 | Review of a record whose review was attested less than 24 hours ago |",
        '"the submitter cannot attest the review of its own record - separation of duties (REV-05-N)"',
        "can be attested once in 24 hours",
        "Retire has no submitter rule; review has one of its own",
    ):
        assert said in actions, said
    assert "which have no submitter rule" not in actions and "whatever it is |" not in actions
    for said in (
        "**A contain repeated too soon.**",
        "**A tenant that changed.**",
        "**A write that may have been applied.**",
        "**Who attests, and how often.**",
        "**A registration's own review date.**",
        "**It never takes the place of a gateway a reader read.**",
        "(`portal-reader`, `portal-containment`, `portal-sweeper`)",
        "the caller to hold every tenant hosted there",
    ):
        assert said in readme, said
    assert "no 366-day rule" not in readme
    for said in (
        "**Role session names.**",
        "| Sweeper | the cell's containment role, with a session policy (section 7) | `portal-sweeper` |",
        "**The session its code asks for cannot either.**",
        "### The audit table, by partition key",
        "| Registrar (registrar role) | `RECORD#<record id>`, `RECORD#NAME#<record name>` | nothing | `RECORD#*` |",
        "| Approver (approver role) | `RECORD#<record id>`, `REVIEWS` | `RECORD#<record id>` | `RECORD#*`, `REVIEWS` |",
        "`sqs:SendMessage`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility` and",
        "`sqs:PurgeQueue`",
        "any principal of the Platform account that holds `lambda:InvokeFunction` on it",
    ):
        assert said in iam, said
    # The session policy in the document is the one the code builds.
    for action in (*sweeper_module.SWEEP_ACTIONS, *sweeper_module.SWEEP_SPANS_ACTIONS):
        assert f"`{action}`" in iam, action
    # The partition keys in the document are the ones the code writes and reads.
    assert audit_reader.record_key("x") == "RECORD#x" and audit_reader.name_key("n") == "RECORD#NAME#n"
    assert audit_reader.containment_key("arn") == "CONTAINMENT#arn" and audit_reader.REVIEWS_KEY == "REVIEWS"
    package = Path(portal_api.__file__).resolve().parent
    for name in ("registrar_flow.py", "registrar.py"):
        source = (package / "actions" / name).read_text()
        assert "read_back" not in source and "submitter(" not in source  # the registrar reads no history
    assert "REVIEWS_KEY" not in (package / "actions" / "containment_flow.py").read_text()
    for document in (containment, actions, readme, iam):
        assert "–" not in document and "—" not in document
