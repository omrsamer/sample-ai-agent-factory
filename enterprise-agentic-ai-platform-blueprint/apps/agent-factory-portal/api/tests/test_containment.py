# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Containment: the pure rules, the contain and release flows through the Lambda handler, and the read view."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mangum import Mangum

from portal_api import containment_policy, deps
from portal_api.actions import app as actions_app
from portal_api.actions import containment_rules as rules
from portal_api.app import create_app
from portal_api.aws import agentcore, registry
from portal_api.config import ConfigError, get_settings, load_action_settings
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    CELLS,
    ORPHAN_RUNTIME_ARN,
    OTHER_ACCOUNT,
    RUNTIME_ARN,
    FakeClient,
    FakeClients,
    agent_document,
    make_service,
    runtime_bundle,
)
from tests.fakes import FakeDynamo, FakePages, FakeRegistry, client_error
from tests.test_api import event

# security, tenants ws1 and ws2. A name is never what a person is recorded as, so this one is "sec-1".
SEC = {"sub": "sec-1", "name": "Sam Security", "cognito:groups": "[sec]"}
PAT = {"sub": "pat-1", "email": "pat@example.com", "cognito:groups": "[platform-admins]"}  # platform
PAT2 = {"sub": "pat-2", "cognito:groups": "[platform-admins]"}
SRE = {"sub": "sre-1", "cognito:groups": "[sre-team]"}  # sre, tenant ws1
SRE2 = {"sub": "sre-2", "cognito:groups": "[sre-team2]"}  # sre, tenant ws2
DEV = {"sub": "dev-1", "cognito:groups": "[devs]"}
ANN = {"sub": "ann-1", "cognito:groups": "[approvers]"}
VIEW = {"sub": "view-1", "cognito:groups": "[viewers]"}

CONTAINMENT_ROLE = f"arn:aws:iam::{CELL_ACCOUNT}:role/agenticai-portal-containment"
ORPHAN_ID = ORPHAN_RUNTIME_ARN.rsplit("/", 1)[-1]
OTHER_STATEMENTS = [
    {
        "Sid": "AllowPartner",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111111111111:role/partner"},
        "Action": "bedrock-agentcore:InvokeAgentRuntime",
        "Resource": RUNTIME_ARN,
    },
    {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "bedrock-agentcore:InvokeAgentRuntime",
        "Resource": RUNTIME_ARN,
        "Condition": {"StringNotEquals": {"aws:SourceVpc": "vpc-1a2b3c4d"}},
    },
]


class FakeCell:
    """The cell account as the containment role sees it: resource policies, spans and sessions."""

    def __init__(self) -> None:
        self.policies: dict[str, str] = {}
        self.calls: list[str] = []
        self.fail: dict[str, str] = {}  # operation -> error code, raised once
        self.sessions: list[dict[str, str]] = []  # Logs Insights rows
        self.query_status = "Complete"
        self.stop_errors: dict[str, str] = {}  # session id -> error code
        self.stopped: list[tuple[str, str]] = []
        self.lose_writes = False  # a put that reports success but does not persist
        self.reject_actions: set[str] = set()  # invoke actions the service refuses in a statement
        self.no_policy_is_empty_response = False  # GetResourcePolicy answers without a policy instead of raising
        self.assumed: list[tuple[str, str | None, str, str]] = []
        self.endpoints: list[str] = ["DEFAULT"]
        self.streams: dict[str, list[dict[str, Any]]] = {}  # log group name -> its streams, newest first
        self.stream_page_size = 50
        self.stream_requests: list[dict[str, Any]] = []
        self.tags: dict[str, dict[str, str]] = {}  # Runtime ARN -> its tags

    def _enter(self, operation: str) -> None:
        self.calls.append(operation)
        if operation in self.fail:
            raise client_error(self.fail.pop(operation), operation)

    # control plane
    def get_resource_policy(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
        self._enter("get_resource_policy")
        if resourceArn not in self.policies:
            if self.no_policy_is_empty_response:
                return {"ResponseMetadata": {}}
            raise client_error("ResourceNotFoundException", "GetResourcePolicy")
        return {"policy": self.policies[resourceArn]}

    def put_resource_policy(self, resourceArn: str, policy: str) -> dict[str, Any]:  # noqa: N803
        self._enter("put_resource_policy")
        for statement in json.loads(policy)["Statement"]:
            actions = statement.get("Action")
            if set([actions] if isinstance(actions, str) else actions) & self.reject_actions:
                raise client_error("ValidationException", "PutResourcePolicy")
            if not isinstance(statement.get("Resource"), str) or statement["Resource"] != resourceArn:
                # As the live service does: exactly one resource ARN, equal to the policy's resource.
                raise client_error("ValidationException", "PutResourcePolicy")
        if not self.lose_writes:
            self.policies[resourceArn] = policy
        return {"policy": policy}

    def delete_resource_policy(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
        self._enter("delete_resource_policy")
        if resourceArn not in self.policies:
            raise client_error("ResourceNotFoundException", "DeleteResourcePolicy")
        del self.policies[resourceArn]
        return {}

    def list_tags_for_resource(self, resourceArn: str) -> dict[str, Any]:  # noqa: N803
        self._enter("list_tags_for_resource")
        return {"tags": dict(self.tags.get(resourceArn, {}))}

    def get_paginator(self, operation: str) -> FakePages:
        assert operation == "list_agent_runtime_endpoints"  # noqa: S101
        self._enter(operation)
        return FakePages([{"runtimeEndpoints": [{"name": name, "status": "READY"} for name in self.endpoints]}])

    # logs
    def describe_log_streams(self, **kwargs: Any) -> dict[str, Any]:
        self._enter("describe_log_streams")
        self.stream_requests.append(kwargs)
        group = kwargs["logGroupName"]
        if group not in self.streams:
            raise client_error("ResourceNotFoundException", "DescribeLogStreams")
        offset = int(kwargs.get("nextToken") or 0)
        page = self.streams[group][offset : offset + self.stream_page_size]
        more = offset + self.stream_page_size < len(self.streams[group])
        return {"logStreams": page, **({"nextToken": str(offset + self.stream_page_size)} if more else {})}

    def start_query(self, **kwargs: Any) -> dict[str, Any]:
        self._enter("start_query")
        self.query = kwargs
        return {"queryId": "q-1"}

    def get_query_results(self, queryId: str) -> dict[str, Any]:  # noqa: N803
        self._enter("get_query_results")
        rows = [[{"field": k, "value": v} for k, v in row.items()] for row in self.sessions]
        return {"status": self.query_status, "results": rows}

    # data plane
    def stop_runtime_session(self, runtimeSessionId: str, agentRuntimeArn: str, qualifier: str) -> dict[str, Any]:  # noqa: N803
        self.calls.append("stop_runtime_session")
        if runtimeSessionId in self.stop_errors:
            raise client_error(self.stop_errors[runtimeSessionId], "StopRuntimeSession")
        self.stopped.append((runtimeSessionId, qualifier))
        return {"runtimeSessionId": runtimeSessionId, "statusCode": 200}


class FakeAssumed:
    def __init__(self, cell: FakeCell) -> None:
        self.cell = cell
        self.error: Exception | None = None
        self.session_policies: list[str | None] = []  # the session policy of every role assumption, in order

    def assumed(
        self, role_arn: str, external_id: str | None, region: str, service: str, session_policy: str | None = None
    ) -> FakeCell:
        if self.error:
            raise self.error
        self.cell.assumed.append((role_arn, external_id, region, service))
        self.session_policies.append(session_policy)
        return self.cell


def sid(name: str) -> str:
    """A Runtime session id: at least 33 characters."""
    return f"session-{name}-".ljust(40, "x")


RUNTIME_ID = RUNTIME_ARN.rsplit("/", 1)[-1]


def log_group(endpoint: str = "DEFAULT", runtime_id: str = RUNTIME_ID) -> str:
    return f"/aws/bedrock-agentcore/runtimes/{runtime_id}-{endpoint}"


def stream(name: str, minutes_ago: float = 5, **times: Any) -> dict[str, Any]:
    """A log stream as DescribeLogStreams returns it. Times are epoch milliseconds."""
    import time

    at = int((time.time() - minutes_ago * 60) * 1000)
    return {"logStreamName": name, "creationTime": at, "lastEventTimestamp": at, "lastIngestionTime": at, **times}


def session_stream(name: str, minutes_ago: float = 5, **times: Any) -> dict[str, Any]:
    return stream(f"runtime-logs-{sid(name)}", minutes_ago, **times)


def session_row(
    session_id: str, endpoint: str = "DEFAULT", last_seen: str = "2026-01-15 12:00:00.000"
) -> dict[str, str]:
    return {
        "session_id": session_id,
        "resource_id": f"{RUNTIME_ARN}/runtime-endpoint/{endpoint}:{endpoint}",
        "last_seen": last_seen,
    }


class World:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.monkeypatch = monkeypatch
        self.cell = FakeCell()
        self.assumed = FakeAssumed(self.cell)
        self.registry = FakeRegistry()
        self.dynamo = FakeDynamo()
        self.record_id = self.registry.seed("agent-ws1-travel-agent-nonprod", json.dumps(agent_document()), "APPROVED")
        application = actions_app.create_action_app("containment")
        application.dependency_overrides[actions_app.registry_client] = lambda: self.registry
        application.dependency_overrides[actions_app.dynamodb_client] = lambda: self.dynamo
        application.dependency_overrides[actions_app.containment_clients] = lambda: self.assumed
        self.handler = Mangum(application, lifespan="off")
        monkeypatch.setenv("PORTAL_ACTION_ROLE", "containment")

    def post(
        self, action: str, agent_id: str | None = None, claims: dict | None = SEC, body: Any = None
    ) -> tuple[int, Any]:
        agent_id = agent_id or self.record_id
        request = event(f"/agents/{agent_id}/containment/{action}", "POST", claims)
        request["body"] = json.dumps({"reason": "Suspected prompt injection."} if body is None else body)
        request["headers"]["content-type"] = "application/json"
        response = self.handler(request, None)
        return response["statusCode"], json.loads(response["body"])

    def statements(self, arn: str = RUNTIME_ARN) -> list[dict[str, Any]]:
        return json.loads(self.cell.policies[arn])["Statement"]

    def trail(self) -> list[tuple[str, str, str]]:
        return [(e["action"], e["phase"], e["outcome"]) for e in self.dynamo.events()]


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return World(monkeypatch)


def refusals_logged(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The refusals the containment function logged instead of writing them to the audit trail."""
    return [r.getMessage() for r in caplog.records if "not written to the audit trail" in r.getMessage()]


# --- the rules (pure) ------------------------------------------------------------------------


def decide(**overrides: Any) -> rules.ContainmentDecision:
    values = {
        "action": "contain",
        "role": "security",
        "principal_id": "p-1",
        "agent_tenant": "ws1",
        "held_tenants": ("ws1",),
        "holds_all_tenants": False,
        "contained_by": None,
        "contained_tenant": "ws1",  # the tenant the Runtime had when it was contained: unchanged
    }
    values.update(overrides)
    return rules.evaluate(**values)


@pytest.mark.parametrize(
    ("role", "contain", "release"),
    [
        ("security", True, True),
        ("platform", True, True),
        ("sre", True, False),
        ("approver", False, False),
        ("developer", False, False),
        ("finops", False, False),
        ("readonly", False, False),
    ],
)
def test_which_role_may_contain_and_release(role, contain, release):
    assert decide(role=role, action="contain").allowed is contain
    assert decide(role=role, action="release", contained_by="someone-else").allowed is release


def test_rule_reasons_and_order():
    assert "CON-01-N" in decide(role="developer").reason
    assert "CON-02-N" in decide(role="sre", action="release").reason
    assert "CON-04-N" in decide(agent_tenant="ws2").reason
    assert "CON-05-N" in decide(role="sre", agent_tenant=None).reason
    assert "CON-05-N" in decide(role="security", agent_tenant=None).reason
    assert "CON-03-N" in decide(action="release", contained_by="p-1").reason
    assert "CON-01-P" in decide().reason and decide().allowed
    assert "CON-03-P" in decide(action="release", contained_by="p-2").reason
    # the role is checked before the tenant, and the tenant before the two-person rule
    assert "CON-01-N" in decide(role="developer", agent_tenant="ws2").reason
    assert "CON-04-N" in decide(action="release", agent_tenant="ws2", contained_by="p-1").reason


def test_two_person_rule_is_not_bypassed_by_the_platform_role():
    same = decide(action="release", role="platform", holds_all_tenants=True, contained_by="p-1")
    assert same.allowed is False and "CON-03-N" in same.reason
    assert decide(action="release", role="platform", holds_all_tenants=True, contained_by="p-2").allowed
    assert decide(action="release", contained_by=None).allowed  # no portal containment on record


def test_tenant_rules():
    assert decide(role="platform", agent_tenant="anything", held_tenants=(), holds_all_tenants=True).allowed
    assert decide(role="platform", agent_tenant=None, holds_all_tenants=True).allowed
    assert not decide(role="security", agent_tenant="ws3", held_tenants=("ws1", "ws2")).allowed
    # A tenant that cannot be determined is for the role that holds every tenant, and for nobody else:
    # a security user of one tenant must not reach an agent that may be another tenant's.
    for role in ("security", "sre"):
        refused = decide(role=role, agent_tenant=None, held_tenants=("ws1", "ws2"))
        assert not refused.allowed and "CON-05-N" in refused.reason


def test_the_tenant_comes_from_where_the_runtime_runs_not_from_a_registration():
    import inspect

    tenant_for = rules.tenant_for
    # One tenant in the Runtime's account: that tenant, whatever the Runtime's tag says.
    assert tenant_for({"ws2"}) == "ws2"
    assert tenant_for({"ws2"}, "ws1") == "ws2"
    assert tenant_for({"ws2"}, runtime_tenant_tag=None) == "ws2"
    # A shared account: the Runtime's own tenant-id tag decides, when it names one of the account's tenants.
    assert tenant_for({"ws1", "ws9"}, "ws1") == "ws1"
    assert tenant_for({"ws1", "ws9"}, "ws9") == "ws9"
    assert tenant_for({"ws1", "ws9"}, "ws5") is None  # a tenant the account does not host
    assert tenant_for({"ws1", "ws9"}, "") is None
    assert tenant_for({"ws1", "ws9"}) is None  # no tag, or a tag that could not be read
    # No cell at all for that account and Region.
    assert tenant_for(set(), "ws1") is None
    # A registration is no input of the rule at all.
    assert list(inspect.signature(tenant_for).parameters) == ["cell_tenants", "runtime_tenant_tag"]


def test_rules_fail_closed():
    assert not decide(action="destroy").allowed and "unknown action" in decide(action="destroy").reason
    assert not decide(principal_id="").allowed
    assert not decide(role="").allowed


# --- contain ------------------------------------------------------------------------------------


def test_contain_a_runtime_that_has_no_policy(world):
    world.cell.sessions = [session_row(sid("aaa")), session_row(sid("bbb"), "LIVE")]
    code, body = world.post("contain")
    assert code == 200
    assert world.statements() == [containment_policy.containment_statement(RUNTIME_ARN)]
    assert body["action"] == "contain" and body["outcome"] == "allowed" and body["changed"] is True
    assert (body["state"], body["agent_id"], body["runtime_arn"]) == ("contained", world.record_id, RUNTIME_ARN)
    assert body["other_statements_kept"] == 0 and body["audit_complete"] is True
    assert body["sessions"] == {
        "discovery": "ok",
        "sources": {"spans": 2, "log_streams": 0},
        "found": 2,
        "stopped": 2,
        "not_active": 0,
        "failed": 0,
        "not_attempted": 0,
        "stop_errors": [],
    }
    assert body["denied_actions"] == list(containment_policy.ALL_INVOKE_ACTIONS)
    assert (body["partial"], body["enforcement_delay_seconds"]) == (False, 90)
    assert [(step["id"], step["status"]) for step in body["steps"]] == [
        ("policy", "done"),
        ("verify", "done"),
        ("sessions", "done"),
    ]
    assert "enforced everywhere within about 90 seconds" in body["reason"]
    assert sorted(world.cell.stopped) == [(sid("aaa"), "DEFAULT"), (sid("bbb"), "LIVE")]
    assert body["reason"].startswith("Suspected prompt injection. [Invocation of the Runtime is denied")
    # read, write, read back to verify
    assert [c for c in world.cell.calls if c.endswith("resource_policy")] == [
        "get_resource_policy",
        "put_resource_policy",
        "get_resource_policy",
    ]
    # everything in the cell is done with the cell's containment role and external id
    assert {(role, external) for role, external, _, _ in world.cell.assumed} == {(CONTAINMENT_ROLE, "portal-ext-id")}
    assert {service for _, _, _, service in world.cell.assumed} == {
        "bedrock-agentcore-control",
        "logs",
        "bedrock-agentcore",
    }
    assert (
        f'like "{RUNTIME_ARN}/"' in world.cell.query["queryString"] and world.cell.query["logGroupName"] == "aws/spans"
    )


def test_contain_keeps_every_other_statement_byte_for_byte(world):
    original = json.dumps({"Version": "2012-10-17", "Id": "team-policy", "Statement": OTHER_STATEMENTS}, indent=3)
    world.cell.policies[RUNTIME_ARN] = original
    code, body = world.post("contain")
    assert code == 200 and body["other_statements_kept"] == 2
    document = json.loads(world.cell.policies[RUNTIME_ARN])
    assert document["Statement"][:2] == OTHER_STATEMENTS and document["Id"] == "team-policy"
    assert document["Statement"][2] == containment_policy.containment_statement(RUNTIME_ARN)
    assert len(document["Statement"]) == 3


def test_contain_audit_events(world):
    world.cell.sessions = [session_row(sid("aaa"))]
    assert world.post("contain")[0] == 200
    intent, result = world.dynamo.events()
    # The history belongs to the Runtime the request resolved to, not to the id the caller used.
    assert intent["pk"] == result["pk"] == f"CONTAINMENT#{RUNTIME_ARN}"
    assert (intent["phase"], intent["outcome"], intent["action"]) == ("intent", "allowed", "contain")
    assert "CON-01-P" in intent["reason"]
    assert (result["phase"], result["outcome"], result["status_before"], result["status_after"]) == (
        "result",
        "allowed",
        "not_contained",
        "contained",
    )
    assert (result["sessions_found"], result["sessions_stopped"], result["sessions_failed"]) == ("1", "1", "0")
    assert (
        result["reason"].startswith("Suspected prompt injection.")
        and "1 of 1 recent session(s) stopped" in result["reason"]
    )
    for item in (intent, result):
        assert (item["actor_subject"], item["actor_label"], item["actor_role"]) == ("sec-1", "sec-1", "security")
        assert (item["agent_id"], item["runtime_arn"], item["tenant_id"]) == (world.record_id, RUNTIME_ARN, "ws1")
        assert item["sk"] == f"EVENT#{item['at']}#{item['event_id']}"
    assert intent["request_id"] == result["request_id"]


def test_a_second_contain_changes_nothing_and_does_not_replace_the_container(world):
    assert world.post("contain", claims=SEC)[0] == 200
    before = world.cell.policies[RUNTIME_ARN]
    world.cell.calls.clear()
    code, body = world.post("contain", claims=PAT)
    assert code == 200 and (body["outcome"], body["changed"], body["state"]) == ("unchanged", False, "contained")
    assert "already contained" in body["reason"]
    assert world.cell.policies[RUNTIME_ARN] == before and "put_resource_policy" not in world.cell.calls
    assert len([s for s in world.statements() if s.get("Sid") == "AgenticAIPortalContainment"]) == 1
    assert world.trail()[-1] == ("contain", "result", "unchanged")
    # the first container is still the container: it cannot release, the second person can
    assert "CON-03-N" in world.post("release", claims=SEC)[1]["detail"]
    assert world.post("release", claims=PAT)[0] == 200


@pytest.mark.parametrize(
    ("claims", "expected", "reason"),
    [
        (SEC, 200, None),
        (PAT, 200, None),
        (SRE, 200, None),
        (SRE2, 403, "CON-04-N"),
        (DEV, 403, "CON-01-N"),
        (ANN, 403, "CON-01-N"),
        (VIEW, 403, "CON-01-N"),
    ],
)
def test_contain_authority_and_tenant(world, caplog, claims, expected, reason):
    with caplog.at_level("WARNING"):
        code, body = world.post("contain", claims=claims)
    assert code == expected
    if reason:
        assert reason in body["detail"] and RUNTIME_ARN not in world.cell.policies
        assert world.cell.calls == []
        # A caller without the role, or without the Runtime's tenant, has no part in the Runtime:
        # nothing is written into its history and nothing is read of it. Any signed-in responder
        # of another tenant could otherwise fill it, and a history is never shortened.
        assert world.trail() == [] and world.dynamo.calls == []
        # The function's log keeps the attempt, under the request id the answer carries.
        (logged,) = refusals_logged(caplog)
        assert body["request_id"] in logged and reason in logged
        if reason == "CON-01-N":
            # Refused before the agent is resolved at all.
            assert world.registry.calls == []


def test_a_caller_without_the_role_is_refused_before_anything_is_looked_up(world):
    code, body = world.post("contain", agent_id="rec999999999", claims=DEV)
    assert code == 403 and "CON-01-N" in body["detail"] and body.get("request_id")
    assert world.registry.calls == [] and world.cell.calls == []
    # ... and nothing is written under an id the caller made up, however often it is tried.
    for _ in range(3):
        assert world.post("release", agent_id="rec999999999", claims=VIEW)[0] == 403
    assert world.dynamo.events() == []


def test_containment_not_enabled_for_the_cell_is_409(world, monkeypatch, caplog):
    without = {k: v for k, v in CELLS[0].items() if k not in ("containmentRoleArn", "containmentSpans")}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([without, CELLS[1]]))
    with caplog.at_level("WARNING"):
        code, body = world.post("contain")
    assert (code, body["detail"]) == (409, "containment is not enabled for this cell")
    # Nothing is read or written about a Runtime the portal cannot contain: logged, not stored.
    assert world.cell.calls == [] and world.trail() == [] and world.dynamo.calls == []
    (logged,) = refusals_logged(caplog)
    assert body["request_id"] in logged and "not enabled" in logged


def test_resolving_a_registered_agent(world):
    assert world.post("contain", agent_id="rec999999999")[0] == 404
    tool = world.registry.seed("tool-echo", json.dumps({"schemaVersion": "agenticai.tool-governance/1.0"}))
    assert world.post("contain", agent_id=tool)[0] == 404
    no_runtime = world.registry.seed("agent-ws1-x-nonprod", json.dumps(agent_document(runtimeArn=None, agentId="x")))
    code, body = world.post("contain", agent_id=no_runtime)
    assert code == 409 and "names no Runtime" in body["detail"]
    code, body = world.post("contain", body={"reason": "r", "runtime_arn": ORPHAN_RUNTIME_ARN})
    assert code == 422 and body["detail"][0]["loc"] == ["body", "runtime_arn"]
    assert world.cell.calls == []


def test_an_agent_with_no_registration_is_addressed_by_its_runtime_id(world):
    code, body = world.post("contain", agent_id=ORPHAN_ID, claims=SRE)
    assert code == 200 and body["runtime_arn"] == ORPHAN_RUNTIME_ARN  # the only cell account with containment enabled
    assert world.registry.calls == []  # no registry read for an unregistered agent
    assert world.dynamo.events()[0]["tenant_id"] == "ws1"  # the tenant of its cell account
    assert world.post("contain", agent_id="not a runtime id!", claims=SEC)[0] in (404, 422)
    code, body = world.post("contain", agent_id=ORPHAN_ID, body={"reason": "r", "runtime_arn": RUNTIME_ARN})
    assert code == 422 and "not this agent's Runtime" in body["detail"][0]["msg"]


def test_runtime_arn_is_needed_when_several_cell_accounts_can_be_contained(world, monkeypatch):
    other = {**CELLS[1], "containmentRoleArn": f"arn:aws:iam::{OTHER_ACCOUNT}:role/agenticai-portal-containment"}
    shared = {**CELLS[0], "tenantId": "ws9", "agentId": "second-agent"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([CELLS[0], other, shared]))
    code, body = world.post("contain", agent_id=ORPHAN_ID)
    assert code == 422 and "runtime_arn is required" in body["detail"][0]["msg"]
    # With the ARN it resolves. Its account now holds two tenants, so the agent's tenant cannot be
    # determined, and only the role that holds every tenant may act: not sre, and not security either.
    orphan = {"reason": "r", "runtime_arn": ORPHAN_RUNTIME_ARN}
    for claims in (SRE, SEC):
        code, body = world.post("contain", agent_id=ORPHAN_ID, claims=claims, body=orphan)
        assert code == 403 and "CON-05-N" in body["detail"]
    assert ORPHAN_RUNTIME_ARN not in world.cell.policies
    assert world.post("contain", agent_id=ORPHAN_ID, claims=PAT, body=orphan)[0] == 200
    assert ORPHAN_RUNTIME_ARN in world.cell.policies


def test_the_statement_names_one_resource_and_every_documented_invoke_action(world):
    assert world.post("contain")[0] == 200
    (statement,) = world.statements()
    assert statement["Resource"] == RUNTIME_ARN and statement["Principal"] == "*" and statement["Effect"] == "Deny"
    assert statement["Action"] == list(containment_policy.ALL_INVOKE_ACTIONS)
    assert set(containment_policy.CORE_INVOKE_ACTIONS) < set(statement["Action"])
    assert not [a for a in statement["Action"] if "Stop" in a or "Get" in a or "*" in a]


def test_falls_back_to_the_core_invoke_actions_when_the_full_list_is_rejected(world):
    world.cell.reject_actions = {"bedrock-agentcore:InvokeAgentRuntimeCommandShell"}
    code, body = world.post("contain")
    assert code == 200 and body["state"] == "contained" and body["changed"] is True
    (statement,) = world.statements()
    assert statement["Action"] == list(containment_policy.CORE_INVOKE_ACTIONS) == body["denied_actions"]
    assert world.cell.calls.count("put_resource_policy") == 2
    assert "rejected the full list" in body["steps"][0]["detail"]
    assert "accepted only the core invoke actions" in body["reason"]
    assert "accepted only the core invoke actions" in world.dynamo.events()[-1]["reason"]
    # a later contain reports what the existing statement denies, and release still removes it
    assert world.post("contain", claims=PAT)[1]["denied_actions"] == list(containment_policy.CORE_INVOKE_ACTIONS)
    assert world.post("release", claims=PAT)[0] == 200 and RUNTIME_ARN not in world.cell.policies


def test_a_rejection_of_the_core_statement_too_is_a_failure(world):
    world.cell.reject_actions = {"bedrock-agentcore:InvokeAgentRuntime"}
    code, body = world.post("contain")
    assert code == 502 and "could not be written (ValidationException). Nothing was changed." in body["detail"]
    assert world.cell.policies == {}
    assert [(step["id"], step["status"]) for step in body["steps"]] == [
        ("policy", "failed"),
        ("verify", "skipped"),
        ("sessions", "skipped"),
    ]


def test_a_runtime_whose_policy_read_answers_with_no_policy(world):
    world.cell.no_policy_is_empty_response = True
    code, body = world.post("contain")
    assert code == 200 and body["other_statements_kept"] == 0
    assert world.post("release", claims=PAT)[1]["policy_deleted"] is True
    assert world.post("release", claims=PAT)[1]["outcome"] == "unchanged"


def test_sessions_are_bounded_in_number_time_and_shape(world, monkeypatch):
    from portal_api.actions import containment
    from portal_api.aws import logs

    assert (logs.MAX_SESSIONS, logs.SESSION_LOOKBACK_HOURS) == (1000, 8)
    world.cell.sessions = [session_row(sid(f"s{i:03d}")) for i in range(40)] + [
        {"session_id": "too-short", "resource_id": ""},  # not a Runtime session id: ignored
    ]
    ticks = iter(range(0, 1000, 5))
    original = containment.stop_sessions
    monkeypatch.setattr(
        containment,
        "stop_sessions",
        lambda client, arn, sessions: original(client, arn, sessions, budget_seconds=12.0, clock=lambda: next(ticks)),
    )
    code, body = world.post("contain")
    assert code == 200 and body["state"] == "contained"
    assert body["sessions"]["found"] == 40 and body["sessions"]["stopped"] == 32  # two batches fit the budget
    assert body["sessions"]["not_attempted"] == 8 and body["partial"] is True
    assert (
        body["steps"][2]["status"] == "partial"
        and "8 were not attempted before the time limit" in body["steps"][2]["detail"]
    )
    assert "limit 1000" in world.cell.query["queryString"]
    assert world.cell.query["endTime"] - world.cell.query["startTime"] == 8 * 3600
    assert world.dynamo.events()[-1]["sessions_failed"] == "8"


def test_a_policy_deleted_by_someone_else_during_release_counts_as_released(world):
    assert world.post("contain", claims=SEC)[0] == 200
    original = world.cell.delete_resource_policy

    def racing_delete(resourceArn: str) -> dict:  # noqa: N803
        world.cell.policies.pop(resourceArn, None)  # another actor removed it first
        return original(resourceArn)

    world.cell.delete_resource_policy = racing_delete
    code, body = world.post("release", claims=PAT)
    assert code == 200 and body["state"] == "not_contained" and body["policy_deleted"] is True


def test_a_failure_answer_carries_the_steps(world):
    world.cell.lose_writes = True
    code, body = world.post("contain")
    assert code == 502
    assert [(step["id"], step["status"]) for step in body["steps"]] == [
        ("policy", "done"),
        ("verify", "failed"),
        ("sessions", "skipped"),
    ]
    assert body["steps"][1]["detail"] == "The statement was not found when the policy was read back."
    assert set(body) == {"detail", "action", "request_id", "steps"}


# --- finding the sessions to stop: spans and session log streams ------------------------------------------


def test_sessions_from_log_streams_only(world):
    """An agent that emits no spans (for example an unmanaged one) still has a log stream per session."""
    world.cell.streams[log_group()] = [session_stream("aaa", 2), session_stream("bbb", 30)]
    code, body = world.post("contain")
    assert code == 200
    assert body["sessions"] == {
        "discovery": "ok",
        "sources": {"spans": 0, "log_streams": 2},
        "found": 2,
        "stopped": 2,
        "not_active": 0,
        "failed": 0,
        "not_attempted": 0,
        "stop_errors": [],
    }
    assert sorted(world.cell.stopped) == [(sid("aaa"), "DEFAULT"), (sid("bbb"), "DEFAULT")]
    assert (body["partial"], body["steps"][2]["status"]) == (False, "done")
    assert "2 of 2 recent session(s) stopped, 0 had already ended (found 0 in traces, 2 in logs)." in body["reason"]
    request = world.cell.stream_requests[0]
    assert request == {"logGroupName": log_group(), "orderBy": "LastEventTime", "descending": True, "limit": 50}
    # stream names only: no log event is ever read
    assert not {"get_log_events", "filter_log_events"} & set(world.cell.calls)


def test_sessions_from_spans_only(world):
    world.cell.sessions = [session_row(sid("aaa"))]
    body = world.post("contain")[1]
    assert (body["sessions"]["sources"], body["sessions"]["found"], body["sessions"]["discovery"]) == (
        {"spans": 1, "log_streams": 0},
        1,
        "ok",
    )
    assert world.cell.stopped == [(sid("aaa"), "DEFAULT")]


def test_sessions_from_both_sources_are_merged_without_duplicates(world):
    import time

    recent = time.strftime("%Y-%m-%d %H:%M:%S.000", time.gmtime(time.time() - 60))
    world.cell.sessions = [session_row(sid("both"), last_seen=recent), session_row(sid("spans"), last_seen=recent)]
    world.cell.streams[log_group()] = [session_stream("logs", 10), session_stream("both", 20)]
    body = world.post("contain")[1]
    assert body["sessions"]["sources"] == {"spans": 2, "log_streams": 2}  # counted before de-duplication
    assert (body["sessions"]["found"], body["sessions"]["stopped"]) == (3, 3)
    assert sorted(world.cell.stopped) == sorted(
        [(sid("both"), "DEFAULT"), (sid("spans"), "DEFAULT"), (sid("logs"), "DEFAULT")]
    )
    assert "(found 2 in traces, 2 in logs)" in body["reason"]
    assert (world.dynamo.events()[-1]["sessions_found"], world.dynamo.events()[-1]["detail"]) == ("3", "ok")


def test_discovered_sessions_are_ordered_most_recent_first_and_capped(world):
    import time

    from portal_api.actions import containment
    from portal_api.aws import logs

    def at(minutes_ago: float) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S.000", time.gmtime(time.time() - minutes_ago * 60))

    world.cell.sessions = [session_row(sid("span-old"), last_seen=at(300)), session_row(sid("both"), last_seen=at(1))]
    world.cell.streams[log_group()] = [session_stream("log-mid", 100), session_stream("both", 200)]
    found = containment.discover_sessions(world.cell, world.cell, RUNTIME_ARN, use_spans=True)
    # one entry for the session both sources saw, placed by its most recent sighting
    assert [s.session_id for s in found.sessions] == [sid("both"), sid("log-mid"), sid("span-old")]
    assert (found.note, found.sources, found.failed) == ("ok", {"spans": 2, "log_streams": 2}, False)

    world.cell.stream_page_size = 50
    world.cell.streams[log_group()] = [session_stream(f"n{i:03d}", 1 + i / 100) for i in range(150)]
    world.cell.sessions = [session_row(sid(f"m{i:03d}"), last_seen=at(60)) for i in range(120)]
    whole = containment.discover_sessions(world.cell, world.cell, RUNTIME_ARN, use_spans=True)
    assert len(whole.sessions) == 270 and whole.note == "ok"  # under the limit: nothing is cut, nothing is said

    world.cell.streams[log_group()] = [session_stream(f"n{i:03d}", 1 + i / 100) for i in range(800)]
    world.cell.sessions = [session_row(sid(f"m{i:03d}"), last_seen=at(60)) for i in range(400)]
    capped = containment.discover_sessions(world.cell, world.cell, RUNTIME_ARN, use_spans=True)
    assert len(capped.sessions) == logs.MAX_SESSIONS == 1000
    assert capped.sources == {"spans": 400, "log_streams": 800}
    assert capped.sessions[0].session_id == sid("n000")  # the newest are kept
    # A cut list never reads as complete.
    assert capped.note == "ok; the limit of 1000 sessions per action was reached, so more sessions may be running"

    # A source that returns as many rows as it may return has probably more.
    world.cell.streams[log_group()] = []
    world.cell.sessions = [session_row(sid(f"q{i:04d}"), last_seen=at(60)) for i in range(1000)]
    full = containment.discover_sessions(world.cell, world.cell, RUNTIME_ARN, use_spans=True)
    assert len(full.sessions) == 1000 and "more sessions may be running" in full.note


def test_the_same_session_id_on_two_endpoints_is_two_sessions(world):
    world.cell.endpoints = ["DEFAULT", "LIVE"]
    world.cell.streams[log_group("DEFAULT")] = [session_stream("aaa")]
    world.cell.streams[log_group("LIVE")] = [session_stream("aaa"), session_stream("bbb")]
    body = world.post("contain")[1]
    assert body["sessions"]["found"] == 3
    assert sorted(world.cell.stopped) == [(sid("aaa"), "DEFAULT"), (sid("aaa"), "LIVE"), (sid("bbb"), "LIVE")]
    assert [request["logGroupName"] for request in world.cell.stream_requests] == [
        log_group("DEFAULT"),
        log_group("LIVE"),
    ]


def test_a_log_group_that_does_not_exist_means_no_sessions_not_an_error(world):
    world.cell.endpoints = ["DEFAULT", "LIVE"]
    world.cell.streams[log_group("LIVE")] = [session_stream("aaa")]  # DEFAULT has no log group at all
    body = world.post("contain")[1]
    assert (body["sessions"]["discovery"], body["sessions"]["found"], body["partial"]) == ("ok", 1, False)
    assert world.cell.stopped == [(sid("aaa"), "LIVE")]


def test_when_endpoints_cannot_be_listed_default_is_checked_and_it_is_said(world):
    world.cell.fail["list_agent_runtime_endpoints"] = "AccessDeniedException"
    world.cell.streams[log_group("DEFAULT")] = [session_stream("aaa")]
    world.cell.streams[log_group("LIVE")] = [session_stream("bbb")]
    body = world.post("contain")[1]
    assert body["sessions"]["discovery"] == (
        "ok; endpoints could not be listed (AccessDeniedException), only DEFAULT was checked"
    )
    assert world.cell.stopped == [(sid("aaa"), "DEFAULT")]
    assert (body["partial"], body["steps"][2]["status"]) == (True, "partial")
    assert "Session discovery was incomplete: endpoints could not be listed" in body["steps"][2]["detail"]


def test_one_source_failing_leaves_the_other_in_use(world):
    world.cell.fail["start_query"] = "AccessDeniedException"
    world.cell.streams[log_group()] = [session_stream("aaa")]
    body = world.post("contain")[1]
    assert (
        body["sessions"]["discovery"]
        == "ok; spans could not be queried (query could not start (AccessDeniedException))"
    )
    assert (body["sessions"]["found"], body["sessions"]["stopped"], body["partial"]) == (1, 1, True)

    world.cell.policies.clear()
    world.cell.stopped.clear()
    world.cell.sessions = [session_row(sid("bbb"))]
    world.cell.fail["describe_log_streams"] = "ThrottlingException"
    body = world.post("contain", claims=PAT)[1]
    assert body["sessions"]["discovery"] == "ok; log streams could not be listed (ThrottlingException)"
    assert world.cell.stopped == [(sid("bbb"), "DEFAULT")] and body["partial"] is True


@pytest.mark.parametrize("status", ["Timeout", "Failed", "Cancelled"])
def test_a_spans_query_that_did_not_finish_never_reads_as_a_complete_list(world, status):
    world.cell.sessions = [session_row(sid("partial"))]
    world.cell.query_status = status  # the query ended, but not as complete: its rows may be a part
    code, body = world.post("contain")
    assert code == 200 and body["state"] == "contained"
    # What it did return is stopped, and the result says that more may be running.
    assert world.cell.stopped == [(sid("partial"), "DEFAULT")]
    note = f"the spans query did not finish (query ended with status {status}), so more sessions may be running"
    assert body["sessions"]["discovery"] == f"ok; {note}"
    assert body["partial"] is True and body["steps"][2]["status"] == "partial"
    assert note in body["steps"][2]["detail"]
    assert world.dynamo.events()[-1]["detail"] == f"ok; {note}"


def test_a_spans_query_still_running_at_the_deadline_never_reads_as_a_complete_list(world, monkeypatch):
    from portal_api.actions import containment

    assert containment.SPANS_WAIT_SECONDS == 8.0
    monkeypatch.setattr(containment, "SPANS_WAIT_SECONDS", 0.05)
    world.cell.sessions = [session_row(sid("partial"))]
    world.cell.query_status = "Running"  # partial rows, as the service returns while a query runs
    code, body = world.post("contain")
    assert code == 200 and world.cell.stopped == [(sid("partial"), "DEFAULT")]
    assert body["sessions"]["discovery"] == (
        "ok; the spans query did not finish (query still running after 0.05s), so more sessions may be running"
    )
    assert body["partial"] is True
    # A query that finished with no row left is complete, and says nothing.
    world.cell.query_status = "Complete"
    again = world.post("contain", claims=PAT)[1]
    assert (again["sessions"]["discovery"], again["partial"]) == ("ok", False)


def test_streams_that_are_not_recent_sessions_are_ignored(world):
    old = 9 * 60  # minutes: outside the eight-hour window
    world.cell.streams[log_group()] = [
        session_stream("recent", 5),
        # lastEventTimestamp lags, so the newest of the three times decides
        session_stream("lagging", old, lastIngestionTime=session_stream("x", 1)["creationTime"]),
        stream("otel-rt-logs", 1),
        stream("spans", 1),
        stream("build-logs-0123456789abcdef0123456789abcdef0123", 1),
        stream("runtime-logs-short", 1),  # not a session id: too short
        stream("runtime-logs-" + "has spaces".ljust(40, "x"), 1),
        stream(f"prefix-runtime-logs-{sid('nope')}", 1),
        session_stream("old", old),  # every time is outside the window
    ]
    body = world.post("contain")[1]
    assert sorted(world.cell.stopped) == [(sid("lagging"), "DEFAULT"), (sid("recent"), "DEFAULT")]
    assert body["sessions"]["sources"] == {"spans": 0, "log_streams": 2}


def test_stream_paging_stops_at_the_page_cap_and_at_the_first_page_outside_the_window(world, monkeypatch):
    from portal_api.actions import containment

    assert (containment.MAX_STREAM_PAGES, containment.STREAM_PAGE_LIMIT, containment.MAX_ENDPOINTS) == (20, 50, 10)
    monkeypatch.setattr(containment, "MAX_STREAM_PAGES", 4)
    world.cell.stream_page_size = 2
    world.cell.streams[log_group()] = [session_stream(f"s{i:02d}", i + 1) for i in range(12)]  # six pages of two
    body = world.post("contain")[1]
    assert len(world.cell.stream_requests) == 4  # the page cap
    assert body["sessions"]["found"] == 8 and len(world.cell.stopped) == 8
    # The cap cut the list, so the result is partial and says that more sessions may be running.
    assert body["partial"] is True and "more sessions may be running" in body["sessions"]["discovery"]
    assert "more sessions may be running" in body["steps"][2]["detail"]

    world.cell.policies.clear()
    world.cell.stream_requests.clear()
    world.cell.stopped.clear()
    old = 9 * 60
    world.cell.streams[log_group()] = [
        session_stream("new1", 1),
        session_stream("new2", 2),
        session_stream("old1", old),
        session_stream("old2", old),  # a page with nothing in the window: stop here
        session_stream("new3", 3),
        session_stream("new4", 4),
    ]
    body = world.post("contain", claims=PAT)[1]
    assert len(world.cell.stream_requests) == 2
    assert sorted(world.cell.stopped) == [(sid("new1"), "DEFAULT"), (sid("new2"), "DEFAULT")]


def test_at_most_ten_endpoints_are_checked_and_odd_names_are_skipped(world):
    world.cell.endpoints = [f"EP{i}" for i in range(14)] + ["bad name"]
    body = world.post("contain")[1]
    assert [request["logGroupName"] for request in world.cell.stream_requests] == [
        log_group(f"EP{i}") for i in range(10)
    ]
    assert body["sessions"]["discovery"] == "ok"


def test_session_discovery_requests_match_the_service_models():
    import boto3
    from botocore.stub import Stubber

    from portal_api.actions import containment
    from tests.conftest import T0

    credentials = {"aws_access_key_id": "test", "aws_secret_access_key": "test", "region_name": "eu-west-1"}
    control = boto3.client("bedrock-agentcore-control", **credentials)
    with Stubber(control) as stub:
        stub.add_response(
            "list_agent_runtime_endpoints",
            {"runtimeEndpoints": [_endpoint("DEFAULT"), _endpoint("LIVE")]},
            {"agentRuntimeId": RUNTIME_ID},
        )
        assert containment.list_endpoints(control, RUNTIME_ID) == (["DEFAULT", "LIVE"], None)
        stub.assert_no_pending_responses()

    logs_client = boto3.client("logs", **credentials)
    recent = session_stream("aaa", 1)
    expected = {"logGroupName": log_group(), "orderBy": "LastEventTime", "descending": True, "limit": 50}
    with Stubber(logs_client) as stub:
        stub.add_response("describe_log_streams", {"logStreams": [recent], "nextToken": "next-page"}, expected)
        stub.add_response(
            "describe_log_streams", {"logStreams": [stream("otel-rt-logs", 1)]}, {**expected, "nextToken": "next-page"}
        )
        found = containment.sessions_from_log_streams(logs_client, RUNTIME_ID, ["DEFAULT"], T0)
        stub.assert_no_pending_responses()
    assert [(s.session_id, s.qualifier) for s in found] == [(sid("aaa"), "DEFAULT")]

    with Stubber(logs_client) as stub:
        stub.add_client_error(
            "describe_log_streams", "ResourceNotFoundException", "The specified log group does not exist."
        )
        assert containment.sessions_from_log_streams(logs_client, RUNTIME_ID, ["DEFAULT"], T0) == []
    with Stubber(logs_client) as stub:
        stub.add_client_error("describe_log_streams", "AccessDeniedException", "not authorized")
        with pytest.raises(containment.SourceFailed, match="AccessDeniedException"):
            containment.sessions_from_log_streams(logs_client, RUNTIME_ID, ["DEFAULT"], T0)


def _endpoint(name: str) -> dict[str, Any]:
    from tests.conftest import T0

    arn = f"{RUNTIME_ARN}/runtime-endpoint/{name}"
    return {
        "name": name,
        "agentRuntimeEndpointArn": arn,
        "agentRuntimeArn": RUNTIME_ARN,
        "status": "READY",
        "id": name,
        "createdAt": T0,
        "lastUpdatedAt": T0,
    }


# --- release -----------------------------------------------------------------------------------------


def test_release_by_the_same_person_is_403(world):
    assert world.post("contain", claims=PAT)[0] == 200
    code, body = world.post("release", claims=PAT)
    assert code == 403 and "two-person rule (CON-03-N)" in body["detail"]
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    assert world.trail()[-1] == ("release", "result", "denied")


def test_release_deletes_the_policy_only_when_nothing_else_remains(world):
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.calls.clear()
    code, body = world.post("release", claims=PAT)
    assert code == 200
    assert (body["outcome"], body["changed"], body["state"], body["policy_deleted"]) == (
        "allowed",
        True,
        "not_contained",
        True,
    )
    assert RUNTIME_ARN not in world.cell.policies
    assert [c for c in world.cell.calls if c.endswith("resource_policy")] == [
        "get_resource_policy",
        "delete_resource_policy",
        "get_resource_policy",
    ]
    assert body["sessions"] is None and "stop_runtime_session" not in world.cell.calls
    result = world.dynamo.events()[-1]
    assert (result["action"], result["outcome"], result["status_before"], result["status_after"]) == (
        "release",
        "allowed",
        "contained",
        "not_contained",
    )
    # A release takes longer to apply everywhere than a contain, and the response says so.
    assert body["enforcement_delay_seconds"] == 300
    assert "some calls can still be refused for about 5 minutes" in body["reason"]


def test_release_keeps_the_other_statements(world):
    world.cell.policies[RUNTIME_ARN] = json.dumps({"Version": "2012-10-17", "Statement": OTHER_STATEMENTS})
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.calls.clear()
    code, body = world.post("release", claims=PAT)
    assert code == 200 and (body["policy_deleted"], body["other_statements_kept"]) == (False, 2)
    assert json.loads(world.cell.policies[RUNTIME_ARN]) == {"Version": "2012-10-17", "Statement": OTHER_STATEMENTS}
    assert "delete_resource_policy" not in world.cell.calls and "put_resource_policy" in world.cell.calls


def test_release_of_a_runtime_that_is_not_contained_changes_nothing(world):
    original = json.dumps({"Version": "2012-10-17", "Statement": OTHER_STATEMENTS})
    world.cell.policies[RUNTIME_ARN] = original
    code, body = world.post("release", claims=PAT)
    assert code == 200 and (body["outcome"], body["changed"], body["state"]) == ("unchanged", False, "not_contained")
    assert world.cell.policies[RUNTIME_ARN] == original
    assert not {"put_resource_policy", "delete_resource_policy"} & set(world.cell.calls)
    assert world.post("release", claims=PAT)[1]["outcome"] == "unchanged"  # with no policy at all, too


def test_release_authority(world):
    assert world.post("contain", claims=SRE)[0] == 200
    assert "CON-02-N" in world.post("release", claims=SRE)[1]["detail"]
    assert "CON-02-N" in world.post("release", claims=DEV)[1]["detail"]
    assert world.post("release", claims=SEC)[0] == 200
    # after a release nobody is "the container": the same person may release a later containment by someone else
    assert world.post("contain", claims=PAT)[0] == 200
    assert world.post("release", claims=SEC)[0] == 200


# --- failures half-way ---------------------------------------------------------------------------------


def test_nothing_is_done_when_the_intent_cannot_be_written(world):
    world.dynamo.fail_put_numbers = {1}
    code, body = world.post("contain")
    assert code == 503 and "not performed" in body["detail"]
    # The policy was read, which changes nothing; nothing was written, there or anywhere.
    assert world.cell.calls == ["get_resource_policy"] and world.cell.policies == {}
    assert world.dynamo.items == {}


def test_no_decision_when_the_trail_cannot_be_read(world):
    world.dynamo.fail_query = True
    code, body = world.post("release")
    assert code == 503 and "no decision" in body["detail"]
    assert world.cell.calls == []


def test_a_failed_write_of_the_deny_statement_says_nothing_was_changed(world):
    world.cell.fail["put_resource_policy"] = "AccessDeniedException"
    code, body = world.post("contain")
    assert (
        code == 502
        and body["detail"] == "The deny statement could not be written (AccessDeniedException). Nothing was changed."
    )
    assert world.cell.policies == {} and "start_query" not in world.cell.calls
    assert world.trail() == [("contain", "intent", "allowed"), ("contain", "result", "failed")]
    failed = world.dynamo.events()[-1]
    assert (failed["status_before"], failed["status_after"]) == ("not_contained", "not_contained")
    assert failed["reason"] == body["detail"] and body["request_id"] == failed["request_id"]


def test_a_statement_that_does_not_read_back_is_reported_and_sessions_are_left_alone(world):
    world.cell.lose_writes = True
    world.cell.sessions = [session_row(sid("aaa"))]
    code, body = world.post("contain")
    assert code == 502 and "was not found when the policy was read back" in body["detail"]
    assert "Sessions were not stopped" in body["detail"] and world.cell.stopped == []
    failed = world.dynamo.events()[-1]
    assert (failed["outcome"], failed["status_after"]) == ("failed", "unknown")


def test_an_unreadable_policy_stops_the_action_before_any_change(world):
    world.cell.fail["get_resource_policy"] = "ThrottlingException"
    code, body = world.post("contain")
    assert (
        code == 502
        and "Nothing was changed. The Runtime's resource policy could not be read (ThrottlingException)"
        in body["detail"]
    )
    assert "put_resource_policy" not in world.cell.calls
    world.cell.policies[RUNTIME_ARN] = "{not json"
    code, body = world.post("contain")
    assert code == 409 and "Nothing was changed" in body["detail"] and world.cell.policies[RUNTIME_ARN] == "{not json"
    code, body = world.post("release", claims=PAT)
    assert code == 409 and world.cell.policies[RUNTIME_ARN] == "{not json"


def test_the_containment_role_cannot_be_assumed(world):
    world.assumed.error = client_error("AccessDenied", "AssumeRole")
    code, body = world.post("contain")
    assert (
        code == 502 and "containment role could not be assumed (AccessDenied). Nothing was changed." in body["detail"]
    )
    assert world.trail()[-1] == ("contain", "result", "failed")


def test_containment_holds_even_when_sessions_cannot_be_listed(world):
    # neither source can be read: the spans query is refused and so is the log stream listing
    world.cell.fail["start_query"] = "AccessDeniedException"
    world.cell.streams[log_group()] = [session_stream("aaa")]
    world.cell.fail["describe_log_streams"] = "AccessDeniedException"
    code, body = world.post("contain")
    assert code == 200 and body["state"] == "contained" and body["changed"] is True
    assert body["sessions"]["found"] == 0 and world.cell.stopped == []
    assert body["sessions"]["discovery"] == (
        "sessions could not be listed (spans could not be queried (query could not start (AccessDeniedException)); "
        "log streams could not be listed (AccessDeniedException))"
    )
    assert body["partial"] is True and body["steps"][2]["status"] == "failed"
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    result = world.dynamo.events()[-1]
    assert result["outcome"] == "allowed" and "Running sessions were not stopped" in result["reason"]
    assert result["detail"] == body["sessions"]["discovery"]


def test_partial_session_stop_is_counted_and_recorded(world):
    world.cell.sessions = [
        session_row(sid("ok")),
        session_row(sid("gone")),
        session_row(sid("denied")),
        {"session_id": "bad id with spaces", "resource_id": ""},
    ]
    world.cell.stop_errors = {sid("gone"): "ResourceNotFoundException", sid("denied"): "AccessDeniedException"}
    code, body = world.post("contain")
    assert code == 200
    assert body["sessions"] == {
        "discovery": "ok",
        "sources": {"spans": 3, "log_streams": 0},
        "found": 3,
        "stopped": 1,
        "not_active": 1,
        "failed": 1,
        "not_attempted": 0,
        "stop_errors": ["AccessDeniedException"],
    }
    assert body["partial"] is True and body["steps"][2]["status"] == "partial"
    result = world.dynamo.events()[-1]
    assert (result["sessions_found"], result["sessions_stopped"], result["sessions_failed"]) == ("3", "1", "1")
    expected = (
        "1 of 3 recent session(s) stopped, 1 had already ended, 1 could not be stopped (AccessDeniedException) "
        "(found 3 in traces, 0 in logs)."
    )
    assert expected in result["reason"] and "discovery was incomplete" not in result["reason"]


def test_a_failed_release_says_the_runtime_is_still_contained(world):
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.fail["delete_resource_policy"] = "ThrottlingException"
    code, body = world.post("release", claims=PAT)
    assert code == 502 and body["detail"].endswith("The Runtime is still contained.")
    assert containment_policy.is_contained(world.cell.policies[RUNTIME_ARN], RUNTIME_ARN)
    failed = world.dynamo.events()[-1]
    assert (failed["outcome"], failed["status_before"], failed["status_after"]) == ("failed", "contained", "contained")
    # a failed release does not clear the container
    assert "CON-03-N" in world.post("release", claims=SEC)[1]["detail"]


def test_a_failed_result_write_is_reported(world):
    world.dynamo.fail_put_numbers = {2}
    code, body = world.post("contain")
    assert code == 200 and body["audit_complete"] is False and body["state"] == "contained"
    # the intent alone still names the container
    assert "CON-03-N" in world.post("release", claims=SEC)[1]["detail"]


# --- 401, 422, routing ---------------------------------------------------------------------------------------


def test_missing_claims_unmapped_identity_and_bad_bodies(world):
    assert world.post("contain", claims=None) == (401, {"detail": "Not authenticated"})
    assert world.post("contain", claims={"sub": "x", "cognito:groups": "[strangers]"})[0] == 403
    for bad in (
        {},
        {"reason": ""},
        {"reason": "r" * 1001},
        {"reason": "r", "extra": 1},
        {"reason": "r", "runtime_arn": "arn:bad"},
    ):
        assert world.post("contain", body=bad)[0] == 422
    assert world.dynamo.items == {} and world.cell.calls == []


def test_the_containment_function_serves_only_its_two_routes(world):
    def call(method: str, path: str) -> int:
        request = event(path, method, PAT)
        request["body"] = json.dumps({"reason": "r"})
        request["headers"]["content-type"] = "application/json"
        return world.handler(request, None)["statusCode"]

    for method, path in [
        ("GET", "/agents"),
        ("GET", f"/agents/{world.record_id}/containment"),
        ("POST", "/registrations"),
        ("POST", f"/registrations/{world.record_id}/approve"),
        ("POST", f"/registrations/{world.record_id}/submit"),
        ("DELETE", f"/registrations/{world.record_id}"),
        ("PUT", f"/agents/{world.record_id}/containment/contain"),
        ("POST", f"/agents/{world.record_id}/containment/destroy"),
    ]:
        assert call(method, path) == 404, (method, path)
    assert world.cell.calls == [] and world.dynamo.items == {}


@pytest.mark.parametrize("role_env", ["registrar", "approver", "", None])
def test_a_mis_wired_containment_function_answers_404(world, monkeypatch, role_env):
    if role_env is None:
        monkeypatch.delenv("PORTAL_ACTION_ROLE")
    else:
        monkeypatch.setenv("PORTAL_ACTION_ROLE", role_env)
    assert world.post("contain", claims=PAT) == (404, {"detail": "Not found"})
    assert world.cell.calls == []


@pytest.mark.parametrize("role", ["registrar", "approver"])
def test_other_action_functions_do_not_serve_containment(monkeypatch, role):
    monkeypatch.setenv("PORTAL_ACTION_ROLE", role)
    handler = Mangum(actions_app.create_action_app(role), lifespan="off")
    for action in ("contain", "release"):
        request = event(f"/agents/rec000000001/containment/{action}", "POST", PAT)
        request["body"] = json.dumps({"reason": "r"})
        assert handler(request, None)["statusCode"] == 404


def test_the_read_api_does_not_serve_the_containment_actions():
    handler = Mangum(create_app(), lifespan="off")
    for action in ("contain", "release"):
        assert handler(event(f"/agents/rec000000001/containment/{action}", "POST", PAT), None)["statusCode"] == 405


def test_containment_settings():
    env = {**BASE_ENV, "PORTAL_ACTION_ROLE": "containment"}
    settings = load_action_settings(env)
    assert settings.cells[0].containment_role_arn == CONTAINMENT_ROLE and settings.cells[1].containment_role_arn is None
    # The registrar and approver functions read the cells too: which tenant runs where.
    for role in ("registrar", "approver", "containment"):
        role_env = {**BASE_ENV, "PORTAL_ACTION_ROLE": role}
        assert [c.tenant_id for c in load_action_settings(role_env).cells] == ["ws1", "ws2"]
        with pytest.raises(ConfigError, match="PORTAL_CELLS"):
            load_action_settings({k: v for k, v in role_env.items() if k != "PORTAL_CELLS"})
    wrong = [{**CELLS[0], "containmentRoleArn": "arn:aws:iam::999999999999:role/elsewhere"}]
    with pytest.raises(ConfigError, match="containmentRoleArn"):
        load_action_settings({**env, "PORTAL_CELLS": json.dumps(wrong)})


# --- the read view -----------------------------------------------------------------------------------------------


@pytest.fixture
def read(world, monkeypatch):
    """The read API over the same cell, registry record and audit table as the containment function."""
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

    def get(agent_id: str, claims: dict | None = VIEW) -> tuple[int, Any]:
        response = handler(event(f"/agents/{agent_id}/containment", "GET", claims), None)
        return response["statusCode"], json.loads(response["body"])

    return get


def test_containment_view(world, read):
    code, view = read(world.record_id)
    assert code == 200
    assert (view["state"], view["enabled"], view["runtime_arn"], view["contained_by"], view["events"]) == (
        "not_contained",
        True,
        RUNTIME_ARN,
        None,
        [],
    )
    assert world.post("contain", claims=SEC)[0] == 200
    code, view = read(world.record_id, PAT)
    assert (view["state"], view["contained_by"], view["contained_by_label"], view["contained_by_me"]) == (
        "contained",
        "sec-1",
        "sec-1",
        False,
    )
    assert view["contained_at"] and view["reason"].startswith("Suspected prompt injection.")
    assert [(e["action"], e["phase"]) for e in view["events"]] == [("contain", "result"), ("contain", "intent")]
    assert read(world.record_id, SEC)[1]["contained_by_me"] is True
    assert world.post("release", claims=PAT)[0] == 200
    code, view = read(world.record_id, PAT)
    assert (view["state"], view["contained_by"], view["reason"]) == ("not_contained", None, None)
    assert [e["action"] for e in view["events"]][:2] == ["release", "release"]


@pytest.mark.parametrize("claims", [VIEW, DEV, ANN])
def test_the_incident_record_is_shown_only_to_roles_that_can_contain_or_release(world, read, claims):
    assert world.post("contain", claims=SEC)[0] == 200
    view = read(world.record_id, claims)[1]
    # What everyone may know: that it is contained, since when, and the delays.
    assert view["state"] == "contained" and view["contained_at"] and view["enabled"] is True
    assert view["contained_by_me"] is False and view["enforcement_delay_seconds"] == 90
    # Who contained it, why, and every attempt are an incident record.
    assert (view["contained_by"], view["contained_by_label"], view["reason"], view["events"]) == (None, None, None, [])
    for responder in (SEC, PAT, SRE):
        full = read(world.record_id, responder)[1]
        assert full["contained_by"] == "sec-1" and full["events"]


def test_containment_view_says_when_the_containment_was_partial(world, read):
    world.cell.fail["start_query"] = "AccessDeniedException"
    assert world.post("contain", claims=SEC)[1]["partial"] is True
    view = read(world.record_id)[1]  # partial is not part of the incident record: every role sees it
    assert (view["state"], view["partial"], view["enforcement_delay_seconds"]) == ("contained", True, 90)
    assert view["release_delay_seconds"] == 300
    events = read(world.record_id, PAT)[1]["events"]
    assert events[0]["detail"] == "ok; spans could not be queried (query could not start (AccessDeniedException))"
    assert world.post("release", claims=PAT)[0] == 200
    assert world.post("contain", claims=SEC)[1]["partial"] is False
    assert read(world.record_id)[1]["partial"] is False


def test_containment_view_unknown_and_missing(world, read, monkeypatch):
    world.cell.fail["get_resource_policy"] = "AccessDeniedException"
    assert read(world.record_id)[1]["state"] == "unknown"
    assert read("no-such-agent-1234567890")[0] == 404
    assert read(world.record_id, None)[0] == 401
    assert read(ORPHAN_ID)[1]["state"] == "not_contained"
    monkeypatch.delenv("PORTAL_AUDIT_TABLE")
    code, view = read(world.record_id)
    assert code == 200 and view["events"] == []


def test_the_delays_are_stated_in_words():
    from portal_api.containment_timing import CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS, delay_words

    assert (CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS) == (90, 300)
    assert delay_words(45) == "about 45 seconds"
    assert delay_words(90) == "about 90 seconds"
    assert delay_words(300) == "about 5 minutes"


# --- what an independent review found: each attack, and the request that must still work ---------------


def test_the_two_person_rule_follows_the_runtime_not_the_id_used(world):
    """Contain through the record id, then try to release through the Runtime's own id."""
    assert world.post("contain", claims=SEC)[0] == 200
    by_runtime_id = {"reason": "Release under another name.", "runtime_arn": RUNTIME_ARN}
    code, body = world.post("release", agent_id=RUNTIME_ID, claims=SEC, body=by_runtime_id)
    assert code == 403 and "CON-03-N" in body["detail"]
    assert RUNTIME_ARN in world.cell.policies  # still contained
    # One history for the Runtime, whatever id each request used.
    assert {e["pk"] for e in world.dynamo.events()} == {f"CONTAINMENT#{RUNTIME_ARN}"}
    # A different person may release it, under either id.
    assert world.post("release", agent_id=RUNTIME_ID, claims=PAT, body=by_runtime_id)[0] == 200
    assert RUNTIME_ARN not in world.cell.policies


def test_a_second_record_naming_the_same_runtime_shares_its_history(world):
    twin = world.registry.seed("agent-ws1-twin-nonprod", json.dumps(agent_document(agentId="twin")), "APPROVED")
    assert world.post("contain", claims=SEC)[0] == 200
    code, body = world.post("release", agent_id=twin, claims=SEC)
    assert code == 403 and "CON-03-N" in body["detail"]
    assert world.post("release", agent_id=twin, claims=PAT)[0] == 200


def test_a_registration_cannot_bring_another_tenants_runtime_into_reach(world):
    """A draft that claims tenant ws2 for a Runtime that runs in tenant ws1's account."""
    claimed = world.registry.seed(
        "agent-ws2-borrowed-nonprod", json.dumps(agent_document(tenantId="ws2", agentId="borrowed")), "DRAFT"
    )
    # A responder of ws2 does not hold the Runtime's real tenant, whatever the record says.
    code, body = world.post("contain", agent_id=claimed, claims=SRE2)
    assert code == 403 and "CON-04-N" in body["detail"]
    assert RUNTIME_ARN not in world.cell.policies and world.cell.calls == []
    # The refusal is not in the Runtime's history: this caller has no part in the Runtime.
    assert world.dynamo.events() == [] and world.dynamo.calls == []
    # A responder of the real tenant can act, through that record or through the genuine one.
    assert world.post("contain", agent_id=claimed, claims=SRE)[0] == 200
    # And the ws2 responder cannot lift a containment the real tenant placed.
    assert world.post("release", agent_id=claimed, claims={"sub": "sec-ws2", "cognito:groups": "[sre-team2]"})[0] == 403
    assert RUNTIME_ARN in world.cell.policies


def shared_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """The cell account hosts two tenants, ws1 and ws9."""
    shared = {**CELLS[0], "tenantId": "ws9", "agentId": "second-agent"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([CELLS[0], CELLS[1], shared]))


def test_in_a_shared_account_the_runtimes_own_tag_names_the_tenant(world, monkeypatch):
    shared_account(monkeypatch)
    # A Runtime tagged ws1 in an account of ws1 and ws9 is ws1's.
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws1", "agent-id": "travel-agent"}
    assert world.post("contain", claims=SRE)[0] == 200
    assert world.cell.calls.count("list_tags_for_resource") == 1
    assert [e["tenant_id"] for e in world.dynamo.events()] == ["ws1", "ws1"]
    # A responder of the other tenant does not hold it.
    code, body = world.post("release", claims={"sub": "sec-ws2", "cognito:groups": "[sre-team2]"})
    assert code == 403
    assert world.post("release", claims=PAT)[0] == 200

    # Tagged for the account's other tenant: ws1's responders do not hold it.
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws9"}
    recorded = len(world.dynamo.events())
    code, body = world.post("contain", claims=SRE)
    assert code == 403 and "CON-04-N" in body["detail"]
    assert len(world.dynamo.events()) == recorded  # not their Runtime, so not in its history
    assert RUNTIME_ARN not in world.cell.policies


@pytest.mark.parametrize("tags", [{}, {"tenant-id": "ws2"}, {"tenant-id": ""}, {"Tenant-Id": "ws1"}])
def test_in_a_shared_account_an_untagged_runtime_has_no_tenant(world, monkeypatch, tags):
    """No tag, or a tag naming a tenant the account does not host: undetermined, platform only."""
    shared_account(monkeypatch)
    world.cell.tags[RUNTIME_ARN] = tags
    for claims in (SRE, SEC, SRE2):
        code, body = world.post("contain", claims=claims)
        assert code == 403 and "CON-05-N" in body["detail"]
    assert RUNTIME_ARN not in world.cell.policies
    assert world.post("contain", claims=PAT)[0] == 200


def test_in_a_shared_account_a_registration_approved_or_not_changes_nothing(world, monkeypatch):
    shared_account(monkeypatch)
    # The seeded record is APPROVED for ws1, one of the account's tenants. The Runtime has no tag.
    code, body = world.post("contain", claims=SRE)
    assert code == 403 and "CON-05-N" in body["detail"]
    # An approved record that claims the account's other tenant decides nothing either.
    other = world.registry.seed(
        "agent-ws9-second-nonprod", json.dumps(agent_document(tenantId="ws9", agentId="second")), "APPROVED"
    )
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws1"}
    assert world.post("contain", agent_id=other, claims=SRE)[0] == 200  # the tag says ws1, whatever the record says
    assert world.dynamo.events()[-1]["tenant_id"] == "ws1"
    # Nor does a draft: with the tag gone the tenant is undetermined again.
    world.cell.tags.clear()
    draft = world.registry.seed("agent-ws1-draft-nonprod", json.dumps(agent_document(agentId="draft")), "DRAFT")
    code, body = world.post("release", agent_id=draft, claims=SEC)
    assert code == 403 and "CON-05-N" in body["detail"]
    # The same holds for an agent with no registration, addressed by its Runtime id.
    code, body = world.post(
        "release", agent_id=RUNTIME_ID, claims=SEC, body={"reason": "x", "runtime_arn": RUNTIME_ARN}
    )
    assert code == 403 and "CON-05-N" in body["detail"]
    assert RUNTIME_ARN in world.cell.policies


def test_in_a_shared_account_a_tag_that_cannot_be_read_leaves_the_tenant_undetermined(world, monkeypatch):
    shared_account(monkeypatch)
    world.cell.tags[RUNTIME_ARN] = {"tenant-id": "ws1"}
    world.cell.fail["list_tags_for_resource"] = "AccessDeniedException"
    code, body = world.post("contain", claims=SRE)
    assert code == 403 and "CON-05-N" in body["detail"]
    # The role could not be assumed at all: undetermined as well.
    world.assumed.error = client_error("AccessDenied", "AssumeRole")
    code, body = world.post("contain", claims=SRE)
    assert code == 403 and "CON-05-N" in body["detail"]
    world.assumed.error = None
    assert world.post("contain", claims=SRE)[0] == 200  # readable again


def test_the_tag_is_read_only_in_a_shared_account_and_only_after_the_role_check(world, monkeypatch):
    # One tenant in the account: nothing is read.
    assert world.post("contain", claims=SRE)[0] == 200
    assert "list_tags_for_resource" not in world.cell.calls
    # A shared account, and a caller without the role: refused before anything is looked up.
    shared_account(monkeypatch)
    world.cell.calls.clear()
    world.registry.calls.clear()
    assumed_before = list(world.cell.assumed)
    code, body = world.post("contain", claims=DEV)
    assert code == 403 and "CON-01-N" in body["detail"]
    assert world.cell.calls == [] and world.cell.assumed == assumed_before and world.registry.calls == []


def test_the_tag_request_matches_the_service_model():
    import boto3
    from botocore.stub import Stubber

    from portal_api.actions import containment

    client = boto3.client(
        "bedrock-agentcore-control", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test"
    )
    with Stubber(client) as stub:
        stub.add_response("list_tags_for_resource", {"tags": {"tenant-id": "ws1"}}, {"resourceArn": RUNTIME_ARN})
        stub.add_response("list_tags_for_resource", {"tags": {"agent-id": "x"}}, {"resourceArn": RUNTIME_ARN})
        stub.add_response("list_tags_for_resource", {}, {"resourceArn": RUNTIME_ARN})
        assert containment.get_tenant_tag(client, RUNTIME_ARN) == "ws1"
        assert containment.get_tenant_tag(client, RUNTIME_ARN) is None
        assert containment.get_tenant_tag(client, RUNTIME_ARN) is None
        stub.assert_no_pending_responses()


def test_a_contain_that_could_not_be_verified_still_has_a_holder(world):
    """The statement is written, the read-back fails: the same person must not be able to release."""
    original, calls = world.cell.get_resource_policy, {"n": 0}

    def fails_on_the_read_back(resourceArn: str) -> dict:  # noqa: N803
        calls["n"] += 1
        if calls["n"] == 2:
            raise client_error("ThrottlingException", "GetResourcePolicy")
        return original(resourceArn)

    world.monkeypatch.setattr(world.cell, "get_resource_policy", fails_on_the_read_back)
    code, body = world.post("contain", claims=SEC)
    assert code == 502 and RUNTIME_ARN in world.cell.policies  # written, not verified
    assert world.trail()[-1] == ("contain", "result", "failed")
    # A retry finds the statement and changes nothing; the first person is the holder all the same.
    assert world.post("contain", claims=SEC)[1]["outcome"] == "unchanged"
    code, body = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in body["detail"]
    assert world.post("release", claims=PAT)[0] == 200


def test_who_holds_a_containment():
    from portal_api.aws.audit import container
    from portal_api.models.portal import AuditEvent

    def event(n: int, who: str, action: str, outcome: str, phase: str = "result", **extra: str) -> AuditEvent:
        return AuditEvent(
            event_id=f"e{n}",
            request_id=extra.pop("request_id", f"r{n}"),
            at=f"2026-01-15T12:00:{n:02d}Z",
            phase=phase,
            action=action,
            outcome=outcome,
            reason="r",
            actor_subject=who,
            actor_label=who,
            actor_role="security",
            **extra,
        )

    def holder(*oldest_first: AuditEvent) -> str | None:
        found = container(list(reversed(oldest_first)))
        return found.actor_subject if found else None

    assert holder() is None
    assert holder(event(1, "ann", "contain", "allowed")) == "ann"
    assert holder(event(1, "ann", "contain", "allowed"), event(2, "bob", "release", "allowed")) is None
    # A repeated contain never replaces the holder ...
    assert holder(event(1, "ann", "contain", "allowed"), event(2, "bob", "contain", "unchanged")) == "ann"
    # ... but with nobody on record, the first person to assert the containment holds it.
    assert holder(event(1, "bob", "contain", "unchanged"), event(2, "cy", "contain", "unchanged")) == "bob"
    assert (
        holder(
            event(1, "ann", "contain", "allowed"),
            event(2, "bob", "release", "allowed"),
            event(3, "cy", "contain", "unchanged"),
        )
        == "cy"
    )
    # A contain that failed after the statement may have been written has a holder; one that wrote nothing has none.
    assert holder(event(1, "ann", "contain", "failed", status_after="unknown")) == "ann"
    assert holder(event(1, "ann", "contain", "failed", status_after="not_contained")) is None
    # Refusals never count, and an intent with no result counts as its result would have.
    assert holder(event(1, "ann", "contain", "allowed"), event(2, "ann", "release", "denied")) == "ann"
    assert holder(event(1, "ann", "contain", "allowed", phase="intent")) == "ann"
    assert (
        holder(
            event(1, "ann", "contain", "allowed", phase="intent", request_id="same"),
            event(2, "ann", "contain", "failed", request_id="same", status_after="not_contained"),
        )
        is None
    )


def test_spans_are_not_searched_unless_the_cell_opted_in(world, monkeypatch):
    without = {k: v for k, v in CELLS[0].items() if k != "containmentSpans"}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([without, CELLS[1]]))
    world.cell.sessions = [session_row(sid("only-in-spans"))]
    world.cell.streams[log_group()] = [session_stream("in-logs")]
    code, body = world.post("contain")
    assert code == 200 and body["partial"] is False
    # No Logs Insights call at all: the cell's role does not need, and does not get, a query permission.
    assert "start_query" not in world.cell.calls and "get_query_results" not in world.cell.calls
    assert body["sessions"]["sources"] == {"log_streams": 1} and body["sessions"]["discovery"] == "ok"
    assert world.cell.stopped == [(sid("in-logs"), "DEFAULT")]
    assert "(found 1 in logs)" in body["steps"][2]["detail"] and "traces" not in body["steps"][2]["detail"]


def test_the_spans_option_needs_a_containment_role():
    cells = [{**{k: v for k, v in CELLS[0].items() if k != "containmentRoleArn"}}, CELLS[1]]
    with pytest.raises(ConfigError, match="containmentSpans needs containmentRoleArn"):
        load_action_settings({**BASE_ENV, "PORTAL_ACTION_ROLE": "containment", "PORTAL_CELLS": json.dumps(cells)})
    not_a_flag = [{**CELLS[0], "containmentSpans": "yes"}, CELLS[1]]
    with pytest.raises(ConfigError, match="containmentSpans must be true or false"):
        load_action_settings({**BASE_ENV, "PORTAL_ACTION_ROLE": "containment", "PORTAL_CELLS": json.dumps(not_a_flag)})
