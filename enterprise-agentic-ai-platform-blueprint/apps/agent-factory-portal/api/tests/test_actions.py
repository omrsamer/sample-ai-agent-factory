# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Registrar and approver functions through their Lambda handlers, with an in-memory registry and audit table."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mangum import Mangum

from portal_api import deps, registrations
from portal_api.actions import app as actions_app
from portal_api.actions import authority
from portal_api.app import create_app
from portal_api.aws import audit as audit_reader
from portal_api.config import ConfigError, get_settings, load_action_settings
from portal_api.identity.provider import Principal
from portal_api.models.portal import AuditEvent
from tests.conftest import BASE_ENV, FakeClients, make_service
from tests.fakes import FakeDynamo, FakeRegistry
from tests.test_api import event

DEV = {"sub": "dev-1", "email": "dev@example.com", "cognito:groups": "[devs]"}  # developer, tenant ws1
DEV2 = {"sub": "dev-2", "email": "dev2@example.com", "cognito:groups": "[devs2]"}  # developer, tenant ws2
ANN = {"sub": "ann-1", "name": "Ann Approver", "cognito:groups": "[approvers]"}  # approver, tenant ws1
ANN2 = {"sub": "ann-2", "cognito:groups": "[approvers2]"}  # approver, tenant ws2
SEC = {"sub": "sec-1", "cognito:groups": "[sec]"}  # security, tenants ws1 and ws2
PAT = {"sub": "pat-1", "email": "pat@example.com", "cognito:groups": "[platform-admins]"}  # platform, every tenant
VIEW = {"sub": "view-1", "cognito:groups": "[viewers]"}

BODY = {
    "tenant_id": "ws1",
    "agent_id": "travel-agent",
    "environment": "nonprod",
    "owner_group": "travel-owners",
    "business_purpose": "Plans trips for employees.",
    "risk_class": "limited",
    "data_classification": "internal",
    "cost_centre": "cc-100",
    "runtime_arn": "arn:aws:bedrock-agentcore:eu-west-1:444444444444:runtime/travel_agent-AbCdEf1234",
    "subscribed_tool_ids": ["tool-ping", "tool-echo"],
}


class World:
    """The three functions wired to one fake registry and one fake audit table."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.monkeypatch = monkeypatch
        monkeypatch.setattr("portal_api.actions.registrar.time.sleep", lambda seconds: None)
        self.registry = FakeRegistry()
        self.dynamo = FakeDynamo()
        self.handlers: dict[str, Any] = {}
        for role in ("registrar", "approver"):
            application = actions_app.create_action_app(role)
            application.dependency_overrides[actions_app.registry_client] = lambda: self.registry
            application.dependency_overrides[actions_app.dynamodb_client] = lambda: self.dynamo
            self.handlers[role] = Mangum(application, lifespan="off")
        read = create_app()
        clients = FakeClients(
            {("platform", "agent-registry-control"): self.registry, ("platform", "dynamodb"): self.dynamo}
        )
        read.dependency_overrides[deps.get_service] = lambda: make_service(get_settings(), clients)
        self.handlers["read"] = Mangum(read, lifespan="off")

    def call(
        self,
        function: str,
        method: str,
        path: str,
        claims: dict | None = None,
        body: Any = None,
        role_env: str | None = "match",
    ) -> tuple[int, Any]:
        if role_env == "match":
            role_env = function if function != "read" else None
        if role_env is None:
            self.monkeypatch.delenv("PORTAL_ACTION_ROLE", raising=False)
        else:
            self.monkeypatch.setenv("PORTAL_ACTION_ROLE", role_env)
        request = event(path, method, claims)
        if body is not None:
            request["body"] = body if isinstance(body, str) else json.dumps(body)
            request["headers"]["content-type"] = "application/json"
        response = self.handlers[function](request, None)
        try:
            return response["statusCode"], json.loads(response["body"])
        except ValueError:
            return response["statusCode"], response["body"]

    # shortcuts
    def create(self, claims: dict = DEV, **changes: Any) -> tuple[int, Any]:
        return self.call("registrar", "POST", "/registrations", claims, {**BODY, **changes})

    def update(self, record_id: str, claims: dict = DEV, **changes: Any) -> tuple[int, Any]:
        return self.call("registrar", "PUT", f"/registrations/{record_id}", claims, {**BODY, **changes})

    def submit(self, record_id: str, claims: dict = DEV) -> tuple[int, Any]:
        return self.call("registrar", "POST", f"/registrations/{record_id}/submit", claims)

    def delete(self, record_id: str, claims: dict = DEV) -> tuple[int, Any]:
        return self.call("registrar", "DELETE", f"/registrations/{record_id}", claims)

    def decide(self, action: str, record_id: str, claims: dict = ANN, reason: Any = "Reviewed and fine.", **extra: Any):
        return self.call(
            "approver", "POST", f"/registrations/{record_id}/{action}", claims, {"reason": reason, **extra}
        )

    def new_record(self, status: str = "DRAFT") -> str:
        code, body = self.create()
        assert code == 201, body
        record_id = body["registration"]["record_id"]
        if status in ("PENDING_APPROVAL", "APPROVED", "REJECTED"):
            assert self.submit(record_id)[0] == 200
        if status == "APPROVED":
            assert self.decide("approve", record_id)[0] == 200
        if status == "REJECTED":
            assert self.decide("reject", record_id)[0] == 200
        return record_id

    def status(self, record_id: str) -> str:
        return self.registry.records[record_id]["status"]

    def trail(self) -> list[tuple[str, str, str]]:
        return [(e["action"], e["phase"], e["outcome"]) for e in self.dynamo.events()]


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return World(monkeypatch)


# --- create ---------------------------------------------------------------------------


def test_create_makes_a_draft_record_in_the_publisher_shape(world):
    code, body = world.create()
    assert code == 201
    registration = body["registration"]
    assert (body["action"], body["outcome"], body["audit_complete"]) == ("create", "allowed", True)
    assert "REG-07-P" in body["reason"]
    assert (registration["name"], registration["status"], registration["record_version"]) == (
        "agent-ws1-travel-agent-nonprod",
        "DRAFT",
        "1.0.0",
    )
    assert registration["document"]["subscribed_tool_ids"] == ["tool-echo", "tool-ping"]
    assert registration["document"]["schema_version"] == "agenticai.agent-governance/1.0"
    args = world.registry.records[registration["record_id"]]["createArgs"]
    document = json.loads(args["descriptors"]["custom"]["data"])
    assert args["recordType"] == "CUSTOM" and args["name"] == args["displayName"] == "agent-ws1-travel-agent-nonprod"
    assert args["description"] == "Agent travel-agent of ws1 (nonprod)"
    assert args["descriptors"]["custom"]["data"] == json.dumps(document, sort_keys=True, separators=(",", ":"))
    assert document["schemaVersion"] == "agenticai.agent-governance/1.0" and document["recordVersion"] == "1.0.0"
    assert registration["document_sha256"] == registrations.sha256(args["descriptors"]["custom"]["data"])
    assert world.trail() == [("create", "intent", "allowed"), ("create", "result", "allowed")]


def test_create_accepts_a_caller_supplied_version(world):
    assert world.create(record_version="2.3.0")[1]["registration"]["record_version"] == "2.3.0"


def test_create_refuses_a_duplicate_name_with_409(world):
    world.new_record()
    code, body = world.create()
    assert code == 409 and "already exists" in body["detail"]
    assert len(world.registry.records) == 1
    assert world.trail()[-1] == ("create", "result", "denied")


@pytest.mark.parametrize(
    ("claims", "tenant", "reason"),
    [
        (VIEW, "ws1", "REG-07-N"),
        (ANN, "ws1", "REG-07-N"),
        (SEC, "ws1", "REG-07-N"),
        (DEV, "ws2", "own tenant"),
        (DEV2, "ws1", "own tenant"),
    ],
)
def test_create_without_authority_or_tenant_is_403_and_audited(world, claims, tenant, reason):
    code, body = world.create(claims, tenant_id=tenant)
    assert code == 403 and reason in body["detail"]
    assert world.registry.records == {}
    assert world.trail() == [("create", "result", "denied")]
    denied = world.dynamo.events()[0]
    assert denied["pk"] == f"RECORD#NAME#agent-{tenant}-travel-agent-nonprod"
    assert denied["actor_subject"] == claims["sub"] and denied["tenant_id"] == tenant


def test_platform_role_is_registrar_for_every_tenant(world):
    assert world.create(PAT, tenant_id="ws2")[0] == 201
    assert world.create(PAT, tenant_id="ws9", agent_id="other")[0] == 201


@pytest.mark.parametrize(
    "changes",
    [
        {"risk_class": "extreme"},
        {"tenant_id": "Bad Tenant"},
        {"runtime_arn": "not-an-arn"},
        {"subscribed_tool_ids": ["Tool One"]},
        {"record_version": "one"},
        {"unknown_field": "x"},
        {"business_purpose": ""},
        {"golden_path": {"name": "only-name"}},
        {"evaluation": {"verdict": "maybe"}},
        {"owner_group": None},
    ],
)
def test_create_with_an_invalid_body_is_422_and_nothing_is_written(world, changes):
    code, _ = world.create(**changes)
    assert code == 422
    assert world.registry.records == {} and world.dynamo.items == {}


@pytest.mark.parametrize(
    ("changes", "loc", "message"),
    [
        (
            {"risk_class": "extreme"},
            ["body", "risk_class"],
            "risk_class must be one of minimal, limited, high, unacceptable",
        ),
        (
            {"business_purpose": "p" * 2001},
            ["body", "business_purpose"],
            "business_purpose is longer than 2000 characters",
        ),
        (
            {"subscribed_tool_ids": ["ok", "Not Ok"]},
            ["body", "subscribed_tool_ids"],
            "subscribed_tool_ids does not match",
        ),
        ({"evaluation": {"verdict": "maybe"}}, ["body", "evaluation", "verdict"], "evaluation.verdict must be one of"),
        (
            {"golden_path": {"name": "", "version": "1"}},
            ["body", "golden_path", "name"],
            "golden_path.name is too short",
        ),
        ({"record_version": "one"}, ["body", "record_version"], "record_version must be a semantic version"),
    ],
)
def test_document_errors_name_the_request_field(world, changes, loc, message):
    code, body = world.create(**changes)
    assert code == 422
    (error,) = body["detail"]
    assert error["loc"] == loc and error["msg"].startswith(message) and error["type"] == "document"


def test_type_errors_use_the_same_list_form(world):
    code, body = world.create(owner_group=None, unknown_field="x")
    assert code == 422
    assert {tuple(e["loc"]) for e in body["detail"]} == {("body", "owner_group"), ("body", "unknown_field")}
    assert all(set(e) == {"loc", "msg", "type"} for e in body["detail"])


def test_malformed_json_body_is_422(world):
    assert world.call("registrar", "POST", "/registrations", DEV, "{not json")[0] == 422


# --- update ---------------------------------------------------------------------------


def test_update_bumps_the_patch_version_and_wraps_optional_values(world):
    record_id = world.new_record()
    code, body = world.update(record_id, business_purpose="Plans trips and events.")
    assert code == 200
    assert (body["registration"]["status"], body["registration"]["record_version"]) == ("DRAFT", "1.0.1")
    assert body["registration"]["document"]["business_purpose"] == "Plans trips and events."
    assert json.loads(world.registry.records[record_id]["descriptors"]["custom"]["data"])["recordVersion"] == "1.0.1"
    assert world.trail()[-2:] == [("update", "intent", "allowed"), ("update", "result", "allowed")]


def test_update_version_rules(world):
    record_id = world.new_record()
    assert (
        world.update(record_id, contact="a@example.com", record_version="1.4.0")[1]["registration"]["record_version"]
        == "1.4.0"
    )
    assert world.update(record_id, contact="b@example.com", record_version="1.4.0")[0] == 422  # not higher
    assert world.update(record_id, contact="b@example.com", record_version="1.3.9")[0] == 422
    assert world.update(record_id, contact="b@example.com")[1]["registration"]["record_version"] == "1.4.1"


@pytest.mark.parametrize("field", ["tenant_id", "agent_id", "environment"])
def test_update_cannot_change_the_record_identity(world, field):
    record_id = world.new_record()
    value = {"tenant_id": "ws1x", "agent_id": "other-agent", "environment": "prod"}[field]
    code, body = world.update(record_id, PAT, **{field: value})
    assert code == 422
    assert body["detail"] == [
        {"loc": ["body", field], "msg": f"{field} cannot be changed; register a new record instead", "type": "document"}
    ]


def test_update_that_changes_nothing_is_409(world):
    record_id = world.new_record("APPROVED")
    code, body = world.update(record_id)
    assert code == 409 and "already holds" in body["detail"]
    assert world.status(record_id) == "APPROVED"


@pytest.mark.parametrize(
    "changes",
    [
        {"risk_class": "high"},
        {"data_classification": "restricted"},
        {"runtime_arn": "arn:aws:bedrock-agentcore:eu-west-1:444444444444:runtime/other_agent-ZyXwVu9876"},
        {"gateway_arn": "arn:aws:bedrock-agentcore:eu-west-1:444444444444:gateway/ws1-tools-abcdefghij"},
        {"subscribed_tool_ids": ["tool-echo"]},
        {"subscribed_tool_ids": None},
    ],
)
def test_update_of_an_approved_reference_is_403_reg_12(world, changes):
    record_id = world.new_record("APPROVED")
    code, body = world.update(record_id, **changes)
    assert code == 403 and "REG-12-N" in body["detail"]
    assert "Register a new record" in body["hint"]
    assert world.status(record_id) == "APPROVED"
    assert world.trail()[-1] == ("update", "result", "denied")


def test_other_update_of_an_approved_record_is_allowed_and_returns_it_to_draft(world):
    record_id = world.new_record("APPROVED")
    code, body = world.update(
        record_id, business_purpose="Reworded purpose.", subscribed_tool_ids=["tool-echo", "tool-ping"]
    )
    assert code == 200 and body["registration"]["status"] == "DRAFT"


def test_reference_change_is_allowed_while_not_approved(world):
    for status in ("DRAFT", "PENDING_APPROVAL", "REJECTED"):
        world.registry.records.clear()
        record_id = world.new_record(status)
        assert world.update(record_id, risk_class="high")[0] == 200, status
        assert world.status(record_id) == "DRAFT"


def test_update_authorization(world):
    record_id = world.new_record()
    assert "cross-tenant update is denied" in world.update(record_id, DEV2)[1]["detail"]
    assert "REG-08-N" in world.update(record_id, ANN)[1]["detail"]
    assert "REG-08-N" in world.update(record_id, VIEW)[1]["detail"]
    assert world.update(record_id, PAT, contact="x@example.com")[0] == 200


def test_update_of_a_deprecated_record_is_409(world):
    record_id = world.new_record()
    world.registry.records[record_id]["status"] = "DEPRECATED"
    code, body = world.update(record_id, contact="x@example.com")
    assert code == 409 and "DEPRECATED" in body["detail"]


# --- submit and delete ----------------------------------------------------------------


def test_submit_moves_a_draft_to_pending_approval(world):
    record_id = world.new_record()
    code, body = world.submit(record_id)
    assert code == 200 and body["registration"]["status"] == "PENDING_APPROVAL"
    assert world.trail()[-2:] == [("submit", "intent", "allowed"), ("submit", "result", "allowed")]


@pytest.mark.parametrize(
    ("status", "message"),
    [
        ("PENDING_APPROVAL", "already submitted"),
        ("REJECTED", "must be updated"),
        ("APPROVED", "cannot be submitted"),
        ("DEPRECATED", "cannot be submitted"),
    ],
)
def test_submit_in_a_state_that_does_not_permit_it_is_409(world, status, message):
    record_id = world.new_record()
    world.registry.records[record_id]["status"] = status
    code, body = world.submit(record_id)
    assert code == 409 and message in body["detail"]
    assert world.trail()[-1] == ("submit", "result", "denied")


def test_submit_authorization(world):
    record_id = world.new_record()
    assert world.submit(record_id, DEV2)[0] == 403
    assert "REG-08-N" in world.submit(record_id, ANN)[1]["detail"]
    assert world.status(record_id) == "DRAFT"


@pytest.mark.parametrize("status", ["DRAFT", "PENDING_APPROVAL", "REJECTED", "DEPRECATED"])
def test_delete_of_a_record_that_is_not_approved(world, status):
    record_id = world.new_record()
    world.registry.records[record_id]["status"] = status
    code, body = world.delete(record_id)
    assert code == 200 and body["registration"] is None and body["action"] == "delete"
    assert record_id not in world.registry.records
    assert world.dynamo.events()[-1]["status_after"] == "DELETED"


def test_delete_of_an_approved_record_is_409(world):
    record_id = world.new_record("APPROVED")
    code, body = world.delete(record_id)
    assert code == 409 and "approved record cannot be deleted" in body["detail"]
    assert record_id in world.registry.records


def test_delete_authorization(world):
    record_id = world.new_record()
    assert "cross-tenant delete is denied" in world.delete(record_id, DEV2)[1]["detail"]
    assert "REG-10-N" in world.delete(record_id, SEC)[1]["detail"]
    assert record_id in world.registry.records


# --- approve and reject -----------------------------------------------------------------


@pytest.mark.parametrize(("action", "status"), [("approve", "APPROVED"), ("reject", "REJECTED")])
@pytest.mark.parametrize("claims", [ANN, SEC, PAT])
def test_a_separate_approver_decides_a_pending_record(world, action, status, claims):
    record_id = world.new_record("PENDING_APPROVAL")
    code, body = world.decide(action, record_id, claims, "Checked the owner and the tools.")
    assert code == 200
    assert (body["registration"]["status"], body["registration"]["status_reason"]) == (
        status,
        "Checked the owner and the tools.",
    )
    assert body["reason"] == "Checked the owner and the tools."
    intent, result = world.dynamo.events()[-2:]
    assert (intent["phase"], intent["reason"]) == (
        "intent",
        "separate approver approves the submitted record (REG-11-P)",
    )
    assert (result["phase"], result["reason"], result["status_before"], result["status_after"]) == (
        "result",
        "Checked the owner and the tools.",
        "PENDING_APPROVAL",
        status,
    )
    assert result["actor_subject"] == claims["sub"] and result["action"] == action


@pytest.mark.parametrize("action", ["approve", "reject"])
def test_the_submitter_cannot_decide_its_own_record(world, action):
    code, body = world.create(PAT)
    record_id = body["registration"]["record_id"]
    assert world.submit(record_id, PAT)[0] == 200
    code, body = world.decide(action, record_id, PAT)
    assert code == 403 and "REG-11-N" in body["detail"]
    assert world.status(record_id) == "PENDING_APPROVAL"
    assert world.decide(action, record_id, ANN)[0] == 200


def test_the_submitter_is_the_latest_allowed_submit(world):
    record_id = world.new_record("PENDING_APPROVAL")  # submitted by the developer
    assert world.update(record_id, contact="x@example.com")[0] == 200  # back to DRAFT
    assert world.submit(record_id, PAT)[0] == 200  # now submitted by the platform user
    assert "REG-11-N" in world.decide("approve", record_id, PAT)[1]["detail"]


def test_a_denied_submit_does_not_make_someone_the_submitter(world):
    record_id = world.new_record("PENDING_APPROVAL")
    assert world.submit(record_id, PAT)[0] == 409  # already submitted: denied, so the developer stays the submitter
    assert world.decide("approve", record_id, PAT)[0] == 200


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        (DEV, "REG-09-N"),
        (VIEW, "REG-09-N"),
        (ANN2, "cross-tenant approve is denied"),
    ],
)
def test_decision_without_authority_or_tenant_is_403(world, claims, reason):
    record_id = world.new_record("PENDING_APPROVAL")
    for action in ("approve", "reject"):
        code, body = world.decide(action, record_id, claims)
        assert code == 403 and reason in body["detail"]
    assert world.status(record_id) == "PENDING_APPROVAL"


@pytest.mark.parametrize("status", ["DRAFT", "APPROVED", "REJECTED", "DEPRECATED"])
def test_decision_on_a_record_that_is_not_pending_is_409(world, status):
    record_id = world.new_record()
    world.registry.records[record_id]["status"] = status
    for action in ("approve", "reject"):
        code, body = world.decide(action, record_id)
        assert code == 409 and "pending approval" in body["detail"]
    assert world.status(record_id) == status


@pytest.mark.parametrize("reason", ["", None, "x" * 1001, 5])
def test_decision_reason_is_required_and_bounded(world, reason):
    record_id = world.new_record("PENDING_APPROVAL")
    assert world.decide("approve", record_id, ANN, reason)[0] == 422
    assert world.call("approver", "POST", f"/registrations/{record_id}/approve", ANN, {})[0] == 422
    assert world.status(record_id) == "PENDING_APPROVAL"


def test_a_long_reason_is_kept_in_full_in_the_audit_trail_and_cut_for_the_registry(world):
    record_id = world.new_record("PENDING_APPROVAL")
    reason = "r" * 1000
    assert world.decide("approve", record_id, ANN, reason)[0] == 200
    assert len(world.registry.records[record_id]["statusReason"]) == 255
    assert world.dynamo.events()[-1]["reason"] == reason


def test_decision_can_be_pinned_to_the_document_that_was_reviewed(world):
    record_id = world.new_record("PENDING_APPROVAL")
    code, body = world.decide("approve", record_id, ANN, document_sha256="0" * 64)
    assert code == 409 and "changed since it was read" in body["detail"]
    current = world.call("read", "GET", "/registrations", VIEW)[1][0]["document_sha256"]
    assert world.decide("approve", record_id, ANN, document_sha256=current)[0] == 200


# --- audit trail ------------------------------------------------------------------------


def test_every_event_carries_the_agreed_fields_and_keys(world):
    record_id = world.new_record("APPROVED")
    events = world.dynamo.events()
    assert [(e["action"], e["phase"]) for e in events] == [
        ("create", "intent"),
        ("create", "result"),
        ("submit", "intent"),
        ("submit", "result"),
        ("approve", "intent"),
        ("approve", "result"),
    ]
    assert events[0]["pk"] == "RECORD#NAME#agent-ws1-travel-agent-nonprod"
    for item in events[1:]:
        assert item["pk"] == f"RECORD#{record_id}"
    for item in events:
        assert item["sk"] == f"EVENT#{item['at']}#{item['event_id']}"
        assert item["at"].endswith("Z") and "T" in item["at"]
        for field in (
            "action",
            "outcome",
            "reason",
            "actor_subject",
            "actor_label",
            "actor_role",
            "tenant_id",
            "record_name",
            "document_sha256",
            "request_id",
            "phase",
        ):
            assert item[field], field
    assert [e.get("status_before") for e in events[2:]] == ["DRAFT", "DRAFT", "PENDING_APPROVAL", "PENDING_APPROVAL"]
    assert [e.get("status_after") for e in events] == [None, "DRAFT", None, "PENDING_APPROVAL", None, "APPROVED"]
    assert events[2]["request_id"] == events[3]["request_id"] != events[4]["request_id"]
    assert (events[5]["actor_label"], events[5]["actor_role"]) == ("Ann Approver", "approver")
    assert events[1]["actor_label"] == "dev@example.com"
    assert set(world.dynamo.calls) <= {"put_item", "query"}


def test_no_action_is_performed_when_the_intent_cannot_be_written(world):
    world.dynamo.fail_put_numbers = {1}
    code, body = world.create()
    assert code == 503 and "not performed" in body["detail"]
    assert world.registry.records == {} and "create_registry_record" not in world.registry.calls

    record_id = world.new_record("PENDING_APPROVAL")
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 1}
    assert world.decide("approve", record_id)[0] == 503
    assert world.status(record_id) == "PENDING_APPROVAL"
    assert "update_registry_record_status" not in world.registry.calls


def test_a_failed_result_write_leaves_the_action_done_and_says_so(world):
    record_id = world.new_record()
    world.dynamo.fail_put_numbers = {world.dynamo._puts + 2}  # the intent succeeds, the result fails
    code, body = world.submit(record_id)
    assert code == 200 and body["audit_complete"] is False
    assert world.status(record_id) == "PENDING_APPROVAL"
    assert world.trail()[-1] == ("submit", "intent", "allowed")
    # The intent alone still names the submitter, so the gap cannot be used to approve one's own record.
    world.registry.records[record_id]["status"] = "DRAFT"
    assert world.submit(record_id, PAT)[0] == 200
    world.dynamo.items = {
        k: v for k, v in world.dynamo.items.items() if v["phase"]["S"] != "result" or v["action"]["S"] != "submit"
    }
    assert "REG-11-N" in world.decide("approve", record_id, PAT)[1]["detail"]


def test_a_registry_refusal_is_recorded_as_failed(world):
    record_id = world.new_record()
    world.registry.fail["submit_registry_record_for_approval"] = "ConflictException"
    code, body = world.submit(record_id)
    assert code == 409 and "refused" in body["detail"]
    assert world.trail()[-2:] == [("submit", "intent", "allowed"), ("submit", "result", "failed")]
    assert world.dynamo.events()[-1]["reason"] == "The registry refused (ConflictException)"
    world.registry.fail["delete_registry_record"] = "ThrottlingException"
    code, body = world.delete(record_id)
    assert (code, body["detail"]) == (502, "An AWS service call failed (ThrottlingException)")


def test_a_failed_submit_does_not_name_a_submitter(world):
    record_id = world.new_record()
    world.registry.fail["submit_registry_record_for_approval"] = "ConflictException"
    assert world.submit(record_id, PAT)[0] == 409
    assert world.submit(record_id, DEV)[0] == 200
    assert world.decide("approve", record_id, PAT)[0] == 200


def test_decision_fails_closed_when_the_trail_cannot_be_read(world):
    record_id = world.new_record("PENDING_APPROVAL")
    world.dynamo.fail_query = True
    code, body = world.decide("approve", record_id)
    assert code == 503 and "no decision" in body["detail"]
    assert world.status(record_id) == "PENDING_APPROVAL"


def test_submitter_helper():
    def make(action, phase, outcome, request_id, subject, at):
        return AuditEvent(
            event_id=at,
            request_id=request_id,
            at=at,
            phase=phase,
            action=action,
            outcome=outcome,
            reason="r",
            actor_subject=subject,
            actor_label=subject,
            actor_role="developer",
        )

    newest_first = [
        make("submit", "result", "denied", "r4", "dora", "4"),
        make("submit", "result", "failed", "r3", "carl", "3b"),
        make("submit", "intent", "allowed", "r3", "carl", "3a"),
        make("update", "result", "allowed", "r2", "bea", "2"),
        make("submit", "result", "allowed", "r1", "alex", "1b"),
        make("submit", "intent", "allowed", "r1", "alex", "1a"),
    ]
    assert audit_reader.submitter(newest_first).actor_subject == "alex"
    assert (
        audit_reader.submitter([make("submit", "intent", "allowed", "r9", "erin", "9"), *newest_first]).actor_subject
        == "erin"
    )
    assert audit_reader.submitter([]) is None


# --- records the portal must not touch, and missing records ---------------------------------


def test_a_record_that_is_not_an_agent_governance_record_is_never_touched(world):
    tool = world.registry.seed(
        "tool-echo", json.dumps({"schemaVersion": "agenticai.tool-governance/1.0"}), "PENDING_APPROVAL"
    )
    other = world.registry.seed("free-form", "not json", "DRAFT")
    for record_id in (tool, other):
        assert world.update(record_id, PAT)[0] == 404
        assert world.submit(record_id, PAT)[0] == 404
        assert world.delete(record_id, PAT)[0] == 404
        assert world.decide("approve", record_id, PAT)[0] == 404
        assert world.decide("reject", record_id, PAT)[0] == 404
    assert world.registry.records[tool]["status"] == "PENDING_APPROVAL" and other in world.registry.records
    assert world.dynamo.items == {}
    assert not set(world.registry.calls) - {"get_registry_record"}


def test_a_missing_record_is_404_for_a_caller_with_authority(world):
    missing = "rec999999999"
    assert world.update(missing)[0] == 404
    assert world.submit(missing)[0] == 404
    assert world.delete(missing)[0] == 404
    assert world.decide("approve", missing)[0] == 404


def test_a_caller_without_authority_is_refused_before_the_record_is_read(world):
    missing = "rec999999999"
    assert world.submit(missing, VIEW)[0] == 403
    assert world.delete(missing, ANN)[0] == 403
    assert world.decide("approve", missing, DEV)[0] == 403
    assert world.registry.calls == []
    assert [e["pk"] for e in world.dynamo.events()] == [f"RECORD#{missing}"] * 3


@pytest.mark.parametrize("record_id", ["short", "rec-00000001", "rec0000000001", "a%20b"])
def test_malformed_record_id_is_422(world, record_id):
    assert world.submit(record_id)[0] == 422
    assert world.decide("approve", record_id)[0] == 422


# --- 401 and routing isolation -----------------------------------------------------------------


ROUTES = {
    "registrar": [
        ("POST", "/registrations"),
        ("PUT", "/registrations/rec000000001"),
        ("POST", "/registrations/rec000000001/submit"),
        ("DELETE", "/registrations/rec000000001"),
    ],
    "approver": [("POST", "/registrations/rec000000001/approve"), ("POST", "/registrations/rec000000001/reject")],
    "read": [
        ("GET", "/registrations"),
        ("GET", "/registrations/rec000000001"),
        ("GET", "/registrations/rec000000001/history"),
        ("GET", "/agents"),
    ],
}


@pytest.mark.parametrize("function", ["registrar", "approver"])
def test_missing_claims_are_401(world, function):
    for method, path in ROUTES[function]:
        code, body = world.call(function, method, path, None, {**BODY, "reason": "x"})
        assert (code, body) == (401, {"detail": "Not authenticated"}), path
    assert world.dynamo.items == {} and world.registry.calls == []


@pytest.mark.parametrize("function", ["registrar", "approver"])
def test_a_token_without_a_mapped_group_is_403(world, function):
    for method, path in ROUTES[function]:
        code, _ = world.call(
            function, method, path, {"sub": "x", "cognito:groups": "[strangers]"}, {**BODY, "reason": "x"}
        )
        assert code == 403, path


@pytest.mark.parametrize(
    ("function", "other"),
    [("registrar", "approver"), ("registrar", "read"), ("approver", "registrar"), ("approver", "read")],
)
def test_an_action_function_answers_404_for_routes_of_the_other_functions(world, function, other):
    for method, path in ROUTES[other]:
        code, body = world.call(function, method, path, PAT, {**BODY, "reason": "x"})
        assert (code, body) == (404, {"detail": "Not found"}), (method, path)
    assert world.registry.calls == [] and world.dynamo.items == {}


@pytest.mark.parametrize("function", ["registrar", "approver"])
@pytest.mark.parametrize("role_env", ["registrar", "approver", None, "", "admin"])
def test_a_mis_wired_function_answers_404_for_everything(world, function, role_env):
    if role_env == function:
        pytest.skip("correctly wired")
    for method, path in ROUTES[function]:
        code, body = world.call(function, method, path, PAT, {**BODY, "reason": "x"}, role_env=role_env)
        assert (code, body) == (404, {"detail": "Not found"})
    assert world.registry.calls == [] and world.dynamo.items == {}


def test_the_read_api_exposes_no_write_route(world):
    for function in ("registrar", "approver"):
        for method, path in ROUTES[function]:
            assert world.call("read", method, path, PAT, {**BODY, "reason": "x"})[0] == 405
    for method in ("POST", "PUT", "DELETE"):
        assert world.call("read", method, "/registrations/rec000000001/history", PAT)[0] == 405
    assert world.registry.calls == [] and world.dynamo.items == {}


@pytest.mark.parametrize(
    "name", ["PORTAL_GROUP_TENANT_MAP", "PORTAL_AUDIT_TABLE", "PORTAL_REGISTRY_ID", "PORTAL_GROUP_ROLE_MAP"]
)
def test_action_configuration_fails_closed(world, monkeypatch, name):
    monkeypatch.delenv(name)
    code, body = world.create()
    assert (code, body) == (500, {"detail": f"Portal configuration error: {name} is not set"})
    assert world.registry.calls == []


def test_action_settings_need_only_their_own_variables():
    needed = (
        "PORTAL_ENV",
        "PORTAL_ACTION_ROLE",
        "PORTAL_REGISTRY_ID",
        "PORTAL_REGISTRY_REGION",
        "PORTAL_IDENTITY_PROVIDER",
        "PORTAL_GROUP_ROLE_MAP",
        "PORTAL_GROUP_TENANT_MAP",
        "PORTAL_AUDIT_TABLE",
    )
    env = {"PORTAL_ACTION_ROLE": "approver", **{k: BASE_ENV[k] for k in needed if k != "PORTAL_ACTION_ROLE"}}
    settings = load_action_settings(env)
    assert settings.action_role == "approver" and settings.group_tenant_map["devs"] == ("ws1",)
    with pytest.raises(ConfigError, match="PORTAL_ACTION_ROLE"):
        load_action_settings({**env, "PORTAL_ACTION_ROLE": "owner"})


@pytest.mark.parametrize(
    "tenant_map",
    ['{"devs": ["*"]}', '{"devs": "ws1"}', '{"devs": ["Bad Tenant"]}', "[]", '{"strangers": ["*"]}'],
)
def test_tenant_map_validation(tenant_map):
    env = {**BASE_ENV, "PORTAL_ACTION_ROLE": "registrar", "PORTAL_GROUP_TENANT_MAP": tenant_map}
    with pytest.raises(ConfigError, match="PORTAL_GROUP_TENANT_MAP"):
        load_action_settings(env)


# --- authority mapping ----------------------------------------------------------------------------


def _principal(role: str, groups: tuple[str, ...] = ()) -> Principal:
    return Principal(subject="s", email=None, display_name=None, groups=groups, role=role)


@pytest.mark.parametrize(
    ("role", "registrar", "approver"),
    [
        ("platform", True, True),
        ("developer", True, False),
        ("approver", False, True),
        ("security", False, True),
        ("sre", False, False),
        ("finops", False, False),
        ("readonly", False, False),
    ],
)
def test_which_portal_role_holds_which_authority(role, registrar, approver):
    principal = _principal(role)
    for action in authority.REGISTRAR_ACTIONS:
        assert authority.has_authority(principal, action) is registrar
    for action in authority.APPROVER_ACTIONS:
        assert authority.has_authority(principal, action) is approver


def test_tenants_come_from_the_group_tenant_map():
    settings = load_action_settings({**BASE_ENV, "PORTAL_ACTION_ROLE": "registrar"})
    developer = _principal("developer", ("devs", "devs2", "unmapped"))
    assert authority.tenants_of(developer, settings) == ("ws1", "ws2")
    assert authority.holds_tenant(developer, settings, "ws2") and not authority.holds_tenant(developer, settings, "ws3")
    assert authority.holds_tenant(_principal("platform"), settings, "anything")
    nobody = authority.core_principal(_principal("developer"), settings, "create", "ws1")
    assert nobody == {"principalId": "s", "role": "registry_admin", "tenantId": "(none)"}


def test_agent_references_are_projected_onto_the_core_slots():
    base = {
        "runtimeArn": "r",
        "gatewayArn": "g",
        "subscribedToolIds": ["b", "a"],
        "riskClass": "limited",
        "dataClassification": "internal",
        "businessPurpose": "p",
    }
    reference = authority.approved_references(base)
    assert set(reference) == {"inferenceTargetArn", "modelId", "rateProfile"}
    assert (
        authority.approved_references({**base, "subscribedToolIds": ["a", "b"], "businessPurpose": "other"})
        == reference
    )
    for field, value in [
        ("runtimeArn", "x"),
        ("gatewayArn", "x"),
        ("subscribedToolIds", ["a"]),
        ("riskClass", "high"),
        ("dataClassification", "public"),
    ]:
        assert authority.approved_references({**base, field: value}) != reference, field


# --- read API: registrations and history -----------------------------------------------------------


def test_registrations_list_and_filters(world):
    first = world.new_record("PENDING_APPROVAL")
    code, body = world.create(PAT, tenant_id="ws2")
    second = body["registration"]["record_id"]
    world.registry.seed("tool-echo", json.dumps({"schemaVersion": "agenticai.tool-governance/1.0"}))
    code, listed = world.call("read", "GET", "/registrations", VIEW)
    assert code == 200 and {r["record_id"] for r in listed} == {first, second}
    assert set(listed[0]) == {
        "record_id",
        "name",
        "status",
        "status_reason",
        "record_version",
        "tenant_id",
        "agent_id",
        "environment",
        "document",
        "document_sha256",
        "created_at",
        "updated_at",
    }
    request = event("/registrations", "GET", VIEW, query="status=PENDING_APPROVAL")
    assert [r["record_id"] for r in json.loads(world.handlers["read"](request, None)["body"])] == [first]
    request = event("/registrations", "GET", VIEW, query="tenant_id=ws2")
    assert [r["record_id"] for r in json.loads(world.handlers["read"](request, None)["body"])] == [second]
    assert (
        world.handlers["read"](event("/registrations", "GET", VIEW, query="status=CREATING"), None)["statusCode"] == 422
    )
    assert world.call("read", "GET", "/registrations", None)[0] == 401


def test_single_registration_with_people_from_the_audit_trail(world):
    record_id = world.new_record()
    code, detail = world.call("read", "GET", f"/registrations/{record_id}", DEV)
    assert code == 200 and detail["record_id"] == record_id and detail["status"] == "DRAFT"
    assert (detail["created_by"], detail["created_by_label"]) == ("dev-1", "dev@example.com")
    assert (detail["submitted_by"], detail["submitted_by_me"], detail["decision"]) == (None, False, None)

    assert world.submit(record_id)[0] == 200
    mine = world.call("read", "GET", f"/registrations/{record_id}", DEV)[1]
    assert (mine["submitted_by"], mine["submitted_by_label"], mine["submitted_by_me"]) == (
        "dev-1",
        "dev@example.com",
        True,
    )
    assert mine["submitted_at"] and mine["decided_at"] is None
    assert world.call("read", "GET", f"/registrations/{record_id}", ANN)[1]["submitted_by_me"] is False

    assert world.decide("reject", record_id, ANN, "Owner contact is missing.")[0] == 200
    rejected = world.call("read", "GET", f"/registrations/{record_id}", VIEW)[1]
    assert (rejected["status"], rejected["decision"], rejected["decided_by_label"], rejected["decision_reason"]) == (
        "REJECTED",
        "reject",
        "Ann Approver",
        "Owner contact is missing.",
    )
    assert world.update(record_id, contact="owner@example.com")[0] == 200  # back to DRAFT
    draft = world.call("read", "GET", f"/registrations/{record_id}", VIEW)[1]
    assert (draft["status"], draft["submitted_by"], draft["decision"], draft["decision_reason"]) == (
        "DRAFT",
        None,
        None,
        None,
    )
    assert draft["created_by_label"] == "dev@example.com"


def test_previous_approved_document_is_kept_for_the_diff(world):
    record_id = world.new_record("PENDING_APPROVAL")
    assert world.call("read", "GET", f"/registrations/{record_id}", ANN)[1]["previous_approved"] is None
    assert world.decide("reject", record_id)[0] == 200
    assert (
        world.call("read", "GET", f"/registrations/{record_id}", ANN)[1]["previous_approved"] is None
    )  # a rejection keeps nothing
    assert world.update(record_id, contact="first@example.com")[0] == 200
    assert world.submit(record_id)[0] == 200
    assert world.decide("approve", record_id)[0] == 200
    approved = world.call("read", "GET", f"/registrations/{record_id}", ANN)[1]
    assert approved["previous_approved"] == approved["document"]

    assert (
        world.update(record_id, contact="first@example.com", business_purpose="Plans trips, events and visas.")[0]
        == 200
    )
    assert world.submit(record_id)[0] == 200
    pending = world.call("read", "GET", f"/registrations/{record_id}", ANN)[1]
    assert pending["status"] == "PENDING_APPROVAL"
    assert pending["previous_approved"]["business_purpose"] == "Plans trips for employees."
    assert pending["document"]["business_purpose"] == "Plans trips, events and visas."
    assert (
        pending["previous_approved"]["record_version"] == "1.0.1" and pending["document"]["record_version"] == "1.0.2"
    )
    assert set(pending["previous_approved"]) == set(pending["document"])

    stored = [e for e in world.dynamo.events() if "document" in e]
    assert [(e["action"], e["phase"], e["outcome"]) for e in stored] == [("approve", "result", "allowed")]
    assert registrations.sha256(stored[0]["document"]) == stored[0]["document_sha256"]
    history = world.call("read", "GET", f"/registrations/{record_id}/history", ANN)[1]
    assert all("document" not in event for event in history["events"])


def test_single_registration_errors_and_records_without_a_trail(world, monkeypatch):
    assert world.call("read", "GET", "/registrations/rec999999999", VIEW) == (404, {"detail": "Registration not found"})
    tool = world.registry.seed("tool-echo", json.dumps({"schemaVersion": "agenticai.tool-governance/1.0"}))
    assert world.call("read", "GET", f"/registrations/{tool}", VIEW)[0] == 404
    assert world.call("read", "GET", "/registrations/bad", VIEW)[0] == 422
    assert world.call("read", "GET", "/registrations/rec999999999", None)[0] == 401
    published = world.registry.seed(
        "agent-ws1-other-nonprod",
        registrations.canonical(
            {
                "schemaVersion": "agenticai.agent-governance/1.0",
                "tenantId": "ws1",
                "agentId": "other",
                "environment": "nonprod",
                "recordVersion": "1.0.0",
            }
        ),
        "PENDING_APPROVAL",
    )
    code, detail = world.call("read", "GET", f"/registrations/{published}", VIEW)
    assert code == 200 and detail["submitted_by"] is None and detail["created_by"] is None
    monkeypatch.delenv("PORTAL_AUDIT_TABLE")
    assert world.call("read", "GET", f"/registrations/{published}", VIEW)[0] == 200


def test_history_is_newest_first_and_survives_deletion(world):
    record_id = world.new_record("REJECTED")
    code, history = world.call("read", "GET", f"/registrations/{record_id}/history", VIEW)
    assert code == 200 and history["record_id"] == record_id
    assert [(e["action"], e["phase"]) for e in history["events"]] == [
        ("reject", "result"),
        ("reject", "intent"),
        ("submit", "result"),
        ("submit", "intent"),
        ("create", "result"),
        ("create", "intent"),
    ]
    assert [e["at"] for e in history["events"]] == sorted((e["at"] for e in history["events"]), reverse=True)
    assert "pk" not in history["events"][0] and "sk" not in history["events"][0]
    assert world.delete(record_id)[0] == 200
    code, history = world.call("read", "GET", f"/registrations/{record_id}/history", VIEW)
    assert (
        code == 200 and history["events"][0]["action"] == "delete" and history["events"][0]["status_after"] == "DELETED"
    )
    assert world.call("read", "GET", "/registrations/rec999999999/history", VIEW)[0] == 404
    assert world.call("read", "GET", "/registrations/bad/history", VIEW)[0] == 422


def test_history_needs_the_audit_table_to_be_configured(world, monkeypatch):
    monkeypatch.delenv("PORTAL_AUDIT_TABLE")
    code, body = world.call("read", "GET", "/registrations/rec000000001/history", VIEW)
    assert (code, body) == (500, {"detail": "Portal configuration error: PORTAL_AUDIT_TABLE is not set"})
    assert world.call("read", "GET", "/agents", None)[0] == 401  # the rest of the read API is unaffected
