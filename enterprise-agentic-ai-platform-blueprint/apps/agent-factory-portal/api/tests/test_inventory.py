# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Inventory states: registry records joined with what the cell readers and the discovery registry detect."""

from __future__ import annotations

import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from portal_api import containment_policy
from portal_api.aws import agentcore, registry
from portal_api.config import load_settings
from portal_api.mappers import discovery as discovery_mapper
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    GATEWAY_ARN,
    ORPHAN_RUNTIME_ARN,
    OTHER_ACCOUNT,
    REGION,
    RUNTIME_ARN,
    T0,
    FakeClient,
    FakeClients,
    agent_record,
    gateway_bundle,
    make_service,
    runtime_bundle,
    tool_record,
)

OUTSIDE_ARN = f"arn:aws:bedrock-agentcore:{REGION}:888888888888:runtime/shadow_agent-QwErTy5678"
DISCOVERY = "DISCOVERYREG0001"


def summary(arn: str, record_id: str, record_type: str = "AGENT") -> dict[str, Any]:
    parts = arn.split(":")
    source_type = "AWS::BedrockAgentCore::Runtime" if record_type == "AGENT" else "AWS::BedrockAgentCore::Gateway"
    return {
        "recordId": record_id,
        "name": f"aws-autodetected-{parts[4]}-{parts[3]}-{arn.rsplit('/', 1)[-1]}",
        "recordType": record_type,
        "status": "DRAFT",
        "createdByAutoDetection": True,
        "createdAt": T0,
        "provenanceSummaryList": [{"relation": "DETECTED_FROM", "sourceId": arn, "sourceType": source_type}],
    }


def full_record(arn: str, record_id: str, jwt: bool = False) -> dict[str, Any]:
    details: dict[str, Any] = {
        "protocolConfiguration": {"serverProtocol": "HTTP"},
        "workloadIdentityDetails": {"workloadIdentityArn": arn.replace(":runtime/", ":workload-identity/")},
    }
    if jwt:
        details["authorizerConfiguration"] = {"customJWTAuthorizer": {"discoveryUrl": "https://idp.example.com"}}
    base = summary(arn, record_id)
    base.pop("provenanceSummaryList")
    return {
        **base,
        "provenance": [
            {
                "relation": "DETECTED_FROM",
                "sourceId": arn,
                "sourceType": "AWS::BedrockAgentCore::Runtime",
                "sourceDetails": {"agentcoreRuntime": details},
            }
        ],
    }


# --- discovery mapper -------------------------------------------------------------------


def test_detections_from_list_summaries():
    found = discovery_mapper.detections(
        [summary(RUNTIME_ARN, "recDetect0001"), summary(GATEWAY_ARN, "recDetect0002", "GATEWAY"), {"recordId": "x"}]
    )
    assert [(d.arn, d.kind, d.record_id, d.authorizer_type) for d in found] == [
        (RUNTIME_ARN, "runtime", "recDetect0001", None),
        (GATEWAY_ARN, "gateway", "recDetect0002", None),
    ]
    assert found[0].record_name == f"aws-autodetected-{CELL_ACCOUNT}-{REGION}-travel_agent-AbCdEf1234"


def test_detections_from_full_records_carry_authorizer_and_identity():
    iam, jwt = discovery_mapper.detections(
        [full_record(RUNTIME_ARN, "recDetect0001"), full_record(OUTSIDE_ARN, "r2", True)]
    )
    assert (iam.authorizer_type, iam.protocol) == ("AWS_IAM", "HTTP")
    assert iam.workload_identity_arn.endswith("workload-identity/travel_agent-AbCdEf1234")
    assert jwt.authorizer_type == "CUSTOM_JWT"
    gateway = discovery_mapper.detections(
        [
            {
                "recordId": "g1",
                "recordType": "GATEWAY",
                "provenance": [
                    {
                        "sourceId": GATEWAY_ARN,
                        "sourceType": "AWS::BedrockAgentCore::Gateway",
                        "sourceDetails": {"agentcoreGateway": {"protocolType": "MCP", "authorizerType": "AWS_IAM"}},
                    }
                ],
            }
        ]
    )[0]
    assert (gateway.kind, gateway.authorizer_type, gateway.protocol) == ("gateway", "AWS_IAM", "MCP")


def test_detections_ignore_records_without_an_agentcore_source_and_duplicates():
    records = [
        {"recordId": "a", "provenance": [{"sourceId": "arn:aws:lambda:eu-west-1:111111111111:function:x"}]},
        {"recordId": "b", "provenance": [{"sourceId": "not-an-arn"}]},
        {"recordId": "c", "provenance": "nope"},
        summary(RUNTIME_ARN, "first"),
        summary(RUNTIME_ARN, "second"),
    ]
    assert [(d.arn, d.record_id) for d in discovery_mapper.detections(records)] == [(RUNTIME_ARN, "first")]


# --- runtime facts read through the cell reader ----------------------------------------------


def _runtime_client(
    env: dict[str, str] | None = None, authorizer: dict | None = None, policy: Any = None
) -> FakeClient:
    def get_resource_policy(resourceArn: str) -> dict[str, Any]:  # noqa: N803
        if isinstance(policy, Exception):
            raise policy
        return {"policy": policy} if policy is not None else {}

    runtime_id = RUNTIME_ARN.rsplit("/", 1)[-1]
    return FakeClient(
        {
            "list_agent_runtimes": [
                {"agentRuntimes": [{"agentRuntimeArn": RUNTIME_ARN, "agentRuntimeId": runtime_id}]}
            ],
            "get_agent_runtime": {
                "createdAt": T0,
                "environmentVariables": env or {},
                **({"authorizerConfiguration": authorizer} if authorizer else {}),
            },
            "get_resource_policy": get_resource_policy,
            "list_tags_for_resource": {"tags": {"tenant-id": "ws1"}},
        }
    )


def test_runtime_detail_reports_derived_facts_and_never_environment_values():
    env = {
        "GUARDRAIL_ID": "abc123",
        "MODEL_ID": "model",
        "API_SECRET": "do-not-return",
        "AGENTCORE_GATEWAY_URL": "https://gw",
    }
    (bundle,) = agentcore.list_runtimes(_runtime_client(env))
    assert bundle["detail"] == {
        "createdAt": T0,
        "gatewayUrl": "https://gw",
        "guardrailConfigured": True,
        "authorizerType": "AWS_IAM",
        "contained": False,
    }
    assert "do-not-return" not in json.dumps(bundle, default=str) and "abc123" not in json.dumps(bundle, default=str)


def test_runtime_detail_guardrail_and_authorizer_variants():
    (none,) = agentcore.list_runtimes(_runtime_client({"MODEL_ID": "m", "GUARDRAIL_ID": " "}))
    assert none["detail"]["guardrailConfigured"] is False
    jwt = {"customJWTAuthorizer": {"discoveryUrl": "https://idp.example.com/.well-known/openid-configuration"}}
    (custom,) = agentcore.list_runtimes(_runtime_client({"BEDROCK_GUARDRAIL_IDENTIFIER": "g"}, jwt))
    assert (custom["detail"]["guardrailConfigured"], custom["detail"]["authorizerType"]) == (True, "CUSTOM_JWT")


def test_a_runtime_that_names_only_the_inference_gateway_is_covered():
    """The blueprint applies the guardrail at the inference gateway, so naming the gateway is coverage."""
    gateway_only = {
        "AGENTCORE_INFERENCE_GATEWAY_URL": "https://inference.example.com/v1",
        "AGENTCORE_MEMORY_ID": "mem-1",
    }
    (bundle,) = agentcore.list_runtimes(_runtime_client(gateway_only))
    assert bundle["detail"]["guardrailConfigured"] is True
    assert "inference.example.com" not in json.dumps(bundle, default=str)  # the value never leaves

    cases = [
        ({"AGENTCORE_GUARDRAIL_ID": "abc123"}, True),  # the blueprint's generated agent
        ({"GUARDRAIL_ID": "abc123", "GUARDRAIL_VERSION": "1"}, True),
        (
            {"AGENTCORE_GUARDRAIL_ID": "abc123", "AGENTCORE_INFERENCE_GATEWAY_URL": "https://inference.example.com"},
            True,
        ),
        ({"AGENTCORE_INFERENCE_GATEWAY_URL": "   "}, False),  # named but empty
        ({"AGENTCORE_INFERENCE_GATEWAY_URL": ""}, False),
        (
            {"AGENTCORE_GATEWAY_URL": "https://tools.example.com/mcp"},
            False,
        ),  # the Tool Gateway is not the inference gateway
        ({"INFERENCE_GATEWAY_URL": "https://inference.example.com"}, False),  # not a name the blueprint uses
        ({"AGENTCORE_MEMORY_ID": "mem-1"}, False),  # the compatibility variant
        ({}, False),
    ]
    for env, expected in cases:
        assert agentcore.guardrail_covered(env) is expected, env
    assert agentcore.INFERENCE_GATEWAY_ENV == ("AGENTCORE_INFERENCE_GATEWAY_URL",)
    assert agentcore.guardrail_covered({"AGENTCORE_INFERENCE_GATEWAY_URL": None, "GUARDRAIL_ID": None}) is False


def test_contained_is_read_from_the_resource_policy():
    contained = containment_policy.with_containment(None, RUNTIME_ARN)
    other = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "Other", "Effect": "Allow"}]})
    missing = ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, "GetResourcePolicy")
    denied = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "GetResourcePolicy")
    for policy, expected in [
        (contained, True),
        (other, False),
        (None, False),
        (missing, False),
        (denied, None),
        ("{bad", None),
    ]:
        (bundle,) = agentcore.list_runtimes(_runtime_client(policy=policy))
        assert bundle["detail"]["contained"] is expected, policy


# --- inventory states ---------------------------------------------------------------------------


class Backend:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, env: dict[str, str] | None = None) -> None:
        self.records = [tool_record("tool-echo"), agent_record()]
        self.summaries: list[dict[str, Any]] = []
        self.full: dict[str, dict[str, Any]] = {}
        self.list_error: Exception | None = None
        self.fetched: list[str] = []
        self.seen_registries: list[str] = []
        self.control = FakeClient()
        self.control.runtimes = [runtime_bundle()]
        self.control.gateways = [gateway_bundle("ENFORCE")]
        monkeypatch.setattr(registry, "list_records", lambda client, registry_id: self.records)
        monkeypatch.setattr(agentcore, "list_runtimes", lambda client: client.runtimes)
        monkeypatch.setattr(agentcore, "list_gateways", lambda client: client.gateways)

        def list_summaries(client: Any, registry_id: str) -> list[dict[str, Any]]:
            self.seen_registries.append(registry_id)
            if self.list_error:
                raise self.list_error
            return self.summaries

        def get_records(client: Any, registry_id: str, record_ids: list[str]) -> dict[str, dict[str, Any]]:
            self.fetched.extend(record_ids)
            return {i: self.full[i] for i in record_ids if i in self.full}

        monkeypatch.setattr(registry, "list_summaries", list_summaries)
        monkeypatch.setattr(registry, "get_records", get_records)
        denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "AssumeRole")
        self.clients = FakeClients(
            {
                ("platform", "agent-registry-control"): FakeClient(),
                (CELL_ACCOUNT, "bedrock-agentcore-control"): self.control,
                (CELL_ACCOUNT, "cloudwatch"): FakeClient({"describe_alarms": [{"MetricAlarms": []}]}),
                (OTHER_ACCOUNT, "bedrock-agentcore-control"): denied,
                (OTHER_ACCOUNT, "cloudwatch"): denied,
            }
        )
        self.service = make_service(load_settings({**BASE_ENV, **(env or {})}), self.clients)

    def agents(self) -> dict[str, Any]:
        self.service.cache.clear()
        return {entry.agent.id: entry.agent for entry in self.service.agents()}


@pytest.fixture
def discovery(monkeypatch: pytest.MonkeyPatch) -> Backend:
    return Backend(monkeypatch, {"PORTAL_DISCOVERY_REGISTRY_ID": DISCOVERY})


def test_without_a_discovery_registry_the_cell_reader_is_the_only_source(monkeypatch):
    backend = Backend(monkeypatch)
    backend.control.runtimes.append(runtime_bundle(ORPHAN_RUNTIME_ARN, tags={}))
    agents = backend.agents()
    registered, orphan = agents["recAgent0001"], agents["orphan_agent-ZyXwVu9876"]
    assert (registered.inventory_state, registered.detection_sources) == ("registered_and_detected", ["cell_reader"])
    assert (orphan.inventory_state, orphan.detection_sources, orphan.lifecycle_state) == (
        "detected_only",
        ["cell_reader"],
        "discovered",
    )
    assert backend.seen_registries == [] and backend.service.inventory().discovery == "disabled"


def test_a_runtime_seen_by_both_sources_is_one_agent(discovery):
    discovery.summaries = [summary(RUNTIME_ARN, "recDetect0001"), summary(GATEWAY_ARN, "recDetect0002", "GATEWAY")]
    agents = discovery.agents()
    assert list(agents) == ["recAgent0001"]
    agent = agents["recAgent0001"]
    assert (agent.inventory_state, agent.detection_sources) == (
        "registered_and_detected",
        ["cell_reader", "organization_registry"],
    )
    assert discovery.seen_registries == [DISCOVERY]
    assert discovery.fetched == []  # the cell reader already knows this Runtime: no per-record read
    (gateway,) = discovery.service.gateways()
    assert gateway.server.detection_sources == ["cell_reader", "organization_registry"]
    assert discovery.service.inventory().discovery == "ok"


def test_registered_only_when_nothing_detects_the_runtime(discovery):
    discovery.control.runtimes = []
    agent = discovery.agents()["recAgent0001"]
    assert (agent.inventory_state, agent.detection_sources, agent.runtime_status) == ("registered_only", [], None)
    assert agent.lifecycle_state == "approved"
    discovery.records = [tool_record("tool-echo"), agent_record(runtimeArn=None, gatewayArn=None)]
    assert discovery.agents()["recAgent0001"].inventory_state == "registered_only"


def test_registered_runtime_detected_only_by_the_organization_registry(discovery):
    discovery.control.runtimes = []
    discovery.summaries = [summary(RUNTIME_ARN, "recDetect0001")]
    discovery.full = {"recDetect0001": full_record(RUNTIME_ARN, "recDetect0001", jwt=True)}
    agent = discovery.agents()["recAgent0001"]
    assert (agent.inventory_state, agent.detection_sources) == ("registered_and_detected", ["organization_registry"])
    assert (agent.inbound_authorizer, agent.auth_type) == ("CUSTOM_JWT", "custom_jwt")
    assert discovery.fetched == ["recDetect0001"]


def test_a_runtime_outside_every_cell_is_detected_only_through_the_organization_registry(discovery):
    discovery.summaries = [summary(RUNTIME_ARN, "recDetect0001"), summary(OUTSIDE_ARN, "recDetect0003")]
    discovery.full = {"recDetect0003": full_record(OUTSIDE_ARN, "recDetect0003")}
    agents = discovery.agents()
    shadow = agents["shadow_agent-QwErTy5678"]
    assert (shadow.inventory_state, shadow.detection_sources, shadow.lifecycle_state, shadow.registration) == (
        "detected_only",
        ["organization_registry"],
        "discovered",
        "discovered",
    )
    assert (shadow.name, shadow.region, shadow.account_id, shadow.agent_arn) == (
        "shadow_agent",
        REGION,
        "888888888888",
        OUTSIDE_ARN,
    )
    assert (shadow.tenant_id, shadow.environment, shadow.runtime_status) == (None, "unknown", "unknown")
    assert (shadow.inbound_authorizer, shadow.auth_type) == ("AWS_IAM", "aws_iam")
    assert discovery.fetched == ["recDetect0003"]
    assert (shadow.reader_status, shadow.account_alias) == ("none", None)
    status = discovery.service.runtime_status("shadow_agent-QwErTy5678")
    assert status.status == "unknown"
    assert status.detail == "There is no reader in this agent's account, so its Runtime status cannot be read."
    assert discovery.service.deployments("shadow_agent-QwErTy5678", 10) == []
    assert discovery.service.traces("shadow_agent-QwErTy5678", 1, 10, 24).warnings == [
        "There is no reader in this agent's account, so its traces cannot be read."
    ]
    assert discovery.service.agent_mcp_grants("shadow_agent-QwErTy5678") == []


def test_a_detection_in_an_unknown_account_degrades_every_per_cell_read(discovery, monkeypatch):
    """The normal case: the organization registry detects Runtimes in an account that has no cell and no reader.

    Every per-agent endpoint answers 200 and says there is no reader, rather than failing or staying empty.
    """
    from mangum import Mangum

    from portal_api import deps
    from portal_api.app import create_app
    from tests.fakes import FakeDynamo
    from tests.test_api import event

    monkeypatch.setenv("PORTAL_DISCOVERY_REGISTRY_ID", DISCOVERY)
    # Only detections, all in one account the portal has no cell for; nothing is registered.
    second = OUTSIDE_ARN.replace("shadow_agent-QwErTy5678", "demo_runtime-AsDfGh1234")
    discovery.records = []
    discovery.control.runtimes = []
    discovery.control.gateways = []
    discovery.summaries = [summary(OUTSIDE_ARN, "recDetect0003"), summary(second, "recDetect0004")]
    discovery.full = {
        "recDetect0003": full_record(OUTSIDE_ARN, "recDetect0003"),
        "recDetect0004": full_record(second, "recDetect0004", jwt=True),
    }
    discovery.clients.clients[("platform", "dynamodb")] = FakeDynamo()
    discovery.service.cache.clear()
    application = create_app()
    application.dependency_overrides[deps.get_service] = lambda: discovery.service
    handler = Mangum(application, lifespan="off")
    claims = {"sub": "u", "cognito:groups": "[viewers]"}

    def get(path: str, query: str = "") -> Any:
        response = handler(event(path, "GET", claims, query=query), None)
        assert response["statusCode"] == 200, (path, response["body"])
        return response["body"] if path.endswith("/export") else json.loads(response["body"])

    no_reader = "There is no reader in this agent's account, so {} cannot be read."
    agents = {a["id"]: a for a in get("/agents")}
    assert set(agents) == {"shadow_agent-QwErTy5678", "demo_runtime-AsDfGh1234"}
    agent_id = "shadow_agent-QwErTy5678"
    agent = get(f"/agents/{agent_id}")
    # identity comes from the ARN: account (no alias is configured for it), Region and name
    assert (agent["name"], agent["region"], agent["account_id"], agent["account_alias"]) == (
        "shadow_agent",
        REGION,
        "888888888888",
        None,
    )
    assert (agent["inventory_state"], agent["detection_sources"], agent["reader_status"]) == (
        "detected_only",
        ["organization_registry"],
        "none",
    )
    assert (agent["agent_arn"], agent["tenant_id"], agent["environment"], agent["omni_url"]) == (
        OUTSIDE_ARN,
        None,
        "unknown",
        None,
    )
    assert agent["flags"] == {
        "unmanaged": True,
        "ownerless": None,
        "review_overdue": None,
        "inactive": None,
        "contained": None,
    }
    assert (agent["risk"]["level"], [r["code"] for r in agent["risk"]["reasons"]]) == ("high", ["UNREGISTERED"])
    assert agents["demo_runtime-AsDfGh1234"]["inbound_authorizer"] == "CUSTOM_JWT"

    runtime = get(f"/agents/{agent_id}/runtime")
    assert (runtime["status"], runtime["detail"]) == ("unknown", no_reader.format("its Runtime status"))
    assert get(f"/agents/{agent_id}/deployments") == []
    traces = get(f"/agents/{agent_id}/traces")
    assert (traces["data"], traces["total"], traces["warnings"]) == ([], 0, [no_reader.format("its traces")])
    metrics = get(f"/agents/{agent_id}/metrics")
    assert metrics["totals"]["traces"] == 0 and metrics["warnings"] == [no_reader.format("its metrics")]
    runs = get(f"/agents/{agent_id}/evals/runs")
    assert runs["runs"] == [] and "does not belong to a configured cell" in runs["warnings"][0]
    assert get(f"/agents/{agent_id}/mcp-grants") == []
    containment = get(f"/agents/{agent_id}/containment")
    assert (containment["state"], containment["enabled"], containment["detail"]) == (
        "unknown",
        False,
        no_reader.format("its containment state"),
    )
    assert containment["events"] == [] and containment["runtime_arn"] == OUTSIDE_ARN

    # fleet-wide views still work and count these agents
    fleet_summary = get("/fleet/summary")
    assert fleet_summary["by_inventory_state"] == {
        "registered_and_detected": 0,
        "registered_only": 0,
        "detected_only": 2,
    }
    assert fleet_summary["flags"]["unmanaged"] == 2 and fleet_summary["flags_unknown"]["contained"] == 2
    assert [a["agent_id"] for a in fleet_summary["needs_attention"]] == ["demo_runtime-AsDfGh1234", agent_id]
    assert {n["id"] for n in get("/governance-graph")["nodes"]} == {f"agent:{i}" for i in agents}
    assert get("/observability/metrics", "scope=tenant")["by_agent"] == []
    export = get("/agents/export")
    assert "shadow_agent-QwErTy5678" in export and "account-8888" in export
    # no cell-account read was attempted for these agents: only the configured cells were tried
    assert {account for account, _ in discovery.clients.cell_calls} <= {CELL_ACCOUNT, OTHER_ACCOUNT}


def test_a_cell_reader_runtime_the_organization_registry_missed_is_still_listed(discovery):
    discovery.control.runtimes.append(runtime_bundle(ORPHAN_RUNTIME_ARN, tags={}))
    discovery.summaries = [summary(RUNTIME_ARN, "recDetect0001")]
    orphan = discovery.agents()["orphan_agent-ZyXwVu9876"]
    assert (orphan.inventory_state, orphan.detection_sources) == ("detected_only", ["cell_reader"])


def test_a_failing_discovery_registry_does_not_fail_the_inventory(discovery):
    discovery.list_error = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "ListRegistryRecords"
    )
    agent = discovery.agents()["recAgent0001"]
    assert (agent.inventory_state, agent.detection_sources) == ("registered_and_detected", ["cell_reader"])
    assert discovery.service.inventory().discovery == "AccessDeniedException"


def test_discovery_registry_id_is_validated():
    from portal_api.config import ConfigError

    with pytest.raises(ConfigError, match="PORTAL_DISCOVERY_REGISTRY_ID"):
        load_settings({**BASE_ENV, "PORTAL_DISCOVERY_REGISTRY_ID": "bad id"})
    assert load_settings({**BASE_ENV, "PORTAL_DISCOVERY_REGISTRY_ID": ""}).discovery_registry_id is None


# --- the containment statement (pure) ----------------------------------------------------------------


def test_containment_statement_denies_every_invoke_to_everyone():
    statement = containment_policy.containment_statement(RUNTIME_ARN)
    assert statement == {
        "Sid": "AgenticAIPortalContainment",
        "Effect": "Deny",
        "Principal": "*",
        "Action": [
            "bedrock-agentcore:InvokeAgentRuntime",
            "bedrock-agentcore:InvokeAgentRuntimeForUser",
            "bedrock-agentcore:InvokeAgentRuntimeCommand",
            "bedrock-agentcore:InvokeAgentRuntimeCommandShell",
            "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
            "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser",
        ],
        "Resource": RUNTIME_ARN,
    }
    assert "bedrock-agentcore:StopRuntimeSession" not in statement["Action"]


def test_adding_and_removing_the_statement_keeps_other_statements_byte_for_byte():
    other = [
        {
            "Sid": "AllowPartner",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
            "Resource": RUNTIME_ARN,
            "Condition": {"StringEquals": {"aws:PrincipalTag/team": "a"}},
        },
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "bedrock-agentcore:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        },
    ]
    original = json.dumps({"Version": "2012-10-17", "Id": "keep-me", "Statement": other})
    contained = containment_policy.with_containment(original, RUNTIME_ARN)
    document = json.loads(contained)
    assert document["Statement"][:2] == other and document["Id"] == "keep-me" and len(document["Statement"]) == 3
    assert containment_policy.is_contained(contained) and not containment_policy.is_contained(original)
    again = containment_policy.with_containment(contained, RUNTIME_ARN)
    assert json.loads(again) == document  # idempotent: never two containment statements
    released = containment_policy.without_containment(contained)
    assert json.loads(released) == json.loads(original)
    assert containment_policy.without_containment(original) is not None  # nothing of ours to remove, policy kept


def test_policy_edge_cases():
    only_ours = containment_policy.with_containment(None, RUNTIME_ARN)
    assert json.loads(only_ours)["Version"] == "2012-10-17"
    assert containment_policy.without_containment(only_ours) is None  # nothing else remains: delete the policy
    assert containment_policy.without_containment(None) is None
    assert containment_policy.is_contained(None) is False and containment_policy.is_contained("  ") is False
    single = json.dumps({"Version": "2012-10-17", "Statement": {"Sid": "One", "Effect": "Allow"}})
    assert json.loads(containment_policy.with_containment(single, RUNTIME_ARN))["Statement"][0] == {
        "Sid": "One",
        "Effect": "Allow",
    }
    for bad in ("{not json", "[1, 2]", '"text"'):
        with pytest.raises(containment_policy.PolicyError):
            containment_policy.with_containment(bad, RUNTIME_ARN)
        with pytest.raises(containment_policy.PolicyError):
            containment_policy.without_containment(bad)


# --- flags and risk on the inventory ---------------------------------------------------------------


def benign(status: str = "APPROVED", **overrides: Any) -> dict[str, Any]:
    """An approved registration that triggers no risk rule on its own."""
    return agent_record(status, **{"dataClassification": "internal", **overrides})


def rich_bundle(arn: str = RUNTIME_ARN, **detail: Any) -> dict[str, Any]:
    """A cell-reader Runtime with every fact known: guardrail named, AWS IAM, not contained."""
    bundle = runtime_bundle(arn)
    bundle["detail"].update({"guardrailConfigured": True, "authorizerType": "AWS_IAM", "contained": False, **detail})
    return bundle


def invoked(*indexes: int) -> list[dict[str, Any]]:
    """GetMetricData pages saying the Runtimes at these positions were invoked yesterday."""
    import datetime as dt

    day = dt.datetime.now(dt.UTC).replace(hour=0, minute=0, second=0, microsecond=0) - dt.timedelta(days=1)
    return [{"MetricDataResults": [{"Id": f"a{i}_invocations", "Timestamps": [day], "Values": [3.0]} for i in indexes]}]


@pytest.fixture
def fleet(monkeypatch: pytest.MonkeyPatch) -> Backend:
    backend = Backend(monkeypatch)
    backend.control.runtimes = [rich_bundle()]
    backend.records = [tool_record("tool-echo"), benign()]
    backend.cloudwatch = backend.clients.clients[(CELL_ACCOUNT, "cloudwatch")]
    backend.cloudwatch.responses["describe_alarms"] = [{"MetricAlarms": [{"AlarmName": "a", "StateValue": "OK"}]}]
    backend.cloudwatch.responses["get_metric_data"] = invoked(0)
    return backend


def test_a_well_governed_agent_has_no_flags_and_low_risk(fleet):
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.model_dump() == {
        "unmanaged": False,
        "ownerless": False,
        "review_overdue": False,
        "inactive": False,
        "contained": False,
    }
    assert (agent.risk.level, agent.risk.reasons) == ("low", [])
    assert agent.last_invoked_on is not None


def test_the_unmanaged_flag_follows_the_status_and_the_reason_names_the_cause(fleet):
    expected = [
        ("APPROVED", False, []),
        ("PENDING_APPROVAL", True, [("REGISTRATION_NOT_APPROVED", "medium")]),
        ("DRAFT", True, [("REGISTRATION_NOT_APPROVED", "medium")]),
        ("UPDATING", True, [("REGISTRATION_NOT_APPROVED", "medium")]),
        ("REJECTED", True, [("REGISTRATION_REJECTED", "high")]),
        ("DEPRECATED", True, [("REGISTRATION_DEPRECATED", "high")]),
    ]
    for status, unmanaged, reasons in expected:
        fleet.records = [benign(status)]
        agent = fleet.agents()["recAgent0001"]
        assert agent.flags.unmanaged is unmanaged, status  # the flag is unchanged: true unless APPROVED
        assert [(r.code, r.severity) for r in agent.risk.reasons] == reasons, status
        assert agent.risk.level == (reasons[0][1] if reasons else "low")


def test_a_rejected_or_deprecated_paper_record_with_no_runtime_is_not_a_risk(fleet):
    fleet.control.runtimes = []  # nothing detects a Runtime for the registration
    for status in ("REJECTED", "DEPRECATED"):
        fleet.records = [benign(status)]
        agent = fleet.agents()["recAgent0001"]
        assert (agent.inventory_state, agent.flags.unmanaged) == ("registered_only", True)
        assert [r.code for r in agent.risk.reasons] == [] and agent.risk.level == "low"
    fleet.records = [benign("PENDING_APPROVAL")]  # waiting for approval is reported with or without a Runtime
    assert [r.code for r in fleet.agents()["recAgent0001"].risk.reasons] == ["REGISTRATION_NOT_APPROVED"]


def test_the_owner_is_the_owner_group_and_a_person_is_optional(fleet):
    # The shape of every record published before sponsors existed: an owner group, no person.
    fleet.records = [benign(sponsor=None, contact=None)]
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.ownerless is False
    assert [(r.code, r.severity) for r in agent.risk.reasons] == [("SPONSOR_MISSING", "low")]
    assert agent.risk.level == "low"
    fleet.records = [benign(sponsor=None)]  # a contact is a person
    assert [r.code for r in fleet.agents()["recAgent0001"].risk.reasons] == []
    fleet.records = [benign(contact=None)]  # so is a sponsor
    assert [r.code for r in fleet.agents()["recAgent0001"].risk.reasons] == []

    # No owner group at all: ownerless, whatever person is named.
    fleet.records = [benign(ownerGroup="")]
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.ownerless is True
    assert [(r.code, r.detail) for r in agent.risk.reasons] == [("OWNERLESS", "The registration names no owner group.")]
    fleet.records = [benign(ownerGroup=None)]
    assert fleet.agents()["recAgent0001"].flags.ownerless is True


def test_the_owner_roster_applies_only_when_one_is_configured(fleet):
    fleet.records = [benign()]
    assert fleet.agents()["recAgent0001"].flags.ownerless is False  # no roster: not knowable, so no finding
    fleet.service.settings = load_settings({**BASE_ENV, "PORTAL_OWNER_GROUPS": json.dumps(["other-owners"])})
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.ownerless is True
    assert [(r.code, r.severity, r.detail) for r in agent.risk.reasons] == [
        ("OWNER_GROUP_NOT_IN_ROSTER", "high", "The registration's owner group is not in the owner roster.")
    ]
    fleet.service.settings = load_settings({**BASE_ENV, "PORTAL_OWNER_GROUPS": json.dumps(["travel-owners"])})
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.ownerless is False and agent.risk.reasons == []
    # a blank owner group is reported once, as ownerless, not also as "not in the roster"
    fleet.records = [benign(ownerGroup="")]
    assert [r.code for r in fleet.agents()["recAgent0001"].risk.reasons] == ["OWNERLESS"]


def test_every_reason_is_true_of_the_real_shaped_registrations(fleet):
    """The two registrations as they really are: an owner group, no sponsor or contact, waiting for approval.

    Both Runtimes are detected, and the roster holds only the first owner group.
    """
    second_arn = RUNTIME_ARN.replace("travel_agent-AbCdEf1234", "travel_agent-ZyXwVu9876")
    shape = {"sponsor": None, "contact": None, "gatewayArn": None, "evaluation": {"verdict": "passed"}}
    fleet.records = [
        benign("PENDING_APPROVAL", record_id="recAgentWs01", ownerGroup="travel-workstream-ws1", **shape),
        benign(
            "PENDING_APPROVAL",
            record_id="recAgentWs02",
            tenantId="ws2",
            ownerGroup="travel-workstream-ws2",
            runtimeArn=second_arn,
            **shape,
        ),
    ]
    fleet.control.runtimes = [rich_bundle(), rich_bundle(second_arn)]
    fleet.cloudwatch.responses["get_metric_data"] = invoked(0, 1)
    fleet.service.settings = load_settings({**BASE_ENV, "PORTAL_OWNER_GROUPS": json.dumps(["travel-workstream-ws1"])})
    agents = fleet.agents()
    first, second = agents["recAgentWs01"], agents["recAgentWs02"]
    assert (first.inventory_state, second.inventory_state) == ("registered_and_detected", "registered_and_detected")

    assert [(r.code, r.severity) for r in first.risk.reasons] == [
        ("REGISTRATION_NOT_APPROVED", "medium"),
        ("SPONSOR_MISSING", "low"),
    ]
    assert first.risk.level == "medium"
    assert (first.flags.unmanaged, first.flags.ownerless) == (True, False)

    assert [(r.code, r.severity) for r in second.risk.reasons] == [
        ("OWNER_GROUP_NOT_IN_ROSTER", "high"),
        ("REGISTRATION_NOT_APPROVED", "medium"),
        ("SPONSOR_MISSING", "low"),
    ]
    assert second.risk.level == "high"
    assert (second.flags.unmanaged, second.flags.ownerless) == (True, True)

    # Nothing is claimed that is not true of these agents.
    for agent in (first, second):
        shown = {r.code: r.detail for r in agent.risk.reasons}
        assert not {"OWNERLESS", "UNREGISTERED", "REGISTRATION_REJECTED", "REGISTRATION_DEPRECATED"} & set(shown)
        assert shown["REGISTRATION_NOT_APPROVED"] == "The agent's registration is not approved yet."
        assert shown["SPONSOR_MISSING"] == "The registration names no accountable person."
    assert "OWNER_GROUP_NOT_IN_ROSTER" not in {r.code for r in first.risk.reasons}


def test_review_overdue(fleet):
    fleet.records = [benign(reviewBy="2020-01-31")]
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.review_overdue is True and [r.code for r in agent.risk.reasons] == ["REVIEW_OVERDUE"]
    fleet.records = [benign(reviewBy=None)]
    assert fleet.agents()["recAgent0001"].flags.review_overdue is False


def test_a_detected_only_agent_is_unmanaged_and_its_ownership_is_unknown(fleet):
    fleet.records = []
    agent = fleet.agents()["travel_agent-AbCdEf1234"]
    assert agent.flags.model_dump() == {
        "unmanaged": True,
        "ownerless": None,
        "review_overdue": None,
        "inactive": False,
        "contained": False,
    }
    assert [(r.code, r.severity, r.detail) for r in agent.risk.reasons] == [
        ("UNREGISTERED", "high", "The agent has no registration.")
    ]
    assert agent.risk.level == "high"


def test_inactive_comes_from_one_metric_request_per_cell_account(fleet):
    fleet.control.runtimes = [rich_bundle(), rich_bundle(ORPHAN_RUNTIME_ARN), rich_bundle(RUNTIME_ARN + "x")]
    fleet.cloudwatch.responses["get_metric_data"] = invoked(1)
    fleet.cloudwatch.calls.clear()
    agents = fleet.agents()
    assert agents["recAgent0001"].flags.inactive is True and agents["recAgent0001"].last_invoked_on is None
    assert agents["orphan_agent-ZyXwVu9876"].flags.inactive is False
    assert [name for name, _ in fleet.cloudwatch.calls].count("paginate:get_metric_data") == 1
    assert "INACTIVE" in [r.code for r in agents["recAgent0001"].risk.reasons]


def test_inactive_is_unknown_when_the_metric_cannot_be_read(fleet):
    fleet.cloudwatch.responses["get_metric_data"] = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetMetricData"
    )
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.inactive is None and "INACTIVE" not in [r.code for r in agent.risk.reasons]


def test_inactive_days_is_configurable_and_validated(fleet):
    from portal_api.config import ConfigError

    assert load_settings({**BASE_ENV, "PORTAL_INACTIVE_DAYS": "7"}).inactive_days == 7
    assert load_settings(BASE_ENV).inactive_days == 30
    for bad in ("0", "366", "soon"):
        with pytest.raises(ConfigError, match="PORTAL_INACTIVE_DAYS"):
            load_settings({**BASE_ENV, "PORTAL_INACTIVE_DAYS": bad})
    with pytest.raises(ConfigError, match="PORTAL_OWNER_GROUPS"):
        load_settings({**BASE_ENV, "PORTAL_OWNER_GROUPS": '{"a": 1}'})


def test_contained_flag_follows_the_runtime_and_does_not_change_the_risk(fleet):
    fleet.control.runtimes = [rich_bundle(contained=True)]
    agent = fleet.agents()["recAgent0001"]
    assert agent.flags.contained is True and agent.risk.level == "low"
    fleet.control.runtimes = [rich_bundle(contained=None)]
    assert fleet.agents()["recAgent0001"].flags.contained is None


def test_risk_uses_gateway_policy_guardrail_evaluation_and_cell_health(fleet):
    def codes() -> list[str]:
        return [r.code for r in fleet.agents()["recAgent0001"].risk.reasons]

    fleet.control.gateways = [gateway_bundle(None)]
    assert codes() == ["GATEWAY_POLICY_NONE"]
    fleet.control.gateways = [gateway_bundle("LOG_ONLY")]
    assert codes() == ["GATEWAY_POLICY_LOG_ONLY"]
    fleet.control.gateways = [gateway_bundle("ENFORCE")]
    fleet.control.runtimes = [rich_bundle(guardrailConfigured=False)]
    assert codes() == ["GUARDRAIL_NOT_CONFIGURED"]
    (reason,) = fleet.agents()["recAgent0001"].risk.reasons
    assert (reason.severity, reason.detail) == (
        "medium",
        "The Runtime's configuration names neither a guardrail nor the inference gateway.",
    )
    fleet.control.runtimes = [rich_bundle()]
    fleet.records = [benign(evaluation={"verdict": "failed"})]
    assert codes() == ["EVALUATION_FAILED"]
    fleet.records = [benign(evaluation=None)]
    assert codes() == ["EVALUATION_NOT_RUN"]
    fleet.records = [benign(riskClass="high", dataClassification="restricted")]
    assert codes() == ["RISK_CLASS_HIGH", "DATA_RESTRICTED"]
    fleet.records = [benign()]
    fleet.cloudwatch.responses["describe_alarms"] = [{"MetricAlarms": [{"AlarmName": "a", "StateValue": "ALARM"}]}]
    agent = fleet.agents()["recAgent0001"]
    assert (agent.risk.level, [r.code for r in agent.risk.reasons]) == ("high", ["CELL_HEALTH_CRITICAL"])


def test_inference_gateway_coverage_reaches_the_risk_through_the_runtime_read(monkeypatch):
    """End to end from GetAgentRuntime: gateway only is covered, neither is not, unreadable is unknown."""
    from portal_api.mappers import agents as agent_mapper

    def runtime_with(env: dict[str, str] | None, readable: bool = True) -> Any:
        client = _runtime_client(env)
        if not readable:
            client.responses["get_agent_runtime"] = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "GetAgentRuntime"
            )
        (bundle,) = agentcore.list_runtimes(client)
        return agent_mapper.runtime_from_bundle(bundle, load_settings(BASE_ENV).cells[0])

    gateway_only = runtime_with({"AGENTCORE_INFERENCE_GATEWAY_URL": "https://inference.example.com"})
    neither = runtime_with({"AGENTCORE_MEMORY_ID": "mem-1"})
    unreadable = runtime_with(None, readable=False)
    assert (gateway_only.guardrail_configured, neither.guardrail_configured, unreadable.guardrail_configured) == (
        True,
        False,
        None,
    )
    from portal_api import risk

    def reasons(runtime: Any) -> list[str]:
        facts = risk.RiskFacts(guardrail_configured=runtime.guardrail_configured)
        return [r.code for r in risk.assess(facts).reasons]

    assert reasons(gateway_only) == [] and reasons(unreadable) == []
    assert reasons(neither) == ["GUARDRAIL_NOT_CONFIGURED"]


def test_an_agent_with_no_linked_gateway_gets_no_gateway_reason(fleet):
    fleet.records = [benign(gatewayArn=None)]
    assert [r.code for r in fleet.agents()["recAgent0001"].risk.reasons] == []


def test_fleet_summary_counts(discovery):
    discovery.control.runtimes = [rich_bundle(), rich_bundle(ORPHAN_RUNTIME_ARN, contained=True)]
    discovery.summaries = [summary(RUNTIME_ARN, "recDetect0001"), summary(OUTSIDE_ARN, "recDetect0003")]
    discovery.records = [
        tool_record("tool-echo"),
        agent_record(),
        agent_record(
            "DRAFT",
            record_id="recAgent0002",
            agentId="other-agent",
            runtimeArn=None,
            gatewayArn=None,
            sponsor=None,
            contact=None,
            reviewBy="2020-01-01",
        ),
    ]
    discovery.service.cache.clear()
    summary_ = discovery.service.fleet_summary()
    assert summary_.agents_total == 4
    assert summary_.by_inventory_state == {"registered_and_detected": 1, "registered_only": 1, "detected_only": 2}
    assert summary_.by_lifecycle == {"approved": 1, "proposed": 1, "discovered": 2}
    assert sum(summary_.by_risk_level.values()) == 4 and set(summary_.by_risk_level) == {
        "low",
        "medium",
        "high",
        "critical",
    }
    # The two detected-only agents are unregistered (high). The draft has an owner group, so it is only
    # waiting for approval and overdue for review (medium), and the tile still counts it as unmanaged.
    assert (summary_.by_risk_level["high"], summary_.by_risk_level["medium"]) == (2, 2)
    assert summary_.flags == {"unmanaged": 3, "ownerless": 0, "review_overdue": 1, "inactive": 2, "contained": 1}
    assert [a.agent_id for a in summary_.needs_attention] == ["orphan_agent-ZyXwVu9876", "shadow_agent-QwErTy5678"]
    assert summary_.flags_unknown == {
        "unmanaged": 0,
        "ownerless": 2,
        "review_overdue": 2,
        "inactive": 2,
        "contained": 2,
    }
    assert (summary_.gateways_total, summary_.gateways_by_policy_mode) == (1, {"enforce": 1, "log_only": 0, "none": 0})
    assert (summary_.organization_registry, summary_.unreachable_cells, summary_.inactive_days) == ("ok", 1, 30)
