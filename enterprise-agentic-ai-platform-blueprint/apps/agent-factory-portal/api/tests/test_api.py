# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""End-to-end through the Lambda handler with API Gateway HTTP API (payload v2) events."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from portal_api import deps
from portal_api.app import create_app
from portal_api.aws import agentcore, registry
from portal_api.config import get_settings
from tests import tokens
from tests.conftest import (
    CELL_ACCOUNT,
    ENGINE_ARN,
    GATEWAY_URL,
    ORPHAN_RUNTIME_ARN,
    OTHER_ACCOUNT,
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
from tests.fakes import FakeDynamo

PLATFORM_CLAIMS = {
    "sub": "user-1",
    "email": "admin@example.com",
    "email_verified": "true",  # as API Gateway passes a boolean claim
    "cognito:groups": "[platform-admins devs]",
}
VIEWER_CLAIMS = {
    "sub": "user-2",
    "email": "viewer@example.com",
    "email_verified": "true",
    "cognito:groups": '["viewers"]',
}
ALL_DATA_PATHS = [
    "/users/me",
    "/agents",
    "/agents/export",
    "/fleet/summary",
    "/agents/recAgent0001",
    "/agents/recAgent0001/runtime",
    "/agents/recAgent0001/deployments",
    "/agents/recAgent0001/traces",
    "/agents/recAgent0001/metrics",
    "/agents/recAgent0001/evals/runs",
    "/agents/recAgent0001/mcp-grants",
    "/agents/recAgent0001/containment",
    "/agents/recAgent0001/evidence",
    "/mcp-servers",
    "/mcp-servers/ws1-tools-abcdefghij",
    "/mcp-servers/ws1-tools-abcdefghij/policies",
    "/mcp-servers/ws1-tools-abcdefghij/policy-enforcement",
    "/mcp-servers/ws1-tools-abcdefghij/grants",
    "/governance-graph",
    "/principals/travel-owners",
    "/governance-graph/principals/travel-owners",
    "/observability/settings",
    "/observability/metrics",
    "/guardrails",
    "/guardrails/aaa111",
    "/fleet/health",
    "/catalog/models",
    "/catalog/tools",
]


def event(
    path: str,
    method: str = "GET",
    claims: dict[str, Any] | None = None,
    query: str = "",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "accountId": "111111111111",
        "apiId": "api",
        "domainName": "api.example.com",
        "http": {
            "method": method,
            "path": f"/api/v1{path}",
            "protocol": "HTTP/1.1",
            "sourceIp": "192.0.2.1",
            "userAgent": "pytest",
        },
        "requestId": "request-1",
        "routeKey": "$default",
        "stage": "$default",
    }
    all_headers = {"host": "api.example.com", **(headers or {})}
    if claims is not None:
        # As API Gateway does for a request whose token its authorizer accepted: the claims in the
        # context, and the token itself still in the header. Every function ignores the context and
        # verifies the token.
        context["authorizer"] = {"jwt": {"claims": claims, "scopes": []}}
        all_headers.setdefault("authorization", f"Bearer {tokens.for_claims(claims)}")
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": f"/api/v1{path}",
        "rawQueryString": query,
        "headers": all_headers,
        "requestContext": context,
        "isBase64Encoded": False,
    }


def _query_results(rows: list[dict[str, str]]) -> dict[str, Any]:
    return {"status": "Complete", "results": [[{"field": k, "value": v} for k, v in row.items()] for row in rows]}


@pytest.fixture
def backend(monkeypatch: pytest.MonkeyPatch):
    """A service wired to fakes: one registered agent, one discovered runtime, one gateway."""
    records = [tool_record("tool-echo"), agent_record()]
    monkeypatch.setattr(registry, "list_records", lambda client, registry_id: records)

    def runtimes(client: Any) -> list[dict[str, Any]]:
        return client.runtimes

    def gateways(client: Any) -> list[dict[str, Any]]:
        return client.gateways

    monkeypatch.setattr(agentcore, "list_runtimes", runtimes)
    monkeypatch.setattr(agentcore, "list_gateways", gateways)

    control = FakeClient(
        {
            "list_agent_runtime_versions": [
                {
                    "agentRuntimes": [
                        {
                            "agentRuntimeId": "travel_agent-AbCdEf1234",
                            "agentRuntimeVersion": "2",
                            "status": "READY",
                            "lastUpdatedAt": T0,
                        }
                    ]
                }
            ],
            "list_policies": [
                {
                    "policies": [
                        {
                            "policyId": "p1",
                            "name": "allow_echo",
                            "status": "ACTIVE",
                            "definition": {"cedar": {"statement": "permit(principal, action, resource);"}},
                        }
                    ]
                }
            ],
        }
    )
    control.runtimes = [runtime_bundle(), runtime_bundle(ORPHAN_RUNTIME_ARN, tags={}, gateway_url=GATEWAY_URL)]
    control.gateways = [gateway_bundle("LOG_ONLY")]

    def query_results(queryId: str) -> dict[str, Any]:  # noqa: N803 - mirrors the API parameter
        return _query_results(
            [
                {
                    "traceId": "trace-1",
                    "start_ns": "1768478400" + "000000500",
                    "duration_ns": "2000000000",
                    "total_tokens": "100",
                    "http_status": "200",
                    "error_spans": "0",
                    "day": "2026-01-15 00:00:00.000",
                    "tokens": "100",
                    "traces": "1",
                    "model": "model-a",
                    "input_tokens": "60",
                    "output_tokens": "40",
                    "user_id": "u1",
                    "resource_id": f"{RUNTIME_ARN}/runtime-endpoint/DEFAULT:DEFAULT",
                }
            ]
        )

    cell_logs = FakeClient({"start_query": {"queryId": "q"}, "get_query_results": query_results})
    day = dt.datetime.now(dt.UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    cell_cloudwatch = FakeClient(
        {
            "get_metric_data": [
                {
                    "MetricDataResults": [
                        {"Id": "m_invocations", "Timestamps": [day], "Values": [5.0]},
                        {"Id": "r0_invocations", "Timestamps": [day], "Values": [5.0]},
                        {"Id": "r1_invocations", "Timestamps": [day], "Values": [2.0]},
                    ]
                }
            ],
            "describe_alarms": [{"MetricAlarms": [{"AlarmName": "a", "StateValue": "OK"}]}],
        }
    )
    codepipeline = FakeClient(
        {
            "list_pipeline_executions": {
                "pipelineExecutionSummaries": [
                    {
                        "pipelineExecutionId": "exec-1",
                        "status": "Succeeded",
                        "startTime": T0,
                        "lastUpdateTime": T0,
                        "sourceRevisions": [{"revisionId": "rev-1"}],
                    }
                ]
            },
            "list_action_executions": [
                {
                    "actionExecutionDetails": [
                        {"actionName": "Synth", "status": "Succeeded"},
                        {"actionName": "EvaluationGate", "status": "Succeeded", "startTime": T0, "lastUpdateTime": T0},
                    ]
                }
            ],
        }
    )
    bedrock = FakeClient(
        {
            "list_guardrails": [
                {
                    "guardrails": [
                        {
                            "id": "aaa111",
                            "arn": "arn:aws:bedrock:eu-west-1:111111111111:guardrail/aaa111",
                            "name": "baseline",
                            "status": "READY",
                            "version": "DRAFT",
                            "createdAt": T0,
                            "updatedAt": T0,
                        },
                        {
                            "id": "bbb222",
                            "arn": "arn:aws:bedrock:eu-west-1:111111111111:guardrail/bbb222",
                            "name": "other",
                            "status": "READY",
                            "version": "DRAFT",
                            "createdAt": T0,
                            "updatedAt": T0,
                        },
                    ]
                }
            ],
            "list_tags_for_resource": lambda resourceARN: {  # noqa: N803
                "tags": [{"key": "agenticai:blueprint", "value": "true"}] if resourceARN.endswith("aaa111") else []
            },
            "get_guardrail": {
                "guardrailId": "aaa111",
                "name": "baseline",
                "status": "READY",
                "version": "DRAFT",
                "createdAt": T0,
                "updatedAt": T0,
            },
        }
    )
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "AssumeRole")
    clients = FakeClients(
        {
            ("platform", "agent-registry-control"): FakeClient(),
            ("platform", "codepipeline"): codepipeline,
            ("platform", "bedrock"): bedrock,
            ("platform", "dynamodb"): FakeDynamo(),
            (CELL_ACCOUNT, "bedrock-agentcore-control"): control,
            (CELL_ACCOUNT, "logs"): cell_logs,
            (CELL_ACCOUNT, "cloudwatch"): cell_cloudwatch,
            (OTHER_ACCOUNT, "bedrock-agentcore-control"): denied,
            (OTHER_ACCOUNT, "cloudwatch"): denied,
        }
    )
    service = make_service(get_settings(), clients)
    return service, clients


@pytest.fixture
def call(backend):
    from mangum import Mangum

    service, _ = backend
    app = create_app()
    app.dependency_overrides[deps.get_service] = lambda: service
    handler = Mangum(app, lifespan="off")

    def invoke(path: str, method: str = "GET", claims: dict[str, Any] | None = PLATFORM_CLAIMS, **kwargs: Any):
        response = handler(event(path, method, claims, **kwargs), None)
        try:
            body = json.loads(response["body"]) if response.get("body") else None
        except ValueError:
            body = response["body"]
        return response["statusCode"], body, {k.lower(): v for k, v in response.get("headers", {}).items()}

    return invoke


# --- authentication, authorization, methods, configuration --------------------


def test_health_is_unauthenticated_and_returns_no_data(call):
    status, body, _ = call("/health", claims=None)
    assert (status, body) == (200, {"status": "ok"})


@pytest.mark.parametrize("path", ALL_DATA_PATHS)
def test_every_data_endpoint_requires_validated_claims(call, path):
    status, body, _ = call(path, claims=None)
    assert (status, body) == (401, {"detail": "Not authenticated"})


@pytest.mark.parametrize("path", ALL_DATA_PATHS)
def test_every_data_endpoint_refuses_an_identity_without_a_mapped_group(call, path):
    status, body, _ = call(path, claims={"sub": "user-3", "cognito:groups": "[strangers]"})
    assert status == 403
    assert body == {"detail": "No portal role is assigned to this identity"}


@pytest.mark.parametrize("path", ALL_DATA_PATHS)
def test_every_data_endpoint_answers_a_mapped_reader(call, path):
    query = "scope=tenant" if path == "/observability/metrics" else ""
    status, _, _ = call(path, claims=VIEWER_CLAIMS, query=query)
    assert status == 200


def test_platform_scope_is_403_below_the_platform_role(call):
    status, body, _ = call("/observability/metrics", claims=VIEWER_CLAIMS, query="scope=platform")
    assert (status, body) == (403, {"detail": "The platform scope requires the platform role"})
    assert call("/observability/metrics", claims=VIEWER_CLAIMS)[0] == 403  # platform is the default scope
    assert call("/observability/metrics", query="scope=platform")[0] == 200


def test_stage_parameter_is_honoured(call):
    assert call("/agents/recAgent0001/runtime", query="stage=nonprod")[1]["status"] == "ready"
    other = call("/agents/recAgent0001/runtime", query="stage=prod")[1]
    assert (other["stage"], other["status"], other["runtime_arn"]) == ("prod", "not_deployed", None)
    assert len(call("/agents/recAgent0001/deployments", query="stage=nonprod&limit=25")[1]) == 1
    assert call("/agents/recAgent0001/deployments", query="stage=prod")[1] == []
    assert call("/agents/recAgent0001/runtime", query="stage=a%20b")[0] == 422


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@pytest.mark.parametrize("path", ["/agents", "/agents/recAgent0001", "/mcp-servers/x/policies", "/health", "/nope"])
def test_non_get_is_405(call, method, path):
    status, _, headers = call(path, method=method)
    assert status == 405
    assert headers["allow"] == "GET"


def test_unknown_path_is_404(call):
    assert call("/nope")[0] == 404


def test_cors_preflight_is_answered_for_an_allowed_origin_only(call):
    preflight = {"origin": "https://portal.example.com", "access-control-request-method": "GET"}
    status, _, headers = call("/agents", method="OPTIONS", claims=None, headers=preflight)
    assert status == 200 and headers["access-control-allow-origin"] == "https://portal.example.com"
    status, _, headers = call(
        "/agents", method="OPTIONS", claims=None, headers={**preflight, "origin": "https://evil.example.com"}
    )
    assert status == 400 and "access-control-allow-origin" not in headers
    status, _, _ = call(
        "/agents", method="OPTIONS", claims=None, headers={**preflight, "access-control-request-method": "POST"}
    )
    assert status == 400


@pytest.mark.parametrize(
    "name", ["PORTAL_CELLS", "PORTAL_GROUP_ROLE_MAP", "PORTAL_REGISTRY_ID", "PORTAL_IDENTITY_PROVIDER"]
)
def test_missing_configuration_fails_closed_with_500(call, monkeypatch, caplog, name):
    monkeypatch.delenv(name)
    status, body, _ = call("/agents")
    assert status == 500
    assert body == {"detail": f"Portal configuration error: {name} is not set"}
    assert name in caplog.text
    assert call("/health", claims=None)[0] == 200


def test_dev_headers_are_ignored_unless_dev_auth_is_enabled(call, monkeypatch):
    headers = {"x-portal-dev-user": "dev@example.com", "x-portal-dev-groups": "platform-admins"}
    assert call("/users/me", claims=None, headers=headers)[0] == 401
    monkeypatch.setenv("PORTAL_DEV_AUTH", "1")
    status, body, _ = call("/users/me", claims=None, headers=headers)
    assert status == 200 and body["portal_role"] == "platform"
    assert call("/users/me", claims=None, headers={"x-portal-dev-user": "dev@example.com"})[0] == 403
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "portal-api")
    assert call("/users/me", claims=None, headers=headers)[0] == 401


def test_entra_claims_when_configured(call, monkeypatch):
    tenant = "00000000-0000-0000-0000-000000000000"
    issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
    monkeypatch.setenv("PORTAL_IDENTITY_PROVIDER", "entra")
    monkeypatch.setenv("PORTAL_JWT_ISSUER", issuer)
    monkeypatch.setenv("PORTAL_JWT_AUDIENCE", '["api://portal"]')
    monkeypatch.setenv("PORTAL_JWKS_URL", f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys")
    claims = {"oid": "oid-1", "preferred_username": "sec@example.com", "name": "Sec", "roles": ["sec"]}
    # An ID token as Microsoft Entra ID issues one: its own issuer and audience, and no token_use.
    token = tokens.sign(claims, iss=issuer, aud="api://portal", token_use=...)
    status, body, _ = call("/users/me", claims=None, headers={"authorization": f"Bearer {token}"})
    assert status == 200
    assert (body["email"], body["role"], body["role_level"], body["oid"], body["name"]) == (
        "sec@example.com",
        "operator",
        1,
        "oid-1",
        "Sec",
    )
    assert call("/users/me", claims=PLATFORM_CLAIMS)[0] == 401  # no oid in a Cognito token


@pytest.mark.parametrize("path", ["/agents/a%22b", "/agents/a%20b/runtime", "/mcp-servers/a;b", "/guardrails/UPPER"])
def test_path_identifiers_are_allow_listed(call, path):
    assert call(path)[0] == 422


# --- data ---------------------------------------------------------------------------


def test_current_user_shape(call):
    status, body, _ = call("/users/me")
    assert status == 200
    assert body == {
        "email": "admin@example.com",
        "role": "admin",
        "role_level": 2,
        "can_deploy": False,
        "oid": "user-1",
        "name": "admin@example.com",
        "tenants": [
            {"id": "ws1", "name": "ws1", "line_of_business": "", "stages": {}},
            {"id": "ws2", "name": "ws2", "line_of_business": "", "stages": {}},
        ],
        "portal_role": "platform",
        "groups": ["platform-admins", "devs"],
        "identity_provider": "cognito",
        "read_only": True,
        "can_register": True,
        "can_approve": True,
        "can_contain": True,
        "can_release": True,
        "authorities": ["registrar", "approver"],
        "registration_tenants": ["*"],
    }


def test_current_user_registration_authorities(call, monkeypatch):
    def me(groups: str) -> dict:
        return call("/users/me", claims={"sub": "u", "cognito:groups": groups})[1]

    developer = me("[devs devs2]")
    assert (developer["can_register"], developer["can_approve"], developer["registration_tenants"]) == (
        True,
        False,
        ["ws1", "ws2"],
    )
    approver = me("[approvers]")
    assert (approver["can_register"], approver["can_approve"], approver["registration_tenants"]) == (
        False,
        True,
        ["ws1"],
    )
    assert (developer["authorities"], approver["authorities"]) == (["registrar"], ["approver"])
    viewer = me("[viewers]")
    assert viewer["authorities"] == []
    assert [
        (me(g)["can_contain"], me(g)["can_release"])
        for g in ("[sec]", "[platform-admins]", "[sre-team]", "[devs]", "[viewers]")
    ] == [
        (True, True),
        (True, True),
        (True, False),
        (False, False),
        (False, False),
    ]
    assert (viewer["can_register"], viewer["can_approve"], viewer["registration_tenants"]) == (False, False, [])
    monkeypatch.delenv("PORTAL_GROUP_TENANT_MAP")
    assert me("[devs]")["registration_tenants"] is None
    assert me("[platform-admins]")["registration_tenants"] == ["*"]


def test_agents_merge_registry_records_and_discovered_runtimes(call):
    status, body, _ = call("/agents")
    assert status == 200
    by_id = {a["id"]: a for a in body}
    assert set(by_id) == {"recAgent0001", "orphan_agent-ZyXwVu9876"}
    registered, discovered = by_id["recAgent0001"], by_id["orphan_agent-ZyXwVu9876"]
    assert (registered["registration"], registered["lifecycle_state"], registered["runtime_status"]) == (
        "registered",
        "approved",
        "ready",
    )
    assert registered["agent_arn"] == RUNTIME_ARN
    assert registered["governance"]["owner_group"] == "travel-owners"
    assert (discovered["registration"], discovered["lifecycle_state"]) == ("discovered", "discovered")
    assert discovered["mcp_server_ids"] == ["ws1-tools-abcdefghij"]
    assert call("/agents", query="lifecycle_state=discovered")[1] == [discovered]
    assert call("/agents/unknown-agent")[0:2] == (404, {"detail": "Agent not found"})


def test_agent_name_is_the_agent_id_and_the_record_name_is_kept(call):
    registered = {a["id"]: a for a in call("/agents")[1]}["recAgent0001"]
    assert (registered["name"], registered["record_name"]) == ("travel-agent", "agent-ws1-travel-agent-nonprod")
    assert call("/agents/recAgent0001")[1]["name"] == "travel-agent"
    graph = call("/governance-graph")[1]
    assert next(n for n in graph["nodes"] if n["id"] == "agent:recAgent0001")["label"] == "travel-agent"


def test_separate_agent_registry(call, backend, monkeypatch):
    """With PORTAL_AGENT_REGISTRY_ID set, agent records come from it and tool records from PORTAL_REGISTRY_ID."""
    service, _ = backend
    stray_agent = agent_record(record_id="recStray0001", agentId="stray-agent", runtimeArn=None, gatewayArn=None)
    by_registry = {
        "REGISTRYID000001": [tool_record("tool-echo"), stray_agent],
        "AGENTREGISTRY001": [agent_record(), tool_record("tool-stray")],
    }
    seen: list[str] = []

    def list_records(client, registry_id):
        seen.append(registry_id)
        return by_registry[registry_id]

    monkeypatch.setattr(registry, "list_records", list_records)

    # Unset: one registry holds both kinds of record, exactly as before.
    assert [t["tool_id"] for t in call("/catalog/tools")[1]] == ["tool-echo"]
    assert {a["id"] for a in call("/agents")[1]} == {
        "recStray0001",
        "travel_agent-AbCdEf1234",
        "orphan_agent-ZyXwVu9876",
    }
    assert set(seen) == {"REGISTRYID000001"}

    monkeypatch.setenv("PORTAL_AGENT_REGISTRY_ID", "AGENTREGISTRY001")
    service.settings = get_settings()
    service.cache.clear()
    seen.clear()
    agents = {a["id"]: a for a in call("/agents")[1]}
    assert set(agents) == {"recAgent0001", "orphan_agent-ZyXwVu9876"}  # the stray agent record is not read
    assert agents["recAgent0001"]["registration"] == "registered"
    assert [t["tool_id"] for t in call("/catalog/tools")[1]] == ["tool-echo"]  # not tool-stray
    tools = call("/mcp-servers/ws1-tools-abcdefghij")[1]["available_tools"]
    assert (tools[0]["name"], tools[0]["registered"]) == ("tool-echo", True)
    graph = call("/governance-graph")[1]
    assert "group:travel-owners" in {n["id"] for n in graph["nodes"]}
    assert call("/principals/travel-owners")[0] == 200
    granted = sorted(g["principal_id"] for g in call("/mcp-servers/ws1-tools-abcdefghij/grants")[1])
    assert granted == ["orphan_agent-ZyXwVu9876", "recAgent0001"]
    assert [r["record_id"] for r in call("/registrations")[1]] == ["recAgent0001"]
    assert set(seen) == {"REGISTRYID000001", "AGENTREGISTRY001"}
    assert seen.count("REGISTRYID000001") == 1  # the tool records are cached across these calls


def test_agent_registry_id_is_validated(call, monkeypatch):
    monkeypatch.setenv("PORTAL_AGENT_REGISTRY_ID", "not a registry id")
    status, body, _ = call("/agents")
    assert (status, body) == (
        500,
        {"detail": "Portal configuration error: PORTAL_AGENT_REGISTRY_ID is missing or malformed"},
    )
    monkeypatch.setenv("PORTAL_AGENT_REGISTRY_ID", "")
    assert call("/agents")[0] == 200


def test_agent_runtime_deployments_and_grants(call):
    assert call("/agents/recAgent0001/runtime")[1]["status"] == "ready"
    deployments = call("/agents/recAgent0001/deployments")[1]
    assert [(d["image_tag"], d["outcome"], d["stage"]) for d in deployments] == [("v2", "succeeded", "nonprod")]
    grants = call("/agents/recAgent0001/mcp-grants")[1]
    assert [(g["mcp_id"], g["source"], g["tool_ids"]) for g in grants] == [
        ("ws1-tools-abcdefghij", "registry", ["tool-echo"])
    ]
    assert [g["source"] for g in call("/agents/orphan_agent-ZyXwVu9876/mcp-grants")[1]] == ["runtime_env"]


def test_agent_traces_and_metrics(call, backend):
    status, body, _ = call("/agents/recAgent0001/traces", query="page=1&limit=10")
    assert status == 200
    assert body["total"] == 1 and body["warnings"] == []
    assert body["data"][0]["id"] == "trace-1" and body["data"][0]["latency_ms"] == 2000.0
    _, clients = backend
    started = [kw for name, kw in clients.clients[(CELL_ACCOUNT, "logs")].calls if name == "start_query"]
    assert started[0]["logGroupName"] == "aws/spans"
    assert f'like "{RUNTIME_ARN}/"' in started[0]["queryString"]

    status, metrics, _ = call("/agents/recAgent0001/metrics")
    assert status == 200
    assert metrics["totals"] == {"traces": 5, "cost_usd": 0.0, "tokens": 100}
    assert metrics["by_model"] == [{"model": "model-a", "cost_usd": 0.0, "tokens": 100}]
    assert metrics["runtime"]["invocations"] == 5 and metrics["cost_available"] is False
    assert call("/agents/recAgent0001/metrics", query="date_from=2026-01-01&date_to=2026-03-01")[0] == 400
    assert call("/agents/recAgent0001/metrics", query="date_from=yesterday")[0] == 400


def test_release_evidence(call):
    body = call("/agents/recAgent0001/evals/runs")[1]
    assert [(r["run_id"], r["status"], r["git_sha"]) for r in body["runs"]] == [("exec-1", "passed", "rev-1")]
    assert body["runs"][0]["pipeline"]["pipeline_name"] == "agenticai-workload-ws1-travel-agent"
    orphan = call("/agents/orphan_agent-ZyXwVu9876/evals/runs")[1]
    assert orphan["runs"] == [] and orphan["warnings"]


def test_mcp_servers_policies_and_grants(call):
    servers = call("/mcp-servers")[1]
    assert [s["id"] for s in servers] == ["ws1-tools-abcdefghij"]
    assert servers[0]["cedar_enforcement_mode"] == "log_only"
    assert servers[0]["available_tools"][0]["registered"] is True
    policies = call("/mcp-servers/ws1-tools-abcdefghij/policies")[1]
    assert policies["enforcement_mode"] == "log_only" and policies["editable"] is False
    assert policies["policies"][0]["cedar_text"] == "permit(principal, action, resource);"
    assert call("/mcp-servers/ws1-tools-abcdefghij/policy-enforcement")[1] == {
        "enforcement_mode": "log_only",
        "engine_id": ENGINE_ARN.rsplit("/", 1)[-1],
        "detail": None,
    }
    grants = call("/mcp-servers/ws1-tools-abcdefghij/grants")[1]
    assert sorted(g["principal_id"] for g in grants) == ["orphan_agent-ZyXwVu9876", "recAgent0001"]
    assert call("/mcp-servers/unknown")[0:2] == (404, {"detail": "MCP server not found"})


def test_governance_graph_and_principal(call):
    graph = call("/governance-graph")[1]
    assert {n["type"] for n in graph["nodes"]} == {"group", "agent", "mcp"}
    assert {e["type"] for e in graph["edges"]} == {"access", "can_call"}
    assert all(e["has_policy"] for e in graph["edges"] if e["type"] == "can_call")
    assert call("/principals/travel-owners")[1]["kind"] == "group"
    assert call("/governance-graph/principals/travel-owners", query="kind=group")[0] == 200
    assert call("/principals/travel-owners", query="kind=user")[0] == 404
    assert call("/principals/nobody")[0] == 404


def test_observability(call):
    assert call("/observability/settings")[1]["backend"] == "cloudwatch"
    body = call("/observability/metrics", query="scope=platform")[1]
    assert body["totals"]["traces"] == 7
    assert {row["agent_id"]: row["totals"]["traces"] for row in body["by_agent"]} == {
        "recAgent0001": 5,
        "orphan_agent-ZyXwVu9876": 2,
    } or {row["totals"]["traces"] for row in body["by_agent"]} == {5, 2}
    assert call("/observability/metrics", query="scope=galaxy")[0] == 422


def test_guardrails(call):
    listed = call("/guardrails")[1]
    assert [g["template_id"] for g in listed] == ["aaa111"]
    assert listed[0]["status"] == "active" and listed[0]["read_only"] is True
    assert call("/guardrails/aaa111")[1]["guardrail_id"] == "aaa111"
    assert call("/guardrails/bbb222")[0] == 404  # exists, but is not tagged for the blueprint
    assert call("/guardrails", query="status=failed")[1] == []


def test_guardrails_without_a_configured_tag_lists_every_guardrail(call, backend, monkeypatch):
    monkeypatch.setenv("PORTAL_GUARDRAIL_TAG_KEY", "")
    monkeypatch.setenv("PORTAL_GUARDRAIL_TAG_VALUE", "")
    service, clients = backend
    service.settings = get_settings()
    assert [g["template_id"] for g in call("/guardrails")[1]] == ["aaa111", "bbb222"]
    assert "list_tags_for_resource" not in [name for name, _ in clients.clients[("platform", "bedrock")].calls]


def test_fleet_health_and_catalogue(call):
    fleet = call("/fleet/health")[1]
    assert [(c["tenant_id"], c["state"], c["reachable"]) for c in fleet["cells"]] == [
        ("ws1", "healthy", True),
        ("ws2", "no_data", False),
    ]
    assert set(fleet["cells"][0]) >= {
        "tenant_id",
        "agent_id",
        "environment",
        "account_alias",
        "region",
        "state",
        "alarms_in_alarm",
        "reachable",
    }
    assert fleet["totals"]["unreachable"] == 1 and "checked_at" in fleet
    assert [c["agent_ref"] for c in fleet["cells"]] == ["recAgent0001", None]
    assert [c["account_alias"] for c in fleet["cells"]] == ["account-4444", "account-7777"]
    assert call("/catalog/models")[1] == [
        {
            "model_id": "anthropic.claude-haiku-4-5-20251001-v1:0",
            "provider": "anthropic",
            "regions": ["eu-west-1"],
            "status": "approved",
        },
        {"model_id": "eu.amazon.nova-pro-v1:0", "provider": "amazon", "regions": ["eu-west-1"], "status": "approved"},
    ]
    tools = call("/catalog/tools")[1]
    assert [t["tool_id"] for t in tools] == ["tool-echo"]
    assert set(tools[0]) == {
        "tool_id",
        "name",
        "description",
        "owner",
        "cost_centre",
        "status",
        "version",
        "target_arn",
    }


def raw(backend, path: str, query: str = "", claims: dict | None = PLATFORM_CLAIMS):
    """The handler's raw response, for endpoints that do not answer with JSON."""
    from mangum import Mangum

    service, _ = backend
    app = create_app()
    app.dependency_overrides[deps.get_service] = lambda: service
    response = Mangum(app, lifespan="off")(event(path, "GET", claims, query=query), None)
    return response["statusCode"], response["body"], {k.lower(): v for k, v in response["headers"].items()}


def test_export_csv(backend, monkeypatch):
    import csv as csv_module
    import io

    from portal_api import export

    hostile = agent_record(
        record_id="recHostile01",
        agentId="hostile-agent",
        runtimeArn=None,
        gatewayArn=None,
        ownerGroup='=HYPERLINK("https://evil.example.com","x")',
        sponsor="+1 555 0100",
        contact='@SUM(1,1), "quoted", and a\nnew line',
    )
    monkeypatch.setattr(
        registry, "list_records", lambda client, registry_id: [tool_record("tool-echo"), agent_record(), hostile]
    )
    status, body, headers = raw(backend, "/agents/export")
    assert status == 200
    assert headers["content-type"] == "text/csv; charset=utf-8"
    assert headers["content-disposition"].startswith('attachment; filename="agents-20') and headers[
        "content-disposition"
    ].endswith('.csv"')
    assert headers["cache-control"] == "no-store"
    rows = list(csv_module.reader(io.StringIO(body)))
    assert tuple(rows[0]) == export.COLUMNS
    assert all(len(row) == len(export.COLUMNS) for row in rows)
    by_id = {row[0]: dict(zip(export.COLUMNS, row, strict=True)) for row in rows[1:]}
    assert set(by_id) == {"recAgent0001", "recHostile01", "orphan_agent-ZyXwVu9876"}

    registered = by_id["recAgent0001"]
    assert (registered["name"], registered["tenant_id"], registered["environment"]) == (
        "travel-agent",
        "ws1",
        "nonprod",
    )
    assert (registered["owner_group"], registered["sponsor"], registered["contact"]) == (
        "travel-owners",
        "Sam Sponsor",
        "travel-owners@example.com",
    )
    assert (registered["risk_class"], registered["data_classification"]) == ("limited", "confidential")
    assert (registered["inventory_state"], registered["detection_sources"], registered["lifecycle_state"]) == (
        "registered_and_detected",
        "cell_reader",
        "approved",
    )
    assert (registered["unmanaged"], registered["ownerless"], registered["review_overdue"]) == (
        "false",
        "false",
        "false",
    )
    assert registered["risk_level"] in ("low", "medium", "high", "critical")
    assert registered["runtime_arn"] == RUNTIME_ARN and registered["region"] == "eu-west-1"
    assert registered["account_alias"] == "account-4444"

    # Formula injection is neutralised and the awkward characters survive a round trip.
    bad = by_id["recHostile01"]
    assert bad["owner_group"] == "'" + '=HYPERLINK("https://evil.example.com","x")'
    assert bad["sponsor"] == "'+1 555 0100"
    assert bad["contact"] == "'" + '@SUM(1,1), "quoted", and a\nnew line'
    assert '"\'=HYPERLINK(""https://evil.example.com"",""x"")"' in body  # quoted, with doubled quotes
    for line in body.split("\r\n"):
        assert not line.startswith(("=", "+", "-", "@"))

    discovered = by_id["orphan_agent-ZyXwVu9876"]
    assert (discovered["owner_group"], discovered["ownerless"], discovered["unmanaged"]) == ("", "", "true")
    assert "UNREGISTERED" in discovered["risk_reasons"].split(";")
    # An account id appears only inside an ARN.
    import re

    for row in rows[1:]:
        for column, value in zip(export.COLUMNS, row, strict=True):
            if column != "runtime_arn":
                assert not re.search(r"\d{12}", value), (column, value)


def test_export_file_name_is_readable_by_a_cross_origin_script(backend):
    from mangum import Mangum

    service, _ = backend
    app = create_app()
    app.dependency_overrides[deps.get_service] = lambda: service
    request = event("/agents/export", "GET", PLATFORM_CLAIMS, headers={"origin": "https://portal.example.com"})
    headers = {k.lower(): v for k, v in Mangum(app, lifespan="off")(request, None)["headers"].items()}
    assert headers["access-control-allow-origin"] == "https://portal.example.com"
    assert "content-disposition" in headers["access-control-expose-headers"].lower()


def test_export_json_and_parameters(backend):
    status, body, headers = raw(backend, "/agents/export", "format=json")
    assert status == 200 and headers["content-type"] == "application/json"
    assert headers["content-disposition"].endswith('.json"')
    rows = json.loads(body)
    assert {row["agent_id"] for row in rows} == {"recAgent0001", "orphan_agent-ZyXwVu9876"}
    first = next(row for row in rows if row["agent_id"] == "recAgent0001")
    assert first["unmanaged"] is False and isinstance(first["risk_reasons"], list)
    # The effective review date and the last review are the last two columns.
    assert list(first)[-2:] == ["review_by", "last_reviewed_at"]
    assert (first["review_by"], first["last_reviewed_at"]) == ("2099-12-31", None)
    assert first["detection_sources"] == ["cell_reader"]
    assert raw(backend, "/agents/export", "format=xlsx")[0] == 422
    assert raw(backend, "/agents/export", claims=None)[0] == 401
    assert raw(backend, "/agents/export", claims={"sub": "x", "cognito:groups": "[strangers]"})[0] == 403


def test_csv_cell_rules():
    from portal_api import export

    assert [export.cell(v) for v in (None, True, False, 3, "plain", ["a", "b"], [])] == [
        "",
        "true",
        "false",
        "3",
        "plain",
        "a;b",
        "",
    ]
    for hostile in ("=1+1", "+1", "-1", "@x", "\tx", "\rx"):
        assert export.cell(hostile) == "'" + hostile
    assert export.cell(["=x", "y"]) == "'=x;y"
    assert export.cell("a=b") == "a=b" and export.cell("x-1") == "x-1"
    text = export.to_csv([{"agent_id": 'a"b', "name": "x,y", "contact": "line1\nline2"}])
    assert text.splitlines()[0] == ",".join(export.COLUMNS)
    assert '"a""b","x,y"' in text and '"line1\nline2"' in text and text.endswith("\r\n")


def test_fleet_summary_endpoint(call):
    status, body, _ = call("/fleet/summary")
    assert status == 200
    assert body["agents_total"] == 2
    assert body["by_inventory_state"] == {"registered_and_detected": 1, "registered_only": 0, "detected_only": 1}
    assert body["by_lifecycle"] == {"approved": 1, "discovered": 1}
    assert (
        set(body["by_risk_level"]) == {"low", "medium", "high", "critical"} and sum(body["by_risk_level"].values()) == 2
    )
    assert (
        set(body["flags"])
        == set(body["flags_unknown"])
        == {"unmanaged", "ownerless", "review_overdue", "inactive", "contained"}
    )
    assert body["flags"]["unmanaged"] == 1
    assert body["gateways_by_policy_mode"] == {"enforce": 0, "log_only": 1, "none": 0, "unknown": 0}
    assert (body["organization_registry"], body["unreachable_cells"]) == ("disabled", 1)
    assert body["review_attestations"] == "ok"
    assert body["warnings"] == ["1 cell account(s) could not be read."]
    urgent = body["needs_attention"]
    assert [a["agent_id"] for a in urgent] == ["orphan_agent-ZyXwVu9876"]
    assert urgent[0]["risk_level"] == "high" and urgent[0]["flags"][0] == "unmanaged"
    assert urgent[0]["reasons"][0] == {
        "code": "UNREGISTERED",
        "severity": "high",
        "detail": "The agent has no registration.",
    }
    assert call("/fleet/summary", claims=None)[0] == 401


def test_agents_carry_flags_and_risk(call):
    agents = {a["id"]: a for a in call("/agents")[1]}
    registered = agents["recAgent0001"]
    assert set(registered["flags"]) == {"unmanaged", "ownerless", "review_overdue", "inactive", "contained"}
    assert registered["flags"]["unmanaged"] is False
    assert (registered["sponsor"], registered["review_by"]) == ("Sam Sponsor", "2099-12-31")
    assert registered["risk"]["level"] in ("low", "medium", "high", "critical")
    assert all(set(r) == {"code", "severity", "detail"} for r in registered["risk"]["reasons"])
    discovered = agents["orphan_agent-ZyXwVu9876"]
    assert discovered["flags"]["unmanaged"] is True and discovered["risk"]["level"] == "high"
    assert (discovered["inventory_state"], discovered["lifecycle_state"]) == ("detected_only", "discovered")


def test_an_unreachable_cell_does_not_fail_the_inventory(call, backend):
    service, _ = backend
    assert call("/agents")[0] == 200
    assert len(service.inventory().unreachable) == 1


def test_upstream_failure_is_a_502_with_the_error_code_only(call, backend, monkeypatch):
    def boom(client, registry_id):
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "account 111111111111"}}, "List")

    monkeypatch.setattr(registry, "list_records", boom)
    status, body, _ = call("/catalog/tools")
    assert (status, body) == (502, {"detail": "An AWS service call failed (ThrottlingException)"})
