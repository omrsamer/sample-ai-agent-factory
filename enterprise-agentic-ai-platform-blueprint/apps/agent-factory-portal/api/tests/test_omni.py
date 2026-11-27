# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CloudWatch Omni hand-off: links, and the agents its Context Graph observes in telemetry."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from mangum import Mangum

from portal_api import deps
from portal_api.app import create_app
from portal_api.aws import agentcore, omni, registry
from portal_api.config import ConfigError, get_settings, load_settings
from portal_api.mappers import omni as omni_mapper
from portal_api.mappers.omni import KnownAgent
from portal_api.models.portal import OmniDomain
from portal_api.routes.omni import own_account_id
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    CELLS,
    ORPHAN_RUNTIME_ARN,
    PLATFORM_ACCOUNT,
    REGION,
    T0,
    FakeClient,
    FakeClients,
    agent_record,
    make_service,
    runtime_bundle,
)
from tests.test_api import event

OMNI_REGION = "us-west-2"
OWN_RUNTIME = f"arn:aws:bedrock-agentcore:{REGION}:{PLATFORM_ACCOUNT}:runtime/platform_agent-AbCdEf1234"
OWN_ORPHAN = f"arn:aws:bedrock-agentcore:{REGION}:{PLATFORM_ACCOUNT}:runtime/unlisted_agent-ZyXwVu9876"
# An agent in the Omni domain's own Region, where the portal has no cell: nobody registered or detected it.
TELEMETRY_ONLY = f"arn:aws:bedrock-agentcore:{OMNI_REGION}:{PLATFORM_ACCOUNT}:runtime/fast_agent-QwErTy5678"
OMNI_URL = "https://d-a1b2c3d4e5.cloudwatch-omni.global.app.aws"
OWN_CELL = {
    "tenantId": "platform",
    "agentId": "platform-agent",
    "environment": "nonprod",
    "accountId": PLATFORM_ACCOUNT,
    "region": REGION,
    "readerRoleArn": f"arn:aws:iam::{PLATFORM_ACCOUNT}:role/agenticai-portal-reader",
    "omniDomainUrl": OMNI_URL,
    "omniRegion": OMNI_REGION,
    "accountAlias": "platform",
}
ENV = {**BASE_ENV, "PORTAL_CELLS": json.dumps([OWN_CELL, CELLS[0], CELLS[1]])}
DOMAIN = OmniDomain(account_alias="platform", region=OMNI_REGION, url=OMNI_URL)


def agent_node(name: str, runtime_arn: str | None, **overrides: Any) -> dict[str, Any]:
    """An agent node as the Context Graph reports it."""
    attributes = {"aws.service.type": "gen_ai_agent", "cloud.platform": "aws_bedrock_agentcore"}
    if runtime_arn:
        attributes["cloud.resource_id"] = f"{runtime_arn}/runtime-endpoint/DEFAULT:DEFAULT"
        attributes["service.name"] = f"{name}.DEFAULT"
    value: dict[str, Any] = {
        "nodeId": f"node-{name}",
        "nodeType": "SERVICE",
        "name": name,
        "alternateNames": [f"{name}.DEFAULT"],
        "nodeProperties": {
            "region": OMNI_REGION,
            "cloudProvider": "aws",
            "sourceAccountId": PLATFORM_ACCOUNT,
            "category": "GEN_AI_AGENT",
            "stage": "bedrock-agentcore:default",
        },
        "telemetryAttributes": attributes,
        "signalTypes": ["TRACES", "METRICS"],
        "firstObservedAt": T0,
        "lastObservedAt": T0,
    }
    value.update(overrides)
    return value


def other_node(name: str, node_type: str, category: str | None) -> dict[str, Any]:
    """Something that is not an agent: a function, compute, a network. Configuration-only nodes report the epoch."""
    properties = {"region": OMNI_REGION, "sourceAccountId": PLATFORM_ACCOUNT}
    if category:
        properties["category"] = category
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)
    return {
        "nodeId": f"node-{name}",
        "nodeType": node_type,
        "name": name,
        "nodeProperties": properties,
        "telemetryAttributes": {},
        "signalTypes": [],
        "firstObservedAt": epoch,
        "lastObservedAt": epoch,
    }


KNOWN = {
    OWN_RUNTIME: KnownAgent("recAgent0001", registered=True, detected=True, inventory_state="registered_and_detected"),
    OWN_ORPHAN: KnownAgent(
        "unlisted_agent-ZyXwVu9876", registered=False, detected=True, inventory_state="detected_only"
    ),
}


# --- mapper -------------------------------------------------------------------------


def test_only_agents_are_listed_and_each_is_matched_against_the_inventory():
    nodes = [
        agent_node("platform_agent", OWN_RUNTIME),
        agent_node("unlisted_agent", OWN_ORPHAN, lastObservedAt=T0 + dt.timedelta(hours=2)),
        agent_node("FAST_stack_FASTAgent", TELEMETRY_ONLY),
        other_node("orders-function", "SERVICE", None),
        other_node("i-0abc", "RESOURCE", "COMPUTE"),
        other_node("a-model", "RESOURCE", "GEN_AI_MODEL"),
        other_node("a-vpc", "RESOURCE", "NETWORK"),
    ]
    services = omni_mapper.observed_services(nodes, KNOWN, DOMAIN)
    assert [s.name for s in services] == ["unlisted_agent", "platform_agent", "FAST_stack_FASTAgent"]
    by_name = {s.name: s for s in services}
    assert by_name["platform_agent"].model_dump() == {
        "name": "platform_agent",
        "node_type": "SERVICE",
        "category": "GEN_AI_AGENT",
        "resource_id": f"{OWN_RUNTIME}/runtime-endpoint/DEFAULT:DEFAULT",
        "runtime_arn": OWN_RUNTIME,
        "region": OMNI_REGION,
        "last_observed_at": "2026-01-15T12:00:00Z",
        "signals": ["TRACES", "METRICS"],
        "registered": True,
        "detected": True,
        "matched_agent_id": "recAgent0001",
        "inventory_state": "registered_and_detected",
        "omni_region": OMNI_REGION,
        "account_alias": "platform",
    }
    detected = by_name["unlisted_agent"]
    assert (detected.registered, detected.detected, detected.inventory_state, detected.matched_agent_id) == (
        False,
        True,
        "detected_only",
        "unlisted_agent-ZyXwVu9876",
    )
    # Seen in telemetry, registered by nobody, detected by nothing: the inventory does not know this agent.
    telemetry_only = by_name["FAST_stack_FASTAgent"]
    assert (telemetry_only.registered, telemetry_only.detected, telemetry_only.matched_agent_id) == (False, False, None)
    assert telemetry_only.inventory_state == "observed_only"
    assert telemetry_only.runtime_arn == TELEMETRY_ONLY  # the UI reads its account and Region from this


def test_a_registration_whose_runtime_nothing_detects_can_still_be_observed():
    known = {
        OWN_RUNTIME: KnownAgent("recAgent0001", registered=True, detected=False, inventory_state="registered_only")
    }
    (service,) = omni_mapper.observed_services([agent_node("platform_agent", OWN_RUNTIME)], known)
    assert (service.registered, service.detected, service.inventory_state) == (True, False, "registered_only")
    assert (service.omni_region, service.account_alias) == (None, None)


def test_runtime_arn_is_cut_from_the_resource_id():
    assert omni_mapper.runtime_arn(f"{OWN_RUNTIME}/runtime-endpoint/DEFAULT:DEFAULT") == OWN_RUNTIME
    assert omni_mapper.runtime_arn(OWN_RUNTIME) == OWN_RUNTIME
    assert omni_mapper.runtime_arn(f"{OWN_RUNTIME}/runtime-endpoint/LIVE:LIVE") == OWN_RUNTIME
    for other in (None, "", "i-0abc", "arn:aws:lambda:us-west-2:111111111111:function:orders", f"x{OWN_RUNTIME}"):
        assert omni_mapper.runtime_arn(other) is None
    # A Runtime whose id merely starts with a known id is a different Runtime.
    (service,) = omni_mapper.observed_services([agent_node("lookalike", f"{OWN_RUNTIME}9")], KNOWN)
    assert (service.matched_agent_id, service.inventory_state) == (None, "observed_only")
    (unnamed,) = omni_mapper.observed_services([agent_node("no-resource", None)], KNOWN)
    assert (unnamed.resource_id, unnamed.runtime_arn, unnamed.inventory_state) == (None, None, "observed_only")


def test_the_epoch_is_never_shown_as_an_observation_time():
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)
    for value in (epoch, epoch.replace(tzinfo=None), "1970-01-01T00:00:00Z", "1970-01-01T00:00:00+00:00", None):
        assert omni_mapper.observed_at(value) is None
    assert omni_mapper.observed_at(T0) == "2026-01-15T12:00:00Z"
    (service,) = omni_mapper.observed_services(
        [agent_node("configured-only", OWN_RUNTIME, lastObservedAt=epoch)], KNOWN
    )
    assert service.last_observed_at is None and "1970" not in service.model_dump_json()


# --- the AWS call, checked against the SDK model ---------------------------------------------------


def test_context_graph_request_asks_for_agents_only_and_matches_the_service_model():
    client = boto3.client(
        "cloudwatchomni", region_name=OMNI_REGION, aws_access_key_id="test", aws_secret_access_key="test"
    )
    assert client.meta.service_model.signing_name == "cloudwatch"  # hence the IAM action cloudwatch:GetContextGraph
    start, end = T0, T0 + dt.timedelta(hours=24)
    expected = {
        "startTime": start,
        "endTime": end,
        "nodeFilters": {"sourceAccountId": [PLATFORM_ACCOUNT], "category": ["GEN_AI_AGENT"]},
        "maxResults": 100,
    }
    first = [agent_node("one", OWN_RUNTIME), agent_node("two", OWN_ORPHAN)]
    with Stubber(client) as stub:
        stub.add_response("get_context_graph", {"nodes": first, "nextToken": "t" * 20}, expected)
        stub.add_response(
            "get_context_graph", {"nodes": [agent_node("three", TELEMETRY_ONLY)]}, {**expected, "nextToken": "t" * 20}
        )
        nodes, truncated = omni.agent_nodes(client, PLATFORM_ACCOUNT, start, end)
        stub.assert_no_pending_responses()
    assert [n["name"] for n in nodes] == ["one", "two", "three"] and truncated is False


def test_context_graph_is_cut_at_the_node_limit():
    client = FakeClient({"get_context_graph": [{"nodes": [agent_node(f"n{i}", None) for i in range(7)]}]})
    nodes, truncated = omni.agent_nodes(client, PLATFORM_ACCOUNT, T0, T0, max_nodes=5)
    assert len(nodes) == 5 and truncated is True


# --- service and endpoint ------------------------------------------------------------------------------


class Backend:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, value in ENV.items():
            monkeypatch.setenv(key, value)
        self.records = [
            agent_record(tenantId="platform", agentId="platform-agent", runtimeArn=OWN_RUNTIME, gatewayArn=None)
        ]
        monkeypatch.setattr(registry, "list_records", lambda client, registry_id: self.records)
        monkeypatch.setattr(agentcore, "list_runtimes", lambda client: client.runtimes)
        monkeypatch.setattr(agentcore, "list_gateways", lambda client: [])
        own = FakeClient()
        own.runtimes = [runtime_bundle(OWN_RUNTIME, tags={}), runtime_bundle(OWN_ORPHAN, tags={})]
        cell = FakeClient()
        cell.runtimes = [runtime_bundle(ORPHAN_RUNTIME_ARN, tags={})]
        self.graph = FakeClient({"get_context_graph": [{"nodes": []}]})
        self.clients = FakeClients(
            {
                ("platform", "agent-registry-control"): FakeClient(),
                ("platform", "cloudwatchomni"): self.graph,
                (PLATFORM_ACCOUNT, "bedrock-agentcore-control"): own,
                (CELL_ACCOUNT, "bedrock-agentcore-control"): cell,
            }
        )
        self.regions: list[str] = []
        original = self.clients.platform

        def platform(service: str, region: str) -> Any:
            if service == "cloudwatchomni":
                self.regions.append(region)
            return original(service, region)

        self.clients.platform = platform  # type: ignore[method-assign]
        self.service = make_service(get_settings(), self.clients)
        application = create_app()
        application.dependency_overrides[deps.get_service] = lambda: self.service
        self.handler = Mangum(application, lifespan="off")

    def get(self, path: str, query: str = "", claims: dict | None = None) -> tuple[int, Any]:
        claims = {"sub": "u", "cognito:groups": "[viewers]"} if claims is None else claims
        response = self.handler(event(path, "GET", claims or None, query=query), None)
        return response["statusCode"], json.loads(response["body"])


@pytest.fixture
def backend(monkeypatch: pytest.MonkeyPatch) -> Backend:
    return Backend(monkeypatch)


def test_observed_agents_for_the_portals_own_account(backend):
    backend.graph.responses["get_context_graph"] = [
        {
            "nodes": [
                agent_node("platform_agent", OWN_RUNTIME),
                agent_node("unlisted_agent", OWN_ORPHAN),
                agent_node("FAST_stack_FASTAgent", TELEMETRY_ONLY),
                other_node("orders-function", "SERVICE", None),
            ]
        }
    ]
    code, body = backend.get("/omni/observed-services")
    assert code == 200
    states = {s["name"]: (s["inventory_state"], s["matched_agent_id"]) for s in body["services"]}
    assert states == {
        "platform_agent": ("registered_and_detected", "recAgent0001"),
        "unlisted_agent": ("detected_only", "unlisted_agent-ZyXwVu9876"),
        "FAST_stack_FASTAgent": ("observed_only", None),
    }
    assert "orders-function" not in states  # a function is not an agent
    assert set(body["services"][0]) == {
        "name",
        "node_type",
        "category",
        "resource_id",
        "runtime_arn",
        "region",
        "last_observed_at",
        "signals",
        "registered",
        "detected",
        "matched_agent_id",
        "inventory_state",
        "omni_region",
        "account_alias",
    }
    # the response says where it was observed
    assert body["domains"] == [{"account_alias": "platform", "region": OMNI_REGION, "url": OMNI_URL}]
    assert {(s["omni_region"], s["account_alias"]) for s in body["services"]} == {(OMNI_REGION, "platform")}
    assert body["omni_url"] == OMNI_URL and body["window_hours"] == 24 and body["checked_at"]
    # the graph is read once, with the function's own role, in the account's Omni Region
    assert backend.regions == [OMNI_REGION]
    assert [name for name, _ in backend.graph.calls] == ["paginate:get_context_graph"]
    # other accounts are skipped and said so, once per account and without an account id
    assert body["warnings"] == [
        "account-4444: skipped, Omni is read only in the portal's own account.",
        "account-7777: skipped, Omni is read only in the portal's own account.",
    ]
    assert CELL_ACCOUNT not in json.dumps(body["warnings"])


def test_cells_in_other_accounts_are_skipped_with_a_warning(backend, monkeypatch):
    other = {
        **CELLS[0],
        "omniRegion": OMNI_REGION,
        "omniDomainUrl": "https://d-ffffffffff.cloudwatch-omni.global.app.aws",
    }
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([OWN_CELL, other]))
    backend.service.settings = get_settings()
    code, body = backend.get("/omni/observed-services", "cell=ws1/travel-agent")
    assert code == 200 and body["services"] == [] and body["omni_url"] is None and body["domains"] == []
    assert body["warnings"] == ["account-4444: skipped, Omni is read only in the portal's own account."]
    assert backend.graph.calls == []


def test_an_own_account_without_an_omni_region_is_said_so(backend, monkeypatch):
    plain = {k: v for k, v in OWN_CELL.items() if not k.startswith("omni")}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([plain]))
    backend.service.settings = get_settings()
    body = backend.get("/omni/observed-services")[1]
    assert body["warnings"] == ["platform: no Omni Region is configured for this account's cells."]
    assert backend.graph.calls == [] and body["domains"] == []


def test_cell_filter_and_parameters(backend):
    assert backend.get("/omni/observed-services", "cell=platform/platform-agent")[0] == 200
    assert (
        backend.get("/omni/observed-services", "cell=platform/platform-agent/nonprod&hours=6")[1]["window_hours"] == 6
    )
    assert backend.get("/omni/observed-services", "cell=nobody/nothing") == (404, {"detail": "Cell not found"})
    assert backend.get("/omni/observed-services", "cell=bad%20cell")[0] == 422
    assert backend.get("/omni/observed-services", "hours=0")[0] == 422
    assert backend.get("/omni/observed-services", claims={})[0] == 401


def test_a_graph_that_cannot_be_read_is_a_warning_not_a_failure(backend):
    backend.graph.responses["get_context_graph"] = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not authorized in this Region"}}, "GetContextGraph"
    )
    code, body = backend.get("/omni/observed-services", "cell=platform/platform-agent")
    assert code == 200 and body["services"] == [] and body["domains"] == []
    assert body["warnings"] == [
        "platform: the Omni Context Graph in us-west-2 could not be read (AccessDeniedException)."
    ]
    assert "not authorized" not in json.dumps(body)


def test_a_long_graph_is_cut_and_said_so(backend, monkeypatch):
    monkeypatch.setattr(omni, "MAX_NODES", 2)
    two = [agent_node("a", OWN_RUNTIME), agent_node("b", OWN_ORPHAN)]
    monkeypatch.setattr(omni, "agent_nodes", lambda client, account, start, end: (two, True))
    body = backend.get("/omni/observed-services", "cell=platform/platform-agent")[1]
    assert len(body["services"]) == 2
    assert body["warnings"] == ["platform: only the first 2 agents in us-west-2 are listed."]


def test_omni_links_on_agents_cells_and_summary(backend):
    agents = {a["name"]: a for a in backend.get("/agents")[1]}
    assert agents["platform-agent"]["omni_url"] == OMNI_URL
    assert agents["unlisted_agent"]["omni_url"] == OMNI_URL  # found through the same cell account's reader
    assert agents["orphan_agent"]["omni_url"] is None
    cells = {c["tenant_id"]: c for c in backend.get("/fleet/health")[1]["cells"]}
    assert cells["platform"]["omni_url"] == OMNI_URL and cells["ws1"]["omni_url"] is None
    summary = backend.get("/fleet/summary")[1]
    assert summary["omni_url"] == OMNI_URL
    assert summary["omni_domains"] == [{"account_alias": "platform", "region": OMNI_REGION, "url": OMNI_URL}]


def test_summary_lists_every_distinct_omni_domain(backend, monkeypatch):
    second = "https://d-ffffffffff.cloudwatch-omni.global.app.aws"
    other = {**CELLS[0], "omniRegion": OMNI_REGION, "omniDomainUrl": second}
    monkeypatch.setenv("PORTAL_CELLS", json.dumps([OWN_CELL, other, {**CELLS[1], "omniDomainUrl": OMNI_URL}]))
    backend.service.settings = get_settings()
    backend.service.cache.clear()
    summary = backend.get("/fleet/summary")[1]
    assert summary["omni_url"] is None
    assert [d["url"] for d in summary["omni_domains"]] == [OMNI_URL, second]
    assert summary["omni_domains"][1]["account_alias"] == "account-4444"


# --- which account is the portal's own -----------------------------------------------------------------------


class _Request:
    def __init__(self, scope: dict[str, Any]) -> None:
        self.scope = scope


class _Context:
    invoked_function_arn = "arn:aws:lambda:eu-west-1:222222222222:function:portal-api"


def test_own_account_comes_from_the_lambda_context_then_the_event_then_local_configuration(monkeypatch):
    with_event = {"aws.event": {"requestContext": {"accountId": "333333333333"}}}
    assert own_account_id(_Request({"aws.context": _Context(), **with_event})) == "222222222222"
    assert own_account_id(_Request(with_event)) == "333333333333"
    assert own_account_id(_Request({})) is None
    assert own_account_id(_Request({"aws.event": {"requestContext": {"accountId": "not-an-account"}}})) is None
    monkeypatch.setenv("PORTAL_ACCOUNT_ID", "555555555555")
    assert own_account_id(_Request({})) == "555555555555"
    monkeypatch.setenv("PORTAL_ACCOUNT_ID", "nope")
    assert own_account_id(_Request({})) is None


# --- configuration ------------------------------------------------------------------------------------------------


def test_omni_cell_fields_are_validated():
    settings = load_settings(ENV)
    assert (settings.cells[0].omni_domain_url, settings.cells[0].omni_region) == (OMNI_URL, OMNI_REGION)
    assert settings.cells[1].omni_domain_url is None
    assert "111111111111" not in OMNI_URL  # the domain URL form holds no account id
    for patch in (
        {"omniDomainUrl": "http://insecure.example.com"},
        {"omniDomainUrl": "javascript:alert(1)"},
        {"omniRegion": "us west 2"},
        {"omniDomainUrl": "https://ok.example.com/path?x=<script>"},
    ):
        with pytest.raises(ConfigError, match="omni"):
            load_settings({**BASE_ENV, "PORTAL_CELLS": json.dumps([{**OWN_CELL, **patch}])})
