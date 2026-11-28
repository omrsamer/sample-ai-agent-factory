# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tool gateways that only the organization registry detected: listed, and nothing about them is guessed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mangum import Mangum

from portal_api import deps
from portal_api.app import create_app
from portal_api.mappers import mcp as mcp_mapper
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    CELLS,
    GATEWAY_ARN,
    ORPHAN_RUNTIME_ARN,
    OTHER_ACCOUNT,
    REGION,
    agent_record,
    runtime_bundle,
    tool_record,
)
from tests.test_api import PLATFORM_CLAIMS, VIEWER_CLAIMS, event
from tests.test_inventory import DISCOVERY, Backend, summary

UNMANAGED_ACCOUNT = "888888888888"
# In an account in which the portal has no reader.
NO_READER = f"arn:aws:bedrock-agentcore:{REGION}:{UNMANAGED_ACCOUNT}:gateway/shadow-tools-qwertyuiop"
# In the account of the second cell, whose reader role cannot be assumed in these tests.
UNREACHABLE = f"arn:aws:bedrock-agentcore:{REGION}:{OTHER_ACCOUNT}:gateway/ws2-tools-zyxwvutsrq"
# In the first cell's account, where the reader works but does not list it.
NOT_LISTED = f"arn:aws:bedrock-agentcore:{REGION}:{CELL_ACCOUNT}:gateway/gone-tools-mnbvcxzlkj"
READ_ID = GATEWAY_ARN.rsplit("/", 1)[-1]
NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID = (arn.rsplit("/", 1)[-1] for arn in (NO_READER, UNREACHABLE, NOT_LISTED))
NO_READER_SENTENCE = (
    "There is no reader role in this gateway's account, so its targets, its policy engine and its policies "
    "cannot be shown."
)


def gateway_record(arn: str, record_id: str, **details: Any) -> dict[str, Any]:
    """The full discovery record of a gateway: its provenance carries the protocol and the authorizer."""
    base = summary(arn, record_id, "GATEWAY")
    base.pop("provenanceSummaryList")
    return {
        **base,
        "provenance": [
            {
                "relation": "DETECTED_FROM",
                "sourceId": arn,
                "sourceType": "AWS::BedrockAgentCore::Gateway",
                "sourceDetails": {"agentcoreGateway": {"protocolType": "MCP", "authorizerType": "AWS_IAM", **details}},
            }
        ],
    }


class Portal:
    """The read API over a backend whose organization registry detected four gateways."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, env: dict[str, str] | None = None) -> None:
        self.backend = Backend(monkeypatch, {"PORTAL_DISCOVERY_REGISTRY_ID": DISCOVERY, **(env or {})})
        self.backend.summaries = [
            summary(GATEWAY_ARN, "recGateway001", "GATEWAY"),
            summary(NO_READER, "recGateway002", "GATEWAY"),
            summary(UNREACHABLE, "recGateway003", "GATEWAY"),
            summary(NOT_LISTED, "recGateway004", "GATEWAY"),
        ]
        self.backend.full = {
            "recGateway001": gateway_record(GATEWAY_ARN, "recGateway001"),
            "recGateway002": gateway_record(NO_READER, "recGateway002"),
            "recGateway003": gateway_record(UNREACHABLE, "recGateway003", authorizerType="CUSTOM_JWT"),
            # recGateway004 has no full record: only what the summary says is known.
        }
        application = create_app()
        application.dependency_overrides[deps.get_service] = lambda: self.backend.service
        self.handler = Mangum(application, lifespan="off")

    def get(self, path: str, claims: dict | None = VIEWER_CLAIMS, query: str = "") -> tuple[int, Any]:
        response = self.handler(event(path, "GET", claims, query=query), None)
        return response["statusCode"], json.loads(response["body"])

    def servers(self) -> dict[str, dict[str, Any]]:
        code, body = self.get("/mcp-servers")
        assert code == 200, body
        return {server["id"]: server for server in body}


@pytest.fixture
def portal(monkeypatch: pytest.MonkeyPatch) -> Portal:
    return Portal(monkeypatch)


def test_a_gateway_that_only_the_organization_registry_detected_is_listed(portal):
    servers = portal.servers()
    assert sorted(servers) == sorted([READ_ID, NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID])
    shadow = servers[NO_READER_ID]
    assert {name: shadow[name] for name in shadow if name not in ("created_at", "updated_at")} == {
        "id": NO_READER_ID,
        "name": "shadow-tools",
        "description": None,
        "kind": "gateway",
        "owner_oid": None,
        "owner_email": None,
        "business_unit": None,
        "region": REGION,
        "data_classification": None,
        "endpoint_url": None,
        "version": "1",
        "available_tools": [],  # no targets are shown
        "gateway_arn": NO_READER,
        "cedar_policy_engine_id": None,  # and no policy
        "cedar_policy_engine_arn": None,
        "cedar_enforcement_mode": "unknown",  # not "none": that would claim it has no policy engine
        "gateway_id": NO_READER_ID,
        "gateway_url": None,
        "runtime_arn": None,
        "identity_status": "none",
        "lifecycle_state": "discovered",
        "tenant_id": None,
        "published": False,
        "shared": False,
        "created_by": None,
        "gateway_status": "UNKNOWN",
        # From the detection's provenance.
        "authorizer_type": "AWS_IAM",
        "protocol": "MCP",
        "environment": None,
        "account_id": UNMANAGED_ACCOUNT,
        "account_alias": None,
        "agent_id": None,
        "detection_sources": ["organization_registry"],
        "reader_status": "none",
        "detail": NO_READER_SENTENCE,
    }
    assert shadow["created_at"] == shadow["updated_at"] == "2026-01-15T12:00:00Z"  # when it was detected
    assert portal.get(f"/mcp-servers/{NO_READER_ID}") == (200, shadow)


def test_a_gateway_a_reader_read_is_unchanged_and_says_who_else_saw_it(portal):
    read = portal.servers()[READ_ID]
    assert (read["reader_status"], read["detection_sources"]) == ("ok", ["cell_reader", "organization_registry"])
    assert (read["cedar_enforcement_mode"], read["detail"], read["protocol"]) == ("enforce", None, "MCP")
    assert read["available_tools"] and read["tenant_id"] == "ws1" and read["lifecycle_state"] == "approved"
    # Its full discovery record is not fetched: the reader already told everything.
    assert sorted(portal.backend.fetched) == ["recGateway002", "recGateway003", "recGateway004"]


def test_why_no_reader_read_it_is_said(portal):
    servers = portal.servers()
    assert {i: servers[i]["reader_status"] for i in (NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID)} == {
        NO_READER_ID: "none",
        UNREACHABLE_ID: "unreachable",
        NOT_LISTED_ID: "not_listed",
    }
    assert servers[UNREACHABLE_ID]["detail"] == (
        "The reader role in this gateway's account could not be used, so its targets, its policy engine and its "
        "policies cannot be shown."
    )
    assert servers[NOT_LISTED_ID]["detail"] == (
        "The reader in this gateway's account did not list this gateway, so its targets, its policy engine and "
        "its policies cannot be shown. It may have been deleted since the organization registry detected it."
    )
    assert (servers[UNREACHABLE_ID]["authorizer_type"], servers[UNREACHABLE_ID]["protocol"]) == ("CUSTOM_JWT", "MCP")
    # Without the full record only the summary is known: the authorizer and the protocol are not guessed.
    assert (servers[NOT_LISTED_ID]["authorizer_type"], servers[NOT_LISTED_ID]["protocol"]) == (None, None)
    for server_id in (NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID):
        server = servers[server_id]
        assert server["cedar_enforcement_mode"] == "unknown" and server["available_tools"] == []
        assert server["detection_sources"] == ["organization_registry"] and server["tenant_id"] is None


def test_the_account_alias_is_the_configured_one(monkeypatch):
    aliased = [{**CELLS[0], "accountAlias": "ws1-nonprod"}, CELLS[1]]
    portal = Portal(monkeypatch, {"PORTAL_CELLS": json.dumps(aliased)})
    servers = portal.servers()
    assert servers[READ_ID]["account_alias"] == servers[NOT_LISTED_ID]["account_alias"] == "ws1-nonprod"
    assert servers[UNREACHABLE_ID]["account_alias"] is None and servers[NO_READER_ID]["account_alias"] is None


@pytest.mark.parametrize("server_id", [NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID])
def test_its_policy_endpoints_answer_200_with_nothing_and_say_why(portal, server_id):
    sentence = portal.servers()[server_id]["detail"]
    control_calls = len(portal.backend.control.calls)
    assert portal.get(f"/mcp-servers/{server_id}/policies") == (
        200,
        {"enforcement_mode": "unknown", "engine_id": None, "policies": [], "editable": False, "warnings": [sentence]},
    )
    assert portal.get(f"/mcp-servers/{server_id}/policy-enforcement") == (
        200,
        {"enforcement_mode": "unknown", "engine_id": None, "detail": sentence},
    )
    assert portal.get(f"/mcp-servers/{server_id}/grants") == (200, [])
    # Nothing was asked of any cell for it.
    assert len(portal.backend.control.calls) == control_calls
    assert portal.get("/mcp-servers/no-such-gateway/policies")[0] == 404


def named_by_a_registration(portal: Portal) -> None:
    """A second registration whose record names the gateway that no reader can read."""
    portal.backend.records = [
        tool_record("tool-echo"),
        agent_record(),
        agent_record(record_id="recAgent0002", agentId="shadow-user", runtimeArn=None, gatewayArn=NO_READER),
    ]
    portal.backend.service.cache.clear()


def test_no_edge_is_drawn_to_it_even_when_a_registration_names_it(portal):
    named_by_a_registration(portal)
    code, graph = portal.get("/governance-graph")
    assert code == 200
    nodes = {node["id"]: node for node in graph["nodes"]}
    # It is in the graph as a node that says what is not known.
    shadow = nodes[f"mcp:{NO_READER_ID}"]
    assert (shadow["label"], shadow["ref_id"]) == ("shadow-tools", NO_READER_ID)
    assert shadow["metadata"] == {
        "kind": "gateway",
        "tenant_id": None,
        "environment": None,
        "enforcement_mode": "unknown",
        "tool_count": 0,
        "reader_status": "none",
        "detection_sources": ["organization_registry"],
    }
    # No edge ends at any of the three: who can call them, and under what policy, is not known.
    targets = {edge["target"] for edge in graph["edges"]}
    assert not targets & {f"mcp:{i}" for i in (NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID)}
    # The gateway a reader read keeps its edge.
    assert f"mcp:{READ_ID}" in targets
    assert nodes[f"mcp:{READ_ID}"]["metadata"]["reader_status"] == "ok"
    # And its grants stay empty, although the registration names it.
    assert portal.get(f"/mcp-servers/{NO_READER_ID}/grants") == (200, [])
    assert portal.get(f"/mcp-servers/{READ_ID}/grants")[1] != []


def test_an_agent_that_names_it_is_not_said_to_have_a_gateway_without_a_policy(portal):
    named_by_a_registration(portal)
    code, agent = portal.get("/agents/recAgent0002")
    assert code == 200 and agent["mcp_server_ids"] == [NO_READER_ID]
    codes = [reason["code"] for reason in agent["risk"]["reasons"]]
    assert "GATEWAY_POLICY_NONE" not in codes and "GATEWAY_POLICY_LOG_ONLY" not in codes
    # The agent's own list of gateways names it by its name.
    grants = portal.get("/agents/recAgent0002/mcp-grants")[1]
    assert [(grant["mcp_id"], grant["mcp_name"]) for grant in grants] == [(NO_READER_ID, "shadow-tools")]
    # The evidence document says the mode is not known, and why.
    code, evidence = portal.get("/agents/recAgent0002/evidence", PLATFORM_CLAIMS)
    assert code == 200
    (policy,) = evidence["policy"]
    assert (policy["gateway_id"], policy["gateway_name"], policy["policy_mode"], policy["policy_count"]) == (
        NO_READER_ID,
        "shadow-tools",
        None,
        None,
    )
    assert f"Tool Gateway {NO_READER_ID}: {NO_READER_SENTENCE}" in evidence["limitations"]


def test_a_runtime_with_no_registration_is_linked_only_to_a_gateway_a_reader_read(portal):
    """Links are derived from addresses and tags, and a gateway no reader read has neither."""
    portal.backend.control.runtimes.append(runtime_bundle(ORPHAN_RUNTIME_ARN))  # the same identity tags as the gateway
    portal.backend.service.cache.clear()
    code, agent = portal.get(f"/agents/{ORPHAN_RUNTIME_ARN.rsplit('/', 1)[-1]}")
    assert code == 200 and agent["mcp_server_ids"] == [READ_ID]
    assert sorted(portal.servers()) == sorted([READ_ID, NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID])


def test_the_fleet_summary_counts_them_and_does_not_call_their_policy_mode_none(portal):
    code, summary_ = portal.get("/fleet/summary")
    assert code == 200
    assert summary_["gateways_total"] == 4
    assert summary_["gateways_by_policy_mode"] == {"enforce": 1, "log_only": 0, "none": 0, "unknown": 3}


def test_they_can_be_filtered_like_any_other(portal):
    code, discovered = portal.get("/mcp-servers", query="lifecycle_state=discovered")
    assert code == 200 and sorted(s["id"] for s in discovered) == sorted([NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID])
    assert [s["id"] for s in portal.get("/mcp-servers", query="tenant_id=ws1")[1]] == [READ_ID]


def test_without_the_organization_registry_there_are_none(monkeypatch):
    backend = Backend(monkeypatch)  # no discovery registry configured
    backend.summaries = [summary(NO_READER, "recGateway002", "GATEWAY")]
    assert [gateway.server.id for gateway in backend.service.gateways()] == [READ_ID]
    assert backend.service.fleet_summary().gateways_by_policy_mode["unknown"] == 0


def test_a_registry_that_cannot_be_read_leaves_the_readers_gateways(portal):
    portal.backend.list_error = RuntimeError("the registry is unavailable")
    portal.backend.service.cache.clear()
    assert sorted(portal.servers()) == [READ_ID]


def test_a_detection_never_takes_the_place_of_a_gateway_that_a_reader_read(portal):
    """A detection is keyed by an ARN that whoever registered it wrote. One that carries the id of a
    gateway a reader read, under another ARN, replaced that gateway under its id: no tools, no
    policy engine, mode unknown."""
    before = portal.servers()[READ_ID]
    assert before["cedar_enforcement_mode"] != "unknown" and before["available_tools"]
    twins = [
        GATEWAY_ARN.replace("arn:aws:", "arn:aws-cn:"),  # another spelling of the same gateway
        GATEWAY_ARN.replace(CELL_ACCOUNT, UNMANAGED_ACCOUNT),  # the same id, claimed for another account
        GATEWAY_ARN.replace(REGION, "us-east-1"),
    ]
    for number, arn in enumerate(twins, start=5):
        record_id = f"recGateway00{number}"
        portal.backend.summaries.append(summary(arn, record_id, "GATEWAY"))
        portal.backend.full[record_id] = gateway_record(arn, record_id, authorizerType="CUSTOM_JWT")
    portal.backend.service.cache.clear()

    code, listed = portal.get("/mcp-servers")
    assert code == 200 and [server["id"] for server in listed].count(READ_ID) == 1
    # What the reader read stands, in the list and under the gateway's id.
    assert portal.servers()[READ_ID] == before
    assert portal.get(f"/mcp-servers/{READ_ID}")[1] == before
    assert before["gateway_arn"] == GATEWAY_ARN and before["reader_status"] == "ok"
    enforcement = portal.get(f"/mcp-servers/{READ_ID}/policy-enforcement")[1]
    assert enforcement["enforcement_mode"] != "unknown" and enforcement.get("detail") is None
    # The gateways that really were only detected are listed as before.
    assert sorted(portal.servers()) == sorted([READ_ID, NO_READER_ID, UNREACHABLE_ID, NOT_LISTED_ID])
    totals = portal.get("/fleet/summary")[1]
    assert totals["gateways_total"] == 4


def test_the_index_of_gateways_prefers_the_one_a_reader_read():
    from portal_api.mappers.discovery import Detection
    from portal_api.service import Inventory

    detected = mcp_mapper.gateway_from_detection(
        Detection(arn=NO_READER, kind="gateway", record_id="r", record_name="n"), mcp_mapper.READER_NONE
    )
    read = mcp_mapper.gateway_from_detection(
        Detection(arn=NO_READER, kind="gateway", record_id="r", record_name="n"), mcp_mapper.READER_NONE
    )
    read.cell = object()  # a reader read this one
    assert read.read is True and detected.read is False and read.server.id == detected.server.id
    for order in ([read, detected], [detected, read]):
        assert Inventory(gateways=order).gateway_index()[read.server.id] is read
    # Two that were only detected: the first stays.
    other = mcp_mapper.gateway_from_detection(
        Detection(arn=NO_READER, kind="gateway", record_id="r2", record_name="n2"), mcp_mapper.READER_NONE
    )
    assert Inventory(gateways=[detected, other]).gateway_index()[detected.server.id] is detected


def test_the_mapper_claims_nothing_it_was_not_told():
    from portal_api.mappers.discovery import Detection

    entry = mcp_mapper.gateway_from_detection(
        Detection(arn=NO_READER, kind="gateway", record_id="r", record_name="n"), mcp_mapper.READER_NONE
    )
    assert (entry.read, entry.has_policy, entry.cell, entry.url, entry.tags) == (False, False, None, None, {})
    assert (entry.enforcement_mode, entry.policy_engine_arn) == ("unknown", None)
    assert (entry.server.authorizer_type, entry.server.protocol, entry.server.available_tools) == (None, None, [])
    assert set(mcp_mapper.NOT_READ) == {"none", "unreachable", "not_listed"}


def test_the_readme_describes_them():
    readme = " ".join((Path(__file__).resolve().parent.parent / "README.md").read_text().split())
    for said in (
        "`reader_status`",
        "`unknown`",
        "`detection_sources`",
        NO_READER_SENTENCE,
        "no edge is drawn to it",
        "`gateways_by_policy_mode`",
    ):
        assert said in readme, said
    assert BASE_ENV["PORTAL_REGISTRY_ID"]  # the fixture this file's backend is built on
