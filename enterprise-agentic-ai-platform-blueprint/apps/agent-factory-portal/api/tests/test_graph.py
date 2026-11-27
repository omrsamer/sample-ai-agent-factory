# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from __future__ import annotations

from portal_api.mappers import agents as agent_mapper
from portal_api.mappers import graph as graph_mapper
from portal_api.mappers import mcp as mcp_mapper
from tests.conftest import GATEWAY_URL, ORPHAN_RUNTIME_ARN, agent_record, gateway_bundle, runtime_bundle


def _fixture(settings, mode="LOG_ONLY", orphan_tags=None, orphan_url=None):
    cell = settings.cells[0]
    gateway = mcp_mapper.gateway_entry(gateway_bundle(mode), cell, {})
    runtime = agent_mapper.runtime_from_bundle(runtime_bundle(), cell)
    registered = agent_mapper.registered_agent(agent_record(), runtime, cell)
    orphan_runtime = agent_mapper.runtime_from_bundle(
        runtime_bundle(ORPHAN_RUNTIME_ARN, tags=orphan_tags if orphan_tags is not None else {}, gateway_url=orphan_url),
        cell,
    )
    orphan = agent_mapper.discovered_agent(orphan_runtime, None)
    orphan.links = graph_mapper.derive_links(orphan, [gateway])
    return registered, orphan, gateway


def test_graph_nodes_and_edges(settings):
    registered, orphan, gateway = _fixture(settings)
    graph = graph_mapper.build_graph([registered, orphan], [gateway])
    assert {(n.type, n.id) for n in graph.nodes} == {
        ("mcp", "mcp:ws1-tools-abcdefghij"),
        ("agent", "agent:recAgent0001"),
        ("agent", "agent:orphan_agent-ZyXwVu9876"),
        ("group", "group:travel-owners"),
    }
    assert not any(n.type == "user" for n in graph.nodes)
    edges = {e.id: e for e in graph.edges}
    assert set(edges) == {"access:travel-owners:recAgent0001", "can_call:recAgent0001:ws1-tools-abcdefghij"}
    access = edges["access:travel-owners:recAgent0001"]
    assert (access.source, access.target, access.type, access.role) == (
        "group:travel-owners",
        "agent:recAgent0001",
        "access",
        "owner",
    )
    call = edges["can_call:recAgent0001:ws1-tools-abcdefghij"]
    assert (call.source, call.target, call.type, call.has_policy) == (
        "agent:recAgent0001",
        "mcp:ws1-tools-abcdefghij",
        "can_call",
        True,
    )
    node = next(n for n in graph.nodes if n.id == "agent:recAgent0001")
    assert node.ref_id == "recAgent0001" and node.metadata["lifecycle_state"] == "approved"


def test_has_policy_follows_the_gateway_enforcement_mode(settings):
    for mode, expected in [("LOG_ONLY", True), ("ENFORCE", True), (None, False)]:
        registered, _, gateway = _fixture(settings, mode=mode)
        graph = graph_mapper.build_graph([registered], [gateway])
        assert [e.has_policy for e in graph.edges if e.type == "can_call"] == [expected]


def test_edge_to_a_gateway_outside_configured_cells_gets_a_placeholder_node(settings):
    registered, _, _ = _fixture(settings)
    graph = graph_mapper.build_graph([registered], [])
    placeholder = next(n for n in graph.nodes if n.type == "mcp")
    assert placeholder.metadata == {"kind": "gateway", "resolved": False}
    assert [e.has_policy for e in graph.edges if e.type == "can_call"] == [False]


def test_discovered_runtime_links_by_configured_gateway_url(settings):
    _, orphan, _ = _fixture(settings, orphan_url=GATEWAY_URL + "/")
    assert [(link.gateway_id, link.source) for link in orphan.links] == [("ws1-tools-abcdefghij", "runtime_env")]


def test_discovered_runtime_links_by_matching_identity_tags(settings):
    tags = {"tenant-id": "ws1", "agent-id": "travel-agent", "environment": "nonprod"}
    _, orphan, _ = _fixture(settings, orphan_tags=tags)
    assert [(link.gateway_id, link.source) for link in orphan.links] == [("ws1-tools-abcdefghij", "tags")]


def test_discovered_runtime_without_derivable_link_has_none(settings):
    _, orphan, _ = _fixture(settings, orphan_tags={"tenant-id": "ws1"})
    assert orphan.links == []
    _, other, _ = _fixture(settings, orphan_tags={"tenant-id": "x", "agent-id": "y", "environment": "nonprod"})
    assert other.links == []


def test_grants_are_derived_in_both_directions(settings):
    registered, orphan, gateway = _fixture(settings)
    index = {gateway.server.id: gateway}
    agent_side = graph_mapper.agent_mcp_grants(registered, index)
    assert [g.model_dump() for g in agent_side] == [
        {
            "mcp_id": "ws1-tools-abcdefghij",
            "mcp_name": "ws1-tools",
            "role": "Invoker",
            "assignment_id": "derived:recAgent0001:ws1-tools-abcdefghij",
            "source": "registry",
            "tool_ids": ["tool-echo"],
            "derived": True,
        }
    ]
    assert graph_mapper.agent_mcp_grants(orphan, index) == []
    gateway_side = graph_mapper.mcp_grants("ws1-tools-abcdefghij", [registered, orphan])
    assert [(g.principal_id, g.principal_display, g.principal_type, g.role) for g in gateway_side] == [
        ("recAgent0001", "Travel agent", "ServicePrincipal", "Invoker")
    ]


def test_owner_group_detail(settings):
    registered, orphan, _ = _fixture(settings)
    detail = graph_mapper.owner_group_detail("travel-owners", [registered, orphan])
    assert detail.kind == "group" and detail.display_name == "travel-owners"
    assert graph_mapper.owner_group_detail("nobody", [registered, orphan]) is None
