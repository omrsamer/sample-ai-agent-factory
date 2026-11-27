# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Mappers for both registry schemas, agents, gateways, guardrails, traces, metrics and release evidence."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from portal_api.mappers import agents as agent_mapper
from portal_api.mappers import guardrails as guardrail_mapper
from portal_api.mappers import mcp as mcp_mapper
from portal_api.mappers import observability as observability_mapper
from portal_api.mappers import registry as registry_mapper
from portal_api.mappers import release as release_mapper
from tests.conftest import (
    CELL_ACCOUNT,
    ENGINE_ARN,
    GATEWAY_ARN,
    ORPHAN_RUNTIME_ARN,
    REGION,
    RUNTIME_ARN,
    T0,
    agent_document,
    agent_record,
    gateway_bundle,
    runtime_bundle,
    tool_record,
)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "agent-governance-1.0.json"


# --- registry: tool-governance/1.0 ------------------------------------------


def test_tool_record_maps_to_catalogue_tool():
    tool = registry_mapper.catalog_tool(tool_record("tool-echo"))
    assert tool.model_dump() == {
        "tool_id": "tool-echo",
        "name": "tool-echo",
        "description": "tool-echo description",
        "owner": "platform-ai",
        "cost_centre": "platform",
        "status": "APPROVED",
        "version": "2.0.0",
        "target_arn": f"arn:aws:lambda:{REGION}:111111111111:function:tool-echo:PROD",
    }


def test_records_are_split_by_schema():
    records = [tool_record("tool-echo"), agent_record(), {"recordId": "x", "descriptors": {"custom": {"data": "{"}}}]
    assert [r["name"] for r in registry_mapper.tool_records(records)] == ["tool-echo"]
    assert [r["recordId"] for r in registry_mapper.agent_records(records)] == ["recAgent0001"]
    assert set(registry_mapper.tool_index(records)) == {"tool-echo"}


@pytest.mark.parametrize(
    "descriptors",
    [
        {"custom": {"data": json.dumps({"schemaVersion": "s/1"})}},
        {"custom": {"inlineContent": json.dumps({"schemaVersion": "s/1"})}},
        {"custom": {"schemaVersion": "s/1"}},
        {"custom": json.dumps({"schemaVersion": "s/1"})},
    ],
)
def test_governance_document_accepts_known_descriptor_forms(descriptors):
    assert registry_mapper.schema_of({"descriptors": descriptors}) == "s/1"


@pytest.mark.parametrize(
    "descriptors", [None, {}, {"custom": {"data": "[1]"}}, {"custom": {"data": "nope"}}, {"mcp": {}}]
)
def test_governance_document_tolerates_other_records(descriptors):
    assert registry_mapper.governance_document({"descriptors": descriptors}) is None


# --- registry: agent-governance/1.0 -----------------------------------------


def test_agent_schema_file_matches_fixture():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["properties"]["schemaVersion"]["const"] == registry_mapper.AGENT_SCHEMA
    assert schema["additionalProperties"] is False
    document = agent_document()
    assert set(document) == set(schema["properties"])
    assert set(schema["required"]) <= set(document)
    assert set(schema["properties"]["goldenPath"]["properties"]) == {"name", "version"}
    assert set(schema["properties"]["evaluation"]["properties"]) == {"verdict", "runId", "completedAt"}


def test_agent_governance_document_is_mapped():
    governance = registry_mapper.agent_governance(agent_record())
    assert governance.tenant_id == "ws1"
    assert governance.agent_id == "travel-agent"
    assert governance.owner_group == "travel-owners"
    assert governance.golden_path == {"name": "strands-runtime", "version": "1.2.0"}
    assert governance.subscribed_tool_ids == ["tool-echo"]
    assert governance.policy_engine_mode == "LOG_ONLY"
    assert governance.evaluation == {"verdict": "passed", "runId": "run-1", "completedAt": "2026-01-15T12:00:00Z"}


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("DRAFT", "proposed"),
        ("PENDING_APPROVAL", "pending_approval"),
        ("APPROVED", "approved"),
        ("REJECTED", "rejected"),
        ("DEPRECATED", "deprecated"),
        ("CREATING", "proposed"),
        ("UPDATE_FAILED", "proposed"),
        ("SOMETHING_NEW", "proposed"),
    ],
)
def test_lifecycle_state_comes_from_native_record_status(status, expected):
    assert registry_mapper.lifecycle_state({"status": status}) == expected


# --- agents -------------------------------------------------------------------


def test_registered_agent_merges_record_and_runtime(settings):
    cell = settings.cells[0]
    runtime = agent_mapper.runtime_from_bundle(runtime_bundle(), cell)
    entry = agent_mapper.registered_agent(agent_record("PENDING_APPROVAL"), runtime, cell)
    agent = entry.agent
    assert agent.id == "recAgent0001"
    assert agent.name == "Travel agent"
    assert agent.lifecycle_state == "pending_approval"
    assert agent.registration == "registered"
    assert agent.purpose == "Plans trips for employees."
    assert agent.sponsor_email == "travel-owners@example.com"
    assert agent.data_classification == "Confidential"
    assert agent.agent_arn == RUNTIME_ARN
    assert agent.agent_arns == {"nonprod": RUNTIME_ARN}
    assert agent.mcp_server_ids == ["ws1-tools-abcdefghij"]
    assert agent.region == REGION and agent.account_id == CELL_ACCOUNT
    assert agent.runtime_status == "ready"
    assert agent.created_at == "2026-01-15T12:00:00Z"
    assert entry.owner_group == "travel-owners"
    assert entry.links == [agent_mapper.GatewayLink("ws1-tools-abcdefghij", GATEWAY_ARN, "registry", ("tool-echo",))]
    assert entry.access_cell is cell


def test_registered_agent_without_runtime_is_registered_origin():
    record = agent_record(runtimeArn=None, gatewayArn=None)
    entry = agent_mapper.registered_agent(record, None, None)
    assert entry.agent.origin == "Registered"
    assert entry.agent.agent_arn is None and entry.agent.agent_arns is None
    assert entry.links == []
    assert agent_mapper.runtime_status(entry, reachable=False).status == "not_deployed"


def test_discovered_agent_from_runtime_tags(settings):
    cell = settings.cells[0]
    runtime = agent_mapper.runtime_from_bundle(runtime_bundle(ORPHAN_RUNTIME_ARN), cell)
    entry = agent_mapper.discovered_agent(runtime, cell)
    agent = entry.agent
    assert agent.id == "orphan_agent-ZyXwVu9876"
    assert agent.lifecycle_state == "discovered"
    assert agent.registration == "discovered"
    assert agent.name == "travel-agent"
    assert agent.tenant_id == "ws1"
    assert agent.environment == "nonprod"
    assert agent.governance is None
    assert entry.owner_group is None


def test_runtime_status_vocabulary(settings):
    cell = settings.cells[0]
    for native, expected in [
        ("READY", "ready"),
        ("CREATING", "creating"),
        ("UPDATING", "updating"),
        ("UPDATE_FAILED", "failed"),
        ("MYSTERY", "unknown"),
    ]:
        runtime = agent_mapper.runtime_from_bundle(runtime_bundle(status=native), cell)
        status = agent_mapper.runtime_status(agent_mapper.discovered_agent(runtime, cell), reachable=True)
        assert status.status == expected
        assert status.image_tag == "v2"
        assert status.stage == "nonprod"
    missing = agent_mapper.registered_agent(agent_record(), None, cell)
    assert agent_mapper.runtime_status(missing, reachable=False).status == "unknown"


def test_deployments_from_runtime_versions_newest_first(settings):
    cell = settings.cells[0]
    entry = agent_mapper.discovered_agent(agent_mapper.runtime_from_bundle(runtime_bundle(), cell), cell)
    versions = [
        {
            "agentRuntimeId": "travel_agent-AbCdEf1234",
            "agentRuntimeVersion": "1",
            "status": "READY",
            "lastUpdatedAt": T0,
        },
        {
            "agentRuntimeId": "travel_agent-AbCdEf1234",
            "agentRuntimeVersion": "2",
            "status": "UPDATE_FAILED",
            "lastUpdatedAt": T0 + dt.timedelta(hours=1),
        },
    ]
    rows = agent_mapper.deployments(entry, versions, limit=10)
    assert [(r.image_tag, r.outcome) for r in rows] == [("v2", "failed"), ("v1", "succeeded")]
    assert rows[0].id == "travel_agent-AbCdEf1234:v2"
    assert len(agent_mapper.deployments(entry, versions, limit=1)) == 1


# --- gateways ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("configuration", "expected"),
    [
        (None, "none"),
        ({}, "none"),
        ({"mode": "ENFORCE"}, "none"),
        ({"arn": ENGINE_ARN, "mode": "LOG_ONLY"}, "log_only"),
        ({"arn": ENGINE_ARN, "mode": "ENFORCE"}, "enforce"),
        ({"arn": ENGINE_ARN, "mode": "SOMETHING"}, "none"),
    ],
)
def test_enforcement_mode(configuration, expected):
    gateway = {"policyEngineConfiguration": configuration} if configuration is not None else {}
    assert mcp_mapper.enforcement_mode(gateway) == expected


def test_gateway_tools_join_registry_tool_records(settings):
    index = registry_mapper.tool_index([tool_record("tool-echo")])
    entry = mcp_mapper.gateway_entry(gateway_bundle("ENFORCE"), settings.cells[0], index)
    server = entry.server
    assert server.id == "ws1-tools-abcdefghij"
    assert server.kind == "gateway"
    assert server.cedar_enforcement_mode == "enforce"
    assert server.cedar_policy_engine_id == "ws1_engine-klmnopqrst"
    assert server.authorizer_type == "AWS_IAM"
    assert server.tenant_id == "ws1"
    assert entry.has_policy is True
    echo, connector = server.available_tools
    assert (echo.name, echo.registered, echo.owner, echo.cost_centre, echo.status, echo.version) == (
        "tool-echo",
        True,
        "platform-ai",
        "platform",
        "APPROVED",
        "2.0.0",
    )
    assert echo.description == "Echoes the input."
    assert echo.input_schema == {"type": "object"}
    assert (connector.name, connector.registered, connector.target_type) == ("inference-connector", False, "CONNECTOR")
    assert connector.input_schema == {}


def test_gateway_without_policy_engine(settings):
    entry = mcp_mapper.gateway_entry(gateway_bundle(None), settings.cells[0], {})
    assert entry.enforcement_mode == "none"
    assert entry.has_policy is False
    assert entry.server.cedar_policy_engine_arn is None


def test_policy_set_returns_cedar_text_as_is_and_not_editable(settings):
    entry = mcp_mapper.gateway_entry(gateway_bundle("LOG_ONLY"), settings.cells[0], {})
    permit = 'permit(\n  principal,\n  action == AgentCore::Action::"tool-echo",\n  resource\n);'
    forbid = "// containment\nforbid(principal, action, resource);"
    policies = [
        {"policyId": "p1", "name": "allow_echo", "status": "ACTIVE", "definition": {"cedar": {"statement": permit}}},
        {"policyId": "p2", "name": "deny_all", "status": "ACTIVE", "definition": {"cedar": {"statement": forbid}}},
    ]
    result = mcp_mapper.policy_set(entry, policies)
    assert result.enforcement_mode == "log_only"
    assert result.engine_id == "ws1_engine-klmnopqrst"
    assert result.editable is False
    assert [(p.policy_id, p.effect, p.cedar_text, p.editable, p.managed) for p in result.policies] == [
        ("p1", "allow", permit, False, False),
        ("p2", "deny", forbid, False, False),
    ]


# --- guardrails ----------------------------------------------------------------


def test_guardrail_detail_maps_to_template_shape():
    detail = {
        "guardrailId": "abc123",
        "guardrailArn": f"arn:aws:bedrock:{REGION}:111111111111:guardrail/abc123",
        "name": "baseline",
        "description": "Baseline guardrail",
        "version": "DRAFT",
        "status": "READY",
        "contentPolicy": {"filters": [{"type": "HATE", "inputStrength": "HIGH", "outputStrength": "MEDIUM"}]},
        "topicPolicy": {"topics": [{"name": "Advice", "definition": "No advice", "examples": ["x"], "type": "DENY"}]},
        "sensitiveInformationPolicy": {
            "piiEntities": [{"type": "EMAIL", "action": "ANONYMIZE"}],
            "regexes": [{"name": "id", "pattern": "\\d+", "action": "BLOCK"}],
        },
        "wordPolicy": {"words": [{"text": "secret"}], "managedWordLists": [{"type": "PROFANITY"}]},
        "contextualGroundingPolicy": {
            "filters": [{"type": "GROUNDING", "threshold": 0.8}, {"type": "RELEVANCE", "threshold": 0.6}]
        },
        "createdAt": T0,
        "updatedAt": T0,
    }
    template = guardrail_mapper.from_detail(detail)
    assert template.template_id == "abc123" and template.status == "active" and template.read_only is True
    assert template.content_filters == [{"type": "HATE", "input_strength": "HIGH", "output_strength": "MEDIUM"}]
    assert template.denied_topics == [{"name": "Advice", "definition": "No advice", "examples": ["x"]}]
    assert template.pii_entities == [{"type": "EMAIL", "action": "ANONYMIZE"}]
    assert template.sensitive_regexes[0]["pattern"] == "\\d+"
    assert template.word_filter == {"enable_profanity": True, "blocked_words": ["secret"]}
    assert template.contextual_grounding == {"enabled": True, "grounding_threshold": 0.8, "relevance_threshold": 0.6}


def test_guardrail_summary_status_mapping():
    summary = {"id": "abc123", "arn": "arn", "name": "g", "status": "VERSIONING", "version": "DRAFT", "createdAt": T0}
    assert guardrail_mapper.from_summary(summary).status == "updating"
    assert guardrail_mapper.from_summary({**summary, "status": "FAILED"}).status == "failed"


# --- traces and metrics ----------------------------------------------------------


def test_trace_row_from_query_result():
    row = observability_mapper.trace_row(
        {
            "traceId": "0123456789abcdef0123456789abcdef",
            "start_ns": "1768478400" + "000000500",
            "duration_ns": "3634818918",
            "input_tokens": "1200",
            "output_tokens": "300",
            "total_tokens": "1500",
            "http_status": "200",
            "user_id": "reviewer",
            "session_id": "session-1",
            "error_spans": "0",
        }
    )
    assert row is not None
    assert row.id == "0123456789abcdef0123456789abcdef"
    assert row.timestamp == "2026-01-15T12:00:00Z"
    assert row.latency_ms == 3634.8
    assert (row.input_tokens, row.output_tokens, row.total_tokens) == (1200, 300, 1500)
    assert row.status == "ok" and row.cost_usd == 0.0


def test_trace_row_status_and_missing_values():
    assert observability_mapper.trace_row({}) is None
    assert observability_mapper.trace_row({"traceId": "t", "error_spans": "2"}).status == "error"
    assert observability_mapper.trace_row({"traceId": "t", "http_status": "502"}).status == "error"
    assert observability_mapper.trace_row({"traceId": "t", "http_status": "404"}).status == "client_error"
    bare = observability_mapper.trace_row({"traceId": "t"})
    assert bare.timestamp is None and bare.latency_ms is None and bare.total_tokens is None


def test_agent_metrics_combines_cloudwatch_and_span_tokens():
    start = dt.datetime(2026, 1, 14, tzinfo=dt.UTC)
    end = dt.datetime(2026, 1, 15, 12, tzinfo=dt.UTC)
    series = {
        "m_invocations": {"2026-01-14": 4.0, "2026-01-15": 6.0},
        "m_system_errors": {"2026-01-15": 1.0},
        "m_user_errors": {"2026-01-15": 2.0},
        "m_latency": {"2026-01-14": 1000.0, "2026-01-15": 2000.0},
    }
    metrics = observability_mapper.agent_metrics(
        series,
        "m",
        start,
        end,
        token_days=[{"day": "2026-01-15 00:00:00.000", "tokens": "500"}],
        token_models=[{"model": "model-a", "input_tokens": "300", "output_tokens": "50"}],
        user_rows=[{"user_id": "u1", "traces": "3"}],
        warnings=["w"],
    )
    assert metrics.totals.model_dump() == {"traces": 10, "cost_usd": 0.0, "tokens": 500}
    assert [(d.date, d.traces, d.tokens, d.errors) for d in metrics.daily] == [
        ("2026-01-14", 4, 0, 0),
        ("2026-01-15", 6, 500, 3),
    ]
    assert metrics.by_model[0].model_dump() == {"model": "model-a", "cost_usd": 0.0, "tokens": 350}
    assert metrics.by_user[0].traces == 3
    assert metrics.runtime.latency_avg_ms == 1600.0
    assert metrics.runtime.system_errors == 1 and metrics.runtime.user_errors == 2
    assert metrics.cost_available is False and metrics.warnings == ["w"]


# --- release evidence -------------------------------------------------------------


@pytest.mark.parametrize(
    ("pipeline_status", "gate_status", "expected"),
    [
        ("Succeeded", "Succeeded", "passed"),
        ("Failed", "Failed", "failed"),
        ("InProgress", "InProgress", "running"),
        ("InProgress", None, "running"),
        ("Failed", None, "error"),
        ("Superseded", None, "error"),
        ("Failed", "Abandoned", "error"),
    ],
)
def test_run_status(pipeline_status, gate_status, expected):
    assert release_mapper.run_status(pipeline_status, gate_status) == expected


def test_eval_runs_from_pipeline_executions():
    items = [
        {
            "execution": {
                "pipelineExecutionId": "exec-1",
                "status": "Failed",
                "startTime": T0,
                "lastUpdateTime": T0 + dt.timedelta(minutes=7),
                "sourceRevisions": [{"actionName": "Source", "revisionId": "rev-1", "revisionSummary": "first"}],
                "trigger": {"triggerType": "Webhook", "triggerDetail": "arn:aws:sts::111111111111:assumed-role/x/y"},
            },
            "gate": None,
        },
        {
            "execution": {
                "pipelineExecutionId": "exec-2",
                "status": "Succeeded",
                "startTime": T0 + dt.timedelta(hours=1),
                "lastUpdateTime": T0 + dt.timedelta(hours=2),
                "sourceRevisions": [{"revisionId": "rev-2"}],
            },
            "gate": {
                "actionName": "EvaluationGate",
                "status": "Succeeded",
                "startTime": T0 + dt.timedelta(minutes=70),
                "lastUpdateTime": T0 + dt.timedelta(minutes=80),
                "output": {"executionResult": {"externalExecutionSummary": "All thresholds met"}},
            },
        },
    ]
    runs = release_mapper.eval_runs("agent-1", "nonprod", "agenticai-workload-ws1-travel-agent", items)
    assert [r.run_id for r in runs.runs] == ["exec-2", "exec-1"]
    newest, oldest = runs.runs
    assert newest.status == "passed" and newest.gate.passed is True and newest.git_sha == "rev-2"
    assert "All thresholds met" in newest.gate.reasons
    assert newest.pipeline.evaluation_gate_status == "Succeeded"
    assert oldest.status == "error" and oldest.gate.passed is False
    assert oldest.pipeline.trigger_type == "Webhook"
    assert "111111111111" not in oldest.model_dump_json()
    assert runs.current_run.run_id == "exec-2" and runs.current_build_tag == "rev-2"
