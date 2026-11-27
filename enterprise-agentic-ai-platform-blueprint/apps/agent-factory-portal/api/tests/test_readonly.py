# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The code base calls no mutating AWS operation, and IAM_ACTIONS.md lists exactly what it calls."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = sorted((ROOT / "portal_api").rglob("*.py"))

# Every boto3 operation the code is allowed to call, with its IAM action.
ALLOWED = {
    "assume_role": "sts:AssumeRole",
    "list_registry_records": "agent-registry:ListRegistryRecords",
    "get_registry_record": "agent-registry:GetRegistryRecord",
    "list_pipeline_executions": "codepipeline:ListPipelineExecutions",
    "list_action_executions": "codepipeline:ListActionExecutions",
    "list_guardrails": "bedrock:ListGuardrails",
    "get_guardrail": "bedrock:GetGuardrail",
    "list_tags_for_resource": "bedrock:ListTagsForResource / bedrock-agentcore:ListTagsForResource",
    "list_agent_runtimes": "bedrock-agentcore:ListAgentRuntimes",
    "get_agent_runtime": "bedrock-agentcore:GetAgentRuntime",
    "list_agent_runtime_versions": "bedrock-agentcore:ListAgentRuntimeVersions",
    "list_gateways": "bedrock-agentcore:ListGateways",
    "get_gateway": "bedrock-agentcore:GetGateway",
    "list_gateway_targets": "bedrock-agentcore:ListGatewayTargets",
    "get_gateway_target": "bedrock-agentcore:GetGatewayTarget",
    "list_policies": "bedrock-agentcore:ListPolicies",
    "get_policy": "bedrock-agentcore:GetPolicy",
    "describe_alarms": "cloudwatch:DescribeAlarms",
    "describe_alarm_history": "cloudwatch:DescribeAlarmHistory",
    "get_metric_data": "cloudwatch:GetMetricData",
    "start_query": "logs:StartQuery",
    "get_query_results": "logs:GetQueryResults",
}
MUTATING = re.compile(
    r"\b(create|update|delete|put|tag|untag|start|stop|submit|invoke|attach|detach|register|deregister|"
    r"associate|disassociate|set|modify|remove|add|enable|disable|cancel|approve|reject)_[a-z_]+\("
)
# start_query starts a read-only Logs Insights query; the others are web-framework calls, not AWS calls.
_NOT_MUTATING = ("start_query", "create_app", "add_middleware", "add_exception_handler")
CALL = re.compile(r"client\.([a-z_]+)\(")
PAGINATED = re.compile(r"""(?:paginate\(\s*[a-z_.()"\s]*?,|get_paginator\()\s*"([a-z_]+)\"""")


def _operations() -> set[str]:
    found: set[str] = set()
    for path in SOURCE:
        text = path.read_text()
        found.update(m for m in CALL.findall(text) if m not in ("get_paginator",))
        found.update(PAGINATED.findall(text))
        found.update(re.findall(r"\.(assume_role)\(", text))
    return found


def test_only_allow_listed_operations_are_called():
    assert _operations() == set(ALLOWED)


def test_no_mutating_operation_appears_in_the_source():
    for path in SOURCE:
        for match in MUTATING.finditer(path.read_text()):
            assert match.group(0).rstrip("(") in _NOT_MUTATING, f"{path.name}: {match.group(0)}"


def test_iam_actions_document_lists_exactly_the_actions_the_code_calls():
    text = (ROOT / "IAM_ACTIONS.md").read_text().split("## 3.")[0]
    documented = set(re.findall(r"`([a-z-]+:[A-Za-z]+)`", text))
    expected = set()
    for value in ALLOWED.values():
        expected.update(part.strip() for part in value.split("/"))
    assert documented == expected


def test_routes_register_get_only():
    from portal_api.app import create_app

    methods: set[str] = set()

    def walk(routes):
        for route in routes:
            methods.update(getattr(route, "methods", None) or set())
            inner = getattr(route, "routes", None) or getattr(getattr(route, "router", None), "routes", None)
            if inner:
                walk(inner)

    walk(create_app().routes)
    assert methods <= {"GET", "HEAD"}
