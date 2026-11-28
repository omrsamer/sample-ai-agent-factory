# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared fixtures. Nothing here touches the network: AWS is replaced by hand-written fakes."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from portal_api import config as config_module
from portal_api import deps
from portal_api.aws.cache import TTLCache
from portal_api.config import load_settings
from portal_api.service import PortalService

PLATFORM_ACCOUNT = "111111111111"
CELL_ACCOUNT = "444444444444"
OTHER_ACCOUNT = "777777777777"
REGION = "eu-west-1"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{CELL_ACCOUNT}:runtime/travel_agent-AbCdEf1234"
ORPHAN_RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{CELL_ACCOUNT}:runtime/orphan_agent-ZyXwVu9876"
GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{CELL_ACCOUNT}:gateway/ws1-tools-abcdefghij"
GATEWAY_URL = f"https://ws1-tools-abcdefghij.gateway.bedrock-agentcore.{REGION}.amazonaws.com/mcp"
ENGINE_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{CELL_ACCOUNT}:policy-engine/ws1_engine-klmnopqrst"
T0 = dt.datetime(2026, 1, 15, 12, 0, tzinfo=dt.UTC)

CELLS = [
    {
        "tenantId": "ws1",
        "agentId": "travel-agent",
        "applicationId": "travel",
        "environment": "nonprod",
        "accountId": CELL_ACCOUNT,
        "region": REGION,
        "readerRoleArn": f"arn:aws:iam::{CELL_ACCOUNT}:role/agenticai-portal-reader",
        "externalId": "portal-ext-id",
        "pipelineName": "agenticai-workload-ws1-travel-agent",
        "containmentRoleArn": f"arn:aws:iam::{CELL_ACCOUNT}:role/agenticai-portal-containment",
        "containmentSpans": True,
    },
    {
        "tenantId": "ws2",
        "agentId": "claims-agent",
        "environment": "prod",
        "accountId": OTHER_ACCOUNT,
        "region": REGION,
        "readerRoleArn": f"arn:aws:iam::{OTHER_ACCOUNT}:role/agenticai-portal-reader",
        "alarmNamePrefix": "custom-prefix-",
    },
]

BASE_ENV = {
    "PORTAL_ENV": "nonprod",
    "PORTAL_REGISTRY_ID": "REGISTRYID000001",
    "PORTAL_REGISTRY_REGION": REGION,
    "PORTAL_CELLS": json.dumps(CELLS),
    "PORTAL_IDENTITY_PROVIDER": "cognito",
    "PORTAL_GROUP_ROLE_MAP": json.dumps(
        {
            "platform-admins": "platform",
            "sec": "security",
            "devs": "developer",
            "devs2": "developer",
            "approvers": "approver",
            "approvers2": "approver",
            "sre-team": "sre",
            "sre-team2": "sre",
            "viewers": "readonly",
        }
    ),
    "PORTAL_GROUP_TENANT_MAP": json.dumps(
        {
            "platform-admins": ["*"],
            "sec": ["ws1", "ws2"],
            "devs": ["ws1"],
            "devs2": ["ws2"],
            "approvers": ["ws1"],
            "approvers2": ["ws2"],
            "sre-team": ["ws1"],
            "sre-team2": ["ws2"],
        }
    ),
    "PORTAL_AUDIT_TABLE": "agenticai-portal-audit-test",
    "PORTAL_GUARDRAIL_TAG_KEY": "agenticai:blueprint",
    "PORTAL_GUARDRAIL_TAG_VALUE": "true",
    "PORTAL_MODEL_ALLOWLIST": json.dumps(
        ["anthropic.claude-haiku-4-5-20251001-v1:0", {"modelId": "eu.amazon.nova-pro-v1:0", "regions": ["eu-west-1"]}]
    ),
    "PORTAL_ALLOWED_ORIGINS": json.dumps(["https://portal.example.com"]),
    "PORTAL_CACHE_TTL_SECONDS": "30",
}


def tool_record(tool_id: str = "tool-echo", status: str = "APPROVED") -> dict[str, Any]:
    document = {
        "schemaVersion": "agenticai.tool-governance/1.0",
        "catalogueVersion": "2",
        "toolId": tool_id,
        "description": f"{tool_id} description",
        "desiredApprovalStatus": "approved",
        "target": {"type": "lambda", "arn": f"arn:aws:lambda:{REGION}:{PLATFORM_ACCOUNT}:function:{tool_id}:PROD"},
        "mcp": {
            "toolName": tool_id,
            "description": f"{tool_id} description",
            "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
        },
        "authorization": {
            "defaultDecision": "DENY",
            "cedarPolicy": "permit(principal, action, resource);",
            "allowedSubjects": [],
            "allowedGroups": [],
            "combination": "AUTHENTICATED",
        },
        "ownership": {"ownerTeam": "platform-ai", "costCentre": "platform"},
    }
    return {
        "recordId": f"rec{tool_id.replace('-', '')}",
        "name": tool_id,
        "displayName": tool_id,
        "description": f"{tool_id} record description",
        "recordType": "CUSTOM",
        "descriptors": {"custom": {"data": json.dumps(document)}},
        "recordVersion": "2.0.0",
        "status": status,
        "createdAt": T0,
        "updatedAt": T0 + dt.timedelta(hours=1),
        "createdBy": PLATFORM_ACCOUNT,
    }


def agent_document(**overrides: Any) -> dict[str, Any]:
    document = {
        "schemaVersion": "agenticai.agent-governance/1.0",
        "tenantId": "ws1",
        "agentId": "travel-agent",
        "applicationId": "travel",
        "environment": "nonprod",
        "ownerGroup": "travel-owners",
        "contact": "travel-owners@example.com",
        "sponsor": "Sam Sponsor",
        "reviewBy": "2099-12-31",
        "businessPurpose": "Plans trips for employees.",
        "riskClass": "limited",
        "dataClassification": "confidential",
        "costCentre": "cc-100",
        "framework": "strands",
        "goldenPath": {"name": "strands-runtime", "version": "1.2.0"},
        "runtimeArn": RUNTIME_ARN,
        "gatewayArn": GATEWAY_ARN,
        "memoryId": "mem-0001",
        "subscribedToolIds": ["tool-echo"],
        "policyEngineArn": ENGINE_ARN,
        "policyEngineMode": "LOG_ONLY",
        "sourceRevision": "abc1234",
        "evaluation": {"verdict": "passed", "runId": "run-1", "completedAt": "2026-01-15T12:00:00Z"},
        "recordVersion": "1.0.0",
    }
    document.update(overrides)
    return document


def agent_record(status: str = "APPROVED", record_id: str = "recAgent0001", **overrides: Any) -> dict[str, Any]:
    return {
        "recordId": record_id,
        "name": "agent-ws1-travel-agent-nonprod",
        "displayName": "agent-ws1-travel-agent-nonprod",
        "description": "Travel agent record",
        "recordType": "CUSTOM",
        "descriptors": {"custom": {"data": json.dumps(agent_document(**overrides))}},
        "recordVersion": "1.0.0",
        "status": status,
        "createdAt": T0,
        "updatedAt": T0 + dt.timedelta(hours=2),
        "createdBy": PLATFORM_ACCOUNT,
    }


IDENTITY_TAGS = {"tenant-id": "ws1", "agent-id": "travel-agent", "environment": "nonprod", "cost-centre": "cc-100"}


def runtime_bundle(
    arn: str = RUNTIME_ARN, tags: dict[str, str] | None = None, gateway_url: str | None = None, status: str = "READY"
) -> dict[str, Any]:
    runtime_id = arn.rsplit("/", 1)[-1]
    return {
        "summary": {
            "agentRuntimeArn": arn,
            "agentRuntimeId": runtime_id,
            "agentRuntimeVersion": "2",
            "agentRuntimeName": runtime_id.rsplit("-", 1)[0],
            "description": "A runtime",
            "lastUpdatedAt": T0 + dt.timedelta(hours=3),
            "status": status,
        },
        "detail": {"createdAt": T0, "gatewayUrl": gateway_url},
        "tags": dict(IDENTITY_TAGS if tags is None else tags),
    }


def gateway_bundle(mode: str | None = "LOG_ONLY", tags: dict[str, str] | None = None) -> dict[str, Any]:
    gateway: dict[str, Any] = {
        "gatewayArn": GATEWAY_ARN,
        "gatewayId": GATEWAY_ARN.rsplit("/", 1)[-1],
        "gatewayUrl": GATEWAY_URL,
        "name": "ws1-tools",
        "description": "Workstream Tool Gateway",
        "status": "READY",
        "authorizerType": "AWS_IAM",
        "protocolType": "MCP",
        "createdAt": T0,
        "updatedAt": T0,
    }
    if mode:
        gateway["policyEngineConfiguration"] = {"arn": ENGINE_ARN, "mode": mode}
    targets = [
        {
            "targetId": "TARGET0001",
            "name": "tool-echo",
            "status": "READY",
            "description": "Echo target",
            "targetConfiguration": {
                "mcp": {
                    "lambda": {
                        "lambdaArn": f"arn:aws:lambda:{REGION}:{PLATFORM_ACCOUNT}:function:tool-echo:PROD",
                        "toolSchema": {
                            "inlinePayload": [
                                {
                                    "name": "tool-echo",
                                    "description": "Echoes the input.",
                                    "inputSchema": {"type": "object"},
                                }
                            ]
                        },
                    }
                }
            },
        },
        {
            "targetId": "TARGET0002",
            "name": "inference-connector",
            "status": "READY",
            "description": "Inference connector",
            "targetType": "CONNECTOR",
            "targetConfiguration": {"inference": {"connector": {"source": {"connectorId": "example"}}}},
        },
    ]
    return {"gateway": gateway, "targets": targets, "tags": dict(IDENTITY_TAGS if tags is None else tags)}


@pytest.fixture(autouse=True)
def portal_env(monkeypatch: pytest.MonkeyPatch):
    """A complete, valid configuration; individual tests remove or break entries."""
    config_module._cached_action = None
    for key in list(config_module._CONFIG_KEYS) + ["PORTAL_DEV_AUTH", "AWS_LAMBDA_FUNCTION_NAME"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    config_module._cached = None
    deps._service = None
    yield
    config_module._cached = None
    deps._service = None


@pytest.fixture
def settings():
    return load_settings(BASE_ENV)


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self._pages


class FakeClient:
    """A stand-in for one boto3 client: canned responses per operation, calls recorded."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get_paginator(self, operation: str) -> FakePaginator:
        self.calls.append((f"paginate:{operation}", {}))
        value = self.responses.get(operation, [{}])
        if isinstance(value, Exception):
            raise value
        return FakePaginator(value)

    def __getattr__(self, operation: str) -> Any:
        def call(**kwargs: Any) -> Any:
            self.calls.append((operation, kwargs))
            value = self.responses.get(operation, {})
            if isinstance(value, Exception):
                raise value
            return value(**kwargs) if callable(value) else value

        return call


class FakeClients:
    """Replaces AwsClients. Keys: ("platform", service) and (account id, service)."""

    def __init__(self, clients: dict[tuple[str, str], Any]) -> None:
        self.clients = clients
        self.cell_calls: list[tuple[str, str]] = []

    def platform(self, service: str, region: str) -> Any:
        return self.clients[("platform", service)]

    def cell(self, cell: Any, service: str) -> Any:
        self.cell_calls.append((cell.account_id, service))
        client = self.clients.get((cell.account_id, service))
        if isinstance(client, Exception):
            raise client
        if client is None:
            raise RuntimeError(f"no fake for {cell.account_id}/{service}")
        return client


def make_service(settings: Any, clients: FakeClients) -> PortalService:
    return PortalService(settings, clients=clients, cache=TTLCache())  # type: ignore[arg-type]
