# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Agent Registry records to portal shapes.

Two governance documents are recognised in a record's custom descriptor:
``agenticai.tool-governance/1.0`` (platform tools) and
``agenticai.agent-governance/1.0`` (deployed agents).
"""

from __future__ import annotations

import json
from typing import Any

from portal_api.mappers.common import text
from portal_api.models.portal import CatalogTool
from portal_api.models.wire import AgentGovernance

TOOL_SCHEMA = "agenticai.tool-governance/1.0"
AGENT_SCHEMA = "agenticai.agent-governance/1.0"

# Native record status -> the console's lifecycle state.
LIFECYCLE = {
    "DRAFT": "proposed",
    "CREATING": "proposed",
    "UPDATING": "proposed",
    "CREATE_FAILED": "proposed",
    "UPDATE_FAILED": "proposed",
    "PENDING_APPROVAL": "pending_approval",
    "APPROVED": "approved",
    "REJECTED": "rejected",
    "DEPRECATED": "deprecated",
}


def lifecycle_state(record: dict[str, Any]) -> str:
    return LIFECYCLE.get(str(record.get("status") or "").upper(), "proposed")


def governance_document(record: dict[str, Any]) -> dict[str, Any] | None:
    """The JSON document in ``descriptors.custom`` of a record, if it holds one."""
    custom = (record.get("descriptors") or {}).get("custom")
    if isinstance(custom, dict):
        raw = custom.get("data") or custom.get("inlineContent") or custom.get("content")
        if raw is None and "schemaVersion" in custom:
            return custom
    else:
        raw = custom
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        document = json.loads(raw)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def schema_of(record: dict[str, Any]) -> str | None:
    document = governance_document(record)
    return text(document.get("schemaVersion")) if document else None


def tool_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if schema_of(r) == TOOL_SCHEMA]


def agent_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if schema_of(r) == AGENT_SCHEMA]


def catalog_tool(record: dict[str, Any]) -> CatalogTool:
    document = governance_document(record) or {}
    ownership = document.get("ownership") or {}
    target = document.get("target") or {}
    tool_id = text(document.get("toolId")) or text(record.get("name")) or str(record.get("recordId"))
    return CatalogTool(
        tool_id=tool_id,
        name=text(record.get("displayName")) or text(record.get("name")) or tool_id,
        description=text(document.get("description")) or text(record.get("description")),
        owner=text(ownership.get("ownerTeam")),
        cost_centre=text(ownership.get("costCentre")),
        status=str(record.get("status") or "UNKNOWN"),
        version=text(record.get("recordVersion")),
        target_arn=text(target.get("arn")),
    )


def tool_index(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Tool records by tool id, for joining with gateway targets."""
    index: dict[str, dict[str, Any]] = {}
    for record in tool_records(records):
        document = governance_document(record) or {}
        tool_id = text(document.get("toolId")) or text(record.get("name"))
        if tool_id:
            index[tool_id] = record
    return index


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def agent_governance(record: dict[str, Any]) -> AgentGovernance:
    document = governance_document(record) or {}
    golden = document.get("goldenPath")
    evaluation = document.get("evaluation")
    return AgentGovernance(
        tenant_id=text(document.get("tenantId")),
        agent_id=text(document.get("agentId")),
        application_id=text(document.get("applicationId")),
        environment=text(document.get("environment")),
        owner_group=text(document.get("ownerGroup")),
        contact=text(document.get("contact")),
        business_purpose=text(document.get("businessPurpose")),
        risk_class=text(document.get("riskClass")),
        data_classification=text(document.get("dataClassification")),
        cost_centre=text(document.get("costCentre")),
        framework=text(document.get("framework")),
        golden_path=(
            {k: str(v) for k, v in golden.items() if k in ("name", "version")} if isinstance(golden, dict) else None
        ),
        runtime_arn=text(document.get("runtimeArn")),
        gateway_arn=text(document.get("gatewayArn")),
        memory_id=text(document.get("memoryId")),
        subscribed_tool_ids=_strings(document.get("subscribedToolIds")),
        policy_engine_arn=text(document.get("policyEngineArn")),
        policy_engine_mode=text(document.get("policyEngineMode")),
        source_revision=text(document.get("sourceRevision")),
        evaluation=(
            {k: v for k, v in evaluation.items() if k in ("verdict", "runId", "completedAt")}
            if isinstance(evaluation, dict)
            else None
        ),
        record_version=text(document.get("recordVersion")) or text(record.get("recordVersion")),
    )
