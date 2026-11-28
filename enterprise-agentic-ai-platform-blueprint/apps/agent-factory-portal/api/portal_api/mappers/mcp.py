# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Workstream Tool Gateways as the console's MCP server shape."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from portal_api.config import Cell
from portal_api.mappers import registry as registry_mapper
from portal_api.mappers.agents import TAG_AGENT, TAG_ENVIRONMENT, TAG_TENANT
from portal_api.mappers.common import EPOCH_ISO, arn_parts, arn_resource_id, iso, text
from portal_api.models.wire import CedarPolicyRow, CedarPolicySet, McpServer, McpTool

_MODES = {"LOG_ONLY": "log_only", "ENFORCE": "enforce"}
# The policy mode of a gateway that no reader read. Not "none": that would claim it has no policy engine.
UNKNOWN_MODE = "unknown"
SOURCE_ORGANIZATION_REGISTRY = "organization_registry"
READER_OK, READER_NONE, READER_UNREACHABLE, READER_NOT_LISTED = "ok", "none", "unreachable", "not_listed"
_NOT_SHOWN = "so its targets, its policy engine and its policies cannot be shown"
NOT_READ = {
    READER_NONE: f"There is no reader role in this gateway's account, {_NOT_SHOWN}.",
    READER_UNREACHABLE: f"The reader role in this gateway's account could not be used, {_NOT_SHOWN}.",
    READER_NOT_LISTED: (
        f"The reader in this gateway's account did not list this gateway, {_NOT_SHOWN}. "
        "It may have been deleted since the organization registry detected it."
    ),
}


@dataclass
class GatewayEntry:
    server: McpServer
    # The cell whose reader read the gateway. None for a gateway known from the organization
    # registry only: nothing of it can be read, so nothing about it is claimed.
    cell: Cell | None
    arn: str
    url: str | None
    tags: dict[str, str]
    policy_engine_arn: str | None
    enforcement_mode: str  # "none" | "log_only" | "enforce", or "unknown" when no reader read it

    @property
    def read(self) -> bool:
        return self.cell is not None

    @property
    def has_policy(self) -> bool:
        return self.policy_engine_arn is not None and self.enforcement_mode in ("log_only", "enforce")


def enforcement_mode(gateway: dict[str, Any]) -> str:
    """none | log_only | enforce, from the gateway's policy engine configuration."""
    configuration = gateway.get("policyEngineConfiguration") or {}
    if not configuration.get("arn"):
        return "none"
    return _MODES.get(str(configuration.get("mode") or "").upper(), "none")


def _inline_tools(target: dict[str, Any]) -> list[dict[str, Any]]:
    mcp = (target.get("targetConfiguration") or {}).get("mcp") or {}
    payload = ((mcp.get("lambda") or {}).get("toolSchema") or {}).get("inlinePayload")
    return [t for t in payload if isinstance(t, dict) and t.get("name")] if isinstance(payload, list) else []


def _target_type(target: dict[str, Any]) -> str | None:
    if target.get("targetType"):
        return str(target["targetType"])
    configuration = target.get("targetConfiguration") or {}
    for family in ("mcp", "inference"):
        inner = configuration.get(family)
        if isinstance(inner, dict) and inner:
            return f"{family}:{next(iter(inner))}"
    return None


def tools(targets: list[dict[str, Any]], tool_index: dict[str, dict[str, Any]]) -> list[McpTool]:
    """Tools of a gateway: its targets joined with the registry's tool records.

    A Lambda target with an inline tool schema contributes one tool per schema
    entry. Any other target contributes one row named after the target.
    """
    result: list[McpTool] = []
    for target in targets:
        target_name = text(target.get("name")) or str(target.get("targetId"))
        definitions = _inline_tools(target) or [{"name": target_name, "description": target.get("description")}]
        for definition in definitions:
            name = str(definition["name"])
            record = tool_index.get(name) or tool_index.get(target_name)
            catalog = registry_mapper.catalog_tool(record) if record else None
            document = registry_mapper.governance_document(record) if record else None
            registry_schema = ((document or {}).get("mcp") or {}).get("inputSchema")
            schema = definition.get("inputSchema") or registry_schema or {}
            result.append(
                McpTool(
                    name=name,
                    description=text(definition.get("description")) or (catalog.description if catalog else None),
                    input_schema=schema if isinstance(schema, dict) else {},
                    tool_id=catalog.tool_id if catalog else None,
                    target_name=target_name,
                    target_type=_target_type(target),
                    target_status=text(target.get("status")),
                    registered=catalog is not None,
                    owner=catalog.owner if catalog else None,
                    cost_centre=catalog.cost_centre if catalog else None,
                    status=catalog.status if catalog else None,
                    version=catalog.version if catalog else None,
                )
            )
    return result


def gateway_entry(bundle: dict[str, Any], cell: Cell, tool_index: dict[str, dict[str, Any]]) -> GatewayEntry:
    gateway = bundle["gateway"]
    tags = dict(bundle.get("tags") or {})
    arn = gateway["gatewayArn"]
    parts = arn_parts(arn) or {}
    configuration = gateway.get("policyEngineConfiguration") or {}
    engine_arn = text(configuration.get("arn"))
    mode = enforcement_mode(gateway)
    created = iso(gateway.get("createdAt")) or EPOCH_ISO
    status = str(gateway.get("status") or "UNKNOWN")
    server = McpServer(
        id=gateway["gatewayId"],
        name=text(gateway.get("name")) or gateway["gatewayId"],
        description=text(gateway.get("description")),
        region=parts.get("region") or cell.region,
        endpoint_url=text(gateway.get("gatewayUrl")),
        available_tools=tools(bundle.get("targets") or [], tool_index),
        gateway_arn=arn,
        cedar_policy_engine_id=arn_resource_id(engine_arn),
        cedar_policy_engine_arn=engine_arn,
        cedar_enforcement_mode=mode,
        gateway_id=gateway["gatewayId"],
        gateway_url=text(gateway.get("gatewayUrl")),
        # A gateway is created only by its cell's pipeline; READY means it is released.
        lifecycle_state="approved" if status == "READY" else "proposed",
        tenant_id=tags.get(TAG_TENANT),
        created_at=created,
        updated_at=iso(gateway.get("updatedAt")) or created,
        gateway_status=status,
        authorizer_type=text(gateway.get("authorizerType")),
        environment=tags.get(TAG_ENVIRONMENT),
        account_id=parts.get("account") or cell.account_id,
        agent_id=tags.get(TAG_AGENT),
        protocol=text(gateway.get("protocolType")),
    )
    return GatewayEntry(
        server=server,
        cell=cell,
        arn=arn,
        url=text(gateway.get("gatewayUrl")),
        tags=tags,
        policy_engine_arn=engine_arn,
        enforcement_mode=mode,
    )


def gateway_from_detection(detection: Any, reader_status: str) -> GatewayEntry:
    """A gateway known only from the organization registry: identity, authorizer and protocol.

    Its status, targets, tags, policy engine and policy mode are not known and
    are not guessed: no tools, no tenant, and the mode is ``unknown``.
    """
    parts = arn_parts(detection.arn) or {}
    gateway_id = arn_resource_id(detection.arn) or detection.arn
    detected = iso(detection.detected_at) or EPOCH_ISO
    server = McpServer(
        id=gateway_id,
        name=gateway_id.rsplit("-", 1)[0] or gateway_id,
        region=parts.get("region") or None,
        gateway_arn=detection.arn,
        cedar_enforcement_mode=UNKNOWN_MODE,
        gateway_id=gateway_id,
        lifecycle_state="discovered",
        created_at=detected,
        updated_at=detected,
        gateway_status="UNKNOWN",
        authorizer_type=detection.authorizer_type,
        account_id=parts.get("account") or None,
        detection_sources=[SOURCE_ORGANIZATION_REGISTRY],
        reader_status=reader_status,
        protocol=detection.protocol,
        detail=NOT_READ[reader_status],
    )
    return GatewayEntry(
        server=server,
        cell=None,
        arn=detection.arn,
        url=None,
        tags={},
        policy_engine_arn=None,
        enforcement_mode=UNKNOWN_MODE,
    )


def _effect(statement: str) -> str:
    for line in statement.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("@"):
            continue
        return "deny" if stripped.lower().startswith("forbid") else "allow"
    return "allow"


def policy_set(
    entry: GatewayEntry, policies: list[dict[str, Any]], warnings: list[str] | None = None
) -> CedarPolicySet:
    """The gateway's Cedar policies exactly as stored, marked not editable."""
    rows = []
    for policy in policies:
        statement = str(((policy.get("definition") or {}).get("cedar") or {}).get("statement") or "")
        rows.append(
            CedarPolicyRow(
                policy_id=str(policy.get("policyId")),
                effect=_effect(statement),
                cedar_text=statement,
                managed=False,
                editable=False,
                name=text(policy.get("name")),
                status=text(policy.get("status")),
            )
        )
    return CedarPolicySet(
        enforcement_mode=entry.enforcement_mode,
        engine_id=arn_resource_id(entry.policy_engine_arn),
        policies=rows,
        editable=False,
        warnings=warnings or [],
    )
