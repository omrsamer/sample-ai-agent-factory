# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Records of the organization-scoped discovery registry (AWS Agent Registry auto-detection).

Auto-detection creates one record per AgentCore Runtime (record type AGENT)
and Gateway (record type GATEWAY) in the organization's accounts. Each record
carries provenance with relation ``DETECTED_FROM`` and the source ARN.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from portal_api.mappers.common import arn_parts, text

RUNTIME_SOURCE = "AWS::BedrockAgentCore::Runtime"
GATEWAY_SOURCE = "AWS::BedrockAgentCore::Gateway"


@dataclass(frozen=True)
class Detection:
    """One resource the discovery registry detected."""

    arn: str
    kind: str  # "runtime" | "gateway"
    record_id: str | None
    record_name: str | None
    authorizer_type: str | None = None  # "AWS_IAM" | "CUSTOM_JWT" | as reported for a gateway
    protocol: str | None = None
    workload_identity_arn: str | None = None
    detected_at: Any = None


def _provenance(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Provenance entries of a full record or of a list summary."""
    entries = record.get("provenance") or record.get("provenanceSummaryList") or []
    return [e for e in entries if isinstance(e, dict)]


def _authorizer(details: dict[str, Any], default: str | None) -> str | None:
    if text(details.get("authorizerType")):
        return str(details["authorizerType"])
    configuration = details.get("authorizerConfiguration") or {}
    if isinstance(configuration, dict) and configuration.get("customJWTAuthorizer"):
        return "CUSTOM_JWT"
    return default


def detections(records: list[dict[str, Any]]) -> list[Detection]:
    """Every detected Runtime and Gateway, one per source ARN."""
    found: dict[str, Detection] = {}
    for record in records:
        for entry in _provenance(record):
            arn = text(entry.get("sourceId"))
            parts = arn_parts(arn)
            if not arn or not parts or parts["service"] != "bedrock-agentcore":
                continue
            source_type = entry.get("sourceType")
            if source_type == RUNTIME_SOURCE or parts["resource"].startswith("runtime/"):
                kind, key = "runtime", "agentcoreRuntime"
            elif source_type == GATEWAY_SOURCE or parts["resource"].startswith("gateway/"):
                kind, key = "gateway", "agentcoreGateway"
            else:
                continue
            details = (entry.get("sourceDetails") or {}).get(key) or {}
            has_details = bool(details)
            protocol = (details.get("protocolConfiguration") or {}).get("serverProtocol") or details.get("protocolType")
            found.setdefault(
                arn,
                Detection(
                    arn=arn,
                    kind=kind,
                    record_id=text(record.get("recordId")),
                    record_name=text(record.get("name")),
                    # A Runtime with no JWT authorizer is invoked with AWS IAM. Unknown without details.
                    authorizer_type=_authorizer(details, "AWS_IAM" if kind == "runtime" and has_details else None),
                    protocol=text(protocol),
                    workload_identity_arn=text(
                        (details.get("workloadIdentityDetails") or {}).get("workloadIdentityArn")
                    ),
                    detected_at=record.get("createdAt"),
                ),
            )
    return list(found.values())
