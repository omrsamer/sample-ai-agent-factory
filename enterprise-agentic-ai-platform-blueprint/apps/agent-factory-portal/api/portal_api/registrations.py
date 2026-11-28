# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Agent governance records: document building, validation and mapping. No AWS calls.

Kept in step with ``pipelines/publish_agent_record.py``: the same canonical
JSON, the same record name and the same schema.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from portal_api.mappers import registry as registry_mapper
from portal_api.mappers.common import iso, text
from portal_api.models.portal import Registration, RegistrationInput

SCHEMA_VERSION = registry_mapper.AGENT_SCHEMA
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "agent-governance-1.0.json"
# ASCII only and applied with ``fullmatch``: ``\d`` would also match digits of other scripts, and
# ``$`` would also match before a final line feed.
RECORD_ID = re.compile(r"[A-Za-z0-9]{12}", re.ASCII)
_SEMVER = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)", re.ASCII)

# Fields that identify a record. The record name is derived from them, so they never change.
IDENTITY_FIELDS = ("tenantId", "agentId", "environment")

_SNAKE = {
    "schemaVersion": "schema_version",
    "tenantId": "tenant_id",
    "agentId": "agent_id",
    "applicationId": "application_id",
    "ownerGroup": "owner_group",
    "businessPurpose": "business_purpose",
    "riskClass": "risk_class",
    "dataClassification": "data_classification",
    "costCentre": "cost_centre",
    "goldenPath": "golden_path",
    "runtimeArn": "runtime_arn",
    "gatewayArn": "gateway_arn",
    "memoryId": "memory_id",
    "subscribedToolIds": "subscribed_tool_ids",
    "policyEngineArn": "policy_engine_arn",
    "policyEngineMode": "policy_engine_mode",
    "sourceRevision": "source_revision",
    "recordVersion": "record_version",
    "reviewBy": "review_by",
    "runId": "run_id",
    "completedAt": "completed_at",
}


class DocumentError(ValueError):
    """The document does not satisfy the governance schema. ``path`` names the offending field."""

    def __init__(self, message: str, path: str = "document") -> None:
        super().__init__(message)
        self.path = path

    def errors(self) -> list[dict[str, Any]]:
        """The error in the list form used for request validation: ``loc`` uses the request's field names."""
        # List positions are left out: lists are sorted before validation, so a position would mislead.
        loc: list[str] = ["body"]
        for part in re.findall(r"[A-Za-z]+", self.path.removeprefix("document")):
            loc.append(_SNAKE.get(part, part))
        message = str(self)
        if len(loc) > 1 and message.startswith(self.path):
            # Name the field the way the request does (risk_class, golden_path.name).
            message = ".".join(str(part) for part in loc[1:]) + message[len(self.path) :]
        return [{"loc": loc, "msg": message, "type": "document"}]


@lru_cache(maxsize=1)
def schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _check(node: dict[str, Any], value: Any, path: str) -> None:
    """Validate the subset of JSON Schema the governance schema uses."""
    if "const" in node and value != node["const"]:
        raise DocumentError(f"{path} must be {node['const']!r}", path)
    kind = node.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise DocumentError(f"{path} must be an object", path)
        properties = node.get("properties", {})
        for name in node.get("required", []):
            if name not in value:
                raise DocumentError(f"{path}.{name} is required", f"{path}.{name}")
        if node.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise DocumentError(f"{path} has unknown field(s): {', '.join(unknown)}", path)
        for name, item in value.items():
            if name in properties:
                _check(properties[name], item, f"{path}.{name}")
        return
    if kind == "array":
        if not isinstance(value, list):
            raise DocumentError(f"{path} must be a list", path)
        if node.get("uniqueItems") and len(set(map(json.dumps, value))) != len(value):
            raise DocumentError(f"{path} must not repeat a value", path)
        for index, item in enumerate(value):
            _check(node.get("items", {}), item, f"{path}[{index}]")
        return
    if kind == "string":
        if not isinstance(value, str):
            raise DocumentError(f"{path} must be a string", path)
        if "enum" in node and value not in node["enum"]:
            raise DocumentError(f"{path} must be one of {', '.join(node['enum'])}", path)
        if "pattern" in node and not _matches(node["pattern"], value):
            raise DocumentError(f"{path} does not match {node['pattern']}", path)
        if len(value) < node.get("minLength", 0):
            raise DocumentError(f"{path} is too short", path)
        if "maxLength" in node and len(value) > node["maxLength"]:
            raise DocumentError(f"{path} is longer than {node['maxLength']} characters", path)


def _matches(pattern: str, value: str) -> bool:
    """Whether ``value`` satisfies a pattern of the schema.

    In the schema ``$`` means the end of the value. Python's ``$`` also
    matches before a final line feed, so it is replaced by ``\\Z``, which
    does not: an ARN or an id followed by a line feed is not that ARN or id.
    """
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + "\\Z"
    return re.search(pattern, value, re.ASCII) is not None


def validate_document(document: dict[str, Any]) -> None:
    _check(schema(), document, "document")


def canonical(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def record_name(tenant_id: str, agent_id: str, environment: str) -> str:
    return f"agent-{tenant_id}-{agent_id}-{environment}"


def record_description(document: dict[str, Any]) -> str:
    return f"Agent {document['agentId']} of {document['tenantId']} ({document['environment']})"


def parse_version(value: Any) -> tuple[int, int, int] | None:
    match = _SEMVER.fullmatch(value) if isinstance(value, str) else None
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def next_version(current: Any, requested: str | None) -> str:
    """Version for an update: the caller's if it is higher than the current one, else a patch bump."""
    base = parse_version(current) or (1, 0, 0)
    if requested is not None:
        wanted = parse_version(requested)
        if wanted is None:
            raise DocumentError(
                "document.recordVersion must be a semantic version such as 1.2.3", "document.recordVersion"
            )
        if wanted <= base:
            raise DocumentError(
                f"document.recordVersion must be higher than the current version {'.'.join(map(str, base))}",
                "document.recordVersion",
            )
        return requested
    return f"{base[0]}.{base[1]}.{base[2] + 1}"


def build_document(body: RegistrationInput, record_version: str) -> dict[str, Any]:
    """The governance document for a request body. The server sets schemaVersion and recordVersion."""
    document: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "tenantId": body.tenant_id,
        "agentId": body.agent_id,
        "environment": body.environment,
        "ownerGroup": body.owner_group,
        "businessPurpose": body.business_purpose,
        "riskClass": body.risk_class,
        "dataClassification": body.data_classification,
        "costCentre": body.cost_centre,
        "recordVersion": record_version,
    }
    optional = {
        "applicationId": body.application_id,
        "contact": body.contact,
        "sponsor": body.sponsor,
        "reviewBy": body.review_by,
        "framework": body.framework,
        "runtimeArn": body.runtime_arn,
        "gatewayArn": body.gateway_arn,
        "memoryId": body.memory_id,
        "policyEngineArn": body.policy_engine_arn,
        "policyEngineMode": body.policy_engine_mode,
        "sourceRevision": body.source_revision,
    }
    document.update({key: value for key, value in optional.items() if value})
    if body.subscribed_tool_ids:
        document["subscribedToolIds"] = sorted(set(body.subscribed_tool_ids))
    if body.golden_path:
        document["goldenPath"] = {"name": body.golden_path.name, "version": body.golden_path.version}
    if body.evaluation:
        evaluation = {"verdict": body.evaluation.verdict}
        if body.evaluation.run_id:
            evaluation["runId"] = body.evaluation.run_id
        if body.evaluation.completed_at:
            evaluation["completedAt"] = body.evaluation.completed_at
        document["evaluation"] = evaluation
    validate_document(document)
    review_by = document.get("reviewBy")
    if review_by is not None:
        try:
            dt.date.fromisoformat(review_by)
        except ValueError as exc:
            raise DocumentError("document.reviewBy is not a calendar date", "document.reviewBy") from exc
    return document


def _snake(value: Any) -> Any:
    if isinstance(value, dict):
        return {_SNAKE.get(key, key): _snake(item) for key, item in value.items()}
    return value


def snake_document(canonical_json: str) -> dict[str, Any] | None:
    """A stored canonical document in the response form (snake_case keys), or ``None`` if unreadable."""
    try:
        document = json.loads(canonical_json)
    except ValueError:
        return None
    return _snake(document) if isinstance(document, dict) else None


def agent_document(record: dict[str, Any]) -> dict[str, Any] | None:
    """The record's governance document, or ``None`` when it is not an agent governance record."""
    document = registry_mapper.governance_document(record)
    if not document or document.get("schemaVersion") != SCHEMA_VERSION:
        return None
    return document


def to_registration(record: dict[str, Any], document: dict[str, Any]) -> Registration:
    return Registration(
        record_id=str(record["recordId"]),
        name=text(record.get("name")) or str(record["recordId"]),
        status=str(record.get("status") or "UNKNOWN"),
        lifecycle_state=registry_mapper.lifecycle_state(record),
        status_reason=text(record.get("statusReason")),
        record_version=text(record.get("recordVersion")) or text(document.get("recordVersion")),
        tenant_id=text(document.get("tenantId")),
        agent_id=text(document.get("agentId")),
        environment=text(document.get("environment")),
        document=_snake(document),
        document_sha256=sha256(canonical(document)),
        created_at=iso(record.get("createdAt")),
        updated_at=iso(record.get("updatedAt")),
    )
