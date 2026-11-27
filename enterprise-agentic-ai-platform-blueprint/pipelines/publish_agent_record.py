#!/usr/bin/env python3
"""Publish one agent's governance record to the Platform AWS Agent Registry.

Run by the Workload pipeline after a cell's Runtime is deployed, so the
Registry holds a queryable inventory of agents next to the tool records. The
record is a CUSTOM record whose descriptor is an
`agenticai.agent-governance/1.0` document
(packages/agent-registry/schemas/agent-governance-1.0.json).

The operation is idempotent. The record name is derived from tenant, agent
and environment; an existing record with an identical document is left
untouched, a different document updates the record, and `--submit` sends a
new or changed record for approval. The script never approves a record:
approval stays with the Platform (registrar and approver are different
identities).

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "agenticai.agent-governance/1.0"
SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "packages"
    / "agent-registry"
    / "schemas"
    / "agent-governance-1.0.json"
)
REGISTRY_ID = re.compile(r"^[A-Za-z0-9]{16}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$")


class PublishError(RuntimeError):
    """The record cannot be published without weakening the contract."""


def record_name(tenant_id: str, agent_id: str, environment: str) -> str:
    return f"agent-{tenant_id}-{agent_id}-{environment}"


def _check(schema: Mapping[str, Any], value: Any, path: str) -> None:
    """Validate the subset of JSON Schema the governance schema uses."""
    if "const" in schema and value != schema["const"]:
        raise PublishError(f"{path} must be {schema['const']!r}")
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise PublishError(f"{path} must be an object")
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                raise PublishError(f"{path}.{name} is required")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise PublishError(f"{path} has unknown field(s): {', '.join(unknown)}")
        for name, item in value.items():
            if name in properties:
                _check(properties[name], item, f"{path}.{name}")
        return
    if kind == "array":
        if not isinstance(value, list):
            raise PublishError(f"{path} must be a list")
        if schema.get("uniqueItems") and len(set(map(json.dumps, value))) != len(value):
            raise PublishError(f"{path} must not repeat a value")
        for index, item in enumerate(value):
            _check(schema.get("items", {}), item, f"{path}[{index}]")
        return
    if kind == "string":
        if not isinstance(value, str):
            raise PublishError(f"{path} must be a string")
        if "enum" in schema and value not in schema["enum"]:
            raise PublishError(f"{path} must be one of {', '.join(schema['enum'])}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise PublishError(f"{path} does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0):
            raise PublishError(f"{path} is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise PublishError(f"{path} is longer than {schema['maxLength']} characters")


def validate_document(document: Mapping[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    _check(schema, document, "document")


def build_document(args: argparse.Namespace) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "tenantId": args.tenant_id,
        "agentId": args.agent_id,
        "environment": args.environment,
        "ownerGroup": args.owner_group,
        "businessPurpose": args.business_purpose,
        "riskClass": args.risk_class,
        "dataClassification": args.data_classification,
        "costCentre": args.cost_centre,
        "recordVersion": args.record_version,
    }
    optional = {
        "applicationId": args.application_id,
        "contact": args.contact,
        "framework": args.framework,
        "runtimeArn": args.runtime_arn,
        "gatewayArn": args.gateway_arn,
        "memoryId": args.memory_id,
        "policyEngineArn": args.policy_engine_arn,
        "policyEngineMode": args.policy_engine_mode,
        "sourceRevision": args.source_revision,
    }
    document.update({key: value for key, value in optional.items() if value})
    if args.subscribed_tool_id:
        document["subscribedToolIds"] = sorted(set(args.subscribed_tool_id))
    if args.golden_path_name or args.golden_path_version:
        if not (args.golden_path_name and args.golden_path_version):
            raise PublishError("--golden-path-name and --golden-path-version go together")
        document["goldenPath"] = {"name": args.golden_path_name, "version": args.golden_path_version}
    if args.evaluation_verdict:
        evaluation = {"verdict": args.evaluation_verdict}
        if args.evaluation_run_id:
            evaluation["runId"] = args.evaluation_run_id
        if args.evaluation_completed_at:
            evaluation["completedAt"] = args.evaluation_completed_at
        document["evaluation"] = evaluation
    validate_document(document)
    return document


def canonical(document: Mapping[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def find_record(client: Any, registry_id: str, name: str) -> dict[str, Any] | None:
    token: str | None = None
    matches: list[dict[str, Any]] = []
    while True:
        kwargs: dict[str, Any] = {"registryId": registry_id}
        if token:
            kwargs["nextToken"] = token
        page = client.list_registry_records(**kwargs)
        matches += [r for r in page.get("registryRecords", []) if r.get("name") == name]
        token = page.get("nextToken")
        if not token:
            break
    if len(matches) > 1:
        raise PublishError(f"{len(matches)} records are named {name}; refusing to choose one")
    return matches[0] if matches else None


TRANSITIONAL_STATUSES = {"CREATING", "UPDATING"}


def wait_until_settled(
    client: Any, registry_id: str, record_id: str, *, timeout: float = 120.0, interval: float = 3.0
) -> str:
    """Wait for the record to leave a transitional status; it cannot be submitted before."""
    deadline = time.monotonic() + timeout
    while True:
        status = client.get_registry_record(registryId=registry_id, recordId=record_id).get("status", "")
        if status not in TRANSITIONAL_STATUSES:
            return status
        if time.monotonic() >= deadline:
            raise PublishError(f"record {record_id} is still {status} after {int(timeout)} seconds")
        time.sleep(interval)


def publish(
    client: Any,
    registry_id: str,
    document: Mapping[str, Any],
    *,
    submit: bool,
    dry_run: bool,
) -> dict[str, Any]:
    """Create, update or leave the record. Returns what was done."""
    name = record_name(document["tenantId"], document["agentId"], document["environment"])
    data = canonical(document)
    description = f"Agent {document['agentId']} of {document['tenantId']} ({document['environment']})"
    existing = find_record(client, registry_id, name)
    if existing is None:
        if dry_run:
            return {"action": "would-create", "name": name}
        created = client.create_registry_record(
            registryId=registry_id,
            name=name,
            displayName=name,
            description=description,
            recordType="CUSTOM",
            descriptors={"custom": {"data": data}},
            recordVersion=document["recordVersion"],
            clientToken=hashlib.sha256(f"{registry_id}:{data}".encode()).hexdigest()[:64],
        )
        record_id = created.get("recordId") or str(created["recordArn"]).rsplit("/", 1)[-1]
        action = "created"
    else:
        record_id = existing["recordId"]
        current = client.get_registry_record(registryId=registry_id, recordId=record_id)
        if current.get("recordType") != "CUSTOM":
            raise PublishError(f"record {name} exists with type {current.get('recordType')}")
        current_data = (current.get("descriptors") or {}).get("custom", {}).get("data", "")
        try:
            current_document = json.loads(current_data)
        except ValueError as error:
            raise PublishError(f"record {name} holds a descriptor that is not JSON") from error
        if current_document.get("schemaVersion") != SCHEMA_VERSION:
            raise PublishError(f"record {name} is not an agent governance record; refusing to overwrite it")
        if canonical(current_document) == data:
            result = {"action": "unchanged", "name": name, "recordId": record_id, "status": current.get("status")}
            # A record left in DRAFT (for example by an interrupted run) still
            # needs to be submitted; anything else already went past this point.
            if submit and not dry_run and current.get("status") == "DRAFT":
                client.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
                result["submitted"] = True
            return result
        if dry_run:
            return {"action": "would-update", "name": name, "recordId": record_id}
        # UpdateRegistryRecord wraps every updatable field in `optionalValue`
        # (absent means "leave unchanged"), unlike CreateRegistryRecord.
        client.update_registry_record(
            registryId=registry_id,
            recordId=record_id,
            descriptors={
                "optionalValue": {"custom": {"optionalValue": {"data": {"optionalValue": data}}}}
            },
            recordVersion=document["recordVersion"],
        )
        action = "updated"
    result = {"action": action, "name": name, "recordId": record_id}
    if submit:
        wait_until_settled(client, registry_id, record_id)
        client.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
        result["submitted"] = True
    return result


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--environment", required=True, choices=["nonprod", "prod"])
    parser.add_argument("--owner-group", required=True)
    parser.add_argument("--business-purpose", required=True)
    parser.add_argument("--risk-class", required=True)
    parser.add_argument("--data-classification", required=True)
    parser.add_argument("--cost-centre", required=True)
    parser.add_argument("--record-version", required=True, help="semantic version of this record")
    parser.add_argument("--application-id")
    parser.add_argument("--contact")
    parser.add_argument("--framework")
    parser.add_argument("--golden-path-name")
    parser.add_argument("--golden-path-version")
    parser.add_argument("--runtime-arn")
    parser.add_argument("--gateway-arn")
    parser.add_argument("--memory-id")
    parser.add_argument("--subscribed-tool-id", action="append", default=[])
    parser.add_argument("--policy-engine-arn")
    parser.add_argument("--policy-engine-mode")
    parser.add_argument("--source-revision")
    parser.add_argument("--evaluation-verdict")
    parser.add_argument("--evaluation-run-id")
    parser.add_argument("--evaluation-completed-at")
    parser.add_argument("--submit", action="store_true", help="submit a new or changed record for approval")
    parser.add_argument("--dry-run", action="store_true", help="validate and report without writing")
    args = parser.parse_args(argv)
    if not REGISTRY_ID.fullmatch(args.registry_id):
        parser.error("--registry-id must be a 16-character Registry id")
    if not REGION.fullmatch(args.region):
        parser.error("--region must be a concrete AWS Region code")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        document = build_document(args)
        import boto3  # imported here so validation and --help need no SDK

        client = boto3.client("agent-registry-control", region_name=args.region)
        result = publish(client, args.registry_id, document, submit=args.submit, dry_run=args.dry_run)
    except PublishError as error:
        print(f"publish_agent_record: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
