# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Reading the append-only audit trail (Amazon DynamoDB). Query only; writes live in ``portal_api/actions``."""

from __future__ import annotations

from typing import Any

from portal_api.models.portal import AuditEvent

_FIELDS = (
    "event_id",
    "request_id",
    "at",
    "phase",
    "action",
    "outcome",
    "reason",
    "actor_subject",
    "actor_label",
    "actor_role",
    "tenant_id",
    "record_id",
    "record_name",
    "document_sha256",
    "status_before",
    "status_after",
)


def record_key(record_id: str) -> str:
    return f"RECORD#{record_id}"


def name_key(record_name: str) -> str:
    """Partition for decisions taken before a record id exists (a create, allowed or denied)."""
    return f"RECORD#NAME#{record_name}"


def from_item(item: dict[str, Any]) -> AuditEvent:
    values = {name: item[name]["S"] for name in _FIELDS if name in item and "S" in item[name]}
    return AuditEvent(**values)


# Attribute of an approve result event that holds the approved document (canonical JSON).
DOCUMENT_ATTRIBUTE = "document"


def query_events(client: Any, table: str, partition_key: str) -> list[AuditEvent]:
    """Every event of one partition, newest first, with a strongly consistent read."""
    return [from_item(item) for item in query_items(client, table, partition_key)]


def last_approved_document(items: list[dict[str, Any]]) -> str | None:
    """The canonical document stored with the latest completed approval, if any. ``items`` is newest first."""
    for item in items:
        event = from_item(item)
        if event.action == "approve" and event.phase == "result" and event.outcome == "allowed":
            return item.get(DOCUMENT_ATTRIBUTE, {}).get("S")
    return None


def query_items(client: Any, table: str, partition_key: str) -> list[dict[str, Any]]:
    """Every raw item of one partition, newest first, with a strongly consistent read."""
    events: list[dict[str, Any]] = []
    paginator = client.get_paginator("query")
    pages = paginator.paginate(
        TableName=table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": {"S": partition_key}, ":prefix": {"S": "EVENT#"}},
        ConsistentRead=True,
        ScanIndexForward=False,
    )
    for page in pages:
        events.extend(page.get("Items") or [])
    return events


def submitter(events: list[AuditEvent]) -> AuditEvent | None:
    """The event that names the record's current submitter.

    That is the latest ``submit`` that was allowed and performed. A submit
    whose intent was written but whose result is missing (the result write
    failed after the registry call) still counts, so a gap in the trail can
    only make self-approval harder, never easier. ``events`` is newest first.
    """
    results = {e.request_id: e for e in events if e.action == "submit" and e.phase == "result"}
    for event in events:
        if event.action != "submit" or event.outcome != "allowed":
            continue
        if event.phase == "result":
            return event
        if event.phase == "intent" and event.request_id not in results:
            return event
    return None
