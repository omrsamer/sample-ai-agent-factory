# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Appending to the audit trail. One item per event; an item is never updated or deleted."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from botocore.exceptions import ClientError

from portal_api.aws import audit
from portal_api.models.portal import AuditEvent
from portal_api.reviews import KIND_REVIEW


def new_request_id() -> str:
    return str(uuid.uuid4())


def now_stamp() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def put_event(
    client: Any, table: str, partition_key: str, event: AuditEvent, attributes: dict[str, str] | None = None
) -> None:
    """Write one event. The condition makes the write append-only: an existing item is never replaced.

    ``attributes`` are extra string attributes stored with the event (the approved document on an approval).
    """
    item = {"pk": {"S": partition_key}, "sk": {"S": f"EVENT#{event.at}#{event.event_id}"}}
    for name, value in (attributes or {}).items():
        item[name] = {"S": value}
    for name, value in event.model_dump().items():
        if value is not None and value != "":
            item[name] = {"S": str(value)}
    _append(client, table, item)


def put_attestation(
    client: Any,
    table: str,
    *,
    at: str,
    record_id: str,
    next_review_by: str,
    reviewed_by: str,
    reviewed_by_label: str,
    reviewed_by_role: str,
    reason: str,
    request_id: str,
    record_name: str | None = None,
    tenant_id: str | None = None,
    kind: str = KIND_REVIEW,
) -> None:
    """Write one attestation to the partition that holds them all. Append-only like every event.

    ``kind`` is ``review`` for a review attestation and ``approval`` for the one an approval
    records. ``request_id`` ties it to the intent and result events in the record's own partition.
    """
    fields = {
        "kind": kind,
        "at": at,
        "record_id": record_id,
        "next_review_by": next_review_by,
        "reviewed_by": reviewed_by,
        "reviewed_by_label": reviewed_by_label,
        "reviewed_by_role": reviewed_by_role,
        "reason": reason[:1000],
        "request_id": request_id,
        "record_name": record_name,
        "tenant_id": tenant_id,
    }
    item = {"pk": {"S": audit.REVIEWS_KEY}, "sk": {"S": audit.attestation_sort_key(at, record_id)}}
    for name, value in fields.items():
        if value is not None and value != "":
            item[name] = {"S": str(value)}
    _append(client, table, item)


def claim_sweep(client: Any, table: str, runtime_arn: str, request_id: str, number: int) -> bool:
    """Claim one background sweep of one contain. True for the first to ask, false for everyone after.

    The claim is one item in the Runtime's own partition, written with the
    same condition as every event: the item must not exist yet. Two
    deliveries of one message, a replay, or two direct invocations at the
    same moment therefore cannot both get it, so a sweep is run once and
    leaves one event. The item is never updated or deleted, like every other
    item of the table, and no read of a history returns it
    (``audit.sweep_claim_sort_key``).

    A write can go through while its answer is lost; the SDK then sends it
    again, and that second try is refused by the condition. So each attempt
    writes an id of its own into the claim, and a refusal is this attempt's
    claim after all when the item that is there carries that id.

    Any other failure of the write, or of that look, is raised: whether the
    sweep may run is then not known.
    """
    claim_id = str(uuid.uuid4())
    item = {
        "pk": {"S": audit.containment_key(runtime_arn)},
        "sk": {"S": audit.sweep_claim_sort_key(request_id, number)},
        "kind": {"S": "sweep_claim"},
        audit.CLAIM_ID_ATTRIBUTE: {"S": claim_id},
        "at": {"S": now_stamp()},
        "request_id": {"S": request_id},
        "sweep": {"S": str(number)},
        "runtime_arn": {"S": runtime_arn},
    }
    try:
        _append(client, table, item)
    except ClientError as exc:
        if (exc.response.get("Error") or {}).get("Code") != "ConditionalCheckFailedException":
            raise
        return audit.sweep_claim_id(client, table, runtime_arn, request_id, number) == claim_id
    return True


def _append(client: Any, table: str, item: dict[str, Any]) -> None:
    """The one write this module makes. The condition refuses to replace an existing item."""
    client.put_item(TableName=table, Item=item, ConditionExpression="attribute_not_exists(pk)")
