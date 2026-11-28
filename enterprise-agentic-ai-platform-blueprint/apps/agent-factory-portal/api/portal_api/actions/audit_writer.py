# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Writing the audit trail. One item per event; an event is never updated, replaced or deleted.

Every write here is a ``PutItem`` with a condition. For an event, a mark and
a claim the condition is that no item with that key exists, which makes the
write append-only (``_append``). One item is not an event and is the only
one that a later write may replace: the latest review attestation of a
record, which a newer attestation of the same record replaces
(``_keep_latest``). The attestations themselves are events of the record's
own history and stay.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from botocore.exceptions import ClientError

from portal_api.aws import audit
from portal_api.models.portal import AuditEvent
from portal_api.reviews import KIND_REVIEW, REASON_MAX

# What a flow logs when ``put_attestation`` answers that the stored attestation is not older.
LATER_ATTESTATION_STORED = "The attestation stored for this record is not older than this one, so it stays the latest"


def new_request_id() -> str:
    return str(uuid.uuid4())


def now_stamp() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def put_event(
    client: Any,
    table: str,
    partition_key: str,
    event: AuditEvent,
    attributes: dict[str, str] | None = None,
    *,
    prefix: str = audit.EVENT_PREFIX,
) -> None:
    """Write one event, once. The condition makes the write append-only: an existing item is never replaced.

    ``attributes`` are extra string attributes stored with the event (the approved document on an approval).
    ``prefix`` is the range of the history the event belongs to. Only a Runtime's containment
    history has a second one, for the events that cannot change who holds the containment
    (``audit.OTHER_PREFIX``); an event is written into one range and never into both.
    """
    item = {"pk": {"S": partition_key}, "sk": {"S": audit.event_sort_key(event, prefix)}}
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
) -> bool:
    """Keep this attestation as the latest of its record. False when the one that is stored is not older.

    The partition the inventory reads holds one item for a record: the
    latest attestation. This write replaces it, on the condition that no
    attestation is stored for the record yet or that the one that is stored
    was attested before ``at``. So the partition grows with the number of
    records and not with the number of approvals and reviews, and an
    attestation that arrives late never replaces a newer one.

    False means that the stored attestation is as new as this one or newer:
    a newer one was recorded in the meantime, or this very write went
    through before and was sent again. Either way the stored one is the
    latest and nothing is lost: this attestation is in the record's own
    history, as the result event that names it. Any other failure of the
    write is raised.

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
        "reason": reason[:REASON_MAX],
        "request_id": request_id,
        "record_name": record_name,
        "tenant_id": tenant_id,
    }
    item = {"pk": {"S": audit.REVIEWS_KEY}, "sk": {"S": audit.latest_attestation_sort_key(record_id)}}
    for name, value in fields.items():
        if value is not None and value != "":
            item[name] = {"S": str(value)}
    try:
        _keep_latest(client, table, item)
    except ClientError as exc:
        if (exc.response.get("Error") or {}).get("Code") != "ConditionalCheckFailedException":
            raise
        return False
    return True


def mark_once(
    client: Any, table: str, partition_key: str, state: str, subject: str, action: str, rule: str, request_id: str
) -> bool:
    """Mark that something is on record for this person and this state of the record. False when it already is.

    One conditional write and no read, so it works for a function that may
    only write (the registrar), and two requests at the same moment cannot
    both get it. ``request_id`` names the request whose event follows the
    mark. Any other failure of the write is raised.
    """
    item = {
        "pk": {"S": partition_key},
        "sk": {"S": audit.once_sort_key(state, subject, action, rule)},
        "kind": {"S": "once"},
        "at": {"S": now_stamp()},
        "state": {"S": state},
        "actor_subject": {"S": subject},
        "action": {"S": action},
        "rule": {"S": rule},
        "request_id": {"S": request_id},
    }
    try:
        _append(client, table, item)
    except ClientError as exc:
        if (exc.response.get("Error") or {}).get("Code") != "ConditionalCheckFailedException":
            raise
        return False
    return True


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
    """The write of every event, mark and claim. The condition refuses to replace an existing item."""
    client.put_item(TableName=table, Item=item, ConditionExpression="attribute_not_exists(pk)")


def _keep_latest(client: Any, table: str, item: dict[str, Any]) -> None:
    """The one write that may replace an item: a record's latest attestation, by one attested later.

    The condition compares the time the stored item was attested with this
    item's own. Both are the function's own clock in one fixed form
    (``now_stamp``), never a value from the request, so they compare as text.
    An item that carries no such time is not an attestation, no read takes
    it for one, and it does not stand in the way: the condition holds for it
    as it does when nothing is stored. ``at`` is a reserved word of the
    service, hence the name.
    """
    client.put_item(
        TableName=table,
        Item=item,
        ConditionExpression="attribute_not_exists(#at) OR #at < :at",
        ExpressionAttributeNames={"#at": "at"},
        ExpressionAttributeValues={":at": item["at"]},
    )
