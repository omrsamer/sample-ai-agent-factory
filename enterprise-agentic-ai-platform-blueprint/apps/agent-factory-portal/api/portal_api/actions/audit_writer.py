# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Appending to the audit trail. One item per event; an item is never updated or deleted."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from portal_api.models.portal import AuditEvent


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
    client.put_item(TableName=table, Item=item, ConditionExpression="attribute_not_exists(pk)")
