# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Agent Registry calls of the approver function: read one record, set its status."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

# The registry limits statusReason to 255 characters. The full reason is kept in the audit trail.
STATUS_REASON_MAX = 255
TRANSITIONAL = frozenset({"CREATING", "UPDATING"})


def get_record(client: Any, registry_id: str, record_id: str) -> dict[str, Any]:
    record = client.get_registry_record(registryId=registry_id, recordId=record_id)
    record.pop("ResponseMetadata", None)
    return record


def wait_until_settled(
    client: Any,
    registry_id: str,
    record_id: str,
    *,
    timeout: float = 12.0,
    interval: float = 0.5,
    sleep: Callable[[float], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Wait (bounded) for the record to leave CREATING or UPDATING and return it as last read."""
    sleep = sleep or time.sleep
    deadline = clock() + timeout
    while True:
        record = get_record(client, registry_id, record_id)
        if record.get("status") not in TRANSITIONAL or clock() >= deadline:
            return record
        sleep(interval)


def set_status(client: Any, registry_id: str, record_id: str, status: str, reason: str) -> None:
    client.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status=status, statusReason=reason[:STATUS_REASON_MAX]
    )
