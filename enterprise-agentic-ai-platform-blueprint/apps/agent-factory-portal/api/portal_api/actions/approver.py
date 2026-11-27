# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Agent Registry calls of the approver function: read one record, set its status."""

from __future__ import annotations

from typing import Any

# The registry limits statusReason to 255 characters. The full reason is kept in the audit trail.
STATUS_REASON_MAX = 255


def get_record(client: Any, registry_id: str, record_id: str) -> dict[str, Any]:
    record = client.get_registry_record(registryId=registry_id, recordId=record_id)
    record.pop("ResponseMetadata", None)
    return record


def set_status(client: Any, registry_id: str, record_id: str, status: str, reason: str) -> None:
    client.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status=status, statusReason=reason[:STATUS_REASON_MAX]
    )
