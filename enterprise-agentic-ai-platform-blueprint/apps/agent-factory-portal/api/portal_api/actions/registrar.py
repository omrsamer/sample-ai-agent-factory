# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Agent Registry calls of the registrar function.

Same record shape and calls as ``pipelines/publish_agent_record.py``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from portal_api import registrations

TRANSITIONAL = frozenset({"CREATING", "UPDATING"})


def get_record(client: Any, registry_id: str, record_id: str) -> dict[str, Any]:
    record = client.get_registry_record(registryId=registry_id, recordId=record_id)
    record.pop("ResponseMetadata", None)
    return record


def find_by_name(client: Any, registry_id: str, name: str) -> list[dict[str, Any]]:
    """Records named ``name``. The registry does not enforce unique names, so the portal does."""
    matches: list[dict[str, Any]] = []
    paginator = client.get_paginator("list_registry_records")
    for page in paginator.paginate(registryId=registry_id):
        matches.extend(r for r in page.get("registryRecords") or [] if r.get("name") == name)
    return matches


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


def create_record(client: Any, registry_id: str, document: dict[str, Any], request_id: str) -> str:
    """Create the record as a draft and return its id."""
    data = registrations.canonical(document)
    name = registrations.record_name(document["tenantId"], document["agentId"], document["environment"])
    created = client.create_registry_record(
        registryId=registry_id,
        name=name,
        displayName=name,
        description=registrations.record_description(document),
        recordType="CUSTOM",
        descriptors={"custom": {"data": data}},
        recordVersion=document["recordVersion"],
        clientToken=registrations.sha256(f"{registry_id}:{data}:{request_id}"),
    )
    return created.get("recordId") or str(created["recordArn"]).rsplit("/", 1)[-1]


def update_record(client: Any, registry_id: str, record_id: str, document: dict[str, Any]) -> None:
    # UpdateRegistryRecord wraps every updatable field in `optionalValue` (absent means "leave unchanged").
    client.update_registry_record(
        registryId=registry_id,
        recordId=record_id,
        descriptors={
            "optionalValue": {
                "custom": {"optionalValue": {"data": {"optionalValue": registrations.canonical(document)}}}
            }
        },
        recordVersion=document["recordVersion"],
    )


def submit_record(client: Any, registry_id: str, record_id: str) -> None:
    client.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)


def delete_record(client: Any, registry_id: str, record_id: str) -> None:
    client.delete_registry_record(registryId=registry_id, recordId=record_id)
