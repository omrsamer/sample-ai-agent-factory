# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""In-memory stand-ins for the registry and the audit table.

The registry fake follows the status transitions observed against a live
AWS Agent Registry: a new or updated record passes through CREATING or
UPDATING and settles in DRAFT, only a pending record can be approved from
DRAFT's side, DEPRECATED is terminal, and names are not unique.
"""

from __future__ import annotations

import datetime as dt
import itertools
from typing import Any

from botocore.exceptions import ClientError


def client_error(code: str, operation: str = "Operation") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "simulated"}}, operation)


class FakePages:
    def __init__(self, pages: list[dict[str, Any]], seen: list[str] | None = None) -> None:
        self.pages = pages
        self.seen = seen

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        if self.seen is not None and "registryId" in kwargs:
            self.seen.append(kwargs["registryId"])
        return self.pages


class FakeRegistry:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.calls: list[str] = []
        self.registry_ids: list[str] = []  # registryId of every read
        self.fail: dict[str, str] = {}  # operation -> error code to raise once
        self._ids = itertools.count(1)
        self.clock = dt.datetime(2026, 1, 15, 12, 0, tzinfo=dt.UTC)

    def _enter(self, operation: str) -> None:
        self.calls.append(operation)
        if operation in self.fail:
            raise client_error(self.fail.pop(operation), operation)

    def _record(self, record_id: str, operation: str) -> dict[str, Any]:
        if record_id not in self.records:
            raise client_error("ResourceNotFoundException", operation)
        return self.records[record_id]

    def _touch(self, record: dict[str, Any]) -> None:
        self.clock += dt.timedelta(seconds=1)
        record["updatedAt"] = self.clock

    def seed(self, name: str, data: str, status: str = "DRAFT", version: str = "1.0.0") -> str:
        record_id = f"rec{next(self._ids):09d}"
        self.records[record_id] = {
            "recordId": record_id,
            "name": name,
            "recordType": "CUSTOM",
            "descriptors": {"custom": {"data": data}},
            "recordVersion": version,
            "status": status,
            "createdAt": self.clock,
            "updatedAt": self.clock,
        }
        return record_id

    # --- reads ---------------------------------------------------------------

    def get_registry_record(self, registryId: str, recordId: str) -> dict[str, Any]:  # noqa: N803
        self._enter("get_registry_record")
        self.registry_ids.append(registryId)
        record = self._record(recordId, "GetRegistryRecord")
        snapshot = {**record, "ResponseMetadata": {}}
        if record["status"] in ("CREATING", "UPDATING"):
            record["status"] = "DRAFT"  # settles by the next read
        return snapshot

    def get_paginator(self, operation: str) -> FakePages:
        self._enter(operation)
        summaries = [{k: v for k, v in r.items() if k != "descriptors"} for r in self.records.values()]
        return FakePages([{"registryRecords": summaries}], self.registry_ids)

    # --- registrar writes ------------------------------------------------------

    def create_registry_record(self, **kwargs: Any) -> dict[str, Any]:
        self._enter("create_registry_record")
        record_id = self.seed(
            kwargs["name"], kwargs["descriptors"]["custom"]["data"], "CREATING", kwargs["recordVersion"]
        )
        self.records[record_id]["createArgs"] = kwargs
        return {
            "recordArn": f"arn:aws:agent-registry:eu-west-1:111111111111:registry/REG/record/{record_id}",
            "status": "CREATING",
        }

    def update_registry_record(self, registryId: str, recordId: str, descriptors: dict, recordVersion: str) -> dict:  # noqa: N803
        self._enter("update_registry_record")
        record = self._record(recordId, "UpdateRegistryRecord")
        if record["status"] == "DEPRECATED":
            raise client_error("ValidationException", "UpdateRegistryRecord")
        record["descriptors"] = {
            "custom": {"data": descriptors["optionalValue"]["custom"]["optionalValue"]["data"]["optionalValue"]}
        }
        record["recordVersion"] = recordVersion
        record["status"] = "UPDATING"
        record.pop("statusReason", None)
        self._touch(record)
        return {"status": "UPDATING"}

    def submit_registry_record_for_approval(self, registryId: str, recordId: str) -> dict[str, Any]:  # noqa: N803
        self._enter("submit_registry_record_for_approval")
        record = self._record(recordId, "SubmitRegistryRecordForApproval")
        if record["status"] in ("CREATING", "UPDATING"):
            raise client_error("ConflictException", "SubmitRegistryRecordForApproval")
        if record["status"] not in ("DRAFT", "PENDING_APPROVAL"):
            raise client_error("ValidationException", "SubmitRegistryRecordForApproval")
        record["status"] = "PENDING_APPROVAL"
        self._touch(record)
        return {"status": "PENDING_APPROVAL"}

    def delete_registry_record(self, registryId: str, recordId: str) -> dict[str, Any]:  # noqa: N803
        self._enter("delete_registry_record")
        self._record(recordId, "DeleteRegistryRecord")
        del self.records[recordId]
        return {}

    # --- approver write -----------------------------------------------------------

    def update_registry_record_status(self, registryId: str, recordId: str, status: str, statusReason: str) -> dict:  # noqa: N803
        self._enter("update_registry_record_status")
        record = self._record(recordId, "UpdateRegistryRecordStatus")
        allowed = {
            "APPROVED": ("PENDING_APPROVAL", "REJECTED", "APPROVED"),
            "REJECTED": ("PENDING_APPROVAL", "APPROVED", "REJECTED"),
            "DEPRECATED": ("DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED"),
        }
        if len(statusReason) > 255 or record["status"] not in allowed.get(status, ()):
            raise client_error("ValidationException", "UpdateRegistryRecordStatus")
        record["status"] = status
        record["statusReason"] = statusReason
        self._touch(record)
        return {"status": status}


class FakeDynamo:
    """An append-only table: put with a condition, query by partition. Nothing else exists."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[str] = []
        self.fail_put_numbers: set[int] = set()  # 1-based indices of put_item calls that fail
        self.fail_query = False
        self._puts = 0

    def put_item(self, TableName: str, Item: dict, ConditionExpression: str) -> dict[str, Any]:  # noqa: N803
        self.calls.append("put_item")
        self._puts += 1
        if self._puts in self.fail_put_numbers:
            raise client_error("ProvisionedThroughputExceededException", "PutItem")
        assert ConditionExpression == "attribute_not_exists(pk)"  # noqa: S101
        key = (Item["pk"]["S"], Item["sk"]["S"])
        if key in self.items:
            raise client_error("ConditionalCheckFailedException", "PutItem")
        self.items[key] = Item
        return {}

    def get_paginator(self, operation: str) -> Any:
        assert operation == "query"  # noqa: S101
        table = self

        class Pages:
            def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
                table.calls.append("query")
                if table.fail_query:
                    raise client_error("InternalServerError", "Query")
                assert kwargs["ConsistentRead"] is True  # noqa: S101
                pk = kwargs["ExpressionAttributeValues"][":pk"]["S"]
                rows = [item for (p, _), item in table.items.items() if p == pk]
                rows.sort(key=lambda item: item["sk"]["S"], reverse=not kwargs.get("ScanIndexForward", True))
                return [{"Items": rows}]

        return Pages()

    def events(self) -> list[dict[str, str]]:
        """Every stored event as plain strings, oldest first."""
        rows = sorted(self.items.values(), key=lambda item: item["sk"]["S"])
        return [{k: v["S"] for k, v in row.items()} for row in rows]
