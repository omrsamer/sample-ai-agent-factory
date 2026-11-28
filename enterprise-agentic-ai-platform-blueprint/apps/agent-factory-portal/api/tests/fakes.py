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

_SERVER_ERRORS = ("InternalServerException", "InternalServerError", "InternalFailure", "ServiceUnavailableException")


def client_error(code: str, operation: str = "Operation", status: int | None = None) -> ClientError:
    """An error as the service answers one: with the HTTP status that goes with the code."""
    if status is None:
        status = 500 if code in _SERVER_ERRORS else 429 if "Throttl" in code else 400
    response = {"Error": {"Code": code, "Message": "simulated"}, "ResponseMetadata": {"HTTPStatusCode": status}}
    return ClientError(response, operation)


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


# The sort-key prefixes of events: a record's history has the first, a Runtime's containment both.
EVENT_RANGES = ("EVENT#", "OTHER#")

# The only two conditions a write of the portal carries.
APPEND_ONLY = "attribute_not_exists(pk)"
KEEP_LATEST = "attribute_not_exists(#at) OR #at < :at"


class FakeDynamo:
    """A table that is written with a condition and queried by partition. Nothing else exists.

    Every write is append-only, with one exception: the item that holds a
    record's latest review attestation (``REVIEWS`` / ``RECORD#<record id>``)
    may be replaced by one that was attested later. ``replaced`` lists the
    keys of the items that were, so a test can show that nothing else is.

    A query is served the way the service serves one: only the items whose
    sort key begins with the prefix the caller named, a page at a time, each
    of at most the page size the caller asked for, and only when the caller
    asks for the next page. ``pages_read`` and ``items_read`` count what was
    actually handed out, so a test can show that a read stopped early.
    """

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[str] = []
        self.fail_put_numbers: set[int] = set()  # 1-based indices of put_item calls that fail
        self.fail_query = False
        self.pages_read = 0
        self.items_read = 0
        self.queried: list[str] = []  # the partition key of every query, in order
        self.prefixes: list[tuple[str, str]] = []  # the partition key and sort-key prefix of every query
        self.replaced: list[tuple[str, str]] = []  # the key of every item a later write replaced
        self._puts = 0

    def put_item(self, TableName: str, Item: dict, ConditionExpression: str, **expression: Any) -> dict[str, Any]:  # noqa: N803
        self.calls.append("put_item")
        self._puts += 1
        if self._puts in self.fail_put_numbers:
            raise client_error("ProvisionedThroughputExceededException", "PutItem")
        key = (Item["pk"]["S"], Item["sk"]["S"])
        stored = self.items.get(key)
        if ConditionExpression == APPEND_ONLY:
            assert not expression  # noqa: S101
            allowed = stored is None
        else:
            # As the service evaluates it: a comparison with an attribute the item lacks is false.
            assert ConditionExpression == KEEP_LATEST  # noqa: S101
            assert set(expression) == {"ExpressionAttributeNames", "ExpressionAttributeValues"}  # noqa: S101
            assert expression["ExpressionAttributeNames"] == {"#at": "at"}  # noqa: S101
            (name,) = expression["ExpressionAttributeValues"]
            assert name == ":at"  # noqa: S101
            newer = expression["ExpressionAttributeValues"][":at"]["S"]
            allowed = stored is None or "at" not in stored or stored["at"]["S"] < newer
        if not allowed:
            raise client_error("ConditionalCheckFailedException", "PutItem")
        if stored is not None:
            self.replaced.append(key)
        self.items[key] = Item
        return {}

    def get_paginator(self, operation: str) -> Any:
        assert operation == "query"  # noqa: S101
        table = self

        class Pages:
            def paginate(self, **kwargs: Any) -> Any:
                table.calls.append("query")
                if table.fail_query:
                    raise client_error("InternalServerError", "Query")
                assert kwargs["ConsistentRead"] is True  # noqa: S101
                assert kwargs["KeyConditionExpression"] == "pk = :pk AND begins_with(sk, :prefix)"  # noqa: S101
                pk = kwargs["ExpressionAttributeValues"][":pk"]["S"]
                prefix = kwargs["ExpressionAttributeValues"][":prefix"]["S"]
                table.queried.append(pk)
                table.prefixes.append((pk, prefix))
                rows = [item for (p, sk), item in table.items.items() if p == pk and sk.startswith(prefix)]
                rows.sort(key=lambda item: item["sk"]["S"], reverse=not kwargs.get("ScanIndexForward", True))
                return table._serve(rows, (kwargs.get("PaginationConfig") or {}).get("PageSize"))

        return Pages()

    def _serve(self, rows: list[dict[str, Any]], page_size: int | None) -> Any:
        """The pages of one query, handed out one at a time as the caller iterates."""
        size = page_size or max(len(rows), 1)
        offset = 0
        while True:
            page = rows[offset : offset + size]
            offset += len(page)
            self.pages_read += 1
            self.items_read += len(page)
            # As the service does: a page that was cut at the page size says that there may be more,
            # even when the next page then turns out to be empty.
            if len(page) == size and page_size is not None:
                yield {"Items": page, "LastEvaluatedKey": {"pk": page[-1]["pk"], "sk": page[-1]["sk"]}}
            else:
                yield {"Items": page}
                return

    def events(self) -> list[dict[str, str]]:
        """Every stored audit event as plain strings, oldest first: what the histories hold.

        Both ranges of a Runtime's containment history: the events that can
        change who holds a containment (``EVENT#``) and every other
        (``OTHER#``), in the order they were written.
        """
        rows = self._rows(lambda pk, sk: pk != "REVIEWS" and sk.startswith(EVENT_RANGES))
        return sorted(rows, key=lambda row: row["sk"].split("#", 1)[1])

    def settling(self) -> list[dict[str, str]]:
        """Of those, the events a release reads to find who holds a containment: the ``EVENT#`` range."""
        return [row for row in self.events() if row["sk"].startswith("EVENT#")]

    def others(self) -> list[dict[str, str]]:
        """Of those, the events that cannot change who holds a containment: the ``OTHER#`` range."""
        return [row for row in self.events() if row["sk"].startswith("OTHER#")]

    def attestations(self) -> list[dict[str, str]]:
        """What the ``REVIEWS`` partition holds as plain strings, oldest first: one attestation for a record."""
        return sorted(self._rows(lambda pk, sk: pk == "REVIEWS"), key=lambda item: item["at"])

    def claims(self) -> list[dict[str, str]]:
        """Every stored item that is neither: the sweeps the sweeper has claimed, and the marks."""
        return self._rows(lambda pk, sk: pk != "REVIEWS" and not sk.startswith(EVENT_RANGES))

    def _rows(self, wanted: Any) -> list[dict[str, str]]:
        rows = sorted(self.items.values(), key=lambda item: item["sk"]["S"])
        return [{k: v["S"] for k, v in row.items()} for row in rows if wanted(row["pk"]["S"], row["sk"]["S"])]
