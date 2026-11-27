# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Agent Registry reads (platform account, the function's own role)."""

from __future__ import annotations

import logging
from typing import Any

from portal_api.aws.parallel import pmap
from portal_api.aws.session import error_code, paginate

logger = logging.getLogger(__name__)


def list_records(client: Any, registry_id: str) -> list[dict[str, Any]]:
    """Every record in the registry, each with its descriptors.

    The list operation returns summaries without descriptors, so each record is
    fetched once. A record that cannot be fetched is kept as its summary.
    """
    summaries = paginate(client, "list_registry_records", "registryRecords", registryId=registry_id)

    def fetch(summary: dict[str, Any]) -> dict[str, Any]:
        record = client.get_registry_record(registryId=registry_id, recordId=summary["recordId"])
        record.pop("ResponseMetadata", None)
        return record

    records: list[dict[str, Any]] = []
    for summary, result in zip(summaries, pmap(fetch, summaries), strict=True):
        if isinstance(result, BaseException):
            logger.warning("Registry record could not be read: %s", error_code(result))
            records.append(summary)
        else:
            records.append(result)
    return records
