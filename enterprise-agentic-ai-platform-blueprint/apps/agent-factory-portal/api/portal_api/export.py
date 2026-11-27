# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Inventory export as CSV or JSON."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

# A spreadsheet treats a cell that starts with one of these as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

COLUMNS: tuple[str, ...] = (
    "agent_id",
    "name",
    "record_name",
    "tenant_id",
    "environment",
    "owner_group",
    "sponsor",
    "contact",
    "risk_class",
    "data_classification",
    "inventory_state",
    "detection_sources",
    "lifecycle_state",
    "unmanaged",
    "ownerless",
    "review_overdue",
    "inactive",
    "contained",
    "risk_level",
    "risk_reasons",
    "runtime_arn",
    "account_alias",
    "region",
    "updated_at",
)


def neutralise(text: str) -> str:
    """Make a cell safe to open in a spreadsheet: a leading formula character is prefixed with a quote."""
    return f"'{text}" if text.startswith(_FORMULA_PREFIXES) else text


def cell(value: Any) -> str:
    """One CSV cell: empty for unknown, true/false for flags, a semicolon list for lists."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return neutralise(";".join(str(item) for item in value))
    return neutralise(str(value))


def to_csv(rows: list[dict[str, Any]]) -> str:
    """RFC 4180 CSV with a header row. Fields that need it are quoted, and quotes are doubled."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([cell(row.get(column)) for column in COLUMNS])
    return buffer.getvalue()


def to_json(rows: list[dict[str, Any]]) -> str:
    return json.dumps([{column: row.get(column) for column in COLUMNS} for row in rows], indent=2)
