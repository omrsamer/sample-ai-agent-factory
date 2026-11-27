# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared helpers for mappers."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

_ARN = re.compile(
    r"^arn:(?P<partition>aws[a-z-]*):(?P<service>[a-z0-9-]+):(?P<region>[a-z0-9-]*):(?P<account>\d{12})?:(?P<resource>.+)$"
)

EPOCH_ISO = "1970-01-01T00:00:00Z"


def iso(value: Any) -> str | None:
    """ISO-8601 UTC string for a datetime (or pass a string through)."""
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        return value.astimezone(dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    return None


def now_iso() -> str:
    return iso(dt.datetime.now(dt.UTC)) or EPOCH_ISO


def arn_parts(arn: Any) -> dict[str, str] | None:
    if not isinstance(arn, str):
        return None
    match = _ARN.match(arn)
    if not match:
        return None
    parts = {k: v or "" for k, v in match.groupdict().items()}
    parts["resource_id"] = parts["resource"].split("/", 1)[-1]
    return parts


def arn_resource_id(arn: Any) -> str | None:
    parts = arn_parts(arn)
    return parts["resource_id"] if parts else None


def text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def to_int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None
