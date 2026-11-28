# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The one queue call of the containment function: leave a sweep message for the sweeper."""

from __future__ import annotations

import re
from typing import Any

_REGION_IN_URL = re.compile(r"^https://sqs\.([a-z0-9-]{1,30})\.amazonaws\.com")


def region_of(queue_url: str) -> str | None:
    """The Region a queue URL names, so the client is made for the queue's Region."""
    match = _REGION_IN_URL.match(queue_url)
    return match.group(1) if match else None


def send(client: Any, queue_url: str, body: str, delay_seconds: int) -> None:
    """Send one message that becomes visible to the sweeper after ``delay_seconds`` (0 to 900)."""
    client.send_message(QueueUrl=queue_url, MessageBody=body, DelaySeconds=delay_seconds)
