# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A Runtime's ARN, in the one spelling the portal uses. Pure functions, no AWS calls.

The service answers for more than one spelling of a Runtime's ARN: another
partition string reads the same resource policy. The history of a
containment is keyed by the ARN, and the two-person rule reads that history,
so a second spelling would be a second history, and the person who contained
a Runtime could release it under the other name.

So the portal never uses an ARN as a caller, a registration or a queue
message wrote it. It builds the ARN itself (``canonical_runtime_arn``): the
partition, the Region and the account from the cell the operator configured,
and the Runtime id exactly as given, which the service treats as case
sensitive. An ARN from outside is accepted only when it is equal to that one,
character for character.

Every pattern here uses ASCII classes and ``re.ASCII``, and is applied with
``fullmatch``: ``\\d`` would also match digits of other scripts, and ``$``
would also match before a final line feed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

_RUNTIME_ID = r"[A-Za-z][A-Za-z0-9_]{0,99}-[A-Za-z0-9]{1,20}"
RUNTIME_ID = re.compile(_RUNTIME_ID, re.ASCII)
RUNTIME_ARN = re.compile(
    r"arn:(?P<partition>aws[a-z-]{0,10}):bedrock-agentcore:(?P<region>[a-z0-9-]{1,30}):(?P<account>[0-9]{12})"
    rf":runtime/(?P<runtime_id>{_RUNTIME_ID})",
    re.ASCII,
)


class _Cell(Protocol):
    """What a configured cell says about where it is (``portal_api.config.Cell``)."""

    account_id: str
    region: str

    @property
    def partition(self) -> str: ...


@dataclass(frozen=True)
class RuntimeArn:
    partition: str
    region: str
    account: str
    runtime_id: str


def parse_runtime_arn(value: Any) -> RuntimeArn | None:
    """The parts of a Runtime ARN, or ``None`` when ``value`` is not exactly one."""
    match = RUNTIME_ARN.fullmatch(value) if isinstance(value, str) else None
    return RuntimeArn(**match.groupdict()) if match else None


def is_runtime_id(value: Any) -> bool:
    return isinstance(value, str) and RUNTIME_ID.fullmatch(value) is not None


def canonical_runtime_arn(cell: _Cell, runtime_id: str) -> str:
    """The ARN of a Runtime of this cell's account and Region, as the portal spells it."""
    return f"arn:{cell.partition}:bedrock-agentcore:{cell.region}:{cell.account_id}:runtime/{runtime_id}"


def canonical_in(cell: _Cell | None, value: Any) -> str | None:
    """``value`` when it is the canonical ARN of a Runtime of this cell, otherwise ``None``.

    ``None`` for no cell, for something that is not a Runtime ARN, for an ARN
    of another account or Region, and for another spelling of the partition.
    """
    parsed = parse_runtime_arn(value)
    if cell is None or parsed is None:
        return None
    return value if canonical_runtime_arn(cell, parsed.runtime_id) == value else None
