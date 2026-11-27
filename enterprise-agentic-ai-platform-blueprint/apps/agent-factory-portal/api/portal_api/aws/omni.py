# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon CloudWatch Omni Context Graph reads (the portal's own account, the function's own role).

A SigV4 call from a principal of the same account needs only the IAM action
``cloudwatch:GetContextGraph``; no Omni access grant is involved. An Omni
domain sees the Region it lives in, so the nodes are those of that Region.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

MAX_NODES = 500
PAGE_SIZE = 100
# The Context Graph holds every service and resource of the account (functions, compute, networks).
# The portal is an agent console, so it asks for agents only.
AGENT_CATEGORY = "GEN_AI_AGENT"


def agent_nodes(
    client: Any, account_id: str, start: dt.datetime, end: dt.datetime, max_nodes: int = MAX_NODES
) -> tuple[list[dict[str, Any]], bool]:
    """Agent nodes the Context Graph reports for one account in the window, and whether the list was cut short."""
    paginator = client.get_paginator("get_context_graph")
    pages = paginator.paginate(
        startTime=start,
        endTime=end,
        nodeFilters={"sourceAccountId": [account_id], "category": [AGENT_CATEGORY]},
        PaginationConfig={"MaxItems": max_nodes + 1, "PageSize": PAGE_SIZE},
    )
    nodes: list[dict[str, Any]] = []
    for page in pages:
        nodes.extend(page.get("nodes") or [])
    return nodes[:max_nodes], len(nodes) > max_nodes
