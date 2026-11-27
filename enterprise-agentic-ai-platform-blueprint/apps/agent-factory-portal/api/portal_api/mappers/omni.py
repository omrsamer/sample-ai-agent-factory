# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Context Graph agent nodes reduced to the agents CloudWatch Omni observes in telemetry."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any

from portal_api.aws.omni import AGENT_CATEGORY
from portal_api.mappers.common import iso, text
from portal_api.models.portal import ObservedService, OmniDomain

RESOURCE_ID_ATTRIBUTE = "cloud.resource_id"
OBSERVED_ONLY = "observed_only"
# An agent node's resource id is its Runtime ARN followed by the endpoint it was called through.
_RUNTIME = re.compile(r"^(arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:\d{12}:runtime/[A-Za-z0-9_-]+)(/.*)?$")


@dataclass(frozen=True)
class KnownAgent:
    """An agent of the inventory, as far as matching a node needs it."""

    agent_id: str
    registered: bool
    detected: bool
    inventory_state: str


def runtime_arn(resource_id: str | None) -> str | None:
    """The Runtime ARN inside a node's resource id (the id cut at the endpoint part), if it holds one."""
    match = _RUNTIME.match(resource_id or "")
    return match.group(1) if match else None


def observed_at(value: Any) -> str | None:
    """An observation time as ISO text. A node known from configuration only reports the epoch: that is no time."""
    if isinstance(value, dt.datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=dt.UTC)
        return None if aware.timestamp() <= 0 else iso(aware)
    if isinstance(value, str) and value.startswith("1970-01-01T00:00:00"):
        return None
    return iso(value)


def observed_services(
    nodes: list[dict[str, Any]], agents: dict[str, KnownAgent], source: OmniDomain | None = None
) -> list[ObservedService]:
    """One row per agent node, most recently observed first.

    ``agents`` maps a Runtime ARN to the inventory's agent with that Runtime.
    A node that matches none is an agent that emits telemetry but that nobody
    registered and no source detected: its ``inventory_state`` is ``observed_only``.
    """
    services = []
    for node in nodes:
        properties = node.get("nodeProperties") or {}
        if properties.get("category") != AGENT_CATEGORY:
            continue  # the request already filters; never list functions or networks as agents
        attributes = node.get("telemetryAttributes") or {}
        resource_id = text(attributes.get(RESOURCE_ID_ATTRIBUTE))
        arn = runtime_arn(resource_id)
        known = agents.get(arn or "")
        services.append(
            ObservedService(
                name=text(node.get("name")) or text(node.get("nodeId")) or "unknown",
                node_type=text(node.get("nodeType")) or "UNKNOWN",
                category=AGENT_CATEGORY,
                resource_id=resource_id,
                runtime_arn=arn,
                region=text(properties.get("region")),
                last_observed_at=observed_at(node.get("lastObservedAt")),
                signals=[str(signal) for signal in node.get("signalTypes") or []],
                registered=bool(known and known.registered),
                detected=bool(known and known.detected),
                matched_agent_id=known.agent_id if known else None,
                inventory_state=known.inventory_state if known else OBSERVED_ONLY,
                omni_region=source.region if source else None,
                account_alias=source.account_alias if source else None,
            )
        )
    services.sort(key=lambda s: (s.last_observed_at or "", s.name), reverse=True)
    return services
