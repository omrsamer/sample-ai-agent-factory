# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The containment statement in a Runtime's resource policy. Pure functions, no AWS calls.

Containment adds exactly one statement, identified by its Sid, that denies
every invoke action on the Runtime (and so on all of its endpoints) to every principal.
Release removes exactly that statement. Every other statement is kept as it
was: the functions here never edit, reorder or drop a statement they did not
write.
"""

from __future__ import annotations

import json
from typing import Any

CONTAINMENT_SID = "AgenticAIPortalContainment"
POLICY_VERSION = "2012-10-17"
# The two invoke operations of the data-plane API. A statement with exactly these is known to be
# accepted by PutResourcePolicy and to deny invocation (measured on a live Runtime).
CORE_INVOKE_ACTIONS: tuple[str, ...] = (
    "bedrock-agentcore:InvokeAgentRuntime",
    "bedrock-agentcore:InvokeAgentRuntimeCommand",
)
# Every invoke action the service documents for a Runtime's resource policy: the two above plus
# the per-user, shell and WebSocket variants, which are authorized as actions of their own.
# StopRuntimeSession and GetAgentCard are left alone on purpose: sessions must stay stoppable.
ALL_INVOKE_ACTIONS: tuple[str, ...] = (
    "bedrock-agentcore:InvokeAgentRuntime",
    "bedrock-agentcore:InvokeAgentRuntimeForUser",
    "bedrock-agentcore:InvokeAgentRuntimeCommand",
    "bedrock-agentcore:InvokeAgentRuntimeCommandShell",
    "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
    "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser",
)


class PolicyError(ValueError):
    """The existing resource policy cannot be parsed, so it is left untouched."""


def parse(policy: str | None) -> dict[str, Any] | None:
    """The policy document, or ``None`` when there is no policy."""
    if policy is None or not policy.strip():
        return None
    try:
        document = json.loads(policy)
    except ValueError as exc:
        raise PolicyError("the Runtime's resource policy is not valid JSON") from exc
    if not isinstance(document, dict):
        raise PolicyError("the Runtime's resource policy is not a JSON object")
    return document


def statements(document: dict[str, Any] | None) -> list[Any]:
    if not document:
        return []
    value = document.get("Statement")
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_contained(policy: str | None) -> bool:
    """True when the policy holds the containment statement."""
    return any(isinstance(s, dict) and s.get("Sid") == CONTAINMENT_SID for s in statements(parse(policy)))


def containment_statement(runtime_arn: str, actions: tuple[str, ...] = ALL_INVOKE_ACTIONS) -> dict[str, Any]:
    """The deny statement.

    ``Resource`` is exactly the Runtime's ARN: the service accepts a statement
    only when it names the single ARN the policy is attached to (no list, no
    wildcard). An invocation through any endpoint is authorized against both
    the endpoint and the Runtime, and an explicit deny on either wins, so this
    one statement blocks every endpoint.
    """
    return {
        "Sid": CONTAINMENT_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": list(actions),
        "Resource": runtime_arn,
    }


def denied_actions(policy: str | None) -> list[str]:
    """The actions the containment statement in the policy denies (empty when it is not contained)."""
    for statement in statements(parse(policy)):
        if isinstance(statement, dict) and statement.get("Sid") == CONTAINMENT_SID:
            actions = statement.get("Action") or []
            return [actions] if isinstance(actions, str) else [str(a) for a in actions]
    return []


def with_containment(policy: str | None, runtime_arn: str, actions: tuple[str, ...] = ALL_INVOKE_ACTIONS) -> str:
    """The policy with the containment statement added. Other statements are kept unchanged and in order."""
    document = parse(policy)
    kept = [s for s in statements(document) if not (isinstance(s, dict) and s.get("Sid") == CONTAINMENT_SID)]
    result = dict(document) if document else {"Version": POLICY_VERSION}
    result["Statement"] = [*kept, containment_statement(runtime_arn, actions)]
    return json.dumps(result, separators=(",", ":"))


def without_containment(policy: str | None) -> str | None:
    """The policy with the containment statement removed, or ``None`` when no statement remains."""
    document = parse(policy)
    kept = [s for s in statements(document) if not (isinstance(s, dict) and s.get("Sid") == CONTAINMENT_SID)]
    if not kept or document is None:
        return None
    result = dict(document)
    result["Statement"] = kept
    return json.dumps(result, separators=(",", ":"))
