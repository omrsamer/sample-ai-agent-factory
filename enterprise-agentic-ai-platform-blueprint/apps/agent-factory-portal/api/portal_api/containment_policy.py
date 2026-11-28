# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The containment statement in a Runtime's resource policy. Pure functions, no AWS calls.

Containment adds exactly one statement that denies every invoke action on the
Runtime (and so on all of its endpoints) to every principal. Release removes
it. Every statement that does not carry the portal's Sid is kept as it was:
the functions here never edit, reorder or drop one.

A Runtime is contained when its policy holds that statement, and the
statement is recognised by its whole shape, not by its Sid (``is_containment``).
Whoever can write the Runtime's policy can write a statement with the
portal's Sid that denies nothing: an ``Allow``, a condition that never holds,
one harmless action. Such a statement is not containment. The policy is then
``FOREIGN``: the Runtime is not contained, the portal says so, and a contain
replaces the statement with its own.

``state`` is the one function that reads a policy this way. Contain, release,
the read API, the sweeper and the evidence document all go through it.
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


# What ``state`` returns.
CONTAINED = "contained"  # the policy holds the statement the portal writes for this Runtime
FOREIGN = "foreign"  # a statement carries the portal's Sid but is not that statement
ABSENT = "absent"  # no statement carries the portal's Sid

# Said wherever a state is shown and the policy is ``FOREIGN``. It does not say what that
# statement does: one in another shape can deny nothing (an Allow, a condition that never holds)
# or deny invocation to some callers or to all (another form of the principal, action names in
# another case). The portal does not try to tell which. It is not the statement the portal
# writes, so the Runtime is not contained by the portal, and a contain replaces it.
FOREIGN_STATEMENT = (
    "A statement with the portal's identifier is in the Runtime's resource policy, but it is not the "
    "statement the portal writes and may or may not deny invocation; contain the agent to replace it."
)

# The elements of the statement the portal writes. A statement with any other element (a
# Condition, NotAction, NotPrincipal, NotResource) is not that statement.
_ELEMENTS = frozenset({"Sid", "Effect", "Principal", "Action", "Resource"})


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


def _marked(statement: Any) -> bool:
    """Whether a statement carries the portal's Sid."""
    return isinstance(statement, dict) and statement.get("Sid") == CONTAINMENT_SID


def is_containment(statement: Any, runtime_arn: str) -> bool:
    """True for the statement the portal writes for this Runtime, and for nothing else.

    - It carries the portal's Sid and has exactly the five elements the
      portal writes: no ``Condition``, ``NotAction``, ``NotPrincipal`` or
      ``NotResource``, and nothing else either.
    - ``Effect`` is ``Deny``.
    - ``Principal`` is ``"*"``. That is the one form that covers every caller
      of a Runtime, whichever way its callers sign in: a Runtime that takes
      OAuth tokens is covered by no other principal.
    - ``Resource`` is this Runtime's ARN as the portal spells it
      (``portal_api/arns.py``), as a string or as a list of that one string.
    - ``Action`` is a list that holds the two core invoke actions and nothing
      but invoke actions. The portal writes either all six or those two.
    """
    if not _marked(statement) or set(statement) != _ELEMENTS:
        return False
    if statement["Effect"] != "Deny" or statement["Principal"] != "*":
        return False
    resource = statement["Resource"]
    if isinstance(resource, list) and len(resource) == 1:
        resource = resource[0]
    if not isinstance(resource, str) or resource != runtime_arn:
        return False
    actions = statement["Action"]
    if not isinstance(actions, list) or not all(isinstance(action, str) for action in actions):
        return False
    return set(CORE_INVOKE_ACTIONS) <= set(actions) <= set(ALL_INVOKE_ACTIONS)


def state(policy: str | None, runtime_arn: str) -> str:
    """``CONTAINED``, ``FOREIGN`` or ``ABSENT``: what the policy says about this Runtime's containment."""
    marked = [s for s in statements(parse(policy)) if _marked(s)]
    if any(is_containment(s, runtime_arn) for s in marked):
        return CONTAINED
    return FOREIGN if marked else ABSENT


def is_contained(policy: str | None, runtime_arn: str) -> bool:
    """True when the policy holds the statement the portal writes for this Runtime."""
    return state(policy, runtime_arn) == CONTAINED


def other_statements(policy: str | None) -> int:
    """How many statements of the policy do not carry the portal's Sid. Contain and release keep every one."""
    return sum(1 for s in statements(parse(policy)) if not _marked(s))


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


def denied_actions(policy: str | None, runtime_arn: str) -> list[str]:
    """The actions the containment statement in the policy denies (empty when it is not contained)."""
    for statement in statements(parse(policy)):
        if is_containment(statement, runtime_arn):
            return list(statement["Action"])
    return []


def with_containment(policy: str | None, runtime_arn: str, actions: tuple[str, ...] = ALL_INVOKE_ACTIONS) -> str:
    """The policy with the containment statement added. Other statements are kept unchanged and in order.

    Whatever carried the portal's Sid before is replaced: the Sid is the
    portal's, so a statement under it that the portal did not write does not
    stay beside the one it writes.
    """
    document = parse(policy)
    kept = [s for s in statements(document) if not _marked(s)]
    result = dict(document) if document else {"Version": POLICY_VERSION}
    result["Statement"] = [*kept, containment_statement(runtime_arn, actions)]
    return json.dumps(result, separators=(",", ":"))


def without_containment(policy: str | None) -> str | None:
    """The policy with the containment statement removed, or ``None`` when no statement remains."""
    document = parse(policy)
    kept = [s for s in statements(document) if not _marked(s)]
    if not kept or document is None:
        return None
    result = dict(document)
    result["Statement"] = kept
    return json.dumps(result, separators=(",", ":"))
