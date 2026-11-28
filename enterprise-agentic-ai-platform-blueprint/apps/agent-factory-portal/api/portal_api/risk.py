# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Risk level of an agent: one pure, deterministic function over facts the API already has.

There are no weights and no scores. Each rule in ``RULES`` looks at one fact
(two for the rules that also need a Runtime to be known) and, when it applies,
contributes one reason with a fixed severity. The risk level is the highest
severity among the reasons, and ``low`` when no rule applies.

Two principles hold for every rule:

- Every reason shown is true of that agent. A rule names the cause it found,
  not a summary: an agent nobody registered and a registration that waits for
  an approver are different findings with different severities.
- A fact that is not known (``None``) never triggers a rule, so an unknown
  never raises or lowers the level.

One guard stands before the table (``closed``): a retired registration with no
Runtime known has nothing left that anyone could act on, so no rule applies
to it. The guard is not granted while the portal is blind for a passing
reason: when the reader of the Runtime's account failed for this inventory,
the rules apply as for any other agent.

The same table is in README.md.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

# Registry statuses of a registration that exists but has not been approved (yet).
NOT_APPROVED_YET = frozenset({"DRAFT", "PENDING_APPROVAL", "CREATING", "UPDATING", "CREATE_FAILED", "UPDATE_FAILED"})


@dataclass(frozen=True)
class RiskFacts:
    """What is known about one agent. ``None`` means not known."""

    risk_class: str | None = None  # minimal | limited | high | unacceptable
    data_classification: str | None = None  # public | internal | confidential | restricted
    registered: bool | None = None  # the agent has a registration, in any status
    registry_status: str | None = None  # the registration's status in the registry
    runtime_known: bool | None = None  # a detection source sees a Runtime for the agent
    # The reader of the account the registration's Runtime is in exists and could not be used for
    # this inventory. False when it answered, when that account has no reader at all, and when
    # the registration names no Runtime.
    runtime_reader_unreachable: bool | None = None
    owner_group_missing: bool | None = None  # the registration names no owner group
    owner_group_in_roster: bool | None = None  # None when no roster is configured
    sponsor_missing: bool | None = None  # the registration names neither a sponsor nor a contact
    review_overdue: bool | None = None  # the effective review date (attestation, else registration) has passed
    inactive: bool | None = None
    gateway_policy_mode: str | None = None  # enforce | log_only | none; None when no Tool Gateway is known
    guardrail_configured: bool | None = None  # the Runtime names a guardrail or the inference gateway
    authorizer_type: str | None = None  # AWS_IAM | CUSTOM_JWT | NONE
    evaluation_verdict: str | None = None  # passed | failed | not_run
    cell_health_state: str | None = None  # healthy | needs_attention | critical | no_data


@dataclass(frozen=True)
class Rule:
    code: str
    severity: str
    applies: Callable[[RiskFacts], bool]
    detail: str


@dataclass(frozen=True)
class Reason:
    code: str
    severity: str
    detail: str


@dataclass(frozen=True)
class Risk:
    level: str
    reasons: tuple[Reason, ...]


# The rule table. Order within a severity is the order reasons are reported in.
RULES: tuple[Rule, ...] = (
    Rule(
        "RISK_CLASS_UNACCEPTABLE",
        "critical",
        lambda f: f.risk_class == "unacceptable",
        "The registration declares risk class unacceptable.",
    ),
    Rule(
        "INBOUND_AUTH_NONE",
        "critical",
        lambda f: f.authorizer_type == "NONE",
        "The Runtime accepts calls without authentication.",
    ),
    Rule("UNREGISTERED", "high", lambda f: f.registered is False, "The agent has no registration."),
    Rule(
        "REGISTRATION_REJECTED",
        "high",
        lambda f: f.registry_status == "REJECTED" and f.runtime_known is True,
        "The agent's registration was rejected and its Runtime is still deployed.",
    ),
    Rule(
        "REGISTRATION_DEPRECATED",
        "high",
        lambda f: f.registry_status == "DEPRECATED" and f.runtime_known is True,
        "The agent's registration is retired (DEPRECATED) and its Runtime is still deployed.",
    ),
    Rule("RISK_CLASS_HIGH", "high", lambda f: f.risk_class == "high", "The registration declares risk class high."),
    Rule(
        "DATA_RESTRICTED",
        "high",
        lambda f: f.data_classification == "restricted",
        "The agent handles data classified restricted.",
    ),
    Rule("OWNERLESS", "high", lambda f: f.owner_group_missing is True, "The registration names no owner group."),
    Rule(
        "OWNER_GROUP_NOT_IN_ROSTER",
        "high",
        lambda f: f.owner_group_in_roster is False,
        "The registration's owner group is not in the owner roster.",
    ),
    Rule(
        "EVALUATION_FAILED",
        "high",
        lambda f: f.evaluation_verdict == "failed",
        "The latest recorded evaluation failed.",
    ),
    Rule(
        "CELL_HEALTH_CRITICAL",
        "high",
        lambda f: f.cell_health_state == "critical",
        "An alarm of the agent's cell is in ALARM.",
    ),
    Rule(
        "REGISTRATION_NOT_APPROVED",
        "medium",
        lambda f: f.registry_status in NOT_APPROVED_YET,
        "The agent's registration is not approved yet.",
    ),
    Rule(
        "GATEWAY_POLICY_NONE",
        "medium",
        lambda f: f.gateway_policy_mode == "none",
        "The agent's Tool Gateway has no policy engine.",
    ),
    Rule(
        "GUARDRAIL_NOT_CONFIGURED",
        "medium",
        lambda f: f.guardrail_configured is False,
        "The Runtime's configuration names neither a guardrail nor the inference gateway.",
    ),
    Rule(
        "DATA_CONFIDENTIAL",
        "medium",
        lambda f: f.data_classification == "confidential",
        "The agent handles data classified confidential.",
    ),
    Rule("REVIEW_OVERDUE", "medium", lambda f: f.review_overdue is True, "The agent's review date has passed."),
    Rule(
        "EVALUATION_NOT_RUN",
        "medium",
        lambda f: f.evaluation_verdict == "not_run",
        "No evaluation result is recorded for the agent.",
    ),
    Rule(
        "CELL_HEALTH_NEEDS_ATTENTION",
        "medium",
        lambda f: f.cell_health_state == "needs_attention",
        "The agent's cell needs attention.",
    ),
    Rule(
        "SPONSOR_MISSING",
        "low",
        lambda f: f.sponsor_missing is True,
        "The registration names no accountable person.",
    ),
    Rule(
        "GATEWAY_POLICY_LOG_ONLY",
        "low",
        lambda f: f.gateway_policy_mode == "log_only",
        "The Tool Gateway's policy engine only logs decisions.",
    ),
    Rule("INACTIVE", "low", lambda f: f.inactive is True, "The Runtime has not been invoked in the inactivity window."),
)


def closed(facts: RiskFacts) -> bool:
    """Whether the agent's obligations are closed: a retired registration with no Runtime known.

    Retirement is terminal. A retired record can no longer be updated,
    reviewed, approved or submitted, so a finding about what it says (its
    owner group, its sponsor, its evaluation) could never be cleared, and the
    agent would stay in the attention list until someone deleted the record.
    With nothing deployed there is nothing left to do, and no rule applies.

    A retired registration whose Runtime is still deployed is the opposite
    case: someone still has to remove that Runtime, so every rule applies,
    ``REGISTRATION_DEPRECATED`` first. A rejected registration is not closed
    either: it can be corrected and submitted again.

    "Closed" takes an agent out of every list that asks for attention, so it
    is not granted while the portal is blind for a passing reason. When the
    reader of the Runtime's account exists and could not be used for this
    inventory, the Runtime may well be there: the agent is not closed, and
    the rules apply to it as to any registered agent whose Runtime could not
    be read. An account with no reader at all, and a registration that names
    no Runtime, do not keep an agent open: nothing would ever close it.

    This is the one place the condition is written. ``assess`` uses it for the
    risk, and the service uses it for the flags and the fleet summary.
    """
    return (
        facts.registry_status == "DEPRECATED"
        and facts.runtime_known is not True
        and facts.runtime_reader_unreachable is not True
    )


def assess(facts: RiskFacts) -> Risk:
    """The agent's risk: every rule that applies, most severe first, and the highest severity as the level."""
    if closed(facts):
        return Risk(level=SEVERITIES[0], reasons=())
    reasons = [Reason(rule.code, rule.severity, rule.detail) for rule in RULES if rule.applies(facts)]
    reasons.sort(key=lambda reason: -SEVERITIES.index(reason.severity))  # stable: table order within a severity
    level = reasons[0].severity if reasons else SEVERITIES[0]
    return Risk(level=level, reasons=tuple(reasons))


def weakest_policy_mode(modes: list[str]) -> str | None:
    """The least protective of several gateway policy modes (none before log_only before enforce)."""
    for mode in ("none", "log_only", "enforce"):
        if mode in modes:
            return mode
    return None
