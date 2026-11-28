# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The risk rule table: every rule, the ordering, unknowns, and that README.md documents it."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from portal_api import risk
from portal_api.risk import RiskFacts

README = (Path(__file__).resolve().parent.parent / "README.md").read_text()

# code -> (severity, the fewest facts that trigger that rule and no other)
CASES: dict[str, tuple[str, RiskFacts]] = {
    "RISK_CLASS_UNACCEPTABLE": ("critical", RiskFacts(risk_class="unacceptable")),
    "INBOUND_AUTH_NONE": ("critical", RiskFacts(authorizer_type="NONE")),
    "UNREGISTERED": ("high", RiskFacts(registered=False)),
    "REGISTRATION_REJECTED": ("high", RiskFacts(registered=True, registry_status="REJECTED", runtime_known=True)),
    "REGISTRATION_DEPRECATED": ("high", RiskFacts(registered=True, registry_status="DEPRECATED", runtime_known=True)),
    "RISK_CLASS_HIGH": ("high", RiskFacts(risk_class="high")),
    "DATA_RESTRICTED": ("high", RiskFacts(data_classification="restricted")),
    "OWNERLESS": ("high", RiskFacts(owner_group_missing=True)),
    "OWNER_GROUP_NOT_IN_ROSTER": ("high", RiskFacts(owner_group_in_roster=False)),
    "EVALUATION_FAILED": ("high", RiskFacts(evaluation_verdict="failed")),
    "CELL_HEALTH_CRITICAL": ("high", RiskFacts(cell_health_state="critical")),
    "REGISTRATION_NOT_APPROVED": ("medium", RiskFacts(registered=True, registry_status="PENDING_APPROVAL")),
    "GATEWAY_POLICY_NONE": ("medium", RiskFacts(gateway_policy_mode="none")),
    "GUARDRAIL_NOT_CONFIGURED": ("medium", RiskFacts(guardrail_configured=False)),
    "DATA_CONFIDENTIAL": ("medium", RiskFacts(data_classification="confidential")),
    "REVIEW_OVERDUE": ("medium", RiskFacts(review_overdue=True)),
    "EVALUATION_NOT_RUN": ("medium", RiskFacts(evaluation_verdict="not_run")),
    "CELL_HEALTH_NEEDS_ATTENTION": ("medium", RiskFacts(cell_health_state="needs_attention")),
    "SPONSOR_MISSING": ("low", RiskFacts(sponsor_missing=True)),
    "GATEWAY_POLICY_LOG_ONLY": ("low", RiskFacts(gateway_policy_mode="log_only")),
    "INACTIVE": ("low", RiskFacts(inactive=True)),
}

# An approved, well-governed agent: no rule applies.
BENIGN = RiskFacts(
    risk_class="minimal",
    data_classification="internal",
    registered=True,
    registry_status="APPROVED",
    runtime_known=True,
    owner_group_missing=False,
    owner_group_in_roster=True,
    sponsor_missing=False,
    review_overdue=False,
    inactive=False,
    gateway_policy_mode="enforce",
    guardrail_configured=True,
    authorizer_type="AWS_IAM",
    evaluation_verdict="passed",
    cell_health_state="healthy",
)


def codes(facts: RiskFacts) -> list[str]:
    return [reason.code for reason in risk.assess(facts).reasons]


def merged(*facts: RiskFacts) -> RiskFacts:
    values = {}
    for item in facts:
        values.update(
            {f.name: getattr(item, f.name) for f in dataclasses.fields(item) if getattr(item, f.name) is not None}
        )
    return RiskFacts(**values)


def test_every_rule_has_a_case_and_every_case_a_rule():
    assert set(CASES) == {rule.code for rule in risk.RULES}
    assert len({rule.code for rule in risk.RULES}) == len(risk.RULES)
    assert {rule.severity for rule in risk.RULES} <= set(risk.SEVERITIES)
    assert [rule.code for rule in risk.RULES] == list(CASES)  # the table order is the reporting order


@pytest.mark.parametrize("code", list(CASES))
def test_rule_applies_alone_with_its_severity(code):
    severity, facts = CASES[code]
    result = risk.assess(facts)
    assert [(r.code, r.severity) for r in result.reasons] == [(code, severity)]
    assert result.level == severity
    assert result.reasons[0].detail.endswith(".")


@pytest.mark.parametrize("code", list(CASES))
def test_rule_adds_to_an_otherwise_benign_agent(code):
    _, facts = CASES[code]
    assert codes(merged(BENIGN, facts)) == [code]


def test_no_rule_applies_to_a_benign_agent_or_to_unknown_facts():
    assert risk.assess(BENIGN) == risk.Risk(level="low", reasons=())
    assert risk.assess(RiskFacts()) == risk.Risk(level="low", reasons=())


@pytest.mark.parametrize(
    "facts",
    [
        RiskFacts(risk_class="limited"),
        RiskFacts(risk_class="minimal", data_classification="public"),
        RiskFacts(authorizer_type="CUSTOM_JWT"),
        RiskFacts(gateway_policy_mode="enforce", cell_health_state="no_data"),
        RiskFacts(registered=True, registry_status="APPROVED", runtime_known=True),
        RiskFacts(owner_group_missing=False, owner_group_in_roster=True, sponsor_missing=False),
        RiskFacts(review_overdue=False, inactive=False, guardrail_configured=True, evaluation_verdict="passed"),
        # not known is not a finding
        RiskFacts(registered=None, owner_group_in_roster=None, inactive=None, guardrail_configured=None),
        RiskFacts(registered=True, registry_status=None),
        RiskFacts(registered=True, registry_status="SOMETHING_NEW"),
    ],
)
def test_values_that_trigger_nothing(facts):
    assert risk.assess(facts).level == "low" and risk.assess(facts).reasons == ()


# --- why an agent is unmanaged: the cause, not one catch-all -----------------------------------------


def test_an_agent_nobody_registered_is_unregistered():
    result = risk.assess(RiskFacts(registered=False, runtime_known=True))
    assert [(r.code, r.severity, r.detail) for r in result.reasons] == [
        ("UNREGISTERED", "high", "The agent has no registration.")
    ]


@pytest.mark.parametrize(
    "status", ["DRAFT", "PENDING_APPROVAL", "CREATING", "UPDATING", "CREATE_FAILED", "UPDATE_FAILED"]
)
def test_a_registration_waiting_for_approval_is_medium_not_high(status):
    for runtime_known in (True, False, None):
        result = risk.assess(RiskFacts(registered=True, registry_status=status, runtime_known=runtime_known))
        assert [(r.code, r.severity) for r in result.reasons] == [("REGISTRATION_NOT_APPROVED", "medium")]
        assert result.reasons[0].detail == "The agent's registration is not approved yet."
        assert result.level == "medium"


@pytest.mark.parametrize(
    ("status", "code", "detail"),
    [
        (
            "REJECTED",
            "REGISTRATION_REJECTED",
            "The agent's registration was rejected and its Runtime is still deployed.",
        ),
        (
            "DEPRECATED",
            "REGISTRATION_DEPRECATED",
            "The agent's registration is retired (DEPRECATED) and its Runtime is still deployed.",
        ),
    ],
)
def test_rejected_and_deprecated_are_a_risk_only_while_a_runtime_is_known(status, code, detail):
    deployed = risk.assess(RiskFacts(registered=True, registry_status=status, runtime_known=True))
    assert [(r.code, r.severity, r.detail) for r in deployed.reasons] == [(code, "high", detail)]
    # a rejected or deprecated paper record with no Runtime is not a risk, and an unknown is not a finding
    for runtime_known in (False, None):
        assert codes(RiskFacts(registered=True, registry_status=status, runtime_known=runtime_known)) == []


def test_exactly_one_registration_cause_is_ever_reported():
    causes = {"UNREGISTERED", "REGISTRATION_REJECTED", "REGISTRATION_DEPRECATED", "REGISTRATION_NOT_APPROVED"}
    statuses = [None, "DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED", "DEPRECATED", "CREATING", "UPDATING"]
    for registered in (True, False):
        for status in statuses if registered else [None]:
            for runtime_known in (True, False):
                found = causes & set(
                    codes(RiskFacts(registered=registered, registry_status=status, runtime_known=runtime_known))
                )
                assert len(found) <= 1, (registered, status, runtime_known, found)
    assert codes(RiskFacts(registered=True, registry_status="APPROVED", runtime_known=True)) == []


# --- who owns an agent: the owner group; a person is optional --------------------------------------------


def test_owner_rules_say_exactly_what_is_wrong():
    assert [(r.code, r.detail) for r in risk.assess(RiskFacts(owner_group_missing=True)).reasons] == [
        ("OWNERLESS", "The registration names no owner group.")
    ]
    assert [(r.code, r.detail) for r in risk.assess(RiskFacts(owner_group_in_roster=False)).reasons] == [
        ("OWNER_GROUP_NOT_IN_ROSTER", "The registration's owner group is not in the owner roster.")
    ]
    sponsor = risk.assess(RiskFacts(sponsor_missing=True))
    assert [(r.code, r.severity, r.detail) for r in sponsor.reasons] == [
        ("SPONSOR_MISSING", "low", "The registration names no accountable person.")
    ]
    # an owner group and no person is a nudge, never an orphan
    owned = RiskFacts(owner_group_missing=False, owner_group_in_roster=None, sponsor_missing=True)
    assert codes(owned) == ["SPONSOR_MISSING"] and risk.assess(owned).level == "low"
    # with no roster configured, whether the group is in it is unknown and triggers nothing
    assert codes(RiskFacts(owner_group_missing=False, owner_group_in_roster=None, sponsor_missing=False)) == []


# --- ordering -------------------------------------------------------------------------------------------


def test_level_is_the_highest_severity_and_each_level_beats_the_ones_below():
    low, medium = CASES["INACTIVE"][1], CASES["REVIEW_OVERDUE"][1]
    high, critical = CASES["UNREGISTERED"][1], CASES["RISK_CLASS_UNACCEPTABLE"][1]
    assert risk.assess(low).level == "low"
    assert risk.assess(merged(low, medium)).level == "medium"
    assert risk.assess(merged(low, medium, high)).level == "high"
    result = risk.assess(merged(low, medium, high, critical))
    assert result.level == "critical"
    assert [r.code for r in result.reasons] == ["RISK_CLASS_UNACCEPTABLE", "UNREGISTERED", "REVIEW_OVERDUE", "INACTIVE"]
    assert [r.severity for r in result.reasons] == ["critical", "high", "medium", "low"]
    # Many lower findings never add up to a higher level: there are no weights.
    many_medium = RiskFacts(
        registered=True,
        registry_status="DRAFT",
        gateway_policy_mode="none",
        guardrail_configured=False,
        data_classification="confidential",
        review_overdue=True,
        evaluation_verdict="not_run",
        cell_health_state="needs_attention",
        inactive=True,
        sponsor_missing=True,
    )
    assert risk.assess(many_medium).level == "medium" and len(risk.assess(many_medium).reasons) == 9


def test_reasons_within_a_severity_follow_the_table_order_and_the_result_is_deterministic():
    facts = RiskFacts(
        cell_health_state="critical",
        evaluation_verdict="failed",
        owner_group_in_roster=False,
        owner_group_missing=True,
        data_classification="restricted",
        risk_class="high",
        registered=True,
        registry_status="REJECTED",
        runtime_known=True,
    )
    assert codes(facts) == [
        "REGISTRATION_REJECTED",
        "RISK_CLASS_HIGH",
        "DATA_RESTRICTED",
        "OWNERLESS",
        "OWNER_GROUP_NOT_IN_ROSTER",
        "EVALUATION_FAILED",
        "CELL_HEALTH_CRITICAL",
    ]
    assert risk.assess(facts) == risk.assess(facts)


def test_guardrail_reason_wording():
    (reason,) = risk.assess(RiskFacts(guardrail_configured=False)).reasons
    assert (reason.code, reason.severity, reason.detail) == (
        "GUARDRAIL_NOT_CONFIGURED",
        "medium",
        "The Runtime's configuration names neither a guardrail nor the inference gateway.",
    )
    assert codes(RiskFacts(guardrail_configured=True)) == [] and codes(RiskFacts(guardrail_configured=None)) == []


def test_weakest_policy_mode():
    assert risk.weakest_policy_mode(["enforce", "none", "log_only"]) == "none"
    assert risk.weakest_policy_mode(["enforce", "log_only"]) == "log_only"
    assert risk.weakest_policy_mode(["enforce"]) == "enforce"
    assert risk.weakest_policy_mode([]) is None


def test_readme_documents_every_rule_with_its_severity_in_table_order():
    positions = []
    for rule in risk.RULES:
        row = f"| `{rule.code}` | {rule.severity} |"
        assert row in README, rule.code
        positions.append(README.index(row))
    assert positions == sorted(positions)
    assert "| `UNMANAGED` |" not in README  # replaced by the cause
    # the exact variable names the guardrail fact accepts are documented
    assert "`AGENTCORE_INFERENCE_GATEWAY_URL`" in README and "`AGENTCORE_GUARDRAIL_ID`" in README
    assert "names neither a guardrail nor the inference gateway" in README
    for flag in ("unmanaged", "ownerless", "review_overdue", "inactive", "contained"):
        assert f"| `{flag}` |" in README


# --- a retired registration with nothing deployed is closed ------------------------------------------

# Every fact that triggers a rule on its own, on a retired registration.
LOUD = RiskFacts(
    risk_class="unacceptable",
    data_classification="restricted",
    registered=True,
    registry_status="DEPRECATED",
    runtime_known=False,
    owner_group_missing=True,
    owner_group_in_roster=False,
    sponsor_missing=True,
    review_overdue=True,
    inactive=True,
    gateway_policy_mode="none",
    guardrail_configured=False,
    authorizer_type="NONE",
    evaluation_verdict="failed",
    cell_health_state="critical",
)


def by_the_table(facts: RiskFacts) -> list[str]:
    """The reasons the rule table alone gives, most severe first: what ``assess`` returns when no guard stands in."""
    found = [rule for rule in risk.RULES if rule.applies(facts)]
    found.sort(key=lambda rule: -risk.SEVERITIES.index(rule.severity))
    return [rule.code for rule in found]


@pytest.mark.parametrize("runtime_known", [False, None])
@pytest.mark.parametrize("reader_unreachable", [False, None])
def test_a_retired_registration_with_no_runtime_known_is_closed_and_no_rule_applies(runtime_known, reader_unreachable):
    facts = dataclasses.replace(LOUD, runtime_known=runtime_known, runtime_reader_unreachable=reader_unreachable)
    assert len(by_the_table(facts)) >= 10  # the table would have plenty to say
    assert risk.closed(facts) is True
    assert risk.assess(facts) == risk.Risk(level="low", reasons=())


@pytest.mark.parametrize("runtime_known", [False, None])
def test_it_is_not_closed_while_the_reader_of_its_runtimes_account_cannot_be_used(runtime_known):
    """Closed takes an agent off every list that asks for attention: never while the portal is blind in passing."""
    facts = dataclasses.replace(LOUD, runtime_known=runtime_known, runtime_reader_unreachable=True)
    assert risk.closed(facts) is False
    # The rules apply as they did before there was a guard: everything but the one that needs the Runtime to be seen.
    assert codes(facts) == by_the_table(facts) and len(codes(facts)) >= 10
    assert "REGISTRATION_DEPRECATED" not in codes(facts) and risk.assess(facts).level == "critical"
    # Seen by another source while the reader is down: still deployed, so not closed either.
    seen = dataclasses.replace(facts, runtime_known=True)
    assert risk.closed(seen) is False and "REGISTRATION_DEPRECATED" in codes(seen)


def test_a_retired_registration_whose_runtime_is_still_deployed_keeps_every_rule():
    facts = dataclasses.replace(LOUD, runtime_known=True)
    assert risk.closed(facts) is False
    found = risk.assess(facts)
    assert [reason.code for reason in found.reasons] == by_the_table(facts)
    assert found.level == "critical" and "REGISTRATION_DEPRECATED" in codes(facts)
    assert {"OWNERLESS", "OWNER_GROUP_NOT_IN_ROSTER", "EVALUATION_FAILED", "SPONSOR_MISSING"} <= set(codes(facts))


@pytest.mark.parametrize("status", ["REJECTED", "APPROVED", "DRAFT", "PENDING_APPROVAL", "UPDATING", None])
@pytest.mark.parametrize("runtime_known", [True, False, None])
def test_only_retirement_closes_an_agent(status, runtime_known):
    """A rejected registration can be corrected and submitted again, so its findings stay."""
    facts = dataclasses.replace(LOUD, registry_status=status, runtime_known=runtime_known)
    assert risk.closed(facts) is False
    assert codes(facts) == by_the_table(facts) and codes(facts)


def test_the_condition_is_written_in_one_place():
    import inspect

    from portal_api import service

    assert inspect.getsource(risk.assess).count("closed(facts)") == 1
    # The rules themselves are untouched: the one about a retired registration still needs a Runtime.
    assert CASES["REGISTRATION_DEPRECATED"][1].runtime_known is True
    # The service asks the same function for the flags and the summary, and holds no copy of the condition.
    source = inspect.getsource(service)
    assert source.count("risk.closed(facts)") == 1 and '"DEPRECATED" and' not in source
    # The service only states the fact that the reader failed; what follows from it is decided in ``closed``.
    assert source.count('runtime_reader_unreachable=agent.reader_status == "unreachable"') == 1
    assert inspect.getsource(risk.closed).count("runtime_reader_unreachable is not True") == 1
    assert "A retired registration with no Runtime known is closed" in " ".join(README.split())
