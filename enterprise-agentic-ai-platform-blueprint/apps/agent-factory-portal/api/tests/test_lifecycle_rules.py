# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The pure rules for retiring a registration and attesting its review."""

from __future__ import annotations

import datetime as dt

import pytest

from portal_api import reviews
from portal_api.actions import lifecycle_rules as rules
from portal_api.config import PORTAL_ROLES
from portal_api.reviews import Attestation

STATUSES = ("DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED", "DEPRECATED", "CREATING", "UPDATING")


def decide(action: str, **changes):
    request = {
        "action": action,
        "role": "approver",
        "principal_id": "ann-1",
        "record_tenant": "ws1",
        "held_tenants": ("ws1",),
        "holds_all_tenants": False,
        "record_status": "APPROVED",
        **changes,
    }
    return rules.evaluate(**request)


# --- who ---------------------------------------------------------------------------------


@pytest.mark.parametrize("action", rules.ACTIONS)
@pytest.mark.parametrize("role", PORTAL_ROLES)
def test_only_the_approver_authority_may_retire_or_attest(action, role):
    decision = decide(action, role=role, holds_all_tenants=role == "platform")
    holds = role in ("platform", "approver", "security")
    assert decision.allowed is holds
    if not holds:
        rule = "RET-01-N" if action == "retire" else "REV-01-N"
        assert decision.outcome == rules.DENY and decision.http_status == 403
        assert rule in decision.reason and f"'{role}'" in decision.reason
        # The same refusal is available before any record is read.
        blind = rules.authority_refusal(action, role, "someone")
        assert blind is not None and blind.reason == decision.reason
    else:
        assert rules.authority_refusal(action, role, "someone") is None


@pytest.mark.parametrize(("action", "rule"), [("retire", "RET-02-N"), ("review", "REV-02-N")])
def test_the_caller_must_hold_the_records_tenant(action, rule):
    other = decide(action, held_tenants=("ws2",))
    assert (other.outcome, other.http_status) == (rules.DENY, 403) and rule in other.reason
    assert rule in decide(action, held_tenants=()).reason
    # A record with no tenant can be acted on only by the role that holds every tenant.
    assert rule in decide(action, record_tenant=None).reason
    assert rule in decide(action, record_tenant="").reason
    assert decide(action, record_tenant=None, role="platform", holds_all_tenants=True).allowed
    assert decide(action, role="platform", held_tenants=(), holds_all_tenants=True).allowed


@pytest.mark.parametrize("action", rules.ACTIONS)
def test_authority_is_checked_before_the_tenant(action):
    decision = decide(action, role="developer", held_tenants=("ws2",))
    assert "01-N" in decision.reason


@pytest.mark.parametrize("action", rules.ACTIONS)
@pytest.mark.parametrize(
    "changes", [{"principal_id": ""}, {"role": ""}, {"record_status": None}, {"record_status": ""}]
)
def test_an_incomplete_request_fails_closed(action, changes):
    decision = decide(action, **changes)
    assert decision.outcome == rules.DENY and "fail closed" in decision.reason


def test_an_unknown_action_fails_closed():
    decision = decide("resurrect")
    assert decision.outcome == rules.DENY and "unknown action 'resurrect'" in decision.reason
    assert rules.authority_refusal("resurrect", "platform", "pat-1") is not None


# --- retire ------------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED", "CREATE_FAILED"])
def test_retire_is_allowed_from_every_settled_status(status):
    decision = decide("retire", record_status=status)
    assert decision.allowed and decision.http_status is None
    assert decision.reason == "approver retires the record (RET-01-P)"


def test_retiring_a_retired_record_changes_nothing():
    decision = decide("retire", record_status="DEPRECATED")
    assert decision.outcome == rules.UNCHANGED and not decision.allowed and decision.http_status is None
    assert "already retired" in decision.reason


@pytest.mark.parametrize("status", ["CREATING", "UPDATING"])
def test_retire_waits_for_a_record_that_is_still_settling(status):
    decision = decide("retire", record_status=status)
    assert (decision.outcome, decision.http_status) == (rules.CONFLICT, 409) and "RET-04-N" in decision.reason


def test_there_is_no_two_person_rule_for_retire():
    """The rules do not ask who registered, submitted or approved the record."""
    assert decide("retire", principal_id="the-approver-of-this-record").allowed


@pytest.mark.parametrize(
    ("action", "word"),
    [("approve", "approved"), ("reject", "rejected"), ("update", "updated"), ("submit", "submitted")],
)
def test_a_retired_record_refuses_every_change(action, word):
    reason = rules.retired_refusal(action, "DEPRECATED")
    assert reason == f"a retired record cannot be {word}: retirement is permanent (RET-03-N)"
    for status in STATUSES:
        if status != "DEPRECATED":
            assert rules.retired_refusal(action, status) is None
    assert rules.retired_refusal(action, None) is None


@pytest.mark.parametrize("action", ["delete", "retire", "review", "create"])
def test_the_retired_refusal_covers_only_the_four_changes(action):
    # A retired record can still be deleted; retire and review have their own rules.
    assert rules.retired_refusal(action, "DEPRECATED") is None


# --- review ------------------------------------------------------------------------------


def test_only_an_approved_record_can_be_attested():
    allowed = decide("review")
    assert allowed.allowed and allowed.reason == "approver attests the review of the approved record (REV-01-P)"
    for status in STATUSES:
        if status == "APPROVED":
            continue
        decision = decide("review", record_status=status)
        assert (decision.outcome, decision.http_status) == (rules.CONFLICT, 409)
        assert "REV-03-N" in decision.reason and status in decision.reason


TODAY = dt.date(2026, 11, 27)


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("2026-11-28", True),  # tomorrow
        ("2027-11-28", True),  # 366 days ahead
        ("2027-11-29", False),  # 367 days ahead
        ("2026-11-27", False),  # today
        ("2026-11-26", False),
        ("2020-01-01", False),
        ("2027-02-30", False),  # not a calendar date
        ("2027-2-1", False),
        ("27-02-01", False),
        ("tomorrow", False),
        ("2027-02-01T00:00:00Z", False),
        ("2027-02-01\n", False),
        (" 2027-02-01", False),
        ("\u0662\u0660\u0662\u0667-\u0660\u0662-\u0660\u0661", False),  # digits that are not ASCII
        ("", False),
        (None, False),
        (20270201, False),
    ],
)
def test_the_next_review_date_is_after_today_and_at_most_366_days_ahead(value, accepted):
    problem = reviews.date_error(value, TODAY)
    assert (problem is None) is accepted
    if problem:
        assert problem.startswith("next_review_by") and "REV-04-N" in problem


def test_date_errors_say_what_is_wrong():
    assert "not a calendar date" in reviews.date_error("2027-02-30", TODAY)
    assert "after today, 2026-11-27" in reviews.date_error("2026-11-27", TODAY)
    assert "no later than 2027-11-28" in reviews.date_error("2028-01-01", TODAY)


def test_a_leap_day_is_a_calendar_date():
    assert reviews.date_error("2028-02-29", dt.date(2027, 3, 1)) is None
    assert reviews.date_error("2027-02-29", dt.date(2026, 3, 1)) is not None


# --- the effective review date -------------------------------------------------------------


def attestation(record_id: str = "recAgent0001", at: str = "2026-06-01T10:00:00.000000Z", next_: str = "2027-06-01"):
    return Attestation(
        record_id=record_id, at=at, next_review_by=next_, reviewed_by="ann-1", reviewed_by_label="Ann Approver"
    )


def test_the_latest_attestation_decides_the_effective_review_date():
    attested = reviews.effective("2026-03-01", attestation())
    assert (attested.review_by, attested.source) == ("2027-06-01", "attestation")
    # Also when the registration's own date is later, or missing.
    assert reviews.effective("2030-01-01", attestation()).review_by == "2027-06-01"
    assert reviews.effective(None, attestation()).review_by == "2027-06-01"


def test_an_approval_is_an_attestation_too_and_the_source_names_it():
    approval = Attestation(
        record_id="recAgent0001",
        at="2026-06-01T10:00:00.000000Z",
        next_review_by="2031-06-01",
        reviewed_by="ann-1",
        reviewed_by_label="Ann Approver",
        kind="approval",
    )
    assert reviews.effective("2026-03-01", approval) == reviews.EffectiveReview("2031-06-01", "approval")
    assert reviews.effective("2026-03-01", attestation()).source == "attestation"
    # The latest of the two kinds wins, whichever it is.
    later_review = attestation(at="2026-09-01T10:00:00.000000Z", next_="2027-09-01")
    latest = reviews.by_record([approval, later_review])["recAgent0001"][0]
    assert reviews.effective(None, latest) == reviews.EffectiveReview("2027-09-01", "attestation")
    earlier_review = attestation(at="2026-01-01T10:00:00.000000Z", next_="2026-12-01")
    latest = reviews.by_record([earlier_review, approval])["recAgent0001"][0]
    assert reviews.effective(None, latest) == reviews.EffectiveReview("2031-06-01", "approval")


def test_without_an_attestation_the_registrations_own_date_is_used():
    assert reviews.effective("2026-03-01", None) == reviews.EffectiveReview("2026-03-01", "registration")
    assert reviews.effective(None, None) == reviews.EffectiveReview(None, "none")
    assert reviews.effective("", None) == reviews.EffectiveReview(None, "none")


def test_overdue_means_the_date_is_before_today():
    assert reviews.overdue("2026-11-26", TODAY) is True
    assert reviews.overdue("2026-11-27", TODAY) is False  # due today is not overdue yet
    assert reviews.overdue("2026-11-28", TODAY) is False
    assert reviews.overdue(None, TODAY) is False
    # No review is due for a retired registration: it can never be attested again.
    assert reviews.overdue("2020-01-01", TODAY, retired=True) is False


def test_attestations_are_grouped_by_record_newest_first():
    first = attestation(at="2026-01-01T00:00:00.000000Z", next_="2026-07-01")
    second = attestation(at="2026-06-01T00:00:00.000000Z", next_="2027-06-01")
    other = attestation("recAgent0002")
    grouped = reviews.by_record([first, other, second])
    assert grouped == {"recAgent0001": [second, first], "recAgent0002": [other]}
    assert reviews.effective("2026-03-01", grouped["recAgent0001"][0]).review_by == "2027-06-01"
