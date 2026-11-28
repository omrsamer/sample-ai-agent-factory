# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Who may retire a registration or attest its review. Pure rules, no AWS calls.

Retire sets a record's status to DEPRECATED, which the registry never undoes.

- It needs the approver authority (RET-01-N) and the record's tenant
  (RET-02-N). ``platform`` holds every tenant.
- There is no two-person rule: the person who registered or approved a record
  may retire it.
- It is allowed from every settled status. Retiring a retired record changes
  nothing and is answered as ``unchanged``. A record that is still being
  created or updated is refused until it settles (RET-04-N).
- A retired record is final. Approving, rejecting, updating or submitting it
  is refused (RET-03-N). It can still be deleted.

A review attestation records that an approver reviewed an approved
registration and by when it must be reviewed again.

- It needs the approver authority (REV-01-N) and the record's tenant (REV-02-N).
- The record must be APPROVED (REV-03-N): there is nothing to attest for a
  record that is not approved.
- The next review date must be after today and at most 366 days ahead
  (REV-04-N, in ``portal_api/reviews.py``).
- The record's submitter cannot attest its review (REV-05-N), as the
  submitter cannot approve it: a review is a second pair of eyes. A record
  the portal knows no submitter of can be attested by any approver.
- A record's review can be attested once in 24 hours (REV-06-N). An approval
  is not a review attestation and is not counted.

The rules are evaluated in that order and the first that fails decides. The
last two need the record's history, so they are functions of their own
(``submitter_refusal``, ``recent_review_refusal``), asked only for a caller
who has passed the rules before them.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from portal_api.authorities import APPROVER_ROLES

ACTIONS = ("retire", "review")
ALLOW, DENY, CONFLICT, UNCHANGED = "allow", "deny", "conflict", "unchanged"

RETIRED = "DEPRECATED"
TRANSITIONAL = frozenset({"CREATING", "UPDATING"})
# How long after a review attestation the same record cannot be attested again.
REVIEW_INTERVAL_HOURS = 24

_AUTHORITY = {
    "retire": "retire requires the approver authority; principal holds the '{role}' role (RET-01-N)",
    "review": "a review attestation requires the approver authority; principal holds the '{role}' role (REV-01-N)",
}
_TENANT = {
    "retire": "the record belongs to a tenant the principal does not hold (RET-02-N)",
    "review": "the record belongs to a tenant the principal does not hold (REV-02-N)",
}
# What a retired record refuses, and the word for it.
_REFUSED_WHEN_RETIRED = {"approve": "approved", "reject": "rejected", "update": "updated", "submit": "submitted"}


@dataclass(frozen=True)
class LifecycleDecision:
    outcome: str  # allow | deny | conflict | unchanged
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome == ALLOW

    @property
    def http_status(self) -> int | None:
        """403 for a deny, 409 for a conflict; ``None`` when the request is not refused."""
        return {DENY: 403, CONFLICT: 409}.get(self.outcome)


def authority_refusal(action: str, role: str, principal_id: str) -> LifecycleDecision | None:
    """The refusal for a caller who may not take ``action`` on any record, or ``None``.

    Checked before a record is read, so the answer does not reveal whether the record exists.
    """
    if action not in ACTIONS:
        return LifecycleDecision(DENY, f"unknown action '{action}' - fail closed")
    if not principal_id or not role:
        return LifecycleDecision(DENY, "missing or incomplete principal - fail closed")
    if role not in APPROVER_ROLES:
        return LifecycleDecision(DENY, _AUTHORITY[action].format(role=role))
    return None


def evaluate(
    *,
    action: str,
    role: str,
    principal_id: str,
    record_tenant: str | None,
    held_tenants: tuple[str, ...],
    holds_all_tenants: bool,
    record_status: str | None,
) -> LifecycleDecision:
    """Decide one retire or review request on one record. Fails closed on anything unexpected."""
    refusal = authority_refusal(action, role, principal_id)
    if refusal is not None:
        return refusal
    if not holds_all_tenants and (not record_tenant or record_tenant not in held_tenants):
        return LifecycleDecision(DENY, _TENANT[action])
    if not record_status:
        return LifecycleDecision(DENY, "the record's status is not known - fail closed")

    if action == "retire":
        if record_status == RETIRED:
            return LifecycleDecision(UNCHANGED, "the record is already retired; nothing was changed")
        if record_status in TRANSITIONAL:
            return LifecycleDecision(
                CONFLICT, "the record is still being created or updated; try again shortly (RET-04-N)"
            )
        return LifecycleDecision(ALLOW, "approver retires the record (RET-01-P)")

    if record_status != "APPROVED":
        return LifecycleDecision(
            CONFLICT, f"only an approved registration can be attested; this one is {record_status} (REV-03-N)"
        )
    return LifecycleDecision(ALLOW, "approver attests the review of the approved record (REV-01-P)")


def submitter_refusal(principal_id: str, submitted_by: str | None) -> LifecycleDecision | None:
    """The refusal of a review by the record's own submitter (REV-05-N), or ``None``.

    ``submitted_by`` is the subject of whoever the audit trail says submitted
    the record last; ``None`` when the portal knows no submitter (a record
    published by a pipeline), which any approver may attest.
    """
    if submitted_by and submitted_by == principal_id:
        return LifecycleDecision(
            DENY, "the submitter cannot attest the review of its own record - separation of duties (REV-05-N)"
        )
    return None


def recent_review_refusal(last_attested_at: dt.datetime | None, now: dt.datetime) -> LifecycleDecision | None:
    """The refusal of a review that comes too soon after the last one (REV-06-N), or ``None``.

    ``last_attested_at`` is the time of the record's latest review
    attestation; ``None`` when it has none. Approvals are not counted.
    """
    if last_attested_at is None or now - last_attested_at >= dt.timedelta(hours=REVIEW_INTERVAL_HOURS):
        return None
    at = last_attested_at.astimezone(dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return LifecycleDecision(
        CONFLICT,
        f"a registration's review can be attested once in {REVIEW_INTERVAL_HOURS} hours; "
        f"this one was attested at {at} (REV-06-N)",
    )


def retired_refusal(action: str, record_status: str | None) -> str | None:
    """Why ``action`` is refused on a retired record (RET-03-N), or ``None`` when that is not the case."""
    if record_status != RETIRED or action not in _REFUSED_WHEN_RETIRED:
        return None
    return f"a retired record cannot be {_REFUSED_WHEN_RETIRED[action]}: retirement is permanent (RET-03-N)"
