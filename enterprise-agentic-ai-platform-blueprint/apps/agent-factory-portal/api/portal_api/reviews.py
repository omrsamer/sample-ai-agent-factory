# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Periodic review of a registration: attestations and the effective review date. Pure, no AWS calls.

An attestation says that an approver reviewed a registration and by when it
must be reviewed again. It lives in the audit trail only, because any update
of a registry record returns the record to DRAFT. There are two kinds:

- ``review``: an approver attested the periodic review of an approved
  registration and set the next date (at most ``MAX_INTERVAL_DAYS`` ahead);
- ``approval``: an approver approved a document that names a ``reviewBy``
  date. Approving is reviewing, so the approval is recorded as an attestation
  with that date, or with the approval date plus ``MAX_INTERVAL_DAYS`` when
  the document's date is later than that. A document with no ``reviewBy``
  attests nothing.

No date gets further than ``MAX_INTERVAL_DAYS`` ahead by any way in: not a
review (``date_error``), not a registration's own date when it is created or
updated (``document_date_error``), not an approval (``approval_date``). A
registration approved with a date in the far future would otherwise never be
due, whatever the limit on reviews.

One rule decides the effective review date of a registered agent: the latest
attestation wins. So a later re-approval with a new date moves the date, and
so does a later review. Without any attestation the date is the ``reviewBy``
of the registration itself (a record that was approved outside the portal).
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable
from dataclasses import dataclass

# A review may be set at most this many days ahead: one year, with room for a leap day.
MAX_INTERVAL_DAYS = 366

KIND_REVIEW = "review"
KIND_APPROVAL = "approval"

SOURCE_ATTESTATION = "attestation"  # the latest attestation is a review
SOURCE_APPROVAL = "approval"  # the latest attestation is an approval
SOURCE_REGISTRATION = "registration"  # no attestation: the registration's own date
SOURCE_NONE = "none"

# ASCII digits only, and nothing after the day: dates are compared as text.
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


@dataclass(frozen=True)
class Attestation:
    """One review attestation, as stored in the audit trail."""

    record_id: str
    at: str  # ISO 8601 UTC, microseconds
    next_review_by: str  # YYYY-MM-DD
    reviewed_by: str  # subject id
    reviewed_by_label: str
    reviewed_by_role: str | None = None
    reason: str | None = None
    request_id: str | None = None
    kind: str = KIND_REVIEW  # review | approval


@dataclass(frozen=True)
class EffectiveReview:
    review_by: str | None  # YYYY-MM-DD, or None when neither an attestation nor the registration sets a date
    source: str  # attestation | approval | registration | none


def parse_date(value: object) -> dt.date | None:
    """A ``YYYY-MM-DD`` calendar date, or ``None`` for anything else."""
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def date_error(next_review_by: object, today: dt.date) -> str | None:
    """Why ``next_review_by`` cannot be attested, or ``None`` when it can.

    The date must be a calendar date after ``today`` and at most
    ``MAX_INTERVAL_DAYS`` days ahead (REV-04-N).
    """
    date = parse_date(next_review_by)
    if date is None:
        return "next_review_by is not a calendar date in the form YYYY-MM-DD (REV-04-N)"
    if date <= today:
        return f"next_review_by must be after today, {today.isoformat()} in UTC (REV-04-N)"
    latest = today + dt.timedelta(days=MAX_INTERVAL_DAYS)
    if date > latest:
        return (
            f"next_review_by may be at most {MAX_INTERVAL_DAYS} days ahead, "
            f"so no later than {latest.isoformat()} (REV-04-N)"
        )
    return None


def document_date_error(review_by: object, today: dt.date) -> str | None:
    """Why a registration's own ``reviewBy`` cannot stand, or ``None`` when it can or there is none.

    It may be at most ``MAX_INTERVAL_DAYS`` days ahead. A date that is not
    after today is the registrant's to give: the registration is then due at
    once. The message names the field as the document does.
    """
    date = parse_date(review_by)
    if date is None:
        return None  # no date, or not a date: the schema and the calendar check say so
    latest = today + dt.timedelta(days=MAX_INTERVAL_DAYS)
    if date > latest:
        return f"document.reviewBy may be at most {MAX_INTERVAL_DAYS} days ahead, so no later than {latest.isoformat()}"
    return None


def approval_date(review_by: str, today: dt.date) -> str:
    """The review date an approval records: the document's, or ``MAX_INTERVAL_DAYS`` from today if that is earlier.

    A document written before the limit, or by other means, can name a later
    date. Approving it does not carry that date into the trail.
    """
    date = parse_date(review_by)
    latest = today + dt.timedelta(days=MAX_INTERVAL_DAYS)
    return review_by if date is None or date <= latest else latest.isoformat()


def by_record(attestations: Iterable[Attestation]) -> dict[str, list[Attestation]]:
    """Attestations grouped by record id, newest first within a record."""
    grouped: dict[str, list[Attestation]] = {}
    for attestation in attestations:
        grouped.setdefault(attestation.record_id, []).append(attestation)
    for items in grouped.values():
        items.sort(key=lambda a: a.at, reverse=True)
    return grouped


def effective(registration_review_by: str | None, latest: Attestation | None) -> EffectiveReview:
    """The date by which the registration must be reviewed next, and where that date comes from."""
    if latest is not None:
        source = SOURCE_APPROVAL if latest.kind == KIND_APPROVAL else SOURCE_ATTESTATION
        return EffectiveReview(latest.next_review_by, source)
    if registration_review_by:
        return EffectiveReview(registration_review_by, SOURCE_REGISTRATION)
    return EffectiveReview(None, SOURCE_NONE)


def overdue(review_by: str | None, today: dt.date, *, retired: bool = False) -> bool:
    """True when the review date is before ``today``. No date means not overdue.

    A retired registration is never overdue: it can no longer be attested,
    updated or approved, so no review of it is due.
    """
    if retired:
        return False
    return bool(review_by and review_by < today.isoformat())
