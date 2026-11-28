# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Reading the append-only audit trail (Amazon DynamoDB). Query only; writes live in ``portal_api/actions``.

Every read here is bounded. A history is append-only and nothing in it is
ever deleted, so a read that follows a partition to its end grows without
limit, and a partition that someone managed to fill would stop every decision
about its record or Runtime. So:

- a decision reads newest first and stops at the event that settles it
  (``read_holder``, ``read_submitter``, ``read_for_review``,
  ``read_for_sweep``), and never reads more than ``MAX_DECISION_EVENTS``. If
  nothing settles it within that, the caller fails closed;
- a view reads the newest ``MAX_VIEW_EVENTS`` and says when older ones were
  left out (``newest``).

No function here follows a partition to its end without such a bound.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from portal_api import sweeps
from portal_api.mappers.common import parse_instant
from portal_api.models.portal import AuditEvent
from portal_api.reviews import KIND_APPROVAL, KIND_REVIEW, Attestation, parse_date

_FIELDS = (
    "event_id",
    "request_id",
    "at",
    "phase",
    "action",
    "outcome",
    "reason",
    "actor_subject",
    "actor_label",
    "actor_role",
    "tenant_id",
    "record_id",
    "record_name",
    "document_sha256",
    "status_before",
    "status_after",
    "next_review_by",
    "attested_at",
    "agent_id",
    "runtime_arn",
    "sessions_found",
    "sessions_stopped",
    "sessions_failed",
    "sweeps_scheduled",
    "sweep",
    "sessions_not_active",
    "duration_ms",
    "detail",
)


def record_key(record_id: str) -> str:
    return f"RECORD#{record_id}"


def name_key(record_name: str) -> str:
    """Partition for decisions taken before a record id exists (a create, allowed or denied)."""
    return f"RECORD#NAME#{record_name}"


def containment_key(runtime_arn: str) -> str:
    """The partition of a Runtime's containment history.

    Keyed by the Runtime the request resolved to, never by the id the caller
    used: a Runtime can be addressed by a registry record id and by its own
    id, and a history split across those would let the person who contained
    it release it under the other name.
    """
    return f"CONTAINMENT#{runtime_arn}"


def sweep_claim_sort_key(request_id: str, number: int) -> str:
    """The sort key of the item that claims one background sweep of one contain.

    The item lies in the Runtime's own partition and is not an event: every
    read of a history asks for sort keys that begin with ``EVENT#``, so none
    returns it. It is written with the condition every write here carries
    (the item must not exist), which is what makes it a claim: of two
    deliveries of the same sweep message, only one gets it.
    """
    return f"SWEEP#{request_id}#{number}"


# The attribute of a claim that says which attempt wrote it.
CLAIM_ID_ATTRIBUTE = "claim_id"


def sweep_claim_id(client: Any, table: str, runtime_arn: str, request_id: str, number: int) -> str | None:
    """Which attempt holds the claim of one sweep: the id stored with it, or ``None`` when nothing is.

    One request for one item, by its whole key.
    """
    sort_key = sweep_claim_sort_key(request_id, number)
    for page in _pages(client, table, containment_key(runtime_arn), page_size=1, prefix=sort_key):
        for item in page.get("Items") or []:
            if item.get("sk", {}).get("S") == sort_key:
                return item.get(CLAIM_ID_ATTRIBUTE, {}).get("S")
        break
    return None


# One partition holds every review attestation, so the read API gets them all with one query
# instead of one per agent. Its sort key is ``EVENT#<UTC timestamp>#<record id>``.
REVIEWS_KEY = "REVIEWS"
# Each page is at most 1 MB; this bounds the read. Newest first, so only the oldest are left out.
MAX_ATTESTATION_PAGES = 20


def attestation_sort_key(at: str, record_id: str) -> str:
    return f"EVENT#{at}#{record_id}"


# How many events one request asks for at a time, and the two bounds of a read.
PAGE_SIZE = 200
# What a view, a history and the evidence document show of one history: its newest events.
MAX_VIEW_EVENTS = 200
# The most a decision reads back while it looks for the event that settles it.
MAX_DECISION_EVENTS = 2000


@dataclass(frozen=True)
class Holder:
    """Who holds the containment of a Runtime, as far as the events that were read say."""

    event: AuditEvent | None  # the event that names the holder; None when nobody holds it
    # True when an event settled it, so that nothing older can change the answer. False when the
    # events ran out first: the answer then holds only if they were the whole history.
    decided: bool
    # How many of the events given belong to the containment that holds, counted from the newest:
    # everything up to and including the event that settled it. All of them when none did.
    current: int = 0


def container(events: list[AuditEvent]) -> AuditEvent | None:
    """The event that names who holds the containment of a Runtime, or ``None`` when nobody does."""
    return holder(events).event


def holder(events: list[AuditEvent]) -> Holder:
    """Who holds the containment of a Runtime, and whether the events given settle it.

    ``events`` is newest first, and may be only the newest part of the
    history. The holder is the person a release must not come from.

    - A contain that was allowed names the holder, until a release is allowed after it.
    - A repeated contain (outcome ``unchanged``) never replaces an earlier holder, so the
      two-person rule cannot be dodged by containing again. When no holder is on record (the
      Runtime was contained by other means, or by a request whose result was lost), the first
      person to assert the containment becomes the holder.
    - A contain that failed after the statement may have been written (``status_after`` other
      than ``not_contained``) names a holder too: the statement can be in place.
    - An intent whose result is missing counts as its result would have.
    - A background sweep is nobody's contain or release. It carries the request id of the contain
      that scheduled it, so it must not be taken for that contain's result: a contain whose own
      result event was lost still names its holder after its sweeps have run.

    The scan ends at the first event that settles the answer: a contain or a
    release that was allowed, a contain that failed after its statement may
    have been written, or an intent with no result. A result is always newer
    than its intent, so the newest part of a history is enough to tell
    whether an intent has one.
    """
    results = {e.request_id for e in events if e.phase == "result" and e.action in ("contain", "release")}
    asserted: AuditEvent | None = None  # the oldest "unchanged" contain since the last release
    for position, event in enumerate(events):
        if event.action not in ("contain", "release"):
            continue
        if event.phase == "intent":
            if event.request_id in results or event.outcome != "allowed":
                continue  # its result event decides
        elif event.action == "contain" and event.outcome == "unchanged":
            asserted = event  # an earlier holder, if there is one, stays the holder
            continue
        elif event.action == "contain" and event.outcome == "failed":
            if event.status_after in (None, "not_contained"):
                continue  # nothing was written
            return Holder(event, True, position + 1)
        elif event.outcome != "allowed":
            continue
        return Holder(asserted if event.action == "release" else event, True, position + 1)
    return Holder(asserted, False, len(events))


def from_item(item: dict[str, Any]) -> AuditEvent:
    values = {name: item[name]["S"] for name in _FIELDS if name in item and "S" in item[name]}
    return AuditEvent(**values)


# Attribute of an approve result event that holds the approved document (canonical JSON).
DOCUMENT_ATTRIBUTE = "document"


def last_approved_document(items: list[dict[str, Any]]) -> str | None:
    """The canonical document stored with the latest completed approval, if any. ``items`` is newest first."""
    for item in items:
        event = from_item(item)
        if event.action == "approve" and event.phase == "result" and event.outcome == "allowed":
            return item.get(DOCUMENT_ATTRIBUTE, {}).get("S")
    return None


def _pages(
    client: Any,
    table: str,
    partition_key: str,
    *,
    page_size: int | None = None,
    oldest_first: bool = False,
    prefix: str = "EVENT#",
) -> Iterator[dict[str, Any]]:
    """The pages of one partition, newest first, with a strongly consistent read.

    A page is requested only when the caller asks for the next one, so a
    caller that stops early reads no further. ``page_size`` is the most items
    one request returns; without it a page holds up to 1 MB. ``prefix`` is
    what the sort keys begin with: events, unless the caller names another.
    """
    paginator = client.get_paginator("query")
    arguments: dict[str, Any] = {
        "TableName": table,
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":pk": {"S": partition_key}, ":prefix": {"S": prefix}},
        "ConsistentRead": True,
        "ScanIndexForward": oldest_first,
    }
    if page_size is not None:
        arguments["PaginationConfig"] = {"PageSize": page_size}
    yield from paginator.paginate(**arguments)


@dataclass(frozen=True)
class Trail:
    """The newest part of one history, as far back as a read went. Newest first."""

    items: list[dict[str, Any]]  # the raw items
    events: list[AuditEvent]  # the same items as events
    ended: bool  # True when the read reached the oldest event: the history holds nothing older


def read_back(
    client: Any,
    table: str,
    partition_key: str,
    enough: Callable[[list[AuditEvent]], bool] | None = None,
    *,
    max_events: int = MAX_DECISION_EVENTS,
    page_size: int = PAGE_SIZE,
    oldest_first: bool = False,
) -> Trail:
    """Read one history back from its newest event, a page at a time, and stop as soon as possible.

    The read stops when ``enough(events so far)`` is true, when the history
    ends, or when ``max_events`` have been read, whichever comes first. It is
    the only way this module reads a history, so no read is without a bound.
    ``oldest_first`` reads forward from the oldest event instead.
    """
    items: list[dict[str, Any]] = []
    events: list[AuditEvent] = []
    for page in _pages(client, table, partition_key, page_size=page_size, oldest_first=oldest_first):
        found = page.get("Items") or []
        items.extend(found)
        events.extend(from_item(item) for item in found)
        if not page.get("LastEvaluatedKey"):
            return Trail(items, events, True)
        if len(events) >= max_events or (enough is not None and enough(events)):
            return Trail(items, events, False)
    return Trail(items, events, True)


def latest(client: Any, table: str, partition_key: str, count: int) -> list[AuditEvent]:
    """The newest ``count`` events of one history, newest first, in one request."""
    return read_back(client, table, partition_key, max_events=count, page_size=count).events


def newest(client: Any, table: str, partition_key: str, limit: int = MAX_VIEW_EVENTS) -> tuple[list[AuditEvent], bool]:
    """The newest ``limit`` events of one history, newest first, and whether older ones were left out."""
    # One more than is shown, in one request: that one says whether anything older exists.
    trail = read_back(client, table, partition_key, max_events=limit + 1, page_size=limit + 1)
    return trail.events[:limit], len(trail.events) > limit


def read_holder(client: Any, table: str, runtime_arn: str, *, at_least: int = 0) -> tuple[Trail, Holder]:
    """A Runtime's containment history, read back to the event that settles who holds it.

    ``at_least`` asks for more than that many events when the history has
    them (a view shows the newest ones). The answer is settled when the
    holder says ``decided`` or the trail says ``ended``. If neither is true,
    ``MAX_DECISION_EVENTS`` were read without finding the event: the caller
    must not treat the holder as known.
    """

    def enough(events: list[AuditEvent]) -> bool:
        return len(events) > at_least and holder(events).decided

    trail = read_back(client, table, containment_key(runtime_arn), enough, page_size=max(PAGE_SIZE, at_least + 1))
    return trail, holder(trail.events)


def read_for_sweep(client: Any, table: str, runtime_arn: str, request_id: str) -> Trail:
    """A Runtime's containment history, read back to the intent of the contain with this request id.

    The sweeper decides on it whether a sweep message belongs to a contain
    that is on record, whether that sweep has already left its event, and
    whether the contain is part of the containment that holds. Everything
    that carries the contain's request id is newer than its intent, so the
    read ends there. A contain that is not among the newest
    ``MAX_DECISION_EVENTS`` events is not found, and no sweep is run for it.
    """
    return read_back(client, table, containment_key(runtime_arn), lambda events: sweeps.intent_read(events, request_id))


def read_submitter(client: Any, table: str, record_id: str) -> tuple[AuditEvent | None, bool]:
    """The event that names a record's current submitter, and whether that answer is settled.

    The record's history is read back to its latest submit. The answer is
    settled when one was found, or when the whole history was read and holds
    none. It is not settled when ``MAX_DECISION_EVENTS`` were read without
    finding one: the caller must not treat the record as having no submitter.
    """
    trail = read_back(client, table, record_key(record_id), lambda events: submitter(events) is not None)
    found = submitter(trail.events)
    return found, found is not None or trail.ended


def attestation_from_item(item: dict[str, Any]) -> Attestation | None:
    """A stored attestation, or ``None`` for an item that is not a complete one."""

    def value(name: str) -> str | None:
        attribute = item.get(name)
        return attribute.get("S") if isinstance(attribute, dict) else None

    record_id, at, next_review_by, reviewed_by = (
        value("record_id"),
        value("at"),
        value("next_review_by"),
        value("reviewed_by"),
    )
    if not record_id or not at or not reviewed_by or parse_date(next_review_by) is None:
        return None
    return Attestation(
        record_id=record_id,
        at=at,
        next_review_by=str(next_review_by),
        reviewed_by=reviewed_by,
        reviewed_by_label=value("reviewed_by_label") or reviewed_by,
        reviewed_by_role=value("reviewed_by_role"),
        reason=value("reason"),
        request_id=value("request_id"),
        kind=KIND_APPROVAL if value("kind") == KIND_APPROVAL else KIND_REVIEW,
    )


def query_attestations(
    client: Any, table: str, max_pages: int = MAX_ATTESTATION_PAGES
) -> tuple[list[Attestation], bool]:
    """Every review attestation, newest first, and whether the read stopped before the end.

    The read is bounded to ``max_pages`` pages. Because it runs newest first,
    a truncated read leaves out only the oldest attestations.
    """
    found: list[Attestation] = []
    read = 0
    for page in _pages(client, table, REVIEWS_KEY):
        read += 1
        for item in page.get("Items") or []:
            attestation = attestation_from_item(item)
            if attestation is not None:
                found.append(attestation)
        if read >= max_pages:
            return found, bool(page.get("LastEvaluatedKey"))
    return found, False


def read_for_review(client: Any, table: str, record_id: str, since: dt.datetime) -> tuple[Trail, bool]:
    """A record's history, read back far enough to decide a review, and whether it was.

    Far enough means: back to the record's latest submit (who submitted it),
    and past ``since`` (every event newer than that is there, so a review
    attested since then is among them). It is not far enough when
    ``MAX_DECISION_EVENTS`` were read first: the caller must not go on.
    """

    def covered(events: list[AuditEvent]) -> bool:
        oldest = parse_instant(events[-1].at) if events else None
        return oldest is not None and oldest < since

    trail = read_back(
        client, table, record_key(record_id), lambda events: submitter(events) is not None and covered(events)
    )
    settled = trail.ended or (submitter(trail.events) is not None and covered(trail.events))
    return trail, settled


def last_review_attempt(events: list[AuditEvent]) -> AuditEvent | None:
    """The record's latest review that attested, or may have. ``events`` is newest first.

    A review whose result says ``allowed`` attested. One whose intent was
    written and whose result is missing may have: the attestation is written
    between the two. Both count for the rule that spaces reviews out, so a
    gap in the trail can only make a second attestation wait, never let it
    through. (``last_review`` is stricter, for what is shown as reviewed.)
    """
    results = {e.request_id for e in events if e.action == "review" and e.phase == "result"}
    for event in events:
        if event.action != "review" or event.outcome != "allowed":
            continue
        if event.phase == "result" or event.request_id not in results:
            return event
    return None


# The actions whose result event can name an attestation, and the kind of attestation it is.
_ATTESTING_ACTIONS = {"review": KIND_REVIEW, "approve": KIND_APPROVAL}


def last_review(events: list[AuditEvent]) -> Attestation | None:
    """The record's latest completed attestation, from its own events. ``events`` is newest first.

    A review counts, and so does an approval that recorded a review date (its
    result event then names the attestation in ``attested_at``). Only a
    ``result`` event that says ``allowed`` counts. An intent with no result
    does not: showing a registration as not yet reviewed is the safe side of
    a gap in the trail.
    """
    for event in events:
        kind = _ATTESTING_ACTIONS.get(event.action)
        if kind is None or event.phase != "result" or event.outcome != "allowed":
            continue
        if kind == KIND_APPROVAL and not event.attested_at:
            continue  # the approved document named no review date, or the attestation was not written
        if event.record_id and parse_date(event.next_review_by) is not None:
            return Attestation(
                record_id=event.record_id,
                # The attestation's own time, so every view shows the same instant for one review.
                at=event.attested_at or event.at,
                next_review_by=str(event.next_review_by),
                reviewed_by=event.actor_subject,
                reviewed_by_label=event.actor_label,
                reviewed_by_role=event.actor_role,
                reason=event.reason,
                request_id=event.request_id,
                kind=kind,
            )
    return None


def submitter(events: list[AuditEvent]) -> AuditEvent | None:
    """The event that names the record's current submitter.

    That is the latest ``submit`` that was allowed and performed. A submit
    whose intent was written but whose result is missing (the result write
    failed after the registry call) still counts, so a gap in the trail can
    only make self-approval harder, never easier. ``events`` is newest first.
    """
    results = {e.request_id: e for e in events if e.action == "submit" and e.phase == "result"}
    for event in events:
        if event.action != "submit" or event.outcome != "allowed":
            continue
        if event.phase == "result":
            return event
        if event.phase == "intent" and event.request_id not in results:
            return event
    return None
