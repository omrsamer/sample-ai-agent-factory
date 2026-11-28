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

A Runtime's containment history is kept in two ranges of its partition, and
every event is written once, into one of them:

- ``EVENT#``: the events that can change who holds the containment. The
  intent and the result of a contain that writes the statement, of a
  release that removes it, and of the first contain that finds the
  statement in place with nobody on record as holding it;
- ``OTHER#``: every other event. A background sweep, a refusal, a contain
  of a Runtime that is already contained and held (it stops sessions and
  schedules sweeps, and changes nothing about who holds it), a release of a
  Runtime that is not contained, and an attempt that failed before it could
  change anything.

Who holds a containment is read from the first range alone (``read_holder``,
``holder``), so that read does not grow with the sweeps and the repeated
contains of a long incident: one settled contain is followed there by
nothing until the next contain or release that changes something. A view,
the sweeper and the check before a contain need both ranges and read them
as one list (``History``). A history written before there were two ranges
holds everything in the first, and is read the same way.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from portal_api import sweeps
from portal_api.mappers.common import parse_instant
from portal_api.models.portal import AuditEvent
from portal_api.reviews import KIND_APPROVAL, KIND_REVIEW, Attestation, approval_reason, parse_date

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
    "sweeps_scheduled_numbers",
    "sweep",
    "sessions_not_active",
    "duration_ms",
    "detail",
)


# The sort keys of events begin with one of these. In a record's history every event is under the
# first. In a Runtime's containment history the first holds the events that can change who holds
# the containment and the second holds every other event (see the module text).
EVENT_PREFIX = "EVENT#"
OTHER_PREFIX = "OTHER#"


def event_sort_key(event: AuditEvent, prefix: str = EVENT_PREFIX) -> str:
    """The sort key of one event: its range, its time, its id. Events of one range sort by time."""
    return f"{prefix}{event.at}#{event.event_id}"


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


def once_sort_key(state: str, subject: str, action: str, rule: str) -> str:
    """The sort key of the item that says: this is on record, for this person and this state of the record.

    A refusal of someone who has a part in a record is written into the
    record's history once for each person, rule and state of the record
    (its status and the document it holds), and so is an answer that
    nothing was changed. The item under this key is what makes that "once"
    hold: it is written with the condition that it does not exist, before
    the event, so that repeating a request adds nothing however often and
    however fast it is repeated. It lies in the record's own partition and
    is not an event: no read of a history returns it. The four parts are
    hashed, so that none of them can run into another.
    """
    digest = hashlib.sha256("\x1f".join((state, subject, action, rule)).encode()).hexdigest()
    return f"ONCE#{digest}"


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


# One partition holds the latest review attestation of every record, so the read API gets the
# review date of every agent with one query instead of one per agent. It holds one item for a
# record, whatever number of attestations the record has had: the item is replaced by a newer
# attestation of the same record and by nothing else (``audit_writer.put_attestation``). So the
# partition grows with the number of records, not with the number of approvals and reviews. The
# attestations themselves, every one of them, are in the record's own history, as the result
# event that names each (``attestations_in``), and that history is append-only like every other.
REVIEWS_KEY = "REVIEWS"
LATEST_ATTESTATION_PREFIX = "RECORD#"
# Attestations that were written before there was one item for a record lie under
# ``EVENT#<UTC timestamp>#<record id>``, one item each. Nothing writes these any more. They are
# still read, so that a table that holds them keeps its review dates: the latest attestation of
# a record wins, whichever of the two it is.
EARLIER_ATTESTATION_PREFIX = "EVENT#"
# Each page is at most 1 MB; this bounds each of the two reads.
MAX_ATTESTATION_PAGES = 20


def latest_attestation_sort_key(record_id: str) -> str:
    """The sort key of the one item that holds a record's latest attestation."""
    return f"{LATEST_ATTESTATION_PREFIX}{record_id}"


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

    ``events`` must be events of the range that can settle it (``EVENT#``)
    and no others. An event of the other range says nothing about who holds
    the containment, and an intent there whose result was lost must not be
    taken for a contain or a release that happened.
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
    prefix: str = EVENT_PREFIX,
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
    prefix: str = EVENT_PREFIX,
) -> Trail:
    """Read one history back from its newest event, a page at a time, and stop as soon as possible.

    The read stops when ``enough(events so far)`` is true, when the history
    ends, or when ``max_events`` have been read, whichever comes first. It is
    the only way this module reads a history, so no read is without a bound.
    ``oldest_first`` reads forward from the oldest event instead. ``prefix``
    names the range that is read: one request reads one range.
    """
    items: list[dict[str, Any]] = []
    events: list[AuditEvent] = []
    for page in _pages(client, table, partition_key, page_size=page_size, oldest_first=oldest_first, prefix=prefix):
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
    """The events that can settle who holds a Runtime's containment, read back to the one that does.

    Only the range that holds those events is read, so the read does not
    grow with the sweeps and repeated contains recorded since the Runtime
    was contained. ``at_least`` asks for more than that many events when
    the range has them (a view shows the newest ones). The answer is
    settled when the holder says ``decided`` or the trail says ``ended``. If
    neither is true, ``MAX_DECISION_EVENTS`` were read without finding the
    event: the caller must not treat the holder as known.
    """

    def enough(events: list[AuditEvent]) -> bool:
        return len(events) > at_least and holder(events).decided

    trail = read_back(client, table, containment_key(runtime_arn), enough, page_size=max(PAGE_SIZE, at_least + 1))
    return trail, holder(trail.events)


@dataclass(frozen=True)
class History:
    """A Runtime's containment history as far as it was read: both of its ranges as one list."""

    events: list[AuditEvent]  # newest first
    # Who holds the containment, decided on the events that can settle it and on no others.
    # ``current`` counts in ``events``: everything up to and including the event that settled it.
    holder: Holder
    # The holder is settled: an event decided it, or the events that can were read to their end.
    settled: bool
    # The events since the containment began are not all here: a bound of the read was reached.
    cut: bool = False


def _newest_first(*groups: list[AuditEvent]) -> list[AuditEvent]:
    """Events of both ranges as one list, in the order each range has on its own: by time, then by id."""
    return sorted((event for group in groups for event in group), key=lambda e: (e.at, e.event_id), reverse=True)


def _history(settling: Trail, other: Trail, cut: bool = False) -> History:
    """Both ranges as one history. The holder comes from the first alone (``holder``)."""
    found = holder(settling.events)
    events = _newest_first(settling.events, other.events)
    current = len(events)
    if found.decided:
        settled_by = settling.events[found.current - 1]
        current = next(index for index, event in enumerate(events) if event is settled_by) + 1
    return History(events, Holder(found.event, found.decided, current), found.decided or settling.ended, cut)


def _older_than(events: list[AuditEvent], at: str | None) -> bool:
    """Whether the oldest of these events (the last: they are newest first) is older than ``at``."""
    return at is not None and bool(events) and events[-1].at < at


def read_history(client: Any, table: str, runtime_arn: str, *, at_least: int = 0) -> History:
    """A Runtime's containment history for a view: who holds it, and the events since.

    The events that can settle the holder are read back to the one that
    does (``read_holder``). The other events are read back to the time of
    that event: the sweeps and repeated contains of the containment that
    holds are all newer. ``at_least`` asks for more than that many events of
    each range when it has them, so that the newest ``at_least`` of the two
    together are among them. Each read stops at ``MAX_DECISION_EVENTS``;
    ``cut`` says when that left out events of the containment that holds.
    """
    key = containment_key(runtime_arn)
    settling, found = read_holder(client, table, runtime_arn, at_least=at_least)
    began = settling.events[found.current - 1].at if found.decided else None

    def enough(events: list[AuditEvent]) -> bool:
        return len(events) > at_least and _older_than(events, began)

    other = read_back(client, table, key, enough, page_size=max(PAGE_SIZE, at_least + 1), prefix=OTHER_PREFIX)
    return _history(settling, other, cut=not other.ended and not _older_than(other.events, began))


def read_newest(client: Any, table: str, runtime_arn: str) -> History:
    """The newest events of a Runtime's containment history: one request for each range, and no more.

    For the check before a contain, which must never wait for a history
    however long it is. ``settled`` says whether those events were enough to
    tell who holds the containment.
    """
    key = containment_key(runtime_arn)
    settling = read_back(client, table, key, max_events=PAGE_SIZE)
    other = read_back(client, table, key, max_events=PAGE_SIZE, prefix=OTHER_PREFIX)
    return _history(settling, other)


def read_for_sweep(client: Any, table: str, runtime_arn: str, request_id: str) -> History:
    """A Runtime's containment history, read back to the intent of the contain with this request id.

    The sweeper decides on it whether a sweep message belongs to a contain
    that is on record, whether that sweep has already left its event, and
    whether the contain is part of the containment that holds. Everything
    that carries the contain's request id is newer than its intent, so each
    range is read back to there: the contain is in one of them (the first
    when it wrote the statement, the second when the Runtime was already
    contained), and its sweeps are in the second. A contain that is not
    among the newest ``MAX_DECISION_EVENTS`` events of either range is not
    found, and no sweep is run for it. ``cut`` says that the contain was
    found and the events since were not all read: whether one of its sweeps
    has left its event is then not known.
    """
    key = containment_key(runtime_arn)

    def named(events: list[AuditEvent]) -> bool:
        return sweeps.intent_read(events, request_id)

    settling = read_back(client, table, key, named)
    began = next(
        (e.at for e in settling.events if e.action == "contain" and e.phase == "intent" and e.request_id == request_id),
        None,
    )

    def reached(events: list[AuditEvent]) -> bool:
        return named(events) or _older_than(events, began)

    other = read_back(client, table, key, reached, prefix=OTHER_PREFIX)
    return _history(settling, other, cut=not other.ended and not reached(other.events))


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
    """The review attestations the inventory needs, and whether a read stopped before the end.

    Two reads of the one partition. The first returns the latest attestation
    of every record, one item each, so its size follows the number of
    records. The second returns the attestations written before there was
    one item for a record, newest first; nothing adds to those any more.
    Each read is bounded to ``max_pages`` pages. The caller takes the latest
    of a record from all that was found (``reviews.by_record``).
    """
    found: list[Attestation] = []
    truncated = False
    for prefix in (LATEST_ATTESTATION_PREFIX, EARLIER_ATTESTATION_PREFIX):
        read = 0
        for page in _pages(client, table, REVIEWS_KEY, prefix=prefix):
            read += 1
            for item in page.get("Items") or []:
                attestation = attestation_from_item(item)
                if attestation is not None:
                    found.append(attestation)
            if read >= max_pages:
                truncated = truncated or bool(page.get("LastEvaluatedKey"))
                break
    return found, truncated


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


def attestations_in(events: list[AuditEvent]) -> list[Attestation]:
    """Every completed attestation among a record's own events, the latest first.

    This is where the history of a record's attestations is kept. A review
    counts, and so does an approval that recorded a review date (its result
    event then names the attestation in ``attested_at``). Only a ``result``
    event that says ``allowed`` counts. An intent with no result does not:
    showing a registration as not yet reviewed is the safe side of a gap in
    the trail.

    The latest is the one that was attested last (``attested_at``), which is
    the one the ``REVIEWS`` partition holds for the record: two attestations
    made at nearly the same moment can leave their result events in the
    other order.
    """
    found: list[Attestation] = []
    for event in events:
        kind = _ATTESTING_ACTIONS.get(event.action)
        if kind is None or event.phase != "result" or event.outcome != "allowed":
            continue
        if kind == KIND_APPROVAL and not event.attested_at:
            continue  # the attestation of this approval was not written
        if event.record_id and parse_date(event.next_review_by) is not None:
            found.append(
                Attestation(
                    record_id=event.record_id,
                    # The attestation's own time, so every view shows the same instant for one review.
                    at=event.attested_at or event.at,
                    next_review_by=str(event.next_review_by),
                    reviewed_by=event.actor_subject,
                    reviewed_by_label=event.actor_label,
                    reviewed_by_role=event.actor_role,
                    # As the stored attestation says it (``approver_flow``).
                    reason=approval_reason(event.reason) if kind == KIND_APPROVAL else event.reason,
                    request_id=event.request_id,
                    kind=kind,
                )
            )
    # Stable, so that of two with the same time the one whose event is newer comes first.
    return sorted(found, key=lambda attestation: attestation.at, reverse=True)


def last_review(events: list[AuditEvent]) -> Attestation | None:
    """The record's latest completed attestation, from its own events (``attestations_in``)."""
    found = attestations_in(events)
    return found[0] if found else None


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
