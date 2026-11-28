# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS calls of the containment function.

Everything in the cell is done with the cell's containment role: reading,
writing and deleting the Runtime's resource policy, finding the Runtime's
recent sessions (in its spans and in the names of its session log streams),
and stopping them. The role cannot read a log event or invoke the Runtime. The function's own role is
used only to read one registry record (to resolve a registered agent) and for
the audit table.
"""

from __future__ import annotations

import datetime as dt
import itertools
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from portal_api.aws import logs
from portal_api.aws.parallel import pmap
from portal_api.aws.session import error_code

logger = logging.getLogger(__name__)

# A Runtime session id is at least 33 characters. Anything else in the spans is not one.
_SESSION_ID = re.compile(r"^[A-Za-z0-9._:\-]{33,256}$")
STOP_BUDGET_SECONDS = 12.0
_BATCH = 16
_ENDPOINT = re.compile(r"^[A-Za-z0-9_\-]{1,100}$")
MAX_ENDPOINTS = 10
STREAM_PREFIX = "runtime-logs-"
STREAM_PAGE_LIMIT = 50
MAX_STREAM_PAGES = 20
SPANS_WAIT_SECONDS = 8.0
_QUALIFIER = re.compile(r"/runtime-endpoint/([A-Za-z0-9_\-]{1,100})")


def get_record(client: Any, registry_id: str, record_id: str) -> dict[str, Any]:
    record = client.get_registry_record(registryId=registry_id, recordId=record_id)
    record.pop("ResponseMetadata", None)
    return record


# The tag the cell's pipeline puts on a Runtime to say which tenant it belongs to.
TENANT_TAG = "tenant-id"


def get_tenant_tag(client: Any, runtime_arn: str) -> str | None:
    """The Runtime's own ``tenant-id`` tag, or ``None`` when it has none. Read with the cell's containment role."""
    tags = client.list_tags_for_resource(resourceArn=runtime_arn).get("tags") or {}
    value = tags.get(TENANT_TAG)
    return value if isinstance(value, str) and value else None


def get_policy(client: Any, runtime_arn: str) -> str | None:
    """The Runtime's resource policy exactly as stored, or ``None`` when it has none."""
    try:
        return client.get_resource_policy(resourceArn=runtime_arn).get("policy") or None
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            return None
        raise


def put_policy(client: Any, runtime_arn: str, policy: str) -> None:
    client.put_resource_policy(resourceArn=runtime_arn, policy=policy)


# Error codes with which the service says "too many requests". The SDK retries them; when it gives
# up, the request may still have been applied.
THROTTLING_CODES = frozenset(
    {
        "ThrottlingException",
        "Throttling",
        "ThrottledException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "RequestThrottledException",
        "SlowDown",
        "ServiceQuotaExceededException",
    }
)


def may_have_been_applied(exc: BaseException) -> bool:
    """Whether a write that failed this way may have taken effect all the same.

    A refusal (a 4xx that is not throttling) changed nothing. Anything else
    leaves it open: a server error, throttling after the SDK's retries, and
    every failure with no answer from the service at all (a timeout, a
    connection that broke).
    """
    if not isinstance(exc, ClientError):
        return True
    if error_code(exc) in THROTTLING_CODES:
        return True
    status = (exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    return not isinstance(status, int) or status >= 500


def delete_policy(client: Any, runtime_arn: str) -> None:
    """Delete the Runtime's resource policy. A policy that is already gone is fine."""
    try:
        client.delete_resource_policy(resourceArn=runtime_arn)
    except ClientError as exc:
        if error_code(exc) != "ResourceNotFoundException":
            raise


@dataclass
class Session:
    session_id: str
    qualifier: str = "DEFAULT"
    last_seen: float = 0.0  # epoch seconds; orders the sessions, most recent first


@dataclass
class SessionStop:
    discovery: str = "ok"
    found: int = 0
    stopped: int = 0
    not_active: int = 0
    failed: int = 0
    not_attempted: int = 0  # the time budget ran out first
    failures: list[str] = field(default_factory=list)  # error codes only


class Found(list):  # type: ignore[type-arg]
    """Sessions from one source. ``truncated`` is true when the source held more than was read."""

    truncated: bool = False
    # Why the source was not read to its end, in words; ``None`` when it was.
    cut: str | None = None
    # The spans query did not end as complete, so its rows may be only a part of the sessions.
    unfinished: bool = False


def limit_note() -> str:
    """Said whenever a limit cut the list: a result must never read as complete when it is not."""
    return f"the limit of {logs.MAX_SESSIONS} sessions per action was reached, so more sessions may be running"


@dataclass
class Discovery:
    """The Runtime's recent sessions and how they were found."""

    sessions: list[Session]
    # "ok", "ok; <what was incomplete>", or "sessions could not be listed (<why>)" when both sources failed.
    note: str
    sources: dict[str, int]  # sessions per source, before de-duplication
    failed: bool = False


class SourceFailed(Exception):
    """One source of session ids could not be read. The message is a short, safe reason."""


def sessions_from_spans(
    client: Any,
    runtime_arn: str,
    start: dt.datetime,
    end: dt.datetime,
    *,
    limit: int = logs.MAX_SESSIONS,
    max_wait_seconds: float | None = None,
) -> list[Session]:
    """Session ids in the Runtime's spans. Only a Runtime that emits spans with a session id has any.

    A query that is still running at the deadline, or that ended in any state
    but complete, can return part of its rows. They are used, and ``unfinished``
    says that they may not be all.
    """
    results, warnings = logs.run_queries(
        client,
        {"sessions": logs.sessions_query(runtime_arn, limit)},
        int(start.timestamp()),
        int(end.timestamp()),
        max_wait_seconds=SPANS_WAIT_SECONDS if max_wait_seconds is None else max_wait_seconds,
    )
    if warnings and not results["sessions"]:
        raise SourceFailed(warnings[0].split(": ", 1)[-1])
    sessions = Found()
    # The query returns at most ``limit`` rows: a full result means there may be more.
    sessions.truncated = len(results["sessions"]) >= limit
    if warnings:
        # The query did not end as complete, so its rows may be only a part.
        why = warnings[0].split(": ", 1)[-1].split(";", 1)[0]
        sessions.unfinished = True
        sessions.cut = f"the spans query did not finish ({why})"
    elif sessions.truncated:
        sessions.cut = f"the spans query returned as many sessions as it may ({limit})"
    for row in results["sessions"]:
        session_id = row.get("session_id") or ""
        if not _SESSION_ID.fullmatch(session_id):
            continue
        qualifier = _QUALIFIER.search(row.get("resource_id") or "")
        sessions.append(
            Session(session_id, qualifier.group(1) if qualifier else "DEFAULT", _epoch(row.get("last_seen")))
        )
    return sessions


def _epoch(value: Any) -> float:
    """A Logs Insights timestamp ("2026-01-15 12:00:00.000", UTC) as epoch seconds; 0 when it cannot be read."""
    try:
        parsed = dt.datetime.fromisoformat(str(value).strip().replace(" ", "T"))
    except ValueError:
        return 0.0
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)).timestamp()


def list_endpoints(client: Any, runtime_id: str) -> tuple[list[str], str | None]:
    """The Runtime's endpoint names, at most ten. Falls back to DEFAULT, with a note, when they cannot be listed."""
    try:
        paginator = client.get_paginator("list_agent_runtime_endpoints")
        pages = paginator.paginate(agentRuntimeId=runtime_id, PaginationConfig={"MaxItems": MAX_ENDPOINTS})
        names = [str(e.get("name")) for page in pages for e in page.get("runtimeEndpoints") or []]
    except Exception as exc:  # noqa: BLE001 - DEFAULT always exists, so discovery can still proceed
        logger.warning("Runtime endpoints could not be listed: %s", error_code(exc))
        return ["DEFAULT"], f"endpoints could not be listed ({error_code(exc)}), only DEFAULT was checked"
    names = [name for name in dict.fromkeys(names) if _ENDPOINT.fullmatch(name)][:MAX_ENDPOINTS]
    return names or ["DEFAULT"], None


def sessions_from_log_streams(
    client: Any,
    runtime_id: str,
    endpoints: list[str],
    since: dt.datetime,
    *,
    max_pages: int | None = MAX_STREAM_PAGES,
    keep_going: Callable[[], bool] | None = None,
) -> list[Session]:
    """Session ids from the names of the Runtime's session log streams.

    The service writes each session's output to a stream named
    ``runtime-logs-<session id>`` in the log group of the endpoint it ran on.
    This needs no instrumentation in the agent, and reads stream names only,
    never a log event. A Runtime that writes nothing has no such stream.

    Inside a request at most ``max_pages`` pages are read per endpoint. A
    background sweep passes ``None`` and reads every page of the lookback
    window, for as long as ``keep_going`` says there is time. Whatever stops
    a sweep before the end, it keeps the sessions it has read, and ``cut``
    says why the list is not whole.
    """
    since_ms = int(since.timestamp() * 1000)
    sessions = Found()
    for endpoint in endpoints:
        group = f"/aws/bedrock-agentcore/runtimes/{runtime_id}-{endpoint}"
        token: str | None = None
        for _ in itertools.count() if max_pages is None else range(max_pages):
            if keep_going is not None and not keep_going():
                # Out of time with pages still to read.
                sessions.truncated = True
                sessions.cut = "not every session could be listed in the time the sweep had"
                return sessions
            kwargs: dict[str, Any] = {
                "logGroupName": group,
                "orderBy": "LastEventTime",
                "descending": True,
                "limit": STREAM_PAGE_LIMIT,
            }
            if token:
                kwargs["nextToken"] = token
            try:
                page = client.describe_log_streams(**kwargs)
            except ClientError as exc:
                if error_code(exc) == "ResourceNotFoundException":
                    break  # the endpoint has no log group: it has had no session that wrote anything
                if max_pages is None and sessions:
                    # A sweep stops what it has listed so far instead of nothing.
                    sessions.truncated = True
                    sessions.cut = f"log streams could not be listed to the end ({error_code(exc)})"
                    return sessions
                raise SourceFailed(error_code(exc)) from exc
            any_recent = False
            for stream in page.get("logStreams") or []:
                # lastEventTimestamp is eventually consistent, so the newest of the three times decides.
                seen = max(
                    stream.get("creationTime") or 0,
                    stream.get("lastEventTimestamp") or 0,
                    stream.get("lastIngestionTime") or 0,
                )
                if seen < since_ms:
                    continue
                any_recent = True
                name = str(stream.get("logStreamName") or "")
                session_id = name.removeprefix(STREAM_PREFIX)
                if name.startswith(STREAM_PREFIX) and _SESSION_ID.fullmatch(session_id):
                    sessions.append(Session(session_id, endpoint, seen / 1000))
            token = page.get("nextToken")
            if not any_recent or not token:
                break
        else:
            # Every allowed page was read and the last one still held recent streams and a next page.
            sessions.truncated = True
    return sessions


def discover_sessions(
    control: Any,
    logs_client: Any,
    runtime_arn: str,
    use_spans: bool = False,
    *,
    limit: int | None = logs.MAX_SESSIONS,
    keep_going: Callable[[], bool] | None = None,
    spans_wait_seconds: float | None = None,
) -> Discovery:
    """The Runtime's sessions of the lookback window.

    Inside a request the list is cut at ``limit`` sessions. A background sweep
    passes ``None``: it reads every page of stream names it can in the time it
    has (``keep_going``), asks the spans for as many sessions as one query
    returns, and says what kept either source from being read to its end.

    No API lists a Runtime's sessions. They are found in the names of the
    Runtime's session log streams, which needs no instrumentation in the agent
    and reads no log event. A cell can opt in to a second source, its spans
    (``use_spans``): that finds a session of an instrumented agent that wrote
    no output, at the price of a Logs Insights query permission on the cell's
    containment role, which can read span content. It is off by default.

    With both sources, each is read independently and the results are merged;
    discovery fails only when every source that was asked failed.
    """
    end = dt.datetime.now(dt.UTC)
    start = end - dt.timedelta(hours=logs.SESSION_LOOKBACK_HOURS)
    runtime_id = runtime_arn.rsplit("/", 1)[-1]
    notes: list[str] = []

    def from_spans() -> list[Session]:
        return sessions_from_spans(
            logs_client,
            runtime_arn,
            start,
            end,
            limit=logs.MAX_SESSIONS if limit is not None else logs.MAX_SWEEP_SESSIONS,
            max_wait_seconds=spans_wait_seconds,
        )

    def from_streams() -> list[Session]:
        endpoints, note = list_endpoints(control, runtime_id)
        if note:
            notes.append(note)
        return sessions_from_log_streams(
            logs_client,
            runtime_id,
            endpoints,
            start,
            max_pages=MAX_STREAM_PAGES if limit is not None else None,
            keep_going=keep_going,
        )

    asked = [from_spans, from_streams] if use_spans else [from_streams]
    found = pmap(lambda source: source(), asked, max_workers=len(asked))
    spans: Any = found[0] if use_spans else Found()
    streams: Any = found[-1]
    failures = []
    if isinstance(spans, BaseException):
        failures.append(f"spans could not be queried ({_reason(spans)})")
        spans = []
    if isinstance(streams, BaseException):
        failures.append(f"log streams could not be listed ({_reason(streams)})")
        streams = []
    # A source that was not asked is not reported: "0 in traces" would read as "looked and found none".
    sources = {"spans": len(spans), "log_streams": len(streams)} if use_spans else {"log_streams": len(streams)}
    if len(failures) == len(asked):
        return Discovery([], f"sessions could not be listed ({'; '.join(failures)})", sources, failed=True)

    merged: dict[tuple[str, str], Session] = {}
    for session in [*spans, *streams]:
        key = (session.session_id, session.qualifier)
        if key not in merged or session.last_seen > merged[key].last_seen:
            merged[key] = session
    spans_cut, streams_cut = getattr(spans, "truncated", False), getattr(streams, "truncated", False)
    if limit is not None:
        if spans_cut or streams_cut or len(merged) > limit:
            notes.append(limit_note())
        if getattr(spans, "unfinished", False):
            # Part of a result is not the result: the list must not read as complete.
            notes.append(f"{spans.cut}, so more sessions may be running")
    else:
        # A sweep has no limit of its own: it says what kept a source from being read to its end.
        for source in (streams, spans):
            if getattr(source, "cut", None):
                notes.append(f"{source.cut}, so more sessions may be running")
    ordered = sorted(merged.values(), key=lambda s: s.last_seen, reverse=True)[:limit]
    return Discovery(ordered, "; ".join(["ok", *failures, *notes]), sources)


def _reason(exc: BaseException) -> str:
    return str(exc) if isinstance(exc, SourceFailed) else error_code(exc)


def stop_session(client: Any, runtime_arn: str, session: Session) -> str:
    """Stop one session: ``stopped``, ``not_active`` (unknown or already ended), or the error code."""
    try:
        client.stop_runtime_session(
            runtimeSessionId=session.session_id, agentRuntimeArn=runtime_arn, qualifier=session.qualifier
        )
        return "stopped"
    except ClientError as exc:
        code = error_code(exc)
        return "not_active" if code == "ResourceNotFoundException" else code


def stop_sessions(
    client: Any,
    runtime_arn: str,
    sessions: list[Session],
    *,
    budget_seconds: float = STOP_BUDGET_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> SessionStop:
    """Stop each session, bounded in number and in time.

    A session that is unknown or has already ended needs no stop and is
    counted as not active, not as a failure. Sessions left when the time
    budget runs out are counted as not attempted.
    """
    outcome = SessionStop(found=len(sessions))
    deadline = clock() + budget_seconds

    def stop(session: Session) -> str:
        return stop_session(client, runtime_arn, session)

    for offset in range(0, len(sessions), _BATCH):
        if clock() >= deadline:
            outcome.not_attempted = len(sessions) - offset
            break
        for result in pmap(stop, sessions[offset : offset + _BATCH], max_workers=8):
            if result == "stopped":
                outcome.stopped += 1
            elif result == "not_active":
                outcome.not_active += 1
            else:
                outcome.failed += 1
                code = error_code(result) if isinstance(result, BaseException) else str(result)
                if code not in outcome.failures:
                    outcome.failures.append(code)
    return outcome
