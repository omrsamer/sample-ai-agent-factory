# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Traces and metrics from Amazon CloudWatch as the console's observability shapes."""

from __future__ import annotations

import datetime as dt

from portal_api.mappers.common import iso, to_int
from portal_api.models.wire import (
    AgentMetrics,
    DailyMetric,
    MetricTotals,
    ModelMetric,
    RuntimeMetrics,
    TraceRow,
    UserMetric,
)


def trace_row(row: dict[str, str]) -> TraceRow | None:
    """One Logs Insights result row (one trace) to a trace row."""
    trace_id = row.get("traceId")
    if not trace_id:
        return None
    start_ns = to_int(row.get("start_ns"))
    duration_ns = to_int(row.get("duration_ns"))
    http_status = to_int(row.get("http_status"))
    errors = to_int(row.get("error_spans")) or 0
    if errors > 0 or (http_status is not None and http_status >= 500):
        status = "error"
    elif http_status is not None and http_status >= 400:
        status = "client_error"
    else:
        status = "ok"
    return TraceRow(
        id=trace_id,
        timestamp=iso(dt.datetime.fromtimestamp(start_ns / 1e9, tz=dt.UTC)) if start_ns else None,
        user_id=row.get("user_id") or None,
        latency_ms=round(duration_ns / 1e6, 1) if duration_ns is not None else None,
        status=status,
        session_id=row.get("session_id") or None,
        input_tokens=to_int(row.get("input_tokens")),
        output_tokens=to_int(row.get("output_tokens")),
        total_tokens=to_int(row.get("total_tokens")),
    )


def _days(start: dt.datetime, end: dt.datetime) -> list[str]:
    # A window that ends exactly at midnight does not include the day that starts there.
    last = (end - dt.timedelta(microseconds=1)).date()
    days = []
    day = start.date()
    while day <= last:
        days.append(day.isoformat())
        day += dt.timedelta(days=1)
    return days


def agent_metrics(
    series: dict[str, dict[str, float]],
    query_prefix: str,
    start: dt.datetime,
    end: dt.datetime,
    token_days: list[dict[str, str]] | None = None,
    token_models: list[dict[str, str]] | None = None,
    user_rows: list[dict[str, str]] | None = None,
    warnings: list[str] | None = None,
) -> AgentMetrics:
    """Combine CloudWatch runtime metrics with token usage read from spans.

    ``traces`` is the runtime invocation count. Cost is not available from
    CloudWatch, so every ``cost_usd`` is 0 and ``cost_available`` is false.
    """

    def metric(name: str) -> dict[str, float]:
        return series.get(f"{query_prefix}_{name}") or {}

    invocations, system_errors, user_errors = metric("invocations"), metric("system_errors"), metric("user_errors")
    throttles, latency = metric("throttles"), metric("latency")

    tokens_by_day: dict[str, int] = {}
    for row in token_days or []:
        day = (row.get("day") or "")[:10]
        if day:
            tokens_by_day[day] = tokens_by_day.get(day, 0) + (to_int(row.get("tokens")) or 0)

    daily = [
        DailyMetric(
            date=day,
            traces=int(invocations.get(day, 0)),
            tokens=tokens_by_day.get(day, 0),
            errors=int(system_errors.get(day, 0) + user_errors.get(day, 0)),
        )
        for day in _days(start, end)
    ]
    by_model = [
        ModelMetric(
            model=row.get("model") or "unknown",
            tokens=(to_int(row.get("input_tokens")) or 0) + (to_int(row.get("output_tokens")) or 0),
        )
        for row in token_models or []
    ]
    by_user = [
        UserMetric(user_id=row.get("user_id") or "", traces=to_int(row.get("traces")) or 0) for row in user_rows or []
    ]
    weighted = sum(latency.get(day, 0.0) * invocations.get(day, 0.0) for day in latency)
    weight = sum(invocations.get(day, 0.0) for day in latency)
    return AgentMetrics(
        totals=MetricTotals(traces=int(sum(invocations.values())), tokens=sum(tokens_by_day.values())),
        daily=daily,
        by_model=sorted(by_model, key=lambda m: m.tokens, reverse=True),
        by_user=sorted(by_user, key=lambda u: u.traces, reverse=True),
        runtime=RuntimeMetrics(
            invocations=int(sum(invocations.values())),
            system_errors=int(sum(system_errors.values())),
            user_errors=int(sum(user_errors.values())),
            throttles=int(sum(throttles.values())),
            latency_avg_ms=round(weighted / weight, 1) if weight else None,
        ),
        warnings=list(warnings or []),
    )
