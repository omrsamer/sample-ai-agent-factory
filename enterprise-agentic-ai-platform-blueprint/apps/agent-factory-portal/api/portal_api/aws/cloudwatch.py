# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon CloudWatch alarm and metric reads (cell accounts, reader role)."""

from __future__ import annotations

import datetime as dt
from typing import Any

from portal_api.aws.logs import safe_runtime_arn
from portal_api.aws.session import paginate

NAMESPACE = "AWS/Bedrock-AgentCore"
_ALARM_TYPES = ["MetricAlarm", "CompositeAlarm"]

# name -> (metric, statistic)
RUNTIME_METRICS: dict[str, tuple[str, str]] = {
    "invocations": ("Invocations", "Sum"),
    "system_errors": ("SystemErrors", "Sum"),
    "user_errors": ("UserErrors", "Sum"),
    "throttles": ("Throttles", "Sum"),
    "latency": ("Latency", "Average"),
}


def describe_alarms(client: Any, name_prefix: str) -> list[dict[str, Any]]:
    """Metric and composite alarms whose name starts with ``name_prefix``."""
    alarms: list[dict[str, Any]] = []
    paginator = client.get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNamePrefix=name_prefix, AlarmTypes=_ALARM_TYPES):
        alarms.extend(page.get("MetricAlarms") or [])
        alarms.extend(page.get("CompositeAlarms") or [])
    return alarms


def entered_alarm_since(client: Any, alarm_name: str, since: dt.datetime, until: dt.datetime) -> bool:
    """True when the alarm's state history shows a transition to ALARM in the window."""
    items = paginate(
        client,
        "describe_alarm_history",
        "AlarmHistoryItems",
        AlarmName=alarm_name,
        AlarmTypes=_ALARM_TYPES,
        HistoryItemType="StateUpdate",
        StartDate=since,
        EndDate=until,
    )
    return any(str(item.get("HistorySummary", "")).rstrip().endswith("to ALARM") for item in items)


def runtime_metric_queries(runtime_arn: str, query_prefix: str, period_seconds: int) -> list[dict[str, Any]]:
    """GetMetricData queries for one runtime.

    A SEARCH expression is used so every endpoint of the runtime is included
    without knowing its name. The ARN is validated before it is interpolated.
    """
    arn = safe_runtime_arn(runtime_arn)
    queries = []
    for key, (metric, stat) in RUNTIME_METRICS.items():
        expression = (
            f"SEARCH('{{{NAMESPACE},Resource,Operation,Name}} "
            f'Resource="{arn}" MetricName="{metric}"\', \'{stat}\', {int(period_seconds)})'
        )
        queries.append({"Id": f"{query_prefix}_{key}", "Expression": expression, "ReturnData": True})
    return queries


def get_metric_data(
    client: Any, queries: list[dict[str, Any]], start: dt.datetime, end: dt.datetime
) -> dict[str, dict[str, float]]:
    """Run the queries and return ``{query id: {ISO date: value}}``.

    A SEARCH can return several series under one id (one per endpoint); their
    values are summed per day, which is exact for counts and an approximation
    for averages.
    """
    series: dict[str, dict[str, float]] = {}
    counts: dict[str, dict[str, int]] = {}
    # GetMetricData accepts at most 500 queries per request.
    for offset in range(0, len(queries), 500):
        paginator = client.get_paginator("get_metric_data")
        for page in paginator.paginate(
            MetricDataQueries=queries[offset : offset + 500], StartTime=start, EndTime=end, ScanBy="TimestampAscending"
        ):
            for result in page.get("MetricDataResults") or []:
                bucket = series.setdefault(result["Id"], {})
                seen = counts.setdefault(result["Id"], {})
                for timestamp, value in zip(result.get("Timestamps") or [], result.get("Values") or [], strict=False):
                    day = timestamp.date().isoformat()
                    bucket[day] = bucket.get(day, 0.0) + float(value)
                    seen[day] = seen.get(day, 0) + 1
    for query_id, bucket in series.items():
        if query_id.endswith("_latency"):
            for day in bucket:
                bucket[day] = bucket[day] / max(counts[query_id][day], 1)
    return series


def runtime_activity(client: Any, runtime_arns: list[str], days: int) -> dict[str, str | None]:
    """For each Runtime, the last day (ISO date) it was invoked in the window, or ``None`` if it was not.

    One GetMetricData request covers up to 500 Runtimes, so this is one call per
    cell account, not one per agent. A Runtime missing from the result could not be read.
    """
    end = dt.datetime.now(dt.UTC)
    start = (end - dt.timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    queries = []
    for index, arn in enumerate(runtime_arns):
        expression = (
            f"SEARCH('{{{NAMESPACE},Resource,Operation,Name}} "
            f'Resource="{safe_runtime_arn(arn)}" MetricName="Invocations"\', \'Sum\', 86400)'
        )
        queries.append({"Id": f"a{index}_invocations", "Expression": expression, "ReturnData": True})
    series = get_metric_data(client, queries, start, end) if queries else {}
    activity: dict[str, str | None] = {}
    for index, arn in enumerate(runtime_arns):
        invoked = [day for day, value in (series.get(f"a{index}_invocations") or {}).items() if value > 0]
        activity[arn] = max(invoked) if invoked else None
    return activity
