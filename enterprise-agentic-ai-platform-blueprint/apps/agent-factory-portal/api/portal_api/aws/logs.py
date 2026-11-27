# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon CloudWatch Logs Insights over the ``aws/spans`` log group of a cell account.

Query text is assembled from fixed templates. The only values ever interpolated
are a runtime ARN and an integer limit, and both pass an allow-list guard first;
free text from a request never reaches a query.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import Any

from portal_api.aws.session import error_code

logger = logging.getLogger(__name__)

SPANS_LOG_GROUP = "aws/spans"
_RUNTIME_ARN = re.compile(
    r"^arn:aws[a-z-]{0,10}:bedrock-agentcore:[a-z0-9-]{1,30}:\d{12}:runtime/[A-Za-z0-9_-]{1,100}$"
)
_TERMINAL = {"Complete", "Failed", "Cancelled", "Timeout", "Unknown"}

MAX_TRACE_ROWS = 200


class UnsafeQueryValue(ValueError):
    """A value was rejected before it could be placed in a query."""


def safe_runtime_arn(value: Any) -> str:
    """Return ``value`` only if it is exactly an AgentCore runtime ARN."""
    if not isinstance(value, str) or not _RUNTIME_ARN.fullmatch(value):
        raise UnsafeQueryValue("runtime ARN contains characters that are not allowed in a query")
    return value


def safe_limit(value: Any, maximum: int = MAX_TRACE_ROWS) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise UnsafeQueryValue("limit is out of range")
    return value


def _runtime_filter(runtime_arn: str) -> str:
    # Spans carry "<runtime ARN>/runtime-endpoint/<name>" in the resource attributes.
    return f'filter resource.attributes.cloud.resource_id like "{safe_runtime_arn(runtime_arn)}/"'


def traces_query(runtime_arn: str, limit: int) -> str:
    """One row per trace of the runtime, anchored on its server (root) span."""
    return (
        f"{_runtime_filter(runtime_arn)}"
        ' | filter kind = "SERVER" or ispresent(attributes.gen_ai.usage.total_tokens)'
        " | stats min(startTimeUnixNano) as start_ns, max(durationNano) as duration_ns,"
        " max(attributes.gen_ai.usage.input_tokens) as input_tokens,"
        " max(attributes.gen_ai.usage.output_tokens) as output_tokens,"
        " max(attributes.gen_ai.usage.total_tokens) as total_tokens,"
        " max(attributes.http.response.status_code) as http_status,"
        " latest(attributes.user.id) as user_id,"
        " latest(attributes.session.id) as session_id,"
        ' sum(status.code = "ERROR") as error_spans'
        " by traceId"
        " | sort start_ns desc"
        f" | limit {safe_limit(limit)}"
    )


def tokens_by_day_query(runtime_arn: str) -> str:
    return (
        f"{_runtime_filter(runtime_arn)}"
        " | filter name like /^invoke_agent/"
        " | stats sum(attributes.gen_ai.usage.total_tokens) as tokens, count_distinct(traceId) as traces"
        " by datefloor(@timestamp, 1d) as day"
    )


def tokens_by_model_query(runtime_arn: str) -> str:
    return (
        f"{_runtime_filter(runtime_arn)}"
        ' | filter attributes.aws.genai.span_kind = "LLM" or name like /^chat /'
        " | stats sum(attributes.gen_ai.usage.input_tokens) as input_tokens,"
        " sum(attributes.gen_ai.usage.output_tokens) as output_tokens"
        " by attributes.gen_ai.request.model as model"
    )


def traces_by_user_query(runtime_arn: str) -> str:
    return (
        f"{_runtime_filter(runtime_arn)}"
        " | filter name like /^invoke_agent/"
        " | stats count_distinct(traceId) as traces by attributes.user.id as user_id"
    )


# No interpolation at all: one row per runtime endpoint in the account.
TOKENS_BY_RUNTIME_QUERY = (
    "filter name like /^invoke_agent/"
    " | stats sum(attributes.gen_ai.usage.total_tokens) as tokens, count_distinct(traceId) as traces"
    " by resource.attributes.cloud.resource_id as resource_id"
)


def run_queries(
    client: Any,
    queries: dict[str, str],
    start_epoch: int,
    end_epoch: int,
    *,
    max_wait_seconds: float = 12.0,
    poll_seconds: float = 0.4,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, list[dict[str, str]]], list[str]]:
    """Start every query, then poll them all against one shared deadline.

    Returns ``(rows by query name, warnings)``. A query that fails, cannot start
    or is still running at the deadline yields whatever rows it has (possibly
    none) and a warning, so the caller answers instead of timing out.
    """
    results: dict[str, list[dict[str, str]]] = {name: [] for name in queries}
    warnings: list[str] = []
    pending: dict[str, str] = {}
    for name, text in queries.items():
        try:
            started = client.start_query(
                logGroupName=SPANS_LOG_GROUP, startTime=start_epoch, endTime=end_epoch, queryString=text
            )
            pending[name] = started["queryId"]
        except Exception as exc:  # noqa: BLE001 - reported as a warning
            logger.warning("Logs Insights query %s could not start: %s", name, error_code(exc))
            warnings.append(f"{name}: query could not start ({error_code(exc)})")

    deadline = clock() + max_wait_seconds
    while pending:
        for name, query_id in list(pending.items()):
            try:
                response = client.get_query_results(queryId=query_id)
            except Exception as exc:  # noqa: BLE001 - reported as a warning
                logger.warning("Logs Insights query %s could not be read: %s", name, error_code(exc))
                warnings.append(f"{name}: results could not be read ({error_code(exc)})")
                del pending[name]
                continue
            status = response.get("status")
            results[name] = [_row(r) for r in response.get("results") or []]
            if status in _TERMINAL:
                del pending[name]
                if status != "Complete":
                    warnings.append(f"{name}: query ended with status {status}")
        if not pending:
            break
        if clock() >= deadline:
            for name in pending:
                warnings.append(f"{name}: query still running after {max_wait_seconds:g}s; partial result returned")
            break
        sleep(poll_seconds)
    return results, warnings


def _row(fields: list[dict[str, str]]) -> dict[str, str]:
    return {f["field"]: f["value"] for f in fields if f.get("field") != "@ptr"}
