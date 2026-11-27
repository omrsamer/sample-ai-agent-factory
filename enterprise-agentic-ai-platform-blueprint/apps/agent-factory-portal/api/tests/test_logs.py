# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Query-injection guard and the bounded Logs Insights wait."""

from __future__ import annotations

import boto3
import pytest
from botocore.stub import Stubber

from portal_api.aws import cloudwatch, logs
from tests.conftest import RUNTIME_ARN, FakeClient


@pytest.mark.parametrize(
    "value",
    [
        RUNTIME_ARN + '" | fields @message | filter "a" = "a',
        RUNTIME_ARN + '"',
        RUNTIME_ARN + " ",
        RUNTIME_ARN + "\n| delete",
        RUNTIME_ARN + "/runtime-endpoint/DEFAULT",
        RUNTIME_ARN + "'",
        RUNTIME_ARN + "|",
        RUNTIME_ARN + "*",
        "arn:aws:bedrock-agentcore:eu-west-1:444444444444:gateway/gw-1",
        "arn:aws:lambda:eu-west-1:444444444444:function:x",
        "travel_agent-AbCdEf1234",
        "",
        None,
        42,
        ["arn"],
    ],
)
def test_guard_rejects_anything_that_is_not_exactly_a_runtime_arn(value):
    with pytest.raises(logs.UnsafeQueryValue):
        logs.safe_runtime_arn(value)
    for build in (logs.tokens_by_day_query, logs.tokens_by_model_query, logs.traces_by_user_query):
        with pytest.raises(logs.UnsafeQueryValue):
            build(value)
    with pytest.raises(logs.UnsafeQueryValue):
        logs.traces_query(value, 10)
    with pytest.raises(logs.UnsafeQueryValue):
        cloudwatch.runtime_metric_queries(value, "m", 86400)


@pytest.mark.parametrize("limit", [0, -1, 201, "10", "10 | delete", 1.5, True, None])
def test_guard_rejects_bad_limits(limit):
    with pytest.raises(logs.UnsafeQueryValue):
        logs.traces_query(RUNTIME_ARN, limit)


def test_traces_query_interpolates_only_the_validated_arn_and_limit():
    query = logs.traces_query(RUNTIME_ARN, 25)
    assert query.startswith(f'filter resource.attributes.cloud.resource_id like "{RUNTIME_ARN}/"')
    assert query.endswith("| limit 25")
    assert query.count('"') == 6  # the ARN literal, "SERVER" and "ERROR"
    assert "by traceId" in query


def test_metric_search_expression_quotes_the_validated_arn():
    queries = cloudwatch.runtime_metric_queries(RUNTIME_ARN, "m", 86400)
    assert [q["Id"] for q in queries] == [
        "m_invocations",
        "m_system_errors",
        "m_user_errors",
        "m_throttles",
        "m_latency",
    ]
    assert queries[0]["Expression"] == (
        "SEARCH('{AWS/Bedrock-AgentCore,Resource,Operation,Name} "
        f'Resource="{RUNTIME_ARN}" MetricName="Invocations"\', \'Sum\', 86400)'
    )


def _results(status: str, rows: list[dict[str, str]]):
    return {"status": status, "results": [[{"field": k, "value": v} for k, v in row.items()] for row in rows]}


def test_run_queries_with_stubbed_client_completes():
    client = boto3.client("logs", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test")
    with Stubber(client) as stub:
        stub.add_response(
            "start_query",
            {"queryId": "q-1"},
            {"logGroupName": "aws/spans", "startTime": 100, "endTime": 200, "queryString": "fields x"},
        )
        stub.add_response("get_query_results", _results("Running", []), {"queryId": "q-1"})
        stub.add_response(
            "get_query_results", _results("Complete", [{"traceId": "t1", "@ptr": "p"}]), {"queryId": "q-1"}
        )
        results, warnings = logs.run_queries(client, {"traces": "fields x"}, 100, 200, sleep=lambda _: None)
        stub.assert_no_pending_responses()
    assert results == {"traces": [{"traceId": "t1"}]}
    assert warnings == []


def test_run_queries_returns_partial_result_at_the_deadline():
    now = [0.0]
    client = FakeClient(
        {
            "start_query": lambda **kw: {"queryId": "slow" if "slow" in kw["queryString"] else "fast"},
            "get_query_results": lambda queryId: (  # noqa: N803 - mirrors the API parameter
                _results("Running", [{"traceId": "partial"}])
                if queryId == "slow"
                else _results("Complete", [{"a": "1"}])
            ),
        }
    )

    def sleep(seconds: float) -> None:
        now[0] += seconds

    results, warnings = logs.run_queries(
        client,
        {"fast": "fields fast", "slow": "fields slow"},
        1,
        2,
        max_wait_seconds=2.0,
        poll_seconds=0.5,
        sleep=sleep,
        clock=lambda: now[0],
    )
    assert results == {"fast": [{"a": "1"}], "slow": [{"traceId": "partial"}]}
    assert warnings == ["slow: query still running after 2s; partial result returned"]
    assert now[0] <= 2.5


def test_run_queries_reports_failures_as_warnings():
    def boom(**_):
        raise RuntimeError("no network")

    results, warnings = logs.run_queries(FakeClient({"start_query": boom}), {"traces": "fields x"}, 1, 2)
    assert results == {"traces": []}
    assert warnings == ["traces: query could not start (RuntimeError)"]

    failed = FakeClient({"start_query": {"queryId": "q"}, "get_query_results": _results("Failed", [])})
    results, warnings = logs.run_queries(failed, {"traces": "fields x"}, 1, 2)
    assert results == {"traces": []} and warnings == ["traces: query ended with status Failed"]
