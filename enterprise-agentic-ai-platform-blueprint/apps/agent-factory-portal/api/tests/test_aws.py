# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS access modules against botocore Stubber (no network)."""

from __future__ import annotations

import datetime as dt

import boto3
from botocore.stub import Stubber

from portal_api.aws import cloudwatch, guardrails, registry
from portal_api.aws.cache import TTLCache
from portal_api.aws.session import AwsClients, error_code
from portal_api.config import load_settings
from tests.conftest import BASE_ENV, CELL_ACCOUNT, PLATFORM_ACCOUNT, REGION, T0, FakeClient

CREDS = {"aws_access_key_id": "test", "aws_secret_access_key": "test"}


def _client(service: str):
    return boto3.client(service, region_name=REGION, **CREDS)


def test_registry_service_is_available_in_the_pinned_sdk():
    operations = set(_client("agent-registry-control").meta.service_model.operation_names)
    assert {"ListRegistryRecords", "GetRegistryRecord"} <= operations


def test_registry_list_records_paginates_and_fetches_descriptors():
    client = _client("agent-registry-control")
    arn = f"arn:aws:agent-registry:{REGION}:{PLATFORM_ACCOUNT}:registry/REGISTRYID000001"

    def summary(record_id: str) -> dict:
        return {
            "registryArn": arn,
            "recordArn": f"{arn}/record/{record_id}",
            "recordId": record_id,
            "name": record_id,
            "recordType": "CUSTOM",
            "recordVersion": "1.0.0",
            "status": "APPROVED",
            "createdAt": T0,
            "updatedAt": T0,
        }

    with Stubber(client) as stub:
        stub.add_response(
            "list_registry_records",
            {"registryRecords": [summary("recAAAAAAAAA1")], "nextToken": "n" * 40},
            {"registryId": "REGISTRYID000001"},
        )
        stub.add_response(
            "list_registry_records",
            {"registryRecords": [summary("recAAAAAAAAA2")]},
            {"registryId": "REGISTRYID000001", "nextToken": "n" * 40},
        )
        for record_id in ("recAAAAAAAAA1", "recAAAAAAAAA2"):
            stub.add_response(
                "get_registry_record",
                {**summary(record_id), "descriptors": {"custom": {"data": '{"schemaVersion":"s/1"}'}}},
                {"registryId": "REGISTRYID000001", "recordId": record_id},
            )
        # Fetches run on a pool; Stubber is strict about order, so run them in sequence here.
        import portal_api.aws.registry as module

        original = module.pmap
        module.pmap = lambda fn, items, max_workers=8: [fn(i) for i in items]
        try:
            records = registry.list_records(client, "REGISTRYID000001")
        finally:
            module.pmap = original
        stub.assert_no_pending_responses()
    assert [r["recordId"] for r in records] == ["recAAAAAAAAA1", "recAAAAAAAAA2"]
    assert all(r["descriptors"]["custom"]["data"] for r in records)
    assert all("ResponseMetadata" not in r for r in records)


def test_describe_alarms_uses_the_prefix_and_both_alarm_types():
    client = _client("cloudwatch")
    with Stubber(client) as stub:
        stub.add_response(
            "describe_alarms",
            {
                "MetricAlarms": [{"AlarmName": "agenticai-nonprod-ws1-travel-agent-errors", "StateValue": "OK"}],
                "CompositeAlarms": [{"AlarmName": "agenticai-nonprod-ws1-travel-agent-health", "StateValue": "ALARM"}],
            },
            {"AlarmNamePrefix": "agenticai-nonprod-ws1-travel-agent", "AlarmTypes": ["MetricAlarm", "CompositeAlarm"]},
        )
        alarms = cloudwatch.describe_alarms(client, "agenticai-nonprod-ws1-travel-agent")
        stub.assert_no_pending_responses()
    assert [a["StateValue"] for a in alarms] == ["OK", "ALARM"]


def test_entered_alarm_since_reads_state_update_history():
    since, until = T0, T0 + dt.timedelta(hours=24)
    expected = {
        "AlarmName": "a-1",
        "AlarmTypes": ["MetricAlarm", "CompositeAlarm"],
        "HistoryItemType": "StateUpdate",
        "StartDate": since,
        "EndDate": until,
    }
    for summaries, outcome in [
        (["Alarm updated from OK to ALARM", "Alarm updated from ALARM to OK"], True),
        (["Alarm updated from INSUFFICIENT_DATA to OK"], False),
        ([], False),
    ]:
        client = _client("cloudwatch")
        with Stubber(client) as stub:
            stub.add_response(
                "describe_alarm_history",
                {"AlarmHistoryItems": [{"AlarmName": "a-1", "HistorySummary": s} for s in summaries]},
                expected,
            )
            assert cloudwatch.entered_alarm_since(client, "a-1", since, until) is outcome


def test_get_metric_data_sums_series_per_day_and_averages_latency():
    day = dt.datetime(2026, 1, 15, tzinfo=dt.UTC)
    client = FakeClient(
        {
            "get_metric_data": [
                {
                    "MetricDataResults": [
                        {"Id": "m_invocations", "Timestamps": [day], "Values": [3.0]},
                        {"Id": "m_invocations", "Timestamps": [day], "Values": [2.0]},
                        {"Id": "m_latency", "Timestamps": [day], "Values": [100.0]},
                        {"Id": "m_latency", "Timestamps": [day], "Values": [300.0]},
                    ]
                }
            ]
        }
    )
    series = cloudwatch.get_metric_data(client, [{"Id": "m_invocations"}], day, day + dt.timedelta(days=1))
    assert series == {"m_invocations": {"2026-01-15": 5.0}, "m_latency": {"2026-01-15": 200.0}}


def test_guardrails_are_filtered_by_tag():
    summaries = [
        {"id": "aaa111", "arn": "arn:aws:bedrock:eu-west-1:111111111111:guardrail/aaa111", "name": "tagged"},
        {"id": "bbb222", "arn": "arn:aws:bedrock:eu-west-1:111111111111:guardrail/bbb222", "name": "untagged"},
        {"id": "ccc333", "arn": "arn:aws:bedrock:eu-west-1:111111111111:guardrail/ccc333", "name": "other-value"},
    ]
    tags = {
        summaries[0]["arn"]: [{"key": "agenticai:blueprint", "value": "true"}],
        summaries[1]["arn"]: [],
        summaries[2]["arn"]: [{"key": "agenticai:blueprint", "value": "false"}],
    }
    client = FakeClient(
        {
            "list_guardrails": [{"guardrails": summaries}],
            "list_tags_for_resource": lambda resourceARN: {"tags": tags[resourceARN]},  # noqa: N803
        }
    )
    assert [g["id"] for g in guardrails.list_tagged(client, "agenticai:blueprint", "true")] == ["aaa111"]


def test_guardrails_without_a_tag_key_lists_all_and_reads_no_tags():
    summaries = [{"id": "aaa111", "arn": "arn-1", "name": "one"}, {"id": "bbb222", "arn": "arn-2", "name": "two"}]
    client = FakeClient({"list_guardrails": [{"guardrails": summaries}]})
    assert [g["id"] for g in guardrails.list_tagged(client, "", "")] == ["aaa111", "bbb222"]
    assert "list_tags_for_resource" not in [name for name, _ in client.calls]


def test_cell_credentials_are_assumed_with_external_id_and_cached_until_near_expiry():
    settings = load_settings(BASE_ENV)
    cell = settings.cells[0]
    clients = AwsClients(session=boto3.session.Session(region_name=REGION, **CREDS), home_region=REGION)
    sts = clients.platform("sts", REGION)

    def credentials(key: str, minutes: int) -> dict:
        return {
            "Credentials": {
                "AccessKeyId": key,
                "SecretAccessKey": "s" * 40,
                "SessionToken": "t" * 40,
                "Expiration": dt.datetime.now(dt.UTC) + dt.timedelta(minutes=minutes),
            }
        }

    expected = {
        "RoleArn": f"arn:aws:iam::{CELL_ACCOUNT}:role/agenticai-portal-reader",
        "RoleSessionName": "agent-factory-portal",
        "DurationSeconds": 900,
        "ExternalId": "portal-ext-id",
    }
    with Stubber(sts) as stub:
        stub.add_response("assume_role", credentials("ASIAFIRSTFIRSTFIRST1", 4), expected)
        stub.add_response("assume_role", credentials("ASIASECONDSECONDSEC2", 15), expected)
        first = clients.cell(cell, "cloudwatch")  # expires inside the refresh margin
        second = clients.cell(cell, "cloudwatch")  # so this assumes again
        third = clients.cell(cell, "cloudwatch")  # and this reuses the cached session
        stub.assert_no_pending_responses()
    assert first is not second
    assert second is third
    assert second.meta.region_name == REGION


def test_cell_without_external_id_omits_it():
    settings = load_settings(BASE_ENV)
    clients = AwsClients(session=boto3.session.Session(region_name=REGION, **CREDS), home_region=REGION)
    sts = clients.platform("sts", REGION)
    with Stubber(sts) as stub:
        stub.add_response(
            "assume_role",
            {
                "Credentials": {
                    "AccessKeyId": "ASIAFIRSTFIRSTFIRST1",
                    "SecretAccessKey": "s" * 40,
                    "SessionToken": "t" * 40,
                    "Expiration": dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15),
                }
            },
            {
                "RoleArn": settings.cells[1].reader_role_arn,
                "RoleSessionName": "agent-factory-portal",
                "DurationSeconds": 900,
            },
        )
        clients.cell(settings.cells[1], "logs")
        stub.assert_no_pending_responses()


def test_ttl_cache_expires_and_never_caches_failures():
    now = [0.0]
    cache = TTLCache(clock=lambda: now[0])
    calls = []

    def loader():
        calls.append(1)
        return len(calls)

    assert cache.get_or_load("k", 30, loader) == 1
    assert cache.get_or_load("k", 30, loader) == 1
    now[0] = 31
    assert cache.get_or_load("k", 30, loader) == 2
    assert cache.get_or_load("off", 0, loader) == 3
    assert cache.get_or_load("off", 0, loader) == 4

    def failing():
        raise RuntimeError("boom")

    for _ in range(2):
        try:
            cache.get_or_load("bad", 30, failing)
        except RuntimeError:
            pass
    assert cache.get_or_load("bad", 30, lambda: "ok") == "ok"


def test_error_code_never_returns_the_message():
    from botocore.exceptions import ClientError

    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "arn:aws:iam::111111111111:role/x"}}, "Op")
    assert error_code(error) == "AccessDenied"
    assert error_code(ValueError("secret")) == "ValueError"
