# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from __future__ import annotations

import datetime as dt

import pytest
from botocore.exceptions import ClientError

from portal_api.mappers import health as health_mapper
from tests.conftest import CELL_ACCOUNT, OTHER_ACCOUNT, FakeClient, FakeClients, make_service

A, OK, ID = "ALARM", "OK", "INSUFFICIENT_DATA"


@pytest.mark.parametrize(
    ("states", "entered", "expected"),
    [
        ([A], False, "critical"),
        ([OK, A, ID], False, "critical"),
        ([A], True, "critical"),
        ([OK, OK], True, "needs_attention"),
        ([OK, ID], False, "needs_attention"),
        ([ID, ID], True, "needs_attention"),
        ([], False, "no_data"),
        ([ID], False, "no_data"),
        ([ID, ID, ID], False, "no_data"),
        ([OK], False, "healthy"),
        ([OK, OK, OK], False, "healthy"),
    ],
)
def test_state_rules(states, entered, expected):
    assert health_mapper.derive_state(states, entered) == expected


def test_fleet_totals(settings):
    cell_a, cell_b = settings.cells
    cells = [
        health_mapper.cell_health(cell_a, [A, A, OK], False),
        health_mapper.cell_health(cell_b, [OK], False),
        health_mapper.unreachable(cell_b, "Cell could not be read (AccessDenied)."),
    ]
    fleet = health_mapper.fleet("2026-01-15T12:00:00Z", cells)
    assert fleet.totals.model_dump() == {
        "cells": 3,
        "healthy": 1,
        "needs_attention": 0,
        "critical": 1,
        "no_data": 1,
        "unreachable": 1,
        "alarms_in_alarm": 2,
    }
    assert cells[0].alarms_in_alarm == 2 and cells[0].alarms_total == 3
    assert cells[0].account_alias == "account-4444"
    assert cells[2].reachable is False and cells[2].state == "no_data"


def _alarm(name: str, state: str, changed_hours_ago: float) -> dict:
    changed = dt.datetime.now(dt.UTC) - dt.timedelta(hours=changed_hours_ago)
    return {"AlarmName": name, "StateValue": state, "StateTransitionedTimestamp": changed}


def test_fleet_health_reports_unreachable_cell_instead_of_failing(settings):
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "secret detail"}}, "AssumeRole")
    cloudwatch = FakeClient(
        {
            "describe_alarms": [{"MetricAlarms": [_alarm("a-1", OK, 100)], "CompositeAlarms": [_alarm("a-2", A, 1)]}],
        }
    )
    clients = FakeClients({(CELL_ACCOUNT, "cloudwatch"): cloudwatch, (OTHER_ACCOUNT, "cloudwatch"): denied})
    fleet = make_service(settings, clients).fleet_health()
    first, second = fleet.cells
    assert (first.tenant_id, first.state, first.alarms_in_alarm, first.reachable) == ("ws1", "critical", 1, True)
    assert (second.tenant_id, second.state, second.reachable) == ("ws2", "no_data", False)
    assert second.detail == "Cell could not be read (AccessDenied)."
    assert "secret detail" not in fleet.model_dump_json()
    assert fleet.totals.unreachable == 1 and fleet.totals.critical == 1
    # one client request per cell: a single assume-role session each
    assert sorted(clients.cell_calls) == [(CELL_ACCOUNT, "cloudwatch"), (OTHER_ACCOUNT, "cloudwatch")]


def test_recent_transition_to_alarm_needs_attention_and_old_ones_are_not_queried(settings):
    history = [
        {
            "AlarmHistoryItems": [
                {"HistorySummary": "Alarm updated from OK to ALARM"},
                {"HistorySummary": "Alarm updated from ALARM to OK"},
            ]
        }
    ]
    cloudwatch = FakeClient(
        {
            "describe_alarms": [{"MetricAlarms": [_alarm("old", OK, 100), _alarm("recent", OK, 2)]}],
            "describe_alarm_history": history,
        }
    )
    quiet = FakeClient({"describe_alarms": [{"MetricAlarms": [_alarm("steady", OK, 100)]}]})
    clients = FakeClients({(CELL_ACCOUNT, "cloudwatch"): cloudwatch, (OTHER_ACCOUNT, "cloudwatch"): quiet})
    fleet = make_service(settings, clients).fleet_health()
    assert [c.state for c in fleet.cells] == ["needs_attention", "healthy"]
    assert [name for name, _ in cloudwatch.calls].count("paginate:describe_alarm_history") == 1
    assert "paginate:describe_alarm_history" not in [name for name, _ in quiet.calls]


def test_recent_recovery_without_alarm_is_healthy(settings):
    history = [{"AlarmHistoryItems": [{"HistorySummary": "Alarm updated from INSUFFICIENT_DATA to OK"}]}]
    cloudwatch = FakeClient(
        {"describe_alarms": [{"MetricAlarms": [_alarm("recent", OK, 2)]}], "describe_alarm_history": history}
    )
    clients = FakeClients({(CELL_ACCOUNT, "cloudwatch"): cloudwatch, (OTHER_ACCOUNT, "cloudwatch"): cloudwatch})
    fleet = make_service(settings, clients).fleet_health()
    assert [c.state for c in fleet.cells] == ["healthy", "healthy"]
