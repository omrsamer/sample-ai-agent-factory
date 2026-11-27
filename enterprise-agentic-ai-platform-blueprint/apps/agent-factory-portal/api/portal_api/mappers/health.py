# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Fleet health state rules."""

from __future__ import annotations

from collections.abc import Iterable

from portal_api.config import Cell
from portal_api.models.portal import CellHealth, FleetHealth, FleetTotals

ALARM = "ALARM"
OK = "OK"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


def derive_state(states: Iterable[str], entered_alarm_last_24h: bool) -> str:
    """State of one cell from its alarm states.

    - ``critical``: any alarm is in ALARM.
    - ``needs_attention``: any alarm changed to ALARM in the last 24 hours, or any
      alarm is INSUFFICIENT_DATA alongside OK alarms.
    - ``no_data``: there are no alarms, or all of them are INSUFFICIENT_DATA.
    - ``healthy``: otherwise.
    """
    values = list(states)
    if any(state == ALARM for state in values):
        return "critical"
    if entered_alarm_last_24h:
        return "needs_attention"
    if not values or all(state == INSUFFICIENT_DATA for state in values):
        return "no_data"
    if any(state == INSUFFICIENT_DATA for state in values) and any(state == OK for state in values):
        return "needs_attention"
    return "healthy"


def _alias(cell: Cell) -> str:
    """The configured display alias. Without one, a masked label; never the full account id."""
    return cell.account_alias or f"account-{cell.account_id[-4:]}"


def cell_health(cell: Cell, states: list[str], entered_alarm_last_24h: bool) -> CellHealth:
    return CellHealth(
        tenant_id=cell.tenant_id,
        agent_id=cell.agent_id,
        environment=cell.environment,
        account_alias=_alias(cell),
        region=cell.region,
        state=derive_state(states, entered_alarm_last_24h),
        alarms_in_alarm=sum(1 for state in states if state == ALARM),
        alarms_total=len(states),
        reachable=True,
    )


def unreachable(cell: Cell, detail: str) -> CellHealth:
    return CellHealth(
        tenant_id=cell.tenant_id,
        agent_id=cell.agent_id,
        environment=cell.environment,
        account_alias=_alias(cell),
        region=cell.region,
        state="no_data",
        reachable=False,
        detail=detail,
    )


def fleet(checked_at: str, cells: list[CellHealth]) -> FleetHealth:
    totals = FleetTotals(cells=len(cells))
    for cell in cells:
        totals.alarms_in_alarm += cell.alarms_in_alarm
        if not cell.reachable:
            totals.unreachable += 1
        setattr(totals, cell.state, getattr(totals, cell.state) + 1)
    return FleetHealth(checked_at=checked_at, cells=cells, totals=totals)
