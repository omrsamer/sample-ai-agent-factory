# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Guardrails tagged for the blueprint in the platform account (read-only)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query

from portal_api.deps import CurrentPrincipal, Service
from portal_api.models.wire import GuardrailTemplate

router = APIRouter(prefix="/guardrails", tags=["guardrails"])


@router.get("", response_model=list[GuardrailTemplate])
def list_guardrails(
    _: CurrentPrincipal,
    service: Service,
    status: Annotated[str | None, Query(pattern="^[a-z]{1,16}$")] = None,
) -> list[GuardrailTemplate]:
    return service.guardrails(status)


@router.get("/{guardrail_id}", response_model=GuardrailTemplate)
def get_guardrail(
    guardrail_id: Annotated[str, Path(pattern="^[a-z0-9]{1,64}$")], _: CurrentPrincipal, service: Service
) -> GuardrailTemplate:
    return service.guardrail(guardrail_id)
