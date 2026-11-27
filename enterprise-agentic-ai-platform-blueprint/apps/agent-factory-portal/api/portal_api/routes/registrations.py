# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Registrations (agent governance records) and their audit trail. Read only."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query

from portal_api.deps import CurrentPrincipal, Service
from portal_api.models.portal import Registration, RegistrationDetail, RegistrationHistory

router = APIRouter(prefix="/registrations", tags=["registrations"])


@router.get("", response_model=list[Registration])
def list_registrations(
    _: CurrentPrincipal,
    service: Service,
    status: Annotated[str | None, Query(pattern="^(DRAFT|PENDING_APPROVAL|APPROVED|REJECTED|DEPRECATED)$")] = None,
    tenant_id: Annotated[str | None, Query(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")] = None,
) -> list[Registration]:
    return service.registrations(status, tenant_id)


RecordId = Annotated[str, Path(pattern=r"^[A-Za-z0-9]{12}$")]


@router.get("/{record_id}", response_model=RegistrationDetail)
def get_registration(record_id: RecordId, principal: CurrentPrincipal, service: Service) -> RegistrationDetail:
    return service.registration(record_id, principal.subject)


@router.get("/{record_id}/history", response_model=RegistrationHistory)
def history(record_id: RecordId, _: CurrentPrincipal, service: Service) -> RegistrationHistory:
    return service.registration_history(record_id)
