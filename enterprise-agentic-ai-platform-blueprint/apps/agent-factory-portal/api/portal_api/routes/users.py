# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Current user."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from portal_api.config import Settings, get_settings
from portal_api.deps import CurrentPrincipal
from portal_api.identity.provider import console_role
from portal_api.models.wire import UserInfo

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserInfo)
def me(principal: CurrentPrincipal, settings: Settings = Depends(get_settings)) -> UserInfo:
    role, level = console_role(principal.role)
    tenants = sorted({cell.tenant_id for cell in settings.cells})
    return UserInfo(
        email=principal.email or "unknown",
        role=role,
        role_level=level,
        # Milestone 1 is read-only: nobody can deploy or change anything through the portal.
        can_deploy=False,
        oid=principal.subject,
        name=principal.display_name,
        tenants=[{"id": tenant, "name": tenant, "line_of_business": "", "stages": {}} for tenant in tenants],
        portal_role=principal.role,
        groups=list(principal.groups),
        identity_provider=settings.identity_provider,
    )
