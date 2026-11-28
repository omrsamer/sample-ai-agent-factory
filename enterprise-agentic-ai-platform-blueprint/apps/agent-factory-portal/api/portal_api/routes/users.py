# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Current user."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from portal_api import authorities
from portal_api.config import Settings, get_settings
from portal_api.deps import CurrentPrincipal
from portal_api.identity.provider import console_role
from portal_api.models.wire import UserInfo

router = APIRouter(prefix="/users", tags=["users"])


def _registration_tenants(role: str, groups: tuple[str, ...], settings: Settings) -> list[str] | None:
    if authorities.holds_all_tenants(role):
        return [authorities.ALL_TENANTS]
    if settings.group_tenant_map is None:
        return None
    return list(authorities.tenants_of(groups, settings.group_tenant_map))


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
        name=principal.name,
        tenants=[{"id": tenant, "name": tenant, "line_of_business": "", "stages": {}} for tenant in tenants],
        portal_role=principal.role,
        groups=list(principal.groups),
        identity_provider=settings.identity_provider,
        can_register=principal.role in authorities.REGISTRAR_ROLES,
        can_approve=principal.role in authorities.APPROVER_ROLES,
        can_contain=principal.role in authorities.CONTAIN_ROLES,
        can_release=principal.role in authorities.RELEASE_ROLES,
        authorities=[
            name
            for name, roles in (("registrar", authorities.REGISTRAR_ROLES), ("approver", authorities.APPROVER_ROLES))
            if principal.role in roles
        ],
        registration_tenants=_registration_tenants(principal.role, principal.groups, settings),
    )
