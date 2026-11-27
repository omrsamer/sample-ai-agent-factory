# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared FastAPI dependencies."""

from __future__ import annotations

import threading
from typing import Annotated

from fastapi import Depends, Path

from portal_api.config import Settings, get_settings
from portal_api.identity.deps import current_principal
from portal_api.identity.provider import Principal
from portal_api.service import PortalService

_lock = threading.Lock()
_service: PortalService | None = None


def get_service(settings: Settings = Depends(get_settings)) -> PortalService:
    """One service (clients and cache) per sandbox, rebuilt only if configuration changes."""
    global _service
    with _lock:
        if _service is None or _service.settings is not settings:
            _service = PortalService(settings)
        return _service


# Path identifiers are allow-listed before they are used for anything.
EntityId = Annotated[str, Path(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")]
PrincipalId = Annotated[str, Path(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.@:-]{0,255}$")]

CurrentPrincipal = Annotated[Principal, Depends(current_principal)]
Service = Annotated[PortalService, Depends(get_service)]
