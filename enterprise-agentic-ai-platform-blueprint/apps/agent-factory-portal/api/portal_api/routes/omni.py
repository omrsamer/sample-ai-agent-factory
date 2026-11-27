# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Hand-off to Amazon CloudWatch Omni: what its Context Graph observes in the portal's own account."""

from __future__ import annotations

import os
import re
from typing import Annotated

from fastapi import APIRouter, Query, Request

from portal_api.deps import CurrentPrincipal, Service
from portal_api.models.portal import ObservedServices

router = APIRouter(prefix="/omni", tags=["omni"])

_ACCOUNT = re.compile(r"^\d{12}$")
_FUNCTION_ARN = re.compile(r"^arn:aws[a-z-]*:lambda:[a-z0-9-]+:(\d{12}):function:")


def own_account_id(request: Request) -> str | None:
    """The account this function runs in: from the Lambda context, else the API event, else local configuration."""
    context = request.scope.get("aws.context")
    match = _FUNCTION_ARN.match(str(getattr(context, "invoked_function_arn", "") or ""))
    if match:
        return match.group(1)
    event = request.scope.get("aws.event")
    account = (event.get("requestContext") or {}).get("accountId") if isinstance(event, dict) else None
    if isinstance(account, str) and _ACCOUNT.fullmatch(account):
        return account
    local = os.environ.get("PORTAL_ACCOUNT_ID", "")
    return local if _ACCOUNT.fullmatch(local) else None


@router.get("/observed-services", response_model=ObservedServices)
def observed_services(
    request: Request,
    _: CurrentPrincipal,
    service: Service,
    cell: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_-]{1,128}(/(nonprod|prod))?$")] = None,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> ObservedServices:
    return service.observed_services(cell, own_account_id(request), hours)
