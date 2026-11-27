# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Model and tool catalogues."""

from __future__ import annotations

from fastapi import APIRouter

from portal_api.deps import CurrentPrincipal, Service
from portal_api.models.portal import CatalogModel, CatalogTool

router = APIRouter(prefix="/catalog", tags=["catalog"])


@router.get("/models", response_model=list[CatalogModel])
def models(_: CurrentPrincipal, service: Service) -> list[CatalogModel]:
    return service.catalog_models()


@router.get("/tools", response_model=list[CatalogTool])
def tools(_: CurrentPrincipal, service: Service) -> list[CatalogTool]:
    return service.catalog_tools()
