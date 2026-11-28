# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""boto3 client factory.

Platform-account data is read with the function's own role. Cell-account data
is read by assuming the cell's reader role (with its external id when set); the
temporary credentials are cached until shortly before they expire.

Each function assumes a cell's role under a session name of its own, so the
cell's CloudTrail says which function made a call. A function can also narrow
what the assumed role may do with a session policy. The sweeper does: the
session it works with cannot write or delete a resource policy. The caller
chooses that narrowing; the role itself allows more.
"""

from __future__ import annotations

import datetime as dt
import threading
from typing import Any

import boto3
from botocore.config import Config

from portal_api.config import Cell

BOTO_CONFIG = Config(
    connect_timeout=3,
    read_timeout=10,
    retries={"max_attempts": 3, "mode": "standard"},
    user_agent_extra="agent-factory-portal",
)

_REFRESH_MARGIN = dt.timedelta(minutes=5)
_SESSION_DURATION_SECONDS = 900
# The role session name of each function that assumes a role in a cell. It is in every CloudTrail
# event of the cell account that the function causes, as the last part of the caller's ARN.
SESSION_READER = "portal-reader"  # the read API, with a cell's reader role
SESSION_CONTAINMENT = "portal-containment"  # the containment function, with a cell's containment role
SESSION_SWEEPER = "portal-sweeper"  # the sweeper, with the same role and a session policy


class AwsClients:
    """Creates and reuses boto3 clients for the platform account and for each cell."""

    def __init__(
        self,
        session: boto3.session.Session | None = None,
        home_region: str | None = None,
        session_name: str = SESSION_READER,
    ) -> None:
        self._session = session or boto3.session.Session()
        self._home_region = home_region
        self._session_name = session_name
        self._lock = threading.Lock()
        self._clients: dict[tuple[Any, ...], Any] = {}
        self._cell_credentials: dict[tuple[Any, ...], tuple[dt.datetime, dict[str, str]]] = {}

    def platform(self, service: str, region: str) -> Any:
        key = ("platform", service, region)
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                client = self._session.client(service, region_name=region, config=BOTO_CONFIG)
                self._clients[key] = client
            return client

    def cell(self, cell: Cell, service: str) -> Any:
        """A client in the cell's account, through the cell's reader role."""
        return self.assumed(cell.reader_role_arn, cell.external_id, cell.region, service)

    def assumed(
        self, role_arn: str, external_id: str | None, region: str, service: str, session_policy: str | None = None
    ) -> Any:
        """A client that uses a role assumed with the given external id.

        ``session_policy`` is an IAM policy document that narrows the role
        for this session: the session can do only what both the role's own
        policies and this document allow.
        """
        scope = (role_arn, external_id, region, session_policy)
        credentials = self._credentials_for(role_arn, external_id, region, session_policy)
        key = ("cell", scope, service, credentials["AccessKeyId"])
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                # Drop clients built on credentials that have since been rotated.
                stale = [k for k in self._clients if k[:3] == ("cell", scope, service)]
                for old in stale:
                    del self._clients[old]
                client = self._session.client(
                    service,
                    region_name=region,
                    config=BOTO_CONFIG,
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
                self._clients[key] = client
            return client

    def _credentials_for(
        self, role_arn: str, external_id: str | None, region: str, session_policy: str | None = None
    ) -> dict[str, str]:
        now = dt.datetime.now(dt.UTC)
        # Credentials narrowed by a session policy are never handed out for a request without one.
        scope = (role_arn, external_id, session_policy)
        with self._lock:
            cached = self._cell_credentials.get(scope)
            if cached is not None and cached[0] - _REFRESH_MARGIN > now:
                return cached[1]
        params: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": self._session_name,
            "DurationSeconds": _SESSION_DURATION_SECONDS,
        }
        if external_id:
            params["ExternalId"] = external_id
        if session_policy:
            params["Policy"] = session_policy
        response = self.platform("sts", self._home_region or region).assume_role(**params)
        credentials = response["Credentials"]
        expiry = credentials["Expiration"]
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=dt.UTC)
        with self._lock:
            self._cell_credentials[scope] = (expiry, credentials)
        return credentials


def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[Any]:
    """Collect every page of a list operation."""
    items: list[Any] = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(result_key) or [])
    return items


def error_code(exc: BaseException) -> str:
    """A short, safe hint for an AWS failure: the error code only, never a message or ARN."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if isinstance(code, str) and code:
            return code
    return type(exc).__name__
