# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Configuration for the Agent Factory Portal API.

Everything comes from environment variables set by infrastructure. Loading
fails closed: a missing or malformed required value raises ``ConfigError``,
which the application turns into a 500 with a reason that names the variable
(never its value). There is no fallback to sample or in-memory data.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

PORTAL_ROLES: tuple[str, ...] = (
    # Lowest to highest privilege. "Highest privilege wins" uses this order.
    "readonly",
    "developer",
    "finops",
    "approver",
    "sre",
    "security",
    "platform",
)

_ACCOUNT_ID = re.compile(r"^\d{12}$")
_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_ALARM_PREFIX = re.compile(r"^[A-Za-z0-9_.\-/ ]{1,255}$")
_PIPELINE_NAME = re.compile(r"^[A-Za-z0-9.@_-]{1,100}$")
_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_EXTERNAL_ID = re.compile(r"^[\w+=,.@:/-]{2,1224}$")


class ConfigError(Exception):
    """Required configuration is missing or malformed."""


@dataclass(frozen=True)
class Cell:
    """One Workstream cell the portal can read through its reader role."""

    tenant_id: str
    agent_id: str
    environment: str
    account_id: str
    region: str
    reader_role_arn: str
    application_id: str | None = None
    external_id: str | None = None
    alarm_name_prefix: str | None = None
    pipeline_name: str | None = None
    account_alias: str | None = None

    @property
    def key(self) -> str:
        return f"{self.tenant_id}/{self.agent_id}/{self.environment}"

    @property
    def scope(self) -> tuple[str, str, str, str | None]:
        """Cells that share account, region and reader role share one discovery pass."""
        return (self.account_id, self.region, self.reader_role_arn, self.external_id)

    @property
    def effective_alarm_prefix(self) -> str:
        # Blueprint convention (packages/observability alarms construct).
        return self.alarm_name_prefix or f"agenticai-{self.environment}-{self.tenant_id}-{self.agent_id}"


@dataclass(frozen=True)
class ModelEntry:
    model_id: str
    provider: str
    regions: tuple[str, ...]
    status: str


@dataclass(frozen=True)
class Settings:
    env: str
    registry_id: str
    registry_region: str
    cells: tuple[Cell, ...]
    identity_provider: str
    group_role_map: Mapping[str, str]
    guardrail_tag_key: str
    guardrail_tag_value: str
    model_allowlist: tuple[ModelEntry, ...]
    allowed_origins: tuple[str, ...] = ()
    cache_ttl_seconds: int = 30
    # Optional in the read API: only the registration history route needs the audit table.
    audit_table: str | None = None
    # Optional in the read API: lets /users/me say which tenants the caller can register for.
    group_tenant_map: Mapping[str, tuple[str, ...]] | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def cell_for(self, tenant_id: str | None, agent_id: str | None, environment: str | None) -> Cell | None:
        for cell in self.cells:
            if (cell.tenant_id, cell.agent_id, cell.environment) == (tenant_id, agent_id, environment):
                return cell
        return None


def _required(env: Mapping[str, str], name: str) -> str:
    value = (env.get(name) or "").strip()
    if not value:
        raise ConfigError(f"{name} is not set")
    return value


def _json(env: Mapping[str, str], name: str, *, required: bool = True, default: Any = None) -> Any:
    raw = (env.get(name) or "").strip()
    if not raw:
        if required:
            raise ConfigError(f"{name} is not set")
        return default
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} is not valid JSON") from exc


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ConfigError(f"{label} is missing or malformed")
    return value


def _optional(pattern: re.Pattern[str], value: Any, label: str) -> str | None:
    if value is None or value == "":
        return None
    return _match(pattern, value, label)


def _parse_cells(raw: Any) -> tuple[Cell, ...]:
    if not isinstance(raw, list):
        raise ConfigError("PORTAL_CELLS must be a JSON list")
    cells: list[Cell] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        label = f"PORTAL_CELLS[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{label} must be an object")
        environment = item.get("environment")
        if environment not in ("nonprod", "prod"):
            raise ConfigError(f"{label}.environment must be nonprod or prod")
        cell = Cell(
            tenant_id=_match(_SLUG, item.get("tenantId"), f"{label}.tenantId"),
            agent_id=_match(_SLUG, item.get("agentId"), f"{label}.agentId"),
            environment=environment,
            account_id=_match(_ACCOUNT_ID, item.get("accountId"), f"{label}.accountId"),
            region=_match(_REGION, item.get("region"), f"{label}.region"),
            reader_role_arn=_match(_ROLE_ARN, item.get("readerRoleArn"), f"{label}.readerRoleArn"),
            application_id=_optional(_SLUG, item.get("applicationId"), f"{label}.applicationId"),
            external_id=_optional(_EXTERNAL_ID, item.get("externalId"), f"{label}.externalId"),
            alarm_name_prefix=_optional(_ALARM_PREFIX, item.get("alarmNamePrefix"), f"{label}.alarmNamePrefix"),
            pipeline_name=_optional(_PIPELINE_NAME, item.get("pipelineName"), f"{label}.pipelineName"),
            account_alias=_optional(_SLUG, item.get("accountAlias"), f"{label}.accountAlias"),
        )
        if f":{cell.account_id}:" not in cell.reader_role_arn:
            raise ConfigError(f"{label}.readerRoleArn is not in the cell account")
        if cell.key in seen:
            raise ConfigError(f"{label} duplicates another cell")
        seen.add(cell.key)
        cells.append(cell)
    return tuple(cells)


def _parse_role_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict) or not raw:
        raise ConfigError("PORTAL_GROUP_ROLE_MAP must be a non-empty JSON object")
    result: dict[str, str] = {}
    for group, role in raw.items():
        if not isinstance(group, str) or not group or role not in PORTAL_ROLES:
            raise ConfigError("PORTAL_GROUP_ROLE_MAP maps a group to an unknown role")
        result[group] = role
    return result


_GEO_PREFIXES = ("us", "eu", "apac", "global", "us-gov", "au", "jp", "ca")


def provider_of(model_id: str) -> str:
    """Provider segment of a Bedrock model or inference-profile id."""
    parts = model_id.split(".")
    if len(parts) > 1 and parts[0] in _GEO_PREFIXES:
        parts = parts[1:]
    return parts[0] if len(parts) > 1 else "unknown"


def _parse_models(raw: Any, default_regions: tuple[str, ...]) -> tuple[ModelEntry, ...]:
    if not isinstance(raw, list):
        raise ConfigError("PORTAL_MODEL_ALLOWLIST must be a JSON list")
    entries: list[ModelEntry] = []
    for index, item in enumerate(raw):
        label = f"PORTAL_MODEL_ALLOWLIST[{index}]"
        if isinstance(item, str):
            item = {"modelId": item}
        if not isinstance(item, dict):
            raise ConfigError(f"{label} must be a string or an object")
        model_id = item.get("modelId") or item.get("model_id")
        if not isinstance(model_id, str) or not re.match(r"^[A-Za-z0-9._:/-]{1,256}$", model_id):
            raise ConfigError(f"{label}.modelId is missing or malformed")
        regions = item.get("regions") or list(default_regions)
        if not isinstance(regions, list) or not all(isinstance(r, str) and _REGION.match(r) for r in regions):
            raise ConfigError(f"{label}.regions is malformed")
        provider = item.get("provider") or provider_of(model_id)
        status = item.get("status") or "approved"
        if not isinstance(provider, str) or not isinstance(status, str):
            raise ConfigError(f"{label} provider and status must be strings")
        entries.append(ModelEntry(model_id=model_id, provider=provider, regions=tuple(regions), status=status))
    return tuple(entries)


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Parse and validate the environment. Raises ``ConfigError`` on any problem."""
    env = os.environ if env is None else env

    portal_env = _required(env, "PORTAL_ENV")
    if portal_env not in ("nonprod", "prod"):
        raise ConfigError("PORTAL_ENV must be nonprod or prod")

    provider = _required(env, "PORTAL_IDENTITY_PROVIDER")
    if provider not in ("cognito", "entra"):
        raise ConfigError("PORTAL_IDENTITY_PROVIDER must be cognito or entra")

    registry_id = _match(_SLUG, _required(env, "PORTAL_REGISTRY_ID"), "PORTAL_REGISTRY_ID")
    registry_region = _match(_REGION, _required(env, "PORTAL_REGISTRY_REGION"), "PORTAL_REGISTRY_REGION")
    cells = _parse_cells(_json(env, "PORTAL_CELLS"))
    role_map = _parse_role_map(_json(env, "PORTAL_GROUP_ROLE_MAP"))

    default_regions = tuple(sorted({registry_region, *(c.region for c in cells)}))
    models = _parse_models(_json(env, "PORTAL_MODEL_ALLOWLIST"), default_regions)

    origins = _json(env, "PORTAL_ALLOWED_ORIGINS", required=False, default=[])
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        raise ConfigError("PORTAL_ALLOWED_ORIGINS must be a JSON list of strings")
    if "*" in origins:
        raise ConfigError("PORTAL_ALLOWED_ORIGINS must list explicit origins")

    ttl_raw = (env.get("PORTAL_CACHE_TTL_SECONDS") or "30").strip()
    try:
        ttl = int(ttl_raw)
    except ValueError as exc:
        raise ConfigError("PORTAL_CACHE_TTL_SECONDS must be an integer") from exc
    if not 0 <= ttl <= 3600:
        raise ConfigError("PORTAL_CACHE_TTL_SECONDS must be between 0 and 3600")

    # The guardrail tag is optional: with no key, every guardrail in the account and Region is listed.
    tag_key = (env.get("PORTAL_GUARDRAIL_TAG_KEY") or "").strip()
    tag_value = (env.get("PORTAL_GUARDRAIL_TAG_VALUE") or "").strip()
    if tag_value and not tag_key:
        raise ConfigError("PORTAL_GUARDRAIL_TAG_VALUE is set but PORTAL_GUARDRAIL_TAG_KEY is not")
    if tag_key and not tag_value:
        raise ConfigError("PORTAL_GUARDRAIL_TAG_KEY is set but PORTAL_GUARDRAIL_TAG_VALUE is not")

    return Settings(
        env=portal_env,
        registry_id=registry_id,
        registry_region=registry_region,
        cells=cells,
        identity_provider=provider,
        group_role_map=role_map,
        guardrail_tag_key=tag_key,
        guardrail_tag_value=tag_value,
        model_allowlist=models,
        allowed_origins=tuple(origins),
        cache_ttl_seconds=ttl,
        audit_table=_optional(_TABLE_NAME, env.get("PORTAL_AUDIT_TABLE", "").strip(), "PORTAL_AUDIT_TABLE"),
        group_tenant_map=(
            _parse_tenant_map(_json(env, "PORTAL_GROUP_TENANT_MAP"), role_map)
            if (env.get("PORTAL_GROUP_TENANT_MAP") or "").strip()
            else None
        ),
    )


_CONFIG_KEYS = (
    "PORTAL_ENV",
    "PORTAL_REGISTRY_ID",
    "PORTAL_REGISTRY_REGION",
    "PORTAL_CELLS",
    "PORTAL_IDENTITY_PROVIDER",
    "PORTAL_GROUP_ROLE_MAP",
    "PORTAL_GUARDRAIL_TAG_KEY",
    "PORTAL_GUARDRAIL_TAG_VALUE",
    "PORTAL_MODEL_ALLOWLIST",
    "PORTAL_ALLOWED_ORIGINS",
    "PORTAL_CACHE_TTL_SECONDS",
    "PORTAL_AUDIT_TABLE",
    "PORTAL_GROUP_TENANT_MAP",
    "PORTAL_ACTION_ROLE",
)
_cached: tuple[tuple[str | None, ...], Settings] | None = None


def get_settings() -> Settings:
    """Settings for the current environment, parsed once per distinct environment snapshot."""
    global _cached
    snapshot = tuple(os.environ.get(key) for key in _CONFIG_KEYS)
    if _cached is not None and _cached[0] == snapshot:
        return _cached[1]
    try:
        settings = load_settings()
    except ConfigError as exc:
        logger.error("Portal configuration rejected: %s", exc)
        raise
    _cached = (snapshot, settings)
    return settings


ACTION_ROLES = ("registrar", "approver")
ALL_TENANTS = "*"  # same marker as portal_api.authorities.ALL_TENANTS


@dataclass(frozen=True)
class ActionSettings:
    """Configuration of one action function (registrar or approver).

    Deliberately smaller than ``Settings``: an action function reads the
    registry and the audit table and nothing else, so it does not need cells,
    guardrail tags or the model allow-list.
    """

    env: str
    action_role: str
    registry_id: str
    registry_region: str
    identity_provider: str
    group_role_map: Mapping[str, str]
    group_tenant_map: Mapping[str, tuple[str, ...]]
    audit_table: str
    allowed_origins: tuple[str, ...] = ()


def _parse_tenant_map(raw: Any, role_map: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise ConfigError("PORTAL_GROUP_TENANT_MAP must be a JSON object")
    result: dict[str, tuple[str, ...]] = {}
    for group, tenants in raw.items():
        if not isinstance(group, str) or not group or not isinstance(tenants, list):
            raise ConfigError("PORTAL_GROUP_TENANT_MAP maps a group to something that is not a list")
        for tenant in tenants:
            if tenant == ALL_TENANTS:
                if role_map.get(group) != "platform":
                    raise ConfigError("PORTAL_GROUP_TENANT_MAP allows '*' only for a group mapped to platform")
            elif not isinstance(tenant, str) or not _TENANT.match(tenant):
                raise ConfigError("PORTAL_GROUP_TENANT_MAP holds a malformed tenant id")
        result[group] = tuple(dict.fromkeys(tenants))
    return result


def load_action_settings(env: Mapping[str, str] | None = None) -> ActionSettings:
    """Parse and validate the environment of an action function. Fails closed."""
    env = os.environ if env is None else env
    portal_env = _required(env, "PORTAL_ENV")
    if portal_env not in ("nonprod", "prod"):
        raise ConfigError("PORTAL_ENV must be nonprod or prod")
    action_role = _required(env, "PORTAL_ACTION_ROLE")
    if action_role not in ACTION_ROLES:
        raise ConfigError("PORTAL_ACTION_ROLE must be registrar or approver")
    provider = _required(env, "PORTAL_IDENTITY_PROVIDER")
    if provider not in ("cognito", "entra"):
        raise ConfigError("PORTAL_IDENTITY_PROVIDER must be cognito or entra")
    role_map = _parse_role_map(_json(env, "PORTAL_GROUP_ROLE_MAP"))
    origins = _json(env, "PORTAL_ALLOWED_ORIGINS", required=False, default=[])
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins) or "*" in origins:
        raise ConfigError("PORTAL_ALLOWED_ORIGINS must be a JSON list of explicit origins")
    return ActionSettings(
        env=portal_env,
        action_role=action_role,
        registry_id=_match(_SLUG, _required(env, "PORTAL_REGISTRY_ID"), "PORTAL_REGISTRY_ID"),
        registry_region=_match(_REGION, _required(env, "PORTAL_REGISTRY_REGION"), "PORTAL_REGISTRY_REGION"),
        identity_provider=provider,
        group_role_map=role_map,
        group_tenant_map=_parse_tenant_map(_json(env, "PORTAL_GROUP_TENANT_MAP"), role_map),
        audit_table=_match(_TABLE_NAME, _required(env, "PORTAL_AUDIT_TABLE"), "PORTAL_AUDIT_TABLE"),
        allowed_origins=tuple(origins),
    )


_cached_action: tuple[tuple[str | None, ...], ActionSettings] | None = None


def get_action_settings() -> ActionSettings:
    global _cached_action
    snapshot = tuple(os.environ.get(key) for key in _CONFIG_KEYS)
    if _cached_action is not None and _cached_action[0] == snapshot:
        return _cached_action[1]
    try:
        settings = load_action_settings()
    except ConfigError as exc:
        logger.error("Action configuration rejected: %s", exc)
        raise
    _cached_action = (snapshot, settings)
    return settings


def dev_auth_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Local-development identity is allowed only outside AWS Lambda and only when asked for."""
    env = os.environ if env is None else env
    if env.get("AWS_LAMBDA_FUNCTION_NAME"):
        return False
    return env.get("PORTAL_DEV_AUTH") == "1"
