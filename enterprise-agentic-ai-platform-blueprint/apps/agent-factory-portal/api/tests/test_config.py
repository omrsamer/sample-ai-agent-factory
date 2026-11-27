# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from __future__ import annotations

import json

import pytest

from portal_api.config import ConfigError, dev_auth_enabled, load_settings, provider_of
from tests.conftest import BASE_ENV, CELL_ACCOUNT, CELLS

REQUIRED = [
    "PORTAL_ENV",
    "PORTAL_REGISTRY_ID",
    "PORTAL_REGISTRY_REGION",
    "PORTAL_CELLS",
    "PORTAL_IDENTITY_PROVIDER",
    "PORTAL_GROUP_ROLE_MAP",
    "PORTAL_MODEL_ALLOWLIST",
]


def test_valid_configuration_parses():
    settings = load_settings(BASE_ENV)
    assert settings.env == "nonprod"
    assert [c.key for c in settings.cells] == ["ws1/travel-agent/nonprod", "ws2/claims-agent/prod"]
    assert settings.cells[0].external_id == "portal-ext-id"
    assert settings.cells[0].effective_alarm_prefix == "agenticai-nonprod-ws1-travel-agent"
    assert settings.cells[1].effective_alarm_prefix == "custom-prefix-"
    assert settings.cache_ttl_seconds == 30
    assert settings.allowed_origins == ("https://portal.example.com",)
    assert [m.provider for m in settings.model_allowlist] == ["anthropic", "amazon"]
    assert settings.model_allowlist[0].regions == ("eu-west-1",)


@pytest.mark.parametrize("name", REQUIRED)
def test_missing_required_value_fails_closed(name):
    env = {k: v for k, v in BASE_ENV.items() if k != name}
    with pytest.raises(ConfigError, match=name):
        load_settings(env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PORTAL_ENV", "staging"),
        ("PORTAL_IDENTITY_PROVIDER", "okta"),
        ("PORTAL_CELLS", "not json"),
        ("PORTAL_CELLS", "{}"),
        ("PORTAL_GROUP_ROLE_MAP", '{"devs": "root"}'),
        ("PORTAL_GROUP_ROLE_MAP", "{}"),
        ("PORTAL_MODEL_ALLOWLIST", '{"a": 1}'),
        ("PORTAL_ALLOWED_ORIGINS", '["*"]'),
        ("PORTAL_CACHE_TTL_SECONDS", "soon"),
        ("PORTAL_REGISTRY_REGION", "eu west 1"),
    ],
)
def test_malformed_value_fails_closed(name, value):
    with pytest.raises(ConfigError):
        load_settings({**BASE_ENV, name: value})


@pytest.mark.parametrize(
    "patch",
    [
        {"accountId": "123"},
        {"environment": "dev"},
        {"readerRoleArn": "arn:aws:iam::999999999999:role/elsewhere"},
        {"readerRoleArn": "not-an-arn"},
        {"tenantId": "bad tenant"},
        {"pipelineName": "has space"},
    ],
)
def test_malformed_cell_fails_closed(patch):
    cells = [{**CELLS[0], **patch}]
    with pytest.raises(ConfigError):
        load_settings({**BASE_ENV, "PORTAL_CELLS": json.dumps(cells)})


def test_guardrail_tag_is_optional_but_must_be_a_pair():
    untagged = load_settings({**BASE_ENV, "PORTAL_GUARDRAIL_TAG_KEY": "", "PORTAL_GUARDRAIL_TAG_VALUE": ""})
    assert (untagged.guardrail_tag_key, untagged.guardrail_tag_value) == ("", "")
    absent = {k: v for k, v in BASE_ENV.items() if not k.startswith("PORTAL_GUARDRAIL_TAG")}
    assert load_settings(absent).guardrail_tag_key == ""
    assert load_settings(BASE_ENV).guardrail_tag_key == "agenticai:blueprint"
    with pytest.raises(ConfigError, match="PORTAL_GUARDRAIL_TAG_VALUE"):
        load_settings({**BASE_ENV, "PORTAL_GUARDRAIL_TAG_VALUE": ""})
    with pytest.raises(ConfigError, match="PORTAL_GUARDRAIL_TAG_KEY"):
        load_settings({**BASE_ENV, "PORTAL_GUARDRAIL_TAG_KEY": ""})


def test_duplicate_cell_is_rejected():
    with pytest.raises(ConfigError, match="duplicates"):
        load_settings({**BASE_ENV, "PORTAL_CELLS": json.dumps([CELLS[0], CELLS[0]])})


def test_error_names_the_variable_not_its_value():
    with pytest.raises(ConfigError) as info:
        load_settings({**BASE_ENV, "PORTAL_CELLS": json.dumps([{**CELLS[0], "accountId": "bad"}])})
    assert "PORTAL_CELLS[0].accountId" in str(info.value)
    assert CELL_ACCOUNT not in str(info.value)


def test_dev_auth_needs_explicit_flag_and_is_impossible_in_lambda():
    assert dev_auth_enabled({}) is False
    assert dev_auth_enabled({"PORTAL_DEV_AUTH": "true"}) is False
    assert dev_auth_enabled({"PORTAL_DEV_AUTH": "1"}) is True
    assert dev_auth_enabled({"PORTAL_DEV_AUTH": "1", "AWS_LAMBDA_FUNCTION_NAME": "portal-api"}) is False


def test_provider_of_strips_geography_prefix():
    assert provider_of("eu.anthropic.claude-haiku-4-5-20251001-v1:0") == "anthropic"
    assert provider_of("amazon.nova-pro-v1:0") == "amazon"
    assert provider_of("custom") == "unknown"
