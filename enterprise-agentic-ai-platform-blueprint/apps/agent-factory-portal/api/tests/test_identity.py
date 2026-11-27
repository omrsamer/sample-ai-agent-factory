# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from __future__ import annotations

import pytest

from portal_api.identity.provider import (
    CognitoProvider,
    EntraProvider,
    NotAuthenticated,
    NotAuthorized,
    console_role,
    parse_multi_value,
    resolve_role,
)

ROLE_MAP = {
    "platform-admins": "platform",
    "sec": "security",
    "sre-oncall": "sre",
    "finance": "finops",
    "approvers": "approver",
    "devs": "developer",
    "viewers": "readonly",
    "Portal.Admin": "platform",
}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("[devs viewers]", ("devs", "viewers")),
        ('["devs","viewers"]', ("devs", "viewers")),
        ("[devs, viewers]", ("devs", "viewers")),
        (["devs", "viewers", "devs"], ("devs", "viewers")),
        ("devs", ("devs",)),
        ("[]", ()),
        ("", ()),
        (None, ()),
        (42, ()),
        ([1, "devs", None], ("devs",)),
    ],
)
def test_parse_multi_value(raw, expected):
    assert parse_multi_value(raw) == expected


def test_highest_privilege_role_wins():
    assert resolve_role(["viewers", "devs"], ROLE_MAP) == "developer"
    assert resolve_role(["devs", "sec", "finance"], ROLE_MAP) == "security"
    assert resolve_role(["viewers", "platform-admins", "sec"], ROLE_MAP) == "platform"
    assert resolve_role(["approvers", "finance"], ROLE_MAP) == "approver"
    assert resolve_role(["sre-oncall", "approvers"], ROLE_MAP) == "sre"


def test_unmapped_groups_have_no_role():
    assert resolve_role(["strangers"], ROLE_MAP) is None
    assert resolve_role([], ROLE_MAP) is None


def test_cognito_principal_from_bracketed_groups():
    claims = {"sub": "sub-1", "email": "a@example.com", "cognito:username": "alice", "cognito:groups": "[devs sec]"}
    principal = CognitoProvider().principal(claims, ROLE_MAP)
    assert principal.subject == "sub-1"
    assert principal.email == "a@example.com"
    assert principal.display_name == "alice"
    assert principal.groups == ("devs", "sec")
    assert principal.role == "security"


def test_cognito_principal_from_json_array_groups():
    claims = {"sub": "sub-1", "cognito:groups": '["viewers"]'}
    principal = CognitoProvider().principal(claims, ROLE_MAP)
    assert principal.role == "readonly"
    assert principal.email is None


@pytest.mark.parametrize(
    ("custom", "expected_groups", "role"),
    [
        ("devs,sec", ("viewers", "devs", "sec"), "security"),
        ("devs, platform-admins", ("viewers", "devs", "platform-admins"), "platform"),
        ('["devs","viewers"]', ("viewers", "devs"), "developer"),
        ("[devs sec]", ("viewers", "devs", "sec"), "security"),
        ("devs", ("viewers", "devs"), "developer"),
        ("", ("viewers",), "readonly"),
    ],
)
def test_cognito_unions_saml_custom_groups(custom, expected_groups, role):
    claims = {"sub": "sub-1", "cognito:groups": "[viewers]", "custom:groups": custom}
    principal = CognitoProvider().principal(claims, ROLE_MAP)
    assert principal.groups == expected_groups
    assert principal.role == role


def test_cognito_saml_user_with_only_custom_groups():
    principal = CognitoProvider().principal({"sub": "sub-1", "custom:groups": "sec,strangers"}, ROLE_MAP)
    assert principal.role == "security"
    with pytest.raises(NotAuthorized):
        CognitoProvider().principal({"sub": "sub-1", "custom:groups": "strangers"}, ROLE_MAP)


def test_entra_principal_uses_roles_and_groups():
    claims = {
        "oid": "oid-1",
        "sub": "ignored",
        "preferred_username": "bob@example.com",
        "name": "Bob",
        "roles": ["Portal.Admin"],
        "groups": "[viewers]",
    }
    principal = EntraProvider().principal(claims, ROLE_MAP)
    assert principal.subject == "oid-1"
    assert principal.email == "bob@example.com"
    assert principal.display_name == "Bob"
    assert principal.groups == ("Portal.Admin", "viewers")
    assert principal.role == "platform"


def test_entra_does_not_read_cognito_groups():
    with pytest.raises(NotAuthorized):
        EntraProvider().principal({"oid": "oid-1", "cognito:groups": ["platform-admins"]}, ROLE_MAP)


@pytest.mark.parametrize("provider", [CognitoProvider(), EntraProvider()])
def test_absent_claims_are_unauthenticated(provider):
    with pytest.raises(NotAuthenticated):
        provider.principal(None, ROLE_MAP)
    with pytest.raises(NotAuthenticated):
        provider.principal({}, ROLE_MAP)


def test_missing_subject_is_unauthenticated():
    with pytest.raises(NotAuthenticated):
        CognitoProvider().principal({"cognito:groups": ["devs"]}, ROLE_MAP)
    with pytest.raises(NotAuthenticated):
        EntraProvider().principal({"sub": "only-sub", "roles": ["Portal.Admin"]}, ROLE_MAP)


def test_no_mapped_group_is_forbidden():
    with pytest.raises(NotAuthorized):
        CognitoProvider().principal({"sub": "sub-1", "cognito:groups": ["strangers"]}, ROLE_MAP)
    with pytest.raises(NotAuthorized):
        CognitoProvider().principal({"sub": "sub-1"}, ROLE_MAP)


def test_console_role_levels():
    assert console_role("platform") == ("admin", 2)
    assert console_role("security") == ("operator", 1)
    assert console_role("sre") == ("operator", 1)
    assert console_role("approver") == ("operator", 1)
    assert console_role("finops") == ("viewer", 0)
    assert console_role("developer") == ("viewer", 0)
    assert console_role("readonly") == ("viewer", 0)
