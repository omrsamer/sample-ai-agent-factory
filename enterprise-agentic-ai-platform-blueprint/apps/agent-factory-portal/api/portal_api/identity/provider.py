# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Identity provider seam.

The API runs behind an Amazon API Gateway HTTP API whose JWT authorizer has
already validated signature, issuer and audience. This module only reads the
validated claims and turns them into a ``Principal``. Role comes from
``PORTAL_GROUP_ROLE_MAP``; the highest-privilege mapped role wins and a caller
with no mapped group has no access.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from portal_api.config import PORTAL_ROLES


class NotAuthenticated(Exception):
    """No usable validated identity on the request (HTTP 401)."""


class NotAuthorized(Exception):
    """Authenticated, but no group or app role maps to a portal role (HTTP 403)."""


@dataclass(frozen=True)
class Principal:
    subject: str
    email: str | None
    display_name: str | None
    groups: tuple[str, ...]
    role: str
    # A readable name for the record, when the token holds one that is not simply what the person
    # typed (see ``label``). ``None`` means the record shows the subject.
    recorded_as: str | None = None

    @property
    def label(self) -> str:
        """What is written beside the subject in a record, for a person to read.

        The subject is the identity. Every rule that compares people (the
        two-person rule, separation of duties) compares subjects, and every
        record stores the subject. The label is a reading aid next to it: an
        email or a user name where the token has one that the directory set
        or verified, else the subject again.

        It is not an identity and nothing is decided on it. An email can
        change: a local Cognito user can change theirs and verify the new
        one, and a directory can rename a user. A display name changes more
        freely still and is never used here; ``name`` is for showing callers
        their own name.
        """
        return self.recorded_as or self.subject

    @property
    def name(self) -> str:
        """The caller's own name, for display to the caller (``/users/me``). Never written to a record."""
        return self.display_name or self.email or self.subject


def parse_multi_value(value: Any) -> tuple[str, ...]:
    """Normalise a multi-valued claim.

    API Gateway HTTP APIs flatten array claims. A group claim can arrive as a
    real list, a JSON array string (``["a","b"]``), or a bracketed,
    space-separated string (``[a b]``). A bare string is a single value.
    """
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        items: Iterable[Any] = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return ()
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                items = parsed
            else:
                items = re.split(r"[\s,]+", text[1:-1].strip())
        else:
            items = [text]
    else:
        return ()
    seen: list[str] = []
    for item in items:
        if isinstance(item, str):
            cleaned = item.strip().strip('"')
            if cleaned and cleaned not in seen:
                seen.append(cleaned)
    return tuple(seen)


def parse_delimited(value: Any) -> tuple[str, ...]:
    """A claim that is a JSON array string, a bracketed list or a comma-separated string."""
    if isinstance(value, str) and "," in value and not value.strip().startswith("["):
        return parse_multi_value([part for part in value.split(",")])
    return parse_multi_value(value)


def resolve_role(groups: Iterable[str], role_map: Mapping[str, str]) -> str | None:
    """Highest-privilege portal role among the caller's mapped groups, or ``None``."""
    best = -1
    for group in groups:
        role = role_map.get(group)
        if role in PORTAL_ROLES:
            best = max(best, PORTAL_ROLES.index(role))
    return PORTAL_ROLES[best] if best >= 0 else None


def _text(claims: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        value = claims.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _display_name(claims: Mapping[str, Any]) -> str | None:
    """A human name for the caller, for display. The subject is the last resort (see ``Principal.name``)."""
    return _text(claims, "name", "email", "cognito:username", "preferred_username")


def _is_true(value: Any) -> bool:
    """A boolean claim. API Gateway passes it as the string ``true``; a verified token holds a boolean."""
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _present(value: Any) -> bool:
    """A claim that holds something: a non-empty list, or a string that is not an empty list."""
    if isinstance(value, str):
        return value.strip() not in ("", "[]", "null")
    return bool(value)


def _cognito_recorded_as(claims: Mapping[str, Any]) -> str | None:
    """The email, when it is more than what the person typed. A label to read, not an identity.

    - A federated user (the token has an ``identities`` claim): the email is
      the one the identity provider set.
    - A local user: only an email that Cognito has verified. An unverified
      one is whatever its owner typed. A verified one can still be replaced
      by its owner with another address they verify.
    """
    email = _text(claims, "email")
    if email and (_present(claims.get("identities")) or _is_true(claims.get("email_verified"))):
        return email
    return None


class IdentityProvider(Protocol):
    name: str

    def principal(self, claims: Mapping[str, Any] | None, role_map: Mapping[str, str]) -> Principal: ...


def _build(
    subject: str | None,
    email: str | None,
    display_name: str | None,
    groups: tuple[str, ...],
    role_map: Mapping[str, str],
    recorded_as: str | None = None,
) -> Principal:
    if not subject:
        raise NotAuthenticated("token has no subject")
    role = resolve_role(groups, role_map)
    if role is None:
        raise NotAuthorized("no group or app role maps to a portal role")
    return Principal(
        subject=subject, email=email, display_name=display_name, groups=groups, role=role, recorded_as=recorded_as
    )


class CognitoProvider:
    """Amazon Cognito ID tokens: groups in ``cognito:groups`` and ``custom:groups``, subject ``sub``."""

    name = "cognito"

    def principal(self, claims: Mapping[str, Any] | None, role_map: Mapping[str, str]) -> Principal:
        if not claims:
            raise NotAuthenticated("no validated claims on the request")
        # Users federated through a SAML identity provider carry their groups in custom:groups.
        groups = tuple(
            dict.fromkeys(
                (*parse_multi_value(claims.get("cognito:groups")), *parse_delimited(claims.get("custom:groups")))
            )
        )
        return _build(
            _text(claims, "sub"),
            _text(claims, "email"),
            _display_name(claims),
            groups,
            role_map,
            _cognito_recorded_as(claims),
        )


class EntraProvider:
    """Entra ID tokens: app roles in ``roles``, groups in ``groups``, subject ``oid``."""

    name = "entra"

    def principal(self, claims: Mapping[str, Any] | None, role_map: Mapping[str, str]) -> Principal:
        if not claims:
            raise NotAuthenticated("no validated claims on the request")
        roles = parse_multi_value(claims.get("roles"))
        groups = parse_multi_value(claims.get("groups"))
        merged = tuple(dict.fromkeys((*roles, *groups)))
        return _build(
            _text(claims, "oid"),
            _text(claims, "preferred_username", "email", "upn"),
            _display_name(claims),
            merged,
            role_map,
            # The user name as the directory holds it. A directory can change it, and for a guest
            # it is the guest's own address: a label to read, like the Cognito one.
            _text(claims, "preferred_username", "upn"),
        )


_PROVIDERS: dict[str, IdentityProvider] = {"cognito": CognitoProvider(), "entra": EntraProvider()}


def get_provider(name: str) -> IdentityProvider:
    return _PROVIDERS[name]


# Role levels follow the console's existing three-level model (viewer 0, operator 1, admin 2).
_CONSOLE_ROLE = {
    "platform": ("admin", 2),
    "security": ("operator", 1),
    "sre": ("operator", 1),
    "approver": ("operator", 1),
    "finops": ("viewer", 0),
    "developer": ("viewer", 0),
    "readonly": ("viewer", 0),
}


def console_role(portal_role: str) -> tuple[str, int]:
    """Map a portal role onto the console's ``role`` and ``role_level`` pair."""
    return _CONSOLE_ROLE[portal_role]
