# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bearer tokens for tests: key pairs made in the test run, tokens signed locally. Nothing touches the network."""

from __future__ import annotations

import functools
import json
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TESTPOOL1"
AUDIENCE = "portal-web-client-id"
KID = "test-key-1"


@functools.cache
def private_key(name: str = "issuer") -> rsa.RSAPrivateKey:
    """A key pair per name, made once per test run. ``issuer`` is the one the fake issuer publishes."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(kid: str = KID, key: rsa.RSAPrivateKey | None = None, **changes: Any) -> dict[str, Any]:
    """The public half of a key, as an issuer publishes it."""
    public = (key or private_key()).public_key()
    return {
        **json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public)),
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        **changes,
    }


def key_set(*keys: dict[str, Any]) -> dict[str, Any]:
    return {"keys": list(keys) if keys else [jwk()]}


def payload(claims: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    """The claims of an ID token of the test issuer. A value of ``...`` removes that claim."""
    now = int(time.time())
    merged = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "token_use": "id",
        "iat": now,
        "exp": now + 3600,
        **(claims or {}),
        **changes,
    }
    return {name: value for name, value in merged.items() if value is not ...}


def sign(
    claims: dict[str, Any] | None = None,
    *,
    kid: str | None = KID,
    key: rsa.RSAPrivateKey | None = None,
    **changes: Any,
) -> str:
    """A token signed with RS256 by the test issuer's key (or by ``key``), naming ``kid``.

    Signed at the lower level, which does not look at the claims, so that a
    test can make a token no issuer would (an issuer that is a list, a date
    that is a word).
    """
    headers = {"typ": "JWT", **({"kid": kid} if kid is not None else {})}
    body = json.dumps(payload(claims, **changes), separators=(",", ":")).encode()
    return jwt.PyJWS().encode(body, key or private_key(), algorithm="RS256", headers=headers)


_signed: dict[str, str] = {}


def for_claims(claims: dict[str, Any]) -> str:
    """A valid token for these claims, signed once per test run (it is good for an hour)."""
    key = json.dumps(claims, sort_keys=True, default=str)
    if key not in _signed:
        _signed[key] = sign(claims)
    return _signed[key]
