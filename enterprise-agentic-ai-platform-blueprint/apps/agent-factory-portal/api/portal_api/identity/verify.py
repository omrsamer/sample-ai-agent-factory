# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Verification of the caller's bearer token, inside every function that has a caller.

The API Gateway JWT authorizer verifies the token before a function is
invoked. The read API and the action functions verify it again themselves
and build the caller from the token alone. None of them reads the claims API
Gateway puts in the event, so an event made up by someone who can invoke a
function directly carries no weight: not to change something, and not to be
shown what a role is shown (an incident record, on the read API).

What is checked (``verify``):

- the algorithm is RS256 and nothing else, before any key is looked up;
- the key id names a key of the issuer's published key set, and the signature
  verifies against it;
- ``iss`` equals the configured issuer exactly;
- the audience is one of the configured ones: ``aud`` for an ID token and for
  Entra, ``client_id`` for a Cognito access token;
- for Cognito, ``token_use`` is the configured one (``id`` by default);
- ``exp`` is in the future, ``iat`` and ``nbf`` are not, with 60 seconds of leeway;
- ``exp``, ``iat``, ``iss`` and the subject claim are present;
- for Entra, the token is a person's: an app-only token is refused.

Keys are never used for longer than ``MAX_KEY_AGE_SECONDS`` after they were
fetched: a key the issuer has withdrawn must not be trusted for as long as
the issuer cannot be reached.

This module makes no AWS call. Its one network request is the HTTPS GET of the
issuer's key set (``fetch_keys``), which is cached in the execution
environment (``KeySet``).

It does not cover revocation: a token is accepted until it expires, as with
the authorizer.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from collections.abc import Callable
from typing import Any

import jwt

from portal_api.config import TokenSettings

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"
ACCESS = "access"  # the kind of Cognito token whose audience is in client_id
LEEWAY_SECONDS = 60
# The claim that names the person, per identity provider.
SUBJECT_CLAIM = {"cognito": "sub", "entra": "oid"}
# How long fetched keys are used before they are fetched again.
CACHE_SECONDS = 12 * 60 * 60
# How long fetched keys are used at all. A refresh that fails keeps the keys it had, but not past
# this: after it no token is verified until a fetch succeeds (503).
MAX_KEY_AGE_SECONDS = 48 * 60 * 60
# Once keys are cached: at most one refresh this often, whether for an unknown key id or for age.
# A token with an invented key id therefore cannot make the function fetch on every request.
REFRESH_SECONDS = 5 * 60
# With no key cached at all, a fetch is tried at most this often.
RETRY_EMPTY_SECONDS = 5
FETCH_TIMEOUT_SECONDS = 3
MAX_KEYSET_BYTES = 256 * 1024
MAX_TOKEN_CHARACTERS = 16 * 1024


class TokenRejected(Exception):
    """The token is not acceptable (HTTP 401). The reason is for the function's log, never for the caller."""


class KeysUnavailable(Exception):
    """The issuer's keys could not be fetched and none are cached, so no token can be verified (HTTP 503)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The key set is read from the configured address and from nowhere it points to."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def fetch_keys(url: str) -> dict[str, Any]:
    """The issuer's key set document. The one network request this module makes."""
    if not url.startswith("https://"):
        raise ValueError("the key set address is not an https address")
    request = urllib.request.Request(  # noqa: S310 - https only, checked above and in the configuration
        url, headers={"Accept": "application/json", "User-Agent": "agent-factory-portal"}
    )
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        body = response.read(MAX_KEYSET_BYTES + 1)
    if len(body) > MAX_KEYSET_BYTES:
        raise ValueError("the key set is larger than expected")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise ValueError("the key set is not a JSON object")
    return document


def parse_keys(document: Any) -> dict[str, Any]:
    """The RSA signing keys of a key set, by key id. Anything else in the set is ignored."""
    keys: dict[str, Any] = {}
    items = document.get("keys") if isinstance(document, dict) else None
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        kid = item.get("kid")
        if not isinstance(kid, str) or not kid or item.get("kty") != "RSA" or item.get("use", "sig") != "sig":
            continue
        try:
            keys[kid] = jwt.PyJWK(item, algorithm=ALGORITHM).key
        except jwt.PyJWTError:
            continue
    return keys


class KeySet:
    """The issuer's signing keys, fetched when needed and kept in the execution environment.

    - Nothing cached: the keys are fetched (at most every ``RETRY_EMPTY_SECONDS``).
      If that fails, ``KeysUnavailable``.
    - Cached keys are used for ``CACHE_SECONDS`` and then fetched again.
    - A key id that is not cached triggers one refresh. The key is then either
      there or the token is rejected.
    - Once keys are cached there is at most one refresh every
      ``REFRESH_SECONDS``, and a refresh that fails keeps the keys it had.
    - Keys older than ``MAX_KEY_AGE_SECONDS`` are not used. They count as no
      keys at all: a fetch is tried at most every ``RETRY_EMPTY_SECONDS``,
      and until one succeeds, ``KeysUnavailable``.
    """

    def __init__(
        self,
        url: str,
        fetch: Callable[[str], dict[str, Any]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None

    def key(self, kid: str) -> Any:
        with self._lock:
            now = self._clock()
            if not self._keys or self._too_old(now):
                self._refresh(now, RETRY_EMPTY_SECONDS)
                if not self._keys or self._too_old(now):
                    raise KeysUnavailable("the issuer's signing keys are not available")
            elif kid not in self._keys or now - (self._fetched_at or now) >= CACHE_SECONDS:
                self._refresh(now, REFRESH_SECONDS)
            key = self._keys.get(kid)
            if key is None:
                raise TokenRejected("the token's key id is not one of the issuer's keys")
            return key

    def _too_old(self, now: float) -> bool:
        """Whether the cached keys were fetched too long ago to be used at all."""
        return self._fetched_at is not None and now - self._fetched_at >= MAX_KEY_AGE_SECONDS

    def _refresh(self, now: float, at_most_every: float) -> None:
        if self._attempted_at is not None and now - self._attempted_at < at_most_every:
            return
        self._attempted_at = now
        try:
            # Looked up here, not at construction, so that the module's fetcher can be replaced.
            keys = parse_keys((self._fetch or fetch_keys)(self.url))
        except Exception as exc:  # noqa: BLE001 - whatever went wrong, the keys already cached stay
            logger.warning("The issuer's signing keys could not be fetched: %s", type(exc).__name__)
            return
        if not keys:
            logger.warning("The issuer's key set holds no usable signing key")
            return
        self._keys, self._fetched_at = keys, now


_keysets: dict[str, KeySet] = {}
_keysets_lock = threading.Lock()


def keys_for(url: str) -> KeySet:
    """The one ``KeySet`` of this execution environment for a key set address."""
    with _keysets_lock:
        if url not in _keysets:
            _keysets[url] = KeySet(url)
        return _keysets[url]


def verify(token: Any, settings: TokenSettings, keys: KeySet) -> dict[str, Any]:
    """The token's claims, or ``TokenRejected``. ``KeysUnavailable`` when no key can be had at all."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARACTERS:
        raise TokenRejected("the token is empty or too long")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenRejected("the token is not a signed JWT") from exc
    # Refused before any key is looked up: "none", and the HMAC algorithms, for which the
    # issuer's public key would be the secret.
    if header.get("alg") != ALGORITHM:
        raise TokenRejected("the token's algorithm is not RS256")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenRejected("the token names no key")
    key = keys.key(kid)
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=[ALGORITHM],
            issuer=settings.issuer,
            leeway=LEEWAY_SECONDS,
            options={
                "require": ["exp", "iat", "iss", SUBJECT_CLAIM[settings.provider]],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_iss": True,
                # Checked below: the claim that holds the audience depends on the kind of token.
                "verify_aud": False,
            },
        )
    except jwt.PyJWTError as exc:
        # The class says which check failed. The message is not used: it can quote the token.
        raise TokenRejected(f"the token failed verification ({type(exc).__name__})") from exc
    if not isinstance(claims, dict):
        raise TokenRejected("the token's payload is not an object")
    _check_audience(claims, settings)
    if settings.provider == "cognito" and claims.get("token_use") != settings.token_use:
        raise TokenRejected(f"the token is not a Cognito {settings.token_use} token")
    if settings.provider == "entra":
        _refuse_app_only(claims)
    return claims


# Claims that only an Entra access token carries: the client that asked for it, and how it signed in.
_ENTRA_ACCESS_TOKEN_CLAIMS = ("scp", "azp", "azpacr", "appid", "appidacr")


def _refuse_app_only(claims: dict[str, Any]) -> None:
    """Refuse an Entra token that speaks for an application and not for a person.

    The portal's rules are about people: who registered, who approved, who
    contained. An application can get a token for the portal's audience with
    its own credentials, and if an app role is mapped to a portal role, that
    token would otherwise pass as a person. It is recognised two ways:

    - ``idtyp`` is ``app`` (an optional claim, present when the tenant emits it);
    - it is an access token (it carries one of the claims only an access
      token has) and has no ``scp``: a token a person signed in for always
      carries the scopes that person consented to.

    An ID token carries none of those claims and is accepted as before.
    """
    if claims.get("idtyp") == "app":
        raise TokenRejected("the token is an app-only token (idtyp)")
    scopes = claims.get("scp")
    if any(name in claims for name in _ENTRA_ACCESS_TOKEN_CLAIMS) and not (isinstance(scopes, str) and scopes.strip()):
        raise TokenRejected("the token is an access token with no delegated scope")


def _check_audience(claims: dict[str, Any], settings: TokenSettings) -> None:
    if settings.provider == "cognito" and settings.token_use == ACCESS:
        offered: list[Any] = [claims.get("client_id")]  # a Cognito access token has no aud
    else:
        audience = claims.get("aud")
        offered = list(audience) if isinstance(audience, (list, tuple)) else [audience]
    if not any(isinstance(value, str) and value in settings.audiences for value in offered):
        raise TokenRejected("the token was issued for another audience")
