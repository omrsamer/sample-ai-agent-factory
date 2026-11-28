# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The action functions verify the caller's bearer token themselves.

Tokens are signed in the test with a key pair made in the test run, and the
issuer's key set is served by a fake fetcher. Nothing touches the network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from portal_api.actions import app as actions_app
from portal_api.config import ConfigError, TokenSettings, load_action_settings, load_sweeper_settings
from portal_api.identity import verify
from portal_api.identity.verify import KeySet, KeysUnavailable, TokenRejected
from tests import tokens
from tests.conftest import BASE_ENV
from tests.test_actions import BODY, DEV, PAT, VIEW
from tests.test_actions import World as RegistrationWorld
from tests.test_api import event
from tests.test_containment import SEC
from tests.test_containment import World as ContainmentWorld

ROOT = Path(__file__).resolve().parent.parent
# The real fetcher, taken before the fixture that replaces it for every test.
fetch_keys = verify.fetch_keys
JWKS_URL = f"{tokens.ISSUER}/.well-known/jwks.json"
SETTINGS = TokenSettings(
    provider="cognito", issuer=tokens.ISSUER, audiences=(tokens.AUDIENCE,), token_use="id", jwks_url=JWKS_URL
)
ACCESS = TokenSettings(
    provider="cognito", issuer=tokens.ISSUER, audiences=(tokens.AUDIENCE,), token_use="access", jwks_url=JWKS_URL
)
TENANT = "00000000-0000-0000-0000-000000000000"
ENTRA_ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
ENTRA = TokenSettings(
    provider="entra",
    issuer=ENTRA_ISSUER,
    audiences=("api://portal",),
    token_use="id",
    jwks_url="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/discovery/v2.0/keys",
)
PERSON = {"sub": "user-1", "email": "ana@example.com", "email_verified": True, "cognito:groups": ["devs"]}


class Issuer:
    """A key set address that counts its fetches and can be made to fail, with a clock the test moves."""

    def __init__(self) -> None:
        self.keys: Any = tokens.key_set()
        self.fetches = 0
        self.now = 1_000.0

    def fetch(self, url: str) -> dict[str, Any]:
        assert url == JWKS_URL
        self.fetches += 1
        if isinstance(self.keys, Exception):
            raise self.keys
        return self.keys

    def key_set(self) -> KeySet:
        return KeySet(JWKS_URL, fetch=self.fetch, clock=lambda: self.now)


@pytest.fixture
def issuer() -> Issuer:
    return Issuer()


def rejected(token: Any, settings: TokenSettings = SETTINGS, keys: KeySet | None = None) -> str:
    with pytest.raises(TokenRejected) as refused:
        verify.verify(token, settings, keys or Issuer().key_set())
    return str(refused.value)


# --- what a token must be ----------------------------------------------------------------------------


def test_a_valid_token_gives_its_claims(issuer):
    claims = verify.verify(tokens.sign(PERSON), SETTINGS, issuer.key_set())
    assert (claims["sub"], claims["email"], claims["cognito:groups"]) == ("user-1", "ana@example.com", ["devs"])
    assert (claims["iss"], claims["aud"], claims["token_use"]) == (tokens.ISSUER, tokens.AUDIENCE, "id")


def test_a_token_signed_with_another_key_is_rejected(issuer):
    forged = tokens.sign(PERSON, key=tokens.private_key("attacker"))  # names the issuer's key id
    assert "InvalidSignatureError" in rejected(forged, keys=issuer.key_set())


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unsigned(header: dict[str, Any], claims: dict[str, Any], signature: bytes = b"") -> str:
    body = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    return f"{body}.{_b64(signature)}"


def test_the_none_algorithm_is_refused_before_any_key_is_looked_up(issuer):
    for alg in ("none", "None", "NONE"):
        token = _unsigned({"alg": alg, "typ": "JWT", "kid": tokens.KID}, tokens.payload(PERSON))
        assert "algorithm is not RS256" in rejected(token, keys=issuer.key_set())
    assert issuer.fetches == 0


def test_an_hmac_token_signed_with_the_public_key_is_refused(issuer):
    """The classic confusion: the issuer's public key used as an HMAC secret."""
    public_pem = (
        tokens.private_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    for alg, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
        header = {"alg": alg, "typ": "JWT", "kid": tokens.KID}
        signing_input = _unsigned(header, tokens.payload(PERSON)).rsplit(".", 1)[0]
        signature = hmac.new(public_pem, signing_input.encode(), digest).digest()
        assert "algorithm is not RS256" in rejected(f"{signing_input}.{_b64(signature)}", keys=issuer.key_set())
    assert issuer.fetches == 0


@pytest.mark.parametrize("alg", ["RS384", "RS512", "PS256", "ES256"])
def test_only_rs256_is_accepted(issuer, alg):
    token = _unsigned({"alg": alg, "kid": tokens.KID}, tokens.payload(PERSON), b"x" * 256)
    assert "algorithm is not RS256" in rejected(token, keys=issuer.key_set())


@pytest.mark.parametrize(
    "issuer_claim",
    [
        "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHERPOOL",
        tokens.ISSUER + "/",
        tokens.ISSUER.upper(),
        tokens.ISSUER.replace("https://", "http://"),
        [tokens.ISSUER],
        "",
    ],
)
def test_the_issuer_must_be_exactly_the_configured_one(issuer_claim):
    assert "Error" in rejected(tokens.sign(PERSON, iss=issuer_claim))


def test_the_audience_must_be_a_configured_one():
    assert "another audience" in rejected(tokens.sign(PERSON, aud="another-client"))
    assert "another audience" in rejected(tokens.sign(PERSON, aud=...))
    assert "another audience" in rejected(tokens.sign(PERSON, aud=["another-client", "third"]))
    assert "another audience" in rejected(tokens.sign(PERSON, aud=[]))
    assert "another audience" in rejected(tokens.sign(PERSON, aud={"x": tokens.AUDIENCE}))
    # A token for several audiences is accepted when one of them is ours, and several can be configured.
    verify.verify(tokens.sign(PERSON, aud=["another-client", tokens.AUDIENCE]), SETTINGS, Issuer().key_set())
    two = TokenSettings("cognito", tokens.ISSUER, ("first-client", tokens.AUDIENCE), "id", JWKS_URL)
    verify.verify(tokens.sign(PERSON), two, Issuer().key_set())


def test_an_access_token_is_not_an_id_token_and_the_other_way_round():
    access = tokens.sign(PERSON, token_use="access", aud=..., client_id=tokens.AUDIENCE)
    # Where an ID token is expected, an access token is refused: it has no aud.
    assert "another audience" in rejected(access)
    # Even one that carries the audience is refused for what it is.
    assert "not a Cognito id token" in rejected(tokens.sign(PERSON, token_use="access"))
    assert "not a Cognito id token" in rejected(tokens.sign(PERSON, token_use=...))
    # Configured for access tokens, the audience is in client_id, and an ID token is refused.
    assert verify.verify(access, ACCESS, Issuer().key_set())["client_id"] == tokens.AUDIENCE
    assert "another audience" in rejected(tokens.sign(PERSON, token_use="access", aud=..., client_id="other"), ACCESS)
    assert "another audience" in rejected(tokens.sign(PERSON), ACCESS)  # an ID token has aud, not client_id
    assert "not a Cognito access token" in rejected(tokens.sign(PERSON, client_id=tokens.AUDIENCE), ACCESS)


def test_the_times_are_checked_with_a_minute_of_leeway():
    now = int(time.time())
    assert verify.LEEWAY_SECONDS == 60
    assert "ExpiredSignatureError" in rejected(tokens.sign(PERSON, exp=now - 120))
    assert "ImmatureSignatureError" in rejected(tokens.sign(PERSON, nbf=now + 300))
    assert "ImmatureSignatureError" in rejected(tokens.sign(PERSON, iat=now + 300))
    assert "InvalidIssuedAtError" in rejected(tokens.sign(PERSON, iat="yesterday"))
    # Within the leeway on either side: accepted.
    for changes in ({"exp": now - 30}, {"nbf": now + 30}, {"iat": now + 30}):
        verify.verify(tokens.sign(PERSON, **changes), SETTINGS, Issuer().key_set())


@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "sub"])
def test_a_token_without_a_required_claim_is_rejected(claim):
    assert "MissingRequiredClaimError" in rejected(tokens.sign(PERSON, **{claim: ...}))


@pytest.mark.parametrize(
    "token",
    [None, "", 42, b"bytes", "not-a-token", "a.b", "a.b.c", "a.b.c.d", "x" * (verify.MAX_TOKEN_CHARACTERS + 1)],
)
def test_something_that_is_not_a_token_is_rejected_without_a_fetch(issuer, token):
    with pytest.raises(TokenRejected):
        verify.verify(token, SETTINGS, issuer.key_set())
    assert issuer.fetches == 0


def test_a_token_that_names_no_key_is_rejected_without_a_fetch(issuer):
    assert "names no key" in rejected(tokens.sign(PERSON, kid=None), keys=issuer.key_set())
    assert "names no key" in rejected(tokens.sign(PERSON, kid=""), keys=issuer.key_set())
    # A key id that is not a string is no header the library accepts.
    token = _unsigned({"alg": "RS256", "kid": 7}, tokens.payload(PERSON), b"x" * 256)
    assert "not a signed JWT" in rejected(token, keys=issuer.key_set())
    assert issuer.fetches == 0


def test_an_entra_token_is_checked_by_its_own_claims(issuer):
    person = {"oid": "oid-1", "preferred_username": "ana@corp.example", "roles": ["Portal.Admin"]}

    def sign(**changes: Any) -> str:
        return tokens.sign(person, **{"iss": ENTRA_ISSUER, "aud": "api://portal", "token_use": ..., **changes})

    def keys() -> KeySet:
        return KeySet(ENTRA.jwks_url, fetch=lambda url: tokens.key_set())

    assert verify.verify(sign(), ENTRA, keys())["oid"] == "oid-1"  # no token_use is asked of it
    with pytest.raises(TokenRejected, match="MissingRequiredClaimError"):
        verify.verify(sign(oid=...), ENTRA, keys())  # the subject claim is oid, not sub
    with pytest.raises(TokenRejected, match="another audience"):
        verify.verify(sign(aud="api://other"), ENTRA, keys())
    with pytest.raises(TokenRejected, match="InvalidIssuerError"):
        verify.verify(sign(iss=tokens.ISSUER), ENTRA, keys())


# What an application gets with its own credentials, for the portal's audience. No person signed in.
APP_ONLY = {
    "idtyp says so": {"idtyp": "app"},
    "idtyp says so, whatever else is claimed": {"idtyp": "app", "scp": "Portal.Use", "azp": "client-1"},
    "a version 2.0 access token with app roles and no scope": {"azp": "client-1", "azpacr": "1"},
    "a version 1.0 access token with app roles and no scope": {"appid": "client-1", "appidacr": "1"},
    "an access token whose scope is empty": {"azp": "client-1", "scp": ""},
    "an access token whose scope is blank": {"azp": "client-1", "scp": "  "},
    "an access token whose scope is not text": {"azp": "client-1", "scp": ["Portal.Use"]},
}
# What a person signed in for.
A_PERSONS = {
    "an ID token": {},
    "an ID token that says it is a user's": {"idtyp": "user"},
    "a delegated access token": {"azp": "client-1", "azpacr": "0", "scp": "Portal.Use"},
    "a delegated version 1.0 access token": {"appid": "client-1", "appidacr": "0", "scp": "Portal.Use User.Read"},
}


def entra_token(**claims: Any) -> str:
    person = {"oid": "oid-1", "preferred_username": "ana@corp.example", "roles": ["Portal.Admin"]}
    return tokens.sign({**person, **claims}, iss=ENTRA_ISSUER, aud="api://portal", token_use=...)


@pytest.mark.parametrize("claims", APP_ONLY.values(), ids=APP_ONLY.keys())
def test_an_entra_app_only_token_is_not_a_person(claims):
    """An app role mapped to a portal role would otherwise let an application act as a person."""
    keys = KeySet(ENTRA.jwks_url, fetch=lambda url: tokens.key_set())
    with pytest.raises(TokenRejected, match="app-only token|no delegated scope"):
        verify.verify(entra_token(**claims), ENTRA, keys)


@pytest.mark.parametrize("claims", A_PERSONS.values(), ids=A_PERSONS.keys())
def test_an_entra_token_a_person_signed_in_for_is_accepted(claims):
    keys = KeySet(ENTRA.jwks_url, fetch=lambda url: tokens.key_set())
    assert verify.verify(entra_token(**claims), ENTRA, keys)["oid"] == "oid-1"


def test_the_app_only_rule_is_entras_and_does_not_touch_a_cognito_token(issuer):
    # A Cognito access token carries a client and a scope claim of its own kind, and no ``scp``.
    token = tokens.sign(PERSON, token_use="access", aud=..., client_id=tokens.AUDIENCE, azp="x", idtyp="app")
    assert verify.verify(token, ACCESS, issuer.key_set())["sub"] == "user-1"


# --- the issuer's keys -------------------------------------------------------------------------------


def test_the_keys_are_fetched_once_and_then_kept(issuer):
    keys = issuer.key_set()
    for _ in range(25):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
        issuer.now += 60
    assert issuer.fetches == 1
    # After twelve hours they are fetched again.
    assert verify.CACHE_SECONDS == 12 * 60 * 60
    issuer.now += verify.CACHE_SECONDS
    verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    assert issuer.fetches == 2


def test_an_unknown_key_id_gets_one_refresh_and_no_more_for_five_minutes(issuer):
    keys = issuer.key_set()
    verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    assert issuer.fetches == 1
    invented = tokens.sign(PERSON, kid="invented", key=tokens.private_key("attacker"))
    # The keys were fetched a moment ago: a key the issuer uses would be among them.
    assert "not one of the issuer's keys" in rejected(invented, keys=keys)
    assert issuer.fetches == 1
    issuer.now += verify.REFRESH_SECONDS
    assert "not one of the issuer's keys" in rejected(invented, keys=keys)
    assert issuer.fetches == 2  # one refresh, to see whether the issuer has a new key
    # Any number of such tokens: no further fetch, and the known key keeps working.
    for n in range(50):
        other = tokens.sign(PERSON, kid=f"invented-{n}", key=tokens.private_key("attacker"))
        assert "not one of the issuer's keys" in rejected(other, keys=keys)
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
        issuer.now += 5
    assert issuer.fetches == 2
    assert verify.REFRESH_SECONDS == 5 * 60
    issuer.now += verify.REFRESH_SECONDS
    assert "not one of the issuer's keys" in rejected(invented, keys=keys)
    assert issuer.fetches == 3


def test_a_key_the_issuer_rotated_in_is_found_by_the_refresh(issuer):
    keys = issuer.key_set()
    verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    new_key = tokens.private_key("rotated")
    issuer.keys = tokens.key_set(tokens.jwk(), tokens.jwk("test-key-2", new_key))
    issuer.now += verify.REFRESH_SECONDS
    assert verify.verify(tokens.sign(PERSON, kid="test-key-2", key=new_key), SETTINGS, keys)["sub"] == "user-1"
    assert issuer.fetches == 2
    # A key the issuer withdrew stops working once the set has been fetched again.
    issuer.keys = tokens.key_set(tokens.jwk("test-key-2", new_key))
    issuer.now += verify.CACHE_SECONDS
    assert "not one of the issuer's keys" in rejected(tokens.sign(PERSON), keys=keys)


def test_with_no_key_at_all_nothing_can_be_verified(issuer):
    issuer.keys = OSError("no route to the issuer")
    keys = issuer.key_set()
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    assert issuer.fetches == 1
    # Not hammered: one attempt every five seconds while there is nothing.
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    assert issuer.fetches == 1
    issuer.now += verify.RETRY_EMPTY_SECONDS
    issuer.keys = tokens.key_set()
    assert verify.verify(tokens.sign(PERSON), SETTINGS, keys)["sub"] == "user-1"
    assert issuer.fetches == 2


def test_a_refresh_that_fails_keeps_the_keys_it_had(issuer):
    keys = issuer.key_set()
    verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    issuer.keys = TimeoutError("the issuer did not answer")
    issuer.now += verify.CACHE_SECONDS + 1
    for _ in range(3):
        assert verify.verify(tokens.sign(PERSON), SETTINGS, keys)["sub"] == "user-1"
    assert issuer.fetches == 2  # tried once, and not again within five minutes
    # A key set with nothing usable in it is a failed refresh too.
    issuer.keys = {"keys": []}
    issuer.now += verify.REFRESH_SECONDS
    assert verify.verify(tokens.sign(PERSON), SETTINGS, keys)["sub"] == "user-1"
    assert issuer.fetches == 3


def test_keys_are_not_used_for_longer_than_two_days_after_they_were_fetched(issuer):
    """A refresh that fails keeps the keys it had, but a key the issuer withdrew must not be trusted for ever."""
    assert verify.MAX_KEY_AGE_SECONDS == 48 * 60 * 60
    keys = issuer.key_set()
    verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    issuer.keys = TimeoutError("the issuer cannot be reached")
    # Up to two days after the last fetch that worked, the keys it gave are used.
    issuer.now += verify.MAX_KEY_AGE_SECONDS - 1
    assert verify.verify(tokens.sign(PERSON), SETTINGS, keys)["sub"] == "user-1"
    # Not a second longer: no token is verified until the issuer answers again.
    issuer.now += 1
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    fetches = issuer.fetches
    # Keys that old count as none: a fetch is tried at most every five seconds.
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    assert issuer.fetches == fetches
    issuer.now += verify.RETRY_EMPTY_SECONDS
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    assert issuer.fetches == fetches + 1
    # A key set with nothing usable in it does not make them young again either.
    issuer.keys = {"keys": []}
    issuer.now += verify.RETRY_EMPTY_SECONDS
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)
    # The issuer answers: the keys it publishes now are used at once, and the withdrawn one is gone.
    issuer.keys = tokens.key_set(tokens.jwk("rotated-key", tokens.private_key("rotated")))
    issuer.now += verify.RETRY_EMPTY_SECONDS
    rotated = tokens.sign(PERSON, kid="rotated-key", key=tokens.private_key("rotated"))
    assert verify.verify(rotated, SETTINGS, keys)["sub"] == "user-1"
    with pytest.raises(TokenRejected, match="not one of the issuer's keys"):
        verify.verify(tokens.sign(PERSON), SETTINGS, keys)


@pytest.mark.parametrize(
    "document",
    [{}, {"keys": []}, {"keys": "x"}, [], None, {"keys": [None, 1, {}, {"kid": "a"}, {"kid": "b", "kty": "EC"}]}],
)
def test_a_key_set_with_no_usable_key_is_no_key_set(issuer, document):
    issuer.keys = document
    with pytest.raises(KeysUnavailable):
        verify.verify(tokens.sign(PERSON), SETTINGS, issuer.key_set())


def test_only_rsa_signing_keys_with_a_key_id_are_taken_from_a_key_set():
    good = tokens.jwk()
    without_use = {k: v for k, v in tokens.jwk("no-use").items() if k != "use"}
    keys = verify.parse_keys(
        {
            "keys": [
                good,
                without_use,
                tokens.jwk("for-encryption", use="enc"),
                tokens.jwk("", use="sig"),
                {**tokens.jwk("broken"), "n": "!!!"},
                {"kty": "oct", "kid": "shared-secret", "k": "c2VjcmV0"},
                {"kty": "EC", "kid": "curve", "crv": "P-256", "x": "AA", "y": "AA"},
            ]
        }
    )
    assert sorted(keys) == ["no-use", tokens.KID]


def test_the_key_set_is_read_over_https_from_the_configured_address_only(monkeypatch):
    with pytest.raises(ValueError, match="https"):
        fetch_keys("http://issuer.example.com/keys")

    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return self.body[:limit]

    seen: dict[str, Any] = {}

    class Opener:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def open(self, request: Any, timeout: float) -> Response:
            seen.update(url=request.full_url, timeout=timeout, headers=dict(request.header_items()))
            return Response(self.body)

    def opener_for(body: bytes) -> None:
        def build(*handlers: Any) -> Opener:
            seen["handlers"] = handlers
            return Opener(body)

        monkeypatch.setattr(verify.urllib.request, "build_opener", build)

    opener_for(json.dumps(tokens.key_set()).encode())
    assert fetch_keys(JWKS_URL)["keys"][0]["kid"] == tokens.KID
    assert (seen["url"], seen["timeout"]) == (JWKS_URL, 3)
    # A redirect is not followed: the keys come from the configured address or not at all.
    (handler,) = seen["handlers"]
    assert handler().redirect_request(None, None, 302, "Found", {}, "https://elsewhere.example.com/keys") is None
    opener_for(b"x" * (verify.MAX_KEYSET_BYTES + 1))
    with pytest.raises(ValueError, match="larger"):
        fetch_keys(JWKS_URL)
    opener_for(b"[1, 2]")
    with pytest.raises(ValueError, match="JSON object"):
        fetch_keys(JWKS_URL)


# --- through the functions' handlers ---------------------------------------------------------------------


@pytest.fixture
def registration(monkeypatch: pytest.MonkeyPatch) -> RegistrationWorld:
    return RegistrationWorld(monkeypatch)


@pytest.fixture
def containment(monkeypatch: pytest.MonkeyPatch) -> ContainmentWorld:
    return ContainmentWorld(monkeypatch)


def send(
    world: Any,
    function: str,
    method: str,
    path: str,
    *,
    context_claims: dict[str, Any] | None = None,
    authorization: str | None = None,
    body: Any = None,
) -> tuple[int, Any]:
    """One request to an action function: the authorizer context and the Authorization header set apart."""
    world.monkeypatch.setenv("PORTAL_ACTION_ROLE", function)
    request = event(path, method, None)
    if context_claims is not None:
        request["requestContext"]["authorizer"] = {"jwt": {"claims": context_claims, "scopes": []}}
    if authorization is not None:
        request["headers"]["authorization"] = authorization
    if body is not None:
        request["body"] = json.dumps(body)
        request["headers"]["content-type"] = "application/json"
    handler = world.handlers[function] if hasattr(world, "handlers") else world.handler
    response = handler(request, None)
    return response["statusCode"], json.loads(response["body"])


CREATE = ("registrar", "POST", "/registrations")


def test_claims_in_the_event_without_a_token_carry_no_weight(registration, containment):
    """What a caller who can invoke a function directly would send: claims of its own making, and no token."""
    forged = {"sub": "pat-1", "cognito:groups": "[platform-admins]"}
    record_id = registration.new_record("PENDING_APPROVAL")
    written = len(registration.dynamo.events())
    registration.registry.calls.clear()
    attempts = [
        (registration, *CREATE, {**BODY, "agent_id": "forged"}),
        (registration, "registrar", "DELETE", f"/registrations/{record_id}", None),
        (registration, "approver", "POST", f"/registrations/{record_id}/approve", {"reason": "forged"}),
        (registration, "approver", "POST", f"/registrations/{record_id}/retire", {"reason": "forged"}),
        (containment, "containment", "POST", f"/agents/{containment.record_id}/containment/contain", {"reason": "x"}),
        (containment, "containment", "POST", f"/agents/{containment.record_id}/containment/release", {"reason": "x"}),
    ]
    for world, function, method, path, body in attempts:
        assert send(world, function, method, path, context_claims=forged, body=body) == (
            401,
            {"detail": "Not authenticated"},
        )
    assert registration.registry.calls == [] and len(registration.dynamo.events()) == written
    assert registration.status(record_id) == "PENDING_APPROVAL"
    assert containment.cell.calls == [] and containment.dynamo.items == {} and containment.registry.calls == []


def test_the_caller_is_the_one_the_token_names_whatever_the_event_claims(registration):
    """Forged claims beside a real token: the token decides."""
    forged = {"sub": "pat-1", "cognito:groups": "[platform-admins]"}
    code, body = send(
        registration,
        *CREATE,
        context_claims=forged,
        authorization=f"Bearer {tokens.sign(VIEW)}",  # a read-only user's genuine token
        body=BODY,
    )
    assert code == 403 and "REG-07-N" in body["detail"]
    assert registration.registry.records == {}
    # And the other way round: a registrar's token, with claims in the event that would refuse.
    code, body = send(registration, *CREATE, context_claims=VIEW, authorization=f"Bearer {tokens.sign(DEV)}", body=BODY)
    assert code == 201
    created = registration.dynamo.events()[-1]
    assert (created["actor_subject"], created["actor_label"]) == ("dev-1", "dev@example.com")


@pytest.mark.parametrize(
    "authorization",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "Token abc",
        "Bearer not-a-token",
        "Bearer a b",
        "bearer",
    ],
)
def test_a_header_that_holds_no_usable_token_is_401(registration, authorization):
    assert send(registration, *CREATE, authorization=authorization, body=BODY) == (
        401,
        {"detail": "Not authenticated"},
    )


def test_a_token_that_fails_any_check_is_401_and_the_reason_stays_in_the_log(registration, caplog):
    now = int(time.time())
    bad = {
        "signed by another key": tokens.sign(PAT, key=tokens.private_key("attacker")),
        "expired": tokens.sign(PAT, exp=now - 3600),
        "for another audience": tokens.sign(PAT, aud="another-client"),
        "from another issuer": tokens.sign(PAT, iss="https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHERPOOL"),
        "an access token": tokens.sign(PAT, token_use="access"),
        "no subject": tokens.sign(PAT, sub=...),
        "unknown key": tokens.sign(PAT, kid="invented", key=tokens.private_key("attacker")),
    }
    for token in bad.values():
        with caplog.at_level("WARNING", logger="portal_api.actions"):
            caplog.clear()
            answer = send(registration, *CREATE, authorization=f"Bearer {token}", body=BODY)
        assert answer == (401, {"detail": "Not authenticated"})  # the caller is told nothing more
        logged = " ".join(record.getMessage() for record in caplog.records)
        assert "Bearer token not accepted" in logged and token not in logged
    assert registration.registry.records == {} and registration.dynamo.items == {}
    # The scheme's case does not matter, and a valid token still works.
    assert send(registration, *CREATE, authorization=f"bearer {tokens.sign(DEV)}", body=BODY)[0] == 201


def test_when_the_issuers_keys_cannot_be_had_the_answer_is_503_and_nothing_is_done(registration, issuer_keys):
    def unreachable(url: str) -> dict[str, Any]:
        raise OSError("no route to the issuer")

    issuer_keys.answer[0] = unreachable
    code, body = send(registration, *CREATE, authorization=f"Bearer {tokens.sign(DEV)}", body=BODY)
    assert (code, body) == (503, {"detail": actions_app.KEYS_UNAVAILABLE})
    assert "Nothing was done" in body["detail"]
    assert registration.registry.calls == [] and registration.dynamo.items == {}


def test_the_keys_are_fetched_from_the_issuer_once_for_many_requests(registration, issuer_keys):
    for n in range(5):
        code, _ = send(
            registration, *CREATE, authorization=f"Bearer {tokens.sign(DEV)}", body={**BODY, "agent_id": f"agent-{n}"}
        )
        assert code == 201
    assert issuer_keys.fetched == [JWKS_URL]  # where Amazon Cognito publishes a user pool's keys


def test_the_three_action_functions_and_the_read_api_all_verify_the_token_themselves(registration, containment):
    garbage = "Bearer not-a-token"
    assert send(registration, *CREATE, authorization=garbage, body=BODY)[0] == 401
    assert (
        send(registration, "approver", "POST", "/registrations/rec000000001/approve", authorization=garbage)[0] == 401
    )
    path = f"/agents/{containment.record_id}/containment/contain"
    assert send(containment, "containment", "POST", path, authorization=garbage, body={"reason": "x"})[0] == 401
    # The read API does the same: the claims in the event beside a token it cannot verify count for nothing.
    registration.monkeypatch.delenv("PORTAL_ACTION_ROLE", raising=False)
    request = event("/registrations", "GET", VIEW, headers={"authorization": garbage})
    assert registration.handlers["read"](request, None)["statusCode"] == 401
    assert registration.handlers["read"](event("/registrations", "GET", VIEW), None)["statusCode"] == 200
    # One function says who the caller is, for all four.
    script = (
        "import sys, handler\n"
        "assert 'portal_api.identity.verify' in sys.modules\n"
        "assert not [m for m in sys.modules if m.startswith('portal_api.actions')]\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0 and result.stdout.strip() == "ok", result.stderr
    assert actions_app.action_principal.__module__ == "portal_api.actions.app"
    assert "principal_from_request(request, settings)" in Path(actions_app.__file__).read_text()


def test_a_verified_boolean_claim_is_read_as_one(registration):
    """In a token a boolean is a boolean; through API Gateway it is a string. Both mean the same."""
    claims = {"sub": "dev-9", "email": "nia@example.com", "email_verified": True, "cognito:groups": ["devs"]}
    assert send(registration, *CREATE, authorization=f"Bearer {tokens.sign(claims)}", body=BODY)[0] == 201
    assert registration.dynamo.events()[-1]["actor_label"] == "nia@example.com"


# --- local development --------------------------------------------------------------------------------


def test_the_header_identity_of_local_development_still_works_and_never_inside_lambda(registration, monkeypatch):
    monkeypatch.setenv("PORTAL_DEV_AUTH", "1")
    registration.monkeypatch.setenv("PORTAL_ACTION_ROLE", "registrar")
    request = event(
        "/registrations", "POST", None, headers={"x-portal-dev-user": "dev@example.com", "x-portal-dev-groups": "devs"}
    )
    request["body"] = json.dumps(BODY)
    request["headers"]["content-type"] = "application/json"
    assert registration.handlers["registrar"](request, None)["statusCode"] == 201
    # Local development needs no token settings at all, as long as none is set.
    env = {k: v for k, v in BASE_ENV.items() if not k.startswith(("PORTAL_JWT", "PORTAL_JWKS"))}
    env = {**env, "PORTAL_ACTION_ROLE": "registrar", "PORTAL_DEV_AUTH": "1"}
    assert load_action_settings(env).token is None
    with pytest.raises(ConfigError, match="PORTAL_JWT_AUDIENCE"):
        load_action_settings({**env, "PORTAL_JWT_ISSUER": tokens.ISSUER})  # half set is a mistake, not development
    # Inside AWS Lambda the switch does nothing: the headers are ignored and the settings are required.
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "portal-registrar")
    request["body"] = json.dumps({**BODY, "agent_id": "second"})
    assert registration.handlers["registrar"](request, None)["statusCode"] == 401
    with pytest.raises(ConfigError, match="PORTAL_JWT_ISSUER"):
        load_action_settings({**env, "AWS_LAMBDA_FUNCTION_NAME": "portal-registrar"})


# --- configuration ------------------------------------------------------------------------------------


def action_env(role: str = "registrar", **changes: Any) -> dict[str, str]:
    env = {**BASE_ENV, "PORTAL_ACTION_ROLE": role, **{k: v for k, v in changes.items() if v is not None}}
    return {k: v for k, v in env.items() if changes.get(k, "") is not None}


@pytest.mark.parametrize("role", ["registrar", "approver", "containment"])
def test_every_action_function_needs_the_token_settings(role):
    token = load_action_settings(action_env(role)).token
    assert token == TokenSettings("cognito", tokens.ISSUER, (tokens.AUDIENCE,), "id", JWKS_URL)
    for name, said in (
        ("PORTAL_JWT_ISSUER", "need the token issuer"),
        ("PORTAL_JWT_AUDIENCE", "need the accepted audiences"),
    ):
        with pytest.raises(ConfigError) as error:
            load_action_settings(action_env(role, **{name: None}))
        # The message names the variable and says why it is needed.
        assert name in str(error.value) and "verify the caller's token themselves" in str(error.value)
        assert said in str(error.value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PORTAL_JWT_ISSUER", "cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TESTPOOL1"),
        ("PORTAL_JWT_ISSUER", "http://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TESTPOOL1"),
        ("PORTAL_JWT_ISSUER", "https://example.com/eu-west-1_TESTPOOL1"),  # not a user pool
        ("PORTAL_JWT_ISSUER", tokens.ISSUER + "/"),
        ("PORTAL_JWT_AUDIENCE", "portal-web-client-id"),
        ("PORTAL_JWT_AUDIENCE", '"portal-web-client-id"'),
        ("PORTAL_JWT_AUDIENCE", "[]"),
        ("PORTAL_JWT_AUDIENCE", '[""]'),
        ("PORTAL_JWT_AUDIENCE", '["has space"]'),
        ("PORTAL_JWT_AUDIENCE", "[1]"),
        ("PORTAL_JWT_TOKEN_USE", "refresh"),
        ("PORTAL_JWKS_URL", "http://issuer.example.com/keys"),
        ("PORTAL_JWKS_URL", "keys.json"),
    ],
)
def test_a_malformed_token_setting_is_a_configuration_error(name, value):
    with pytest.raises(ConfigError, match=name):
        load_action_settings(action_env(**{name: value}))


def test_token_settings_for_access_tokens_and_entra():
    access = load_action_settings(action_env(PORTAL_JWT_TOKEN_USE="access")).token
    assert access is not None and access.token_use == "access"
    # Entra: the issuer has one of its two forms, and the address of the keys must be given.
    entra = action_env(
        PORTAL_IDENTITY_PROVIDER="entra", PORTAL_JWT_ISSUER=ENTRA_ISSUER, PORTAL_JWT_AUDIENCE='["api://portal"]'
    )
    with pytest.raises(ConfigError, match="PORTAL_JWKS_URL is not set"):
        load_action_settings(entra)
    token = load_action_settings({**entra, "PORTAL_JWKS_URL": ENTRA.jwks_url}).token
    assert token == ENTRA
    # The issuer of version 1.0 tokens names the same tenant, and so the same key set.
    v1 = {**entra, "PORTAL_JWT_ISSUER": f"https://sts.windows.net/{TENANT}/", "PORTAL_JWKS_URL": ENTRA.jwks_url}
    assert load_action_settings(v1).token.jwks_url == ENTRA.jwks_url


OTHER_TENANT = "11111111-1111-1111-1111-111111111111"


@pytest.mark.parametrize(
    "address",
    [
        "https://keys.example.com/pool/jwks.json",  # another host: whoever runs it would sign portal tokens
        "https://login.microsoftonline.com.example.com/00000000-0000-0000-0000-000000000000/discovery/v2.0/keys",
        f"https://login.microsoftonline.com/{OTHER_TENANT}/discovery/v2.0/keys",  # another tenant's keys
        "https://login.microsoftonline.com/common/discovery/v2.0/keys",  # every tenant's keys
        "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/discovery/keys",
        "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/discovery/v2.0/keys/",
        "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/discovery/v2.0/keys?x=1",
        "http://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/discovery/v2.0/keys",
        "https://LOGIN.microsoftonline.com/00000000-0000-0000-0000-000000000000/discovery/v2.0/keys",
    ],
)
def test_an_entra_key_set_is_read_only_from_the_issuers_own_tenant(address):
    """The key set address decides who is believed, so it is not free: it follows from the issuer."""
    from portal_api import config

    assert config.ENTRA_KEY_HOSTS == ("login.microsoftonline.com",)  # the hosts, in one place
    entra = action_env(
        PORTAL_IDENTITY_PROVIDER="entra",
        PORTAL_JWT_ISSUER=ENTRA_ISSUER,
        PORTAL_JWT_AUDIENCE='["api://portal"]',
        PORTAL_JWKS_URL=address,
    )
    with pytest.raises(ConfigError, match="PORTAL_JWKS_URL is malformed: for Microsoft Entra ID it must be"):
        load_action_settings(entra)


@pytest.mark.parametrize(
    "issuer",
    [
        "https://issuer.example.com/tenant",
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0/",
        "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000",
        "https://sts.windows.net/00000000-0000-0000-0000-000000000000",
        "https://login.microsoftonline.com/00000000-0000-0000-0000-00000000000O/v2.0",
    ],
)
def test_an_entra_issuer_names_one_tenant_in_one_of_its_two_forms(issuer):
    entra = action_env(
        PORTAL_IDENTITY_PROVIDER="entra",
        PORTAL_JWT_ISSUER=issuer,
        PORTAL_JWT_AUDIENCE='["api://portal"]',
        PORTAL_JWKS_URL=ENTRA.jwks_url,
    )
    with pytest.raises(ConfigError, match="PORTAL_JWT_ISSUER is malformed"):
        load_action_settings(entra)


def test_with_cognito_the_key_set_address_always_follows_from_the_issuer():
    """``PORTAL_JWKS_URL`` is for Entra. With Cognito an address of one's own choosing is refused, not used."""
    assert load_action_settings(action_env()).token.jwks_url == JWKS_URL
    assert load_action_settings(action_env(PORTAL_JWKS_URL=JWKS_URL)).token.jwks_url == JWKS_URL  # the same address
    for address in (
        "https://keys.example.com/pool/jwks.json",
        JWKS_URL.replace("eu-west-1", "us-east-1"),
        JWKS_URL + "x",
        ENTRA.jwks_url,
    ):
        with pytest.raises(ConfigError, match="PORTAL_JWKS_URL is not used with Amazon Cognito"):
            load_action_settings(action_env(PORTAL_JWKS_URL=address))


def test_a_function_without_the_token_settings_answers_500_and_names_the_variable(registration, monkeypatch):
    monkeypatch.delenv("PORTAL_JWT_ISSUER")
    code, body = send(registration, *CREATE, authorization=f"Bearer {tokens.sign(DEV)}", body=BODY)
    assert code == 500 and body["detail"].startswith("Portal configuration error: PORTAL_JWT_ISSUER is not set")
    assert registration.registry.calls == [] and registration.dynamo.items == {}


def test_the_sweeper_has_no_caller_and_needs_no_token_setting():
    env = {k: v for k, v in BASE_ENV.items() if not k.startswith("PORTAL_JWT")}
    assert load_sweeper_settings({**env, "PORTAL_ACTION_ROLE": "sweeper"}).audit_table == BASE_ENV["PORTAL_AUDIT_TABLE"]


def test_the_library_versions_are_pinned():
    pinned = dict(line.split("==") for line in (ROOT / "requirements.txt").read_text().splitlines() if "==" in line)
    assert pinned["PyJWT"] == jwt.__version__
    assert {"cryptography", "cffi", "pycparser"} <= set(pinned)


def test_the_contract_between_containment_and_registration_worlds_is_one_issuer(containment):
    """The containment function verifies with the same settings as the other two."""
    code, body = send(
        containment,
        "containment",
        "POST",
        f"/agents/{containment.record_id}/containment/contain",
        authorization=f"Bearer {tokens.sign(SEC)}",
        body={"reason": "Suspected prompt injection."},
    )
    assert code == 200 and body["state"] == "contained"
    assert containment.dynamo.events()[0]["actor_subject"] == "sec-1"


def test_the_documents_state_what_is_checked_and_what_is_not_covered():
    readme = " ".join((ROOT / "README.md").read_text().split())
    assert (verify.CACHE_SECONDS, verify.REFRESH_SECONDS, verify.LEEWAY_SECONDS) == (12 * 60 * 60, 5 * 60, 60)
    assert (verify.ALGORITHM, verify.FETCH_TIMEOUT_SECONDS) == ("RS256", 3)
    for said in (
        "`RS256` only",
        "`iss` equals `PORTAL_JWT_ISSUER` exactly",
        "with 60 seconds of leeway",
        "kept in the execution environment for 12 hours",
        "at most one refresh every 5 minutes",
        "A refresh that fails keeps the keys already there",
        "keys fetched more than 48 hours ago are not used",
        "a redirect is not followed",
        "the answer is `503` and nothing is done",
        # The address of the keys follows from the issuer.
        "**The address of the keys is not free to choose.**",
        "`https://login.microsoftonline.com/<that tenant id>/discovery/v2.0/keys`",
        "`ENTRA_KEY_HOSTS` in `portal_api/config.py`",
        "`PORTAL_JWKS_URL` is not used, and setting it to any other address is a configuration error",
        # An application is not a person.
        "**A person's token (Entra):** an app-only token is refused",
        "`PORTAL_JWT_ISSUER`",
        "`PORTAL_JWT_AUDIENCE`",
        "`PORTAL_JWT_TOKEN_USE`",
        "`PORTAL_JWKS_URL`",
        # Every function that has a caller verifies the token; what that does not cover, said plainly.
        "**No function takes the caller from the invocation event.**",
        "The read API verifies the caller's bearer token itself",
        "which is not signed",
        "**Invoking a function directly.**",
        "A token is accepted until it expires",
        # Who a person is, and what a record shows beside it.
        "The subject is the identity",
        "Every rule that compares people compares subjects",
        "The label is a reading aid, not an identity. It can change for the same person",
        "the `email` when `email_verified` is true",
        "the token has an `identities` claim",
        "`preferred_username`, as the directory holds it; else `upn`",
        "is never used for a record",
    ):
        assert said in readme, said
    assert "an identifier the person cannot change" not in readme
    assert "still trusts the claims" not in readme and "takes the caller from the claims" not in readme
    assert (verify.MAX_KEY_AGE_SECONDS, verify.RETRY_EMPTY_SECONDS) == (48 * 60 * 60, 5)
    contract = " ".join((ROOT / "ACTIONS_CONTRACT.md").read_text().split())
    assert "Never the display name" in contract and "The functions verify the token themselves" in contract
    assert "the person's identity: every rule compares this, and only this" in contract
    assert "cannot change themselves" not in contract
    iam = " ".join((ROOT / "IAM_ACTIONS.md").read_text().split())
    assert "That needs no IAM action" in iam and "outbound HTTPS" in iam
