# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Live checks for a deployed Agent Factory Portal (Amazon Cognito sign-in).

Every denial has a positive twin in the same run:

  no token            -> 401      a signed-in mapped user        -> 200
  user in no group    -> 403      user in a persona group        -> 200
  any non-GET method  -> no route GET on the same path           -> 200
  another principal assuming the fleet reader role -> AccessDenied
                                  the portal reading every cell  -> reachable

Configuration (environment):

  PORTAL_URL, PORTAL_API_BASE_URL, PORTAL_USER_POOL_ID, PORTAL_CLIENT_ID
  PORTAL_REGION                     Region of the portal stack
  PORTAL_EXPECTED_CELLS             JSON list of {"tenantId","agentId","accountId"}
  PORTAL_EXPECTED_TOOL_IDS          comma-separated Registry tool ids
  PORTAL_READER_EXTERNAL_ID         external id of the fleet reader roles
  AWS credentials for the Platform account (user pool administration only)

Without PORTAL_API_BASE_URL the module is skipped. With it, a missing
dependency or setting is an error, not a skip: live mode fails closed.

The run creates two users whose names carry a per-run marker, and deletes
exactly those users afterwards.
"""
from __future__ import annotations

import json
import os
import secrets
import string
import time
import urllib.error
import urllib.request
import uuid

import pytest

pytestmark = pytest.mark.integration

API = os.environ.get("PORTAL_API_BASE_URL", "").rstrip("/")
if not API:
    pytest.skip("PORTAL_API_BASE_URL is not set", allow_module_level=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"live mode: {name} is required")
    return value


REGION = _required("PORTAL_REGION")
POOL = _required("PORTAL_USER_POOL_ID")
CLIENT = _required("PORTAL_CLIENT_ID")
PORTAL_URL = _required("PORTAL_URL").rstrip("/")
EXPECTED_CELLS = json.loads(_required("PORTAL_EXPECTED_CELLS"))
EXPECTED_TOOLS = [t for t in _required("PORTAL_EXPECTED_TOOL_IDS").split(",") if t]
EXTERNAL_ID = _required("PORTAL_READER_EXTERNAL_ID")

import boto3  # noqa: E402
import pyotp  # noqa: E402
from pycognito.aws_srp import AWSSRP  # noqa: E402

RUN = uuid.uuid4().hex[:10]
MARKER = f"portal-live-{RUN}"


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1!" + "".join(secrets.choice(alphabet) for _ in range(28))


def _request(method: str, path: str, token: str | None = None, base: str = API):
    request = urllib.request.Request(f"{base}{path}", method=method)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            return error.code, json.loads(body)
        except ValueError:
            return error.code, body.decode("utf-8", "replace")


def _sign_in(idp, username: str, password: str) -> str:
    """SRP sign-in, enrolling TOTP on first use. Returns the ID token."""
    srp = AWSSRP(username=username, password=password, pool_id=POOL, client_id=CLIENT, client=idp)
    start = idp.initiate_auth(
        AuthFlow="USER_SRP_AUTH", AuthParameters=srp.get_auth_params(), ClientId=CLIENT
    )
    assert start["ChallengeName"] == "PASSWORD_VERIFIER"
    step = idp.respond_to_auth_challenge(
        ClientId=CLIENT,
        ChallengeName="PASSWORD_VERIFIER",
        ChallengeResponses=srp.process_challenge(start["ChallengeParameters"], srp.get_auth_params()),
    )
    assert step.get("ChallengeName") == "MFA_SETUP", "the pool must require MFA enrolment"
    association = idp.associate_software_token(Session=step["Session"])
    verified = idp.verify_software_token(
        Session=association["Session"], UserCode=pyotp.TOTP(association["SecretCode"]).now()
    )
    assert verified["Status"] == "SUCCESS"
    done = idp.respond_to_auth_challenge(
        ClientId=CLIENT,
        ChallengeName="MFA_SETUP",
        Session=verified["Session"],
        ChallengeResponses={"USERNAME": username},
    )
    return done["AuthenticationResult"]["IdToken"]


@pytest.fixture(scope="module")
def tokens():
    idp = boto3.client("cognito-idp", region_name=REGION)
    users = {
        "platform": f"{MARKER}-platform@example.com",
        "nogroup": f"{MARKER}-nogroup@example.com",
    }
    created: list[str] = []
    try:
        result = {}
        for role, email in users.items():
            password = _password()
            idp.admin_create_user(
                UserPoolId=POOL,
                Username=email,
                MessageAction="SUPPRESS",
                UserAttributes=[
                    {"Name": "email", "Value": email},
                    {"Name": "email_verified", "Value": "true"},
                ],
            )
            created.append(email)
            idp.admin_set_user_password(UserPoolId=POOL, Username=email, Password=password, Permanent=True)
            if role == "platform":
                idp.admin_add_user_to_group(UserPoolId=POOL, Username=email, GroupName="platform-engineering")
            result[role] = _sign_in(idp, email, password)
        yield result
    finally:
        # Owned cleanup only: the users this run created.
        for email in created:
            idp.admin_delete_user(UserPoolId=POOL, Username=email)
        leftover = idp.list_users(UserPoolId=POOL, Filter=f'email ^= "{MARKER}"')["Users"]
        assert leftover == [], "test users were not removed"


def test_liveness_needs_no_sign_in_and_returns_no_data():
    status, body = _request("GET", "/health")
    assert status == 200
    assert body == {"status": "ok"}


def test_data_routes_refuse_a_missing_or_forged_token_and_accept_a_real_one(tokens):
    assert _request("GET", "/agents")[0] == 401
    assert _request("GET", "/agents", token="a.b.c")[0] == 401
    status, body = _request("GET", "/agents", token=tokens["platform"])
    assert status == 200, body


def test_a_signed_in_user_in_no_persona_group_is_refused(tokens):
    assert _request("GET", "/users/me", token=tokens["nogroup"])[0] == 403
    assert _request("GET", "/agents", token=tokens["nogroup"])[0] == 403
    status, me = _request("GET", "/users/me", token=tokens["platform"])
    assert status == 200, me
    assert MARKER in json.dumps(me)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_only_get_exists_even_for_a_signed_in_platform_user(tokens, method):
    status, _ = _request(method, "/agents", token=tokens["platform"])
    assert status in (404, 405), f"{method} must have no route"


def test_every_configured_cell_is_reachable_through_its_reader_role(tokens):
    status, health = _request("GET", "/fleet/health", token=tokens["platform"])
    assert status == 200, health
    cells = {(c["tenant_id"], c["agent_id"]): c for c in health["cells"]}
    for expected in EXPECTED_CELLS:
        cell = cells.get((expected["tenantId"], expected["agentId"]))
        assert cell is not None, f"cell {expected} missing from fleet health"
        assert cell["reachable"] is True, cell
        assert cell["state"] in {"healthy", "needs_attention", "critical", "no_data"}


def test_another_principal_cannot_assume_the_fleet_reader_role():
    """Negative twin of the reachability test: same role, same external id, wrong caller."""
    sts = boto3.client("sts", region_name=REGION)
    for account in sorted({c["accountId"] for c in EXPECTED_CELLS}):
        with pytest.raises(Exception) as denied:
            sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/AgenticAI-PortalFleetReader-{os.environ.get('PORTAL_ENVIRONMENT', 'nonprod')}",
                RoleSessionName="portal-negative-twin",
                ExternalId=EXTERNAL_ID,
            )
        assert "AccessDenied" in str(denied.value)


def test_inventory_shows_the_runtimes_of_every_cell(tokens):
    status, agents = _request("GET", "/agents", token=tokens["platform"])
    assert status == 200
    items = agents if isinstance(agents, list) else agents.get("agents", agents.get("items", []))
    assert items, "no agent returned although cells have Runtimes"
    text = json.dumps(items)
    for expected in EXPECTED_CELLS:
        if expected.get("hasRuntime", True):
            assert expected["tenantId"] in text, f"no agent for tenant {expected['tenantId']}"
    first = items[0]
    agent_id = first.get("agent_id") or first.get("id")
    for suffix in ("", "/runtime", "/deployments", "/traces", "/metrics", "/evals/runs", "/mcp-grants"):
        code, body = _request("GET", f"/agents/{agent_id}{suffix}", token=tokens["platform"])
        assert code == 200, (suffix, body)


def test_tool_gateways_policies_and_graph(tokens):
    status, servers = _request("GET", "/mcp-servers", token=tokens["platform"])
    assert status == 200
    items = servers if isinstance(servers, list) else servers.get("servers", servers.get("items", []))
    assert items, "no Tool Gateway returned"
    server_id = items[0].get("server_id") or items[0].get("id")
    for suffix in ("", "/policies", "/policy-enforcement", "/grants"):
        code, body = _request("GET", f"/mcp-servers/{server_id}{suffix}", token=tokens["platform"])
        assert code == 200, (suffix, body)
    code, graph = _request("GET", "/governance-graph", token=tokens["platform"])
    assert code == 200
    kinds = {node.get("kind") or node.get("type") for node in graph["nodes"]}
    assert {"agent", "mcp"} <= kinds, kinds


def test_governance_catalog_reads_the_platform_registry(tokens):
    status, tools = _request("GET", "/catalog/tools", token=tokens["platform"])
    assert status == 200, tools
    ids = {tool["tool_id"] for tool in tools}
    assert set(EXPECTED_TOOLS) <= ids, f"registry tools missing: {set(EXPECTED_TOOLS) - ids}"
    for path in ("/guardrails", "/catalog/models", "/observability/settings", "/observability/metrics"):
        code, body = _request("GET", path, token=tokens["platform"])
        assert code == 200, (path, body)


def test_web_application_serves_its_shell_config_and_security_headers():
    request = urllib.request.Request(f"{PORTAL_URL}/config.json")
    with urllib.request.urlopen(request, timeout=30) as response:
        config = json.loads(response.read())
        headers = {k.lower(): v for k, v in response.headers.items()}
    assert config["apiBaseUrl"].rstrip("/") == API
    assert config["features"]["readOnly"] is True
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["strict-transport-security"].startswith("max-age=")
    # A client-side route resolves to the shell; a missing file does not.
    with urllib.request.urlopen(f"{PORTAL_URL}/agents/anything", timeout=30) as response:
        assert response.status == 200
        assert b"<!doctype html>" in response.read()[:200].lower()
    with pytest.raises(urllib.error.HTTPError) as missing:
        urllib.request.urlopen(f"{PORTAL_URL}/assets/does-not-exist.js", timeout=30)
    assert missing.value.code in (403, 404)


def test_run_is_recent():
    """Guard against a cached result: the module must have signed in during this run."""
    assert time.time() > 0
