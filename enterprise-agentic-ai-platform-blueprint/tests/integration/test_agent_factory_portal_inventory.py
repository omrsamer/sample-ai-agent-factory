# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Live checks for the portal's inventory completeness, risk level, export
and hand-off to Amazon CloudWatch Omni. Read-only.

What is proven on the deployed portal:

  - the fleet summary adds up to the inventory it summarizes;
  - every agent is in exactly one inventory state (registered and detected,
    registered only, detected only), and no Runtime appears twice;
  - every risk level is the highest severity among its reasons, and an agent
    with no approved registration is flagged;
  - an agent detected in an account the portal has no reader role in is
    listed, and every panel about it answers instead of failing;
  - the export holds exactly the inventory;
  - the Omni read lists agents only, and never an agent twice.

Every refusal has a positive twin in the same run:

  no token                  -> 401     a signed-in persona -> 200
  a user in no group        -> 403
  an unknown export format  -> 422     csv and json        -> 200

Configuration: the variables of test_agent_factory_portal.py. Each of the
following makes the matching check strict instead of informative:

  PORTAL_EXPECT_DISCOVERY=1   the portal reads an organization discovery
                              Registry that has detected at least one agent
                              outside the configured cells
  PORTAL_EXPECT_OMNI=1        a cell in the portal's own account names an
                              Omni Region, so the Context Graph must be read
  PORTAL_EXPECT_OWNED_RECORD, PORTAL_EXPECT_UNKNOWN_OWNER_RECORD
                              record names of a registered agent whose owner
                              group is, and is not, in the owner roster

The run creates two users whose names carry a per-run marker, and deletes
exactly those users afterwards.
"""
from __future__ import annotations

import csv
import io
import json
import os
import secrets
import string
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
EXPECT_DISCOVERY = os.environ.get("PORTAL_EXPECT_DISCOVERY") == "1"
EXPECT_OMNI = os.environ.get("PORTAL_EXPECT_OMNI") == "1"
OWNED_RECORD = os.environ.get("PORTAL_EXPECT_OWNED_RECORD", "")
UNKNOWN_OWNER_RECORD = os.environ.get("PORTAL_EXPECT_UNKNOWN_OWNER_RECORD", "")

import boto3  # noqa: E402
import pyotp  # noqa: E402
from pycognito.aws_srp import AWSSRP  # noqa: E402

RUN = uuid.uuid4().hex[:10]
MARKER = f"portal-live-{RUN}"
STATES = {"registered_and_detected", "registered_only", "detected_only"}
SEVERITIES = ("low", "medium", "high", "critical")
FLAGS = {"unmanaged", "ownerless", "review_overdue", "inactive", "contained"}
SOURCES = {"organization_registry", "cell_reader"}
# Panels of one agent. Each must answer for every agent, including one the portal cannot reach.
PANELS = ("", "/runtime", "/deployments", "/traces", "/metrics", "/evals/runs", "/mcp-grants", "/containment")


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1!" + "".join(secrets.choice(alphabet) for _ in range(28))


def _raw(path: str, token: str | None = None):
    request = urllib.request.Request(f"{API}{path}", method="GET")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def _get(path: str, token: str | None = None):
    status, _, body = _raw(path, token)
    try:
        return status, json.loads(body) if body else None
    except ValueError:
        return status, body.decode("utf-8", "replace")


def _sign_in(idp, username: str, password: str) -> str:
    srp = AWSSRP(username=username, password=password, pool_id=POOL, client_id=CLIENT, client=idp)
    start = idp.initiate_auth(AuthFlow="USER_SRP_AUTH", AuthParameters=srp.get_auth_params(), ClientId=CLIENT)
    step = idp.respond_to_auth_challenge(
        ClientId=CLIENT,
        ChallengeName="PASSWORD_VERIFIER",
        ChallengeResponses=srp.process_challenge(start["ChallengeParameters"], srp.get_auth_params()),
    )
    association = idp.associate_software_token(Session=step["Session"])
    verified = idp.verify_software_token(
        Session=association["Session"], UserCode=pyotp.TOTP(association["SecretCode"]).now()
    )
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
    users = {"security": "security-and-risk", "nogroup": None}
    created: list[str] = []
    try:
        result = {}
        for persona, group in users.items():
            email = f"{MARKER}-{persona}@example.com"
            password = _password()
            idp.admin_create_user(
                UserPoolId=POOL,
                Username=email,
                MessageAction="SUPPRESS",
                UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
            )
            created.append(email)
            idp.admin_set_user_password(UserPoolId=POOL, Username=email, Password=password, Permanent=True)
            if group:
                idp.admin_add_user_to_group(UserPoolId=POOL, Username=email, GroupName=group)
            result[persona] = _sign_in(idp, email, password)
        yield result
    finally:
        for email in created:
            idp.admin_delete_user(UserPoolId=POOL, Username=email)


@pytest.fixture(scope="module")
def inventory(tokens) -> list[dict]:
    status, agents = _get("/agents", tokens["security"])
    assert status == 200, agents
    assert agents, "the inventory is empty"
    return agents


@pytest.mark.parametrize("path", ["/fleet/summary", "/agents/export", "/omni/observed-services"])
def test_the_new_reads_need_a_signed_in_persona(tokens, path):
    assert _raw(path)[0] == 401
    assert _raw(path, "a.b.c")[0] == 401
    assert _raw(path, tokens["nogroup"])[0] == 403
    assert _raw(path, tokens["security"])[0] == 200


def test_the_fleet_summary_adds_up_to_the_inventory(tokens, inventory):
    status, summary = _get("/fleet/summary", tokens["security"])
    assert status == 200, summary
    total = len(inventory)
    assert summary["agents_total"] == total
    assert set(summary["by_inventory_state"]) <= STATES
    assert sum(summary["by_inventory_state"].values()) == total
    assert set(summary["by_risk_level"]) <= set(SEVERITIES)
    assert sum(summary["by_risk_level"].values()) == total
    for flag in FLAGS:
        assert summary["flags"].get(flag, 0) == sum(1 for a in inventory if a["flags"][flag] is True), flag
        assert summary["flags_unknown"].get(flag, 0) == sum(1 for a in inventory if a["flags"][flag] is None), flag
    assert summary["unreachable_cells"] == 0, summary["warnings"]
    assert summary["organization_registry"] in ("ok", "disabled"), summary["organization_registry"]
    if EXPECT_DISCOVERY:
        assert summary["organization_registry"] == "ok"
    ids = {a["id"] for a in inventory}
    assert len(summary["needs_attention"]) <= 20
    for item in summary["needs_attention"]:
        assert item["agent_id"] in ids
        assert item["risk_level"] in ("high", "critical")
    for domain in summary["omni_domains"]:
        assert domain["url"].startswith("https://")


def test_every_agent_is_in_one_state_and_no_runtime_is_listed_twice(inventory):
    arns = [a["agent_arn"] for a in inventory if a.get("agent_arn")]
    assert len(arns) == len(set(arns)), "a Runtime seen by two sources must be one agent"
    assert len({a["id"] for a in inventory}) == len(inventory)
    for agent in inventory:
        assert agent["inventory_state"] in STATES, agent["id"]
        assert set(agent["detection_sources"]) <= SOURCES
        assert agent["reader_status"] in ("ok", "unreachable", "none")
        if agent["inventory_state"] == "registered_only":
            assert agent["detection_sources"] == [], agent["id"]
        else:
            assert agent["detection_sources"], agent["id"]
        if agent["inventory_state"] == "detected_only":
            assert agent["registration"] == "discovered"
            assert agent["lifecycle_state"] == "discovered"
        else:
            assert agent["registration"] == "registered"
            assert agent["record_name"]


def test_every_risk_level_is_explained_by_its_reasons(inventory):
    for agent in inventory:
        risk, flags = agent["risk"], agent["flags"]
        assert set(flags) == FLAGS
        assert risk["level"] in SEVERITIES
        for reason in risk["reasons"]:
            assert reason["severity"] in SEVERITIES and reason["code"] and reason["detail"]
        highest = max((SEVERITIES.index(r["severity"]) for r in risk["reasons"]), default=0)
        assert SEVERITIES.index(risk["level"]) == highest, agent["id"]
        # No approved registration: flagged, and the level says why.
        approved = agent["registration"] == "registered" and agent["lifecycle_state"] == "approved"
        assert flags["unmanaged"] is (not approved), agent["id"]
        if agent["inventory_state"] == "detected_only":
            assert SEVERITIES.index(risk["level"]) >= SEVERITIES.index("high"), agent["id"]
            assert flags["ownerless"] is None and flags["review_overdue"] is None, "unknown for an unregistered agent"


def test_an_agent_detected_outside_the_cells_is_listed_and_every_panel_answers(tokens, inventory):
    outside = [
        a
        for a in inventory
        if a["inventory_state"] == "detected_only"
        and "organization_registry" in a["detection_sources"]
        and a["reader_status"] == "none"
    ]
    if not outside:
        if EXPECT_DISCOVERY:
            pytest.fail("no agent detected by the organization Registry outside the configured cells")
        pytest.skip("no agent is detected outside the configured cells in this deployment")
    agent = outside[0]
    assert agent["agent_arn"] and agent["account_id"] and agent["region"]
    assert agent["flags"]["contained"] is None, "containment state cannot be known without a reader"
    for panel in PANELS:
        status, body = _get(f"/agents/{agent['id']}{panel}", tokens["security"])
        assert status == 200, (panel, body)
    view = _get(f"/agents/{agent['id']}/containment", tokens["security"])[1]
    assert view["state"] == "unknown" and view["enabled"] is False

    # Positive twin: an agent in a configured cell is read through its cell.
    reachable = [a for a in inventory if a["reader_status"] == "ok" and "cell_reader" in a["detection_sources"]]
    assert reachable, "no agent is read through a cell reader"
    status, runtime = _get(f"/agents/{reachable[0]['id']}/runtime", tokens["security"])
    assert status == 200, runtime
    assert _get(f"/agents/{reachable[0]['id']}/containment", tokens["security"])[1]["state"] in (
        "contained",
        "not_contained",
    )


def test_the_owner_roster_is_applied_to_registered_agents(inventory):
    if not (OWNED_RECORD and UNKNOWN_OWNER_RECORD):
        pytest.skip("PORTAL_EXPECT_OWNED_RECORD and PORTAL_EXPECT_UNKNOWN_OWNER_RECORD are not set")
    by_record = {a.get("record_name"): a for a in inventory}
    owned, unknown = by_record.get(OWNED_RECORD), by_record.get(UNKNOWN_OWNER_RECORD)
    assert owned and unknown, "the expected records are not in the inventory"
    assert owned["flags"]["ownerless"] is False, owned["risk"]
    assert unknown["flags"]["ownerless"] is True, unknown["risk"]
    owner_codes = {"OWNERLESS", "OWNER_GROUP_NOT_IN_ROSTER"}
    assert owner_codes & {r["code"] for r in unknown["risk"]["reasons"]}
    assert not owner_codes & {r["code"] for r in owned["risk"]["reasons"]}


def test_the_export_holds_exactly_the_inventory(tokens, inventory):
    status, headers, body = _raw("/agents/export", tokens["security"])
    assert status == 200
    assert headers["content-type"].startswith("text/csv")
    assert "attachment" in headers["content-disposition"] and ".csv" in headers["content-disposition"]
    assert headers.get("cache-control") == "no-store"
    rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))
    assert {"agent_id", "name", "inventory_state", "risk_level", "runtime_arn", "unmanaged"} <= set(rows[0])
    assert sorted(r["agent_id"] for r in rows) == sorted(a["id"] for a in inventory)
    by_id = {a["id"]: a for a in inventory}
    for row in rows:
        agent = by_id[row["agent_id"]]
        assert row["inventory_state"] == agent["inventory_state"]
        assert row["risk_level"] == agent["risk"]["level"]
        assert row["runtime_arn"] == (agent.get("agent_arn") or "")
        # A spreadsheet must not read any cell as a formula.
        assert not any(value[:1] in ("=", "+", "-", "@") for value in row.values() if value), row["agent_id"]

    status, headers, body = _raw("/agents/export?format=json", tokens["security"])
    assert status == 200 and headers["content-type"].startswith("application/json")
    exported = json.loads(body)
    assert sorted(r["agent_id"] for r in exported) == sorted(by_id)
    assert _raw("/agents/export?format=xml", tokens["security"])[0] == 422


def test_omni_lists_observed_agents_only(tokens, inventory):
    status, observed = _get("/omni/observed-services", tokens["security"])
    assert status == 200, observed
    if EXPECT_OMNI:
        assert not [w for w in observed["warnings"] if "could not be read" in w], observed["warnings"]
        assert (observed["omni_url"] or "").startswith("https://")
    ids = {a["id"] for a in inventory}
    seen = set()
    for service in observed["services"]:
        assert service["category"] == "GEN_AI_AGENT", "an agent console lists agents, not every service"
        assert not (service["last_observed_at"] or "").startswith("1970"), "an unknown time is null, not 1970"
        if service["registered"]:
            assert service["detected"], "a registered Runtime is a detected Runtime"
        if service["matched_agent_id"]:
            assert service["matched_agent_id"] in ids
        key = (service["name"], service["resource_id"])
        assert key not in seen, "an observed agent is listed once"
        seen.add(key)
    assert _raw("/omni/observed-services?hours=0", tokens["security"])[0] == 422
    assert _raw("/omni/observed-services?hours=169", tokens["security"])[0] == 422
    for agent in inventory:
        if agent.get("omni_url"):
            assert agent["omni_url"].startswith("https://")
