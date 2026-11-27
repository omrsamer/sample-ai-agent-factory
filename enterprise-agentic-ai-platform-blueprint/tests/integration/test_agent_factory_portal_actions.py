# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Live checks for the portal's governed registration and approval.

Run against a portal deployed with `agenticai/portalGovernedActions=true`
whose Registry has no auto-approval (a submitted record must stay
PENDING_APPROVAL until a person decides it).

Every refusal has a positive twin in the same run:

  read-only persona creates        -> 403   developer of the tenant creates -> 201
  developer creates for a tenant
    it does not hold               -> 403   same developer, own tenant      -> 201
  developer approves               -> 403   approver approves               -> 200
  submitter approves own record,
    even with the platform role    -> 403   a different approver approves   -> 200
  approved record: change a
    governed reference             -> 403   change the business purpose     -> 200
  invalid document                 -> 422   valid document                  -> 201

Configuration: the variables of test_agent_factory_portal.py, plus

  PORTAL_ACTIONS=1                  opt in to this module
  PORTAL_ACTIONS_TENANT             a tenant the `product-teams` and
                                    `human-approvers` groups are mapped to

The run creates users and records whose names carry a per-run marker and
removes exactly those.
"""
from __future__ import annotations

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
if not API or os.environ.get("PORTAL_ACTIONS") != "1":
    pytest.skip("PORTAL_API_BASE_URL and PORTAL_ACTIONS=1 are not set", allow_module_level=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"live mode: {name} is required")
    return value


REGION = _required("PORTAL_REGION")
POOL = _required("PORTAL_USER_POOL_ID")
CLIENT = _required("PORTAL_CLIENT_ID")
TENANT = _required("PORTAL_ACTIONS_TENANT")

import boto3  # noqa: E402
import pyotp  # noqa: E402
from pycognito.aws_srp import AWSSRP  # noqa: E402

RUN = uuid.uuid4().hex[:10]
MARKER = f"portal-live-{RUN}"
GROUPS = {
    "developer": "product-teams",
    "approver": "human-approvers",
    "platform": "platform-engineering",
    "readonly": "portal-readonly",
}


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1!" + "".join(secrets.choice(alphabet) for _ in range(28))


def _call(method: str, path: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{API}{path}", method=method, data=data)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw)
        except ValueError:
            return error.code, raw.decode("utf-8", "replace")


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


def _document(agent_id: str, tenant: str = TENANT, **changes) -> dict:
    document = {
        "tenant_id": tenant,
        "agent_id": agent_id,
        "environment": "nonprod",
        "owner_group": "live-validation",
        "business_purpose": f"Live validation record {MARKER}.",
        "risk_class": "limited",
        "data_classification": "internal",
        "cost_centre": "validation",
    }
    document.update(changes)
    return document


@pytest.fixture(scope="module")
def session():
    """Signed-in personas, and a list of the records this run created."""
    idp = boto3.client("cognito-idp", region_name=REGION)
    created_users: list[str] = []
    state = {"tokens": {}, "records": []}
    try:
        for persona, group in GROUPS.items():
            email = f"{MARKER}-{persona}@example.com"
            password = _password()
            idp.admin_create_user(
                UserPoolId=POOL,
                Username=email,
                MessageAction="SUPPRESS",
                UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
            )
            created_users.append(email)
            idp.admin_set_user_password(UserPoolId=POOL, Username=email, Password=password, Permanent=True)
            idp.admin_add_user_to_group(UserPoolId=POOL, Username=email, GroupName=group)
            state["tokens"][persona] = _sign_in(idp, email, password)
        yield state
    finally:
        # Owned cleanup: records this run created that still exist, then its users.
        platform = state["tokens"].get("platform")
        for record_id in state["records"]:
            if platform:
                _call("DELETE", f"/registrations/{record_id}", platform)
        for email in created_users:
            idp.admin_delete_user(UserPoolId=POOL, Username=email)


def test_users_me_reports_the_authorities_each_persona_holds(session):
    expected = {
        "developer": {"registrar"},
        "approver": {"approver"},
        "platform": {"registrar", "approver"},
        "readonly": set(),
    }
    for persona, authorities in expected.items():
        status, me = _call("GET", "/users/me", session["tokens"][persona])
        assert status == 200, me
        assert set(me["authorities"]) == authorities, persona


def test_create_is_refused_without_authority_tenant_or_a_valid_document(session):
    tokens = session["tokens"]
    document = _document(f"live-{RUN}-refused")
    assert _call("POST", "/registrations", None, document)[0] == 401
    status, body = _call("POST", "/registrations", tokens["readonly"], document)
    assert status == 403, body
    status, body = _call("POST", "/registrations", tokens["approver"], document)
    assert status == 403, body
    assert "REG-07-N" in json.dumps(body)
    status, body = _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-refused", tenant="tenant-not-held"))
    assert status == 403, body
    status, body = _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-refused", risk_class="tiny"))
    assert status == 422, body
    listed = _call("GET", "/registrations", tokens["platform"])[1]
    assert not [r for r in listed if r["agent_id"] == f"live-{RUN}-refused"], "a refused create left a record"


def test_register_submit_and_decide_with_separation_of_duties(session):
    tokens = session["tokens"]

    # Developer of the tenant registers and submits record A.
    status, created = _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-a"))
    assert status == 201, created
    record_a = created["registration"]["record_id"]
    session["records"].append(record_a)
    assert created["registration"]["status"] == "DRAFT"
    assert _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-a"))[0] == 409

    status, submitted = _call("POST", f"/registrations/{record_a}/submit", tokens["developer"])
    assert status == 200, submitted
    assert submitted["registration"]["status"] == "PENDING_APPROVAL", (
        "the Registry auto-approved; run this module against a Registry without auto-approval"
    )

    # The developer holds no approver authority.
    status, body = _call("POST", f"/registrations/{record_a}/approve", tokens["developer"], {"reason": "self-serve"})
    assert status == 403, body
    # The approver cannot change the record.
    status, body = _call("PUT", f"/registrations/{record_a}", tokens["approver"], _document(f"live-{RUN}-a"))
    assert status == 403, body
    # A decision needs a reason.
    assert _call("POST", f"/registrations/{record_a}/reject", tokens["approver"], {"reason": ""})[0] == 422

    # Platform user registers and submits record B, then tries to approve it.
    status, created_b = _call("POST", "/registrations", tokens["platform"], _document(f"live-{RUN}-b"))
    assert status == 201, created_b
    record_b = created_b["registration"]["record_id"]
    session["records"].append(record_b)
    assert _call("POST", f"/registrations/{record_b}/submit", tokens["platform"])[0] == 200
    status, body = _call("POST", f"/registrations/{record_b}/approve", tokens["platform"], {"reason": "my own record"})
    assert status == 403, body
    assert "REG-11-N" in json.dumps(body)
    detail = _call("GET", f"/registrations/{record_b}", tokens["platform"])[1]
    assert detail["submitted_by_me"] is True
    assert detail["status"] == "PENDING_APPROVAL", "a refused approval changed the record"

    # A different person with the approver authority decides both records.
    reviewed = _call("GET", f"/registrations/{record_b}", tokens["approver"])[1]
    assert reviewed["submitted_by_me"] is False
    status, approved = _call(
        "POST",
        f"/registrations/{record_b}/approve",
        tokens["approver"],
        {"reason": "Reviewed for the live validation run.", "document_sha256": reviewed["document_sha256"]},
    )
    assert status == 200, approved
    assert approved["registration"]["status"] == "APPROVED"
    status, rejected = _call(
        "POST", f"/registrations/{record_a}/reject", tokens["approver"], {"reason": "Rejected for the live validation run."}
    )
    assert status == 200, rejected
    assert rejected["registration"]["status"] == "REJECTED"

    # A stale review is not applied.
    status, body = _call(
        "POST", f"/registrations/{record_b}/reject", tokens["approver"], {"reason": "late", "document_sha256": "0" * 64}
    )
    assert status == 409, body

    # The audit trail shows the refused attempts as well as the decisions.
    history_a = _call("GET", f"/registrations/{record_a}/history", tokens["platform"])[1]["events"]
    outcomes_a = {(e["action"], e["outcome"]) for e in history_a if e["phase"] == "result"}
    assert {("create", "allowed"), ("submit", "allowed"), ("approve", "denied"), ("reject", "allowed")} <= outcomes_a
    history_b = _call("GET", f"/registrations/{record_b}/history", tokens["platform"])[1]["events"]
    denied_b = [e for e in history_b if e["action"] == "approve" and e["outcome"] == "denied"]
    assert denied_b and "REG-11-N" in denied_b[0]["reason"]
    assert MARKER in json.dumps([e["actor_label"] for e in history_b])

    session["approved"] = record_b
    session["rejected"] = record_a


def test_an_approved_record_cannot_have_its_governed_references_changed(session):
    tokens = session["tokens"]
    record_b = session["approved"]
    status, body = _call("PUT", f"/registrations/{record_b}", tokens["platform"], _document(f"live-{RUN}-b", risk_class="high"))
    assert status == 403, body
    assert "REG-12-N" in json.dumps(body)
    assert _call("GET", f"/registrations/{record_b}", tokens["platform"])[1]["status"] == "APPROVED"

    status, updated = _call(
        "PUT",
        f"/registrations/{record_b}",
        tokens["platform"],
        _document(f"live-{RUN}-b", business_purpose=f"Live validation record {MARKER}, revised."),
    )
    assert status == 200, updated
    assert updated["registration"]["status"] == "DRAFT", "an update must return the record to DRAFT for a new review"


def test_owned_records_are_removed_and_nothing_else_is_touched(session):
    tokens = session["tokens"]
    before = {r["record_id"] for r in _call("GET", "/registrations", tokens["platform"])[1]}
    for record_id in list(session["records"]):
        status, body = _call("DELETE", f"/registrations/{record_id}", tokens["platform"])
        assert status == 200, body
        session["records"].remove(record_id)
    after = {r["record_id"] for r in _call("GET", "/registrations", tokens["platform"])[1]}
    assert before - after == {session["approved"], session["rejected"]}
    # History survives deletion.
    status, history = _call("GET", f"/registrations/{session['rejected']}/history", tokens["platform"])
    assert status == 200 and history["events"]


def test_the_read_function_still_has_no_write_route(session):
    assert _call("POST", "/agents", session["tokens"]["platform"], {})[0] in (404, 405)
    assert _call("DELETE", "/agents/anything", session["tokens"]["platform"])[0] in (404, 405)
