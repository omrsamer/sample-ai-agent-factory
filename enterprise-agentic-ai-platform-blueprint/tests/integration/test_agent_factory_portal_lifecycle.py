# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Live checks for an agent's life after approval: periodic review, retirement
and the evidence document.

Run against a portal deployed with governed actions and an agent Registry
without auto-approval.

Every refusal has a positive twin in the same run:

  developer attests a review          -> 403   approver attests it           -> 200
  a date today, or over a year ahead  -> 422   a date inside the window      -> 200
  review of a record not approved     -> 409   review of an approved record  -> 200
  developer retires                   -> 403   approver retires              -> 200
  approve, reject, update, submit
    or review a retired record        -> 409   retire it again -> 200, unchanged
  evidence without a token            -> 401   a signed-in persona           -> 200
  a review date over a year ahead in
    a registration                    -> 422   inside a year                 -> 201
  the person who submitted the record
    attests its review                -> 403   another approver              -> 200
  a second attestation the same day   -> 409   the first                     -> 200
  an approver of another tenant
    decides or attests                -> 403, and nothing in the record's history

Configuration: the variables of test_agent_factory_portal_actions.py, plus

  PORTAL_LIFECYCLE=1               opt in to this module
  PORTAL_LIFECYCLE_OTHER_TENANT    optional: a tenant the `human-approvers`
                                   group does not hold; enables the check
                                   that an approver of another tenant leaves
                                   nothing in a record's history

The run creates users and records whose names carry a per-run marker and
removes exactly those.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import string
import time
import urllib.error
import urllib.request
import uuid

import pytest

pytestmark = pytest.mark.integration

API = os.environ.get("PORTAL_API_BASE_URL", "").rstrip("/")
if not API or os.environ.get("PORTAL_LIFECYCLE") != "1":
    pytest.skip("PORTAL_API_BASE_URL and PORTAL_LIFECYCLE=1 are not set", allow_module_level=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"live mode: {name} is required")
    return value


REGION = _required("PORTAL_REGION")
POOL = _required("PORTAL_USER_POOL_ID")
CLIENT = _required("PORTAL_CLIENT_ID")
TENANT = _required("PORTAL_ACTIONS_TENANT")
OTHER_TENANT = os.environ.get("PORTAL_LIFECYCLE_OTHER_TENANT", "")

import boto3  # noqa: E402
import pyotp  # noqa: E402
from pycognito.aws_srp import AWSSRP  # noqa: E402

RUN = uuid.uuid4().hex[:10]
MARKER = f"portal-live-{RUN}"
GROUPS = {"developer": "product-teams", "approver": "human-approvers", "platform": "platform-engineering"}
TODAY = dt.datetime.now(dt.timezone.utc).date()


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1!" + "".join(secrets.choice(alphabet) for _ in range(28))


def _raw(method: str, path: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{API}{path}", method=method, data=data)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def _call(method: str, path: str, token: str | None = None, body: dict | None = None):
    status, _, raw = _raw(method, path, token, body)
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode("utf-8", "replace")


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


def _document(agent_id: str, **changes) -> dict:
    document = {
        "tenant_id": TENANT,
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
        if state["tokens"].get("platform"):
            for record_id in state["records"]:
                _remove(record_id, state["tokens"])
        for email in created_users:
            idp.admin_delete_user(UserPoolId=POOL, Username=email)


def _approved_record(session, suffix: str, **changes) -> str:
    """A record registered and submitted by the developer and approved by the approver."""
    tokens = session["tokens"]
    status, created = _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-{suffix}", **changes))
    assert status == 201, created
    record_id = created["registration"]["record_id"]
    session["records"].append(record_id)
    assert _call("POST", f"/registrations/{record_id}/submit", tokens["developer"])[0] == 200
    detail = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
    status, approved = _call(
        "POST",
        f"/registrations/{record_id}/approve",
        tokens["approver"],
        {"reason": "Approved for the live lifecycle run.", "document_sha256": detail["document_sha256"]},
    )
    assert status == 200 and approved["registration"]["status"] == "APPROVED", approved
    return record_id


def test_a_review_is_attested_by_an_approver_inside_the_date_window(session):
    tokens = session["tokens"]
    record_id = _approved_record(session, "review")
    session["reviewed"] = record_id
    path = f"/registrations/{record_id}/review"
    inside = (TODAY + dt.timedelta(days=180)).isoformat()

    assert _call("POST", path, None, {"reason": "x", "next_review_by": inside})[0] == 401
    status, body = _call("POST", path, tokens["developer"], {"reason": "Reviewed.", "next_review_by": inside})
    assert status == 403 and "REV-01-N" in json.dumps(body), body
    for bad in (TODAY.isoformat(), (TODAY + dt.timedelta(days=367)).isoformat(), "2026-13-45"):
        status, body = _call("POST", path, tokens["approver"], {"reason": "Reviewed.", "next_review_by": bad})
        assert status == 422, (bad, body)
    assert _call("POST", path, tokens["approver"], {"reason": "", "next_review_by": inside})[0] == 422
    before = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
    # The registration names no review date. Its approval set one all the same, a year from the
    # approval, so that an approved registration is always due at some point.
    assert before["status"] == "APPROVED" and before["last_reviewed_at"], before
    due = dt.date.fromisoformat(before["effective_review_by"])
    assert dt.timedelta(days=365) <= due - TODAY <= dt.timedelta(days=367), before["effective_review_by"]

    status, result = _call(
        "POST", path, tokens["approver"], {"reason": f"Reviewed in the live run {MARKER}.", "next_review_by": inside}
    )
    assert status == 200, result
    assert result["action"] == "review" and result["outcome"] == "allowed"
    assert result["registration"]["status"] == "APPROVED", "an attestation must not change the record"

    after = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
    assert after["status"] == "APPROVED" and after["document_sha256"] == before["document_sha256"]
    assert after["effective_review_by"] == inside
    assert after["last_reviewed_at"] and MARKER in (after["last_reviewed_by"] or "")
    history = _call("GET", f"/registrations/{record_id}/history", tokens["approver"])[1]["events"]
    outcomes = {(e["action"], e["outcome"]) for e in history if e["phase"] == "result"}
    assert ("review", "allowed") in outcomes, outcomes
    # The developer was refused before the record was read: logged by the function, not stored here.
    assert ("review", "denied") not in outcomes, outcomes


def test_a_record_that_is_not_approved_cannot_be_attested(session):
    tokens = session["tokens"]
    status, created = _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-draft"))
    assert status == 201, created
    record_id = created["registration"]["record_id"]
    session["records"].append(record_id)
    inside = (TODAY + dt.timedelta(days=30)).isoformat()
    status, body = _call(
        "POST", f"/registrations/{record_id}/review", tokens["approver"], {"reason": "Reviewed.", "next_review_by": inside}
    )
    assert status == 409 and "REV-03-N" in json.dumps(body), body


def test_retirement_is_decided_by_an_approver_and_is_permanent(session):
    tokens = session["tokens"]
    record_id = session["reviewed"]
    path = f"/registrations/{record_id}/retire"

    assert _call("POST", path, None, {"reason": "x"})[0] == 401
    status, body = _call("POST", path, tokens["developer"], {"reason": "No longer needed."})
    assert status == 403 and "RET-01-N" in json.dumps(body), body
    assert _call("POST", path, tokens["approver"], {"reason": ""})[0] == 422
    assert _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]["status"] == "APPROVED"

    status, result = _call("POST", path, tokens["approver"], {"reason": f"Retired in the live run {MARKER}."})
    assert status == 200, result
    assert result["action"] == "retire" and result["outcome"] == "allowed"
    assert result["registration"]["status"] == "DEPRECATED"
    assert "permanent" in result["reason"]

    status, again = _call("POST", path, tokens["approver"], {"reason": "Second attempt."})
    assert status == 200 and again["outcome"] == "unchanged", again

    # A retired record refuses every further decision and change, by rule.
    detail = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
    assert detail["status"] == "DEPRECATED"
    refused = {
        "approve": ("POST", tokens["approver"], {"reason": "Bring it back.", "document_sha256": detail["document_sha256"]}),
        "reject": ("POST", tokens["approver"], {"reason": "Reject it."}),
        "submit": ("POST", tokens["developer"], None),
        "review": ("POST", tokens["approver"], {"reason": "Reviewed.", "next_review_by": (TODAY + dt.timedelta(days=30)).isoformat()}),
    }
    for action, (method, token, payload) in refused.items():
        status, body = _call(method, f"/registrations/{record_id}/{action}", token, payload)
        assert status == 409, (action, body)
    # Asking again changes nothing in the history: a refusal of someone who has a part in the
    # record is written once, so repeating it cannot push the record's decisions out of reach.
    for _ in range(6):
        method, token, payload = refused["approve"]
        assert _call(method, f"/registrations/{record_id}/approve", token, payload)[0] == 409
    status, body = _call("PUT", f"/registrations/{record_id}", tokens["developer"], _document(f"live-{RUN}-review"))
    assert status == 409 and "RET-03-N" in json.dumps(body), body
    assert _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]["status"] == "DEPRECATED"

    history = _call("GET", f"/registrations/{record_id}/history", tokens["approver"])[1]["events"]
    outcomes = {(e["action"], e["outcome"]) for e in history if e["phase"] == "result"}
    # The refusals about the retired record are in its history; the developer's attempt, refused
    # before the record was read, is not.
    assert {("retire", "allowed"), ("retire", "unchanged"), ("approve", "denied")} <= outcomes, outcomes
    assert ("retire", "denied") not in outcomes, outcomes
    refused_approvals = [e for e in history if e["phase"] == "result" and (e["action"], e["outcome"]) == ("approve", "denied")]
    assert len(refused_approvals) == 1, f"seven refused approvals left {len(refused_approvals)} entries"


def test_the_evidence_document_holds_the_decisions_and_no_secret(session):
    tokens = session["tokens"]
    record_id = session["reviewed"]
    assert _raw("GET", f"/agents/{record_id}/evidence")[0] == 401
    # The agent list is cached for a short time, so a new registration appears after a moment.
    deadline = time.monotonic() + 90
    while True:
        status, headers, raw = _raw("GET", f"/agents/{record_id}/evidence", tokens["approver"])
        if status == 200 or time.monotonic() > deadline:
            break
        time.sleep(5)
    assert status == 200, raw[:300]
    assert headers["content-type"].startswith("application/json")
    assert "attachment" in headers["content-disposition"] and ".json" in headers["content-disposition"]
    assert headers.get("cache-control") == "no-store"
    assert "content-disposition" in headers.get("access-control-expose-headers", "content-disposition").lower()
    evidence = json.loads(raw)
    for section in ("generated_at", "agent", "registration", "decisions", "reviews", "containment", "risk", "policy", "limitations"):
        assert section in evidence, section
    assert evidence["registration"]["status"] == "DEPRECATED"
    assert evidence["registration"]["document_sha256"]
    actions = [(e["action"], e["outcome"]) for e in evidence["decisions"] if e.get("phase", "result") == "result"]
    for expected in (("create", "allowed"), ("submit", "allowed"), ("approve", "allowed"), ("retire", "allowed")):
        assert expected in actions, (expected, actions)
    assert evidence["reviews"], "the attestation is part of the evidence"
    text = raw.decode("utf-8")
    # No account id outside an ARN, and nothing that looks like a credential. Event and request
    # ids are UUIDs, whose last group can be twelve digits: they are not account ids.
    outside_arns = re.sub(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:\S+", "", text)
    outside_arns = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "", outside_arns)
    found = re.search(r"(?<!\d)\d{12}(?!\d)", outside_arns)
    assert not found, "a full account id appears outside an ARN: ..." + outside_arns[max(0, found.start() - 60) : found.start()]
    assert not re.search(r"eyJ[A-Za-z0-9_-]{20,}\.", text), "a token appears in the evidence"


def test_a_review_date_is_at_most_a_year_ahead_wherever_it_is_set(session):
    """The bound on a review attestation would mean little if a registration could name any date."""
    tokens = session["tokens"]
    far = (TODAY + dt.timedelta(days=800)).isoformat()
    status, body = _call("POST", "/registrations", tokens["developer"], _document(f"live-{RUN}-far", review_by=far))
    if status == 201:
        session["records"].append(body["registration"]["record_id"])
    assert status == 422, body
    near = (TODAY + dt.timedelta(days=200)).isoformat()
    record_id = _approved_record(session, "dated", review_by=near)
    session["dated"] = record_id
    detail = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
    # An approval of a registration that names a review date counts as a review, with that date.
    assert detail["effective_review_by"] == near, detail
    assert detail["last_reviewed_at"] and MARKER in (detail["last_reviewed_by"] or ""), detail


def test_a_record_has_one_latest_attestation_however_often_it_is_approved(session, platform_session):
    """The review dates of the whole fleet are read from one place. It holds one entry for a
    record, its latest attestation, so that approving one record again and again cannot push the
    entries of other records out of that read."""
    tokens = session["tokens"]
    record_id = session["dated"]
    stack = os.environ.get("PORTAL_STACK_NAME") or f"AgenticAI-AgentFactoryPortal-{os.environ.get('PORTAL_ENVIRONMENT', 'nonprod')}"
    table = next(
        resource["PhysicalResourceId"]
        for page in platform_session.client("cloudformation", region_name=REGION)
        .get_paginator("list_stack_resources")
        .paginate(StackName=stack)
        for resource in page["StackResourceSummaries"]
        if resource["ResourceType"] == "AWS::DynamoDB::Table"
    )
    dynamodb = platform_session.client("dynamodb", region_name=REGION)

    def latest() -> list[dict]:
        items = dynamodb.query(
            TableName=table,
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
            ExpressionAttributeValues={":pk": {"S": "REVIEWS"}, ":sk": {"S": f"RECORD#{record_id}"}},
            ConsistentRead=True,
        )["Items"]
        return [{name: next(iter(value.values())) for name, value in item.items()} for item in items]

    first = latest()
    assert len(first) == 1, first
    # Change the record, submit it and approve it again, three times: a new attestation each time.
    stamps = [first[0]["at"]]
    for round_number in range(3):
        nearer = (TODAY + dt.timedelta(days=150 - round_number)).isoformat()
        document = _document(f"live-{RUN}-dated", review_by=nearer, business_purpose=f"Live validation record {MARKER}, round {round_number}.")
        status, body = _call("PUT", f"/registrations/{record_id}", tokens["developer"], document)
        assert status == 200, body
        assert _call("POST", f"/registrations/{record_id}/submit", tokens["developer"])[0] == 200
        detail = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
        status, body = _call(
            "POST",
            f"/registrations/{record_id}/approve",
            tokens["approver"],
            {"reason": "Approved again for the live lifecycle run.", "document_sha256": detail["document_sha256"]},
        )
        assert status == 200, body
        now = latest()
        assert len(now) == 1, f"round {round_number}: {len(now)} entries for one record"
        assert now[0]["at"] > stamps[-1], "the entry was not replaced by the later attestation"
        stamps.append(now[0]["at"])
        assert _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]["effective_review_by"] == nearer


def test_one_attestation_a_day_and_never_by_the_person_who_submitted(session):
    tokens = session["tokens"]
    # The platform role holds both authorities. A record it submitted is approved by someone else,
    # and its periodic review is attested by someone else too.
    status, created = _call("POST", "/registrations", tokens["platform"], _document(f"live-{RUN}-own"))
    assert status == 201, created
    record_id = created["registration"]["record_id"]
    session["records"].append(record_id)
    assert _call("POST", f"/registrations/{record_id}/submit", tokens["platform"])[0] == 200
    detail = _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]
    status, approved = _call(
        "POST",
        f"/registrations/{record_id}/approve",
        tokens["approver"],
        {"reason": "Approved for the live lifecycle run.", "document_sha256": detail["document_sha256"]},
    )
    assert status == 200, approved
    path = f"/registrations/{record_id}/review"
    inside = (TODAY + dt.timedelta(days=90)).isoformat()
    status, body = _call("POST", path, tokens["platform"], {"reason": "Reviewed by its submitter.", "next_review_by": inside})
    assert status == 403 and "REV-05-N" in json.dumps(body), body
    status, body = _call("POST", path, tokens["approver"], {"reason": "Reviewed.", "next_review_by": inside})
    assert status == 200, body
    # One attestation per record per day: the review trail cannot be filled.
    later = (TODAY + dt.timedelta(days=120)).isoformat()
    status, body = _call("POST", path, tokens["approver"], {"reason": "Reviewed again.", "next_review_by": later})
    assert status == 409 and "REV-06-N" in json.dumps(body), body
    assert _call("GET", f"/registrations/{record_id}", tokens["approver"])[1]["effective_review_by"] == inside

    # An approval that recorded a review date is not an attestation of a review: one can follow it the same day.
    status, body = _call(
        "POST",
        f"/registrations/{session['dated']}/review",
        tokens["approver"],
        {"reason": "Reviewed after approval.", "next_review_by": inside},
    )
    assert status == 200, body


def test_an_approver_of_another_tenant_leaves_nothing_in_a_records_history(session):
    if not OTHER_TENANT:
        pytest.skip("PORTAL_LIFECYCLE_OTHER_TENANT is not set")
    tokens = session["tokens"]
    status, created = _call(
        "POST", "/registrations", tokens["platform"], _document(f"live-{RUN}-other", tenant_id=OTHER_TENANT)
    )
    assert status == 201, created
    record_id = created["registration"]["record_id"]
    session["records"].append(record_id)
    assert _call("POST", f"/registrations/{record_id}/submit", tokens["platform"])[0] == 200
    detail = _call("GET", f"/registrations/{record_id}", tokens["platform"])[1]
    inside = (TODAY + dt.timedelta(days=30)).isoformat()
    attempts = {
        "approve": {"reason": "Not my tenant.", "document_sha256": detail["document_sha256"]},
        "reject": {"reason": "Not my tenant."},
        "retire": {"reason": "Not my tenant."},
        "review": {"reason": "Not my tenant.", "next_review_by": inside},
    }
    for _ in range(3):
        for action, payload in attempts.items():
            status, body = _call("POST", f"/registrations/{record_id}/{action}", tokens["approver"], payload)
            assert status == 403, (action, body)
    assert _call("GET", f"/registrations/{record_id}", tokens["platform"])[1]["status"] == "PENDING_APPROVAL"
    history = _call("GET", f"/registrations/{record_id}/history", tokens["platform"])[1]["events"]
    strangers = [e for e in history if "-approver@" in (e.get("actor_label") or "")]
    assert not strangers, f"an approver of another tenant wrote {len(strangers)} entries into the record's history"


def _remove(record_id: str, tokens: dict) -> tuple[int, object]:
    """Delete a record of this run. An approved record cannot be deleted: it is retired first."""
    status, body = _call("DELETE", f"/registrations/{record_id}", tokens["platform"])
    if status == 409:
        _call("POST", f"/registrations/{record_id}/retire", tokens["platform"], {"reason": f"Removing a record of {MARKER}."})
        status, body = _call("DELETE", f"/registrations/{record_id}", tokens["platform"])
    return status, body


def test_owned_records_are_removed(session):
    tokens = session["tokens"]
    for record_id in list(session["records"]):
        status, body = _remove(record_id, tokens)
        assert status == 200, body
        session["records"].remove(record_id)
    listed = _call("GET", "/registrations", tokens["platform"])[1]
    assert not [r for r in listed if MARKER in json.dumps(r)], "a record of this run was left behind"
