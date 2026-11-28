# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Live checks for incident containment from the Agent Factory Portal.

Containment blocks every invocation of an agent's Runtime and stops its
running sessions; release lifts the block. This module proves it end to end
on a deployed portal: the decision in the portal, and the effect on the
Runtime measured with the cell account's own credentials.

Every refusal has a positive twin in the same run:

  developer contains                 -> 403   security contains            -> 200, invocation denied
  sre without the agent's tenant     -> 403   security holding the tenant  -> 200
  no reason                          -> 422   with a reason                -> 200
  the person who contained releases  -> 403   a different person releases  -> 200, invocation allowed
  developer releases                 -> 403
  another principal assumes the
    cell's containment role          -> AccessDenied   the portal function -> acts
  an agent whose cell did not opt in -> 409   an agent whose cell did      -> 200
  the person who contained under one
    id releases under another        -> 403   a different person, either id -> 200
  a registration claims the Runtime
    for another tenant               -> 403   for the tenant of its cell    -> 201
  a function invoked directly, with
    claims in the event and no token -> 401   through the API with a token  -> 200
  the same, with a token whose
    content was changed              -> 401
  claims of a responder in the event
    beside a developer's real token  -> 403   (the token decides, not the event)
  a statement with the portal's name
    that denies nothing              -> not contained   the portal's own statement -> contained
  the person who contained releases
    under another spelling of the ARN -> refused   a different person -> 200

It also proves that containment keeps every statement of the Runtime's
resource policy that it did not write, that a registration naming the Runtime
for another tenant changes neither the tenant that decides nor the history,
that the incident record is shown only to the roles that can act, and that a
caller without the role or without the tenant leaves nothing in the Runtime's
history.

THE TARGET MUST BE SAFE TO BLOCK. The module blocks the Runtime named by
PORTAL_CONTAINMENT_RUNTIME_ARN for a few minutes. It refuses to start unless
that Runtime carries the tag `portal-containment-test` = `allowed`, so it
cannot be pointed at a production agent by mistake.

Configuration: the variables of test_agent_factory_portal.py, plus

  PORTAL_CONTAINMENT=1                 opt in to this module
  PORTAL_CONTAINMENT_RUNTIME_ARN       the tagged validation Runtime, in a cell
                                       that deployed the containment stage
  PORTAL_CONTAINMENT_AGENT_ID          optional: the agent's id in GET /agents
                                       (default: the Runtime id, which is the
                                       id of an agent with no registration)
  PORTAL_CONTAINMENT_EXPECT_SESSIONS=1 optional: require that the running
                                       session is found and stopped (the
                                       Runtime must write output)
  PORTAL_CONTAINMENT_CELL_TENANT       optional: the tenant of the Runtime's
                                       cell, which the `product-teams` group
                                       must hold; enables the check that the
                                       history follows the Runtime whichever
                                       id a request uses
  PORTAL_CONTAINMENT_CLAIMED_TENANT    optional, with the one above: another
                                       tenant the `product-teams` group
                                       holds; enables the check that a
                                       registration cannot claim the Runtime
                                       for a tenant whose cell it is not in
  PORTAL_CONTAINMENT_EXPECT_SWEEPS=1   optional: the portal is deployed with
                                       background sweeps; require that the
                                       second sweep runs and records that the
                                       agent is quiet (adds about 4 minutes)
  PORTAL_CONTAINMENT_SHARED_ACCOUNT=1  optional, with PORTAL_CONTAINMENT_CELL_TENANT:
                                       the portal is configured with cells of
                                       several tenants in the Runtime's account
                                       and Region. Run only the check named
                                       `shared_account` in that configuration:
                                       it sets and removes the Runtime's
                                       `tenant-id` tag, and the other checks
                                       assume an account with one tenant
  PORTAL_CONTAINMENT_SHARED_OTHER_TENANT  optional, with the one above: a
                                       second tenant with a cell there that
                                       the `security-and-risk` group also
                                       holds; enables the check that a
                                       changed tag does not hand a contained
                                       agent to another tenant's responders
  PORTAL_CONTAINMENT_SHARED_UNHELD_TENANT optional, with the first: a tenant
                                       with a cell there that the
                                       `product-teams` group does not hold;
                                       enables the check that a registration
                                       cannot name a Runtime of a shared
                                       account unless its author holds every
                                       tenant there
  PORTAL_STACK_NAME                    optional: the portal stack, to find the
                                       action functions for the direct
                                       invocation check (default
                                       AgenticAI-AgentFactoryPortal-<environment>);
                                       the Platform credentials need
                                       lambda:InvokeFunction on them
  Credentials of the cell account (AWS_PROFILE_WORKLOAD or the *_WORKLOAD
  keys of conftest.py), used only to invoke the Runtime and read its policy.

The `security-and-risk` group must hold the agent's tenant and the
`platform-sre` group must not (PORTAL_GROUP_TENANT_MAP of the deployment).

The run creates users whose names carry a per-run marker and removes exactly
those. If it stops part-way, it removes the containment statement it added
and nothing else.
"""
from __future__ import annotations

import base64
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
if not API or os.environ.get("PORTAL_CONTAINMENT") != "1":
    pytest.skip("PORTAL_API_BASE_URL and PORTAL_CONTAINMENT=1 are not set", allow_module_level=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"live mode: {name} is required")
    return value


REGION = _required("PORTAL_REGION")
POOL = _required("PORTAL_USER_POOL_ID")
CLIENT = _required("PORTAL_CLIENT_ID")
RUNTIME_ARN = _required("PORTAL_CONTAINMENT_RUNTIME_ARN")
EXTERNAL_ID = _required("PORTAL_READER_EXTERNAL_ID")
ENVIRONMENT = os.environ.get("PORTAL_ENVIRONMENT", "nonprod")
EXPECT_SESSIONS = os.environ.get("PORTAL_CONTAINMENT_EXPECT_SESSIONS") == "1"
CLAIMED_TENANT = os.environ.get("PORTAL_CONTAINMENT_CLAIMED_TENANT", "")
CELL_TENANT = os.environ.get("PORTAL_CONTAINMENT_CELL_TENANT", "")
EXPECT_SWEEPS = os.environ.get("PORTAL_CONTAINMENT_EXPECT_SWEEPS") == "1"
SHARED_ACCOUNT = os.environ.get("PORTAL_CONTAINMENT_SHARED_ACCOUNT") == "1"
SHARED_OTHER_TENANT = os.environ.get("PORTAL_CONTAINMENT_SHARED_OTHER_TENANT", "")
SHARED_UNHELD_TENANT = os.environ.get("PORTAL_CONTAINMENT_SHARED_UNHELD_TENANT", "")
TENANT_TAG = "tenant-id"

_ARN = RUNTIME_ARN.split(":")
if len(_ARN) != 6 or _ARN[2] != "bedrock-agentcore" or not _ARN[5].startswith("runtime/"):
    raise RuntimeError("live mode: PORTAL_CONTAINMENT_RUNTIME_ARN is not an AgentCore Runtime ARN")
RUNTIME_REGION, CELL_ACCOUNT, RUNTIME_ID = _ARN[3], _ARN[4], _ARN[5].split("/", 1)[1]
AGENT_ID = os.environ.get("PORTAL_CONTAINMENT_AGENT_ID") or RUNTIME_ID

import boto3  # noqa: E402
import pyotp  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from pycognito.aws_srp import AWSSRP  # noqa: E402

RUN = uuid.uuid4().hex[:10]
MARKER = f"portal-live-{RUN}"
SAFETY_TAG = ("portal-containment-test", "allowed")
CONTAINMENT_SID = "AgenticAIPortalContainment"
KEPT_SID = "PortalLiveValidationKeepMe"
GROUPS = {
    "security": "security-and-risk",
    "security_b": "security-and-risk",
    "platform": "platform-engineering",
    "sre": "platform-sre",
    "developer": "product-teams",
    "readonly": "portal-readonly",
}
# The service applies a change to a Runtime's resource policy host by host. Measured: after a
# contain an occasional invocation still succeeds for up to about a minute; after a release
# refusals continue, at a falling rate, for several minutes. So "closed" is asserted as a quiet
# period with no successful call, and "open again" as the first successful call.
CLOSED_QUIET_SECONDS = 45
CLOSED_TIMEOUT_SECONDS = 240
FIRST_ANSWER_TIMEOUT_SECONDS = 180


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


class Cell:
    """The cell account's own view of the Runtime: invoke it, read and restore its policy."""

    def __init__(self, session) -> None:
        self.control = session.client("bedrock-agentcore-control", region_name=RUNTIME_REGION)
        self.data = session.client("bedrock-agentcore", region_name=RUNTIME_REGION)
        self.account = session.client("sts").get_caller_identity()["Account"]

    def invoke(self, session_id: str | None = None) -> tuple[object, str]:
        """200, or the error code. A new session each time unless one is given."""
        session_id = session_id or f"{MARKER}-{uuid.uuid4().hex}{uuid.uuid4().hex}"[:60]
        try:
            response = self.data.invoke_agent_runtime(
                agentRuntimeArn=RUNTIME_ARN,
                runtimeSessionId=session_id,
                payload=json.dumps({"prompt": "portal live validation"}).encode(),
                contentType="application/json",
            )
            response["response"].read()
            return response["statusCode"], session_id
        except ClientError as error:
            return error.response["Error"]["Code"], session_id

    def first(self, expected: object, timeout: int = FIRST_ANSWER_TIMEOUT_SECONDS) -> float:
        """Seconds until invocation first answers `expected`."""
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if self.invoke()[0] == expected:
                return time.monotonic() - started
            time.sleep(2)
        raise AssertionError(f"invocation never answered {expected!r} within {timeout} s")

    def closed(self) -> float:
        """Seconds until no invocation has succeeded for CLOSED_QUIET_SECONDS in a row."""
        started = quiet_since = time.monotonic()
        while time.monotonic() - started < CLOSED_TIMEOUT_SECONDS:
            if self.invoke()[0] == "AccessDeniedException":
                if time.monotonic() - quiet_since >= CLOSED_QUIET_SECONDS:
                    return quiet_since - started
            else:
                quiet_since = time.monotonic()
            time.sleep(2)
        raise AssertionError(f"invocations were still succeeding {CLOSED_TIMEOUT_SECONDS} s after containment")

    def opened(self, quiet: int = 40, timeout: int = 420) -> float:
        """Seconds until no invocation has been refused for `quiet` seconds in a row."""
        started = quiet_since = time.monotonic()
        while time.monotonic() - started < timeout:
            if self.invoke()[0] == 200:
                if time.monotonic() - quiet_since >= quiet:
                    return quiet_since - started
            else:
                quiet_since = time.monotonic()
            time.sleep(2)
        raise AssertionError(f"invocations were still refused {timeout} s after the release")

    def refused_share(self, calls: int = 10) -> float:
        """The share of `calls` invocations that are refused right now."""
        refused = 0
        for _ in range(calls):
            refused += self.invoke()[0] == "AccessDeniedException"
            time.sleep(1)
        return refused / calls

    def policy(self) -> dict | None:
        try:
            raw = self.control.get_resource_policy(resourceArn=RUNTIME_ARN).get("policy")
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise
        return json.loads(raw) if raw else None

    def statements(self) -> list[dict]:
        document = self.policy() or {}
        value = document.get("Statement", [])
        return value if isinstance(value, list) else [value]

    def sids(self) -> set[str]:
        return {s.get("Sid", "") for s in self.statements()}

    def session_is_active(self, session_id: str) -> bool:
        """Stopping a session answers ResourceNotFoundException when it has already ended."""
        try:
            self.data.stop_runtime_session(runtimeSessionId=session_id, agentRuntimeArn=RUNTIME_ARN)
            return True
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            raise

    def tenant_tag(self) -> str | None:
        return self.control.list_tags_for_resource(resourceArn=RUNTIME_ARN).get("tags", {}).get(TENANT_TAG)

    def set_tenant_tag(self, value: str | None) -> None:
        """What the cell's pipeline does when it deploys a Runtime: say whose it is."""
        if value is None:
            self.control.untag_resource(resourceArn=RUNTIME_ARN, tagKeys=[TENANT_TAG])
        else:
            self.control.tag_resource(resourceArn=RUNTIME_ARN, tags={TENANT_TAG: value})

    def remove_statements(self, sids: set[str]) -> None:
        """Owned cleanup: drop exactly the named statements, keep every other one."""
        document = self.policy()
        if not document:
            return
        kept = [s for s in self.statements() if s.get("Sid") not in sids]
        if len(kept) == len(self.statements()):
            return
        if kept:
            document["Statement"] = kept
            self.control.put_resource_policy(resourceArn=RUNTIME_ARN, policy=json.dumps(document))
        else:
            self.control.delete_resource_policy(resourceArn=RUNTIME_ARN)


@pytest.fixture(scope="module")
def live(workload_session):
    """Signed-in personas and the cell's view of the target Runtime."""
    cell = Cell(workload_session)
    assert cell.account == CELL_ACCOUNT, "the workload credentials are not for the Runtime's account"
    tags = cell.control.list_tags_for_resource(resourceArn=RUNTIME_ARN).get("tags", {})
    if tags.get(SAFETY_TAG[0]) != SAFETY_TAG[1]:
        raise RuntimeError(
            f"refusing to block {RUNTIME_ID}: it is not tagged {SAFETY_TAG[0]}={SAFETY_TAG[1]}. "
            "Point this module at a validation Runtime, never at a production agent."
        )
    if cell.sids() & {CONTAINMENT_SID, KEPT_SID}:
        raise RuntimeError("the target Runtime is already contained or holds a leftover test statement; release it first")

    idp = boto3.client("cognito-idp", region_name=REGION)
    created: list[str] = []
    state = {"tokens": {}, "cell": cell, "records": []}
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
            created.append(email)
            idp.admin_set_user_password(UserPoolId=POOL, Username=email, Password=password, Permanent=True)
            idp.admin_add_user_to_group(UserPoolId=POOL, Username=email, GroupName=group)
            state["tokens"][persona] = _sign_in(idp, email, password)
        yield state
    finally:
        # Owned cleanup only: the two statements this module can add, its records, then its users.
        cell.remove_statements({CONTAINMENT_SID, KEPT_SID})
        for record_id in state["records"]:
            if state["tokens"].get("platform"):
                _call("DELETE", f"/registrations/{record_id}", state["tokens"]["platform"])
        for email in created:
            idp.admin_delete_user(UserPoolId=POOL, Username=email)


def _contain(token, reason="Live validation: contain the validation Runtime."):
    return _call("POST", f"/agents/{AGENT_ID}/containment/contain", token, {"reason": reason, "runtime_arn": RUNTIME_ARN})


def _release(token, reason="Live validation: release the validation Runtime."):
    return _call("POST", f"/agents/{AGENT_ID}/containment/release", token, {"reason": reason, "runtime_arn": RUNTIME_ARN})


def _view(token) -> dict:
    # While a registration names the Runtime the agent is listed under the registration's id, and
    # the list is cached for a short time: just after such a registration is removed, the
    # Runtime's own id can answer 404 for a moment.
    deadline = time.monotonic() + 60
    while True:
        status, body = _call("GET", f"/agents/{AGENT_ID}/containment", token)
        if status != 404 or time.monotonic() > deadline:
            break
        time.sleep(5)
    assert status == 200, body
    return body


def test_the_target_is_invocable_and_containment_is_enabled_for_its_cell(live):
    cell, tokens = live["cell"], live["tokens"]
    # Tolerant of an earlier run: refusals can linger for minutes after a release.
    cell.first(200)
    view = _view(tokens["security"])
    assert view["state"] == "not_contained", view
    assert view["enabled"] is True, "the Runtime's cell has not deployed the containment stage"
    assert view["runtime_arn"] == RUNTIME_ARN


def test_contain_is_refused_without_the_role_the_tenant_or_a_reason(live):
    cell, tokens = live["cell"], live["tokens"]
    assert _contain(None)[0] == 401
    for persona, rule in (("developer", "CON-01-N"), ("readonly", "CON-01-N")):
        status, body = _contain(tokens[persona])
        assert status == 403, (persona, body)
        assert rule in json.dumps(body), (persona, body)
    # The sre role may contain, but this sre holds no tenant.
    status, body = _contain(tokens["sre"])
    assert status == 403, body
    assert "CON-04-N" in json.dumps(body) or "CON-05-N" in json.dumps(body), body
    status, body = _call("POST", f"/agents/{AGENT_ID}/containment/contain", tokens["security"], {"reason": ""})
    assert status == 422, body
    status, body = _call("POST", f"/agents/{AGENT_ID}/containment/contain", tokens["security"], {})
    assert status == 422, body
    # Nothing was changed by any refusal.
    assert CONTAINMENT_SID not in cell.sids()
    assert _view(tokens["security"])["state"] == "not_contained"
    cell.first(200)


def test_contain_blocks_invocation_and_stops_the_running_session(live):
    cell, tokens = live["cell"], live["tokens"]
    # A release in an earlier run can still be spreading: some hosts refuse for a few minutes.
    deadline = time.monotonic() + FIRST_ANSWER_TIMEOUT_SECONDS
    while True:
        status, running = cell.invoke()
        if status == 200 or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert status == 200
    if EXPECT_SESSIONS:
        time.sleep(25)  # the session's log stream and spans take a few seconds to appear

    status, result = _contain(tokens["security"])
    assert status == 200, result
    assert result["action"] == "contain" and result["outcome"] == "allowed", result
    assert result["state"] == "contained" and result["changed"] is True
    assert result["runtime_arn"] == RUNTIME_ARN
    assert result["request_id"]
    assert "bedrock-agentcore:InvokeAgentRuntime" in result["denied_actions"]
    assert result["other_statements_kept"] == 0
    assert result["audit_complete"] is True
    assert {s["id"]: s["status"] for s in result["steps"]}["policy"] == "done"
    live["contain_request"] = result["request_id"]

    # The effect, measured from the cell account: the statement is there, and invocation is denied
    # for a new session and for the one that was running.
    statement = next(s for s in cell.statements() if s.get("Sid") == CONTAINMENT_SID)
    assert statement["Effect"] == "Deny" and statement["Principal"] == "*"
    assert statement["Resource"] == RUNTIME_ARN
    live["seconds_to_deny"] = cell.first("AccessDeniedException")
    live["seconds_to_closed"] = cell.closed()
    assert cell.invoke(running)[0] == "AccessDeniedException"

    sessions = result["sessions"]
    assert sessions is not None
    live["sessions"] = sessions
    if EXPECT_SESSIONS:
        assert sessions["found"] >= 1 and sessions["stopped"] >= 1, sessions
        assert sessions["failed"] == 0, sessions
        assert cell.session_is_active(running) is False, "the running session was not stopped"

    view = _view(tokens["security"])
    assert view["state"] == "contained" and view["contained_by_me"] is True
    assert MARKER in (view["contained_by_label"] or "")
    assert _view(tokens["platform"])["contained_by_me"] is False
    # The incident record is for the roles that can act. Everyone else sees that it is contained.
    for persona in ("developer", "readonly"):
        redacted = _view(tokens[persona])
        assert redacted["state"] == "contained" and redacted["contained_at"], persona
        assert redacted["contained_by"] is None and redacted["contained_by_label"] is None, persona
        assert redacted["reason"] is None and redacted["events"] == [], persona


def test_containing_a_contained_agent_changes_nothing(live):
    cell, tokens = live["cell"], live["tokens"]
    before = cell.policy()
    started = time.monotonic()
    status, result = _contain(tokens["platform"], "Live validation: second contain.")
    elapsed = time.monotonic() - started
    assert status == 200, result
    assert result["outcome"] == "unchanged" and result["changed"] is False
    assert result["state"] == "contained"
    assert cell.policy() == before
    if EXPECT_SWEEPS:
        # The sweeps of the first contain are still to run: a repeated contain neither stops
        # sessions again nor schedules more, so it cannot be used to hold the function's capacity.
        assert result["sweeps_scheduled_in_seconds"] == [], result
        assert elapsed < 8, f"a repeated contain took {elapsed:.1f} s while sweeps were pending"
    # The person who contained first is still the one on record.
    assert _view(tokens["security"])["contained_by_me"] is True


def test_release_needs_the_role_and_a_second_person(live):
    cell, tokens = live["cell"], live["tokens"]
    status, body = _release(tokens["security"])
    assert status == 403, body
    assert "CON-03-N" in json.dumps(body), body
    status, body = _release(tokens["developer"])
    assert status == 403, body
    assert "CON-02-N" in json.dumps(body), body
    # The sre role may contain but never release.
    status, body = _release(tokens["sre"])
    assert status == 403, body
    assert _release(None)[0] == 401
    # Still contained after every refusal.
    assert CONTAINMENT_SID in cell.sids()
    assert _view(tokens["platform"])["state"] == "contained"
    assert cell.invoke()[0] == "AccessDeniedException"


def test_a_different_person_releases_and_invocation_works_again(live):
    cell, tokens = live["cell"], live["tokens"]
    status, result = _release(tokens["platform"])
    assert status == 200, result
    assert result["action"] == "release" and result["outcome"] == "allowed", result
    assert result["state"] == "not_contained" and result["changed"] is True
    assert result["policy_deleted"] is True, "the policy held only the containment statement"
    assert cell.policy() is None
    live["seconds_to_allow"] = cell.first(200)
    live["refused_after_release"] = cell.refused_share()

    status, again = _release(tokens["platform"])
    assert status == 200, again
    assert again["outcome"] == "unchanged" and again["changed"] is False
    view = _view(tokens["security"])
    assert view["state"] == "not_contained" and view["contained_by_me"] is False


def test_the_audit_trail_records_the_refusals_and_the_decisions(live):
    events = _view(live["tokens"]["platform"])["events"]
    mine = [e for e in events if MARKER in (e.get("actor_label") or "")]
    results = {(e["action"], e["outcome"]) for e in mine if e["phase"] == "result"}
    assert {
        ("contain", "allowed"),
        ("contain", "unchanged"),
        ("release", "denied"),
        ("release", "allowed"),
    } <= results, results
    # A refusal of someone who holds the Runtime's tenant is in its history: the person who
    # contained it asked to release it.
    refused_release = [e for e in mine if e["action"] == "release" and e["outcome"] == "denied"]
    assert refused_release and all("CON-03-N" in e["reason"] for e in refused_release), refused_release
    assert all("-security@" in e["actor_label"] for e in refused_release), refused_release
    # Whoever lacks the role (developer, readonly, and sre for a release) or the tenant (this sre)
    # was refused and left nothing here: those refusals are in the function's log. So nobody can
    # write into the history of an agent they have no authority over.
    assert ("contain", "denied") not in results, results
    for persona in ("sre", "developer", "readonly"):
        assert not [e for e in mine if f"-{persona}@" in e["actor_label"]], persona
    # An intent is recorded before anything is changed, with the same request id as its result.
    contained = next(e for e in mine if e["action"] == "contain" and e["outcome"] == "allowed" and e["phase"] == "result")
    assert contained["request_id"] == live["contain_request"]
    assert any(
        e["phase"] == "intent" and e["request_id"] == live["contain_request"] and e["action"] == "contain" for e in mine
    )
    assert contained["status_before"] == "not_contained" and contained["status_after"] == "contained"
    # Shown with `pytest -rP`: the measured enforcement times, for the evidence record.
    print(
        f"containment: first refusal after {live['seconds_to_deny']:.0f} s, no successful call after "
        f"{live['seconds_to_closed']:.0f} s; release: first successful call after {live['seconds_to_allow']:.0f} s, "
        f"{live['refused_after_release']:.0%} of calls still refused just after; "
        f"sessions {json.dumps(live['sessions'], sort_keys=True)}"
    )


def test_containment_keeps_every_statement_it_did_not_write(live):
    cell, tokens = live["cell"], live["tokens"]
    kept = {
        "Sid": KEPT_SID,
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{CELL_ACCOUNT}:root"},
        "Action": "bedrock-agentcore:InvokeAgentRuntime",
        "Resource": RUNTIME_ARN,
    }
    cell.control.put_resource_policy(
        resourceArn=RUNTIME_ARN, policy=json.dumps({"Version": "2012-10-17", "Statement": [kept]})
    )
    original = cell.statements()
    assert len(original) == 1

    status, result = _contain(tokens["platform"], "Live validation: contain with an existing policy.")
    assert status == 200, result
    assert result["changed"] is True and result["other_statements_kept"] == 1
    during = cell.statements()
    assert [s for s in during if s.get("Sid") != CONTAINMENT_SID] == original, "an existing statement was altered"
    assert CONTAINMENT_SID in {s.get("Sid") for s in during}
    cell.closed()  # an explicit deny wins over the kept allow

    status, result = _release(tokens["security"], "Live validation: release with an existing policy.")
    assert status == 200, result
    assert result["changed"] is True and result["policy_deleted"] is False
    assert result["other_statements_kept"] == 1
    assert cell.statements() == original, "release must leave the policy exactly as it found it"
    cell.first(200)

    cell.remove_statements({KEPT_SID})
    assert cell.policy() is None


def _registration(tenant: str, suffix: str) -> dict:
    return {
        "tenant_id": tenant,
        "agent_id": f"live-{RUN}-{suffix}",
        "environment": ENVIRONMENT,
        "owner_group": "live-validation",
        "business_purpose": f"Live validation {MARKER}: a registration that names the validation Runtime.",
        "risk_class": "limited",
        "data_classification": "internal",
        "cost_centre": "validation",
        "runtime_arn": RUNTIME_ARN,
    }


def test_a_registration_cannot_claim_the_runtime_for_a_tenant_whose_cell_it_is_not_in(live):
    """The attack: register the Runtime for another tenant, to bring it into that tenant's reach."""
    if not (CLAIMED_TENANT and CELL_TENANT):
        pytest.skip("PORTAL_CONTAINMENT_CLAIMED_TENANT and PORTAL_CONTAINMENT_CELL_TENANT are not set")
    tokens = live["tokens"]
    status, body = _call("POST", "/registrations", tokens["developer"], _registration(CLAIMED_TENANT, "claim"))
    if status == 201:  # leave nothing behind before failing
        live["records"].append(body["registration"]["record_id"])
    assert status == 403, body
    assert "tenant" in json.dumps(body).lower() and "-N)" in json.dumps(body), body
    listed = _call("GET", "/registrations", tokens["platform"])[1]
    assert not [r for r in listed if r["agent_id"] == f"live-{RUN}-claim"], "a refused registration left a record"


def test_the_history_follows_the_runtime_whichever_id_a_request_uses(live):
    """Contain through a registration's id, then try to release through the Runtime's own id."""
    if not CELL_TENANT:
        pytest.skip("PORTAL_CONTAINMENT_CELL_TENANT is not set")
    cell, tokens = live["cell"], live["tokens"]
    status, created = _call("POST", "/registrations", tokens["developer"], _registration(CELL_TENANT, "twin"))
    assert status == 201, created
    record_id = created["registration"]["record_id"]
    live["records"].append(record_id)
    by_record = f"/agents/{record_id}/containment"

    status, result = _call(
        "POST", f"{by_record}/contain", tokens["security"], {"reason": "Live validation: contain by record id."}
    )
    assert status == 200, result
    assert result["runtime_arn"] == RUNTIME_ARN and result["changed"] is True
    cell.closed()
    events = _events_of_the_runtime(tokens["platform"], record_id)
    contained = next(e for e in events if e["request_id"] == result["request_id"] and e["phase"] == "result")
    assert contained["tenant_id"] == CELL_TENANT, "the tenant that decides is the cell's"

    # The person who contained it under the record id cannot release it under either id.
    status, body = _release(tokens["security"])
    assert status == 403 and "CON-03-N" in json.dumps(body), body
    status, body = _call("POST", f"{by_record}/release", tokens["security"], {"reason": "Same person, other id."})
    assert status == 403 and "CON-03-N" in json.dumps(body), body
    assert CONTAINMENT_SID in cell.sids()

    # A different person can, and the one history holds everything, whichever id each request used.
    status, released = _release(tokens["platform"])
    assert status == 200 and released["state"] == "not_contained", released
    cell.first(200)
    events = _events_of_the_runtime(tokens["platform"], record_id)
    wanted = (result["request_id"], released["request_id"])
    outcomes = {(e["action"], e["outcome"]) for e in events if e["request_id"] in wanted}
    assert {("contain", "allowed"), ("release", "allowed")} <= outcomes

    status, body = _call("DELETE", f"/registrations/{record_id}", tokens["platform"])
    assert status == 200, body
    live["records"].remove(record_id)


def test_containment_finishes_in_the_background(live, platform_session):
    """The second sweep runs after every host applies the deny and records that the agent is quiet.
    A principal that can invoke the sweeper directly cannot make it write or run anything more."""
    if not EXPECT_SWEEPS:
        pytest.skip("PORTAL_CONTAINMENT_EXPECT_SWEEPS=1 is not set")
    cell, tokens = live["cell"], live["tokens"]
    status, result = _contain(tokens["security"], "Live validation: contain, then let the sweeps finish.")
    assert status == 200 and result["changed"] is True, result
    scheduled = result["sweeps_scheduled_in_seconds"]
    assert 120 in scheduled and 900 in scheduled, scheduled
    background = next(step for step in result["steps"] if step["id"] == "background")
    # Nothing has been stopped in the background yet when the request answers.
    assert background["status"] == "scheduled", background

    # Try to start sessions while some hosts have not applied the deny yet (up to about a minute).
    late, started = [], time.monotonic()
    while time.monotonic() - started < 70:
        status, session_id = cell.invoke()
        if status == 200:
            late.append(session_id)
        time.sleep(1)

    # Sweep 2 becomes visible 120 seconds after the contain. Wait for its event: the history also
    # holds the sweeps of earlier contains, so the one that counts carries this contain's request id.
    deadline, sweep = time.monotonic() + 240, None
    while time.monotonic() < deadline and sweep is None:
        view = _view(tokens["platform"])
        sweep = next(
            (
                e
                for e in view["events"]
                if e["action"] == "sweep" and e.get("sweep") == 2 and e["request_id"] == result["request_id"]
            ),
            None,
        )
        if sweep is None:
            time.sleep(10)
    assert sweep is not None, "the second sweep of this contain did not run"
    assert sweep["outcome"] == "allowed", sweep
    assert sweep["actor_role"] == "system", "a sweep is the portal's own act, not a person's"
    assert view["quiet_at"], "a clean sweep after the enforcement delay means the agent is quiet"
    assert view["sweeps"]["scheduled"] >= 2 and view["sweeps"]["done"] >= 1, view["sweeps"]
    for session_id in late:
        assert cell.session_is_active(session_id) is False, "a session that slipped in was left running"
    # A sweep is not a decision: the person who contained it is still the one on record.
    assert _view(tokens["security"])["contained_by_me"] is True

    # The sweeper is fed by its queue, which only the containment role can write to. A principal
    # of the Platform account that may invoke functions can still call it with an event of its
    # own. Whatever that event says, the history gains nothing: an invalid message, a request id
    # no contain has, a replay of the sweep that ran, and the third sweep sent before it is due.
    functions, by_handler = _functions_by_handler(platform_session)

    def sweeper(body: object) -> str:
        text = body if isinstance(body, str) else json.dumps(body)
        event = {"Records": [{"messageId": str(uuid.uuid4()), "receiptHandle": "forged", "body": text, "eventSource": "aws:sqs"}]}
        response = functions.invoke(FunctionName=by_handler["sweep_handler.handler"], Payload=json.dumps(event).encode())
        answer = response["Payload"].read().decode()
        return "error" if "FunctionError" in response else answer

    def sweep_events() -> list[tuple]:
        events = _view(tokens["platform"])["events"]
        return sorted((e["request_id"], e.get("sweep"), e["outcome"]) for e in events if e["action"] == "sweep")

    before = sweep_events()
    message = {
        "version": 1,
        "kind": "containment_sweep",
        "sweep": 2,
        "runtime_arn": RUNTIME_ARN,
        "agent_id": AGENT_ID,
        "request_id": result["request_id"],
    }
    two_records = {
        "Records": [
            {"messageId": str(uuid.uuid4()), "receiptHandle": "forged", "body": json.dumps(message), "eventSource": "aws:sqs"}
            for _ in range(2)
        ]
    }
    response = functions.invoke(FunctionName=by_handler["sweep_handler.handler"], Payload=json.dumps(two_records).encode())
    assert "FunctionError" not in response and json.loads(response["Payload"].read()) == {"handled": 0}, (
        "an invocation with more than one record must run nothing"
    )
    answers = {
        "not a sweep request": sweeper("portal live validation: not a sweep request"),
        "an extra field": sweeper({**message, "role_arn": f"arn:aws:iam::{CELL_ACCOUNT}:role/Admin"}),
        "a request id no contain has": sweeper({**message, "request_id": str(uuid.uuid4())}),
        "a replay of the sweep that ran": sweeper(message),
        "the third sweep before it is due": sweeper({**message, "sweep": 3}),
    }
    assert sweep_events() == before, f"a direct invocation of the sweeper added to the history: {answers}"
    assert answers["the third sweep before it is due"] == "error", answers
    for name in ("not a sweep request", "an extra field", "a request id no contain has", "a replay of the sweep that ran"):
        assert answers[name] != "error", (name, answers)

    # A release must find who holds the containment however much happens after the contain. So
    # only what can change the holder is written where a release reads: the contain's intent and
    # result. A contain asked for again, a sweep and a refused release are written beside it.
    status, repeated = _contain(tokens["platform"], "Live validation: contain asked for again.")
    assert status == 200 and repeated["outcome"] == "unchanged", repeated
    for _ in range(3):
        status, body = _release(tokens["security"])
        assert status == 403 and "CON-03-N" in json.dumps(body), body
    table = next(
        resource["PhysicalResourceId"]
        for page in platform_session.client("cloudformation", region_name=REGION)
        .get_paginator("list_stack_resources")
        .paginate(StackName=os.environ.get("PORTAL_STACK_NAME") or f"AgenticAI-AgentFactoryPortal-{ENVIRONMENT}")
        for resource in page["StackResourceSummaries"]
        if resource["ResourceType"] == "AWS::DynamoDB::Table"
    )
    dynamodb = platform_session.client("dynamodb", region_name=REGION)

    def stored(prefix: str) -> list[dict]:
        items = dynamodb.query(
            TableName=table,
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={":pk": {"S": f"CONTAINMENT#{RUNTIME_ARN}"}, ":prefix": {"S": prefix}},
            ScanIndexForward=False,
            Limit=100,
            ConsistentRead=True,
        )["Items"]
        return [{name: next(iter(value.values())) for name, value in item.items()} for item in items]

    deciding = stored("EVENT#")
    mine = [e for e in deciding if e.get("request_id") == result["request_id"]]
    assert sorted(e["phase"] for e in mine) == ["intent", "result"], mine
    assert deciding[0]["request_id"] == result["request_id"], "something after the contain was written where a release reads"
    beside = stored("OTHER#")
    kinds = {(e.get("action"), e.get("outcome")) for e in beside}
    assert ("sweep", "allowed") in kinds and ("contain", "unchanged") in kinds, kinds
    # Refused releases of earlier containments in this run are in the same history: count the
    # ones that came after this contain.
    contained_at = max(e["at"] for e in mine)
    refusals = [
        e
        for e in beside
        if e.get("action") == "release" and e.get("outcome") == "denied" and e["at"] > contained_at and MARKER in e.get("actor_label", "")
    ]
    assert len(refusals) == 1, f"three refused releases by the same person left {len(refusals)} entries"
    print(
        f"sweeps: scheduled {scheduled}; sessions that started after the contain: {len(late)}; "
        f"sweep 2 found {sweep.get('sessions_found')}, stopped {sweep.get('sessions_stopped')}, "
        f"already ended {sweep.get('sessions_not_active')}, in {sweep.get('duration_ms')} ms"
    )

    status, released = _release(tokens["platform"])
    assert status == 200, released
    assert _view(tokens["platform"])["quiet_at"] is None, "quiet since applies to a containment that holds"
    cell.first(200)


def test_another_spelling_of_the_runtimes_arn_is_the_same_runtime(live):
    """The service accepts more than one spelling of a Runtime's ARN (measured: another partition
    string reads the same policy). The history, and so the two-person rule, must not depend on the
    spelling a request uses."""
    if AGENT_ID != RUNTIME_ID:
        pytest.skip("the spelling of the ARN is the caller's only for an agent with no registration")
    cell, tokens = live["cell"], live["tokens"]
    spellings = [RUNTIME_ARN.replace("arn:aws:", f"arn:{partition}:", 1) for partition in ("aws-cn", "aws-us-gov", "aws-xyz")]
    assert all(spelling != RUNTIME_ARN for spelling in spellings)

    def release_as(token, runtime_arn):
        return _call(
            "POST",
            f"/agents/{AGENT_ID}/containment/release",
            token,
            {"reason": "Live validation: release under another spelling of the ARN.", "runtime_arn": runtime_arn},
        )

    status, result = _contain(tokens["security"], "Live validation: contain, then try other spellings of the ARN.")
    assert status == 200 and result["changed"] is True, result
    try:
        # The person who contained it is refused under every spelling: with a refusal, or because
        # the spelling is not accepted at all. Never with a release.
        for spelling in spellings:
            status, body = release_as(tokens["security"], spelling)
            assert status in (403, 409, 422), (spelling, status, body)
            if status == 403:
                assert "CON-03-N" in json.dumps(body), body
            assert CONTAINMENT_SID in cell.sids(), f"the person who contained the agent released it as {spelling}"
        # A contain under another spelling does not make someone else the holder.
        for spelling in spellings:
            status, body = _call(
                "POST",
                f"/agents/{AGENT_ID}/containment/contain",
                tokens["platform"],
                {"reason": "Live validation: contain under another spelling of the ARN.", "runtime_arn": spelling},
            )
            assert status in (200, 409, 422), (spelling, status, body)
        view = _view(tokens["security"])
        assert view["contained_by_me"] is True, "another spelling of the ARN changed who holds the containment"
        if CELL_TENANT:
            # A registration is refused the same spelling, so that no record names a Runtime the
            # portal could not act on under the record's id.
            document = {**_registration(CELL_TENANT, "spelling"), "runtime_arn": spellings[0]}
            status, body = _call("POST", "/registrations", tokens["developer"], document)
            if status == 201:
                live["records"].append(body["registration"]["record_id"])
            assert status == 422, body
    finally:
        status, released = _release(tokens["platform"])
        assert status == 200, released
        cell.first(200, timeout=360)


def test_a_statement_with_the_portals_name_that_denies_nothing_is_not_a_containment(live):
    """Whoever can write the Runtime's policy in the cell can plant a statement that carries the
    portal's identifier. The portal recognises its statement by what it denies, so it neither
    reports such an agent as contained nor leaves the statement in place when asked to contain."""
    cell, tokens = live["cell"], live["tokens"]
    assert CONTAINMENT_SID not in cell.sids()
    # An earlier release in the same run is still spreading for a few minutes; start from a
    # Runtime that every host answers for, so that a refusal below can only be the decoy's.
    cell.opened()
    decoys = [
        # Right identifier, right actions, and a condition that no caller ever meets.
        {"Sid": CONTAINMENT_SID, "Effect": "Deny", "Principal": "*", "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
         "Resource": RUNTIME_ARN, "Condition": {"StringEquals": {"aws:PrincipalTag/portal-validation-never": MARKER}}},
        # Right identifier, and an action that has nothing to do with invoking.
        {"Sid": CONTAINMENT_SID, "Effect": "Deny", "Principal": "*", "Action": ["bedrock-agentcore:GetAgentCard"],
         "Resource": RUNTIME_ARN},
    ]
    planted = None
    for decoy in decoys:
        try:
            cell.control.put_resource_policy(
                resourceArn=RUNTIME_ARN, policy=json.dumps({"Version": "2012-10-17", "Statement": [decoy]})
            )
            planted = decoy
            break
        except ClientError:
            continue
    if planted is None:
        pytest.skip("the service accepted none of the decoy statements")
    try:
        time.sleep(60)  # longer than a deny takes to reach every host
        assert cell.refused_share(12) == 0, "the decoy statement itself blocks invocation; it proves nothing"
        view = _view(tokens["platform"])
        assert view["state"] == "not_contained", view
        status, result = _contain(tokens["security"], "Live validation: contain over a planted statement.")
        assert status == 200, result
        assert result["changed"] is True and result["outcome"] == "allowed", result
        statement = next(s for s in cell.statements() if s.get("Sid") == CONTAINMENT_SID)
        assert "Condition" not in statement and statement["Effect"] == "Deny" and statement["Principal"] == "*"
        assert "bedrock-agentcore:InvokeAgentRuntime" in statement["Action"], statement
        cell.closed()
        assert _view(tokens["security"])["contained_by_me"] is True
    finally:
        _release(tokens["platform"])
        cell.remove_statements({CONTAINMENT_SID})
        cell.first(200, timeout=360)


def test_in_a_shared_account_the_runtimes_own_tag_names_the_tenant(live):
    """Several tenants have a cell in the Runtime's account and Region, so the place alone does
    not say whose the Runtime is. Its `tenant-id` tag does, and only when it names one of them."""
    if not SHARED_ACCOUNT or not CELL_TENANT:
        pytest.skip("PORTAL_CONTAINMENT_SHARED_ACCOUNT=1 and PORTAL_CONTAINMENT_CELL_TENANT are not set")
    cell, tokens = live["cell"], live["tokens"]
    original = cell.tenant_tag()
    try:
        # No tag: the tenant cannot be determined. A responder who holds every tenant of the
        # account is refused, because holding the tenants is not the same as the Runtime being theirs.
        cell.set_tenant_tag(None)
        status, body = _contain(tokens["security"])
        assert status == 403 and "CON-05-N" in json.dumps(body), body
        # A tag that names a tenant the account does not host decides nothing.
        cell.set_tenant_tag(f"elsewhere-{RUN}")
        status, body = _contain(tokens["security"])
        assert status == 403 and "CON-05-N" in json.dumps(body), body
        assert CONTAINMENT_SID not in cell.sids(), "a refused request changed the Runtime's policy"

        # The tag of a tenant that has a cell here: a responder who holds that tenant acts.
        cell.set_tenant_tag(CELL_TENANT)
        status, result = _contain(tokens["security"], "Live validation: the Runtime's tag names the tenant.")
        assert status == 200 and result["changed"] is True, result
        assert CONTAINMENT_SID in cell.sids()
        event = next(e for e in _view(tokens["security"])["events"] if e["request_id"] == result["request_id"] and e["phase"] == "result")
        assert event["tenant_id"] == CELL_TENANT, event
        if SHARED_OTHER_TENANT:
            # Someone in the account moves the Runtime to another tenant while it is contained.
            # That tenant's responder, who is not the person who contained it, is still refused:
            # a changed tag does not hand a contained agent over.
            cell.set_tenant_tag(SHARED_OTHER_TENANT)
            status, body = _release(tokens["security_b"])
            assert status == 403 and "CON-06-N" in json.dumps(body), body
            assert CONTAINMENT_SID in cell.sids(), "a changed tag let another tenant release the agent"
        if SHARED_UNHELD_TENANT:
            # A registration cannot name a Runtime of a shared account unless its author holds
            # every tenant there: the ARN does not say whose Runtime it is.
            status, body = _call("POST", "/registrations", tokens["developer"], _registration(CELL_TENANT, "shared"))
            if status == 201:
                live["records"].append(body["registration"]["record_id"])
            assert status == 403 and "REG-13-N" in json.dumps(body), body
        # The tag is removed while the agent is contained: only the platform role can still act.
        cell.set_tenant_tag(None)
        status, body = _release(tokens["security_b"])
        assert status == 403, body
        status, released = _release(tokens["platform"])
        assert status == 200 and released["changed"] is True, released
        assert CONTAINMENT_SID not in cell.sids()
        cell.first(200, timeout=360)
    finally:
        cell.set_tenant_tag(original)
        cell.remove_statements({CONTAINMENT_SID})


def _events_of_the_runtime(token: str, record_id: str) -> list[dict]:
    """The Runtime's history. The agent is listed under its Runtime id or, once the read API has
    seen the registration, under the record id: the history is the same."""
    deadline = time.monotonic() + 90
    while True:
        for agent_id in (record_id, AGENT_ID):
            status, view = _call("GET", f"/agents/{agent_id}/containment", token)
            if status == 200:
                return view["events"]
        if time.monotonic() > deadline:
            raise AssertionError("the agent's containment view could not be read under either id")
        time.sleep(5)


def test_an_agent_whose_cell_did_not_opt_in_cannot_be_contained(live):
    tokens = live["tokens"]
    status, agents = _call("GET", "/agents", tokens["platform"])
    assert status == 200, agents
    items = agents if isinstance(agents, list) else agents.get("agents", [])
    other = None
    for agent in items:
        agent_id = agent.get("agent_id") or agent.get("id")
        if agent_id == AGENT_ID or not agent.get("agent_arn"):
            continue
        code, view = _call("GET", f"/agents/{agent_id}/containment", tokens["platform"])
        if code == 200 and view["enabled"] is False:
            other = (agent_id, agent["agent_arn"], view["state"])
            break
    if other is None:
        pytest.skip("every agent in the inventory is in a cell that enabled containment")
    agent_id, agent_arn, state_before = other
    status, body = _call(
        "POST",
        f"/agents/{agent_id}/containment/contain",
        tokens["platform"],
        {"reason": "Live validation: expected refusal, the cell did not enable containment.", "runtime_arn": agent_arn},
    )
    assert status == 409, body
    assert _call("GET", f"/agents/{agent_id}/containment", tokens["platform"])[1]["state"] == state_before


def _functions_by_handler(platform_session) -> tuple[object, dict[str, str]]:
    """The Lambda client of the Platform account and the portal's functions, by handler."""
    stack = os.environ.get("PORTAL_STACK_NAME") or f"AgenticAI-AgentFactoryPortal-{ENVIRONMENT}"
    cloudformation = platform_session.client("cloudformation", region_name=REGION)
    functions = platform_session.client("lambda", region_name=REGION)
    by_handler: dict[str, str] = {}
    for page in cloudformation.get_paginator("list_stack_resources").paginate(StackName=stack):
        for resource in page["StackResourceSummaries"]:
            if resource["ResourceType"] == "AWS::Lambda::Function":
                name = resource["PhysicalResourceId"]
                by_handler[functions.get_function_configuration(FunctionName=name)["Handler"]] = name
    return functions, by_handler


def _forged_event(
    route: str, path: str, parameters: dict, body: dict | None, token: str | None = None, method: str = "POST"
) -> dict:
    """What Amazon API Gateway hands a function once its authorizer has accepted a token, written
    by hand: the claims say the caller holds every authority."""
    now = int(time.time())
    claims = {
        "sub": str(uuid.uuid4()),
        "email": f"{MARKER}-forged@example.com",
        "email_verified": "true",
        "cognito:username": f"{MARKER}-forged",
        "cognito:groups": "[platform-engineering security-and-risk human-approvers product-teams]",
        "token_use": "id",
        "iss": f"https://cognito-idp.{REGION}.amazonaws.com/{POOL}",
        "aud": CLIENT,
        "iat": str(now),
        "exp": str(now + 3600),
    }
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    return {
        "version": "2.0",
        "routeKey": f"{method} {route}",
        "rawPath": path,
        "rawQueryString": "",
        "headers": headers,
        "requestContext": {
            "accountId": "000000000000",
            "apiId": "forged",
            "domainName": "forged.invalid",
            "domainPrefix": "forged",
            "http": {"method": method, "path": path, "protocol": "HTTP/1.1", "sourceIp": "192.0.2.1", "userAgent": "forged"},
            "requestId": f"forged-{uuid.uuid4()}",
            "routeKey": f"{method} {route}",
            "stage": "$default",
            "time": "01/Jan/2026:00:00:00 +0000",
            "timeEpoch": now * 1000,
            "authorizer": {"jwt": {"claims": claims, "scopes": None}},
        },
        "pathParameters": parameters,
        **({"body": json.dumps(body)} if body is not None else {}),
        "isBase64Encoded": False,
    }


def _with_other_groups(token: str, groups: list[str]) -> str:
    """A real token whose content says something else; its signature no longer matches."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["cognito:groups"] = groups
    forged = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{header}.{forged}.{signature}"


def _unsigned(token: str) -> str:
    """The same claims under `alg: none`, with no signature."""
    payload = token.split(".")[1]
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}."


def test_a_function_invoked_directly_trusts_nothing_in_the_event(live, platform_session):
    """The functions that decide verify the caller's token themselves.

    A principal of the Platform account that may invoke a function can write the whole event,
    including the claims Amazon API Gateway would have put there. None of it carries weight.
    """
    cell, tokens = live["cell"], live["tokens"]
    functions, by_handler = _functions_by_handler(platform_session)

    def invoke(handler: str, event: dict) -> tuple[int, str]:
        response = functions.invoke(FunctionName=by_handler[handler], Payload=json.dumps(event).encode())
        assert "FunctionError" not in response, response["Payload"].read()[:400]
        answer = json.loads(response["Payload"].read())
        return answer["statusCode"], str(answer.get("body", ""))

    contain_route = "/api/v1/agents/{agent_id}/containment/contain"
    contain_path = f"/api/v1/agents/{AGENT_ID}/containment/contain"
    contain_body = {"reason": "Live validation: a forged request, expected to be refused.", "runtime_arn": RUNTIME_ARN}

    def contain(token: str | None) -> tuple[int, str]:
        return invoke(
            "containment_handler.handler", _forged_event(contain_route, contain_path, {"agent_id": AGENT_ID}, contain_body, token)
        )

    assert CONTAINMENT_SID not in cell.sids()
    # Claims of a responder in the event, and no token at all.
    status, body = contain(None)
    assert status == 401, (status, body[:300])
    # A real token whose content was changed to name the responder groups, and the same claims unsigned.
    for forged in (
        _with_other_groups(tokens["developer"], ["platform-engineering", "security-and-risk"]),
        _unsigned(tokens["platform"]),
        "not.a.token",
    ):
        status, body = contain(forged)
        assert status == 401, (status, body[:300])
    # Claims of a responder in the event beside a developer's real token: the token decides.
    status, body = contain(tokens["developer"])
    assert status == 403 and "CON-01-N" in body, (status, body[:300])
    assert CONTAINMENT_SID not in cell.sids(), "a forged request changed the Runtime's policy"
    # The policy is the proof. The agent also answers; after an earlier release in the same run
    # some hosts can still refuse for a few minutes, so wait for the first answer.
    cell.first(200, timeout=360)

    # The registration functions: the same forged claims, no token.
    document = _registration(CELL_TENANT or "ws1", f"forged-{RUN}")
    status, body = invoke(
        "registrar_handler.handler", _forged_event("/api/v1/registrations", "/api/v1/registrations", {}, document)
    )
    assert status == 401, (status, body[:300])
    record_id = "A" * 12
    status, body = invoke(
        "approver_handler.handler",
        _forged_event(
            "/api/v1/registrations/{record_id}/retire",
            f"/api/v1/registrations/{record_id}/retire",
            {"record_id": record_id},
            {"reason": "Live validation: a forged request, expected to be refused."},
        ),
    )
    assert status == 401, (status, body[:300])
    listed = _call("GET", "/registrations", tokens["platform"])[1]
    assert not [r for r in listed if f"forged-{RUN}" in json.dumps(r)], "a forged request created a registration"

    # The read function: the claims in the event say platform, security and approver. Without a
    # token it answers nothing; beside a developer's real token it answers as the developer.
    def read(path: str, token: str | None) -> tuple[int, str]:
        proxy = path.removeprefix("/api/v1/")
        return invoke("handler.handler", _forged_event("/api/v1/{proxy+}", path, {"proxy": proxy}, None, token, "GET"))

    for path in ("/api/v1/users/me", f"/api/v1/agents/{AGENT_ID}/containment", "/api/v1/agents"):
        status, body = read(path, None)
        assert status == 401, (path, status, body[:200])
    status, body = read("/api/v1/users/me", tokens["developer"])
    assert status == 200, (status, body[:300])
    me = json.loads(body)
    assert me["portal_role"] == "developer" and not me.get("can_contain") and not me.get("can_release"), me


def test_another_principal_cannot_assume_the_cells_containment_role():
    """Negative twin of the contain test: same role, same external id, wrong caller."""
    sts = boto3.client("sts", region_name=REGION)
    with pytest.raises(ClientError) as denied:
        sts.assume_role(
            RoleArn=f"arn:aws:iam::{CELL_ACCOUNT}:role/AgenticAI-PortalContainmentTarget-{ENVIRONMENT}",
            RoleSessionName="portal-negative-twin",
            ExternalId=EXTERNAL_ID,
        )
    assert denied.value.response["Error"]["Code"] == "AccessDenied"
