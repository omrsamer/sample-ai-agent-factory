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

It also proves that containment keeps every statement of the Runtime's
resource policy that it did not write.

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
                                       Runtime must write logs or emit spans)
  Credentials of the cell account (AWS_PROFILE_WORKLOAD or the *_WORKLOAD
  keys of conftest.py), used only to invoke the Runtime and read its policy.

The `security-and-risk` group must hold the agent's tenant and the
`platform-sre` group must not (PORTAL_GROUP_TENANT_MAP of the deployment).

The run creates users whose names carry a per-run marker and removes exactly
those. If it stops part-way, it removes the containment statement it added
and nothing else.
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
    state = {"tokens": {}, "cell": cell}
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
        # Owned cleanup only: the two statements this module can add, then its users.
        cell.remove_statements({CONTAINMENT_SID, KEPT_SID})
        for email in created:
            idp.admin_delete_user(UserPoolId=POOL, Username=email)


def _contain(token, reason="Live validation: contain the validation Runtime."):
    return _call("POST", f"/agents/{AGENT_ID}/containment/contain", token, {"reason": reason, "runtime_arn": RUNTIME_ARN})


def _release(token, reason="Live validation: release the validation Runtime."):
    return _call("POST", f"/agents/{AGENT_ID}/containment/release", token, {"reason": reason, "runtime_arn": RUNTIME_ARN})


def _view(token) -> dict:
    status, body = _call("GET", f"/agents/{AGENT_ID}/containment", token)
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
    status, running = cell.invoke()
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


def test_containing_a_contained_agent_changes_nothing(live):
    cell, tokens = live["cell"], live["tokens"]
    before = cell.policy()
    status, result = _contain(tokens["platform"], "Live validation: second contain.")
    assert status == 200, result
    assert result["outcome"] == "unchanged" and result["changed"] is False
    assert result["state"] == "contained"
    assert cell.policy() == before
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
        ("contain", "denied"),
        ("contain", "allowed"),
        ("contain", "unchanged"),
        ("release", "denied"),
        ("release", "allowed"),
    } <= results, results
    refused_release = [e for e in mine if e["action"] == "release" and e["outcome"] == "denied"]
    assert any("CON-03-N" in e["reason"] for e in refused_release)
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
