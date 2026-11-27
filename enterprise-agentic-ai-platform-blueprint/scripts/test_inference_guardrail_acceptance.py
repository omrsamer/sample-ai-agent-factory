"""Security boundary tests for the bounded inference acceptance utility."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from botocore.credentials import Credentials

SPEC = importlib.util.spec_from_file_location(
    "inference_guardrail_acceptance",
    Path(__file__).with_name("inference_guardrail_acceptance.py"),
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

OWNER = "123456789012"
REGION = "eu-west-1"
ALLOWED = [
    f"arn:aws:iam::{OWNER}:user/operator",
    "arn:aws:iam::222222222222:user/workstream",
]


class FakeSession:
    def __init__(self, account=OWNER, url=None, caller_arn=None):
        self.account = account
        self.caller_arn = caller_arn or f"arn:aws:iam::{self.account}:user/operator"
        self.url = url or f"https://gateway-test.gateway.bedrock-agentcore.{REGION}.amazonaws.com/mcp"
        self.services = []

    def client(self, service, **kwargs):
        self.services.append(service)
        if service == "sts":
            return SimpleNamespace(get_caller_identity=lambda: {
                "Account": self.account, "Arn": self.caller_arn,
            })
        if service == "cloudformation":
            outputs = {
                "GatewayArn": f"arn:aws:bedrock-agentcore:{REGION}:{OWNER}:gateway/gateway-test",
                "GatewayIdentifier": "gateway-test", "GatewayUrl": self.url,
                "InferenceTargetName": "target", "GuardrailInterceptorFunctionArn": "function",
                "EnforcedGuardrailIdentifier": "guardrail", "EnforcedGuardrailVersion": "DRAFT",
            }
            return SimpleNamespace(describe_stacks=lambda **kwargs: {"Stacks": [{
                "StackStatus": "UPDATE_COMPLETE",
                "Outputs": [{"OutputKey": key, "OutputValue": value} for key, value in outputs.items()],
            }]})
        raise AssertionError(f"Unexpected API client: {service}")

    def get_credentials(self):
        return Credentials("fixture-id", "fixture-secret")


def test_wrong_owner_account_stops_before_resource_policy_writes():
    session = FakeSession(account="333333333333")
    with pytest.raises(ValueError, match="Caller account"):
        probe.apply_policy(session, OWNER, REGION, "Stack", ALLOWED)
    assert session.services == ["sts"]


@pytest.mark.parametrize("unreviewed", [
    "arn:aws:iam::222222222222:user/*",
    "arn:aws:iam::222222222222:role/workstream",
    "arn:aws:sts::222222222222:assumed-role/workstream/session",
])
def test_unreviewed_principal_shapes_stop_before_any_aws_call(unreviewed):
    session = FakeSession()
    with pytest.raises(ValueError, match="exact IAM user"):
        probe.apply_policy(session, OWNER, REGION, "Stack", [ALLOWED[0], unreviewed])
    assert session.services == []


def test_spoofed_stack_endpoint_is_not_used_for_signed_requests():
    session = FakeSession(url="https://gateway-test.gateway.bedrock-agentcore.eu-west-1.amazonaws.com.evil.example/mcp")
    with pytest.raises(ValueError, match="endpoint"):
        probe.load_gateway(session, OWNER, REGION, "Stack")
    assert session.services == ["cloudformation"]


def test_signed_probe_never_includes_reply_or_authorization_in_evidence(monkeypatch):
    reply = "model-private-reply"
    captured = []

    def send(request):
        captured.append(request)
        return SimpleNamespace(
            status_code=200, headers={"x-amzn-requestid": "request-id"},
            content=json.dumps({"choices": [{"message": {"content": reply}}]}).encode(),
        )

    monkeypatch.setattr(probe, "URLLib3Session", lambda **kwargs: SimpleNamespace(send=send))
    result = probe.signed_call(
        FakeSession(), REGION,
        {"GatewayUrl": f"https://gateway-test.gateway.bedrock-agentcore.{REGION}.amazonaws.com/mcp",
         "InferenceTargetName": "target"},
        probe.BENIGN_TEXT,
    )
    assert result["hasChoices"] is True
    assert "Authorization" in captured[0].headers
    assert reply not in json.dumps(result)
    assert "fixture-secret" not in json.dumps(result)
    assert "Authorization" not in json.dumps(result)


def test_three_account_scope_keeps_exact_users_and_explicit_outsider_deny():
    users = [*ALLOWED, "arn:aws:iam::333333333333:user/third"]
    validated = probe.validate_scope(OWNER, REGION, users)
    policy = probe.caller_policy("gateway", validated)
    assert policy["Statement"][0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] == sorted(users)
    assert policy["Statement"][1]["Principal"]["AWS"] == sorted(users)
    with pytest.raises(ValueError, match="One reviewed user per account"):
        probe.validate_scope(OWNER, REGION, [*ALLOWED, "arn:aws:iam::222222222222:user/second"])


def test_three_account_negative_fixture_requires_exact_asserted_session():
    third = "arn:aws:iam::333333333333:user/third"
    expected = "arn:aws:sts::333333333333:assumed-role/negative/reviewed-session"
    owner = FakeSession()
    approved = [
        FakeSession(account="222222222222", caller_arn=ALLOWED[1]),
        FakeSession(account="333333333333", caller_arn=third),
    ]
    outsider = FakeSession(account="333333333333", caller_arn=expected + "-unexpected")
    with pytest.raises(ValueError, match="negative fixture"):
        probe.verify(owner, approved, outsider, OWNER, REGION, "Stack", [*ALLOWED, third], expected)
    assert owner.services == ["sts"]
    assert outsider.services == ["sts"]


def test_policy_comparison_accepts_aws_arn_ordering_but_rejects_added_caller():
    reviewed = probe.caller_policy("gateway", ALLOWED)
    readback = json.loads(json.dumps(reviewed))
    readback["Statement"][0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"].reverse()
    readback["Statement"][1]["Principal"]["AWS"].reverse()
    assert probe.caller_policy_digest(readback) == probe.caller_policy_digest(reviewed)
    readback["Statement"][1]["Principal"]["AWS"].append("arn:aws:iam::333333333333:user/unreviewed")
    assert probe.caller_policy_digest(readback) != probe.caller_policy_digest(reviewed)
