#!/usr/bin/env python3
"""Apply and verify an exact-caller policy on a deployed IAM inference Gateway.

The policy operation is an audited post-deployment step because the Gateway
CloudFormation resource has no ResourcePolicy property. Verification makes
bounded inference calls with synthetic text; it never prints tokens, request
text, model replies, classifier matches, or presigned Lambda code locations.

Example (keep account IDs and release evidence outside source control):
  python scripts/inference_guardrail_acceptance.py policy \
    --owner-profile OWNER --expected-account ACCOUNT --region REGION \
    --stack-name STACK --allowed-principal-arn OWNER_USER_ARN \
    --allowed-principal-arn WORKSTREAM_USER_ARN --evidence-file RELEASE_JSON
  python scripts/inference_guardrail_acceptance.py verify \
    --owner-profile OWNER --approved-profile WORKSTREAM --outsider-profile OTHER \
    --expected-account ACCOUNT --region REGION --stack-name STACK \
    --allowed-principal-arn OWNER_USER_ARN \
    --allowed-principal-arn WORKSTREAM_USER_ARN --evidence-file VERDICT_JSON

The supplied identities must be reviewed IAM users. These bounded development
checks do not certify protected-role enrollment, Organizations enforcement, or
regulated deployment.

For a three-account proof, add the third exact user to both operations and
repeat --approved-profile for that account. Supply --expected-outsider-arn
with the exact temporary assumed-role session ARN. The negative fixture must
have an identity policy allowing only this Gateway so its explicit resource
policy denial can be tested; create and remove the fixture separately.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError
from botocore.httpsession import URLLib3Session

ACCOUNT = re.compile(r"^\d{12}$")
USER_ARN = re.compile(r"^arn:aws:iam::(\d{12}):user/[A-Za-z0-9+=,.@_/-]+$")
ASSUMED_ROLE_ARN = re.compile(r"^arn:aws:sts::\d{12}:assumed-role/[A-Za-z0-9+=,.@_-]+/[A-Za-z0-9+=,.@_-]+$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d+$")
BENIGN_TEXT = "Reply with exactly the word verified."
SYNTHETIC_TEXT = "The test contact address is qa.person@example.com."
SOURCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "packages/platform-inference-gateway/lambda/guardrail-interceptor/index.py"
)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def caller_policy_digest(policy: dict[str, Any]) -> str:
    """Ignore AWS's ARN-array ordering without widening the reviewed policy."""
    normalized = json.loads(json.dumps(policy))
    for statement in normalized.get("Statement", []):
        principal = statement.get("Principal")
        if isinstance(principal, dict) and isinstance(principal.get("AWS"), list):
            principal["AWS"] = sorted(principal["AWS"])
        condition = statement.get("Condition", {}).get("ArnNotEquals", {})
        if isinstance(condition.get("aws:PrincipalArn"), list):
            condition["aws:PrincipalArn"] = sorted(condition["aws:PrincipalArn"])
    return digest(normalized)


def validate_scope(account: str, region: str, allowed: list[str]) -> list[str]:
    require(bool(ACCOUNT.fullmatch(account)), "Invalid expected account")
    require(bool(REGION.fullmatch(region)), "Invalid explicit Region")
    require(len(allowed) in {2, 3} and len(set(allowed)) == len(allowed), "Exactly two or three distinct reviewed users required")
    matches = [USER_ARN.fullmatch(value) for value in allowed]
    require(all(matches), "Only exact IAM user ARNs are accepted")
    require(any(match.group(1) == account for match in matches if match), "An owner-account user is required")
    require(any(match.group(1) != account for match in matches if match), "A cross-account user is required")
    require(len({match.group(1) for match in matches if match}) == len(allowed), "One reviewed user per account is required")
    return sorted(allowed)


def identity(session: Any, expected_account: str | None = None) -> dict[str, str]:
    value = session.client("sts").get_caller_identity()
    if expected_account:
        require(value["Account"] == expected_account, "Caller account differs from explicit target")
    return {"Account": value["Account"], "Arn": value["Arn"]}


def load_gateway(session: Any, account: str, region: str, stack_name: str) -> dict[str, str]:
    stack = session.client("cloudformation", region_name=region).describe_stacks(
        StackName=stack_name
    )["Stacks"][0]
    require(stack["StackStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}, "Stack is not healthy")
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    required = {
        "GatewayArn", "GatewayIdentifier", "GatewayUrl", "InferenceTargetName",
        "GuardrailInterceptorFunctionArn", "EnforcedGuardrailIdentifier",
        "EnforcedGuardrailVersion",
    }
    require(required <= outputs.keys(), "Inference stack outputs are incomplete")
    prefix = f"arn:aws:bedrock-agentcore:{region}:{account}:gateway/"
    require(outputs["GatewayArn"].startswith(prefix), "Gateway differs from target account/Region")
    parsed = urlparse(outputs["GatewayUrl"])
    require(
        parsed.scheme == "https"
        and parsed.hostname == f"{outputs['GatewayIdentifier']}.gateway.bedrock-agentcore.{region}.amazonaws.com"
        and not parsed.username
        and not parsed.password
        and not parsed.query,
        "Gateway endpoint does not match its AWS resource identity",
    )
    gateway = session.client("bedrock-agentcore-control", region_name=region).get_gateway(
        gatewayIdentifier=outputs["GatewayIdentifier"]
    )
    require(gateway["status"] == "READY" and gateway["authorizerType"] == "AWS_IAM", "IAM Gateway is not READY")
    interceptors = gateway.get("interceptorConfigurations", [])
    require(
        any(
            item.get("interceptionPoints") == ["REQUEST"]
            and item.get("interceptor", {}).get("lambda", {}).get("arn")
            == outputs["GuardrailInterceptorFunctionArn"]
            and item.get("inputConfiguration", {}).get("passRequestHeaders") is False
            for item in interceptors
        ),
        "Exact REQUEST interceptor is not attached",
    )
    return outputs


def caller_policy(gateway_arn: str, allowed: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnapprovedInferenceCallers",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "bedrock-agentcore:InvokeGateway",
                "Resource": gateway_arn,
                "Condition": {"ArnNotEquals": {"aws:PrincipalArn": sorted(allowed)}},
            },
            {
                "Sid": "AllowReviewedInferenceCallers",
                "Effect": "Allow",
                "Principal": {"AWS": sorted(allowed)},
                "Action": "bedrock-agentcore:InvokeGateway",
                "Resource": gateway_arn,
            },
        ],
    }


def apply_policy(session: Any, account: str, region: str, stack_name: str, allowed: list[str]) -> dict[str, Any]:
    allowed = validate_scope(account, region, allowed)
    caller = identity(session, account)
    require(caller["Arn"] in allowed, "Policy writer is not a reviewed owner user")
    outputs = load_gateway(session, account, region, stack_name)
    policy = caller_policy(outputs["GatewayArn"], allowed)
    control = session.client("bedrock-agentcore-control", region_name=region)
    control.put_resource_policy(resourceArn=outputs["GatewayArn"], policy=json.dumps(policy))
    actual = json.loads(control.get_resource_policy(resourceArn=outputs["GatewayArn"])["policy"])
    require(caller_policy_digest(actual) == caller_policy_digest(policy), "Resource policy readback differs from reviewed policy")
    return {
        "operation": "exact-caller-policy", "status": "passed",
        "policySha256": caller_policy_digest(actual), "gatewayArnSha256": digest(outputs["GatewayArn"]),
        "approvedPrincipalSha256": [digest(value) for value in allowed],
    }


def signed_call(session: Any, region: str, outputs: dict[str, str], text: str) -> dict[str, Any]:
    base = outputs["GatewayUrl"].removesuffix("/mcp").rstrip("/")
    body = json.dumps({
        "model": f"{outputs['InferenceTargetName']}/openai.gpt-oss-120b",
        "messages": [{"role": "user", "content": text}],
        "max_tokens": 16,
        "stream": False,
    }, separators=(",", ":")).encode()
    request = AWSRequest(
        method="POST", url=f"{base}/inference/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    credentials = session.get_credentials()
    require(credentials is not None, "Missing request credentials")
    SigV4Auth(credentials.get_frozen_credentials(), "bedrock-agentcore", region).add_auth(request)
    response = URLLib3Session(timeout=120).send(request.prepare())
    raw = response.content
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else None
    error_code = error.get("code", error.get("type")) if isinstance(error, dict) else None
    if not error_code and isinstance(payload, dict):
        error_code = payload.get("__type", payload.get("code"))
    return {
        "status": response.status_code,
        "errorCode": error_code,
        "hasChoices": bool(payload.get("choices")) if isinstance(payload, dict) else False,
        "tripped": error.get("tripped", []) if isinstance(error, dict) else [],
        "textAbsent": text.encode() not in raw,
        "responseSha256": hashlib.sha256(raw).hexdigest(),
        "requestId": response.headers.get("x-amzn-requestid", response.headers.get("x-amz-request-id")),
    }


def assessment_actions(response: dict[str, Any]) -> set[str]:
    actions: set[str] = set()
    for assessment in response.get("assessments") or []:
        for policy, entries in (
            ("contentPolicy", "filters"), ("topicPolicy", "topics"),
            ("wordPolicy", "customWords"), ("wordPolicy", "managedWordLists"),
            ("sensitiveInformationPolicy", "piiEntities"), ("sensitiveInformationPolicy", "regexes"),
        ):
            for item in (assessment.get(policy) or {}).get(entries) or []:
                if item.get("action"):
                    actions.add(item["action"])
    return actions


def verify(owner: Any, approved: Any, outsider: Any, account: str, region: str, stack_name: str, allowed: list[str], expected_outsider_arn: str | None = None) -> dict[str, Any]:
    allowed = validate_scope(account, region, allowed)
    owner_identity = identity(owner, account)
    approved_sessions = approved if isinstance(approved, list) else [approved]
    approved_identities = [identity(session) for session in approved_sessions]
    outsider_identity = identity(outsider)
    require(
        sorted([owner_identity["Arn"], *[item["Arn"] for item in approved_identities]]) == allowed,
        "Positive identities differ from reviewed users",
    )
    require(all(item["Account"] != account for item in approved_identities), "Positive twins must cross accounts")
    require(outsider_identity["Arn"] not in allowed, "Outsider is an approved identity")
    if len(allowed) == 3:
        require(
            bool(expected_outsider_arn) and bool(ASSUMED_ROLE_ARN.fullmatch(expected_outsider_arn or "")),
            "Three-account proof requires an exact negative fixture session ARN",
        )
    if expected_outsider_arn:
        require(outsider_identity["Arn"] == expected_outsider_arn, "Outsider session differs from reviewed negative fixture")
    outputs = load_gateway(owner, account, region, stack_name)
    control = owner.client("bedrock-agentcore-control", region_name=region)
    actual = json.loads(control.get_resource_policy(resourceArn=outputs["GatewayArn"])["policy"])
    require(caller_policy_digest(actual) == caller_policy_digest(caller_policy(outputs["GatewayArn"], allowed)), "Exact-caller policy changed")

    deployed = owner.client("lambda", region_name=region).get_function(
        FunctionName=outputs["GuardrailInterceptorFunctionArn"]
    )
    with urllib.request.urlopen(deployed["Code"]["Location"], timeout=30) as response:
        code = response.read(10_000_001)
    require(len(code) <= 10_000_000, "Unexpectedly large interceptor archive")
    require(
        base64.b64encode(hashlib.sha256(code).digest()).decode() == deployed["Configuration"]["CodeSha256"],
        "Deployed Lambda archive digest differs from AWS metadata",
    )
    with zipfile.ZipFile(io.BytesIO(code)) as archive:
        require(archive.read("index.py") == SOURCE_PATH.read_bytes(), "Live interceptor differs from reviewed source")

    bedrock = owner.client("bedrock-runtime", region_name=region)
    decisions: dict[str, Any] = {}
    for name, text in (("benign", BENIGN_TEXT), ("synthetic_anonymization", SYNTHETIC_TEXT)):
        response = bedrock.apply_guardrail(
            guardrailIdentifier=outputs["EnforcedGuardrailIdentifier"],
            guardrailVersion=outputs["EnforcedGuardrailVersion"],
            source="INPUT", content=[{"text": {"text": text}}],
        )
        decisions[name] = {"action": response.get("action"), "assessmentActions": sorted(assessment_actions(response))}
    require(decisions["benign"]["action"] == "NONE", "Benign calibration did not produce NONE")
    require(
        decisions["synthetic_anonymization"]["action"] == "GUARDRAIL_INTERVENED"
        and "ANONYMIZED" in decisions["synthetic_anonymization"]["assessmentActions"]
        and "BLOCKED" not in decisions["synthetic_anonymization"]["assessmentActions"],
        "Synthetic fixture did not produce anonymization-only intervention",
    )
    benign = signed_call(owner, region, outputs, BENIGN_TEXT)
    require(benign["status"] == 200 and benign["hasChoices"], "Owner benign inference failed")
    sensitive = signed_call(owner, region, outputs, SYNTHETIC_TEXT)
    require(
        sensitive["status"] == 403 and sensitive["errorCode"] == "guardrail_intervened"
        and sensitive["tripped"] == ["guardrail.INTERVENTION"] and sensitive["textAbsent"],
        "Anonymization-only input was not refused by the interceptor",
    )
    cross_accounts = []
    for session, caller in zip(approved_sessions, approved_identities, strict=True):
        cross_account = signed_call(session, region, outputs, BENIGN_TEXT)
        require(cross_account["status"] == 200 and cross_account["hasChoices"], "Approved cross-account inference failed")
        refused = signed_call(session, region, outputs, SYNTHETIC_TEXT)
        require(
            refused["status"] == 403 and refused["errorCode"] == "guardrail_intervened"
            and refused["tripped"] == ["guardrail.INTERVENTION"] and refused["textAbsent"],
            "Approved cross-account anonymization-only input was not refused",
        )
        cross_accounts.append({
            "principalSha256": digest(caller["Arn"]),
            "benign": cross_account, "anonymizationRefused": refused,
        })
    denied = signed_call(outsider, region, outputs, BENIGN_TEXT)
    require(
        denied["status"] == 403 and not denied["hasChoices"] and denied["errorCode"] != "guardrail_intervened",
        "Outsider did not receive an authorization denial",
    )
    return {
        "operation": "guardrail-acceptance", "status": "passed", "classification": decisions,
        "ownerBenign": benign, "anonymizationRefused": sensitive,
        "crossAccountChecks": cross_accounts, "outsiderDenied": denied,
        "policySha256": caller_policy_digest(actual),
        "deployedCodeSha256": deployed["Configuration"]["CodeSha256"],
        "sourceSha256": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
        "scope": "bounded-development; no regulated or Organizations-enforcement certification",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("policy", "verify"))
    parser.add_argument("--owner-profile")
    parser.add_argument("--approved-profile", action="append")
    parser.add_argument("--outsider-profile")
    parser.add_argument("--expected-outsider-arn")
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--allowed-principal-arn", action="append", required=True)
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, Any]
    try:
        validate_scope(args.expected_account, args.region, args.allowed_principal_arn)
        owner = boto3.Session(profile_name=args.owner_profile, region_name=args.region)
        if args.operation == "policy":
            report = apply_policy(owner, args.expected_account, args.region, args.stack_name, args.allowed_principal_arn)
        else:
            require(bool(args.approved_profile) and bool(args.outsider_profile), "Explicit positive and outsider profiles required")
            report = verify(
                owner, [boto3.Session(profile_name=profile, region_name=args.region) for profile in args.approved_profile],
                boto3.Session(profile_name=args.outsider_profile, region_name=args.region),
                args.expected_account, args.region, args.stack_name, args.allowed_principal_arn,
                args.expected_outsider_arn,
            )
    except Exception as exc:
        # Exceptions can include model content, tokens or presigned URL strings.
        report = {"operation": args.operation, "status": "failed", "errorType": type(exc).__name__}
        if isinstance(exc, ClientError):
            report["awsErrorCode"] = exc.response.get("Error", {}).get("Code")
        elif isinstance(exc, ValueError):
            report["check"] = str(exc)
    report["timestamp"] = datetime.now(timezone.utc).isoformat()
    args.evidence_file.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_file.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
