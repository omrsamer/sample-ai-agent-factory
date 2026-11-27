"""Offline attack/control tests for the read-only protected-authority verifier."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import sys
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import botocore.session
import pytest
from botocore.exceptions import ClientError

SPEC = importlib.util.spec_from_file_location(
    "verify_protected_authority",
    Path(__file__).with_name("verify-protected-authority.py"),
)
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)

MEMBER = "111111111111"
CONTROL = "222222222222"
MANAGEMENT = "333333333333"
ROLE = f"arn:aws:iam::{MEMBER}:role/ProtectedGatewayAdmin"
ROLE_ID = "AROAABCDEFGHIJKLMNOPQ"
FUNCTION = f"arn:aws:lambda:us-east-1:{MEMBER}:function:GeneratedProvider"
STACK = f"arn:aws:cloudformation:us-east-1:{MEMBER}:stack/UnrelatedLegacyStack/abcd"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
INLINE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}
    ],
}
TEMPLATE = {"Resources": {"Provider": {"Type": "AWS::Lambda::Function"}}}
POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "iam:DeleteRole", "Resource": ROLE}],
}


def expected_digest(value):
    """Independent spelling of the documented canonical JSON protocol."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


class Missing(Exception):
    pass


class FakePaginator:
    def __init__(self, client, operation):
        self.client, self.operation = client, operation

    def paginate(self, **kwargs):
        self.client.calls.append((self.operation, kwargs, "paginated"))
        result = self.client.responses[self.operation]
        if isinstance(result, Exception):
            raise result
        yield from copy.deepcopy(result(kwargs) if callable(result) else result)


class FakeClient:
    def __init__(self, responses, calls, service=None):
        self.responses, self.calls = responses, calls
        if service in {"bedrock-agentcore-control", "bedrock-agentcore"}:
            self.meta = SimpleNamespace(service_model=service_model(service))
        self.exceptions = SimpleNamespace(
            ResourceNotFoundException=Missing, NoSuchBucketPolicy=Missing
        )

    def can_paginate(self, operation):
        return operation in self.responses and not operation.startswith("get_")

    def get_paginator(self, operation):
        return FakePaginator(self, operation)

    def __getattr__(self, operation):
        def call(**kwargs):
            self.calls.append((operation, kwargs, "direct"))
            assert operation in self.responses, f"unexpected API: {operation}"
            result = self.responses[operation]
            if isinstance(result, Exception):
                raise result
            value = result(kwargs) if callable(result) else result
            return (
                copy.deepcopy(value)
                if not isinstance(value, dict) or "Body" not in value
                else value
            )

        return call


class FakeSessions:
    def __init__(self, responses):
        self.responses, self.calls, self.profiles = responses, [], []

    def __call__(self, profile_name, region_name):
        self.profiles.append((profile_name, region_name))
        account = profile_name
        owner = self

        class Session:
            def client(self, service, region_name, config):
                assert config.connect_timeout == 5 and config.read_timeout == 20
                assert config.ignore_configured_endpoint_urls is True
                if service == "sts":
                    return FakeClient(
                        {"get_caller_identity": {"Account": account}}, owner.calls
                    )
                assert (account, service, region_name) in owner.responses
                return FakeClient(
                    owner.responses[(account, service, region_name)],
                    owner.calls,
                    service,
                )

            def get_available_regions(self, service, partition_name):
                assert partition_name == "aws"
                return ["us-east-1", "eu-west-1"]

        return Session()


@lru_cache
def service_model(service):
    return botocore.session.get_session().get_service_model(service)


def fixture():
    function_state = {
        "Configuration": {
            "FunctionArn": FUNCTION,
            "FunctionName": "GeneratedProvider",
            "Role": ROLE,
            "Runtime": "python3.13",
            "Handler": "index.handler",
            "CodeSha256": "approved-code",
            "Environment": {"Variables": {"PRIVATE_CONFIGURATION": "do-not-print"}},
        },
        "Code": {"RepositoryType": "S3"},
        "Aliases": [],
        "Versions": [],
        "EventSourceMappings": [],
        "ResourcePolicy": {},
        "QualifiedPolicies": {},
        "FunctionUrls": [],
        "Concurrency": {},
        "CodeSigningConfig": {},
    }
    stack = {
        "StackId": STACK,
        "StackName": "UnrelatedLegacyStack",
        "StackStatus": "CREATE_COMPLETE",
        "RoleARN": ROLE,
    }
    role = {
        "id": "provider-role",
        "arn": ROLE,
        "roleId": ROLE_ID,
        "purposes": ["gateway-admin"],
        "lifecycleControllerIds": [],
        "policyResourceIds": [],
        "consumerResourceIds": ["provider", "legacy"],
        "trustPolicySha256": expected_digest(TRUST),
        "inlinePolicySha256": {"Provision": expected_digest(INLINE)},
        "attachedPolicyArns": [],
    }
    resources = [
        {
            "id": "provider",
            "kind": "lambda",
            "arn": FUNCTION,
            "controllerIds": [],
            "dependsOnIds": [],
            "executionRoleArn": ROLE,
            "codeSha256": "approved-code",
            "configurationSha256": expected_digest(function_state),
        },
        {
            "id": "legacy",
            "kind": "stack",
            "arn": STACK,
            "controllerIds": [],
            "dependsOnIds": [],
            "executionRoleArn": ROLE,
            "documentSha256": expected_digest(TEMPLATE),
            "configurationSha256": expected_digest(
                {"Stack": stack, "Template": TEMPLATE}
            ),
        },
    ]
    manifest = {
        "schemaVersion": 1,
        "organizationId": "o-abcdefghij",
        "managementAccountId": MANAGEMENT,
        "trustedControlAccountIds": [CONTROL],
        "governedAccountIds": [MEMBER],
        "epoch": "owner-approved-1",
        "roles": [role],
        "resources": resources,
    }
    expected = {
        "manifestSha256": expected_digest(manifest),
        "policies": [
            {
                "name": "ProtectedAuthority",
                "bodySha256": expected_digest(POLICY),
                "targetIds": ["ou-abcd-governed"],
            },
            {
                "name": f"AgenticAI-ProtectedAuthority-{MEMBER}-1",
                "bodySha256": expected_digest(POLICY),
                "targetIds": [MEMBER],
            },
        ],
    }
    profiles = {account: account for account in (MEMBER, CONTROL, MANAGEMENT)}
    responses = {
        (MEMBER, "iam", "us-east-1"): {
            "get_role": {
                "Role": {
                    "Arn": ROLE,
                    "RoleId": ROLE_ID,
                    "AssumeRolePolicyDocument": TRUST,
                }
            },
            "list_role_policies": [{"PolicyNames": ["Provision"]}],
            "get_role_policy": {"PolicyDocument": quote(json.dumps(INLINE))},
            "list_attached_role_policies": [{"AttachedPolicies": []}],
            "list_instance_profiles_for_role": [{"InstanceProfiles": []}],
        },
        (MEMBER, "ec2", "us-east-1"): {
            "describe_regions": {
                "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]
            }
        },
        (MEMBER, "cloudformation", "us-east-1"): {
            "describe_stacks": [{"Stacks": [stack]}],
            "get_template": {"TemplateBody": json.dumps(TEMPLATE)},
            "list_stack_sets": [{"Summaries": []}],
            "list_change_sets": [{"Summaries": []}],
        },
        (MEMBER, "lambda", "us-east-1"): {
            "get_function": {
                "Configuration": copy.deepcopy(function_state["Configuration"]),
                "Code": {
                    "RepositoryType": "S3",
                    "Location": "https://temporary.invalid/signed-url",
                },
            },
            "list_aliases": [{"Aliases": []}],
            "list_event_source_mappings": [{"EventSourceMappings": []}],
            "list_versions_by_function": [{"Versions": []}],
            "get_policy": Missing(),
            "list_function_url_configs": [{"FunctionUrlConfigs": []}],
            "get_function_concurrency": {},
            "get_function_code_signing_config": {},
            "list_functions": [
                {
                    "Functions": [
                        {
                            "FunctionArn": FUNCTION,
                            "FunctionName": "GeneratedProvider",
                            "Role": ROLE,
                        }
                    ]
                },
                {
                    "Functions": [
                        {
                            "FunctionArn": FUNCTION + ":17",
                            "FunctionName": "GeneratedProvider",
                            "Role": ROLE,
                        }
                    ]
                },
            ],
        },
        (MANAGEMENT, "organizations", "us-east-1"): {
            "describe_organization": {
                "Organization": {"Id": "o-abcdefghij", "MasterAccountId": MANAGEMENT}
            },
            "list_policies": [
                {
                    "Policies": [
                        {"Name": "ProtectedAuthority", "Id": "p-protected"},
                        {
                            "Name": f"AgenticAI-ProtectedAuthority-{MEMBER}-1",
                            "Id": "p-own",
                        },
                    ]
                }
            ],
            "describe_policy": {"Policy": {"Content": json.dumps(POLICY)}},
            "list_targets_for_policy": lambda args: [
                {
                    "Targets": [
                        {
                            "TargetId": MEMBER
                            if args["PolicyId"] == "p-own"
                            else "ou-abcd-governed"
                        }
                    ]
                }
            ],
            "list_parents": lambda args: (
                [
                    {
                        "Parents": [
                            {"Id": "ou-abcd-governed", "Type": "ORGANIZATIONAL_UNIT"}
                        ]
                    }
                ]
                if args["ChildId"] == MEMBER
                else [{"Parents": [{"Id": "r-abcd", "Type": "ROOT"}]}]
            ),
        },
    }
    for region in ("us-east-1", "eu-west-1"):
        responses[(MEMBER, "codebuild", region)] = {
            "list_projects": [{"projects": []}],
            "list_fleets": [{"fleets": []}],
            "list_sandboxes": [{"ids": []}],
            "list_builds": [{"ids": []}],
            "list_build_batches": [{"ids": []}],
        }
        responses[(MEMBER, "codepipeline", region)] = {
            "list_pipelines": [{"pipelines": []}],
            "list_pipeline_executions": [{"pipelineExecutionSummaries": []}],
        }
        responses[(MEMBER, "stepfunctions", region)] = {
            "list_state_machines": [{"stateMachines": []}],
            "list_map_runs": [{"mapRuns": []}],
        }
        responses[(MEMBER, "bedrock-agentcore-control", region)] = {
            "list_gateways": [{"items": []}],
            "list_agent_runtimes": [{"agentRuntimes": []}],
            "list_browsers": [{"browserSummaries": []}],
            "list_code_interpreters": [{"codeInterpreterSummaries": []}],
            "list_memories": [{"memories": []}],
            "list_online_evaluation_configs": [{"onlineEvaluationConfigs": []}],
            "list_capacity_providers": [{"capacityProviders": []}],
            "list_consent_portals": [{"consentPortals": []}],
            "list_harnesses": [{"harnesses": []}],
            "list_payment_managers": [{"paymentManagers": []}],
            "list_registries": [{"registries": []}],
        }
        responses[(MEMBER, "bedrock-agentcore", region)] = {
            "list_ab_tests": [{"abTests": []}],
        }
    responses[(MEMBER, "cloudformation", "eu-west-1")] = {
        "describe_stacks": [{"Stacks": []}],
        "list_stack_sets": [{"Summaries": []}],
        "list_change_sets": [{"Summaries": []}],
    }
    responses[(MEMBER, "lambda", "eu-west-1")] = {"list_functions": [{"Functions": []}]}
    # Direct describe and paginator results differ only in their response wrapper.
    cfn = responses[(MEMBER, "cloudformation", "us-east-1")]
    cfn["describe_stacks"] = lambda args: (
        {"Stacks": [stack]} if args.get("StackName") else [{"Stacks": [stack]}]
    )
    return manifest, profiles, expected, FakeSessions(responses)


def make_verifier(data):
    manifest, profiles, expected, sessions = data
    return verifier.Verifier(manifest, profiles, expected, session_factory=sessions)


def refresh_binding(data):
    data[2]["manifestSha256"] = expected_digest(data[0])


def test_legitimate_inventory_includes_legacy_stack_all_versions_and_regions():
    data = fixture()
    result = make_verifier(data).run()
    assert result["status"] == "passed"
    assert result["inventoryRegions"][MEMBER] == ["eu-west-1", "us-east-1"]
    assert "resource:legacy" in result["checks"]
    calls = data[3].calls
    assert ("list_functions", {"FunctionVersion": "ALL"}, "paginated") in calls
    assert all(
        operation.startswith(("get_", "list_", "describe_", "batch_get_"))
        for operation, _, _ in calls
    )
    assert "do-not-print" not in json.dumps(result)
    assert "https://temporary.invalid" not in json.dumps(result)


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("RoleId", "AROAQRSTUVWXYZABCDEFG", "recreated"),
        ("Arn", f"arn:aws:iam::{MEMBER}:role/Lookalike", "entity differs"),
        (
            "AssumeRolePolicyDocument",
            {"Statement": [{"Principal": "*"}]},
            "trust policy",
        ),
        (
            "PermissionsBoundary",
            {"PermissionsBoundaryArn": f"arn:aws:iam::{MEMBER}:policy/Attacker"},
            "boundary",
        ),
    ],
)
def test_role_mutation_is_rejected(field, value, reason):
    data = fixture()
    data[3].responses[(MEMBER, "iam", "us-east-1")]["get_role"]["Role"][field] = value
    with pytest.raises(verifier.VerificationFailure, match=reason):
        make_verifier(data).run()


def test_new_inline_policy_cannot_hide_on_later_page():
    data = fixture()
    data[3].responses[(MEMBER, "iam", "us-east-1")]["list_role_policies"].append(
        {"PolicyNames": ["Escalation"]}
    )
    with pytest.raises(verifier.VerificationFailure, match="inline policy"):
        make_verifier(data).run()


def test_new_attached_policy_is_rejected():
    data = fixture()
    data[3].responses[(MEMBER, "iam", "us-east-1")]["list_attached_role_policies"] = [
        {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ]
        },
    ]
    with pytest.raises(verifier.VerificationFailure, match="attached policy"):
        make_verifier(data).run()


def test_instance_profile_is_an_unapproved_execution_consumer():
    data = fixture()
    data[3].responses[(MEMBER, "iam", "us-east-1")][
        "list_instance_profiles_for_role"
    ] = [
        {
            "InstanceProfiles": [
                {"Arn": f"arn:aws:iam::{MEMBER}:instance-profile/Attacker"}
            ]
        },
    ]
    with pytest.raises(verifier.VerificationFailure, match="instance-profile"):
        make_verifier(data).run()


@pytest.mark.parametrize("surface", ["lambda", "cloudformation"])
def test_unlisted_consumer_in_another_region_is_rejected(surface):
    data = fixture()
    if surface == "lambda":
        data[3].responses[(MEMBER, surface, "eu-west-1")]["list_functions"] = [
            {
                "Functions": [
                    {
                        "FunctionArn": f"arn:aws:lambda:eu-west-1:{MEMBER}:function:Attacker",
                        "FunctionName": "Attacker",
                        "Role": ROLE,
                    }
                ]
            },
        ]
    else:
        data[3].responses[(MEMBER, surface, "eu-west-1")]["describe_stacks"] = [
            {
                "Stacks": [
                    {
                        "StackId": f"arn:aws:cloudformation:eu-west-1:{MEMBER}:stack/Payments/unknown",
                        "RoleARN": ROLE,
                        "StackStatus": "UPDATE_COMPLETE",
                    }
                ]
            },
        ]
    with pytest.raises(
        verifier.VerificationFailure, match="execution consumers|quiet cutover"
    ):
        make_verifier(data).run()


def test_removed_existing_stack_is_rejected_even_without_name_prefix():
    data = fixture()
    data[0]["resources"].pop()
    data[0]["roles"][0]["consumerResourceIds"] = ["provider"]
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="execution consumers"):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "field,value",
    [
        ("Role", f"arn:aws:iam::{MEMBER}:role/AnotherRole"),
        ("CodeSha256", "malicious-code"),
        ("Environment", {"Variables": {"PRIVATE_CONFIGURATION": "overridden"}}),
    ],
)
def test_privileged_lambda_changes_are_rejected(field, value):
    data = fixture()
    data[3].responses[(MEMBER, "lambda", "us-east-1")]["get_function"]["Configuration"][
        field
    ] = value
    with pytest.raises(verifier.VerificationFailure, match="differs"):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "operation,value",
    [
        (
            "list_aliases",
            [{"Aliases": [{"Name": "approved", "FunctionVersion": "99"}]}],
        ),
        (
            "list_event_source_mappings",
            [{"EventSourceMappings": [{"UUID": "attacker", "FunctionArn": FUNCTION}]}],
        ),
        (
            "list_function_url_configs",
            [{"FunctionUrlConfigs": [{"AuthType": "NONE", "FunctionArn": FUNCTION}]}],
        ),
        (
            "get_policy",
            {
                "Policy": '{"Statement":[{"Principal":"*","Action":"lambda:InvokeFunction"}]}'
            },
        ),
        ("get_function_concurrency", {"ReservedConcurrentExecutions": 0}),
        ("get_function_code_signing_config", {"CodeSigningConfigArn": "changed"}),
    ],
)
def test_unchanged_provider_execution_routes_cannot_hide(operation, value):
    data = fixture()
    data[3].responses[(MEMBER, "lambda", "us-east-1")][operation] = value
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).run()


def test_template_replacement_is_rejected_with_same_stored_role():
    data = fixture()
    data[3].responses[(MEMBER, "cloudformation", "us-east-1")]["get_template"] = {
        "TemplateBody": '{"Resources":{"Attacker":{"Type":"AWS::Lambda::Function"}}}',
    }
    with pytest.raises(verifier.VerificationFailure, match="configuration differs"):
        make_verifier(data).run()


@pytest.mark.parametrize("kind", ["content", "attachment", "organization", "coverage"])
def test_installed_guards_require_content_targets_and_effective_coverage(kind):
    data = fixture()
    org = data[3].responses[(MANAGEMENT, "organizations", "us-east-1")]
    if kind == "content":
        org["describe_policy"] = {"Policy": {"Content": '{"Statement":[]}'}}
    elif kind == "attachment":
        org["list_targets_for_policy"] = [{"Targets": [{"TargetId": "ou-abcd-other"}]}]
    elif kind == "organization":
        org["describe_organization"]["Organization"]["Id"] = "o-wrongorgxx"
    else:
        org["list_parents"] = lambda args: [
            {"Parents": [{"Id": "r-other", "Type": "ROOT"}]}
        ]
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).run()


def test_profile_account_mismatch_fails_before_any_inventory():
    data = fixture()
    data[1][MEMBER] = CONTROL
    with pytest.raises(verifier.VerificationFailure, match="wrong account"):
        make_verifier(data).run()
    assert all(operation == "get_caller_identity" for operation, _, _ in data[3].calls)


def test_manifest_binding_rejects_stale_policy_expectations_without_aws():
    data = fixture()
    data[0]["epoch"] = "new-epoch"
    with pytest.raises(verifier.VerificationFailure, match="exact canonical manifest"):
        make_verifier(data)
    assert data[3].calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-profile",
        "wildcard",
        "missing-digest",
        "duplicate-id",
        "unknown-reference",
    ],
)
def test_incomplete_input_is_rejected_without_aws(mutation):
    data = fixture()
    if mutation == "missing-profile":
        del data[1][MEMBER]
    elif mutation == "wildcard":
        data[0]["roles"][0]["arn"] = f"arn:aws:iam::{MEMBER}:role/Protected*"
    elif mutation == "missing-digest":
        del data[0]["resources"][0]["configurationSha256"]
    elif mutation == "duplicate-id":
        data[0]["resources"][0]["id"] = "provider-role"
    else:
        data[0]["roles"][0]["consumerResourceIds"].append("unknown")
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data)
    assert data[3].calls == []


def test_access_denied_is_never_an_empty_inventory():
    data = fixture()
    data[3].responses[(MEMBER, "lambda", "eu-west-1")]["list_functions"] = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive remote text"}},
        "ListFunctions",
    )
    with pytest.raises(ClientError):
        make_verifier(data).run()


def test_missing_sdk_pagination_is_not_partial_success():
    data = fixture()
    del data[3].responses[(MEMBER, "lambda", "eu-west-1")]["list_functions"]
    with pytest.raises(verifier.VerificationFailure, match="complete SDK pagination"):
        make_verifier(data).run()


def test_cli_missing_input_has_nonzero_exit_and_no_aws(tmp_path, capsys):
    result = verifier.main(
        [
            "--manifest",
            str(tmp_path / "missing.json"),
            "--profile-map",
            str(tmp_path / "profiles.json"),
            "--expected-policies",
            str(tmp_path / "policies.json"),
        ]
    )
    assert result == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "failed" and output["readOnly"] is True


def test_duplicate_json_key_is_rejected(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"epoch":"first","epoch":"replacement"}')
    with pytest.raises(verifier.VerificationFailure, match="duplicate JSON"):
        verifier.read_json(path)


@pytest.mark.parametrize(
    "service",
    ["codebuild", "codepipeline", "stepfunctions", "bedrock-agentcore-control"],
)
def test_other_unlisted_service_execution_consumers_fail(service):
    data = fixture()
    values = data[3].responses[(MEMBER, service, "eu-west-1")]
    if service == "codebuild":
        values["list_projects"] = [{"projects": ["Attacker"]}]
        values["batch_get_projects"] = {
            "projects": [
                {
                    "arn": f"arn:aws:codebuild:eu-west-1:{MEMBER}:project/Attacker",
                    "serviceRole": ROLE,
                }
            ]
        }
    elif service == "codepipeline":
        values["list_pipelines"] = [{"pipelines": [{"name": "Attacker"}]}]
        values["get_pipeline"] = {"pipeline": {"name": "Attacker", "roleArn": ROLE}}
    elif service == "stepfunctions":
        machine_arn = f"arn:aws:states:eu-west-1:{MEMBER}:stateMachine:Attacker"
        values["list_state_machines"] = [
            {"stateMachines": [{"stateMachineArn": machine_arn}]}
        ]
        values["describe_state_machine"] = {"roleArn": ROLE, "type": "STANDARD"}
        values["list_state_machine_versions"] = [{"stateMachineVersions": []}]
        values["list_state_machine_aliases"] = [{"stateMachineAliases": []}]
        values["list_executions"] = [{"executions": []}]
    else:
        values["list_gateways"] = [{"items": [{"gatewayId": "attacker"}]}]
        values["get_gateway"] = {
            "gatewayArn": f"arn:aws:bedrock-agentcore:eu-west-1:{MEMBER}:gateway/attacker",
            "roleArn": ROLE,
        }
    with pytest.raises(verifier.VerificationFailure, match="execution consumers"):
        make_verifier(data).run()


def policy_fixture(data):
    policy_arn = f"arn:aws:iam::{MEMBER}:policy/ProtectedPolicy"
    identity = {
        "Arn": policy_arn,
        "PolicyId": "ANPAABCDEFGHIJKLMNOPQ",
        "DefaultVersionId": "v3",
    }
    data[0]["roles"][0]["attachedPolicyArns"] = [policy_arn]
    data[0]["roles"][0]["policyResourceIds"] = ["managed-policy"]
    data[0]["resources"].append(
        {
            "id": "managed-policy",
            "kind": "policy",
            "arn": policy_arn,
            "controllerIds": [],
            "dependsOnIds": [],
            "policyId": identity["PolicyId"],
            "defaultVersionId": "v3",
            "documentSha256": expected_digest(INLINE),
        }
    )
    refresh_binding(data)
    iam = data[3].responses[(MEMBER, "iam", "us-east-1")]
    iam["list_attached_role_policies"] = [
        {"AttachedPolicies": [{"PolicyArn": policy_arn}]}
    ]
    iam["get_policy"] = {"Policy": identity}
    iam["get_policy_version"] = {"PolicyVersion": {"Document": INLINE}}
    return identity


def test_legitimate_customer_managed_policy_is_entity_and_document_bound():
    data = fixture()
    policy_fixture(data)
    assert make_verifier(data).run()["status"] == "passed"
    assert (
        "get_policy_version",
        {
            "PolicyArn": f"arn:aws:iam::{MEMBER}:policy/ProtectedPolicy",
            "VersionId": "v3",
        },
        "direct",
    ) in data[3].calls


@pytest.mark.parametrize("mutation", ["unprotected", "entity", "version", "document"])
def test_customer_managed_policy_changes_cannot_hide(mutation):
    data = fixture()
    identity = policy_fixture(data)
    if mutation == "unprotected":
        data[0]["roles"][0]["policyResourceIds"] = []
        refresh_binding(data)
    elif mutation == "entity":
        identity["PolicyId"] = "ANPAQRSTUVWXYZABCDEFG"
    elif mutation == "version":
        identity["DefaultVersionId"] = "v4"
    else:
        data[3].responses[(MEMBER, "iam", "us-east-1")]["get_policy_version"][
            "PolicyVersion"
        ]["Document"] = {
            "Statement": [{"Action": "*", "Resource": "*", "Effect": "Allow"}],
        }
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "kind,service,resource_name,operation,response,role_field",
    [
        (
            "pipeline",
            "codepipeline",
            "ApprovedPipeline",
            "get_pipeline",
            {
                "pipeline": {
                    "name": "ApprovedPipeline",
                    "roleArn": ROLE,
                    "stages": [
                        {
                            "name": "Source",
                            "actions": [
                                {
                                    "actionTypeId": {
                                        "owner": "AWS",
                                        "category": "Source",
                                        "provider": "ECR",
                                    },
                                    "configuration": {
                                        "RepositoryName": "approved-repo",
                                        "ImageTag": "approved",
                                    },
                                }
                            ],
                        }
                    ],
                }
            },
            "roleArn",
        ),
        (
            "build",
            "codebuild",
            "project/ApprovedBuild",
            "batch_get_projects",
            {
                "projects": [
                    {
                        "name": "ApprovedBuild",
                        "arn": f"arn:aws:codebuild:us-east-1:{MEMBER}:project/ApprovedBuild",
                        "serviceRole": ROLE,
                        "source": {
                            "type": "NO_SOURCE",
                            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - true\n",
                        },
                        "artifacts": {"type": "NO_ARTIFACTS"},
                        "environment": {
                            "privilegedMode": False,
                            "image": "aws/codebuild/standard:7.0",
                        },
                    }
                ]
            },
            "serviceRole",
        ),
        (
            "state-machine",
            "stepfunctions",
            "stateMachine:ApprovedMachine",
            "describe_state_machine",
            {
                "roleArn": ROLE,
                "definition": '{"StartAt":"Approved","States":{"Approved":{"Type":"Succeed"}}}',
            },
            "roleArn",
        ),
    ],
)
def test_ci_configuration_snapshots_cover_source_overrides_and_service_roles(
    kind, service, resource_name, operation, response, role_field
):
    data = fixture()
    arn_service = "states" if service == "stepfunctions" else service
    resource = {
        "id": "approved-ci",
        "kind": kind,
        "arn": f"arn:aws:{arn_service}:us-east-1:{MEMBER}:{resource_name}",
        "executionRoleArn": ROLE,
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
    }
    data[0]["resources"].append(resource)
    if kind == "pipeline":
        data[0]["resources"].append(
            {
                "id": "pipeline-repository",
                "kind": "ecr",
                "arn": f"arn:aws:ecr:us-east-1:{MEMBER}:repository/approved-repo",
                "controllerIds": [],
                "dependsOnIds": [],
                "configurationSha256": "0" * 64,
            }
        )
        resource["dependsOnIds"] = ["pipeline-repository"]
        add_pipeline_storage(data, resource, response["pipeline"])
    refresh_binding(data)
    values = data[3].responses[(MEMBER, service, "us-east-1")]
    values[operation] = copy.deepcopy(response)
    if kind == "state-machine":
        values["list_tags_for_resource"] = {"tags": []}
        values["list_state_machine_versions"] = [{"stateMachineVersions": []}]
        values["list_state_machine_aliases"] = [{"stateMachineAliases": []}]
    if kind == "build":
        values["get_resource_policy"] = {}
    instance = make_verifier(data)
    state, _ = instance.resource_snapshot(resource)
    assert state[role_field] == ROLE
    if kind == "pipeline":
        assert (
            state["stages"][0]["actions"][0]["configuration"]["ImageTag"] == "approved"
        )
    elif kind == "build":
        assert state["environment"]["privilegedMode"] is False
    else:
        assert "Approved" in state["definition"]
    values[operation] = copy.deepcopy(response)
    target = (
        values[operation]["pipeline"]
        if kind == "pipeline"
        else (
            values[operation]["projects"][0] if kind == "build" else values[operation]
        )
    )
    target[role_field] = f"arn:aws:iam::{MEMBER}:role/Attacker"
    with pytest.raises(verifier.VerificationFailure, match="execution role differs"):
        instance.resource_snapshot(resource)


def test_s3_asset_reads_pin_the_head_version_and_close_the_stream():
    data = fixture()
    body = io.BytesIO(b"approved deployment code")
    resource = {
        "id": "asset",
        "kind": "s3-object",
        "arn": "arn:aws:s3:::protected-assets/code.zip",
        "accountId": MEMBER,
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
        "documentSha256": hashlib.sha256(b"approved deployment code").hexdigest(),
    }
    data[0]["resources"].append(resource)
    refresh_binding(data)
    data[3].responses[(MEMBER, "s3", "us-east-1")] = {
        "head_object": {
            "ContentLength": len(body.getvalue()),
            "VersionId": "immutable-v1",
            "ETag": '"etag-1"',
        },
        "get_object_acl": {"Owner": {"ID": "canonical-owner"}, "Grants": []},
        "get_object": {"Body": body},
    }
    state, bytes_hash = make_verifier(data).resource_snapshot(resource)
    assert state["VersionId"] == "immutable-v1"
    assert bytes_hash["ObjectBytesSha256"] == resource["documentSha256"]
    assert body.closed
    assert (
        "get_object",
        {
            "Bucket": "protected-assets",
            "Key": "code.zip",
            "ExpectedBucketOwner": MEMBER,
            "IfMatch": '"etag-1"',
            "VersionId": "immutable-v1",
        },
        "direct",
    ) in data[3].calls


def test_s3_asset_truncation_fails_and_closes_the_stream():
    data = fixture()
    body = io.BytesIO(b"short")
    resource = {
        "id": "asset",
        "kind": "s3-object",
        "arn": "arn:aws:s3:::protected-assets/code.zip",
        "accountId": MEMBER,
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
    }
    data[0]["resources"].append(resource)
    refresh_binding(data)
    data[3].responses[(MEMBER, "s3", "us-east-1")] = {
        "head_object": {"ContentLength": 100, "ETag": '"etag-1"'},
        "get_object_acl": {"Owner": {"ID": "canonical-owner"}, "Grants": []},
        "get_object": {"Body": body},
    }
    with pytest.raises(verifier.VerificationFailure, match="object changed"):
        make_verifier(data).resource_snapshot(resource)
    assert body.closed


def test_service_managed_stackset_cannot_be_certified_as_scp_protected():
    data = fixture()
    resource = {
        "id": "stackset",
        "kind": "stack-set",
        "arn": f"arn:aws:cloudformation:us-east-1:{MEMBER}:stackset/unsafe:id",
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
    }
    data[0]["resources"].append(resource)
    refresh_binding(data)
    data[3].responses[(MEMBER, "cloudformation", "us-east-1")]["describe_stack_set"] = {
        "StackSet": {"PermissionModel": "SERVICE_MANAGED"},
    }
    with pytest.raises(verifier.VerificationFailure, match="service-managed"):
        make_verifier(data).resource_snapshot(resource)


def test_installed_sdk_has_the_organization_identity_field_the_verifier_uses():
    import botocore.session

    model = botocore.session.get_session().get_service_model("organizations")
    assert "MasterAccountId" in model.shape_for("Organization").members
    assert "ManagementAccountId" not in model.shape_for("Organization").members


def test_approved_hash_does_not_make_an_external_trust_delegation_safe():
    data = fixture()
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            },
        ],
    }
    data[0]["roles"][0]["trustPolicySha256"] = expected_digest(trust)
    data[3].responses[(MEMBER, "iam", "us-east-1")]["get_role"]["Role"][
        "AssumeRolePolicyDocument"
    ] = trust
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="unapproved trust"):
        make_verifier(data).run()


def test_qualified_provider_policy_cannot_allow_an_external_invoker():
    data = fixture()
    sdk = data[3].responses[(MEMBER, "lambda", "us-east-1")]
    sdk["list_aliases"] = [{"Aliases": [{"Name": "approved", "FunctionVersion": "1"}]}]
    policy = {
        "Policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "lambda:InvokeFunction",
                    },
                ]
            }
        )
    }
    sdk["get_policy"] = lambda args: (
        policy if args.get("Qualifier") == "approved" else {}
    )
    with pytest.raises(
        verifier.VerificationFailure, match="external positive resource grant"
    ):
        make_verifier(data).run()


def test_service_invoker_requires_exact_protected_source_not_only_an_account():
    data = fixture()
    instance = make_verifier(data)
    resource = data[0]["resources"][0]
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": MEMBER},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:cloudformation:*:{MEMBER}:stack/*"
                    },
                },
            }
        ]
    }
    with pytest.raises(verifier.VerificationFailure, match="exact protected source"):
        instance.verify_resource_policy(resource, policy)
    resource["dependsOnIds"] = ["legacy"]
    policy["Statement"][0]["Condition"] = {
        "StringEquals": {"aws:SourceAccount": MEMBER},
        "ArnEquals": {"aws:SourceArn": STACK},
    }
    instance.verify_resource_policy(resource, policy)


@pytest.mark.parametrize(
    "principal",
    [
        "*",
        {"AWS": "arn:aws:iam::999999999999:root"},
        {"AWS": "arn:aws:iam::222222222222:role/Unlisted"},
    ],
)
def test_external_resource_grants_cannot_be_hidden_behind_snapshot_hashes(principal):
    data = fixture()
    instance = make_verifier(data)
    policy = {
        "Statement": [
            {"Effect": "Allow", "Principal": principal, "Action": "*", "Resource": "*"}
        ]
    }
    with pytest.raises(verifier.VerificationFailure):
        instance.verify_resource_policy(data[0]["resources"][0], policy)


def test_acl_external_writer_is_rejected_but_private_owner_control_is_allowed():
    resource = {"id": "asset"}
    verifier.Verifier.verify_acl(
        resource,
        {
            "Owner": {"ID": "owner"},
            "Grants": [
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "owner"},
                    "Permission": "FULL_CONTROL",
                }
            ],
        },
    )
    with pytest.raises(verifier.VerificationFailure, match="external ACL write"):
        verifier.Verifier.verify_acl(
            resource,
            {
                "Owner": {"ID": "owner"},
                "Grants": [
                    {
                        "Grantee": {"Type": "Group", "URI": "all-users"},
                        "Permission": "WRITE",
                    }
                ],
            },
        )


def region_fixture(data, statement=None):
    statement = statement or {
        "Sid": "DenyActionsOutsideApprovedRegions",
        "Effect": "Deny",
        "NotAction": ["iam:*", "sts:*", "organizations:*"],
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}},
    }
    policy = {"Version": "2012-10-17", "Statement": [statement]}
    data[2]["policies"].append(
        {
            "name": "VerifiedRegionBoundary",
            "bodySha256": expected_digest(policy),
            "targetIds": ["ou-abcd-governed"],
        }
    )
    org = data[3].responses[(MANAGEMENT, "organizations", "us-east-1")]
    org["list_policies"].append(
        {
            "Policies": [{"Name": "VerifiedRegionBoundary", "Id": "p-region"}],
        }
    )
    org["describe_policy"] = lambda args: {
        "Policy": {
            "Content": json.dumps(policy if args["PolicyId"] == "p-region" else POLICY)
        },
    }
    return policy


@pytest.mark.parametrize(
    "service,operation", [("lambda", "list_functions"), ("codebuild", "list_projects")]
)
def test_verified_region_deny_never_hides_historical_consumers_or_denied_reads(
    service, operation
):
    data = fixture()
    region_fixture(data)
    denied = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "regional deny"}}, "ListFunctions"
    )
    data[3].responses[(MEMBER, service, "eu-west-1")][operation] = denied
    with pytest.raises(ClientError):
        make_verifier(data).run()
    assert any(read == operation for read, _, _ in data[3].calls)


def test_verified_region_deny_still_inventories_every_enabled_region():
    data = fixture()
    policy = region_fixture(data)
    result = make_verifier(data).run()
    assert result["inventoryRegions"][MEMBER] == ["eu-west-1", "us-east-1"]
    anchor = result["regionalDiscoveryAnchors"][MEMBER]
    assert anchor["region"] == "us-east-1"
    assert anchor["policyBindings"][0]["bodySha256"] == expected_digest(policy)
    assert "regionsCoveredByVerifiedDeny" not in result
    assert sum(operation == "list_functions" for operation, _, _ in data[3].calls) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "principal-condition",
        "regional-exception",
        "partial-action",
        "resource-scope",
        "condition-operator",
    ],
)
def test_partial_region_policy_never_suppresses_inventory_errors(mutation):
    data = fixture()
    statement = {
        "Effect": "Deny",
        "NotAction": ["iam:*", "sts:*"],
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}},
    }
    if mutation == "principal-condition":
        statement["Condition"]["ArnNotEquals"] = {"aws:PrincipalArn": ROLE}
    elif mutation == "regional-exception":
        statement["NotAction"].append("lambda:*")
    elif mutation == "partial-action":
        del statement["NotAction"]
        statement["Action"] = ["lambda:CreateFunction"]
    elif mutation == "resource-scope":
        statement["Resource"] = FUNCTION
    else:
        statement["Condition"] = {
            "StringNotEqualsIfExists": {"aws:RequestedRegion": ["us-east-1"]}
        }
    region_fixture(data, statement)
    data[3].responses[(MEMBER, "lambda", "eu-west-1")]["list_functions"] = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "do not hide"}},
        "ListFunctions",
    )
    with pytest.raises(ClientError):
        make_verifier(data).run()


def test_changed_region_policy_hash_cannot_authorize_skipping_reads():
    data = fixture()
    policy = region_fixture(data)
    policy["Statement"][0]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] = [
        "eu-west-1"
    ]
    with pytest.raises(verifier.VerificationFailure, match="policy content differs"):
        make_verifier(data).run()
    assert all(
        operation not in {"list_functions", "describe_regions"}
        for operation, _, _ in data[3].calls
    )


def test_enabled_region_discovery_uses_verified_allowed_region():
    data = fixture()
    data[0]["resources"] = []
    data[0]["roles"][0]["consumerResourceIds"] = []
    data[0]["roles"][0]["purposes"] = ["controller"]
    refresh_binding(data)
    region_fixture(
        data,
        {
            "Effect": "Deny",
            "NotAction": ["iam:*", "sts:*"],
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}},
        },
    )
    data[3].responses[(MEMBER, "ec2", "eu-west-1")] = data[3].responses.pop(
        (MEMBER, "ec2", "us-east-1")
    )
    data[3].responses[(MEMBER, "cloudformation", "us-east-1")]["describe_stacks"] = [
        {"Stacks": []}
    ]
    data[3].responses[(MEMBER, "lambda", "us-east-1")]["list_functions"] = [
        {"Functions": []}
    ]
    instance = make_verifier(data)
    instance.verify_installed_policies()
    instance.verify_consumers()
    assert instance.regions[MEMBER] == ["eu-west-1", "us-east-1"]
    assert instance.discovery_anchors[MEMBER]["region"] == "eu-west-1"


def test_narrow_region_proof_does_not_apply_to_an_ungoverned_control_account():
    data = fixture()
    region_fixture(data)
    instance = make_verifier(data)
    instance.verify_installed_policies()
    assert MEMBER in instance.region_denies
    assert CONTROL not in instance.region_denies


def test_management_only_authority_root_needs_no_trusted_control_account():
    data = fixture()
    data[0]["trustedControlAccountIds"] = []
    del data[1][CONTROL]
    refresh_binding(data)
    assert make_verifier(data).run()["status"] == "passed"


def two_account_policy_fixture(data):
    second = "444444444444"
    data[0]["governedAccountIds"].append(second)
    data[1][second] = second
    data[2]["policies"].append(
        {
            "name": f"AgenticAI-ProtectedAuthority-{second}-1",
            "bodySha256": expected_digest(POLICY),
            "targetIds": [second],
        }
    )
    refresh_binding(data)
    org = data[3].responses[(MANAGEMENT, "organizations", "us-east-1")]
    identities = {
        record["name"]: f"p-fixture-{index}"
        for index, record in enumerate(data[2]["policies"])
    }
    records = {identities[record["name"]]: record for record in data[2]["policies"]}
    org["list_policies"] = [
        {
            "Policies": [
                {"Name": name, "Id": identity} for name, identity in identities.items()
            ]
        }
    ]
    org["describe_policy"] = lambda args: {"Policy": {"Content": json.dumps(POLICY)}}
    org["list_targets_for_policy"] = lambda args: [
        {
            "Targets": [
                {"TargetId": target}
                for target in records[args["PolicyId"]]["targetIds"]
            ]
        }
    ]
    org["list_parents"] = lambda args: [
        {
            "Parents": [
                {"Id": "ou-abcd-governed", "Type": "ORGANIZATIONAL_UNIT"}
                if args["ChildId"] in {MEMBER, second}
                else {"Id": "r-abcd", "Type": "ROOT"}
            ]
        }
    ]
    return second, identities, records, org


def test_separate_member_authority_guards_do_not_require_other_member_ancestry():
    data = fixture()
    two_account_policy_fixture(data)
    instance = make_verifier(data)
    instance.verify_installed_policies()
    assert "installed-scp-content-and-effective-attachments" in instance.checks


@pytest.mark.parametrize(
    "mutation", ["missing-own", "other-target", "business-coverage"]
)
def test_each_governed_cell_requires_own_guards_and_shared_business_coverage(mutation):
    data = fixture()
    second, _, _, org = two_account_policy_fixture(data)
    if mutation == "missing-own":
        data[2]["policies"] = [
            value
            for value in data[2]["policies"]
            if value["name"] != f"AgenticAI-ProtectedAuthority-{second}-1"
        ]
    elif mutation == "other-target":
        data[2]["policies"][-1]["targetIds"] = [MEMBER]
    else:
        org["list_parents"] = lambda args: [
            {
                "Parents": [
                    {"Id": "ou-abcd-governed", "Type": "ORGANIZATIONAL_UNIT"}
                    if args["ChildId"] == MEMBER
                    else {"Id": "r-abcd", "Type": "ROOT"}
                ]
            }
        ]
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).verify_installed_policies()


def test_regional_proof_is_bound_to_the_member_receiving_that_authority_policy():
    data = fixture()
    second, identities, _, org = two_account_policy_fixture(data)
    body = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "NotAction": ["iam:*", "sts:*"],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}
                },
            }
        ],
    }
    own_name = f"AgenticAI-ProtectedAuthority-{MEMBER}-1"
    next(record for record in data[2]["policies"] if record["name"] == own_name)[
        "bodySha256"
    ] = expected_digest(body)
    org["describe_policy"] = lambda args: {
        "Policy": {
            "Content": json.dumps(
                body if args["PolicyId"] == identities[own_name] else POLICY
            )
        }
    }
    instance = make_verifier(data)
    instance.verify_installed_policies()
    assert instance.regional_anchor(MEMBER) == "eu-west-1"
    assert second not in instance.region_denies


def state_machine_fixture(data):
    arn = f"arn:aws:states:us-east-1:{MEMBER}:stateMachine:OutsideProjectNaming"
    version_arn, alias_arn = arn + ":17", arn + ":approved"
    base = {
        "stateMachineArn": arn,
        "roleArn": ROLE,
        "type": "STANDARD",
        "definition": '{"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}',
    }
    version = {**base, "stateMachineArn": version_arn}
    alias = {
        "stateMachineAliasArn": alias_arn,
        "routingConfiguration": [
            {"stateMachineVersionArn": version_arn, "weight": 100}
        ],
    }
    resource = {
        "id": "historical-machine",
        "kind": "state-machine",
        "arn": arn,
        "executionRoleArn": ROLE,
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": expected_digest(
            {**base, "Tags": [], "Versions": [version], "Aliases": [alias]}
        ),
    }
    data[0]["resources"].append(resource)
    data[0]["roles"][0]["consumerResourceIds"].append(resource["id"])
    refresh_binding(data)
    sdk = data[3].responses[(MEMBER, "stepfunctions", "us-east-1")]
    sdk.update(
        {
            "list_state_machines": [{"stateMachines": [{"stateMachineArn": arn}]}],
            "describe_state_machine": lambda args: (
                version if args["stateMachineArn"] == version_arn else base
            ),
            "list_tags_for_resource": {"tags": []},
            "list_state_machine_versions": [
                {"stateMachineVersions": [{"stateMachineVersionArn": version_arn}]}
            ],
            "list_state_machine_aliases": [
                {"stateMachineAliases": [{"stateMachineAliasArn": alias_arn}]}
            ],
            "describe_state_machine_alias": alias,
            "list_executions": [{"executions": []}],
        }
    )
    return resource, base, version, alias, sdk


def test_state_machine_published_versions_and_aliases_are_bound_to_protected_base():
    data = fixture()
    resource, _, _, _, _ = state_machine_fixture(data)
    result = make_verifier(data).run()
    assert result["status"] == "passed"
    assert f"resource:{resource['id']}" in result["checks"]
    assert any(
        operation == "describe_state_machine_alias" for operation, _, _ in data[3].calls
    )


def test_historical_protected_version_cannot_hide_after_base_role_is_replaced():
    data = fixture()
    resource, base, _, _, _ = state_machine_fixture(data)
    data[0]["resources"].remove(resource)
    data[0]["roles"][0]["consumerResourceIds"].remove(resource["id"])
    base["roleArn"] = f"arn:aws:iam::{MEMBER}:role/Unprotected"
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="execution consumers"):
        make_verifier(data).run()


def test_mixed_historical_state_machine_role_is_unsupported_even_with_approved_hash():
    data = fixture()
    resource, base, version, alias, _ = state_machine_fixture(data)
    version["roleArn"] = f"arn:aws:iam::{MEMBER}:role/Unprotected"
    resource["configurationSha256"] = expected_digest(
        {**base, "Tags": [], "Versions": [version], "Aliases": [alias]}
    )
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="historical state-machine"):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "operation", ["list_state_machine_versions", "list_state_machine_aliases"]
)
def test_state_machine_version_or_alias_access_denial_is_not_empty_inventory(operation):
    data = fixture()
    _, _, _, _, sdk = state_machine_fixture(data)
    sdk[operation] = ClientError({"Error": {"Code": "AccessDenied"}}, operation)
    with pytest.raises(ClientError):
        make_verifier(data).run()


def ecr_fixture(data, principal):
    resource = {
        "id": "protected-repository",
        "kind": "ecr",
        "arn": f"arn:aws:ecr:us-east-1:{MEMBER}:repository/deployment",
        "controllerIds": ["provider-role"],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
    }
    data[0]["resources"].append(resource)
    refresh_binding(data)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": principal,
                "Action": ["ecr:PutImage", "ecr:UploadLayerPart"],
                "Resource": resource["arn"],
            }
        ],
    }
    data[3].responses[(MEMBER, "ecr", "us-east-1")] = {
        "describe_repositories": {"repositories": [{"repositoryArn": resource["arn"]}]},
        "get_repository_policy": {"policyText": json.dumps(policy)},
        "describe_images": [{"imageDetails": []}],
    }
    resource["configurationSha256"] = expected_digest(
        {
            "repositories": [{"repositoryArn": resource["arn"]}],
            "Policy": {"policyText": json.dumps(policy)},
            "Images": [],
        }
    )
    refresh_binding(data)
    return resource


@pytest.mark.parametrize(
    "principal",
    [
        "*",
        {"AWS": "arn:aws:iam::999999999999:role/ForeignWriter"},
        {"Service": "codebuild.amazonaws.com"},
    ],
)
def test_approved_ecr_configuration_hash_cannot_admit_external_push_principal(
    principal,
):
    data = fixture()
    ecr_fixture(data, principal)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).verify_resources()


def test_exact_enrolled_ecr_controller_can_push_without_external_authority():
    data = fixture()
    ecr_fixture(data, {"AWS": ROLE})
    instance = make_verifier(data)
    instance.verify_resources()
    assert "resource:protected-repository" in instance.checks


@pytest.mark.parametrize("kind", ["s3-bucket", "s3-object"])
def test_eu_only_policy_selects_allowed_region_for_arnless_s3_reads(kind):
    data = fixture()
    region_fixture(
        data,
        {
            "Effect": "Deny",
            "NotAction": ["iam:*", "sts:*"],
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}},
        },
    )
    resource = {
        "id": "eu-asset",
        "kind": kind,
        "arn": "arn:aws:s3:::eu-protected-assets"
        + ("/code.zip" if kind == "s3-object" else ""),
        "accountId": MEMBER,
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
    }
    data[0]["resources"].append(resource)
    refresh_binding(data)
    responses = {
        "get_bucket_policy": {"Policy": '{"Statement":[]}'},
        "get_bucket_acl": {"Owner": {"ID": "owner"}, "Grants": []},
        "get_bucket_versioning": {},
        "get_bucket_encryption": {},
        "get_public_access_block": {},
        "get_bucket_ownership_controls": {
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
        },
        "get_bucket_notification_configuration": {},
        "head_object": {
            "ContentLength": 3,
            "ETag": '"eu-etag"',
            "VersionId": "eu-version",
        },
        "get_object_acl": {"Owner": {"ID": "owner"}, "Grants": []},
        "get_object": {"Body": io.BytesIO(b"zip")},
    }
    data[3].responses[(MEMBER, "s3", "eu-west-1")] = responses
    instance = make_verifier(data)
    instance.verify_installed_policies()
    state, _ = instance.resource_snapshot(resource)
    assert state
    assert (MEMBER, "s3", "eu-west-1") in instance.clients
    assert (MEMBER, "s3", "us-east-1") not in instance.clients
    if kind == "s3-object":
        assert (
            "get_object_acl",
            {
                "Bucket": "eu-protected-assets",
                "ExpectedBucketOwner": MEMBER,
                "Key": "code.zip",
                "VersionId": "eu-version",
            },
            "direct",
        ) in data[3].calls


def add_record(data, identity, kind, arn, **fields):
    value = {
        "id": identity,
        "kind": kind,
        "arn": arn,
        "controllerIds": [],
        "dependsOnIds": [],
        "configurationSha256": "0" * 64,
        **fields,
    }
    data[0]["resources"].append(value)
    return value


def add_pipeline_storage(data, resource, pipeline):
    bucket = add_record(
        data,
        "ci-artifacts-bucket",
        "s3-bucket",
        "arn:aws:s3:::ci-protected-artifacts",
        accountId=MEMBER,
    )
    key = add_record(
        data,
        "ci-artifacts-key",
        "kms",
        f"arn:aws:kms:us-east-1:{MEMBER}:key/11111111-2222-3333-4444-555555555555",
    )
    resource["dependsOnIds"].extend([bucket["id"], key["id"]])
    pipeline["artifactStore"] = {
        "type": "S3",
        "location": "ci-protected-artifacts",
        "encryptionKey": {"type": "KMS", "id": key["arn"]},
    }
    return bucket, key


def add_s3_source(data, resource):
    bucket = add_record(
        data,
        "ci-source-bucket",
        "s3-bucket",
        "arn:aws:s3:::ci-protected-source",
        accountId=MEMBER,
    )
    obj = add_record(
        data,
        "ci-source-object",
        "s3-object",
        "arn:aws:s3:::ci-protected-source/source.zip",
        accountId=MEMBER,
        dependsOnIds=[bucket["id"]],
        documentSha256=hashlib.sha256(b"approved source").hexdigest(),
    )
    # The bucket is deliberately reached through the object, as the TS graph allows.
    resource["dependsOnIds"].append(obj["id"])
    return bucket, obj


def codebuild_fixture(data, source_type="NO_SOURCE"):
    resource = add_record(
        data,
        "protected-build",
        "build",
        f"arn:aws:codebuild:us-east-1:{MEMBER}:project/OutsideNamedBuild",
        executionRoleArn=ROLE,
        controllerIds=["provider-role"],
    )
    project = {
        "name": "OutsideNamedBuild",
        "arn": resource["arn"],
        "serviceRole": ROLE,
        "source": {
            "type": source_type,
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - true\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
        },
        "cache": {"type": "NO_CACHE"},
    }
    if source_type == "S3":
        add_s3_source(data, resource)
        project["source"]["location"] = "ci-protected-source/source.zip"
    data[3].responses[(MEMBER, "codebuild", "us-east-1")].update(
        {
            "batch_get_projects": {"projects": [project]},
            "list_projects": [{"projects": [project["name"]]}],
            "get_resource_policy": {},
        }
    )
    resource["configurationSha256"] = expected_digest({**project, "ResourcePolicy": {}})
    data[0]["roles"][0]["consumerResourceIds"].append(resource["id"])
    refresh_binding(data)
    return resource, project


def pipeline_fixture(data, build_resource=None):
    resource = add_record(
        data,
        "protected-pipeline",
        "pipeline",
        f"arn:aws:codepipeline:us-east-1:{MEMBER}:OutsideNamedPipeline",
        executionRoleArn=ROLE,
    )
    add_s3_source(data, resource)
    pipeline = {
        "name": "OutsideNamedPipeline",
        "roleArn": ROLE,
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Source",
                        "actionTypeId": {
                            "owner": "AWS",
                            "category": "Source",
                            "provider": "S3",
                            "version": "1",
                        },
                        "configuration": {
                            "S3Bucket": "ci-protected-source",
                            "S3ObjectKey": "source.zip",
                        },
                        "outputArtifacts": [{"name": "ApprovedSource"}],
                    }
                ],
            }
        ],
    }
    add_pipeline_storage(data, resource, pipeline)
    if build_resource:
        resource["dependsOnIds"].append(build_resource["id"])
        pipeline["stages"].append(
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "Build",
                        "actionTypeId": {
                            "owner": "AWS",
                            "category": "Build",
                            "provider": "CodeBuild",
                            "version": "1",
                        },
                        "configuration": {"ProjectName": "OutsideNamedBuild"},
                        "inputArtifacts": [{"name": "ApprovedSource"}],
                    }
                ],
            }
        )
    resource["configurationSha256"] = expected_digest(pipeline)
    data[0]["roles"][0]["consumerResourceIds"].append(resource["id"])
    data[3].responses[(MEMBER, "codepipeline", "us-east-1")].update(
        {
            "get_pipeline": {"pipeline": pipeline},
            "list_pipelines": [{"pipelines": [{"name": pipeline["name"]}]}],
        }
    )
    refresh_binding(data)
    return resource, pipeline


def test_complete_no_source_build_control_uses_approved_inline_code_and_managed_image():
    data = fixture()
    _, project = codebuild_fixture(data)
    project["source"]["buildspec"] = json.dumps(
        {"version": "0.2", "phases": {"build": {"commands": ["true"]}}}
    )
    data[0]["resources"][-1]["configurationSha256"] = expected_digest(
        {**project, "ResourcePolicy": {}}
    )
    refresh_binding(data)
    assert make_verifier(data).run()["status"] == "passed"


def test_exact_s3_build_source_accepts_transitive_protected_bucket():
    data = fixture()
    resource, project = codebuild_fixture(data, "S3")
    state, _ = make_verifier(data).resource_snapshot(resource)
    assert state["source"] == project["source"]


@pytest.mark.parametrize(
    "mutation",
    [
        "github",
        "webhook",
        "secondary",
        "s3-mismatch",
        "buildspec-path",
        "cache",
        "filesystem",
        "registry",
        "unprotected-image",
        "batch-role",
        "artifact-bucket",
    ],
)
def test_dummy_enrolled_asset_cannot_hide_external_build_input_authority(mutation):
    data = fixture()
    resource, project = codebuild_fixture(data)
    add_s3_source(data, resource)
    if mutation == "github":
        project["source"].update(
            type="GITHUB", location="https://github.com/foreign/repository"
        )
    elif mutation == "webhook":
        project["webhook"] = {
            "url": "https://github.com/foreign/repository",
            "filterGroups": [],
        }
    elif mutation == "secondary":
        project["secondarySources"] = [
            {"type": "BITBUCKET", "location": "https://bitbucket.org/foreign/repo"}
        ]
    elif mutation == "s3-mismatch":
        project["source"].update(type="S3", location="unprotected/source.zip")
    elif mutation == "buildspec-path":
        project["source"]["buildspec"] = "arn:aws:s3:::unprotected/buildspec.yml"
    elif mutation == "cache":
        project["cache"] = {"type": "S3", "location": "unprotected/cache"}
    elif mutation == "filesystem":
        project["fileSystemLocations"] = [{"type": "EFS", "location": "foreign:/"}]
    elif mutation == "registry":
        project["environment"]["registryCredential"] = {
            "credential": "unprotected",
            "credentialProvider": "SECRETS_MANAGER",
        }
    elif mutation == "unprotected-image":
        project["environment"]["image"] = "docker.io/foreign/build:latest"
    elif mutation == "batch-role":
        project["buildBatchConfig"] = {
            "serviceRole": f"arn:aws:iam::{MEMBER}:role/UnprotectedBatch"
        }
    else:
        project["artifacts"] = {"type": "S3", "location": "unprotected"}
    resource["configurationSha256"] = expected_digest(project)
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).resource_snapshot(resource)


def test_approved_pipeline_sources_and_actual_protected_build_controller_are_bound():
    data = fixture()
    build_resource, project = codebuild_fixture(data, "CODEPIPELINE")
    pipeline_resource, pipeline = pipeline_fixture(data, build_resource)
    project["artifacts"] = {"type": "CODEPIPELINE"}
    build_resource["configurationSha256"] = expected_digest(project)
    refresh_binding(data)
    instance = make_verifier(data)
    build, _ = instance.resource_snapshot(build_resource)
    pipe, _ = instance.resource_snapshot(pipeline_resource)
    assert build["source"]["type"] == "CODEPIPELINE"
    assert pipe == pipeline


@pytest.mark.parametrize(
    "mutation",
    ["dummy-pipeline", "wrong-controller", "actual-project", "unapproved-config"],
)
def test_codepipeline_build_requires_real_project_and_controller_association(mutation):
    data = fixture()
    resource, _ = codebuild_fixture(data, "CODEPIPELINE")
    pipeline_resource, pipeline = pipeline_fixture(data, resource)
    if mutation == "dummy-pipeline":
        pipeline_resource["dependsOnIds"].remove(resource["id"])
    elif mutation == "wrong-controller":
        resource["controllerIds"] = []
    elif mutation == "actual-project":
        pipeline["stages"][1]["actions"][0]["configuration"]["ProjectName"] = (
            "OtherBuild"
        )
        pipeline_resource["configurationSha256"] = expected_digest(pipeline)
    else:
        pipeline["version"] = 999
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).resource_snapshot(resource)


@pytest.mark.parametrize(
    "mutation",
    [
        "foreign-git",
        "source-mismatch",
        "artifact-bucket",
        "artifact-key",
        "build-project",
        "buildspec-override",
        "mixed-action-role",
    ],
)
def test_pipeline_real_inputs_and_artifact_stores_cannot_hide_behind_dummy_dependencies(
    mutation,
):
    data = fixture()
    build, _ = codebuild_fixture(data)
    resource, pipeline = pipeline_fixture(data, build)
    action = pipeline["stages"][0]["actions"][0]
    if mutation == "foreign-git":
        action["actionTypeId"]["provider"] = "CodeStarSourceConnection"
        action["configuration"] = {
            "ConnectionArn": "unprotected",
            "FullRepositoryId": "foreign/repo",
            "BranchName": "mutable",
        }
    elif mutation == "source-mismatch":
        action["configuration"]["S3ObjectKey"] = "unprotected.zip"
    elif mutation == "artifact-bucket":
        pipeline["artifactStore"]["location"] = "unprotected-artifacts"
    elif mutation == "artifact-key":
        pipeline["artifactStore"]["encryptionKey"]["id"] = (
            f"arn:aws:kms:us-east-1:{MEMBER}:alias/unprotected"
        )
    elif mutation == "build-project":
        pipeline["stages"][1]["actions"][0]["configuration"]["ProjectName"] = (
            "UnprotectedProject"
        )
    elif mutation == "buildspec-override":
        pipeline["stages"][1]["actions"][0]["configuration"]["BuildspecOverride"] = (
            "arn:aws:s3:::unprotected/buildspec"
        )
    else:
        action["roleArn"] = f"arn:aws:iam::{MEMBER}:role/UnprotectedAction"
    resource["configurationSha256"] = expected_digest(pipeline)
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).resource_snapshot(resource)


def test_unlisted_outside_name_pipeline_action_role_is_an_execution_consumer():
    data = fixture()
    sdk = data[3].responses[(MEMBER, "codepipeline", "eu-west-1")]
    sdk.update(
        {
            "list_pipelines": [{"pipelines": [{"name": "UnlistedOutsideName"}]}],
            "get_pipeline": {
                "pipeline": {
                    "name": "UnlistedOutsideName",
                    "roleArn": f"arn:aws:iam::{MEMBER}:role/UnprotectedPipeline",
                    "stages": [{"actions": [{"roleArn": ROLE}]}],
                }
            },
        }
    )
    with pytest.raises(verifier.VerificationFailure, match="execution consumers"):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "service,operation,api,key,item_field",
    [
        (
            "stepfunctions",
            "list_state_machine_versions",
            "ListStateMachineVersions",
            "stateMachineVersions",
            "stateMachineVersionArn",
        ),
        (
            "stepfunctions",
            "list_state_machine_aliases",
            "ListStateMachineAliases",
            "stateMachineAliases",
            "stateMachineAliasArn",
        ),
        ("codebuild", "list_fleets", "ListFleets", "fleets", None),
    ],
)
def test_real_sdk_custom_pagination_contract_reads_all_pages_offline(
    service, operation, api, key, item_field
):
    import botocore.session
    from botocore.stub import Stubber

    client = botocore.session.get_session().create_client(
        service,
        region_name="us-east-1",
        aws_access_key_id="offline",
        aws_secret_access_key="offline",
        config=verifier.CONFIG,
    )
    arn = f"arn:aws:states:us-east-1:{MEMBER}:stateMachine:Offline"
    first = (
        {item_field: arn + ":1", "creationDate": "2026-11-25T00:00:00Z"}
        if item_field
        else "offline-fleet-one"
    )
    second = (
        {item_field: arn + ":2", "creationDate": "2026-11-25T00:00:00Z"}
        if item_field
        else "offline-fleet-two"
    )
    params = {"stateMachineArn": arn} if service == "stepfunctions" else {}
    assert not client.can_paginate(operation)
    model = client.meta.service_model.operation_model(api)
    assert (
        "nextToken" in model.input_shape.members and key in model.output_shape.members
    )
    with Stubber(client) as stubber:
        stubber.add_response(operation, {key: [first], "nextToken": "next"}, params)
        stubber.add_response(
            operation, {key: [second]}, {**params, "nextToken": "next"}
        )
        assert verifier.Verifier.pages(client, operation, key, **params) == [
            first,
            second,
        ]
        stubber.assert_no_pending_responses()
    client.close()


@pytest.mark.parametrize("surface", ["batch", "resource-access", "fleet", "sandbox"])
def test_ordinary_main_role_cannot_hide_other_protected_codebuild_authority(surface):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "codebuild", "eu-west-1")]
    if surface in {"batch", "resource-access"}:
        project = {
            "name": "OutsideName",
            "arn": f"arn:aws:codebuild:eu-west-1:{MEMBER}:project/OutsideName",
            "serviceRole": f"arn:aws:iam::{MEMBER}:role/Ordinary",
        }
        project["buildBatchConfig" if surface == "batch" else "resourceAccessRole"] = (
            {"serviceRole": ROLE} if surface == "batch" else ROLE
        )
        sdk["list_projects"] = [{"projects": ["OutsideName"]}]
        sdk["batch_get_projects"] = {"projects": [project]}
    elif surface == "fleet":
        sdk["list_fleets"] = [{"fleets": []}, {"fleets": ["OutsideFleet"]}]
        sdk["batch_get_fleets"] = {
            "fleets": [{"name": "OutsideFleet", "fleetServiceRole": ROLE}]
        }
    else:
        sdk["list_sandboxes"] = [{"ids": []}, {"ids": ["OutsideSandbox"]}]
        sdk["batch_get_sandboxes"] = {
            "sandboxes": [{"id": "OutsideSandbox", "serviceRole": ROLE}]
        }
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).run()


def test_unrelated_ordinary_codebuild_authorities_are_preserved():
    data = fixture()
    sdk = data[3].responses[(MEMBER, "codebuild", "eu-west-1")]
    ordinary = f"arn:aws:iam::{MEMBER}:role/Ordinary"
    sdk.update(
        {
            "list_projects": [{"projects": ["OrdinaryProject"]}],
            "batch_get_projects": {
                "projects": [
                    {
                        "arn": f"arn:aws:codebuild:eu-west-1:{MEMBER}:project/OrdinaryProject",
                        "serviceRole": ordinary,
                        "resourceAccessRole": ordinary,
                        "buildBatchConfig": {"serviceRole": ordinary},
                    }
                ]
            },
            "list_fleets": [{"fleets": ["OrdinaryFleet"]}],
            "batch_get_fleets": {"fleets": [{"fleetServiceRole": ordinary}]},
            "list_sandboxes": [{"ids": ["OrdinarySandbox"]}],
            "batch_get_sandboxes": {"sandboxes": [{"serviceRole": ordinary}]},
        }
    )
    assert make_verifier(data).run()["status"] == "passed"


@pytest.mark.parametrize(
    "mutation",
    [
        "public",
        "resource-access",
        "fleet",
        "batch-config",
        "yaml-batch",
        "json-batch",
        "merged-batch",
        "inline-parameter",
    ],
)
def test_protected_projects_reject_unsupported_batch_and_external_access_configuration(
    mutation,
):
    data = fixture()
    resource, project = codebuild_fixture(data)
    if mutation == "public":
        project["projectVisibility"] = "PUBLIC_READ"
    elif mutation == "resource-access":
        project["resourceAccessRole"] = f"arn:aws:iam::{MEMBER}:role/Ordinary"
    elif mutation == "fleet":
        project["environment"]["fleet"] = {
            "fleetArn": f"arn:aws:codebuild:us-east-1:{MEMBER}:fleet/Unprotected:id"
        }
    elif mutation == "batch-config":
        project["buildBatchConfig"] = {"serviceRole": ROLE}
    elif mutation == "yaml-batch":
        project["source"]["buildspec"] += "'batch':\n  build-list: []\n"
    elif mutation == "json-batch":
        project["source"]["buildspec"] = json.dumps(
            {"version": 0.2, "phases": {}, "batch": {}}
        )
    elif mutation == "merged-batch":
        project["source"]["buildspec"] = (
            "<<: &defaults {'batch': {}}\nversion: 0.2\nphases: {}\n"
        )
    else:
        project["source"]["buildspec"] += (
            "env:\n  parameter-store:\n    UNTRUSTED: /unprotected/input\n"
        )
    resource["configurationSha256"] = expected_digest({**project, "ResourcePolicy": {}})
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).resource_snapshot(resource)


@pytest.mark.parametrize("trusted", [False, True])
def test_build_resource_policy_requires_exact_enrolled_controller_principal(trusted):
    data = fixture()
    resource, project = codebuild_fixture(data)
    policy = {
        "policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": ROLE
                            if trusted
                            else "arn:aws:iam::999999999999:role/Foreign"
                        },
                        "Action": "codebuild:StartBuild",
                        "Resource": resource["arn"],
                    }
                ]
            }
        )
    }
    data[3].responses[(MEMBER, "codebuild", "us-east-1")]["get_resource_policy"] = (
        policy
    )
    resource["configurationSha256"] = expected_digest(
        {**project, "ResourcePolicy": policy}
    )
    refresh_binding(data)
    if trusted:
        assert make_verifier(data).run()["status"] == "passed"
    else:
        with pytest.raises(
            verifier.VerificationFailure, match="external positive resource grant"
        ):
            make_verifier(data).run()


@pytest.mark.parametrize("complete", [False, True])
def test_outside_project_historical_protected_build_role_never_hides_after_role_change(
    complete,
):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "codebuild", "eu-west-1")]
    sdk["list_builds"] = [{"ids": ["OutsideOldBuild"]}]
    sdk["batch_get_builds"] = {
        "builds": [
            {
                "projectName": "OutsideOldProject",
                "serviceRole": ROLE,
                "buildComplete": complete,
            }
        ]
    }
    with pytest.raises(
        verifier.VerificationFailure, match="quiet cutover|execution consumers"
    ):
        make_verifier(data).run()


def test_completed_build_history_is_bound_to_enrolled_current_project():
    data = fixture()
    _, project = codebuild_fixture(data)
    sdk = data[3].responses[(MEMBER, "codebuild", "us-east-1")]
    sdk["list_builds"] = [{"ids": ["ApprovedOldBuild"]}]
    sdk["batch_get_builds"] = {
        "builds": [
            {
                "projectName": project["name"],
                "serviceRole": ROLE,
                "buildComplete": True,
            }
        ]
    }
    assert make_verifier(data).run()["status"] == "passed"


@pytest.mark.parametrize("protected_field", ["serviceRole", "buildBatchConfig"])
def test_historical_protected_batch_build_authority_is_unsupported(protected_field):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "codebuild", "eu-west-1")]
    build = {"serviceRole": f"arn:aws:iam::{MEMBER}:role/Ordinary", "complete": True}
    build[protected_field] = (
        ROLE if protected_field == "serviceRole" else {"serviceRole": ROLE}
    )
    sdk["list_build_batches"] = [{"ids": ["OldOutsideBatch"]}]
    sdk["batch_get_build_batches"] = {"buildBatches": [build]}
    with pytest.raises(
        verifier.VerificationFailure, match="historical protected-role batch"
    ):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "status,redrive",
    [("RUNNING", None), ("FAILED", "REDRIVABLE"), ("ABORTED", "REDRIVABLE_BY_MAP_RUN")],
)
def test_saved_state_machine_execution_role_cannot_hide_after_base_changes(
    status, redrive
):
    data = fixture()
    resource, base, _, _, sdk = state_machine_fixture(data)
    data[0]["resources"].remove(resource)
    data[0]["roles"][0]["consumerResourceIds"].remove(resource["id"])
    base["roleArn"] = f"arn:aws:iam::{MEMBER}:role/Ordinary"
    sdk["list_state_machine_versions"] = [{"stateMachineVersions": []}]
    sdk["list_state_machine_aliases"] = [{"stateMachineAliases": []}]
    execution_arn = resource["arn"].replace(":stateMachine:", ":execution:") + ":saved"
    sdk["list_executions"] = [
        {"executions": [{"executionArn": execution_arn, "status": status}]}
    ]
    sdk["describe_execution"] = {
        "status": status,
        **({"redriveStatus": redrive} if redrive else {}),
    }
    sdk["describe_state_machine_for_execution"] = {"roleArn": ROLE}
    refresh_binding(data)
    with pytest.raises(
        verifier.VerificationFailure, match="execution consumers|quiet cutover"
    ):
        make_verifier(data).run()


def test_enrolled_standard_saved_execution_keeps_same_protected_role():
    data = fixture()
    resource, _, _, _, sdk = state_machine_fixture(data)
    execution = resource["arn"].replace(":stateMachine:", ":execution:") + ":approved"
    sdk["list_executions"] = [
        {"executions": [{"executionArn": execution, "status": "FAILED"}]}
    ]
    sdk["describe_execution"] = {"status": "FAILED", "redriveStatus": "REDRIVABLE"}
    sdk["describe_state_machine_for_execution"] = {"roleArn": ROLE}
    assert make_verifier(data).run()["status"] == "passed"
    assert any(
        operation == "describe_state_machine_for_execution"
        and args["includedData"] == "METADATA_ONLY"
        for operation, args, _ in data[3].calls
    )


def test_express_history_is_explicitly_unsupported_even_for_ordinary_current_role():
    data = fixture()
    resource, base, _, _, _ = state_machine_fixture(data)
    data[0]["resources"].remove(resource)
    data[0]["roles"][0]["consumerResourceIds"].remove(resource["id"])
    base["roleArn"] = f"arn:aws:iam::{MEMBER}:role/Ordinary"
    base["type"] = "EXPRESS"
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="EXPRESS execution history"):
        make_verifier(data).run()


def nested_state(path, role):
    result = role
    for field in reversed(path):
        result = {field: result}
    return result


@pytest.mark.parametrize("protected", [False, True])
@pytest.mark.parametrize(
    "listed,collection,getter,identity,argument,path",
    verifier.AGENTCORE_DIRECT_CONSUMERS,
)
def test_all_direct_agentcore_families_reject_protected_roles_and_preserve_ordinary(
    protected, listed, collection, getter, identity, argument, path
):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "eu-west-1")]
    sdk[listed] = [{collection: [{identity: "OutsideProjectNaming"}]}]
    sdk[getter] = nested_state(
        path, ROLE if protected else f"arn:aws:iam::{MEMBER}:role/Ordinary"
    )
    if protected:
        with pytest.raises(
            verifier.VerificationFailure, match="outside enrolled Gateways"
        ):
            make_verifier(data).run()
    else:
        assert make_verifier(data).run()["status"] == "passed"
        assert (getter, {argument: "OutsideProjectNaming"}, "direct") in data[3].calls


@pytest.mark.parametrize(
    "listed,collection,getter,identity",
    [
        ("list_browsers", "browserSummaries", "get_browser", "browserId"),
        (
            "list_code_interpreters",
            "codeInterpreterSummaries",
            "get_code_interpreter",
            "codeInterpreterId",
        ),
    ],
)
@pytest.mark.parametrize("role", [ROLE, "ordinary", "missing"])
def test_custom_browser_and_interpreter_roles_are_required_and_cannot_be_protected(
    listed, collection, getter, identity, role
):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "eu-west-1")]
    sdk[listed] = lambda args: [
        {collection: [{identity: "OutsideName"}] if args["type"] == "CUSTOM" else []}
    ]
    sdk[getter] = (
        {}
        if role == "missing"
        else {
            "executionRoleArn": ROLE
            if role == ROLE
            else f"arn:aws:iam::{MEMBER}:role/Ordinary"
        }
    )
    if role == "ordinary":
        assert make_verifier(data).run()["status"] == "passed"
    else:
        with pytest.raises(verifier.VerificationFailure, match="AgentCore"):
            make_verifier(data).run()


def test_builtin_system_tools_without_a_customer_role_remain_supported():
    data = fixture()
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "eu-west-1")]
    sdk["list_browsers"] = lambda args: [
        {
            "browserSummaries": [{"browserId": "builtin"}]
            if args["type"] == "SYSTEM"
            else []
        }
    ]
    sdk["get_browser"] = {}
    assert make_verifier(data).run()["status"] == "passed"


@pytest.mark.parametrize("family", ["runtime", "harness"])
@pytest.mark.parametrize("old_role_source", ["ordinary", "version", "endpoint"])
def test_agentcore_runtime_and_harness_published_versions_and_endpoints_are_inventoried(
    family, old_role_source
):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "eu-west-1")]
    runtime = family == "runtime"
    identity = "agentRuntimeId" if runtime else "harnessId"
    version = "agentRuntimeVersion" if runtime else "harnessVersion"
    sdk["list_agent_runtimes" if runtime else "list_harnesses"] = [
        {
            "agentRuntimes" if runtime else "harnesses": [
                {identity: "outside", version: "2"}
            ]
        }
    ]
    sdk["list_agent_runtime_versions" if runtime else "list_harness_versions"] = [
        {
            "agentRuntimes" if runtime else "harnessVersions": [
                {version: "1"} if old_role_source == "version" else {version: "2"}
            ]
        }
    ]
    sdk["list_agent_runtime_endpoints" if runtime else "list_harness_endpoints"] = [
        {
            "runtimeEndpoints" if runtime else "endpoints": [
                {"name" if runtime else "endpointName": "live"}
            ]
        }
    ]
    endpoint = {
        "liveVersion": "1" if old_role_source == "endpoint" else "2",
        "targetVersion": "2",
    }
    sdk["get_agent_runtime_endpoint" if runtime else "get_harness_endpoint"] = (
        endpoint if runtime else {"endpoint": endpoint}
    )
    sdk["get_agent_runtime" if runtime else "get_harness"] = lambda args: nested_state(
        ("roleArn",) if runtime else ("harness", "executionRoleArn"),
        ROLE if args[version] == "1" else f"arn:aws:iam::{MEMBER}:role/Ordinary",
    )
    if old_role_source == "ordinary":
        assert make_verifier(data).run()["status"] == "passed"
    else:
        with pytest.raises(
            verifier.VerificationFailure, match="outside enrolled Gateways"
        ):
            make_verifier(data).run()
    assert any(
        operation
        == ("list_agent_runtime_endpoints" if runtime else "list_harness_endpoints")
        for operation, _, _ in data[3].calls
    )


@pytest.mark.parametrize("protected", [False, True])
def test_registry_iam_credential_provider_role_is_an_actual_consumer(protected):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "eu-west-1")]
    sdk["list_registries"] = [{"registries": [{"registryId": "outside"}]}]
    sdk["list_registry_records"] = [{"registryRecords": [{"recordId": "source"}]}]
    sdk["get_registry_record"] = {
        "synchronizationConfiguration": {
            "fromUrl": {
                "credentialProviderConfigurations": [
                    {
                        "credentialProvider": {
                            "iamCredentialProvider": {
                                "roleArn": ROLE
                                if protected
                                else f"arn:aws:iam::{MEMBER}:role/Ordinary"
                            }
                        }
                    }
                ]
            }
        }
    }
    if protected:
        with pytest.raises(verifier.VerificationFailure, match="get_registry_record"):
            make_verifier(data).run()
    else:
        assert make_verifier(data).run()["status"] == "passed"


@pytest.mark.parametrize("protected", [False, True])
def test_dataplane_ab_test_role_is_not_omitted_by_control_namespace_scan(protected):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore", "eu-west-1")]
    sdk["list_ab_tests"] = [{"abTests": [{"abTestId": "outside"}]}]
    sdk["get_ab_test"] = {
        "roleArn": ROLE if protected else f"arn:aws:iam::{MEMBER}:role/Ordinary"
    }
    if protected:
        with pytest.raises(verifier.VerificationFailure, match="get_ab_test"):
            make_verifier(data).run()
    else:
        assert make_verifier(data).run()["status"] == "passed"


@pytest.mark.parametrize(
    "service,allowed",
    [
        ("bedrock-agentcore-control", verifier.AGENTCORE_ROLE_READ_OPERATIONS),
        ("bedrock-agentcore", frozenset({"GetABTest"})),
    ],
)
def test_primary_sdk_role_bearing_reads_are_complete_and_new_paths_fail_closed(
    service, allowed
):
    verifier.Verifier.verify_agentcore_model(service_model(service), allowed)
    with pytest.raises(verifier.VerificationFailure, match="inventory contract"):
        verifier.Verifier.verify_agentcore_model(
            service_model(service), allowed | {"GetUnknownNewExecutionRole"}
        )


def gateway_fixture(data, target="inference"):
    resource = add_record(
        data,
        "protected-gateway",
        "gateway",
        f"arn:aws:bedrock-agentcore:us-east-1:{MEMBER}:gateway/approved",
        executionRoleArn=ROLE,
        dependsOnIds=["provider"],
    )
    data[0]["resources"][0]["invokerIds"] = ["provider-role"]
    gateway = {
        "gatewayArn": resource["arn"],
        "roleArn": ROLE,
        "authorizerType": "AWS_IAM",
        "interceptorConfigurations": [
            {
                "interceptor": {"lambda": {"arn": FUNCTION}},
                "interceptionPoints": ["REQUEST"],
                "inputConfiguration": {"passRequestHeaders": False},
            }
        ],
        "Targets": [
            {
                "gatewayArn": resource["arn"],
                "targetId": "approved",
                "credentialProviderConfigurations": [
                    {"credentialProviderType": "GATEWAY_IAM_ROLE"}
                ],
                "targetConfiguration": (
                    {
                        "inference": {
                            "connector": {"source": {"connectorId": "bedrock-mantle"}}
                        }
                    }
                    if target == "inference"
                    else {
                        "mcp": {
                            "lambda": {
                                "lambdaArn": FUNCTION,
                                "toolSchema": {"inlinePayload": []},
                            }
                        }
                    }
                ),
            }
        ],
    }
    resource["configurationSha256"] = expected_digest(gateway)
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "us-east-1")]
    sdk.update(
        {
            "get_gateway": {
                key: value for key, value in gateway.items() if key != "Targets"
            },
            "list_gateway_targets": [{"items": [{"targetId": "approved"}]}],
            "get_gateway_target": gateway["Targets"][0],
        }
    )
    refresh_binding(data)
    return resource, gateway


@pytest.mark.parametrize("target", ["inference", "lambda"])
def test_enrolled_iam_gateway_supports_protected_request_mantle_and_lambda_targets(
    target,
):
    data = fixture()
    resource, gateway = gateway_fixture(data, target)
    actual, _ = make_verifier(data).resource_snapshot(resource)
    assert actual == gateway


def native_policy_fixture(data):
    gateway_resource, gateway = gateway_fixture(data)
    key = add_record(
        data,
        "native-policy-key",
        "kms",
        f"arn:aws:kms:us-east-1:{MEMBER}:key/11111111-2222-4333-8444-555555555555",
    )
    key_state = {"KeyMetadata": {"Arn": key["arn"]}, "Policy": {}, "Grants": []}
    key["configurationSha256"] = expected_digest(key_state)
    key["documentSha256"] = expected_digest({})
    data[3].responses[(MEMBER, "kms", "us-east-1")] = {
        "describe_key": {"KeyMetadata": key_state["KeyMetadata"]},
        "get_key_policy": {"Policy": "{}"},
        "list_grants": [{"Grants": []}],
    }
    engine_resource = add_record(
        data,
        "native-engine",
        "agentcore-policy-engine",
        f"arn:aws:bedrock-agentcore:us-east-1:{MEMBER}:policy-engine/approved-1234567890",
        dependsOnIds=[key["id"], "legacy"],
    )
    policy_resource = add_record(
        data,
        "native-policy",
        "agentcore-policy",
        engine_resource["arn"] + "/policy/approved-policy-1234567890",
        dependsOnIds=[engine_resource["id"]],
    )
    engine = {
        "policyEngineId": "approved-1234567890",
        "name": "approved",
        "policyEngineArn": engine_resource["arn"],
        "encryptionKeyArn": key["arn"],
        "createdAt": "2026-11-25T12:00:00Z",
        "updatedAt": "2026-11-25T12:00:00Z",
        "status": "ACTIVE",
        "statusReasons": [],
    }
    policy = {
        "policyId": "approved-policy-1234567890",
        "name": "approved",
        "policyEngineId": "approved-1234567890",
        "policyArn": policy_resource["arn"],
        "createdAt": "2026-11-25T12:00:00Z",
        "updatedAt": "2026-11-25T12:00:00Z",
        "status": "ACTIVE",
        "statusReasons": [],
        "definition": {"cedar": {"statement": "permit(principal, action, resource);"}},
    }
    engine_resource["configurationSha256"] = expected_digest(
        {"Engine": engine, "Policies": [policy], "Tags": {"tags": {}}}
    )
    policy_resource["configurationSha256"] = expected_digest(policy)
    policy_resource["documentSha256"] = expected_digest(policy["definition"])
    gateway["policyEngineConfiguration"] = {
        "arn": engine_resource["arn"],
        "mode": "ENFORCE",
    }
    gateway["ResourcePolicy"] = {}
    gateway_resource["dependsOnIds"].extend(
        [engine_resource["id"], policy_resource["id"]]
    )
    gateway_resource["configurationSha256"] = expected_digest(gateway)
    sdk = data[3].responses[(MEMBER, "bedrock-agentcore-control", "us-east-1")]
    sdk.update(
        {
            "get_policy_engine": engine,
            "list_policies": [{"policies": [policy]}],
            "get_policy": policy,
            "list_tags_for_resource": {"tags": {}},
            "get_resource_policy": {},
            "get_gateway": {
                key: value
                for key, value in gateway.items()
                if key not in {"Targets", "ResourcePolicy"}
            },
        }
    )
    refresh_binding(data)
    return gateway_resource, engine_resource, policy_resource, gateway, sdk


def test_native_policy_fixture_matches_the_installed_sdk_response_contract():
    from botocore.validate import validate_parameters

    data = fixture()
    *_, sdk = native_policy_fixture(data)
    model = service_model("bedrock-agentcore-control")
    for operation, response in [
        ("GetPolicyEngine", sdk["get_policy_engine"]),
        ("GetPolicy", sdk["get_policy"]),
        ("ListPolicies", sdk["list_policies"][0]),
    ]:
        validate_parameters(response, model.operation_model(operation).output_shape)
    policies = model.operation_model("ListPolicies").output_shape.members["policies"]
    assert "definition" in policies.member.members
    assert "ACTIVE" in model.operation_model("GetPolicyEngine").output_shape.members[
        "status"
    ].enum
    assert "ACTIVE" in model.operation_model("GetPolicy").output_shape.members["status"].enum


def test_native_policy_engine_and_documents_are_reconciled_with_gateway_dependencies():
    data = fixture()
    gateway_resource, engine_resource, policy_resource, gateway, _ = (
        native_policy_fixture(data)
    )
    instance = make_verifier(data)
    assert instance.resource_snapshot(gateway_resource)[0] == gateway
    assert instance.resource_snapshot(engine_resource)[0]["Engine"]["status"] == "ACTIVE"
    assert instance.resource_snapshot(policy_resource)[1] == {
        "cedar": {"statement": "permit(principal, action, resource);"}
    }
    instance.verify_resources()
    assert "resource:native-engine" in instance.checks
    assert "resource:native-policy" in instance.checks


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-policy",
        "extra-policy",
        "duplicate-policy",
        "engine-key",
        "engine-identity",
        "policy-identity",
        "policy-status",
        "policy-definition",
        "document-drift",
        "document-missing",
        "unreadable-policy-list",
        "unmodeled-gateway-engine",
        "unmodeled-gateway-policy",
        "unsupported-mode",
    ],
)
def test_native_policy_authority_rejects_missing_and_unmodeled_inputs(mutation):
    data = fixture()
    gateway_resource, engine_resource, policy_resource, gateway, sdk = (
        native_policy_fixture(data)
    )
    if mutation == "missing-policy":
        sdk["list_policies"] = [{"policies": []}]
    elif mutation == "extra-policy":
        sdk["list_policies"][0]["policies"].append(
            {"policyArn": engine_resource["arn"] + "/policy/unapproved"}
        )
    elif mutation == "duplicate-policy":
        sdk["list_policies"][0]["policies"] *= 2
    elif mutation == "engine-key":
        sdk["get_policy_engine"]["encryptionKeyArn"] += "-unapproved"
    elif mutation == "engine-identity":
        sdk["get_policy_engine"]["policyEngineId"] = "other"
    elif mutation == "policy-identity":
        sdk["get_policy"]["policyArn"] += "-other"
    elif mutation == "policy-status":
        sdk["get_policy"]["status"] = "DELETING"
    elif mutation == "policy-definition":
        sdk["get_policy"]["definition"] = {
            "policyGeneration": {"policyGenerationId": "unprotected"}
        }
    elif mutation == "document-drift":
        policy_resource["documentSha256"] = "f" * 64
    elif mutation == "document-missing":
        policy_resource.pop("documentSha256")
    elif mutation == "unreadable-policy-list":
        sdk["list_policies"] = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListPolicies",
        )
    elif mutation == "unmodeled-gateway-engine":
        gateway_resource["dependsOnIds"].remove(engine_resource["id"])
        gateway_resource["dependsOnIds"].remove(policy_resource["id"])
    elif mutation == "unmodeled-gateway-policy":
        gateway_resource["dependsOnIds"].remove(policy_resource["id"])
    else:
        sdk["get_gateway"]["policyEngineConfiguration"]["mode"] = "OFF"
    refresh_binding(data)
    with pytest.raises((verifier.VerificationFailure, ClientError)):
        make_verifier(data).verify_resources()


@pytest.mark.parametrize(
    "mutation",
    [
        "CUSTOM_JWT",
        "NONE",
        "AUTHENTICATE_ONLY",
        "unprotected-interceptor",
        "unapproved-invoker",
        "request-headers",
        "missing-request",
        "response-only",
        "external-inference",
        "wrong-connector",
        "remote-mcp",
        "API_KEY",
        "OAUTH",
        "CALLER",
        "external-lambda",
        "external-schema",
        "private-endpoint",
    ],
)
def test_approved_gateway_hash_does_not_enroll_external_auth_input_or_privileged_route(
    mutation,
):
    data = fixture()
    resource, gateway = gateway_fixture(data)
    if mutation in {"CUSTOM_JWT", "NONE", "AUTHENTICATE_ONLY"}:
        gateway["authorizerType"] = mutation
    elif mutation == "unprotected-interceptor":
        gateway["interceptorConfigurations"][0]["interceptor"]["lambda"]["arn"] = (
            FUNCTION + "Other"
        )
    elif mutation == "unapproved-invoker":
        data[0]["resources"][0]["invokerIds"] = []
    elif mutation == "request-headers":
        gateway["interceptorConfigurations"][0]["inputConfiguration"][
            "passRequestHeaders"
        ] = True
    elif mutation == "missing-request":
        gateway["interceptorConfigurations"] = []
    elif mutation == "response-only":
        gateway["interceptorConfigurations"][0]["interceptionPoints"] = ["RESPONSE"]
    else:
        target = gateway["Targets"][0]
        if mutation == "external-inference":
            target["targetConfiguration"] = {
                "inference": {"provider": {"endpoint": "https://external.invalid"}}
            }
        elif mutation == "wrong-connector":
            target["targetConfiguration"]["inference"]["connector"]["source"][
                "connectorId"
            ] = "external"
        elif mutation == "remote-mcp":
            target["targetConfiguration"] = {
                "mcp": {"mcpServer": {"endpoint": "https://external.invalid"}}
            }
        elif mutation in {"API_KEY", "OAUTH", "CALLER"}:
            target["credentialProviderConfigurations"][0]["credentialProviderType"] = (
                mutation
            )
        elif mutation == "private-endpoint":
            target["privateEndpoint"] = {"vpcEndpointId": "unprotected"}
        else:
            target["targetConfiguration"] = {
                "mcp": {
                    "lambda": {
                        "lambdaArn": FUNCTION + "Other"
                        if mutation == "external-lambda"
                        else FUNCTION,
                        "toolSchema": {
                            "s3": {
                                "uri": "s3://external/schema.json",
                                "bucketOwnerAccountId": MEMBER,
                            }
                        },
                    }
                }
            }
    resource["configurationSha256"] = expected_digest(gateway)
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).verify_gateway_inputs(resource, gateway)


@pytest.mark.parametrize("active_status", ["RUNNING", "PENDING_REDRIVE"])
def test_enrolled_active_standard_execution_prevents_quiet_cutover(active_status):
    data = fixture()
    resource, _, _, _, sdk = state_machine_fixture(data)
    execution = resource["arn"].replace(":stateMachine:", ":execution:") + ":active"
    sdk["list_executions"] = [
        {"executions": [{"executionArn": execution, "status": active_status}]}
    ]
    sdk["describe_execution"] = {"status": active_status}
    sdk["describe_state_machine_for_execution"] = {"roleArn": ROLE}
    with pytest.raises(verifier.VerificationFailure, match="quiet cutover"):
        make_verifier(data).run()


@pytest.mark.parametrize("historic_role", ["pipeline", "action"])
def test_historical_pipeline_version_role_cannot_hide_behind_ordinary_current_role(
    historic_role,
):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "codepipeline", "eu-west-1")]
    current = {
        "name": "OutsideNaming",
        "version": 2,
        "roleArn": f"arn:aws:iam::{MEMBER}:role/Ordinary",
        "stages": [],
    }
    saved = copy.deepcopy(current)
    saved["version"] = 1
    if historic_role == "pipeline":
        saved["roleArn"] = ROLE
    else:
        saved["stages"] = [{"actions": [{"roleArn": ROLE}]}]
    sdk.update(
        {
            "list_pipelines": [{"pipelines": [{"name": current["name"]}]}],
            "get_pipeline": lambda args: {
                "pipeline": saved if args.get("version") == 1 else current
            },
            "list_pipeline_executions": [
                {"pipelineExecutionSummaries": [{"pipelineExecutionId": "old"}]}
            ],
            "get_pipeline_execution": {
                "pipelineExecution": {"pipelineVersion": 1, "status": "Succeeded"}
            },
        }
    )
    with pytest.raises(verifier.VerificationFailure, match="execution consumers"):
        make_verifier(data).run()
    assert ("get_pipeline", {"name": "OutsideNaming", "version": 1}, "direct") in data[
        3
    ].calls


@pytest.mark.parametrize("status", ["Succeeded", "Failed", "InProgress", "Stopping"])
def test_enrolled_pipeline_saved_versions_require_quiet_cutover_but_allow_completed_history(
    status,
):
    data = fixture()
    resource, pipeline = pipeline_fixture(data)
    saved = {**copy.deepcopy(pipeline), "version": 1}
    sdk = data[3].responses[(MEMBER, "codepipeline", "us-east-1")]
    sdk["get_pipeline"] = lambda args: {
        "pipeline": saved if args.get("version") else pipeline
    }
    sdk["list_pipeline_executions"] = [
        {"pipelineExecutionSummaries": [{"pipelineExecutionId": "saved"}]}
    ]
    sdk["get_pipeline_execution"] = {
        "pipelineExecution": {"pipelineVersion": 1, "status": status}
    }
    instance = make_verifier(data)
    if status in {"InProgress", "Stopping"}:
        with pytest.raises(verifier.VerificationFailure, match="quiet cutover"):
            instance.verify_consumers()
    else:
        instance.verify_consumers()
        assert (
            f"consumers:{resource['id']}" not in instance.checks
        )  # Complete graph is the verifier-wide check.


@pytest.mark.parametrize(
    "template",
    [
        {"Transform": "MutableMacro", "Resources": {}},
        {
            "Resources": {
                "Include": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "Fn::Transform": {
                            "Name": "AWS::Include",
                            "Parameters": {"Location": "s3://external/input"},
                        }
                    },
                }
            }
        },
        {
            "Resources": {
                "Macro": {
                    "Type": "AWS::CloudFormation::Macro",
                    "Properties": {"FunctionName": "external"},
                }
            }
        },
        {
            "Resources": {
                "Child": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {"TemplateURL": "https://external.invalid/template"},
                }
            }
        },
    ],
)
@pytest.mark.parametrize("kind", ["stack", "stack-set"])
def test_macros_transforms_and_nested_templates_fail_even_with_approved_hash(
    template, kind
):
    data = fixture()
    resource = data[0]["resources"][1]
    resource["kind"] = kind
    resource["documentSha256"] = expected_digest(template)
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="unsupported"):
        make_verifier(data).verify_template_inputs(resource, template, [])


def protected_template_inputs(data):
    stack = data[0]["resources"][1]
    ssm = add_record(
        data,
        "bootstrap-version",
        "ssm",
        f"arn:aws:ssm:us-east-1:{MEMBER}:parameter/cdk-bootstrap/hnb659fds/version",
    )
    secret = add_record(
        data,
        "template-secret",
        "secret",
        f"arn:aws:secretsmanager:us-east-1:{MEMBER}:secret:protected-input-AbCdEf",
    )
    stack["dependsOnIds"] = [ssm["id"], secret["id"]]
    refresh_binding(data)
    return stack, ssm, secret


def test_bootstrap_ssm_parameter_and_literal_dynamic_refs_use_exact_protected_stores():
    data = fixture()
    stack, ssm, secret = protected_template_inputs(data)
    template = {
        "Parameters": {
            "BootstrapVersion": {
                "Type": "AWS::SSM::Parameter::Value<String>",
                "Default": "/cdk-bootstrap/hnb659fds/version",
            }
        },
        "Resources": {
            "Config": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "Ssm": "{{resolve:ssm:/cdk-bootstrap/hnb659fds/version:6}}",
                    "Secure": "{{resolve:ssm-secure:" + ssm["arn"] + ":6}}",
                    "Secret": "{{resolve:secretsmanager:"
                    + secret["arn"]
                    + ":SecretString:key}}",
                },
            }
        },
    }
    parameters = [
        {
            "ParameterKey": "BootstrapVersion",
            "ParameterValue": "/cdk-bootstrap/hnb659fds/version",
            "ResolvedValue": "6",
        }
    ]
    assert make_verifier(data).verify_template_inputs(stack, template, parameters) == []


@pytest.mark.parametrize(
    "mode",
    [
        "missing-dependency",
        "unprotected-actual-parameter",
        "unresolved-parameter",
        "relative-secret",
        "dynamic-substitution",
        "malformed",
        "unknown-resolver",
    ],
)
def test_template_parameter_hash_cannot_substitute_for_future_input_authority(mode):
    data = fixture()
    stack, _, secret = protected_template_inputs(data)
    template = {
        "Parameters": {
            "BootstrapVersion": {
                "Type": "AWS::SSM::Parameter::Value<String>",
                "Default": "/cdk-bootstrap/hnb659fds/version",
            }
        },
        "Resources": {},
    }
    parameters = [
        {
            "ParameterKey": "BootstrapVersion",
            "ParameterValue": "/cdk-bootstrap/hnb659fds/version",
            "ResolvedValue": "6",
        }
    ]
    if mode == "missing-dependency":
        stack["dependsOnIds"] = []
    elif mode == "unprotected-actual-parameter":
        parameters[0]["ParameterValue"] = "/external/future-input"
    elif mode == "unresolved-parameter":
        parameters[0]["ParameterValue"] = "${SomeMutableName}"
    else:
        template["Parameters"] = {}
        template["Metadata"] = {
            "relative-secret": "{{resolve:secretsmanager:external:SecretString}}",
            "dynamic-substitution": "{{resolve:secretsmanager:"
            + secret["arn"]
            + "${Input}:SecretString}}",
            "malformed": "{{resolve:ssm:/external",
            "unknown-resolver": "{{resolve:unknown:/external}}",
        }[mode]
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).verify_template_inputs(stack, template, parameters)


@pytest.mark.parametrize("callback", ["literal", "getatt", "getatt-string"])
def test_cdk_custom_provider_resolves_actual_lambda_and_exact_iam_invoker_without_cycle(
    callback,
):
    data = fixture()
    stack = data[0]["resources"][1]
    provider = data[0]["resources"][0]
    stack["dependsOnIds"] = ["provider"]
    provider["invokerIds"] = ["provider-role"]
    token = (
        FUNCTION
        if callback == "literal"
        else {
            "Fn::GetAtt": ["GeneratedProviderLogical", "Arn"]
            if callback == "getatt"
            else "GeneratedProviderLogical.Arn"
        }
    )
    template = {
        "Resources": {
            "Custom": {
                "Type": "Custom::CDKProvider",
                "Properties": {"ServiceToken": token},
            }
        }
    }
    binding = {
        "LogicalResourceId": "GeneratedProviderLogical",
        "PhysicalResourceId": "GeneratedProvider",
        "ResourceType": "AWS::Lambda::Function",
    }
    data[3].responses[(MEMBER, "cloudformation", "us-east-1")][
        "list_stack_resources"
    ] = [{"StackResourceSummaries": [binding]}]
    refresh_binding(data)
    actual = make_verifier(data).verify_template_inputs(stack, template, [])
    assert actual == ([] if callback == "literal" else [binding])
    assert provider["dependsOnIds"] == []


@pytest.mark.parametrize(
    "mode", ["external", "sns", "unknown-binding", "unapproved-invoker"]
)
def test_unprotected_custom_provider_callbacks_cannot_feed_privileged_cfn(mode):
    data = fixture()
    stack = data[0]["resources"][1]
    stack["dependsOnIds"] = ["provider"]
    data[0]["resources"][0]["invokerIds"] = (
        [] if mode == "unapproved-invoker" else ["provider-role"]
    )
    token = {
        "external": FUNCTION + "External",
        "sns": f"arn:aws:sns:us-east-1:{MEMBER}:External",
        "unknown-binding": {"Fn::GetAtt": ["External", "Arn"]},
        "unapproved-invoker": FUNCTION,
    }[mode]
    template = {
        "Resources": {
            "Custom": {
                "Type": "AWS::CloudFormation::CustomResource",
                "Properties": {"ServiceToken": token},
            }
        }
    }
    data[3].responses[(MEMBER, "cloudformation", "us-east-1")][
        "list_stack_resources"
    ] = [{"StackResourceSummaries": []}]
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure):
        make_verifier(data).verify_template_inputs(stack, template, [])


@pytest.mark.parametrize("historical", [False, True])
def test_lambda_mounted_filesystems_are_unsupported_even_when_approved(historical):
    data = fixture()
    sdk = data[3].responses[(MEMBER, "lambda", "us-east-1")]
    config = {
        "FileSystemConfigs": [
            {
                "Arn": f"arn:aws:elasticfilesystem:us-east-1:{MEMBER}:access-point/external",
                "LocalMountPath": "/mnt/imports",
            }
        ]
    }
    if historical:
        sdk["list_versions_by_function"] = [{"Versions": [{**config, "Version": "17"}]}]
    else:
        sdk["get_function"]["Configuration"].update(config)
    with pytest.raises(verifier.VerificationFailure, match="filesystem inputs"):
        make_verifier(data).resource_snapshot(data[0]["resources"][0])


def add_invoker_role(data):
    caller = copy.deepcopy(data[0]["roles"][0])
    caller.update(
        {
            "id": "inference-caller",
            "arn": f"arn:aws:iam::{MEMBER}:role/ExactInferenceCaller",
            "roleId": "AROAZBCDEFGHIJKLMNOPQ",
            "purposes": ["gateway-invoker"],
            "consumerResourceIds": [],
        }
    )
    data[0]["roles"].append(caller)
    data[0]["resources"][0]["invokerIds"] = [caller["id"]]
    refresh_binding(data)
    return caller


@pytest.mark.parametrize(
    "action",
    [
        "lambda:InvokeFunction",
        "lambda:InvokeFunctionUrl",
        "lambda:UpdateFunctionCode",
        "*",
    ],
)
def test_additional_lambda_invoker_role_cannot_acquire_write_authority(action):
    data = fixture()
    caller = add_invoker_role(data)
    policy = {
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": caller["arn"]}, "Action": action}
        ]
    }
    instance = make_verifier(data)
    if action.startswith("lambda:Invoke"):
        instance.verify_resource_policy(data[0]["resources"][0], policy)
    else:
        with pytest.raises(verifier.VerificationFailure, match="controller graph"):
            instance.verify_resource_policy(data[0]["resources"][0], policy)


@pytest.mark.parametrize("mutation", ["unknown", "wrong-kind"])
def test_invalid_invoker_references_fail_before_any_aws_calls(mutation):
    data = fixture()
    resource = data[0]["resources"][0 if mutation == "unknown" else 1]
    resource["invokerIds"] = ["unknown" if mutation == "unknown" else "provider-role"]
    refresh_binding(data)
    with pytest.raises(verifier.VerificationFailure, match="invokerIds"):
        make_verifier(data)
    assert data[3].calls == []


@pytest.mark.parametrize("parent_status", ["SUCCEEDED", "FAILED", "RUNNING"])
def test_distributed_map_children_cannot_hide_behind_terminal_or_active_standard_parent(
    parent_status,
):
    data = fixture()
    resource, _, _, _, sdk = state_machine_fixture(data)
    execution = resource["arn"].replace(":stateMachine:", ":execution:") + ":map-parent"
    sdk["list_executions"] = [
        {"executions": [{"executionArn": execution, "status": parent_status}]}
    ]
    sdk["list_map_runs"] = [{"mapRuns": [{"mapRunArn": "saved-child-history"}]}]
    with pytest.raises(verifier.VerificationFailure, match="Distributed Map"):
        make_verifier(data).run()


def test_unknown_maprun_inventory_does_not_become_empty_child_history():
    data = fixture()
    resource, _, _, _, sdk = state_machine_fixture(data)
    execution = resource["arn"].replace(":stateMachine:", ":execution:") + ":succeeded"
    sdk["list_executions"] = [
        {"executions": [{"executionArn": execution, "status": "SUCCEEDED"}]}
    ]
    sdk["list_map_runs"] = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "ListMapRuns"
    )
    with pytest.raises(ClientError):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "status",
    [
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "IMPORT_COMPLETE",
        "ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
        "IMPORT_IN_PROGRESS",
    ],
)
def test_protected_cfn_snapshot_requires_an_explicit_stable_cutover_status(status):
    data = fixture()
    cfn = data[3].responses[(MEMBER, "cloudformation", "us-east-1")]
    stack = cfn["describe_stacks"]({"StackName": STACK})["Stacks"][0]
    stack["StackStatus"] = status
    instance = make_verifier(data)
    if status.endswith("_IN_PROGRESS"):
        with pytest.raises(verifier.VerificationFailure, match="quiet cutover"):
            instance.resource_snapshot(data[0]["resources"][1])
    else:
        state, _ = instance.resource_snapshot(data[0]["resources"][1])
        assert state["Stack"]["StackStatus"] == status


@pytest.mark.parametrize(
    "mode",
    ["ordinary", "administration", "execution-name", "service-managed", "unknown"],
)
def test_all_active_stacksets_inventory_stored_roles_and_reject_protected_unsupported_modes(
    mode,
):
    data = fixture()
    cfn = data[3].responses[(MEMBER, "cloudformation", "eu-west-1")]
    stack_set = {
        "PermissionModel": "SELF_MANAGED",
        "AdministrationRoleARN": f"arn:aws:iam::{MEMBER}:role/OrdinaryAdmin",
        "ExecutionRoleName": "OrdinaryExecution",
    }
    if mode == "administration":
        stack_set["AdministrationRoleARN"] = ROLE
    elif mode == "execution-name":
        stack_set["ExecutionRoleName"] = "ProtectedGatewayAdmin"
    elif mode == "service-managed":
        stack_set["PermissionModel"] = "SERVICE_MANAGED"
    elif mode == "unknown":
        stack_set.pop("ExecutionRoleName")
    cfn["list_stack_sets"] = [{"Summaries": [{"StackSetId": "OutsideNaming:id"}]}]
    cfn["describe_stack_set"] = {"StackSet": stack_set}
    if mode == "ordinary":
        assert make_verifier(data).run()["status"] == "passed"
    else:
        with pytest.raises(verifier.VerificationFailure, match="StackSet"):
            make_verifier(data).run()
    assert ("list_stack_sets", {"Status": "ACTIVE"}, "paginated") in data[3].calls


def test_declared_protected_self_managed_stackset_is_explicitly_unsupported():
    data = fixture()
    resource = add_record(
        data,
        "protected-stackset",
        "stack-set",
        f"arn:aws:cloudformation:us-east-1:{MEMBER}:stackset/declared:id",
        executionRoleArn=ROLE,
    )
    data[3].responses[(MEMBER, "cloudformation", "us-east-1")]["describe_stack_set"] = {
        "StackSet": {"PermissionModel": "SELF_MANAGED", "AdministrationRoleARN": ROLE}
    }
    refresh_binding(data)
    with pytest.raises(
        verifier.VerificationFailure, match="queued-operation authority"
    ):
        make_verifier(data).resource_snapshot(resource)


def test_cfn_snapshot_binds_generated_custom_provider_physical_resolution():
    data = fixture()
    stack = data[0]["resources"][1]
    stack["dependsOnIds"] = ["provider"]
    data[0]["resources"][0]["invokerIds"] = ["provider-role"]
    template = {
        "Resources": {
            "Custom": {
                "Type": "Custom::Provider",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": ["GeneratedLogical", "Arn"]}
                },
            }
        }
    }
    binding = {
        "LogicalResourceId": "GeneratedLogical",
        "PhysicalResourceId": FUNCTION,
        "ResourceType": "AWS::Lambda::Function",
    }
    cfn = data[3].responses[(MEMBER, "cloudformation", "us-east-1")]
    cfn["get_template"] = {"TemplateBody": template}
    cfn["list_stack_resources"] = [{"StackResourceSummaries": [binding]}]
    stack["documentSha256"] = expected_digest(template)
    stack["configurationSha256"] = expected_digest(
        {
            "Stack": cfn["describe_stacks"]({"StackName": STACK})["Stacks"][0],
            "Template": template,
            "ResourceBindings": [binding],
        }
    )
    refresh_binding(data)
    assert make_verifier(data).run()["status"] == "passed"


@pytest.mark.parametrize(
    "body,reason",
    [
        (
            "Resources:\n  X:\n    Type: AWS::S3::Bucket\n    Type: Custom::External\n",
            "duplicate template",
        ),
        (
            "Resources:\n  X:\n    Type: AWS::S3::Bucket\n    Properties:\n      Value: !Ref Unknown\n",
            "template syntax",
        ),
    ],
)
def test_ambiguous_or_unmodeled_yaml_template_semantics_fail_closed(body, reason):
    data = fixture()
    with pytest.raises(verifier.VerificationFailure, match=reason):
        make_verifier(data).verify_template_inputs(data[0]["resources"][1], body, [])


def test_macro_free_plain_yaml_template_is_supported():
    data = fixture()
    assert (
        make_verifier(data).verify_template_inputs(
            data[0]["resources"][1],
            "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n",
            [],
        )
        == []
    )


def test_literal_lambda_target_schema_can_use_actual_transitive_protected_s3_input():
    data = fixture()
    resource, gateway = gateway_fixture(data, "lambda")
    add_s3_source(data, resource)
    gateway["Targets"][0]["targetConfiguration"]["mcp"]["lambda"]["toolSchema"] = {
        "s3": {
            "uri": "s3://ci-protected-source/source.zip",
            "bucketOwnerAccountId": MEMBER,
        }
    }
    refresh_binding(data)
    make_verifier(data).verify_gateway_inputs(resource, gateway)


def ordinary_stack_change_set_fixture(data, status, execution_status):
    """The retained role is intentionally absent from AWS read metadata."""
    sdk = data[3].responses[(MEMBER, "cloudformation", "eu-west-1")]
    stack = {
        "StackId": f"arn:aws:cloudformation:eu-west-1:{MEMBER}:stack/OrdinaryOutsideNaming/old",
        "StackName": "OrdinaryOutsideNaming",
        "RoleARN": f"arn:aws:iam::{MEMBER}:role/Ordinary",
        "StackStatus": "CREATE_COMPLETE",
    }
    identity = (
        f"arn:aws:cloudformation:eu-west-1:{MEMBER}:changeSet/StoredOldAuthority/old"
    )
    summary = {
        "ChangeSetId": identity,
        "StackId": stack["StackId"],
        "Status": status,
        "ExecutionStatus": execution_status,
    }
    sdk["describe_stacks"] = [{"Stacks": [stack]}]
    sdk["list_change_sets"] = [{"Summaries": [summary]}]
    sdk["describe_change_set"] = dict(summary)
    return sdk, stack, summary


def test_available_change_set_cannot_hide_retained_role_under_an_ordinary_current_stack():
    data = fixture()
    _, stack, summary = ordinary_stack_change_set_fixture(
        data, "CREATE_COMPLETE", "AVAILABLE"
    )
    model = service_model("cloudformation")
    assert "RoleARN" in model.operation_model("CreateChangeSet").input_shape.members
    assert (
        "RoleARN" not in model.operation_model("DescribeChangeSet").output_shape.members
    )
    assert (
        "RoleARN" not in model.operation_model("ExecuteChangeSet").input_shape.members
    )
    assert stack["RoleARN"] != ROLE and "RoleARN" not in summary
    with pytest.raises(verifier.VerificationFailure, match="change-set authority"):
        make_verifier(data).run()
    assert ("list_change_sets", {"StackName": stack["StackId"]}, "paginated") in data[
        3
    ].calls


@pytest.mark.parametrize(
    "status,execution_status",
    [
        ("CREATE_PENDING", "UNAVAILABLE"),
        ("CREATE_IN_PROGRESS", "UNAVAILABLE"),
        ("DELETE_PENDING", "UNAVAILABLE"),
        ("DELETE_IN_PROGRESS", "UNAVAILABLE"),
        ("CREATE_COMPLETE", "EXECUTE_IN_PROGRESS"),
        ("CREATE_COMPLETE", "EXECUTE_FAILED"),
        ("FAILED", "AVAILABLE"),
        ("DELETE_FAILED", "UNAVAILABLE"),
        (None, "UNAVAILABLE"),
        ("CREATE_COMPLETE", None),
        ("UNKNOWN", "OBSOLETE"),
        ("CREATE_COMPLETE", "UNKNOWN"),
    ],
)
def test_pending_in_progress_failed_execution_and_unknown_changeset_authority_fail_closed(
    status, execution_status
):
    data = fixture()
    ordinary_stack_change_set_fixture(data, status, execution_status)
    with pytest.raises(verifier.VerificationFailure, match="change-set authority"):
        make_verifier(data).run()


@pytest.mark.parametrize(
    "status,execution_status",
    [
        ("FAILED", "UNAVAILABLE"),
        ("DELETE_COMPLETE", "UNAVAILABLE"),
        ("CREATE_COMPLETE", "EXECUTE_COMPLETE"),
        ("CREATE_COMPLETE", "OBSOLETE"),
    ],
)
def test_proven_terminal_nonexecutable_changesets_preserve_ordinary_stacks(
    status, execution_status
):
    data = fixture()
    _, stack, summary = ordinary_stack_change_set_fixture(
        data, status, execution_status
    )
    assert make_verifier(data).run()["status"] == "passed"
    assert (
        "describe_change_set",
        {
            "ChangeSetName": summary["ChangeSetId"],
            "StackName": stack["StackId"],
            "IncludePropertyValues": False,
        },
        "direct",
    ) in data[3].calls


def test_ordinary_and_protected_stacks_with_no_changesets_remain_supported():
    data = fixture()
    sdk, ordinary, _ = ordinary_stack_change_set_fixture(
        data, "CREATE_COMPLETE", "AVAILABLE"
    )
    sdk["list_change_sets"] = [{"Summaries": []}]
    assert make_verifier(data).run()["status"] == "passed"
    queried = {
        args["StackName"]
        for operation, args, _ in data[3].calls
        if operation == "list_change_sets"
    }
    assert queried == {STACK, ordinary["StackId"]}


@pytest.mark.parametrize("mutation", ["status", "missing-status", "identity", "stack"])
def test_terminal_changeset_summary_is_confirmed_against_bound_current_metadata(
    mutation,
):
    data = fixture()
    sdk, _, _ = ordinary_stack_change_set_fixture(data, "CREATE_COMPLETE", "OBSOLETE")
    saved = sdk["describe_change_set"]
    if mutation == "status":
        saved["ExecutionStatus"] = "AVAILABLE"
    elif mutation == "missing-status":
        saved.pop("Status")
    elif mutation == "identity":
        saved["ChangeSetId"] += "Different"
    else:
        saved["StackId"] = STACK
    with pytest.raises(verifier.VerificationFailure, match="change-set authority"):
        make_verifier(data).run()


@pytest.mark.parametrize("operation", ["list_change_sets", "describe_change_set"])
def test_unreadable_changeset_inventory_is_not_a_quiet_cutover_proof(operation):
    data = fixture()
    sdk, _, _ = ordinary_stack_change_set_fixture(data, "FAILED", "UNAVAILABLE")
    sdk[operation] = ClientError({"Error": {"Code": "AccessDenied"}}, operation)
    with pytest.raises(ClientError):
        make_verifier(data).run()


def test_changeset_sdk_paginator_checks_every_page_before_accepting_ordinary_stack():
    data = fixture()
    sdk, _, summary = ordinary_stack_change_set_fixture(data, "FAILED", "UNAVAILABLE")
    sdk["list_change_sets"] = [
        {"Summaries": [summary]},
        {
            "Summaries": [
                {
                    **summary,
                    "ChangeSetId": summary["ChangeSetId"] + "Second",
                    "Status": "CREATE_COMPLETE",
                    "ExecutionStatus": "AVAILABLE",
                }
            ]
        },
    ]
    with pytest.raises(verifier.VerificationFailure, match="change-set authority"):
        make_verifier(data).run()
