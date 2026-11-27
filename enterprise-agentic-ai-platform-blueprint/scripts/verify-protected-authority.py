#!/usr/bin/env python3
"""Read-only verification of an approved protected-authority manifest.

Requires explicit account profiles and installed SCP expectations. It never
updates a manifest or calls a write API. Missing permissions, unknown consumers,
configuration drift and incomplete regional inventory fail verification.

JSON document hashes use sorted object keys, original array order, compact
UTF-8 JSON and no NaN values. Resource configuration hashes cover the complete
service-specific read snapshot below, excluding request metadata and temporary
Lambda download URLs. S3 object document hashes cover the actual object bytes.
No trust documents, environment values, secret values or asset bytes are emitted.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import boto3
import yaml
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.paginate import Paginator

CONFIG = Config(
    connect_timeout=5,
    read_timeout=20,
    retries={"total_max_attempts": 3, "mode": "standard"},
    ignore_configured_endpoint_urls=True,
)
ACCOUNT = re.compile(r"^\d{12}$")
ROLE_ID = re.compile(r"^AROA[A-Z0-9]{17}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
AUTHORITY_POLICY_NAME = re.compile(
    r"^AgenticAI-ProtectedAuthority-(\d{12})-([1-9]\d*)$"
)
SDK_PAGINATION_CONTRACTS = {
    "list_state_machine_versions": (
        "stepfunctions",
        "ListStateMachineVersions",
        "stateMachineVersions",
    ),
    "list_state_machine_aliases": (
        "stepfunctions",
        "ListStateMachineAliases",
        "stateMachineAliases",
    ),
    "list_fleets": ("codebuild", "ListFleets", "fleets"),
    "list_policies": ("bedrock-agentcore-control", "ListPolicies", "policies"),
}
MAX_OBJECT_BYTES = 512 * 1024 * 1024
REGIONAL_SERVICES = (
    "cloudformation",
    "lambda",
    "codebuild",
    "codepipeline",
    "stepfunctions",
    "bedrock-agentcore-control",
    "bedrock-agentcore",
)
AGENTCORE_DIRECT_CONSUMERS = (
    (
        "list_memories",
        "memories",
        "get_memory",
        "id",
        "memoryId",
        ("memory", "memoryExecutionRoleArn"),
    ),
    (
        "list_online_evaluation_configs",
        "onlineEvaluationConfigs",
        "get_online_evaluation_config",
        "onlineEvaluationConfigId",
        "onlineEvaluationConfigId",
        ("evaluationExecutionRoleArn",),
    ),
    (
        "list_capacity_providers",
        "capacityProviders",
        "get_capacity_provider",
        "capacityProviderId",
        "capacityProviderId",
        ("permissionsConfiguration", "capacityProviderOperatorRoleArn"),
    ),
    (
        "list_consent_portals",
        "consentPortals",
        "get_consent_portal",
        "consentPortalId",
        "consentPortalIdentifier",
        ("executionRoleArn",),
    ),
    (
        "list_payment_managers",
        "paymentManagers",
        "get_payment_manager",
        "paymentManagerId",
        "paymentManagerId",
        ("roleArn",),
    ),
)
AGENTCORE_ROLE_READ_OPERATIONS = frozenset(
    {
        "GetAgentRuntime",
        "GetBrowser",
        "GetCodeInterpreter",
        "GetCapacityProvider",
        "GetConsentPortal",
        "GetGateway",
        "GetHarness",
        "GetMemory",
        "GetOnlineEvaluationConfig",
        "GetPaymentManager",
        "GetRegistryRecord",
        "ListPaymentManagers",
    }
)
GLOBAL_REGION_EXEMPTIONS = {
    "iam:*",
    "sts:*",
    "organizations:*",
    "support:*",
    "budgets:*",
    "ce:*",
    "cur:*",
    "route53:*",
    "cloudfront:*",
    "waf:*",
    "wafv2:*",
    "globalaccelerator:*",
    "a4b:*",
    "aws-portal:*",
    "artifact:*",
    "health:*",
    "importexport:*",
}


class VerificationFailure(ValueError):
    """An observed state cannot establish the approved authority boundary."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise VerificationFailure(reason)


class TemplateLoader(yaml.SafeLoader):
    """Reject duplicate template keys and unknown intrinsic YAML tags."""


def template_mapping(loader: TemplateLoader, node: Any) -> dict[str, Any]:
    pairs = loader.construct_pairs(node)
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate template keys are forbidden")
        result[key] = value
    return result


TemplateLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, template_mapping
)


def normalise(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalise(item)
            for key, item in value.items()
            if key != "ResponseMetadata"
        }
    if isinstance(value, list):
        return [normalise(item) for item in value]
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    return value


def document(value: Any) -> Any:
    if isinstance(value, str):
        for candidate in (value, unquote(value)):
            try:
                return json.loads(candidate, object_pairs_hook=_unique_json)
            except json.JSONDecodeError:
                pass
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            normalise(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def arn_parts(arn: str) -> list[str]:
    parts = arn.split(":", 5)
    require(
        len(parts) == 6 and parts[0] == "arn" and parts[1] == "aws",
        "an exact commercial-partition ARN is required",
    )
    require(
        "*" not in arn and "?" not in arn, "wildcard resource identities are forbidden"
    )
    return parts


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON keys are forbidden")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    result = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json
    )
    require(isinstance(result, dict), "input must be a JSON object")
    return result


def values(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


class Verifier:
    def __init__(
        self,
        manifest: dict[str, Any],
        profiles: dict[str, str],
        expected: dict[str, Any],
        session_factory: Callable[..., Any] = boto3.Session,
    ) -> None:
        self.manifest, self.expected = manifest, expected
        self.profiles, self.session_factory = profiles, session_factory
        self.sessions: dict[str, Any] = {}
        self.clients: dict[tuple[str, str, str], Any] = {}
        self.checks: list[str] = []
        self.regions: dict[str, list[str]] = {}
        self.region_denies: dict[str, list[dict[str, Any]]] = {}
        self.discovery_anchors: dict[str, dict[str, Any]] = {}
        self._validate()
        self.roles = {role["id"]: role for role in manifest["roles"]}
        self.resources = {
            resource["id"]: resource for resource in manifest["resources"]
        }
        self.role_arns = {role["arn"] for role in manifest["roles"]}

    def _validate(self) -> None:
        m = self.manifest
        require(m.get("schemaVersion") == 1, "unsupported manifest schema")
        require(
            re.fullmatch(r"o-[a-z0-9]{10,32}", m.get("organizationId", "")) is not None,
            "organization ID is required",
        )
        require(
            ACCOUNT.fullmatch(m.get("managementAccountId", "")) is not None,
            "management account ID is required",
        )
        require(
            isinstance(m.get("epoch"), str) and bool(m["epoch"]),
            "manifest epoch is required",
        )
        for field in ("trustedControlAccountIds", "governedAccountIds"):
            values = m.get(field)
            require(
                isinstance(values, list)
                and (field != "governedAccountIds" or bool(values)),
                f"{field} must be a list and governed accounts must be nonempty",
            )
            require(
                all(
                    isinstance(value, str) and ACCOUNT.fullmatch(value)
                    for value in values
                ),
                f"{field} contains an invalid account",
            )
            require(
                len(values) == len(set(values)), f"{field} contains duplicate accounts"
            )
        require(
            not set(m["trustedControlAccountIds"]) & set(m["governedAccountIds"]),
            "trusted control and governed accounts must be disjoint",
        )
        require(
            m["managementAccountId"] not in m["governedAccountIds"],
            "the management account cannot be a governed member",
        )
        accounts = set(m["trustedControlAccountIds"] + m["governedAccountIds"])
        accounts.add(m["managementAccountId"])
        require(
            set(self.profiles) == accounts,
            "provide one explicit profile for every declared account",
        )
        require(
            all(
                isinstance(value, str) and value.strip()
                for value in self.profiles.values()
            ),
            "profile names must be explicit nonempty strings",
        )
        ids: set[str] = set()
        for field in ("roles", "resources"):
            require(isinstance(m.get(field), list), f"{field} must be a list")
            for item in m[field]:
                require(
                    isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                    and item["id"],
                    f"{field} requires nonempty record IDs",
                )
                require(item["id"] not in ids, "record IDs must be globally unique")
                ids.add(item["id"])
                parts = arn_parts(item.get("arn", ""))
                account = item.get("accountId", parts[4])
                require(
                    account in accounts,
                    "resource account is outside the declared scope",
                )
                if field == "roles":
                    require(
                        parts[2] == "iam" and parts[5].startswith("role/"),
                        "role records require IAM role ARNs",
                    )
                    require(
                        ROLE_ID.fullmatch(item.get("roleId", "")) is not None,
                        "role records require a live immutable RoleId",
                    )
                    require(
                        SHA256.fullmatch(item.get("trustPolicySha256", "")) is not None,
                        "approved role trust digest is required",
                    )
                    require(
                        isinstance(item.get("inlinePolicySha256"), dict),
                        "complete inline-policy digests are required",
                    )
                    require(
                        all(
                            SHA256.fullmatch(value)
                            for value in item["inlinePolicySha256"].values()
                        ),
                        "inline-policy digests must be SHA-256",
                    )
                    require(
                        isinstance(item.get("attachedPolicyArns"), list),
                        "complete attached-policy ARNs are required",
                    )
                else:
                    require(
                        item.get("kind") == "policy"
                        or SHA256.fullmatch(item.get("configurationSha256", ""))
                        is not None,
                        "every configuration-bearing resource needs an approved digest",
                    )
        for role in m["roles"]:
            for field in (
                "lifecycleControllerIds",
                "policyResourceIds",
                "consumerResourceIds",
            ):
                require(isinstance(role.get(field), list), f"role {field} is required")
                require(
                    all(value in ids for value in role[field]),
                    f"role {field} contains an unknown reference",
                )
        for resource in m["resources"]:
            for field in ("controllerIds", "dependsOnIds"):
                require(
                    isinstance(resource.get(field), list),
                    f"resource {field} is required",
                )
                require(
                    all(value in ids for value in resource[field]),
                    f"resource {field} contains an unknown reference",
                )
            if "invokerIds" in resource:
                require(
                    isinstance(resource["invokerIds"], list)
                    and resource["kind"] in {"lambda", "gateway"}
                    and all(
                        value in {role["id"] for role in m["roles"]}
                        for value in resource["invokerIds"]
                    ),
                    "resource invokerIds contains an unknown reference",
                )
        require(
            self.expected.get("manifestSha256") == digest(m),
            "installed-policy expectations must bind the exact canonical manifest",
        )
        require(
            isinstance(self.expected.get("policies"), list)
            and self.expected["policies"],
            "installed protection policy expectations are required",
        )

    def client(self, account: str, service: str, region: str = "us-east-1") -> Any:
        key = (account, service, region)
        if key not in self.clients:
            if account not in self.sessions:
                self.sessions[account] = self.session_factory(
                    profile_name=self.profiles[account],
                    region_name="us-east-1",
                )
                sts = self.sessions[account].client(
                    "sts", region_name="us-east-1", config=CONFIG
                )
                require(
                    sts.get_caller_identity()["Account"] == account,
                    "an explicit profile resolves to the wrong account",
                )
            self.clients[key] = self.sessions[account].client(
                service, region_name=region, config=CONFIG
            )
        return self.clients[key]

    @staticmethod
    def pages(client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
        if client.can_paginate(operation):
            paginator = client.get_paginator(operation)
        else:
            # These paginated API operations currently lack a bundled
            # boto3 paginator. Use botocore's SDK paginator with the exact
            # operation-model-checked contract; never loop tokens manually.
            contract = SDK_PAGINATION_CONTRACTS.get(operation)
            require(
                contract is not None and contract[2] == key,
                f"{operation} must support complete SDK pagination",
            )
            require(
                client.meta.service_model.service_name == contract[0],
                f"{operation}: unsupported pagination service contract",
            )
            model = client.meta.service_model.operation_model(contract[1])
            require(
                {"nextToken", "maxResults"} <= set(model.input_shape.members)
                and {"nextToken", key} <= set(model.output_shape.members),
                f"{operation}: SDK pagination contract differs",
            )
            paginator = Paginator(
                getattr(client, operation),
                {
                    "input_token": "nextToken",
                    "output_token": "nextToken",
                    "limit_key": "maxResults",
                    "result_key": key,
                },
                model,
            )
        return [
            item for page in paginator.paginate(**kwargs) for item in page.get(key, [])
        ]

    def optional(self, client: Any, operation: str, missing: str, **kwargs: Any) -> Any:
        missing_type = getattr(client.exceptions, missing, None)
        if missing_type is None:
            # Some S3 absence errors have no modeled SDK exception. They
            # propagate as an incomplete inventory rather than becoming an
            # assumed empty policy.
            return getattr(client, operation)(**kwargs)
        try:
            return getattr(client, operation)(**kwargs)
        except missing_type:
            return {}

    def verify_resource_policy(self, resource: dict[str, Any], policy: Any) -> None:
        """Reject positive grants that can reach protected inputs outside SCPs."""
        parsed = document(policy)
        require(
            isinstance(parsed, dict), f"{resource['id']}: resource policy is unreadable"
        )
        controller_roles = {
            self.roles[identity]["arn"] for identity in resource["controllerIds"]
        }
        controller_roles.add(resource.get("executionRoleArn", ""))
        invoker_roles = (
            {
                self.roles[identity]["arn"]
                for identity in resource.get("invokerIds", resource["controllerIds"])
            }
            if resource["kind"] in {"lambda", "gateway"}
            else set()
        )
        dependencies = [
            self.resources[identity] for identity in resource["dependsOnIds"]
        ]
        sources = {item["arn"] for item in dependencies}
        accounts = {
            arn_parts(item["arn"])[4] or item.get("accountId") for item in dependencies
        }
        governed = set(self.manifest["governedAccountIds"])
        for statement in values(parsed.get("Statement", [])):
            require(
                isinstance(statement, dict),
                f"{resource['id']}: invalid policy statement",
            )
            if statement.get("Effect") == "Deny":
                continue
            require(
                statement.get("Effect") == "Allow" and "NotPrincipal" not in statement,
                f"{resource['id']}: unsupported positive policy",
            )
            principal = statement.get("Principal")
            actions = values(statement.get("Action", []))
            invocation_only = (
                resource["kind"] == "lambda"
                and "NotAction" not in statement
                and bool(actions)
                and all(
                    isinstance(action, str)
                    and action.lower()
                    in {"lambda:invokefunction", "lambda:invokefunctionurl"}
                    for action in actions
                )
            )
            allowed_roles = controller_roles | (
                invoker_roles if invocation_only else set()
            )
            conditions = statement.get("Condition", {})
            exact = conditions.get("ArnEquals", {}).get("aws:PrincipalArn")
            if (
                principal == "*"
                or isinstance(principal, dict)
                and principal.get("AWS") == "*"
            ):
                require(
                    bool(exact) and set(values(exact)) <= allowed_roles,
                    f"{resource['id']}: wildcard positive resource grant",
                )
                continue
            require(
                isinstance(principal, dict),
                f"{resource['id']}: unsupported resource principal",
            )
            if "Service" in principal:
                require(
                    set(principal) == {"Service"},
                    f"{resource['id']}: mixed service resource principal",
                )
                source_accounts = conditions.get("StringEquals", {}).get(
                    "aws:SourceAccount"
                )
                source_arns = conditions.get("ArnEquals", {}).get(
                    "aws:SourceArn"
                ) or conditions.get("StringEquals", {}).get("aws:SourceArn")
                require(
                    bool(source_accounts)
                    and bool(source_arns)
                    and set(values(source_accounts)) <= accounts
                    and set(values(source_arns)) <= sources,
                    f"{resource['id']}: an AWS service grant lacks exact protected source constraints",
                )
                continue
            require(
                set(principal) == {"AWS"},
                f"{resource['id']}: unsupported resource principal type",
            )
            for identity in values(principal["AWS"]):
                if identity in allowed_roles:
                    continue
                match = re.fullmatch(r"arn:aws:iam::(\d{12}):root", identity)
                require(
                    bool(match)
                    and match[1] in governed
                    and resource["kind"] in {"kms", "s3-bucket"},
                    f"{resource['id']}: external positive resource grant is outside the controller graph",
                )
                # Same-account IAM delegation remains bounded by the installed
                # member SCP. Cross-account roots are deliberately not inferred.
                owner = resource.get("accountId", arn_parts(resource["arn"])[4])
                require(
                    match[1] == owner, f"{resource['id']}: foreign account root grant"
                )

    def verify_role_trust(self, role: dict[str, Any], trust: Any) -> None:
        parsed = document(trust)
        require(isinstance(parsed, dict), f"{role['id']}: role trust is unreadable")
        allowed = {
            self.roles[identity]["arn"] for identity in role["lifecycleControllerIds"]
        }
        roots = set(self.manifest["trustedControlAccountIds"]) | {
            self.manifest["managementAccountId"]
        }
        consumers = [
            self.resources[identity] for identity in role["consumerResourceIds"]
        ]
        services = {
            "lambda": "lambda.amazonaws.com",
            "gateway": "bedrock-agentcore.amazonaws.com",
            "build": "codebuild.amazonaws.com",
            "pipeline": "codepipeline.amazonaws.com",
            "stack": "cloudformation.amazonaws.com",
            "state-machine": "states.amazonaws.com",
        }
        permitted_services = {
            services[item["kind"]] for item in consumers if item["kind"] in services
        }
        for statement in values(parsed.get("Statement", [])):
            if statement.get("Effect") == "Deny":
                continue
            require(
                statement.get("Effect") == "Allow" and "NotPrincipal" not in statement,
                f"{role['id']}: unsupported positive trust policy",
            )
            principal = statement.get("Principal")
            require(isinstance(principal, dict), f"{role['id']}: wildcard role trust")
            if set(principal) == {"Service"}:
                require(
                    set(values(principal["Service"])) <= permitted_services,
                    f"{role['id']}: service trust lacks a protected consumer",
                )
            elif set(principal) == {"AWS"}:
                for identity in values(principal["AWS"]):
                    root = re.fullmatch(r"arn:aws:iam::(\d{12}):root", identity)
                    require(
                        identity in allowed or bool(root) and root[1] in roots,
                        f"{role['id']}: unapproved trust delegation",
                    )
            else:
                raise VerificationFailure(
                    f"{role['id']}: unapproved trust principal type"
                )

    @staticmethod
    def verify_acl(resource: dict[str, Any], acl: dict[str, Any]) -> None:
        owner = acl.get("Owner", {}).get("ID")
        require(bool(owner), f"{resource['id']}: ACL owner is unknown")
        for grant in acl.get("Grants", []):
            if grant.get("Permission") in {"WRITE", "WRITE_ACP", "FULL_CONTROL"}:
                require(
                    grant.get("Grantee", {}).get("Type") == "CanonicalUser"
                    and grant["Grantee"].get("ID") == owner,
                    f"{resource['id']}: external ACL write grant",
                )

    def verify_roles(self) -> None:
        for role in self.roles.values():
            iam = self.client(arn_parts(role["arn"])[4], "iam")
            name = role["arn"].split("/")[-1]
            observed = iam.get_role(RoleName=name)["Role"]
            require(
                observed["Arn"] == role["arn"] and observed["RoleId"] == role["roleId"],
                f"{role['id']}: role entity differs or was recreated",
            )
            require(
                digest(document(observed["AssumeRolePolicyDocument"]))
                == role["trustPolicySha256"],
                f"{role['id']}: trust policy differs",
            )
            self.verify_role_trust(role, observed["AssumeRolePolicyDocument"])
            names = self.pages(iam, "list_role_policies", "PolicyNames", RoleName=name)
            inline = {
                policy_name: digest(
                    document(
                        iam.get_role_policy(
                            RoleName=name,
                            PolicyName=policy_name,
                        )["PolicyDocument"]
                    )
                )
                for policy_name in names
            }
            require(
                inline == role["inlinePolicySha256"],
                f"{role['id']}: inline policy set differs",
            )
            attached = self.pages(
                iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name
            )
            require(
                sorted(item["PolicyArn"] for item in attached)
                == sorted(role["attachedPolicyArns"]),
                f"{role['id']}: attached policy set differs",
            )
            boundary = observed.get("PermissionsBoundary", {}).get(
                "PermissionsBoundaryArn"
            )
            require(
                boundary == role.get("permissionsBoundaryArn"),
                f"{role['id']}: boundary differs",
            )
            records = [
                self.resources[identity] for identity in role["policyResourceIds"]
            ]
            custom = {
                value
                for value in role["attachedPolicyArns"]
                + ([boundary] if boundary else [])
                if arn_parts(value)[4] != "aws"
            }
            require(
                custom
                <= {record["arn"] for record in records if record["kind"] == "policy"},
                f"{role['id']}: customer-managed policies are not protected",
            )
            require(
                not self.pages(
                    iam,
                    "list_instance_profiles_for_role",
                    "InstanceProfiles",
                    RoleName=name,
                ),
                f"{role['id']}: unsupported instance-profile execution consumer",
            )
            self.checks.append(f"role:{role['id']}")

    def regional_anchor(self, account: str) -> str:
        proofs = self.region_denies.get(account, [])
        if not proofs:
            return "us-east-1"
        allowed = set(proofs[0]["allowedRegions"])
        for proof in proofs[1:]:
            allowed &= set(proof["allowedRegions"])
        require(
            bool(allowed), "verified Region deny policies have no usable intersection"
        )
        return next(
            region
            for proof in proofs
            for region in proof["allowedRegions"]
            if region in allowed
        )

    def dependencies(self, resource: dict[str, Any]) -> list[dict[str, Any]]:
        pending = list(resource["dependsOnIds"])
        visited: set[str] = set()
        result: list[dict[str, Any]] = []
        while pending:
            identity = pending.pop()
            if identity in visited:
                continue
            visited.add(identity)
            dependency = self.resources[identity]
            result.append(dependency)
            pending.extend(dependency["dependsOnIds"])
        return result

    def protected_s3_bucket(
        self, resource: dict[str, Any], bucket: str
    ) -> dict[str, Any]:
        matches = [
            value
            for value in self.dependencies(resource)
            if value["kind"] == "s3-bucket" and value["arn"] == f"arn:aws:s3:::{bucket}"
        ]
        require(
            len(matches) == 1,
            f"{resource['id']}: artifact storage has no exact protected bucket dependency",
        )
        return matches[0]

    def protected_s3_input(
        self, resource: dict[str, Any], bucket: str, key: str
    ) -> None:
        dependencies = self.dependencies(resource)
        objects = [
            value
            for value in dependencies
            if value["kind"] == "s3-object"
            and value["arn"] == f"arn:aws:s3:::{bucket}/{key}"
        ]
        require(
            bool(bucket) and bool(key) and len(objects) == 1,
            f"{resource['id']}: S3 input is not an exact protected source object",
        )
        obj = objects[0]
        owner = self.protected_s3_bucket(resource, bucket).get("accountId")
        require(
            owner == obj.get("accountId"),
            f"{resource['id']}: S3 input has no matching protected bucket dependency",
        )

    def protected_ecr_input(
        self, resource: dict[str, Any], account: str, region: str, repository: str
    ) -> None:
        require(
            any(
                value["kind"] == "ecr"
                and value["arn"]
                == f"arn:aws:ecr:{region}:{account}:repository/{repository}"
                for value in self.dependencies(resource)
            ),
            f"{resource['id']}: image or repository input is outside the protected graph",
        )

    def verify_build_inputs(
        self, resource: dict[str, Any], project: dict[str, Any]
    ) -> None:
        """Support only inputs whose AWS mutation authority is in the manifest."""
        require(
            not project.get("webhook"),
            f"{resource['id']}: external build webhook authority is unsupported",
        )
        require(
            project.get("projectVisibility", "PRIVATE") == "PRIVATE"
            and not project.get("resourceAccessRole")
            and not project.get("publicProjectAlias"),
            f"{resource['id']}: public project or resource-access role authority is unsupported",
        )
        require(
            not project.get("buildBatchConfig"),
            f"{resource['id']}: batch build execution is unsupported",
        )
        sources = [project.get("source", {})] + project.get("secondarySources", [])
        for source in sources:
            source_type = source.get("type")
            require(
                source_type in {"NO_SOURCE", "S3", "CODEPIPELINE"},
                f"{resource['id']}: external or unsupported build source",
            )
            require(
                not source.get("auth"),
                f"{resource['id']}: build source authentication is outside the protected graph",
            )
            if source_type in {"NO_SOURCE", "CODEPIPELINE"}:
                require(
                    not source.get("location"),
                    f"{resource['id']}: build has an external location",
                )
                if source_type == "CODEPIPELINE":
                    self.verify_build_pipeline_authority(resource)
            else:
                bucket, separator, key = source.get("location", "").partition("/")
                require(
                    bool(separator), f"{resource['id']}: invalid S3 source location"
                )
                self.protected_s3_input(resource, bucket, key)
        buildspec = project.get("source", {}).get("buildspec")
        require(
            isinstance(buildspec, str),
            f"{resource['id']}: approved inline buildspec is required",
        )
        try:
            parsed_buildspec = yaml.safe_load(buildspec)
        except yaml.YAMLError as error:
            raise VerificationFailure(
                f"{resource['id']}: inline buildspec is not supported YAML or JSON"
            ) from error
        require(
            isinstance(parsed_buildspec, dict)
            and str(parsed_buildspec.get("version")) in {"0.1", "0.2"}
            and isinstance(parsed_buildspec.get("phases"), dict),
            f"{resource['id']}: approved inline buildspec is required",
        )
        require(
            "batch" not in parsed_buildspec,
            f"{resource['id']}: inline batch build configuration is unsupported",
        )
        for field, kind in [("parameter-store", "ssm"), ("secrets-manager", "secret")]:
            for value in parsed_buildspec.get("env", {}).get(field, {}).values():
                require(
                    any(
                        dependency["kind"] == kind and dependency["arn"] == value
                        for dependency in self.dependencies(resource)
                    ),
                    f"{resource['id']}: inline dynamic environment input is outside the protected graph",
                )
        require(
            project.get("cache", {}).get("type", "NO_CACHE") == "NO_CACHE",
            f"{resource['id']}: external build cache inputs are unsupported",
        )
        require(
            not project.get("fileSystemLocations"),
            f"{resource['id']}: external build filesystem inputs are unsupported",
        )
        for artifact in [project.get("artifacts", {})] + project.get(
            "secondaryArtifacts", []
        ):
            artifact_type = artifact.get("type")
            if artifact_type == "NO_ARTIFACTS":
                continue
            if artifact_type == "CODEPIPELINE":
                self.verify_build_pipeline_authority(resource)
                continue
            require(
                artifact_type == "S3",
                f"{resource['id']}: unsupported build artifact authority",
            )
            self.protected_s3_bucket(resource, artifact.get("location", ""))
            require(
                not artifact.get("encryptionDisabled"),
                f"{resource['id']}: unencrypted build artifact output is unsupported",
            )
        environment = project.get("environment", {})
        require(
            not environment.get("fleet"),
            f"{resource['id']}: external fleet build configuration is unsupported",
        )
        require(
            not environment.get("registryCredential"),
            f"{resource['id']}: external image registry credentials are unsupported",
        )
        image = environment.get("image", "")
        managed = re.fullmatch(
            r"aws/codebuild/(standard|amazonlinux2-x86_64-standard|"
            r"amazonlinux2-aarch64-standard|amazonlinux-x86_64-standard|"
            r"amazonlinux-aarch64-standard):\d+\.\d+",
            image,
        )
        if not managed:
            match = re.fullmatch(
                r"(\d{12})\.dkr\.ecr\.([a-z]{2}(?:-[a-z0-9]+)+-\d+)"
                r"\.amazonaws\.com/([a-z0-9][a-z0-9._/-]*)"
                r"(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})?",
                image,
            )
            require(
                match is not None,
                f"{resource['id']}: build image is neither an approved AWS curated image nor protected ECR",
            )
            self.protected_ecr_input(resource, match[1], match[2], match[3])
        for variable in environment.get("environmentVariables", []):
            variable_type = variable.get("type", "PLAINTEXT")
            if variable_type == "PLAINTEXT":
                continue
            required_kind = {
                "PARAMETER_STORE": "ssm",
                "SECRETS_MANAGER": "secret",
            }.get(variable_type)
            require(
                required_kind is not None
                and any(
                    value["kind"] == required_kind
                    and value["arn"] == variable.get("value")
                    for value in self.dependencies(resource)
                ),
                f"{resource['id']}: dynamic build environment input is outside the protected graph",
            )

    def verify_build_pipeline_authority(self, resource: dict[str, Any]) -> None:
        controllers = {self.roles[value]["arn"] for value in resource["controllerIds"]}
        candidates = [
            value
            for value in self.resources.values()
            if value["kind"] == "pipeline"
            and value.get("executionRoleArn") in controllers
            and resource["id"]
            in {dependency["id"] for dependency in self.dependencies(value)}
        ]
        confirmed = False
        for pipeline_resource in candidates:
            parts = arn_parts(pipeline_resource["arn"])
            pipeline = self.client(parts[4], "codepipeline", parts[3]).get_pipeline(
                name=parts[5]
            )["pipeline"]
            require(
                pipeline["roleArn"] == pipeline_resource.get("executionRoleArn")
                and digest(pipeline) == pipeline_resource["configurationSha256"],
                f"{resource['id']}: upstream pipeline role or approved configuration differs",
            )
            self.verify_pipeline_inputs(pipeline_resource, pipeline)
            project = arn_parts(resource["arn"])[5].split("/", 1)[-1]
            confirmed |= any(
                action.get("actionTypeId", {}).get("category") == "Build"
                and action.get("actionTypeId", {}).get("provider") == "CodeBuild"
                and action.get("configuration", {}).get("ProjectName") == project
                and parts[3:5] == arn_parts(resource["arn"])[3:5]
                for stage in pipeline.get("stages", [])
                for action in stage.get("actions", [])
            )
        require(
            confirmed,
            f"{resource['id']}: CODEPIPELINE source or artifacts lack an actual protected pipeline controller",
        )

    def verify_pipeline_inputs(
        self, resource: dict[str, Any], pipeline: dict[str, Any]
    ) -> None:
        parts = arn_parts(resource["arn"])
        source_count = 0
        stages = pipeline.get("stages", [])
        require(bool(stages), f"{resource['id']}: pipeline action inventory is empty")
        stores = pipeline.get("artifactStores", {})
        if pipeline.get("artifactStore"):
            require(not stores, f"{resource['id']}: ambiguous pipeline artifact stores")
            stores = {parts[3]: pipeline["artifactStore"]}
        require(
            isinstance(stores, dict) and bool(stores),
            f"{resource['id']}: pipeline artifact store inventory is required",
        )
        for store_region, store in stores.items():
            require(
                store.get("type") == "S3",
                f"{resource['id']}: unsupported pipeline artifact store",
            )
            bucket = self.protected_s3_bucket(resource, store.get("location", ""))
            require(
                bucket.get("accountId") == parts[4],
                f"{resource['id']}: cross-account artifact storage is unsupported",
            )
            encryption = store.get("encryptionKey", {})
            require(
                encryption.get("type") == "KMS"
                and any(
                    dependency["kind"] == "kms"
                    and dependency["arn"] == encryption.get("id")
                    and arn_parts(dependency["arn"])[3] == store_region
                    for dependency in self.dependencies(resource)
                ),
                f"{resource['id']}: pipeline artifact encryption lacks an exact protected KMS key",
            )
        for stage in stages:
            for action in stage.get("actions", []):
                require(
                    action.get("roleArn", pipeline["roleArn"]) == pipeline["roleArn"],
                    f"{resource['id']}: mixed pipeline action execution roles are unsupported",
                )
                require(
                    action.get("region", parts[3]) == parts[3],
                    f"{resource['id']}: cross-region pipeline actions are unsupported",
                )
                action_type = action.get("actionTypeId", {})
                require(
                    action_type.get("owner") == "AWS",
                    f"{resource['id']}: external pipeline action authority is unsupported",
                )
                category, provider = (
                    action_type.get("category"),
                    action_type.get("provider"),
                )
                config = action.get("configuration", {})
                if category == "Source" and provider == "S3":
                    require(
                        set(config)
                        <= {"S3Bucket", "S3ObjectKey", "PollForSourceChanges"},
                        f"{resource['id']}: unsupported S3 pipeline source configuration",
                    )
                    self.protected_s3_input(
                        resource,
                        config.get("S3Bucket", ""),
                        config.get("S3ObjectKey", ""),
                    )
                    source_count += 1
                elif category == "Source" and provider == "ECR":
                    require(
                        set(config) <= {"RepositoryName", "ImageTag"},
                        f"{resource['id']}: unsupported ECR pipeline source configuration",
                    )
                    self.protected_ecr_input(
                        resource, parts[4], parts[3], config.get("RepositoryName", "")
                    )
                    source_count += 1
                elif category == "Build" and provider == "CodeBuild":
                    require(
                        set(config) <= {"ProjectName", "PrimarySource"},
                        f"{resource['id']}: pipeline build input overrides are unsupported",
                    )
                    project_arn = (
                        f"arn:aws:codebuild:{parts[3]}:{parts[4]}:project/"
                        + config.get("ProjectName", "")
                    )
                    require(
                        any(
                            value["kind"] == "build" and value["arn"] == project_arn
                            for value in self.dependencies(resource)
                        ),
                        f"{resource['id']}: pipeline build project is outside the protected graph",
                    )
                else:
                    raise VerificationFailure(
                        f"{resource['id']}: external or unsupported pipeline action input"
                    )
        require(
            source_count > 0, f"{resource['id']}: protected pipeline source is required"
        )

    def protected_dependency(
        self, resource: dict[str, Any], kind: str, arn: Any
    ) -> None:
        require(
            isinstance(arn, str)
            and any(
                value["kind"] == kind and value["arn"] == arn
                for value in self.dependencies(resource)
            ),
            f"{resource['id']}: actual {kind} input is outside the protected dependency graph",
        )

    def protected_lambda_caller(self, resource: dict[str, Any], arn: Any) -> None:
        self.protected_dependency(resource, "lambda", arn)
        provider = next(
            value
            for value in self.dependencies(resource)
            if value["kind"] == "lambda" and value["arn"] == arn
        )
        callers = {
            self.roles[identity]["arn"]
            for identity in provider.get("invokerIds", provider["controllerIds"])
        }
        require(
            resource.get("executionRoleArn") in callers,
            f"{resource['id']}: protected Lambda caller is outside the approved invoker graph",
        )

    def verify_template_inputs(
        self,
        resource: dict[str, Any],
        original: Any,
        parameters: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        """Bind future CFN reads, rather than only its last resolved template."""
        template = original
        if isinstance(template, str):
            try:
                template = yaml.load(template, Loader=TemplateLoader)
            except yaml.YAMLError as error:
                raise VerificationFailure(
                    f"{resource['id']}: unsupported or unreadable template syntax"
                ) from error
        require(
            isinstance(template, dict),
            f"{resource['id']}: template input is incomplete",
        )
        require(
            "Transform" not in template,
            f"{resource['id']}: mutable template transforms are unsupported",
        )
        parts = arn_parts(resource["arn"])
        account, region = parts[4], parts[3]
        resource_bindings: dict[str, dict[str, str]] = {}
        all_bindings: dict[str, dict[str, Any]] | None = None

        def custom_provider(value: dict[str, Any]) -> None:
            nonlocal all_bindings
            token = value.get("Properties", {}).get("ServiceToken")
            if isinstance(token, dict) and set(token) == {"Fn::GetAtt"}:
                attribute = token["Fn::GetAtt"]
                reference = (
                    attribute.split(".", 1) if isinstance(attribute, str) else attribute
                )
                require(
                    isinstance(reference, list)
                    and len(reference) == 2
                    and reference[1] == "Arn"
                    and resource["kind"] == "stack",
                    f"{resource['id']}: custom provider token is unsupported",
                )
                if all_bindings is None:
                    bindings = self.pages(
                        self.client(account, "cloudformation", region),
                        "list_stack_resources",
                        "StackResourceSummaries",
                        StackName=resource["arn"],
                    )
                    all_bindings = {
                        item["LogicalResourceId"]: item for item in bindings
                    }
                    require(
                        len(all_bindings) == len(bindings),
                        f"{resource['id']}: custom provider resource bindings are ambiguous",
                    )
                binding = all_bindings.get(reference[0], {})
                require(
                    binding.get("ResourceType") == "AWS::Lambda::Function"
                    and isinstance(binding.get("PhysicalResourceId"), str)
                    and bool(binding["PhysicalResourceId"]),
                    f"{resource['id']}: custom provider resource binding is incomplete",
                )
                physical = binding["PhysicalResourceId"]
                token = (
                    physical
                    if physical.startswith("arn:")
                    else f"arn:aws:lambda:{region}:{account}:function:{physical}"
                )
                resource_bindings[reference[0]] = {
                    key: binding[key]
                    for key in (
                        "LogicalResourceId",
                        "PhysicalResourceId",
                        "ResourceType",
                    )
                }
            require(
                isinstance(token, str) and token.startswith("arn:aws:lambda:"),
                f"{resource['id']}: external or unknown custom provider token is unsupported",
            )
            self.protected_lambda_caller(resource, token)

        def ssm_input(value: Any) -> None:
            require(
                isinstance(value, str) and bool(value) and "${" not in value,
                f"{resource['id']}: SSM template input is unresolved",
            )
            location = value
            if location.startswith("arn:"):
                parsed = arn_parts(location)
                require(
                    parsed[2] == "ssm" and parsed[5].startswith("parameter/"),
                    f"{resource['id']}: SSM template input identity is unsupported",
                )
            else:
                require(
                    re.fullmatch(r"/?[A-Za-z0-9_./-]+", location) is not None,
                    f"{resource['id']}: SSM template input identity is unsupported",
                )
                location = (
                    f"arn:aws:ssm:{region}:{account}:parameter/{location.lstrip('/')}"
                )
            self.protected_dependency(resource, "ssm", location)

        actual_parameters: dict[str, Any] = {}
        for parameter in parameters:
            key = parameter.get("ParameterKey")
            require(
                isinstance(key, str) and key not in actual_parameters,
                f"{resource['id']}: stored template parameters are incomplete",
            )
            actual_parameters[key] = parameter.get("ParameterValue")
        definitions = template.get("Parameters", {})
        require(
            isinstance(definitions, dict),
            f"{resource['id']}: template parameter definitions are incomplete",
        )
        for key, definition in definitions.items():
            require(
                isinstance(definition, dict),
                f"{resource['id']}: template parameter definition is incomplete",
            )
            kind = definition.get("Type", "")
            if isinstance(kind, str) and kind.startswith("AWS::SSM::Parameter::"):
                require(
                    re.fullmatch(r"AWS::SSM::Parameter::Value<.+>", kind) is not None,
                    f"{resource['id']}: unsupported SSM parameter type",
                )
                ssm_input(actual_parameters.get(key, definition.get("Default")))

        def dynamic_input(value: str) -> None:
            if "{{resolve:" not in value:
                return
            matches = list(re.finditer(r"\{\{resolve:([^{}]+)\}\}", value))
            require(
                len(matches) == value.count("{{resolve:"),
                f"{resource['id']}: unresolved dynamic template input",
            )
            for match in matches:
                mode, separator, target = match.group(1).partition(":")
                require(
                    separator and "${" not in target,
                    f"{resource['id']}: unresolved dynamic template input",
                )
                if mode in {"ssm", "ssm-secure"}:
                    ssm_input(re.sub(r":\d+$", "", target))
                elif mode == "secretsmanager":
                    location, marker, suffix = target.partition(":SecretString")
                    require(
                        marker
                        and location.startswith("arn:aws:secretsmanager:")
                        and (not suffix or suffix.startswith(":"))
                        and len(suffix.split(":")) <= 4,
                        f"{resource['id']}: secret template inputs require an exact protected ARN",
                    )
                    self.protected_dependency(resource, "secret", location)
                else:
                    raise VerificationFailure(
                        f"{resource['id']}: unsupported dynamic template input"
                    )

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                require(
                    "Fn::Transform" not in value,
                    f"{resource['id']}: mutable template transforms are unsupported",
                )
                require(
                    value.get("Type")
                    not in {"AWS::CloudFormation::Macro", "AWS::CloudFormation::Stack"},
                    f"{resource['id']}: macros and nested template inputs are unsupported",
                )
                kind = value.get("Type", "")
                if (
                    kind == "AWS::CloudFormation::CustomResource"
                    or isinstance(kind, str)
                    and kind.startswith("Custom::")
                ):
                    custom_provider(value)
                for key, child in value.items():
                    dynamic_input(str(key))
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
            elif isinstance(value, str):
                dynamic_input(value)

        walk(template)
        return [resource_bindings[key] for key in sorted(resource_bindings)]

    def verify_gateway_inputs(
        self, resource: dict[str, Any], gateway: dict[str, Any]
    ) -> None:
        require(
            gateway.get("authorizerType") == "AWS_IAM"
            and not gateway.get("authorizerConfiguration"),
            f"{resource['id']}: protected Gateway requires AWS_IAM authorization",
        )
        request_interceptor = False
        for interceptor in gateway.get("interceptorConfigurations", []):
            config = interceptor.get("interceptor", {})
            require(
                set(config) == {"lambda"},
                f"{resource['id']}: unsupported Gateway interceptor",
            )
            self.protected_lambda_caller(resource, config["lambda"].get("arn"))
            if "REQUEST" in interceptor.get("interceptionPoints", []):
                require(
                    interceptor.get("inputConfiguration", {}).get("passRequestHeaders")
                    is False,
                    f"{resource['id']}: protected request interceptor must exclude caller headers",
                )
                request_interceptor = True
        transform = gateway.get("customTransformConfiguration")
        if transform:
            require(
                set(transform) == {"lambda"},
                f"{resource['id']}: unsupported Gateway transform",
            )
            self.protected_lambda_caller(resource, transform["lambda"].get("arn"))
        if gateway.get("kmsKeyArn"):
            self.protected_dependency(resource, "kms", gateway["kmsKeyArn"])
        native = gateway.get("policyEngineConfiguration")
        if native:
            require(
                isinstance(native, dict)
                and set(native) == {"arn", "mode"}
                and native.get("mode") in {"LOG_ONLY", "ENFORCE"},
                f"{resource['id']}: unsupported Gateway policy-engine configuration",
            )
            self.protected_dependency(
                resource, "agentcore-policy-engine", native.get("arn")
            )
            prefix = native["arn"] + "/policy/"
            required_policies = {
                record["id"]
                for record in self.resources.values()
                if record["kind"] == "agentcore-policy"
                and record["arn"].startswith(prefix)
            }
            require(
                bool(required_policies)
                and required_policies
                <= {record["id"] for record in self.dependencies(resource)},
                f"{resource['id']}: every native policy must be a protected Gateway dependency",
            )
        for target in gateway["Targets"]:
            require(
                target.get("gatewayArn") == resource["arn"],
                f"{resource['id']}: Gateway target belongs to a different gateway",
            )
            credentials = target.get("credentialProviderConfigurations")
            require(
                isinstance(credentials, list)
                and bool(credentials)
                and all(
                    value.get("credentialProviderType") == "GATEWAY_IAM_ROLE"
                    and not value.get("credentialProvider")
                    for value in credentials
                ),
                f"{resource['id']}: remote or delegated Gateway credential authority is unsupported",
            )
            require(
                not target.get("privateEndpoint")
                and not target.get("certificateConfigurations"),
                f"{resource['id']}: unmodeled Gateway private or certificate inputs are unsupported",
            )
            target_config = target.get("targetConfiguration", {})
            if set(target_config) == {"inference"}:
                require(
                    target_config["inference"]
                    == {"connector": {"source": {"connectorId": "bedrock-mantle"}}},
                    f"{resource['id']}: external inference provider or connector is unsupported",
                )
                require(
                    request_interceptor,
                    f"{resource['id']}: first-party inference target requires a protected REQUEST interceptor",
                )
                continue
            require(
                set(target_config) == {"mcp"}
                and set(target_config["mcp"]) == {"lambda"},
                f"{resource['id']}: external or unsupported Gateway target input",
            )
            target_lambda = target_config["mcp"]["lambda"]
            self.protected_lambda_caller(resource, target_lambda.get("lambdaArn"))
            schema = target_lambda.get("toolSchema", {})
            if set(schema) == {"inlinePayload"}:
                require(
                    isinstance(schema["inlinePayload"], list),
                    f"{resource['id']}: Lambda tool schema is incomplete",
                )
            else:
                require(
                    set(schema) == {"s3"},
                    f"{resource['id']}: unsupported Lambda tool schema",
                )
                location = schema["s3"].get("uri", "")
                require(
                    location.startswith("s3://"),
                    f"{resource['id']}: unsupported schema URI",
                )
                bucket, separator, key = location[5:].partition("/")
                require(
                    bool(separator), f"{resource['id']}: schema source is incomplete"
                )
                self.protected_s3_input(resource, bucket, key)
                require(
                    schema["s3"].get("bucketOwnerAccountId")
                    == self.protected_s3_bucket(resource, bucket)["accountId"],
                    f"{resource['id']}: schema bucket owner differs",
                )

    def resource_snapshot(self, resource: dict[str, Any]) -> tuple[Any, Any | None]:
        parts = arn_parts(resource["arn"])
        account, region, name = (
            resource.get("accountId", parts[4]),
            parts[3] or self.regional_anchor(resource.get("accountId", parts[4])),
            parts[5],
        )
        kind = resource["kind"]
        if kind == "policy":
            iam = self.client(account, "iam")
            policy = iam.get_policy(PolicyArn=resource["arn"])["Policy"]
            require(
                policy["Arn"] == resource["arn"]
                and policy["PolicyId"] == resource.get("policyId")
                and policy["DefaultVersionId"] == resource.get("defaultVersionId"),
                f"{resource['id']}: managed policy identity or version differs",
            )
            policy_doc = iam.get_policy_version(
                PolicyArn=resource["arn"],
                VersionId=policy["DefaultVersionId"],
            )["PolicyVersion"]["Document"]
            return policy, document(policy_doc)
        if kind == "lambda":
            client = self.client(account, "lambda", region)
            config = client.get_function(FunctionName=resource["arn"])
            require(
                "Error" not in config["Configuration"].get("Environment", {}),
                f"{resource['id']}: Lambda environment is unreadable",
            )
            config["Code"].pop("Location", None)
            config["Aliases"] = self.pages(
                client, "list_aliases", "Aliases", FunctionName=resource["arn"]
            )
            config["Versions"] = self.pages(
                client,
                "list_versions_by_function",
                "Versions",
                FunctionName=resource["arn"],
            )
            require(
                all(
                    not item.get("FileSystemConfigs")
                    for item in [config["Configuration"], *config["Versions"]]
                ),
                f"{resource['id']}: external Lambda filesystem inputs are unsupported",
            )
            config["EventSourceMappings"] = self.pages(
                client,
                "list_event_source_mappings",
                "EventSourceMappings",
                FunctionName=resource["arn"],
            )
            config["ResourcePolicy"] = self.optional(
                client,
                "get_policy",
                "ResourceNotFoundException",
                FunctionName=resource["arn"],
            )
            config["FunctionUrls"] = self.pages(
                client,
                "list_function_url_configs",
                "FunctionUrlConfigs",
                FunctionName=resource["arn"],
            )
            config["Concurrency"] = client.get_function_concurrency(
                FunctionName=resource["arn"]
            )
            config["CodeSigningConfig"] = client.get_function_code_signing_config(
                FunctionName=resource["arn"]
            )
            self.verify_resource_policy(
                resource, config["ResourcePolicy"].get("Policy", {})
            )
            config["QualifiedPolicies"] = {}
            for qualifier in [item["Name"] for item in config["Aliases"]] + [
                item["Version"]
                for item in config["Versions"]
                if item["Version"] != "$LATEST"
            ]:
                policy = self.optional(
                    client,
                    "get_policy",
                    "ResourceNotFoundException",
                    FunctionName=resource["arn"],
                    Qualifier=qualifier,
                )
                self.verify_resource_policy(resource, policy.get("Policy", {}))
                config["QualifiedPolicies"][qualifier] = policy
            require(
                all(item["AuthType"] == "AWS_IAM" for item in config["FunctionUrls"]),
                f"{resource['id']}: unauthenticated Function URL",
            )
            for mapping in config["EventSourceMappings"]:
                require(
                    mapping.get("EventSourceArn")
                    in {
                        self.resources[identity]["arn"]
                        for identity in resource["dependsOnIds"]
                    },
                    f"{resource['id']}: event source is outside the protected dependency graph",
                )
            require(
                config["Configuration"]["Role"] == resource.get("executionRoleArn"),
                f"{resource['id']}: Lambda execution role differs",
            )
            require(
                config["Configuration"]["CodeSha256"] == resource.get("codeSha256"),
                f"{resource['id']}: Lambda code differs",
            )
            return config, None
        if kind == "lambda-event-source-mapping":
            uuid = name.rsplit(":", 1)[-1]
            config = self.client(account, "lambda", region).get_event_source_mapping(
                UUID=uuid
            )
            return config, None
        if kind == "stack":
            client = self.client(account, "cloudformation", region)
            stack = client.describe_stacks(StackName=resource["arn"])["Stacks"][0]
            require(
                stack.get("StackStatus")
                in {
                    "CREATE_COMPLETE",
                    "UPDATE_COMPLETE",
                    "IMPORT_COMPLETE",
                    "ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_COMPLETE",
                },
                f"{resource['id']}: active or incomplete protected stack prevents a quiet cutover",
            )
            require(
                stack.get("RoleARN") == resource.get("executionRoleArn"),
                f"{resource['id']}: stored CloudFormation execution role differs",
            )
            template = document(
                client.get_template(
                    StackName=resource["arn"], TemplateStage="Original"
                )["TemplateBody"]
            )
            bindings = self.verify_template_inputs(
                resource, template, stack.get("Parameters", [])
            )
            snapshot = {"Stack": stack, "Template": template}
            if bindings:
                snapshot["ResourceBindings"] = bindings
            return snapshot, template
        if kind == "stack-set":
            client = self.client(account, "cloudformation", region)
            stack_set = client.describe_stack_set(StackSetName=name.split("/", 1)[-1])[
                "StackSet"
            ]
            require(
                stack_set.get("PermissionModel") == "SELF_MANAGED",
                f"{resource['id']}: service-managed StackSet authority is unsupported",
            )
            raise VerificationFailure(
                f"{resource['id']}: protected self-managed StackSet execution and queued-operation authority is unsupported"
            )
        if kind == "gateway":
            client = self.client(account, "bedrock-agentcore-control", region)
            identity = name.split("/", 1)[-1]
            config = client.get_gateway(gatewayIdentifier=identity)
            require(
                config["roleArn"] == resource.get("executionRoleArn"),
                f"{resource['id']}: Gateway execution role differs",
            )
            targets = self.pages(
                client, "list_gateway_targets", "items", gatewayIdentifier=identity
            )
            config["Targets"] = [
                client.get_gateway_target(
                    gatewayIdentifier=identity, targetId=target["targetId"]
                )
                for target in targets
            ]
            if config.get("policyEngineConfiguration"):
                config["ResourcePolicy"] = self.optional(
                    client,
                    "get_resource_policy",
                    "ResourceNotFoundException",
                    resourceArn=resource["arn"],
                )
                self.verify_resource_policy(
                    resource, config["ResourcePolicy"].get("policy", {})
                )
            self.verify_gateway_inputs(resource, config)
            return config, None
        if kind == "agentcore-policy-engine":
            client = self.client(account, "bedrock-agentcore-control", region)
            identity = name.split("/", 1)[1]
            engine = client.get_policy_engine(policyEngineId=identity)
            require(
                engine.get("policyEngineArn") == resource["arn"]
                and engine.get("policyEngineId") == identity
                and engine.get("status") == "ACTIVE",
                f"{resource['id']}: native policy-engine identity or status differs",
            )
            self.protected_dependency(
                resource, "kms", engine.get("encryptionKeyArn")
            )
            prefix = resource["arn"] + "/policy/"
            declared = {
                record["arn"]
                for record in self.resources.values()
                if record["kind"] == "agentcore-policy"
                and record["arn"].startswith(prefix)
            }
            policies = self.pages(
                client, "list_policies", "policies", policyEngineId=identity
            )
            actual = [policy.get("policyArn") for policy in policies]
            require(
                bool(declared)
                and len(actual) == len(set(actual))
                and set(actual) == declared,
                f"{resource['id']}: native policy inventory is missing or unexpected",
            )
            return {
                "Engine": engine,
                "Policies": sorted(policies, key=lambda policy: policy["policyArn"]),
                "Tags": client.list_tags_for_resource(resourceArn=resource["arn"]),
            }, None
        if kind == "agentcore-policy":
            client = self.client(account, "bedrock-agentcore-control", region)
            _, engine_id, _, policy_id = name.split("/")
            engine_arn = resource["arn"].split("/policy/")[0]
            self.protected_dependency(
                resource, "agentcore-policy-engine", engine_arn
            )
            policy = client.get_policy(
                policyEngineId=engine_id, policyId=policy_id
            )
            definition = policy.get("definition")
            require(
                policy.get("policyArn") == resource["arn"]
                and policy.get("policyEngineId") == engine_id
                and policy.get("policyId") == policy_id
                and policy.get("status") == "ACTIVE"
                and isinstance(definition, dict)
                and set(definition) == {"cedar"}
                and isinstance(definition["cedar"], dict)
                and set(definition["cedar"]) == {"statement"}
                and isinstance(definition["cedar"]["statement"], str)
                and bool(definition["cedar"]["statement"]),
                f"{resource['id']}: native policy identity, status or definition differs",
            )
            return policy, policy["definition"]
        if kind == "pipeline":
            pipeline = self.client(account, "codepipeline", region).get_pipeline(
                name=name
            )["pipeline"]
            require(
                pipeline["roleArn"] == resource.get("executionRoleArn"),
                f"{resource['id']}: pipeline execution role differs",
            )
            self.verify_pipeline_inputs(resource, pipeline)
            return pipeline, None
        if kind == "build":
            result = self.client(account, "codebuild", region).batch_get_projects(
                names=[name.split("/", 1)[-1]]
            )
            require(
                not result.get("projectsNotFound") and len(result["projects"]) == 1,
                f"{resource['id']}: build project is missing",
            )
            project = result["projects"][0]
            require(
                project["serviceRole"] == resource.get("executionRoleArn"),
                f"{resource['id']}: build execution role differs",
            )
            self.verify_build_inputs(resource, project)
            project["ResourcePolicy"] = self.optional(
                self.client(account, "codebuild", region),
                "get_resource_policy",
                "ResourceNotFoundException",
                resourceArn=resource["arn"],
            )
            self.verify_resource_policy(
                resource, project["ResourcePolicy"].get("policy", {})
            )
            return project, None
        if kind == "state-machine":
            client = self.client(account, "stepfunctions", region)
            machine = client.describe_state_machine(stateMachineArn=resource["arn"])
            require(
                machine["roleArn"] == resource.get("executionRoleArn"),
                f"{resource['id']}: state-machine execution role differs",
            )
            machine["Tags"] = client.list_tags_for_resource(
                resourceArn=resource["arn"]
            ).get("tags", [])
            machine["Versions"] = self.state_machine_versions(client, resource["arn"])
            require(
                all(
                    version["roleArn"] == resource["executionRoleArn"]
                    for version in machine["Versions"]
                ),
                f"{resource['id']}: historical state-machine versions have a different execution role",
            )
            machine["Aliases"] = self.state_machine_aliases(client, resource["arn"])
            return machine, document(machine["definition"])
        if kind in {"s3-bucket", "s3-object"}:
            client = self.client(account, "s3", region)
            bucket, _, key = name.partition("/")
            kwargs = {"Bucket": bucket, "ExpectedBucketOwner": account}
            if kind == "s3-object":
                object_args = {**kwargs, "Key": key}
                if resource.get("versionId"):
                    object_args["VersionId"] = resource["versionId"]
                metadata = client.head_object(**object_args)
                if metadata.get("VersionId") and not resource.get("versionId"):
                    object_args["VersionId"] = metadata["VersionId"]
                acl_args = {
                    key: value for key, value in object_args.items() if key != "IfMatch"
                }
                metadata["Acl"] = client.get_object_acl(**acl_args)
                self.verify_acl(resource, metadata["Acl"])
                object_args["IfMatch"] = metadata["ETag"]
                body = client.get_object(**object_args)["Body"]
                size, result, deadline = 0, hashlib.sha256(), time.monotonic() + 60
                try:
                    while chunk := body.read(1024 * 1024):
                        size += len(chunk)
                        require(
                            size <= MAX_OBJECT_BYTES and time.monotonic() <= deadline,
                            f"{resource['id']}: object verification limit exceeded",
                        )
                        result.update(chunk)
                finally:
                    body.close()
                require(
                    size == metadata["ContentLength"],
                    f"{resource['id']}: object changed during verification",
                )
                return metadata, {"ObjectBytesSha256": result.hexdigest()}
            policy = self.optional(
                client, "get_bucket_policy", "NoSuchBucketPolicy", **kwargs
            )
            state = {
                "Policy": document(policy.get("Policy", {})),
                "Acl": client.get_bucket_acl(**kwargs),
                "Versioning": client.get_bucket_versioning(**kwargs),
                "Encryption": client.get_bucket_encryption(**kwargs),
                "PublicAccessBlock": client.get_public_access_block(**kwargs),
                "OwnershipControls": client.get_bucket_ownership_controls(**kwargs),
                "Notifications": client.get_bucket_notification_configuration(**kwargs),
            }
            self.verify_acl(resource, state["Acl"])
            self.verify_resource_policy(resource, state["Policy"])
            require(
                state["OwnershipControls"].get("OwnershipControls", {}).get("Rules")
                == [{"ObjectOwnership": "BucketOwnerEnforced"}],
                f"{resource['id']}: protected buckets must enforce bucket ownership",
            )
            return state, state["Policy"]
        if kind == "ecr":
            client = self.client(account, "ecr", region)
            repo = name.split("/", 1)[-1]
            state = client.describe_repositories(
                registryId=account, repositoryNames=[repo]
            )
            state["Policy"] = self.optional(
                client,
                "get_repository_policy",
                "RepositoryPolicyNotFoundException",
                registryId=account,
                repositoryName=repo,
            )
            state["Images"] = self.pages(
                client,
                "describe_images",
                "imageDetails",
                registryId=account,
                repositoryName=repo,
            )
            self.verify_resource_policy(resource, state["Policy"].get("policyText", {}))
            return state, document(state["Policy"].get("policyText", {}))
        if kind == "kms":
            client = self.client(account, "kms", region)
            state = client.describe_key(KeyId=resource["arn"])
            state["Policy"] = document(
                client.get_key_policy(KeyId=resource["arn"], PolicyName="default")[
                    "Policy"
                ]
            )
            state["Grants"] = self.pages(
                client, "list_grants", "Grants", KeyId=resource["arn"]
            )
            self.verify_resource_policy(resource, state["Policy"])
            approved = {
                self.roles[identity]["arn"] for identity in resource["controllerIds"]
            }
            for grant in state["Grants"]:
                require(
                    grant.get("GranteePrincipal") in approved
                    and (
                        not grant.get("RetiringPrincipal")
                        or grant["RetiringPrincipal"] in approved
                    ),
                    f"{resource['id']}: KMS grant is outside the controller graph",
                )
            return state, state["Policy"]
        if kind == "ssm":
            client = self.client(account, "ssm", region)
            parameters = self.pages(
                client,
                "describe_parameters",
                "Parameters",
                ParameterFilters=[
                    {
                        "Key": "Name",
                        "Option": "Equals",
                        "Values": [name[len("parameter") :]],
                    }
                ],
            )
            require(
                len(parameters) == 1, f"{resource['id']}: SSM configuration is missing"
            )
            parameters[0]["Tags"] = client.list_tags_for_resource(
                ResourceType="Parameter",
                ResourceId=parameters[0]["Name"],
            ).get("TagList", [])
            return parameters[0], None
        if kind == "secret":
            client = self.client(account, "secretsmanager", region)
            state = client.describe_secret(SecretId=resource["arn"])
            policy = client.get_resource_policy(SecretId=resource["arn"])
            state["Policy"] = document(policy.get("ResourcePolicy", {}))
            self.verify_resource_policy(resource, state["Policy"])
            return state, state["Policy"]
        if kind == "connection":
            service = (
                "codeconnections"
                if parts[2] == "codeconnections"
                else "codestar-connections"
            )
            return self.client(account, service, region).get_connection(
                ConnectionArn=resource["arn"]
            ), None
        if kind == "layer":
            state = self.client(account, "lambda", region).get_layer_version_by_arn(
                Arn=resource["arn"]
            )
            state["Content"].pop("Location", None)
            return state, None
        raise VerificationFailure(f"{resource['id']}: unsupported resource kind")

    def state_machine_versions(self, client: Any, arn: str) -> list[dict[str, Any]]:
        return [
            client.describe_state_machine(
                stateMachineArn=version["stateMachineVersionArn"]
            )
            for version in self.pages(
                client,
                "list_state_machine_versions",
                "stateMachineVersions",
                stateMachineArn=arn,
            )
        ]

    def state_machine_aliases(self, client: Any, arn: str) -> list[dict[str, Any]]:
        return [
            client.describe_state_machine_alias(
                stateMachineAliasArn=alias["stateMachineAliasArn"]
            )
            for alias in self.pages(
                client,
                "list_state_machine_aliases",
                "stateMachineAliases",
                stateMachineArn=arn,
            )
        ]

    def historical_codebuild_consumers(
        self, client: Any, account: str, region: str
    ) -> set[tuple[str, str]]:
        observed: set[tuple[str, str]] = set()
        ids = self.pages(client, "list_builds", "ids")
        for offset in range(0, len(ids), 100):
            batch = ids[offset : offset + 100]
            result = client.batch_get_builds(ids=batch)
            require(
                not result.get("buildsNotFound")
                and len(result["builds"]) == len(batch),
                "historical CodeBuild build inventory is incomplete",
            )
            for build in result["builds"]:
                require(
                    "serviceRole" in build and "buildComplete" in build,
                    "a historical build's execution authority is unknown",
                )
                if build["serviceRole"] not in self.role_arns:
                    continue
                require(
                    build["buildComplete"] is True,
                    "an active historical protected-role build prevents a quiet cutover",
                )
                observed.add(
                    (
                        f"arn:aws:codebuild:{region}:{account}:project/{build['projectName']}",
                        build["serviceRole"],
                    )
                )
        ids = self.pages(client, "list_build_batches", "ids")
        for offset in range(0, len(ids), 100):
            batch = ids[offset : offset + 100]
            result = client.batch_get_build_batches(ids=batch)
            require(
                not result.get("buildBatchesNotFound")
                and len(result["buildBatches"]) == len(batch),
                "historical CodeBuild batch inventory is incomplete",
            )
            for build in result["buildBatches"]:
                require(
                    "serviceRole" in build,
                    "a historical batch build's execution authority is unknown",
                )
                require(
                    not {
                        build["serviceRole"],
                        build.get("buildBatchConfig", {}).get("serviceRole"),
                    }
                    & self.role_arns,
                    "a historical protected-role batch build consumer is unsupported",
                )
        return observed

    def historical_state_machine_consumers(
        self, client: Any, arn: str, machine: dict[str, Any]
    ) -> set[tuple[str, str]]:
        require(
            machine.get("type") in {"STANDARD", "EXPRESS"},
            "the state-machine execution history type is unknown",
        )
        require(
            machine["type"] == "STANDARD",
            "EXPRESS execution history cannot establish complete protected-role consumer inventory; independent quiet-cutover acceptance is required",
        )
        observed: set[tuple[str, str]] = set()
        for summary in self.pages(
            client, "list_executions", "executions", stateMachineArn=arn
        ):
            require(
                not self.pages(
                    client,
                    "list_map_runs",
                    "mapRuns",
                    executionArn=summary["executionArn"],
                ),
                "Distributed Map child execution history cannot establish complete protected-role consumer inventory and is unsupported",
            )
            if summary.get("status") == "SUCCEEDED":
                continue
            execution = client.describe_execution(
                executionArn=summary["executionArn"], includedData="METADATA_ONLY"
            )
            status = execution.get("status")
            require(
                status
                in {
                    "RUNNING",
                    "SUCCEEDED",
                    "FAILED",
                    "TIMED_OUT",
                    "ABORTED",
                    "PENDING_REDRIVE",
                },
                "a historical state-machine execution status is unknown",
            )
            if status == "SUCCEEDED":
                continue
            if status not in {"RUNNING", "PENDING_REDRIVE"}:
                require(
                    execution.get("redriveStatus")
                    in {
                        "REDRIVABLE",
                        "NOT_REDRIVABLE",
                        "REDRIVABLE_BY_MAP_RUN",
                    },
                    "historical state-machine redrive authority is unknown",
                )
                if execution["redriveStatus"] == "NOT_REDRIVABLE":
                    continue
            saved = client.describe_state_machine_for_execution(
                executionArn=summary["executionArn"], includedData="METADATA_ONLY"
            )
            require(
                "roleArn" in saved,
                "a historical state-machine execution role is unknown",
            )
            if saved["roleArn"] in self.role_arns:
                require(
                    status not in {"RUNNING", "PENDING_REDRIVE"},
                    "an active protected state-machine execution prevents a quiet cutover",
                )
                observed.add((arn, saved["roleArn"]))
        return observed

    @staticmethod
    def role_paths(shape: Any, seen: frozenset[str] = frozenset()) -> bool:
        if shape is None or shape.name in seen:
            return False
        visited = seen | {shape.name}
        if shape.type_name == "structure":
            return any(
                name.lower().endswith("rolearn") or Verifier.role_paths(member, visited)
                for name, member in shape.members.items()
            )
        if shape.type_name == "list":
            return Verifier.role_paths(shape.member, visited)
        if shape.type_name == "map":
            return Verifier.role_paths(shape.value, visited)
        return False

    @staticmethod
    def verify_agentcore_model(model: Any, allowed: frozenset[str]) -> None:
        operations = {
            name
            for name in model.operation_names
            if name.startswith(("Get", "List"))
            and Verifier.role_paths(model.operation_model(name).output_shape)
        }
        require(
            operations == allowed,
            "the SDK has an unknown or incomplete AgentCore role-bearing inventory contract",
        )

    def reject_agentcore_role(
        self, state: Any, path: tuple[str, ...], operation: str
    ) -> None:
        value = state
        for field in path:
            require(
                isinstance(value, dict) and field in value,
                f"{operation}: the stored AgentCore execution role is unknown",
            )
            value = value[field]
        require(
            isinstance(value, str) and value.startswith("arn:aws:iam::"),
            f"{operation}: the stored AgentCore execution role is unknown",
        )
        require(
            value not in self.role_arns,
            f"{operation}: protected AgentCore authority outside enrolled Gateways is unsupported",
        )

    def agentcore_unsupported_consumers(self, client: Any) -> None:
        self.verify_agentcore_model(
            client.meta.service_model, AGENTCORE_ROLE_READ_OPERATIONS
        )
        for (
            listed,
            collection,
            getter,
            identity,
            argument,
            path,
        ) in AGENTCORE_DIRECT_CONSUMERS:
            for summary in self.pages(client, listed, collection):
                state = getattr(client, getter)(**{argument: summary[identity]})
                self.reject_agentcore_role(state, path, getter)
        for listed, collection, getter, identity in [
            ("list_browsers", "browserSummaries", "get_browser", "browserId"),
            (
                "list_code_interpreters",
                "codeInterpreterSummaries",
                "get_code_interpreter",
                "codeInterpreterId",
            ),
        ]:
            for browser_type in ("CUSTOM", "SYSTEM"):
                for summary in self.pages(
                    client, listed, collection, type=browser_type
                ):
                    state = getattr(client, getter)(**{identity: summary[identity]})
                    # Built-in SYSTEM tools have no customer execution role.
                    # CUSTOM consumers must return the configured role.
                    if browser_type == "SYSTEM" and "executionRoleArn" not in state:
                        continue
                    self.reject_agentcore_role(state, ("executionRoleArn",), getter)
        for summary in self.pages(client, "list_agent_runtimes", "agentRuntimes"):
            identity = summary["agentRuntimeId"]
            versions = {summary["agentRuntimeVersion"]}
            versions.update(
                value["agentRuntimeVersion"]
                for value in self.pages(
                    client,
                    "list_agent_runtime_versions",
                    "agentRuntimes",
                    agentRuntimeId=identity,
                )
            )
            for endpoint in self.pages(
                client,
                "list_agent_runtime_endpoints",
                "runtimeEndpoints",
                agentRuntimeId=identity,
            ):
                state = client.get_agent_runtime_endpoint(
                    agentRuntimeId=identity, endpointName=endpoint["name"]
                )
                require(
                    "liveVersion" in state and "targetVersion" in state,
                    "an AgentCore runtime endpoint version is unknown",
                )
                versions.update([state["liveVersion"], state["targetVersion"]])
            for version in sorted(versions):
                state = client.get_agent_runtime(
                    agentRuntimeId=identity, agentRuntimeVersion=version
                )
                self.reject_agentcore_role(state, ("roleArn",), "get_agent_runtime")
        for summary in self.pages(client, "list_harnesses", "harnesses"):
            identity = summary["harnessId"]
            versions = {summary["harnessVersion"]}
            versions.update(
                value["harnessVersion"]
                for value in self.pages(
                    client,
                    "list_harness_versions",
                    "harnessVersions",
                    harnessId=identity,
                )
            )
            for endpoint in self.pages(
                client, "list_harness_endpoints", "endpoints", harnessId=identity
            ):
                state = client.get_harness_endpoint(
                    harnessId=identity, endpointName=endpoint["endpointName"]
                )["endpoint"]
                require(
                    "liveVersion" in state and "targetVersion" in state,
                    "an AgentCore harness endpoint version is unknown",
                )
                versions.update([state["liveVersion"], state["targetVersion"]])
            for version in sorted(versions):
                state = client.get_harness(harnessId=identity, harnessVersion=version)
                self.reject_agentcore_role(
                    state, ("harness", "executionRoleArn"), "get_harness"
                )
        for registry in self.pages(client, "list_registries", "registries"):
            identity = registry["registryId"]
            for summary in self.pages(
                client, "list_registry_records", "registryRecords", registryId=identity
            ):
                state = client.get_registry_record(
                    registryId=identity, recordId=summary["recordId"]
                )
                providers = (
                    state.get("synchronizationConfiguration", {})
                    .get("fromUrl", {})
                    .get("credentialProviderConfigurations", [])
                )
                for provider in providers:
                    credential = provider.get("credentialProvider", {})
                    if "iamCredentialProvider" in credential:
                        self.reject_agentcore_role(
                            credential["iamCredentialProvider"],
                            ("roleArn",),
                            "get_registry_record",
                        )

    def historical_pipeline_consumers(
        self, client: Any, pipeline: dict[str, Any], account: str, region: str
    ) -> set[tuple[str, str]]:
        observed: set[tuple[str, str]] = set()
        base = f"arn:aws:codepipeline:{region}:{account}:{pipeline['name']}"
        versions: dict[int, set[str]] = {}
        for summary in self.pages(
            client,
            "list_pipeline_executions",
            "pipelineExecutionSummaries",
            pipelineName=pipeline["name"],
        ):
            execution = client.get_pipeline_execution(
                pipelineName=pipeline["name"],
                pipelineExecutionId=summary["pipelineExecutionId"],
            )["pipelineExecution"]
            require(
                isinstance(execution.get("pipelineVersion"), int)
                and execution.get("status")
                in {
                    "Cancelled",
                    "InProgress",
                    "Stopped",
                    "Stopping",
                    "Succeeded",
                    "Superseded",
                    "Failed",
                },
                "a saved pipeline execution version or status is unknown",
            )
            versions.setdefault(execution["pipelineVersion"], set()).add(
                execution["status"]
            )
        for version, statuses in versions.items():
            saved = client.get_pipeline(name=pipeline["name"], version=version)[
                "pipeline"
            ]
            require(
                saved.get("version") == version
                and saved.get("name") == pipeline["name"],
                "a saved pipeline execution configuration version differs",
            )
            roles = {saved.get("roleArn")} | {
                action.get("roleArn")
                for stage in saved.get("stages", [])
                for action in stage.get("actions", [])
            }
            for role in roles & self.role_arns:
                require(
                    not statuses & {"InProgress", "Stopping"},
                    "an active protected pipeline execution prevents a quiet cutover",
                )
                observed.add((base, role))
        return observed

    def verify_stack_change_sets(self, client: Any, stack: dict[str, Any]) -> None:
        """A saved change-set RoleARN is absent from read APIs.

        Current Stack.RoleARN therefore cannot prove the authority of a
        pending change set. Enrollment requires only explicitly terminal,
        nonexecutable metadata; every available or unknown set must be
        removed or drained through centrally reviewed cutover procedures.
        """
        nonexecutable = {
            ("FAILED", "UNAVAILABLE"),
            ("DELETE_COMPLETE", "UNAVAILABLE"),
            ("CREATE_COMPLETE", "EXECUTE_COMPLETE"),
            ("CREATE_COMPLETE", "OBSOLETE"),
        }
        for summary in self.pages(
            client, "list_change_sets", "Summaries", StackName=stack["StackId"]
        ):
            require(
                (summary.get("Status"), summary.get("ExecutionStatus"))
                in nonexecutable,
                "unresolved executable or pending CloudFormation change-set authority prevents a quiet cutover",
            )
            identity = summary.get("ChangeSetId")
            require(
                isinstance(identity, str)
                and identity.startswith("arn:aws:cloudformation:"),
                "a saved CloudFormation change-set identity is unknown",
            )
            saved = client.describe_change_set(
                ChangeSetName=identity,
                StackName=stack["StackId"],
                IncludePropertyValues=False,
            )
            require(
                saved.get("ChangeSetId") == identity
                and saved.get("StackId") == stack["StackId"]
                and (saved.get("Status"), saved.get("ExecutionStatus"))
                in nonexecutable,
                "unresolved or changed CloudFormation change-set authority prevents a quiet cutover",
            )

    def verify_resources(self) -> None:
        for resource in self.resources.values():
            state, policy_doc = self.resource_snapshot(resource)
            if resource["kind"] != "policy":
                require(
                    digest(state) == resource["configurationSha256"],
                    f"{resource['id']}: protected resource configuration differs",
                )
            if resource.get("documentSha256"):
                require(
                    policy_doc is not None,
                    f"{resource['id']}: no document can be verified",
                )
                actual = (
                    policy_doc.get("ObjectBytesSha256")
                    if resource["kind"] == "s3-object"
                    else digest(policy_doc)
                )
                require(
                    actual == resource["documentSha256"],
                    f"{resource['id']}: protected document differs",
                )
            elif resource["kind"] in {
                "policy", "agentcore-policy", "stack", "s3-object"
            }:
                raise VerificationFailure(
                    f"{resource['id']}: an approved document digest is required"
                )
            self.checks.append(f"resource:{resource['id']}")

    def verify_consumers(self) -> None:
        declared = {
            (resource["arn"], resource["executionRoleArn"])
            for resource in self.resources.values()
            if resource.get("executionRoleArn") in self.role_arns
        }
        observed: set[tuple[str, str]] = set()
        accounts = {arn_parts(role["arn"])[4] for role in self.roles.values()}
        for account in sorted(accounts):
            proofs = self.region_denies.get(account, [])
            anchor = self.regional_anchor(account)
            regions = self.client(account, "ec2", anchor).describe_regions(
                AllRegions=False
            )["Regions"]
            enabled = sorted(item["RegionName"] for item in regions)
            self.regions[account] = enabled
            require(
                bool(self.regions[account]), "the enabled Region inventory is empty"
            )
            if proofs:
                self.discovery_anchors[account] = {
                    "region": anchor,
                    "purpose": "select an allowed API discovery anchor; every enabled Region is still inventoried",
                    "policyBindings": proofs,
                }
            for region in self.regions[account]:
                for service in REGIONAL_SERVICES:
                    supported = self.sessions[account].get_available_regions(
                        service, partition_name="aws"
                    )
                    if region not in supported:
                        require(
                            False,
                            "the SDK cannot establish a complete enabled-Region service inventory",
                        )
                    client = self.client(account, service, region)
                    if service == "cloudformation":
                        for stack in self.pages(client, "describe_stacks", "Stacks"):
                            if stack.get("StackStatus") != "DELETE_COMPLETE":
                                self.verify_stack_change_sets(client, stack)
                            if (
                                stack.get("StackStatus") != "DELETE_COMPLETE"
                                and stack.get("RoleARN") in self.role_arns
                            ):
                                observed.add((stack["StackId"], stack["RoleARN"]))
                        protected_role_names = {
                            role["arn"].rsplit("/", 1)[-1]
                            for role in self.roles.values()
                        }
                        for summary in self.pages(
                            client, "list_stack_sets", "Summaries", Status="ACTIVE"
                        ):
                            stack_set = client.describe_stack_set(
                                StackSetName=summary["StackSetId"]
                            )["StackSet"]
                            require(
                                stack_set.get("PermissionModel") == "SELF_MANAGED",
                                "service-managed StackSet consumer authority is unsupported",
                            )
                            require(
                                isinstance(stack_set.get("AdministrationRoleARN"), str)
                                and bool(stack_set.get("ExecutionRoleName")),
                                "a StackSet's stored role authority is unknown",
                            )
                            require(
                                stack_set.get("AdministrationRoleARN")
                                not in self.role_arns
                                and stack_set.get("ExecutionRoleName")
                                not in protected_role_names,
                                "protected-role StackSet consumer or queued-operation authority is unsupported",
                            )
                    elif service == "lambda":
                        for function in self.pages(
                            client, "list_functions", "Functions", FunctionVersion="ALL"
                        ):
                            if function.get("Role") in self.role_arns:
                                # Every version is an execution entry point of its
                                # protected base function; the renderer fences :*.
                                observed.add(
                                    (
                                        function["FunctionArn"].split(":function:")[0]
                                        + ":function:"
                                        + function["FunctionName"],
                                        function["Role"],
                                    )
                                )
                    elif service == "codebuild":
                        names = self.pages(client, "list_projects", "projects")
                        for offset in range(0, len(names), 100):
                            result = client.batch_get_projects(
                                names=names[offset : offset + 100]
                            )
                            require(
                                not result.get("projectsNotFound"),
                                "a build project disappeared during inventory",
                            )
                            for project in result["projects"]:
                                require(
                                    project.get("resourceAccessRole")
                                    not in self.role_arns,
                                    "a protected project resource-access role consumer is unsupported",
                                )
                                project_roles = {
                                    project.get("serviceRole"),
                                    project.get("buildBatchConfig", {}).get(
                                        "serviceRole"
                                    ),
                                }
                                for execution_role in project_roles & self.role_arns:
                                    observed.add((project["arn"], execution_role))
                        fleet_names = self.pages(client, "list_fleets", "fleets")
                        for offset in range(0, len(fleet_names), 100):
                            result = client.batch_get_fleets(
                                names=fleet_names[offset : offset + 100]
                            )
                            require(
                                not result.get("fleetsNotFound"),
                                "a fleet disappeared during inventory",
                            )
                            require(
                                all(
                                    fleet.get("fleetServiceRole") not in self.role_arns
                                    for fleet in result["fleets"]
                                ),
                                "a protected-role CodeBuild fleet consumer is unsupported",
                            )
                        sandbox_ids = self.pages(client, "list_sandboxes", "ids")
                        for offset in range(0, len(sandbox_ids), 100):
                            result = client.batch_get_sandboxes(
                                ids=sandbox_ids[offset : offset + 100]
                            )
                            require(
                                not result.get("sandboxesNotFound")
                                and all(
                                    "serviceRole" in sandbox
                                    for sandbox in result["sandboxes"]
                                ),
                                "a sandbox disappeared or its execution role is unknown",
                            )
                            require(
                                all(
                                    sandbox["serviceRole"] not in self.role_arns
                                    for sandbox in result["sandboxes"]
                                ),
                                "a protected-role CodeBuild sandbox consumer is unsupported",
                            )
                        observed |= self.historical_codebuild_consumers(
                            client, account, region
                        )
                    elif service == "codepipeline":
                        for summary in self.pages(
                            client, "list_pipelines", "pipelines"
                        ):
                            pipeline = client.get_pipeline(name=summary["name"])[
                                "pipeline"
                            ]
                            pipeline_roles = {pipeline.get("roleArn")} | {
                                action.get("roleArn")
                                for stage in pipeline.get("stages", [])
                                for action in stage.get("actions", [])
                            }
                            for execution_role in pipeline_roles & self.role_arns:
                                observed.add(
                                    (
                                        f"arn:aws:codepipeline:{region}:{account}:{pipeline['name']}",
                                        execution_role,
                                    )
                                )
                            observed |= self.historical_pipeline_consumers(
                                client, pipeline, account, region
                            )
                    elif service == "stepfunctions":
                        for summary in self.pages(
                            client, "list_state_machines", "stateMachines"
                        ):
                            machine = client.describe_state_machine(
                                stateMachineArn=summary["stateMachineArn"]
                            )
                            if machine.get("roleArn") in self.role_arns:
                                observed.add(
                                    (summary["stateMachineArn"], machine["roleArn"])
                                )
                            for version in self.state_machine_versions(
                                client, summary["stateMachineArn"]
                            ):
                                if version.get("roleArn") in self.role_arns:
                                    observed.add(
                                        (summary["stateMachineArn"], version["roleArn"])
                                    )
                            # Alias inventory is required even though IAM evaluates
                            # version/alias execution against the base machine ARN.
                            self.state_machine_aliases(
                                client, summary["stateMachineArn"]
                            )
                            observed |= self.historical_state_machine_consumers(
                                client, summary["stateMachineArn"], machine
                            )
                    elif service == "bedrock-agentcore-control":
                        for summary in self.pages(client, "list_gateways", "items"):
                            gateway = client.get_gateway(
                                gatewayIdentifier=summary["gatewayId"]
                            )
                            if gateway.get("roleArn") in self.role_arns:
                                observed.add(
                                    (gateway["gatewayArn"], gateway["roleArn"])
                                )
                        self.agentcore_unsupported_consumers(client)
                    else:
                        self.verify_agentcore_model(
                            client.meta.service_model, frozenset({"GetABTest"})
                        )
                        for summary in self.pages(client, "list_ab_tests", "abTests"):
                            state = client.get_ab_test(abTestId=summary["abTestId"])
                            self.reject_agentcore_role(
                                state, ("roleArn",), "get_ab_test"
                            )
        require(
            observed == declared,
            "protected execution consumers are missing, unexpected or outside the manifest",
        )
        for role in self.roles.values():
            expected_ids = {
                resource["id"]
                for resource in self.resources.values()
                if resource.get("executionRoleArn") == role["arn"]
            }
            require(
                set(role["consumerResourceIds"]) == expected_ids,
                f"{role['id']}: the declared role consumer set is incomplete",
            )
        self.checks.append("all-enabled-region-execution-consumers")

    def verify_installed_policies(self) -> None:
        client = self.client(self.manifest["managementAccountId"], "organizations")
        org = client.describe_organization()["Organization"]
        require(
            org["Id"] == self.manifest["organizationId"]
            and org["MasterAccountId"] == self.manifest["managementAccountId"],
            "the live organization or management account differs",
        )
        policies = self.pages(
            client, "list_policies", "Policies", Filter="SERVICE_CONTROL_POLICY"
        )
        by_name: dict[str, list[dict[str, Any]]] = {}
        for policy in policies:
            by_name.setdefault(policy["Name"], []).append(policy)
        expected_names: set[str] = set()
        coverage: dict[str, set[str]] = {}
        bodies: dict[str, Any] = {}
        authority_accounts: dict[str, str] = {}
        authority_chunks: dict[str, set[int]] = {}
        for record in self.expected["policies"]:
            name = record.get("name")
            require(
                isinstance(name, str) and name not in expected_names,
                "installed policy names must be unique",
            )
            expected_names.add(name)
            require(
                SHA256.fullmatch(record.get("bodySha256", "")) is not None,
                "expected installed policy hashes are required",
            )
            require(
                isinstance(record.get("targetIds"), list) and record["targetIds"],
                "expected installed policy targets are required",
            )
            require(
                len(by_name.get(name, [])) == 1,
                "an expected installed policy is missing or ambiguous",
            )
            identity = by_name[name][0]["Id"]
            value = client.describe_policy(PolicyId=identity)["Policy"]["Content"]
            require(
                digest(document(value)) == record["bodySha256"],
                "installed protection policy content differs",
            )
            bodies[name] = document(value)
            targets = self.pages(
                client, "list_targets_for_policy", "Targets", PolicyId=identity
            )
            require(
                {target["TargetId"] for target in targets} == set(record["targetIds"]),
                "installed protection policy attachments differ",
            )
            coverage[name] = set(record["targetIds"])
            match = AUTHORITY_POLICY_NAME.fullmatch(name)
            if name.startswith("AgenticAI-ProtectedAuthority-"):
                require(
                    match is not None,
                    "authority policy name has an invalid account or chunk",
                )
            if match:
                account = match[1]
                require(
                    account in self.manifest["governedAccountIds"]
                    and coverage[name] == {account},
                    "an authority policy must target only its exact governed account",
                )
                authority_accounts[name] = account
                authority_chunks.setdefault(account, set()).add(int(match[2]))
        for account in self.manifest["governedAccountIds"]:
            chunks = authority_chunks.get(account, set())
            require(
                bool(chunks) and chunks == set(range(1, len(chunks) + 1)),
                "a governed account is missing its complete direct authority policy set",
            )
        for account in self.manifest["governedAccountIds"]:
            ancestors = {account}
            child = account
            while True:
                parents = self.pages(client, "list_parents", "Parents", ChildId=child)
                require(
                    len(parents) == 1,
                    "a governed account has an ambiguous organization placement",
                )
                parent = parents[0]
                require(parent["Id"] not in ancestors, "organization parent cycle")
                ancestors.add(parent["Id"])
                if parent["Type"] == "ROOT":
                    break
                require(
                    parent["Type"] == "ORGANIZATIONAL_UNIT",
                    "unknown organization parent type",
                )
                child = parent["Id"]
            require(
                all(
                    ancestors & targets
                    for name, targets in coverage.items()
                    if name not in authority_accounts
                    or authority_accounts[name] == account
                ),
                "a governed account is missing an expected protection policy attachment",
            )
            for record in self.expected["policies"]:
                if not ancestors & coverage[record["name"]]:
                    continue
                for statement in values(bodies[record["name"]].get("Statement", [])):
                    proof = self.regional_deny_proof(statement)
                    if proof is not None:
                        self.region_denies.setdefault(account, []).append(
                            {
                                "name": record["name"],
                                "bodySha256": record["bodySha256"],
                                "targetIds": record["targetIds"],
                                "allowedRegions": proof,
                            }
                        )
        self.checks.append("installed-scp-content-and-effective-attachments")

    @staticmethod
    def regional_deny_proof(statement: Any) -> list[str] | None:
        """Recognise only the exact unconditional SCP-06 discovery anchor shape.

        A partial action list, regional NotAction exemption, principal filter,
        extra condition or non-global resource scope is not proof. No read API
        error is converted into an empty inventory. A regional deny never
        proves the absence of historical service execution consumers.
        """
        if not isinstance(statement, dict) or set(statement) - {
            "Sid",
            "Effect",
            "NotAction",
            "Resource",
            "Condition",
        }:
            return None
        if statement.get("Effect") != "Deny" or statement.get("Resource") != "*":
            return None
        exceptions = statement.get("NotAction")
        if (
            not isinstance(exceptions, list)
            or not exceptions
            or not all(
                isinstance(action, str) and action.lower() in GLOBAL_REGION_EXEMPTIONS
                for action in exceptions
            )
        ):
            return None
        condition = statement.get("Condition")
        if not isinstance(condition, dict) or set(condition) != {"StringNotEquals"}:
            return None
        test = condition["StringNotEquals"]
        if not isinstance(test, dict) or set(test) != {"aws:RequestedRegion"}:
            return None
        regions = values(test["aws:RequestedRegion"])
        if not regions or not all(
            isinstance(region, str)
            and re.fullmatch(r"[a-z]{2}(-[a-z0-9]+)+-\d+", region)
            for region in regions
        ):
            return None
        return list(dict.fromkeys(regions))

    def run(self) -> dict[str, Any]:
        for account in sorted(self.profiles):
            self.client(account, "sts")
        self.verify_installed_policies()
        self.verify_roles()
        self.verify_resources()
        self.verify_consumers()
        return {
            "schemaVersion": 1,
            "kind": "protected-authority-live-inventory-verification",
            "verifiedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "manifestSha256": digest(self.manifest),
            "epoch": self.manifest["epoch"],
            "status": "passed",
            "readOnly": True,
            "checks": self.checks,
            "inventoryRegions": self.regions,
            "regionalDiscoveryAnchors": self.discovery_anchors,
            "limitations": [
                "A point-in-time read inventory does not replace live attack/control acceptance.",
                "Management and declared trusted-control accounts remain explicit authority roots.",
                "External Git/webhook/connection build sources, mixed action roles, and unsupported pipeline action providers fail verification.",
                "Supported CI inputs are approved inline builds using NO_SOURCE, exact protected S3, or actual enrolled CODEPIPELINE authority; images must be AWS curated or protected ECR, and pipeline sources/artifact stores must be protected.",
                "Instance profiles, service-managed and protected-role self-managed StackSets, protected CodeBuild fleets/sandboxes/batches/public resource-access authority, EXPRESS execution history and saved Distributed Map child history are unsupported and fail verification.",
                "Active protected CodeBuild builds, pipeline executions and STANDARD saved executions prevent quiet cutover; reusable terminal histories must reference an enrolled and fenced current base consumer.",
                "Saved CloudFormation change-set RoleARN is not exposed by read APIs. Every extant stack, including ordinary-role stacks, must have no pending, executable or unknown change sets; only explicitly terminal/nonexecutable metadata passes.",
                "Protected AgentCore authority is supported only for enrolled AWS_IAM Gateways with protected Lambda inputs or the exact bedrock-mantle connector and a protected REQUEST interceptor; all other role-bearing AgentCore families fail verification.",
                "Lambda EFS inputs, CloudFormation macros/transforms/nested templates and intrinsic-tag YAML are unsupported. Future SSM and secret template reads require exact protected dependency ARNs; unresolved or relative secret references fail verification.",
            ],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--profile-map",
        type=Path,
        required=True,
        help="JSON object mapping every declared account ID to an explicit AWS profile",
    )
    parser.add_argument(
        "--expected-policies",
        type=Path,
        required=True,
        help="JSON {manifestSha256,policies:[{name,bodySha256,targetIds}]} from the approved assembly",
    )
    args = parser.parse_args(argv)
    try:
        result = Verifier(
            read_json(args.manifest),
            read_json(args.profile_map),
            read_json(args.expected_policies),
        ).run()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except VerificationFailure as error:
        print(json.dumps({"status": "failed", "readOnly": True, "reason": str(error)}))
    except ClientError as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "readOnly": True,
                    "reason": "AWS inventory permission or service failure",
                    "errorCode": error.response.get("Error", {}).get("Code", "Unknown"),
                }
            )
        )
    except (BotoCoreError, OSError, ValueError, KeyError, TypeError) as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "readOnly": True,
                    "reason": "inventory is incomplete or input is invalid",
                    "errorType": type(error).__name__,
                }
            )
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
