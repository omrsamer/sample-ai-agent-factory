# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon Bedrock AgentCore control-plane reads (cell accounts, reader role)."""

from __future__ import annotations

import logging
from typing import Any

from botocore.exceptions import ClientError

from portal_api import containment_policy
from portal_api.aws.parallel import pmap
from portal_api.aws.session import error_code, paginate

logger = logging.getLogger(__name__)

# The only runtime environment variable the portal reads. Environment variables are
# never returned to callers; this one names the Tool Gateway the runtime calls.
GATEWAY_URL_ENV = "AGENTCORE_GATEWAY_URL"
# A Runtime names a guardrail when a variable whose name contains this marker has a value
# (the blueprint sets AGENTCORE_GUARDRAIL_ID; other agents use names such as GUARDRAIL_ID).
GUARDRAIL_ENV_MARKER = "GUARDRAIL"
# The variable the blueprint sets to the platform inference gateway's URL, in every variant that sets one.
INFERENCE_GATEWAY_ENV: tuple[str, ...] = ("AGENTCORE_INFERENCE_GATEWAY_URL",)


def _tags(client: Any, arn: str) -> dict[str, str]:
    try:
        return dict(client.list_tags_for_resource(resourceArn=arn).get("tags") or {})
    except Exception as exc:  # noqa: BLE001 - tags are optional enrichment
        logger.warning("Tags could not be read: %s", error_code(exc))
        return {}


def resource_policy(client: Any, resource_arn: str) -> str | None:
    """The resource policy of a Runtime as stored, or ``None`` when it has none."""
    try:
        return client.get_resource_policy(resourceArn=resource_arn).get("policy") or None
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            return None
        raise


def containment_state(client: Any, runtime_arn: str) -> str | None:
    """What the Runtime's resource policy says about its containment. ``None`` when it cannot be read.

    One of ``containment_policy.CONTAINED``, ``FOREIGN`` (a statement carries
    the portal's Sid but does not deny invocation) and ``ABSENT``.
    ``runtime_arn`` is the ARN as the service or the portal spells it, never
    as a caller wrote it.
    """
    try:
        return containment_policy.state(resource_policy(client, runtime_arn), runtime_arn)
    except Exception as exc:  # noqa: BLE001 - unknown is reported as unknown
        logger.warning("Runtime resource policy could not be read: %s", error_code(exc))
        return None


def contained(client: Any, runtime_arn: str) -> bool | None:
    """Whether the Runtime's resource policy holds the containment statement. ``None`` when it cannot be read."""
    state = containment_state(client, runtime_arn)
    return None if state is None else state == containment_policy.CONTAINED


def guardrail_covered(env: dict[str, Any]) -> bool:
    """Whether the Runtime's configuration names a guardrail or the platform inference gateway.

    In the blueprint a guardrail is applied to every model call at the
    inference gateway, so a Runtime that is configured with the gateway is
    covered even when it names no guardrail of its own. Only the variable
    names and whether they are empty are looked at; no value leaves this
    function or is logged.
    """

    def has_value(value: Any) -> bool:
        return bool(str(value if value is not None else "").strip())

    names_guardrail = any(GUARDRAIL_ENV_MARKER in key.upper() and has_value(value) for key, value in env.items())
    names_gateway = any(has_value(env.get(name)) for name in INFERENCE_GATEWAY_ENV)
    return names_guardrail or names_gateway


def list_runtimes(client: Any) -> list[dict[str, Any]]:
    """Runtimes in one account and Region: ``{"summary", "detail", "tags"}`` each."""
    summaries = paginate(client, "list_agent_runtimes", "agentRuntimes")

    def fetch(summary: dict[str, Any]) -> dict[str, Any]:
        detail: dict[str, Any] = {}
        try:
            response = client.get_agent_runtime(agentRuntimeId=summary["agentRuntimeId"])
            env = response.get("environmentVariables") or {}
            authorizer = response.get("authorizerConfiguration") or {}
            # Only derived facts leave this function. Environment values are never returned.
            detail = {
                "createdAt": response.get("createdAt"),
                "gatewayUrl": env.get(GATEWAY_URL_ENV),
                "guardrailConfigured": guardrail_covered(env),
                "authorizerType": "CUSTOM_JWT" if authorizer.get("customJWTAuthorizer") else "AWS_IAM",
            }
        except Exception as exc:  # noqa: BLE001 - the summary alone is still useful
            logger.warning("Runtime detail could not be read: %s", error_code(exc))
        detail["contained"] = contained(client, summary["agentRuntimeArn"])
        return {"summary": summary, "detail": detail, "tags": _tags(client, summary["agentRuntimeArn"])}

    return [r for r in pmap(fetch, summaries) if not isinstance(r, BaseException)]


def list_runtime_versions(client: Any, runtime_id: str) -> list[dict[str, Any]]:
    return paginate(client, "list_agent_runtime_versions", "agentRuntimes", agentRuntimeId=runtime_id)


def list_gateways(client: Any) -> list[dict[str, Any]]:
    """Gateways in one account and Region: ``{"gateway", "targets", "tags"}`` each."""
    summaries = paginate(client, "list_gateways", "items")

    def fetch(summary: dict[str, Any]) -> dict[str, Any]:
        gateway_id = summary["gatewayId"]
        gateway = client.get_gateway(gatewayIdentifier=gateway_id)
        gateway.pop("ResponseMetadata", None)
        target_summaries = paginate(client, "list_gateway_targets", "items", gatewayIdentifier=gateway_id)

        def fetch_target(target: dict[str, Any]) -> dict[str, Any]:
            try:
                detail = client.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target["targetId"])
                detail.pop("ResponseMetadata", None)
                return {**target, **detail}
            except Exception as exc:  # noqa: BLE001 - keep the summary
                logger.warning("Gateway target could not be read: %s", error_code(exc))
                return target

        targets = [fetch_target(t) for t in target_summaries]
        return {"gateway": gateway, "targets": targets, "tags": _tags(client, gateway["gatewayArn"])}

    bundles: list[dict[str, Any]] = []
    for result in pmap(fetch, summaries):
        if isinstance(result, BaseException):
            logger.warning("Gateway could not be read: %s", error_code(result))
        else:
            bundles.append(result)
    return bundles


def list_policies(client: Any, policy_engine_id: str) -> list[dict[str, Any]]:
    """Policies of one policy engine, each with its Cedar statement."""
    policies = paginate(client, "list_policies", "policies", policyEngineId=policy_engine_id)
    complete: list[dict[str, Any]] = []
    for policy in policies:
        if not ((policy.get("definition") or {}).get("cedar") or {}).get("statement"):
            detail = client.get_policy(policyEngineId=policy_engine_id, policyId=policy["policyId"])
            detail.pop("ResponseMetadata", None)
            policy = {**policy, **detail}
        complete.append(policy)
    return complete
