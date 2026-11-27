# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon Bedrock AgentCore control-plane reads (cell accounts, reader role)."""

from __future__ import annotations

import logging
from typing import Any

from portal_api.aws.parallel import pmap
from portal_api.aws.session import error_code, paginate

logger = logging.getLogger(__name__)

# The only runtime environment variable the portal reads. Environment variables are
# never returned to callers; this one names the Tool Gateway the runtime calls.
GATEWAY_URL_ENV = "AGENTCORE_GATEWAY_URL"


def _tags(client: Any, arn: str) -> dict[str, str]:
    try:
        return dict(client.list_tags_for_resource(resourceArn=arn).get("tags") or {})
    except Exception as exc:  # noqa: BLE001 - tags are optional enrichment
        logger.warning("Tags could not be read: %s", error_code(exc))
        return {}


def list_runtimes(client: Any) -> list[dict[str, Any]]:
    """Runtimes in one account and Region: ``{"summary", "detail", "tags"}`` each."""
    summaries = paginate(client, "list_agent_runtimes", "agentRuntimes")

    def fetch(summary: dict[str, Any]) -> dict[str, Any]:
        detail: dict[str, Any] = {}
        try:
            response = client.get_agent_runtime(agentRuntimeId=summary["agentRuntimeId"])
            env = response.get("environmentVariables") or {}
            detail = {
                "createdAt": response.get("createdAt"),
                "gatewayUrl": env.get(GATEWAY_URL_ENV),
            }
        except Exception as exc:  # noqa: BLE001 - the summary alone is still useful
            logger.warning("Runtime detail could not be read: %s", error_code(exc))
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
