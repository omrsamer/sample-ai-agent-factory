# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon Bedrock guardrail reads (platform account, the function's own role)."""

from __future__ import annotations

import logging
from typing import Any

from portal_api.aws.parallel import pmap
from portal_api.aws.session import error_code, paginate

logger = logging.getLogger(__name__)


def list_tagged(client: Any, tag_key: str, tag_value: str) -> list[dict[str, Any]]:
    """Guardrail summaries (working drafts), filtered by the blueprint tag when one is configured.

    With no tag key, every guardrail in the account and Region is returned and tags are not read.
    """
    summaries = paginate(client, "list_guardrails", "guardrails")
    if not tag_key:
        return summaries

    def tagged(summary: dict[str, Any]) -> bool:
        tags = client.list_tags_for_resource(resourceARN=summary["arn"]).get("tags") or []
        return any(t.get("key") == tag_key and t.get("value") == tag_value for t in tags)

    selected: list[dict[str, Any]] = []
    for summary, result in zip(summaries, pmap(tagged, summaries), strict=True):
        if isinstance(result, BaseException):
            logger.warning("Guardrail tags could not be read: %s", error_code(result))
        elif result:
            selected.append(summary)
    return selected


def get(client: Any, guardrail_id: str) -> dict[str, Any]:
    response = client.get_guardrail(guardrailIdentifier=guardrail_id)
    response.pop("ResponseMetadata", None)
    return response
