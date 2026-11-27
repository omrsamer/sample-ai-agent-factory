# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Amazon Bedrock guardrails as the console's guardrail template shape (read-only)."""

from __future__ import annotations

from typing import Any

from portal_api.mappers.common import EPOCH_ISO, iso, text
from portal_api.models.wire import GuardrailTemplate

STATUS = {
    "READY": "active",
    "CREATING": "creating",
    "UPDATING": "updating",
    "VERSIONING": "updating",
    "FAILED": "failed",
    "DELETING": "deleting",
}


def _status(value: Any) -> str:
    return STATUS.get(str(value or "").upper(), "draft")


def from_summary(summary: dict[str, Any]) -> GuardrailTemplate:
    created = iso(summary.get("createdAt")) or EPOCH_ISO
    return GuardrailTemplate(
        template_id=summary["id"],
        name=summary.get("name") or summary["id"],
        description=text(summary.get("description")),
        status=_status(summary.get("status")),
        guardrail_id=summary["id"],
        guardrail_arn=summary.get("arn"),
        guardrail_version=text(summary.get("version")),
        created_at=created,
        updated_at=iso(summary.get("updatedAt")) or created,
    )


def from_detail(detail: dict[str, Any]) -> GuardrailTemplate:
    content = (detail.get("contentPolicy") or {}).get("filters") or []
    topics = (detail.get("topicPolicy") or {}).get("topics") or []
    sensitive = detail.get("sensitiveInformationPolicy") or {}
    words = detail.get("wordPolicy") or {}
    grounding = {f.get("type"): f for f in (detail.get("contextualGroundingPolicy") or {}).get("filters") or []}
    created = iso(detail.get("createdAt")) or EPOCH_ISO
    return GuardrailTemplate(
        template_id=detail["guardrailId"],
        name=detail.get("name") or detail["guardrailId"],
        description=text(detail.get("description")),
        status=_status(detail.get("status")),
        guardrail_id=detail["guardrailId"],
        guardrail_arn=detail.get("guardrailArn"),
        guardrail_version=text(detail.get("version")),
        content_filters=[
            {
                "type": f.get("type"),
                "input_strength": f.get("inputStrength", "NONE"),
                "output_strength": f.get("outputStrength", "NONE"),
            }
            for f in content
        ],
        denied_topics=[
            {"name": t.get("name"), "definition": t.get("definition", ""), "examples": list(t.get("examples") or [])}
            for t in topics
            if str(t.get("type", "DENY")).upper() == "DENY"
        ],
        pii_entities=[{"type": e.get("type"), "action": e.get("action")} for e in sensitive.get("piiEntities") or []],
        sensitive_regexes=[
            {
                "name": r.get("name"),
                "pattern": r.get("pattern"),
                "description": r.get("description"),
                "action": r.get("action"),
            }
            for r in sensitive.get("regexes") or []
        ],
        word_filter=(
            {
                "enable_profanity": any(m.get("type") == "PROFANITY" for m in words.get("managedWordLists") or []),
                "blocked_words": [w.get("text") for w in words.get("words") or [] if w.get("text")],
            }
            if words
            else None
        ),
        contextual_grounding=(
            {
                "enabled": True,
                "grounding_threshold": float((grounding.get("GROUNDING") or {}).get("threshold", 0.0)),
                "relevance_threshold": float((grounding.get("RELEVANCE") or {}).get("threshold", 0.0)),
            }
            if grounding
            else None
        ),
        created_at=created,
        updated_at=iso(detail.get("updatedAt")) or created,
    )
