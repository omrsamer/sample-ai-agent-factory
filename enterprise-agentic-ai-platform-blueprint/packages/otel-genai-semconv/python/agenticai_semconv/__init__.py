# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GenAI semantic-convention constants and normalization for Python agents.

The constants are generated from the same registry as the TypeScript package
(`packages/otel-genai-semconv/registry/gen-ai.json`), and `normalize_attributes`
is held to the same vectors, so spans written by an agent and spans read by the
evaluation gates and fleet views agree on names.
"""
from ._generated import *  # noqa: F401,F403
from ._generated import (
    GEN_AI_OPERATION_NAME,
    GEN_AI_OPERATIONS,
    GEN_AI_PROVIDER_NAME,
    GEN_AI_PROVIDERS,
    LEGACY_ATTRIBUTE_RENAMES,
    LEGACY_VALUE_RENAMES,
    LIST_ATTRIBUTES,
    REMOVED_ATTRIBUTES,
    REQUIRED_ATTRIBUTES,
)

__all__ = ["normalize_attributes", "validate_request_attributes"]


def _canonical_value(key, value):
    renames = LEGACY_VALUE_RENAMES.get(key)
    if renames and isinstance(value, str) and value in renames:
        value = renames[value]
    if key in LIST_ATTRIBUTES and not isinstance(value, (list, tuple)):
        value = [value]
    return value


def normalize_attributes(attributes):
    """Return ``(canonical_attributes, dropped_names)``.

    Legacy names and values are renamed, a single value of a list-typed
    attribute is wrapped in a list, and attributes the conventions removed are
    dropped and reported. When a legacy and a canonical name are both present
    the canonical one wins. Unknown attributes are kept unchanged.
    """
    out = {}
    dropped = []
    for key, value in attributes.items():
        if key in REMOVED_ATTRIBUTES:
            dropped.append(key)
            continue
        if key in LEGACY_ATTRIBUTE_RENAMES:
            continue
        out[key] = _canonical_value(key, value)
    for legacy, canonical in LEGACY_ATTRIBUTE_RENAMES.items():
        if legacy in attributes and canonical not in out:
            out[canonical] = _canonical_value(canonical, attributes[legacy])
    return out, sorted(dropped)


def validate_request_attributes(attributes):
    """Raise ``ValueError`` when required request attributes are missing or invalid."""
    normalized, _ = normalize_attributes(attributes)
    for key in REQUIRED_ATTRIBUTES:
        if key not in normalized:
            raise ValueError(f"OTel GenAI sem-conv: missing required {key}")
        if not isinstance(normalized[key], str):
            raise ValueError(f"OTel GenAI sem-conv: {key} must be string")
    if normalized[GEN_AI_OPERATION_NAME] not in GEN_AI_OPERATIONS:
        raise ValueError(
            f"OTel GenAI sem-conv: {GEN_AI_OPERATION_NAME} '{normalized[GEN_AI_OPERATION_NAME]}' is not a known operation"
        )
    if normalized[GEN_AI_PROVIDER_NAME] not in GEN_AI_PROVIDERS:
        raise ValueError(
            f"OTel GenAI sem-conv: {GEN_AI_PROVIDER_NAME} '{normalized[GEN_AI_PROVIDER_NAME]}' is not a known provider"
        )
