# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Python side of the semantic-convention parity checks."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agenticai_semconv as semconv  # noqa: E402

REGISTRY = json.loads((PACKAGE / "registry" / "gen-ai.json").read_text(encoding="utf-8"))
VECTORS = json.loads((PACKAGE / "registry" / "normalization-vectors.json").read_text(encoding="utf-8"))["vectors"]


def test_generated_modules_match_the_registry():
    result = subprocess.run(
        [sys.executable, str(PACKAGE / "scripts" / "generate.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_constants_cover_the_registry():
    merged = {**REGISTRY["attributes"], **REGISTRY["extensions"]}
    assert semconv.ATTRIBUTE_TYPES == {k: v["type"] for k, v in merged.items()}
    assert list(semconv.GEN_AI_OPERATIONS) == REGISTRY["operations"]
    assert list(semconv.GEN_AI_PROVIDERS) == REGISTRY["providers"]
    assert semconv.SEMCONV_UPSTREAM_VERSION == REGISTRY["upstream"]["version"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_normalization_vector(vector):
    attributes, dropped = semconv.normalize_attributes(vector["input"])
    assert attributes == vector["expected"]
    assert dropped == vector["dropped"]


def test_validation_accepts_legacy_names_and_rejects_unknown_values():
    semconv.validate_request_attributes(
        {"gen_ai.operation.name": "tool_call", "gen_ai.system": "aws.bedrock", "gen_ai.request.model": "m", "agenticai.tenant.id": "t"}
    )
    with pytest.raises(ValueError, match="missing required gen_ai.provider.name"):
        semconv.validate_request_attributes({"gen_ai.operation.name": "chat", "gen_ai.request.model": "m", "agenticai.tenant.id": "t"})
    with pytest.raises(ValueError, match="not a known operation"):
        semconv.validate_request_attributes(
            {"gen_ai.operation.name": "summon", "gen_ai.provider.name": "aws.bedrock", "gen_ai.request.model": "m", "agenticai.tenant.id": "t"}
        )
