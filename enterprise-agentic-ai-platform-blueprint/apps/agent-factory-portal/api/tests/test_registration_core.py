# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The Python port of the authorization core, run against the vectors shared with the TypeScript core."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from portal_api import registration_core as core

VECTORS_PATH = (
    Path(__file__).resolve().parents[4] / "packages" / "agent-registry" / "vectors" / "registration-decisions.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def assemble(vector: dict) -> dict:
    """A vector's request as the core receives it: the request fields plus action and principal."""
    return {**(vector["request"] or {}), "action": vector["action"], "principal": vector["principal"]}


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(vector):
    decision = core.evaluate_registration_request(assemble(vector), vector["currentState"])
    assert decision.allowed is vector["expected"]["allowed"], decision.reason
    assert vector["expected"]["reasonContains"] in decision.reason
    assert decision.http_status == (None if decision.allowed else 403)


def test_vectors_have_the_agreed_shape_and_unique_names():
    names = [v["name"] for v in VECTORS]
    assert len(names) == len(set(names))
    for vector in VECTORS:
        assert set(vector) == {"name", "principal", "action", "request", "currentState", "expected"}
        assert set(vector["expected"]) == {"allowed", "reasonContains"}
        assert isinstance(vector["expected"]["allowed"], bool) and vector["expected"]["reasonContains"]


def test_vectors_cover_every_rule_identifier_and_both_outcomes():
    text = " ".join(v["expected"]["reasonContains"] for v in VECTORS)
    for identifier in ("REG-07-N", "REG-07-P", "REG-08-N", "REG-09-N", "REG-10-N", "REG-11-N", "REG-11-P", "REG-12-N"):
        assert identifier in text, identifier
    for action in ("create", "update", "delete", "approve"):
        outcomes = {v["expected"]["allowed"] for v in VECTORS if v["action"] == action}
        assert outcomes == {True, False}, action
    for phrase in (
        "missing or incomplete principal",
        "missing tenantId",
        "unknown action",
        "does not exist",
        "cross-tenant",
    ):
        assert phrase in text, phrase


@pytest.mark.parametrize("request_value", [None, "", 0, "create", ["create"], 42])
def test_malformed_request_denies(request_value):
    decision = core.evaluate_registration_request(request_value)
    assert (decision.allowed, decision.reason, decision.http_status) == (False, "malformed request", 403)


def test_changes_approved_reference_matches_the_typescript_helper():
    state = {"references": {"inferenceTargetArn": "a", "modelId": "m", "rateProfile": "r"}}
    assert core.changes_approved_reference({"proposedReferences": {"modelId": "x"}}, state) is True
    assert core.changes_approved_reference({"proposedReferences": {"modelId": "m"}}, state) is False
    assert core.changes_approved_reference({"proposedReferences": {"other": "x"}}, state) is False
    assert core.changes_approved_reference({}, state) is False
    assert core.changes_approved_reference({"proposedReferences": {"modelId": "x"}}, {}) is False
    assert core.APPROVED_REFERENCE_KEYS == ("inferenceTargetArn", "modelId", "rateProfile")
