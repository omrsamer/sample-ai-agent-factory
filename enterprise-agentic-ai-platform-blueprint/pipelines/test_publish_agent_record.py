"""Tests for publish_agent_record.py (no network).

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("publish_agent_record", ROOT / "pipelines" / "publish_agent_record.py")
publisher = importlib.util.module_from_spec(SPEC)
sys.modules["publish_agent_record"] = publisher
SPEC.loader.exec_module(publisher)

REGISTRY = "abcdEFGH1234ijkl"
BASE = [
    "--registry-id", REGISTRY, "--region", "eu-west-1",
    "--tenant-id", "ws1", "--agent-id", "travel-agent", "--environment", "nonprod",
    "--owner-group", "travel-platform", "--business-purpose", "Books and changes trips.",
    "--risk-class", "limited", "--data-classification", "internal",
    "--cost-centre", "cc-100", "--record-version", "1.0.0",
]


def document(*extra: str) -> dict:
    return publisher.build_document(publisher.parse_args([*BASE, *extra]))


class FakeRegistry:
    """Records calls; behaves like the Registry control plane for one registry."""

    def __init__(self, records: list[dict] | None = None, settle_after: int = 0):
        self.records = {r["recordId"]: dict(r) for r in records or []}
        self.calls: list[tuple[str, dict]] = []
        # Number of reads that still report a transitional status after a write.
        self.settle_after = settle_after
        self.pending = 0

    def list_registry_records(self, **kwargs):
        self.calls.append(("list", kwargs))
        return {"registryRecords": [{"recordId": r["recordId"], "name": r["name"]} for r in self.records.values()]}

    def get_registry_record(self, **kwargs):
        self.calls.append(("get", kwargs))
        record = dict(self.records[kwargs["recordId"]])
        if self.pending > 0:
            self.pending -= 1
            record["status"] = "UPDATING"
        return record

    def create_registry_record(self, **kwargs):
        self.calls.append(("create", kwargs))
        self.records["rec000000001"] = {"recordId": "rec000000001", "status": "DRAFT", **kwargs}
        self.pending = self.settle_after
        return {"recordArn": f"arn:aws:agent-registry:eu-west-1:111111111111:registry/{REGISTRY}/record/rec000000001"}

    def update_registry_record(self, **kwargs):
        self.calls.append(("update", kwargs))
        # The update operation wraps each field in `optionalValue`.
        data = kwargs["descriptors"]["optionalValue"]["custom"]["optionalValue"]["data"]["optionalValue"]
        self.records[kwargs["recordId"]].update(
            {"descriptors": {"custom": {"data": data}}, "recordVersion": kwargs["recordVersion"], "status": "DRAFT"}
        )
        self.pending = self.settle_after
        return {}

    def submit_registry_record_for_approval(self, **kwargs):
        self.calls.append(("submit", kwargs))
        return {}

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def existing(doc: dict, record_type: str = "CUSTOM") -> dict:
    return {
        "recordId": "rec000000009",
        "name": publisher.record_name(doc["tenantId"], doc["agentId"], doc["environment"]),
        "recordType": record_type,
        "status": "APPROVED",
        "descriptors": {"custom": {"data": json.dumps(doc)}},
    }


def test_document_carries_required_and_optional_fields_and_matches_the_schema():
    doc = document(
        "--runtime-arn", "arn:aws:bedrock-agentcore:eu-west-1:111111111111:runtime/travel_agent-AbC123",
        "--subscribed-tool-id", "tool-ping", "--subscribed-tool-id", "tool-echo", "--subscribed-tool-id", "tool-echo",
        "--golden-path-name", "agenticai-task-agent", "--golden-path-version", "1.2.0",
        "--evaluation-verdict", "passed", "--evaluation-run-id", "exec-1",
        "--sponsor", "jane.doe@example.com", "--review-by", "2027-06-30",
    )
    assert doc["sponsor"] == "jane.doe@example.com"
    assert doc["reviewBy"] == "2027-06-30"
    assert doc["schemaVersion"] == "agenticai.agent-governance/1.0"
    assert doc["subscribedToolIds"] == ["tool-echo", "tool-ping"]
    assert doc["goldenPath"] == {"name": "agenticai-task-agent", "version": "1.2.0"}
    assert doc["evaluation"] == {"verdict": "passed", "runId": "exec-1"}
    assert "contact" not in doc


@pytest.mark.parametrize(
    "extra, message",
    [
        (["--risk-class", "tiny"], "riskClass must be one of"),
        (["--runtime-arn", "arn:aws:lambda:eu-west-1:111111111111:function:x"], "runtimeArn does not match"),
        (["--record-version", "v1"], "recordVersion does not match"),
        (["--golden-path-name", "only-name"], "go together"),
        (["--policy-engine-mode", "MAYBE"], "policyEngineMode must be one of"),
        (["--review-by", "next year"], "reviewBy does not match"),
    ],
)
def test_invalid_input_is_refused_before_any_call(extra, message):
    with pytest.raises(publisher.PublishError, match=message):
        document(*extra)


def test_new_record_is_created_as_custom_and_submitted_only_on_request():
    doc = document()
    registry = FakeRegistry()
    result = publisher.publish(registry, REGISTRY, doc, submit=False, dry_run=False)
    assert result == {"action": "created", "name": "agent-ws1-travel-agent-nonprod", "recordId": "rec000000001"}
    create = dict(registry.calls)["create"]
    assert create["recordType"] == "CUSTOM"
    assert json.loads(create["descriptors"]["custom"]["data"]) == doc
    assert "submit" not in registry.names()

    registry = FakeRegistry()
    assert publisher.publish(registry, REGISTRY, doc, submit=True, dry_run=False)["submitted"] is True
    assert registry.names()[-1] == "submit"


def test_identical_record_is_left_untouched():
    doc = document()
    registry = FakeRegistry([existing(doc)])
    result = publisher.publish(registry, REGISTRY, doc, submit=True, dry_run=False)
    assert result["action"] == "unchanged"
    assert registry.names() == ["list", "get"]


def test_changed_document_updates_the_same_record():
    registry = FakeRegistry([existing(document())])
    changed = document("--record-version", "1.1.0")
    result = publisher.publish(registry, REGISTRY, changed, submit=True, dry_run=False)
    assert result == {"action": "updated", "name": "agent-ws1-travel-agent-nonprod", "recordId": "rec000000009", "submitted": True}
    assert registry.names() == ["list", "get", "update", "get", "submit"]
    stored = json.loads(registry.records["rec000000009"]["descriptors"]["custom"]["data"])
    assert stored["recordVersion"] == "1.1.0"


def test_submission_waits_for_the_record_to_settle(monkeypatch):
    monkeypatch.setattr(publisher.time, "sleep", lambda _seconds: None)
    registry = FakeRegistry(settle_after=2)
    publisher.publish(registry, REGISTRY, document(), submit=True, dry_run=False)
    assert registry.names() == ["list", "create", "get", "get", "get", "submit"]

    stuck = FakeRegistry(settle_after=10**6)
    clock = iter(range(0, 10**6, 60))
    monkeypatch.setattr(publisher.time, "monotonic", lambda: next(clock))
    with pytest.raises(publisher.PublishError, match="still UPDATING"):
        publisher.publish(stuck, REGISTRY, document(), submit=True, dry_run=False)
    assert "submit" not in stuck.names()


def test_an_unchanged_draft_is_submitted_but_an_approved_record_is_not():
    doc = document()
    draft = existing(doc)
    draft["status"] = "DRAFT"
    registry = FakeRegistry([draft])
    assert publisher.publish(registry, REGISTRY, doc, submit=True, dry_run=False)["submitted"] is True
    assert registry.names() == ["list", "get", "submit"]
    approved = FakeRegistry([existing(doc)])
    assert "submitted" not in publisher.publish(approved, REGISTRY, doc, submit=True, dry_run=False)


def test_dry_run_writes_nothing():
    doc = document()
    registry = FakeRegistry()
    assert publisher.publish(registry, REGISTRY, doc, submit=True, dry_run=True)["action"] == "would-create"
    registry_with_old = FakeRegistry([existing(document("--record-version", "0.9.0"))])
    assert publisher.publish(registry_with_old, REGISTRY, doc, submit=True, dry_run=True)["action"] == "would-update"
    assert not {"create", "update", "submit"} & set(registry.names() + registry_with_old.names())


def test_refuses_to_overwrite_a_record_it_does_not_own():
    doc = document()
    tool = existing(doc)
    tool["descriptors"] = {"custom": {"data": json.dumps({"schemaVersion": "agenticai.tool-governance/1.0"})}}
    with pytest.raises(publisher.PublishError, match="not an agent governance record"):
        publisher.publish(FakeRegistry([tool]), REGISTRY, doc, submit=False, dry_run=False)
    with pytest.raises(publisher.PublishError, match="exists with type"):
        publisher.publish(FakeRegistry([existing(doc, "MCP")]), REGISTRY, doc, submit=False, dry_run=False)
    duplicate = existing(doc)
    duplicate["recordId"] = "rec000000010"
    with pytest.raises(publisher.PublishError, match="refusing to choose one"):
        publisher.publish(FakeRegistry([existing(doc), duplicate]), REGISTRY, doc, submit=False, dry_run=False)


def test_it_never_approves_a_record():
    source = (ROOT / "pipelines" / "publish_agent_record.py").read_text(encoding="utf-8")
    assert "update_registry_record_status" not in source


def test_the_portal_reads_the_same_schema():
    canonical = ROOT / "packages" / "agent-registry" / "schemas" / "agent-governance-1.0.json"
    portal = ROOT / "apps" / "agent-factory-portal" / "api" / "schemas" / "agent-governance-1.0.json"
    assert json.loads(canonical.read_text()) == json.loads(portal.read_text())
