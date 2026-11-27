"""Tests for agent_factory_portal_teardown.py (no network).

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "agent_factory_portal_teardown", Path(__file__).resolve().parent / "agent_factory_portal_teardown.py"
)
teardown = importlib.util.module_from_spec(SPEC)
sys.modules["agent_factory_portal_teardown"] = teardown
SPEC.loader.exec_module(teardown)

STACK = "AgenticAI-AgentFactoryPortal-nonprod"
RESOURCES = [
    {"ResourceType": "AWS::S3::Bucket", "PhysicalResourceId": "portal-content", "ResourceStatus": "CREATE_COMPLETE"},
    {"ResourceType": "AWS::S3::Bucket", "PhysicalResourceId": "portal-access-logs", "ResourceStatus": "CREATE_COMPLETE"},
    {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "portal-api-fn", "ResourceStatus": "CREATE_COMPLETE"},
    {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "portal-provider-fn", "ResourceStatus": "UPDATE_COMPLETE"},
    {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "already-gone", "ResourceStatus": "DELETE_COMPLETE"},
    {"ResourceType": "AWS::Cognito::UserPool", "PhysicalResourceId": "pool-1", "ResourceStatus": "CREATE_COMPLETE"},
    {"ResourceType": "AWS::IAM::Role", "PhysicalResourceId": "some-role", "ResourceStatus": "CREATE_COMPLETE"},
]


class Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_kwargs):
        return list(self.pages)


class FakeCloudFormation:
    """A stack whose delete fails `failures` times, then succeeds."""

    def __init__(self, failures: int = 0, exists: bool = True):
        self.failures = failures
        self.exists = exists
        self.status = "CREATE_COMPLETE"
        self.deletes: list[dict] = []

    def describe_stacks(self, StackName):  # noqa: N803
        if not self.exists or self.status == "DELETE_COMPLETE":
            raise RuntimeError(f"Stack with id {StackName} does not exist")
        return {"Stacks": [{"StackStatus": self.status}]}

    def get_paginator(self, name):
        assert name == "list_stack_resources"
        return Paginator([{"StackResourceSummaries": RESOURCES}])

    def delete_stack(self, **kwargs):
        self.deletes.append(kwargs)
        if self.failures > 0:
            self.failures -= 1
            self.status = "DELETE_FAILED"
        else:
            self.status = "DELETE_COMPLETE"


class FakeS3:
    def __init__(self, contents: dict[str, int] | None = None, missing: tuple[str, ...] = ()):
        self.contents = dict(contents or {})
        self.missing = set(missing)
        self.emptied: list[str] = []

    def get_paginator(self, name):
        assert name == "list_object_versions"
        s3 = self

        class Versions:
            def paginate(self, Bucket):  # noqa: N803
                if Bucket in s3.missing:
                    raise RuntimeError("An error occurred (NoSuchBucket)")
                count = s3.contents.get(Bucket, 0)
                return [
                    {
                        "Versions": [{"Key": f"k{i}", "VersionId": f"v{i}"} for i in range(count)],
                        "DeleteMarkers": [{"Key": "marker", "VersionId": "m"}] if count else [],
                    }
                ]

        return Versions()

    def delete_objects(self, Bucket, Delete):  # noqa: N803
        self.emptied.append(Bucket)
        self.contents[Bucket] = 0


class FakeLogs:
    def __init__(self, missing: tuple[str, ...] = ()):
        self.missing = set(missing)
        self.deleted: list[str] = []

    def delete_log_group(self, logGroupName):  # noqa: N803
        if logGroupName in self.missing:
            raise RuntimeError("ResourceNotFoundException")
        self.deleted.append(logGroupName)


def test_capture_records_only_what_the_stack_owns():
    plan = teardown.capture(FakeCloudFormation(), STACK)
    assert plan.buckets == ["portal-access-logs", "portal-content"]
    assert plan.functions == ["portal-api-fn", "portal-provider-fn"]
    assert plan.log_groups == ["/aws/lambda/portal-api-fn", "/aws/lambda/portal-provider-fn"]
    assert any("pool-1" in line for line in plan.retained)
    assert not any("some-role" in line for line in plan.lines())


@pytest.mark.parametrize(
    "name",
    [
        "AgenticAI-Platform-GuardrailStack",
        "Nonprod-Registry",
        "AgenticAI-AgentFactoryPortal-staging",
        # The Registries hold the system of record: removing one is a deliberate operator act, not a teardown step.
        "AgenticAI-AgentFactoryPortal-AgentRegistry-nonprod",
        "AgenticAI-AgentFactoryPortal-DiscoveryRegistry",
        "anything",
    ],
)
def test_it_refuses_a_stack_that_is_not_a_portal_stack(name):
    with pytest.raises(teardown.TeardownError, match="not an Agent Factory Portal stack"):
        teardown.capture(FakeCloudFormation(), name)


@pytest.mark.parametrize(
    "name",
    [
        "AgenticAI-AgentFactoryPortal-nonprod",
        "AgenticAI-AgentFactoryPortal-prod",
        "AgenticAI-AgentFactoryPortal-Edge-nonprod",
        "AgenticAI-AgentFactoryPortal-FleetReader-prod",
        "AgenticAI-AgentFactoryPortal-Containment-nonprod",
        "AgenticAI-AgentFactoryPortal-ExternalReader-prod",
    ],
)
def test_portal_stage_stacks_are_accepted(name):
    assert teardown.capture(FakeCloudFormation(), name).stack_name == name


def test_a_clean_delete_empties_nothing_and_removes_the_service_log_groups():
    cloudformation, s3, logs = FakeCloudFormation(), FakeS3({"portal-access-logs": 3}), FakeLogs()
    plan = teardown.capture(cloudformation, STACK)
    teardown.execute(plan, cloudformation, s3, logs, sleep=lambda _s: None, report=lambda _m: None)
    assert len(cloudformation.deletes) == 1
    assert s3.emptied == []
    assert logs.deleted == ["/aws/lambda/portal-api-fn", "/aws/lambda/portal-provider-fn"]


def test_a_failed_delete_empties_the_captured_buckets_and_retries_with_the_same_role():
    cloudformation, s3, logs = FakeCloudFormation(failures=2), FakeS3({"portal-access-logs": 3, "other-bucket": 9}), FakeLogs()
    plan = teardown.capture(cloudformation, STACK)
    teardown.execute(
        plan, cloudformation, s3, logs, role_arn="arn:aws:iam::111111111111:role/scoped", sleep=lambda _s: None, report=lambda _m: None
    )
    assert len(cloudformation.deletes) == 3
    assert all(call["RoleARN"].endswith("role/scoped") for call in cloudformation.deletes)
    assert set(s3.emptied) == {"portal-access-logs"}
    assert s3.contents["other-bucket"] == 9, "a bucket the stack does not own must not be touched"


def test_it_gives_up_after_the_attempt_limit_without_removing_log_groups():
    cloudformation, s3, logs = FakeCloudFormation(failures=10), FakeS3(), FakeLogs()
    plan = teardown.capture(cloudformation, STACK)
    with pytest.raises(teardown.TeardownError, match="could not be deleted in 3 attempts"):
        teardown.execute(plan, cloudformation, s3, logs, attempts=3, sleep=lambda _s: None, report=lambda _m: None)
    assert logs.deleted == []


def test_missing_buckets_and_log_groups_are_tolerated():
    cloudformation = FakeCloudFormation(failures=1)
    s3 = FakeS3(missing=("portal-content", "portal-access-logs"))
    logs = FakeLogs(missing=("/aws/lambda/portal-api-fn",))
    plan = teardown.capture(cloudformation, STACK)
    teardown.execute(plan, cloudformation, s3, logs, sleep=lambda _s: None, report=lambda _m: None)
    assert logs.deleted == ["/aws/lambda/portal-provider-fn"]


def test_a_stack_stuck_in_progress_times_out():
    cloudformation = FakeCloudFormation()
    cloudformation.delete_stack = lambda **_kwargs: setattr(cloudformation, "status", "DELETE_IN_PROGRESS")
    plan = teardown.capture(cloudformation, STACK)
    with pytest.raises(teardown.TeardownError, match="still DELETE_IN_PROGRESS"):
        teardown.execute(plan, cloudformation, FakeS3(), FakeLogs(), sleep=lambda _s: None, timeout=30, report=lambda _m: None)
