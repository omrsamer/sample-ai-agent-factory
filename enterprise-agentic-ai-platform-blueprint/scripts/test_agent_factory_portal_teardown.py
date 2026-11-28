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
    # A function that an earlier attempt already deleted is kept: its service log group outlives it.
    assert plan.functions == ["already-gone", "portal-api-fn", "portal-provider-fn"]
    assert plan.log_groups == ["/aws/lambda/already-gone", "/aws/lambda/portal-api-fn", "/aws/lambda/portal-provider-fn"]
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
    assert logs.deleted == ["/aws/lambda/already-gone", "/aws/lambda/portal-api-fn", "/aws/lambda/portal-provider-fn"]


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
    assert logs.deleted == ["/aws/lambda/already-gone", "/aws/lambda/portal-provider-fn"]


def test_a_stack_stuck_in_progress_times_out():
    cloudformation = FakeCloudFormation()
    cloudformation.delete_stack = lambda **_kwargs: setattr(cloudformation, "status", "DELETE_IN_PROGRESS")
    plan = teardown.capture(cloudformation, STACK)
    with pytest.raises(teardown.TeardownError, match="still DELETE_IN_PROGRESS"):
        teardown.execute(plan, cloudformation, FakeS3(), FakeLogs(), sleep=lambda _s: None, timeout=30, report=lambda _m: None)


MAPPING = {
    "ResourceType": "AWS::Lambda::EventSourceMapping",
    "LogicalResourceId": "SweeperFunctionSqsEventSource",
    "PhysicalResourceId": "11111111-2222-4333-8444-555555555555",
    "ResourceStatus": "DELETE_FAILED",
}


class StackWithMapping(FakeCloudFormation):
    """A stack whose event source mapping is reported as not deleted until it is left out."""

    def __init__(self, status: str = "CREATE_COMPLETE"):
        super().__init__()
        self.status = status

    def get_paginator(self, name):
        assert name == "list_stack_resources"
        return Paginator([{"StackResourceSummaries": [*RESOURCES, MAPPING]}])

    def delete_stack(self, **kwargs):
        self.deletes.append(kwargs)
        left_out = kwargs.get("RetainResources") == [MAPPING["LogicalResourceId"]]
        self.status = "DELETE_COMPLETE" if left_out else "DELETE_FAILED"


class FakeFunctions:
    def __init__(self, existing: tuple[str, ...] = (), denied: bool = False):
        self.existing = set(existing)
        self.denied = denied
        self.asked: list[str] = []

    def get_event_source_mapping(self, UUID):  # noqa: N803
        self.asked.append(UUID)
        if self.denied:
            raise ServiceError("AccessDeniedException")
        if UUID not in self.existing:
            raise ServiceError("ResourceNotFoundException")
        return {"UUID": UUID, "State": "Enabled"}


class ServiceError(Exception):
    """Shaped like a botocore ClientError: the code is in ``response``, not in the text."""

    def __init__(self, code: str):
        super().__init__("the service refused the call")
        self.response = {"Error": {"Code": code}}


def test_a_mapping_that_is_gone_but_reported_as_failed_is_left_out_of_the_next_attempt():
    cloudformation, functions = StackWithMapping(), FakeFunctions()
    plan = teardown.capture(cloudformation, STACK)
    said: list[str] = []
    teardown.execute(
        plan, cloudformation, FakeS3(), FakeLogs(), role_arn="arn:aws:iam::111111111111:role/scoped",
        sleep=lambda _s: None, report=said.append, functions=functions,
    )
    # The first attempt names nothing: CloudFormation accepts the list only for a failed delete.
    assert "RetainResources" not in cloudformation.deletes[0]
    assert cloudformation.deletes[1]["RetainResources"] == [MAPPING["LogicalResourceId"]]
    assert all(call["RoleARN"].endswith("role/scoped") for call in cloudformation.deletes)
    assert len(cloudformation.deletes) == 2
    assert functions.asked == [MAPPING["PhysicalResourceId"]]
    assert any("no longer exist" in line for line in said)


@pytest.mark.parametrize("functions", [FakeFunctions(existing=(MAPPING["PhysicalResourceId"],)), FakeFunctions(denied=True)])
def test_a_mapping_that_still_exists_or_cannot_be_read_is_never_left_out(functions):
    cloudformation = StackWithMapping()
    plan = teardown.capture(cloudformation, STACK)
    with pytest.raises(teardown.TeardownError, match="could not be deleted"):
        teardown.execute(
            plan, cloudformation, FakeS3(), FakeLogs(), attempts=3, sleep=lambda _s: None, report=lambda _m: None, functions=functions
        )
    assert all("RetainResources" not in call for call in cloudformation.deletes)


def test_a_stack_already_left_in_a_failed_delete_is_checked_before_the_first_attempt():
    cloudformation, functions = StackWithMapping(status="DELETE_FAILED"), FakeFunctions()
    plan = teardown.capture(cloudformation, STACK)
    teardown.execute(plan, cloudformation, FakeS3(), FakeLogs(), sleep=lambda _s: None, report=lambda _m: None, functions=functions)
    assert len(cloudformation.deletes) == 1
    assert cloudformation.deletes[0]["RetainResources"] == [MAPPING["LogicalResourceId"]]


def test_without_a_lambda_client_nothing_is_ever_left_out():
    cloudformation = StackWithMapping()
    plan = teardown.capture(cloudformation, STACK)
    with pytest.raises(teardown.TeardownError):
        teardown.execute(plan, cloudformation, FakeS3(), FakeLogs(), attempts=2, sleep=lambda _s: None, report=lambda _m: None)
    assert all("RetainResources" not in call for call in cloudformation.deletes)
