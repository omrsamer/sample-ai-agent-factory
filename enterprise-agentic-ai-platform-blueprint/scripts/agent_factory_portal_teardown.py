#!/usr/bin/env python3
"""Tear down one Agent Factory Portal stack and what it leaves behind.

A portal stack cannot always be deleted in one pass. Its access-log bucket
keeps receiving Amazon S3 and Amazon CloudFront log deliveries for a while
after the stack's own clean-up has emptied it, so the bucket delete can fail
with "not empty"; and the log groups AWS Lambda creates for the stack's
provider functions are not stack resources, so they would be left behind.

This script captures, BEFORE deleting, the exact physical ids the stack owns
(its buckets and its functions), deletes the stack, and on a failed bucket
delete empties exactly those buckets and retries. It then removes exactly the
service log groups of the captured functions. It touches nothing it did not
capture from the named stack.

    # print the plan, change nothing (default)
    python3 scripts/agent_factory_portal_teardown.py --stack-name AgenticAI-AgentFactoryPortal-nonprod \\
        --expected-account <12-digit id> --region eu-west-1
    # after reviewing the plan
    python3 scripts/agent_factory_portal_teardown.py ... --execute [--role-arn <CloudFormation role>]

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

PORTAL_STACK = re.compile(r"^AgenticAI-AgentFactoryPortal-(Edge-|FleetReader-|Containment-|ExternalReader-)?(nonprod|prod)$")
ACCOUNT = re.compile(r"^\d{12}$")


class TeardownError(RuntimeError):
    """The teardown cannot continue without touching something it does not own."""


@dataclass
class Plan:
    stack_name: str
    status: str
    buckets: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    retained: list[str] = field(default_factory=list)

    @property
    def log_groups(self) -> list[str]:
        return [f"/aws/lambda/{name}" for name in self.functions]

    def lines(self) -> list[str]:
        out = [f"stack              {self.stack_name} ({self.status})"]
        out += [f"empty on failure   s3://{name}" for name in self.buckets]
        out += [f"delete log group   {name}" for name in self.log_groups]
        out += [f"retained by stack  {name}" for name in self.retained]
        return out


def capture(cloudformation: Any, stack_name: str) -> Plan:
    """Read the stack and record exactly what it owns. Raises when it does not exist."""
    if not PORTAL_STACK.fullmatch(stack_name):
        raise TeardownError(f"{stack_name} is not an Agent Factory Portal stack name")
    stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    plan = Plan(stack_name=stack_name, status=stack["StackStatus"])
    paginator = cloudformation.get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=stack_name):
        for resource in page["StackResourceSummaries"]:
            physical = resource.get("PhysicalResourceId")
            if not physical or resource.get("ResourceStatus") == "DELETE_COMPLETE":
                continue
            kind = resource["ResourceType"]
            if kind == "AWS::S3::Bucket":
                plan.buckets.append(physical)
            elif kind == "AWS::Lambda::Function":
                plan.functions.append(physical)
            elif kind in ("AWS::Cognito::UserPool", "AWS::DynamoDB::Table"):
                plan.retained.append(f"{kind} {physical} (only when the stack was deployed to retain data)")
    plan.buckets.sort()
    plan.functions.sort()
    return plan


def empty_bucket(s3: Any, bucket: str) -> int:
    """Delete every object version and delete marker of one bucket. Returns the count."""
    removed = 0
    paginator = s3.get_paginator("list_object_versions")
    try:
        pages = list(paginator.paginate(Bucket=bucket))
    except Exception as error:  # noqa: BLE001 - the bucket may already be gone
        if "NoSuchBucket" in str(error):
            return 0
        raise
    for page in pages:
        objects = [
            {"Key": item["Key"], "VersionId": item["VersionId"]}
            for key in ("Versions", "DeleteMarkers")
            for item in page.get(key, [])
        ]
        for start in range(0, len(objects), 1000):
            batch = objects[start : start + 1000]
            s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
            removed += len(batch)
    return removed


def stack_status(cloudformation: Any, stack_name: str) -> str:
    try:
        return cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except Exception as error:  # noqa: BLE001
        if "does not exist" in str(error):
            return "DELETE_COMPLETE"
        raise


def wait_for_delete(
    cloudformation: Any,
    stack_name: str,
    *,
    sleep: Callable[[float], None],
    timeout: float,
    interval: float = 10.0,
) -> str:
    waited = 0.0
    while True:
        status = stack_status(cloudformation, stack_name)
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        if waited >= timeout:
            raise TeardownError(f"{stack_name} is still {status} after {int(timeout)} seconds")
        sleep(interval)
        waited += interval


def execute(
    plan: Plan,
    cloudformation: Any,
    s3: Any,
    logs: Any,
    *,
    role_arn: str | None = None,
    attempts: int = 4,
    sleep: Callable[[float], None] = time.sleep,
    timeout: float = 1800.0,
    report: Callable[[str], None] = print,
) -> None:
    kwargs = {"StackName": plan.stack_name, **({"RoleARN": role_arn} if role_arn else {})}
    for attempt in range(1, attempts + 1):
        cloudformation.delete_stack(**kwargs)
        status = wait_for_delete(cloudformation, plan.stack_name, sleep=sleep, timeout=timeout)
        if status == "DELETE_COMPLETE":
            report(f"stack deleted (attempt {attempt})")
            break
        report(f"delete attempt {attempt} failed; emptying the stack's own buckets")
        for bucket in plan.buckets:
            removed = empty_bucket(s3, bucket)
            report(f"  s3://{bucket}: removed {removed} object version(s)")
    else:
        raise TeardownError(f"{plan.stack_name} could not be deleted in {attempts} attempts")
    for group in plan.log_groups:
        try:
            logs.delete_log_group(logGroupName=group)
            report(f"log group deleted: {group}")
        except Exception as error:  # noqa: BLE001
            if "ResourceNotFound" not in str(error):
                raise
            report(f"log group absent: {group}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--role-arn", help="CloudFormation role to delete the stack with")
    parser.add_argument("--execute", action="store_true", help="perform the teardown; default prints the plan")
    args = parser.parse_args(argv)
    if not ACCOUNT.fullmatch(args.expected_account):
        parser.error("--expected-account must be a 12-digit AWS account id")

    import boto3

    session = boto3.Session(region_name=args.region)
    actual = session.client("sts").get_caller_identity()["Account"]
    if actual != args.expected_account:
        raise SystemExit(f"REFUSING: credentials belong to ...{actual[-4:]}, expected ...{args.expected_account[-4:]}")
    cloudformation = session.client("cloudformation")
    try:
        plan = capture(cloudformation, args.stack_name)
    except TeardownError as error:
        raise SystemExit(f"REFUSING: {error}") from error
    for line in plan.lines():
        print(line)
    if not args.execute:
        print("dry run: nothing was changed (pass --execute after reviewing the plan)")
        return 0
    try:
        execute(plan, cloudformation, session.client("s3"), session.client("logs"), role_arn=args.role_arn)
    except TeardownError as error:
        print(f"teardown failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
