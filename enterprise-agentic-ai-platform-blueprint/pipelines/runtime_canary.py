#!/usr/bin/env python3
"""Shift real Lambda alias traffic to a version-pinned AgentCore router.

The router's published versions must each pin an AgentCore endpoint. This
controller refuses mutable Lambda versions, unexpected alias state and missing
or unhealthy alarms. An alarm/error during the soak restores the baseline only
when the alias still matches this deployment, never overwriting another rollout.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import time
from typing import Callable


class CanaryError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CanaryError(message)


class StateJournal:
    """Exclusive, fsynced local dispatch history; never resumes an old action."""
    def __init__(self, path, scope):
        self.path = Path(path)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps({"status": "PREPARED", **scope}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        parent = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

    def __call__(self, event):
        with self.path.open("a") as handle:
            handle.write(json.dumps(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def validate(alias_arn, baseline, candidate, percent, alarm, minutes):
    match = re.fullmatch(r"arn:aws:lambda:([a-z0-9-]+):(\d{12}):function:([A-Za-z0-9_-]+):([A-Za-z0-9_-]+)", alias_arn)
    require(match is not None, "canary alias must be a qualified Lambda ARN")
    require(not match[4].isdigit(), "canary target must be an alias")
    require(bool(re.fullmatch(r"[1-9]\d*", baseline)), "baseline must be a published version")
    require(bool(re.fullmatch(r"[1-9]\d*", candidate)), "candidate must be a published version")
    require(baseline != candidate, "canary requires distinct baseline and candidate versions")
    require(0 < percent < 100, "canary percentage must be between 0 and 100")
    require(1 <= minutes <= 120, "canary soak must be between 1 and 120 minutes")
    require(bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", alarm)), "canary alarm name is invalid")
    return match


def run_canary(lambdas, cloudwatch, agentcore, *, alias_arn, baseline, candidate,
               percent, alarm, minutes, action, owned_revision=None,
               record: Callable = lambda _: None, sleep: Callable = time.sleep):
    match = validate(alias_arn, baseline, candidate, percent, alarm, minutes)
    require(action in {"start", "soak"}, "unsupported canary action")
    require(action != "soak" or isinstance(owned_revision, str) and bool(owned_revision),
            "soak requires the revision returned by this rollout's weighted update")
    function = alias_arn.rsplit(":", 1)[0]
    alias = match[4]
    weights = {candidate: percent / 100}
    ambiguous_update = False
    def get():
        return lambdas.get_alias(FunctionName=function, Name=alias)
    def matches(state, weighted):
        return (state.get("AliasArn") == alias_arn and state.get("FunctionVersion") == baseline
                and state.get("RoutingConfig", {}).get("AdditionalVersionWeights", {}) ==
                (weights if weighted else {}))
    def owns(state):
        return bool(owned_revision) and state.get("RevisionId") == owned_revision
    def healthy():
        response = cloudwatch.describe_alarms(AlarmNames=[alarm], AlarmTypes=["CompositeAlarm"])
        observed = response.get("CompositeAlarms", [])
        require(len(observed) == 1 and observed[0].get("AlarmName") == alarm
                and observed[0].get("StateValue") == "OK", "canary alarm is missing or not OK")
    def update(state, version, new_weights):
        nonlocal owned_revision, ambiguous_update
        require(isinstance(state.get("RevisionId"), str) and state["RevisionId"], "alias revision is missing")
        require(owned_revision is None or owns(state), "canary lost ownership of the alias revision")
        record({"status": "DISPATCH_INTENT", "revisionId": state["RevisionId"],
                "functionVersion": version, "weights": new_weights})
        ambiguous_update = True
        try:
            changed = lambdas.update_alias(
                FunctionName=function, Name=alias, FunctionVersion=version,
                RoutingConfig={"AdditionalVersionWeights": new_weights}, RevisionId=state["RevisionId"],
            )
            require(changed.get("AliasArn") == alias_arn and changed.get("FunctionVersion") == version and
                    changed.get("RoutingConfig", {}).get("AdditionalVersionWeights", {}) == new_weights and
                    isinstance(changed.get("RevisionId"), str) and bool(changed["RevisionId"]) and
                    changed["RevisionId"] != state["RevisionId"], "alias update readback differs")
            record({"status": "OWNED_UPDATE", "revisionId": changed["RevisionId"],
                    "functionVersion": version, "weights": new_weights})
        except Exception:
            record({"status": "AMBIGUOUS_ALIAS_UPDATE", "previousOwnedRevisionId": owned_revision,
                    "requiresReadOnlyReconciliation": True})
            raise CanaryError("alias update outcome requires read-only reconciliation; no retry or blind rollback") from None
        owned_revision = changed["RevisionId"]
        ambiguous_update = False
    def verify_pins():
        # Both versions must actually exist; a fake number must never pass.
        pinned = []
        for version in (baseline, candidate):
            config = lambdas.get_function_configuration(FunctionName=function, Qualifier=version)
            require(config.get("Version") == version and config.get("State") == "Active",
                    "router version is unavailable")
            env = config.get("Environment", {}).get("Variables", {})
            runtime = env.get("AGENTCORE_RUNTIME_ARN", "")
            endpoint = env.get("AGENTCORE_ENDPOINT", "")
            runtime_match = re.fullmatch(rf"arn:aws:bedrock-agentcore:{match[1]}:{match[2]}:runtime/([A-Za-z][A-Za-z0-9_]{{0,99}}-[A-Za-z0-9]{{10}})", runtime)
            require(runtime_match is not None and
                    bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", endpoint)) and endpoint != "DEFAULT",
                    "router must pin a same-account named AgentCore endpoint")
            observed = agentcore.get_agent_runtime_endpoint(
                agentRuntimeId=runtime_match[1], endpointName=endpoint)
            require(observed.get("status") == "READY" and
                    str(observed.get("liveVersion", "")) == env.get("AGENTCORE_VERSION") and
                    str(observed.get("targetVersion", "")) == env.get("AGENTCORE_VERSION"),
                    "router endpoint does not match its reviewed ready runtime version")
            pinned.append((runtime, env.get("AGENTCORE_VERSION")))
        require(pinned[0][0] == pinned[1][0] and pinned[0][1] != pinned[1][1],
                "canary must route two distinct versions of the same runtime")
    if action == "start":
        healthy()
        state = get()
        require(matches(state, False), "baseline alias differs from reviewed state")
        verify_pins()
        try:
            update(state, baseline, weights)
        except Exception:
            if not ambiguous_update:
                observed = get()
                if owns(observed) and matches(observed, True):
                    update(observed, baseline, {})
            raise
    elif action == "soak":
        try:
            for _ in range(minutes * 2 + 1):
                state = get()
                require(owns(state) and matches(state, True), "weighted alias revision changed during soak")
                verify_pins()
                healthy()
                if _ < minutes * 2:
                    sleep(30)
            state = get()
            require(owns(state) and matches(state, True), "weighted alias revision changed before promotion")
            verify_pins()
            healthy()
            update(state, candidate, {})
        except Exception:
            if not ambiguous_update:
                state = get()
                if owns(state) and matches(state, True):
                    update(state, baseline, {})
            raise
    return {"action": action, "status": "passed", "aliasArn": alias_arn,
            "baselineVersion": baseline, "candidateVersion": candidate, "percent": percent,
            "ownedRevisionId": owned_revision}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["start", "soak"], required=True)
    parser.add_argument("--alias-arn", required=True)
    parser.add_argument("--baseline-version", required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--percent", type=int, required=True)
    parser.add_argument("--alarm", required=True)
    parser.add_argument("--minutes", type=int, required=True)
    parser.add_argument("--assume-role-arn", required=True)
    parser.add_argument("--owned-revision", help="exact revision exported by the successful weighted start")
    parser.add_argument("--state-file", help="new local action journal; existing paths refuse replay")
    args = parser.parse_args(argv)
    match = validate(args.alias_arn, args.baseline_version, args.candidate_version,
                     args.percent, args.alarm, args.minutes)
    require(bool(re.fullmatch(rf"arn:aws:iam::{match[2]}:role/[A-Za-z0-9+=,.@_/-]+", args.assume_role_arn)),
            "routing role must belong to the alias account")
    require(args.action != "soak" or bool(args.owned_revision), "soak requires an owned revision")
    journal = StateJournal(args.state_file or f"runtime-canary-{args.action}-state.jsonl", {
        "action": args.action, "aliasArn": args.alias_arn, "baselineVersion": args.baseline_version,
        "candidateVersion": args.candidate_version, "ownedRevisionId": args.owned_revision,
    })
    import boto3
    from botocore.config import Config
    creds = boto3.client("sts").assume_role(RoleArn=args.assume_role_arn,
        RoleSessionName="reviewed-runtime-canary", DurationSeconds=3600)["Credentials"]
    session = boto3.Session(aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"],
        region_name=match[1])
    config = Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1})
    result = run_canary(session.client("lambda", config=config), session.client("cloudwatch", config=config),
        session.client("bedrock-agentcore-control", config=config),
        alias_arn=args.alias_arn, baseline=args.baseline_version, candidate=args.candidate_version,
        percent=args.percent, alarm=args.alarm, minutes=args.minutes, action=args.action,
        owned_revision=args.owned_revision, record=journal)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
