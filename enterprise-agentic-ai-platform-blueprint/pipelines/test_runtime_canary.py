"""Real alias-state contract: weighted start, bounded soak and safe rollback."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from runtime_canary import CanaryError, StateJournal, run_canary

ALIAS = "arn:aws:lambda:eu-west-1:111111111111:function:owned-runtime-router:live"
RUNTIME = "arn:aws:bedrock-agentcore:eu-west-1:111111111111:runtime/owned_runtime-abcdefghij"


class Lambda:
    def __init__(self):
        self.state = {"AliasArn": ALIAS, "FunctionVersion": "1", "RoutingConfig": {}, "RevisionId": "r1"}
        self.updates = []
    def get_alias(self, **kwargs):
        return copy.deepcopy(self.state)
    def get_function_configuration(self, **kwargs):
        v = kwargs["Qualifier"]
        return {"Version": v, "State": "Active", "Environment": {"Variables": {
            "AGENTCORE_RUNTIME_ARN": RUNTIME, "AGENTCORE_ENDPOINT": f"pinned_v{v}", "AGENTCORE_VERSION": v,
        }}}
    def update_alias(self, **kwargs):
        assert kwargs["RevisionId"] == self.state["RevisionId"]
        self.updates.append(copy.deepcopy(kwargs))
        self.state.update({k: copy.deepcopy(kwargs[k]) for k in ("FunctionVersion", "RoutingConfig")})
        self.state["RevisionId"] += "n"
        return copy.deepcopy(self.state)


class CloudWatch:
    state = "OK"
    def describe_alarms(self, **kwargs):
        return {"CompositeAlarms": [{"AlarmName": "owned-evaluation-alarm", "StateValue": self.state}]}


class AgentCore:
    def get_agent_runtime_endpoint(self, **kwargs):
        v = kwargs["endpointName"].removeprefix("pinned_v")
        return {"status": "READY", "liveVersion": v, "targetVersion": v}


def run(lambdas, cw, action, **kwargs):
    result = run_canary(lambdas, cw, AgentCore(), alias_arn=ALIAS, baseline="1", candidate="2",
        percent=5, alarm="owned-evaluation-alarm", minutes=1, action=action,
        owned_revision=getattr(lambdas, "owned_revision", None) if action == "soak" else None, **kwargs)
    lambdas.owned_revision = result["ownedRevisionId"]
    return result


def test_real_weight_then_soak_promotes_exact_candidate():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {"2": .05}}
    sleeps = []
    run(lambdas, cw, "soak", sleep=sleeps.append)
    assert sleeps == [30, 30]
    assert lambdas.state["FunctionVersion"] == "2"
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {}}


@pytest.mark.parametrize("state", ["ALARM", "INSUFFICIENT_DATA"])
def test_alarm_regression_rolls_back_without_promotion(state):
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    cw.state = state
    with pytest.raises(CanaryError):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert lambdas.state["FunctionVersion"] == "1"
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {}}


def test_concurrent_alias_change_is_never_overwritten():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    lambdas.state["RoutingConfig"] = {"AdditionalVersionWeights": {"3": .10}}
    with pytest.raises(CanaryError):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {"3": .10}}
    assert len(lambdas.updates) == 1


def test_missing_alarm_and_unknown_baseline_refuse_before_mutation():
    lambdas, cw = Lambda(), CloudWatch()
    cw.describe_alarms = lambda **_: {"CompositeAlarms": []}
    with pytest.raises(CanaryError):
        run(lambdas, cw, "start")
    assert not lambdas.updates
    cw = CloudWatch()
    lambdas.state["FunctionVersion"] = "3"
    with pytest.raises(CanaryError):
        run(lambdas, cw, "start")
    assert not lambdas.updates


def test_unpinned_endpoint_refuses_before_mutation():
    lambdas, cw = Lambda(), CloudWatch()
    previous = lambdas.get_function_configuration
    def unpinned(**kwargs):
        config = previous(**kwargs)
        config["Environment"]["Variables"]["AGENTCORE_ENDPOINT"] = "DEFAULT"
        return config
    lambdas.get_function_configuration = unpinned
    with pytest.raises(CanaryError):
        run(lambdas, cw, "start")
    assert not lambdas.updates


def test_endpoint_drift_during_soak_restores_baseline():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    original = lambdas.get_function_configuration
    def drift(**kwargs):
        config = original(**kwargs)
        if kwargs["Qualifier"] == "2":
            config["Environment"]["Variables"]["AGENTCORE_VERSION"] = "3"
        return config
    lambdas.get_function_configuration = drift
    with pytest.raises(CanaryError):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {}}
    assert lambdas.state["FunctionVersion"] == "1"


def test_alarm_changed_at_promotion_restores_baseline():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    count = 0
    def alarm(**kwargs):
        nonlocal count
        count += 1
        return {"CompositeAlarms": [{"AlarmName": "owned-evaluation-alarm",
            "StateValue": "ALARM" if count == 4 else "OK"}]}
    cw.describe_alarms = alarm
    with pytest.raises(CanaryError):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {}}
    assert lambdas.state["FunctionVersion"] == "1"


def test_same_weighted_shape_new_revision_is_not_owned():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    lambdas.state["RevisionId"] = "another-rollout"
    with pytest.raises(CanaryError, match="revision changed"):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert len(lambdas.updates) == 1
    assert lambdas.state["RevisionId"] == "another-rollout"
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {"2": .05}}


def test_missing_owned_revision_refuses_before_any_read_or_write():
    lambdas, cw = Lambda(), CloudWatch()
    lambdas.get_alias = lambda **_: pytest.fail("unowned soak read alias")
    with pytest.raises(CanaryError, match="requires the revision"):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert not lambdas.updates


def test_revision_race_after_last_healthy_poll_prevents_promotion_and_rollback():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    calls = 0
    original = cw.describe_alarms
    def racing_alarm(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 4:
            lambdas.state["RevisionId"] = "foreign-at-promotion"
        return original(**kwargs)
    cw.describe_alarms = racing_alarm
    with pytest.raises(CanaryError, match="reconciliation"):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert len(lambdas.updates) == 1
    assert lambdas.state["RevisionId"] == "foreign-at-promotion"


def test_alarm_race_with_same_shape_revision_never_rolls_back_other_owner():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    def racing_alarm(**kwargs):
        lambdas.state["RevisionId"] = "foreign-at-alarm"
        return {"CompositeAlarms": [{"AlarmName": "owned-evaluation-alarm", "StateValue": "ALARM"}]}
    cw.describe_alarms = racing_alarm
    with pytest.raises(CanaryError):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert len(lambdas.updates) == 1
    assert lambdas.state["RevisionId"] == "foreign-at-alarm"


def test_successful_weight_update_response_loss_requires_reconciliation_without_replay():
    lambdas, cw = Lambda(), CloudWatch()
    original = lambdas.update_alias
    events = []
    def response_loss(**kwargs):
        original(**kwargs)
        raise TimeoutError("response lost")
    lambdas.update_alias = response_loss
    with pytest.raises(CanaryError, match="reconciliation"):
        run(lambdas, cw, "start", record=events.append)
    assert len(lambdas.updates) == 1
    assert lambdas.state["FunctionVersion"] == "1"
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {"2": .05}}
    assert events[-1]["status"] == "AMBIGUOUS_ALIAS_UPDATE"


def test_successful_promotion_response_loss_is_not_replayed_or_rolled_back():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    original = lambdas.update_alias
    def response_loss(**kwargs):
        original(**kwargs)
        raise TimeoutError("response lost")
    lambdas.update_alias = response_loss
    with pytest.raises(CanaryError, match="reconciliation"):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert len(lambdas.updates) == 2
    assert lambdas.state["FunctionVersion"] == "2"
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {}}


def test_owned_revision_is_the_update_return_and_every_write_uses_exact_cas():
    lambdas, cw = Lambda(), CloudWatch()
    start = run(lambdas, cw, "start")
    assert start["ownedRevisionId"] == lambdas.state["RevisionId"] == "r1n"
    soak = run(lambdas, cw, "soak", sleep=lambda _: None)
    assert [x["RevisionId"] for x in lambdas.updates] == ["r1", "r1n"]
    assert soak["ownedRevisionId"] == lambdas.state["RevisionId"] == "r1nn"


def test_state_journal_fsyncs_dispatch_and_owner_and_refuses_replay(tmp_path, monkeypatch):
    import json
    import runtime_canary
    synced = []
    real_fsync = runtime_canary.os.fsync
    monkeypatch.setattr(runtime_canary.os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1])
    path = tmp_path / "state.jsonl"
    journal = StateJournal(path, {"action": "start", "aliasArn": ALIAS})
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start", record=journal)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [x["status"] for x in events] == ["PREPARED", "DISPATCH_INTENT", "OWNED_UPDATE"]
    assert events[-1]["revisionId"] == lambdas.state["RevisionId"]
    assert len(synced) == 4
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        StateJournal(path, {"action": "start", "aliasArn": ALIAS})


def test_failure_to_persist_owned_response_does_not_blindly_rollback():
    lambdas, cw = Lambda(), CloudWatch()
    def record(event):
        if event["status"] == "OWNED_UPDATE":
            raise OSError("journal unavailable")
    with pytest.raises(CanaryError, match="reconciliation"):
        run(lambdas, cw, "start", record=record)
    assert len(lambdas.updates) == 1
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {"2": .05}}


def test_missing_update_returned_revision_does_not_adopt_readback_or_rollback():
    lambdas, cw = Lambda(), CloudWatch()
    original = lambdas.update_alias
    def missing_revision(**kwargs):
        changed = original(**kwargs)
        del changed["RevisionId"]
        return changed
    lambdas.update_alias = missing_revision
    with pytest.raises(CanaryError, match="reconciliation"):
        run(lambdas, cw, "start")
    assert len(lambdas.updates) == 1
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {"2": .05}}


def test_successful_rollback_response_loss_is_not_retried():
    lambdas, cw = Lambda(), CloudWatch()
    run(lambdas, cw, "start")
    cw.state = "ALARM"
    original = lambdas.update_alias
    def response_loss(**kwargs):
        original(**kwargs)
        raise TimeoutError("rollback response lost")
    lambdas.update_alias = response_loss
    with pytest.raises(CanaryError, match="reconciliation"):
        run(lambdas, cw, "soak", sleep=lambda _: None)
    assert [x["RevisionId"] for x in lambdas.updates] == ["r1", "r1n"]
    assert lambdas.state["FunctionVersion"] == "1"
    assert lambdas.state["RoutingConfig"] == {"AdditionalVersionWeights": {}}


def test_existing_cli_journal_refuses_before_sdk_factory(tmp_path, monkeypatch):
    import types
    import runtime_canary
    path = tmp_path / "existing-state.jsonl"
    path.write_text('{"status":"AMBIGUOUS_ALIAS_UPDATE"}\n')
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(
        client=lambda *a, **k: pytest.fail("replayed CLI created a native client")))
    with pytest.raises(FileExistsError):
        runtime_canary.main([
            "--action", "start", "--alias-arn", ALIAS,
            "--baseline-version", "1", "--candidate-version", "2",
            "--percent", "50", "--minutes", "1",
            "--alarm", "owned-evaluation-alarm",
            "--assume-role-arn", "arn:aws:iam::111111111111:role/owned-routing",
            "--state-file", str(path),
        ])
    assert path.read_text() == '{"status":"AMBIGUOUS_ALIAS_UPDATE"}\n'
