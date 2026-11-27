"""The trusted service router cannot accept an arbitrary target or replay calls."""
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import runtime_router


class Client:
    calls = None
    body = None
    def __init__(self):
        self.calls = []
        self.body = io.BytesIO(b'{"answer":"synthetic response","stopReason":"done","inferenceFirstTokenMs":750}')
    def invoke_agent_runtime(self, **kwargs):
        self.calls.append(kwargs)
        return {"response": self.body}


@pytest.fixture
def client(monkeypatch):
    c = Client()
    monkeypatch.setattr(runtime_router, "_client", c)
    for k, v in {"AGENTCORE_RUNTIME_ARN": "reviewed-runtime", "AGENTCORE_ENDPOINT": "pinned_v2",
                 "AGENTCORE_VERSION": "2", "SOURCE_REVISION": "s3-sha256:" + "a" * 64,
                 "ROUTER_FUNCTION_NAME": "owned-router"}.items():
        monkeypatch.setenv(k, v)
    return c


def event():
    return {"prompt": "Synthetic arithmetic: 2 + 2", "actor_id": "synthetic_owner",
            "sessionId": "synthetic_session_12345678901234567890"}


def test_only_reviewed_runtime_endpoint_and_identity_payload(client):
    result = runtime_router.handler(event(), None)
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["agentRuntimeArn"] == "reviewed-runtime" and call["qualifier"] == "pinned_v2"
    assert json.loads(call["payload"]) == {"prompt": event()["prompt"], "actorId": "synthetic_owner"}
    assert client.body.closed and result["runtimeVersion"] == "2"


@pytest.mark.parametrize("change", [
    {"runtimeArn": "foreign-runtime"}, {"qualifier": "DEFAULT"}, {"actor_id": ""},
    {"sessionId": "short"}, {"prompt": "x" * 8193}, {"prompt": {"text": "unsafe"}},
])
def test_invalid_or_target_override_never_dispatches(client, change):
    with pytest.raises(ValueError):
        runtime_router.handler({**event(), **change}, None)
    assert not client.calls


def test_invocation_failure_is_single_attempt_and_redacted(client):
    def failed(**kwargs):
        client.calls.append(kwargs)
        raise RuntimeError("private prompt or credential from agent error")
    client.invoke_agent_runtime = failed
    with pytest.raises(RuntimeError, match="^Pinned runtime invocation failed$") as error:
        runtime_router.handler(event(), None)
    assert len(client.calls) == 1 and error.value.__suppress_context__


def test_oversized_runtime_response_is_closed(client):
    client.body = io.BytesIO(b"x" * (256 * 1024 + 1))
    with pytest.raises(ValueError, match="exceeds limit"):
        runtime_router.handler(event(), None)
    assert client.body.closed


def test_actual_response_emits_numeric_telemetry_without_content(client, capsys):
    runtime_router.handler(event(), None)
    observed = json.loads(capsys.readouterr().out)
    assert observed["CompletionFailures"] == 0 and observed["InferenceFirstTokenMs"] == 750
    assert set(observed) == {"_aws", "FunctionName", "CompletionFailures", "InferenceFirstTokenMs"}


def test_successful_guardrail_refusal_is_not_a_completion_failure(client, capsys):
    client.body = io.BytesIO(b'{"stopReason":"guardrail_intervened","inferenceFirstTokenMs":0}')
    runtime_router.handler(event(), None)
    observed = json.loads(capsys.readouterr().out)
    assert observed["CompletionFailures"] == 0
    assert "InferenceFirstTokenMs" not in observed


@pytest.mark.parametrize("latency", [None, True, -1, float("nan"), "750"])
def test_invalid_runtime_telemetry_cannot_be_healthy(client, latency):
    client.body = io.BytesIO(json.dumps({"stopReason": "done", "inferenceFirstTokenMs": latency}).encode())
    with pytest.raises(ValueError, match="telemetry"):
        runtime_router.handler(event(), None)
    assert client.body.closed
