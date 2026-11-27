"""Offline tests for the inference-Gateway guardrail interceptor.

Run: scripts/live-agentcore-generated-agent-spike/.venv/bin/python -m pytest \
       packages/platform-inference-gateway/lambda/guardrail-interceptor -q
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).parent))
import index  # noqa: E402


def _b64(obj) -> str:
    raw = obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj).encode()
    return base64.b64encode(raw).decode()


def _event(body, path="/inference/v1/chat/completions", method="POST"):
    return {
        "interceptorInputVersion": "1.0",
        "http": {"gatewayRequest": {"path": path, "httpMethod": method, "body": body}},
    }


def _response(result):
    body = json.loads(base64.b64decode(result["http"]["transformedGatewayResponse"]["body"]))
    return result["http"]["transformedGatewayResponse"]["statusCode"], body


class FakeBedrock:
    def __init__(self, action="NONE", assessments=None, error=None):
        self.action = action
        self.assessments = assessments or []
        self.error = error
        self.calls = []

    def apply_guardrail(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"action": self.action, "assessments": self.assessments}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GUARDRAIL_IDENTIFIER", "abc123guard")
    monkeypatch.setenv("GUARDRAIL_VERSION", "DRAFT")
    monkeypatch.setenv("MAX_GUARDED_CHARACTERS", "60000")
    monkeypatch.delenv("BLOCKED_MESSAGE", raising=False)
    monkeypatch.delenv("TRUSTED_SYSTEM_PROMPT_SHA256", raising=False)


@pytest.fixture
def bedrock(monkeypatch):
    fake = FakeBedrock()
    monkeypatch.setattr(index, "_bedrock_runtime", lambda: fake)
    return fake


BLOCKED_VIOLENCE = [
    {"contentPolicy": {"filters": [
        {"type": "VIOLENCE", "action": "BLOCKED", "detected": True, "confidence": "HIGH"},
        {"type": "HATE", "action": "NONE", "detected": False},
    ]}},
]
ANONYMIZED_ONLY = [
    {"sensitiveInformationPolicy": {"piiEntities": [
        {"type": "EMAIL", "action": "ANONYMIZED", "detected": True, "match": "a@b.c"},
    ]}},
]


# ----------------------------------------------------------------- extraction
def test_extracts_all_client_controlled_turns():
    payload = {
        "model": "m",
        "messages": [
            {"role": "system", "content": "You are an agent. Reply with a single TOOL line and nothing else."},
            {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url", "image_url": {"url": "x"}}]},
            {"role": "assistant", "content": "TOOL echo {}"},
            {"role": "tool", "content": "TOOL RESULT: {}"},
            {"content": "no role -> guarded"},
        ],
    }
    assert index.extract_texts(payload) == [
        "You are an agent. Reply with a single TOOL line and nothing else.",
        "hello", "TOOL echo {}", "TOOL RESULT: {}", "no role -> guarded",
    ]


def test_top_level_and_responses_inputs_are_guarded():
    assert index.extract_texts({"system": "s", "messages": [{"role": "developer", "content": "d"}, {"role": "user", "content": "u"}]}) == ["d", "u", "s"]
    assert index.extract_texts({"input": "plain"}) == ["plain"]
    assert index.extract_texts({"input": [{"role": "user", "content": [{"type": "input_text", "text": "t"}]}, {"role": "system", "content": "s"}]}) == ["t", "s"]
    assert index.extract_texts({"prompt": "p", "instructions": "i"}) == ["p", "i"]
    assert index.extract_texts({"messages": [{"role": "function", "content": "f"}]}) == ["f"]


@pytest.mark.parametrize("payload", [
    {"messages": [{"role": role, "content": "blocked"}]}
    for role in ("system", "developer", "assistant", "SYSTEM", "unknown")
] + [
    {"input": [{"role": "system", "content": [{"type": "input_text", "text": "blocked"}]}]},
    {"system": "blocked"},
    {"instructions": "blocked"},
    {"system": [{"type": "text", "text": "blocked"}]},
    {"system": {"type": "text", "text": "blocked"}},
    {"input": [{"type": "function_call_output", "call_id": "call", "output": "blocked"}]},
    {"input": [{"type": "function_call", "call_id": "call", "arguments": "blocked"}]},
    {"messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": "blocked"}]}]},
    {"messages": [{"role": "assistant", "content": [{"type": "refusal", "refusal": "blocked"}]}]},
])
def test_role_labels_and_top_level_fields_cannot_bypass_guardrail(bedrock, payload):
    bedrock.action, bedrock.assessments = "GUARDRAIL_INTERVENED", BLOCKED_VIOLENCE
    assert _response(index.handler(_event(_b64(payload)), None))[0] == 403
    assert bedrock.calls[0]["content"] == [{"text": {"text": "blocked"}}]

@pytest.mark.parametrize("payload", [
    {"messages": [{"role": "assistant", "content": None, "tool_calls": [{"type": "function", "function": {"name": "echo", "arguments": '{"text":"blocked"}'}}]}]},
    {"messages": [{"role": "assistant", "content": None, "function_call": {"name": "echo", "arguments": '{"text":"blocked"}'}}]},
    {"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "call", "name": "echo", "input": {"text": "blocked"}}]}]},
    {"tools": [{"type": "function", "function": {"name": "echo", "description": "blocked"}}]},
    {"functions": [{"name": "echo", "description": "blocked"}]},
])
def test_structured_function_context_cannot_bypass_guardrail(bedrock, payload):
    bedrock.action, bedrock.assessments = "GUARDRAIL_INTERVENED", BLOCKED_VIOLENCE
    assert _response(index.handler(_event(_b64(payload)), None))[0] == 403
    assert "blocked" in bedrock.calls[0]["content"][0]["text"]["text"]


def test_exact_operator_approved_system_prompt_preserves_agent_protocol(bedrock, monkeypatch):
    protocol = "Reply with a single TOOL line and nothing else."
    digest = hashlib.sha256(protocol.encode()).hexdigest()
    monkeypatch.setenv("TRUSTED_SYSTEM_PROMPT_SHA256", json.dumps([digest]))
    payload = {"messages": [
        {"role": "system", "content": protocol},
        {"role": "user", "content": "hello"},
    ]}
    assert index.handler(_event(_b64(payload)), None) == index.passthrough()
    assert [call["content"] for call in bedrock.calls] == [[{"text": {"text": "hello"}}]]


@pytest.mark.parametrize("payload", [
    {"messages": [{"role": "system", "content": "approved\nblocked"}]},
    {"messages": [{"role": "system", "content": [{"type": "text", "text": "approved"}, {"type": "text", "text": "blocked"}]}]},
    {"messages": [{"role": "user", "content": "approved"}]},
    {"messages": [{"role": "assistant", "content": "approved"}]},
    {"messages": [{"role": "tool", "content": "approved"}]},
    {"prompt": "approved"},
    {"input": "approved"},
])
def test_approved_hash_does_not_exempt_modified_prompts_or_other_roles(bedrock, monkeypatch, payload):
    monkeypatch.setenv("TRUSTED_SYSTEM_PROMPT_SHA256", json.dumps([hashlib.sha256(b"approved").hexdigest()]))
    bedrock.action, bedrock.assessments = "GUARDRAIL_INTERVENED", BLOCKED_VIOLENCE
    assert _response(index.handler(_event(_b64(payload)), None))[0] == 403
    assert bedrock.calls


@pytest.mark.parametrize("value", ['null', '{}', '["*"]', '["' + "a" * 63 + '"]', 'not json'])
def test_invalid_trusted_prompt_configuration_fails_closed(bedrock, monkeypatch, value):
    monkeypatch.setenv("TRUSTED_SYSTEM_PROMPT_SHA256", value)
    result = index.handler(_event(_b64({"system": "blocked"})), None)
    assert _response(result)[0] == 503
    assert bedrock.calls == []


def test_split_and_batch_respect_limits():
    blocks = index.split_blocks(["a" * 45_000, "b"])
    assert [len(b) for b in blocks] == [20_000, 20_000, 5_000, 1]
    grouped = list(index.turn_batches("a" * 45_000))
    assert all(sum(len(b) for b in g) <= index.BATCH_CHARACTERS for g in grouped)
    assert sum(len(g) for g in grouped) == 3


def test_each_untrusted_turn_is_scored_on_its_own_call(bedrock):
    payload = {
        "messages": [
            {"role": "system", "content": "protocol"},
            {"role": "user", "content": "use the echo tool please"},
            {"role": "assistant", "content": "TOOL echo {}"},
            {"role": "tool", "content": "TOOL RESULT: {}"},
        ],
    }
    result = index.handler(_event(_b64(payload)), None)
    assert result == index.passthrough()
    sent = sorted(c["text"]["text"] for call in bedrock.calls for c in call["content"])
    assert sent == ["TOOL RESULT: {}", "TOOL echo {}", "protocol", "use the echo tool please"]
    assert len(bedrock.calls) == 4  # one call per turn, never a joint evaluation


def test_multipart_user_turn_stays_one_turn():
    payload = {"messages": [{"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}]}
    assert index.extract_texts(payload) == ["a\nb"]


def test_blocked_types_only_reports_blocked_actions():
    assert index.blocked_types(BLOCKED_VIOLENCE) == ["contentPolicy.VIOLENCE"]
    assert index.blocked_types(ANONYMIZED_ONLY) == []
    topics = [{"topicPolicy": {"topics": [{"name": "CredentialExposure", "action": "BLOCKED"}]}}]
    assert index.blocked_types(topics) == ["topicPolicy.CredentialExposure"]


# ------------------------------------------------------------------ decisions
def test_benign_request_passes_through_unchanged(bedrock):
    result = index.handler(_event(_b64({"model": "m", "messages": [{"role": "user", "content": "hi"}]})), None)
    assert result == {"interceptorOutputVersion": "1.0", "http": {}}
    assert bedrock.calls[0]["source"] == "INPUT"
    assert bedrock.calls[0]["guardrailIdentifier"] == "abc123guard"
    assert bedrock.calls[0]["guardrailVersion"] == "DRAFT"
    assert bedrock.calls[0]["content"] == [{"text": {"text": "hi"}}]


def test_blocked_request_short_circuits_with_403(bedrock):
    bedrock.action, bedrock.assessments = "GUARDRAIL_INTERVENED", BLOCKED_VIOLENCE
    result = index.handler(_event(_b64({"model": "m", "messages": [{"role": "user", "content": "x"}]})), None)
    status, body = _response(result)
    assert status == 403
    assert body["error"]["code"] == "guardrail_intervened"
    assert body["error"]["tripped"] == ["contentPolicy.VIOLENCE"]
    assert body["error"]["guardrail"] == {"id": "abc123guard", "version": "DRAFT"}
    assert result["http"]["transformedGatewayResponse"]["headers"]["x-agenticai-guardrail"] == "guardrail_intervened"
    assert "x" not in json.dumps(body)  # request text is never echoed


@pytest.mark.parametrize("assessment", [
    {"piiEntities": [{"type": kind, "action": "ANONYMIZED", "match": "a@b.c"}]}
    for kind in ("EMAIL", "PHONE", "IP_ADDRESS")
] + [
    {"regexes": [{"name": name, "action": "ANONYMIZED", "match": "a@b.c"}]}
    for name in ("AU_TFN", "AU_Medicare", "AU_BSB_Account")
])
def test_anonymize_only_intervention_refuses_original_request(bedrock, assessment, caplog):
    bedrock.action = "GUARDRAIL_INTERVENED"
    bedrock.assessments = [{"sensitiveInformationPolicy": assessment}]
    result = index.handler(_event(_b64({"messages": [{"role": "user", "content": "mail a@b.c"}]})), None)
    status, body = _response(result)
    assert status == 403
    assert body["error"]["code"] == "guardrail_intervened"
    assert body["error"]["tripped"] == ["guardrail.INTERVENTION"]
    assert "transformedGatewayRequest" not in result["http"]
    assert "a@b.c" not in json.dumps(result)
    assert "a@b.c" not in caplog.text


@pytest.mark.parametrize("payload", [
    {"messages": [{"role": "user", "content": [{"type": "text", "text": "mail"}, {"type": "text", "text": "a@b.c"}]}]},
    {"input": [{"role": "user", "content": [{"type": "input_text", "text": "mail a@b.c"}]}]},
    {"prompt": "mail a@b.c"},
    {"system": "mail a@b.c"},
    {"instructions": "mail a@b.c"},
    {"messages": [{"role": "assistant", "content": None, "tool_calls": [{"type": "function", "function": {"name": "send", "arguments": '{"email":"a@b.c"}'}}]}]},
    {"tools": [{"type": "function", "function": {"name": "send", "description": "mail a@b.c"}}]},
    {"stream": True, "messages": [{"role": "user", "content": "mail a@b.c"}]},
])
def test_anonymization_refuses_all_supported_input_representations(bedrock, payload):
    bedrock.action, bedrock.assessments = "GUARDRAIL_INTERVENED", ANONYMIZED_ONLY
    assert _response(index.handler(_event(_b64(payload)), None))[0] == 403
    assert bedrock.calls


@pytest.mark.parametrize("outputs", [None, [], [{"text": "mail {EMAIL}"}], {"text": "mail {EMAIL}"}])
def test_anonymization_output_cannot_authorize_untransformed_body(bedrock, monkeypatch, outputs):
    monkeypatch.setattr(bedrock, "apply_guardrail", lambda **kwargs: {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": ANONYMIZED_ONLY,
        "outputs": outputs,
    })
    result = index.handler(_event(_b64({"prompt": "mail a@b.c"})), None)
    assert _response(result)[0] == 403
    assert "a@b.c" not in json.dumps(result)


@pytest.mark.parametrize("assessments", [None, [], [{"newPolicy": {"action": "ANONYMIZED"}}]])
def test_intervention_without_blocked_assessment_fails_closed(bedrock, monkeypatch, assessments):
    monkeypatch.setattr(bedrock, "apply_guardrail", lambda **kwargs: {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": assessments,
    })
    status, body = _response(index.handler(_event(_b64({"prompt": "mail a@b.c"})), None))
    assert status == 403
    assert body["error"]["tripped"] == ["guardrail.INTERVENTION"]


def test_mixed_blocking_and_anonymization_keeps_blocked_types(bedrock):
    bedrock.action = "GUARDRAIL_INTERVENED"
    bedrock.assessments = BLOCKED_VIOLENCE + ANONYMIZED_ONLY
    status, body = _response(index.handler(_event(_b64({"prompt": "mail a@b.c"})), None))
    assert status == 403
    assert body["error"]["tripped"] == ["contentPolicy.VIOLENCE"]


def test_anonymization_in_later_chunk_refuses_entire_request(bedrock, monkeypatch):
    def evaluate(**kwargs):
        bedrock.calls.append(kwargs)
        sensitive = any("a@b.c" in part["text"]["text"] for part in kwargs["content"])
        return {
            "action": "GUARDRAIL_INTERVENED" if sensitive else "NONE",
            "assessments": ANONYMIZED_ONLY if sensitive else [],
        }

    monkeypatch.setattr(bedrock, "apply_guardrail", evaluate)
    text = "q" * 40_000 + "mail a@b.c"
    assert _response(index.handler(_event(_b64({"prompt": text})), None))[0] == 403
    assert len(bedrock.calls) >= 2


def test_anonymization_in_one_turn_refuses_otherwise_benign_request(bedrock, monkeypatch):
    def evaluate(**kwargs):
        bedrock.calls.append(kwargs)
        sensitive = any("a@b.c" in part["text"]["text"] for part in kwargs["content"])
        return {
            "action": "GUARDRAIL_INTERVENED" if sensitive else "NONE",
            "assessments": ANONYMIZED_ONLY if sensitive else [],
        }

    monkeypatch.setattr(bedrock, "apply_guardrail", evaluate)
    payload = {"messages": [
        {"role": "user", "content": "hello"},
        {"role": "tool", "content": "mail a@b.c"},
    ]}
    assert _response(index.handler(_event(_b64(payload)), None))[0] == 403
    assert len(bedrock.calls) == 2


def test_streaming_flag_does_not_bypass_evaluation(bedrock):
    bedrock.action, bedrock.assessments = "GUARDRAIL_INTERVENED", BLOCKED_VIOLENCE
    result = index.handler(_event(_b64({"stream": True, "messages": [{"role": "user", "content": "x"}]})), None)
    assert _response(result)[0] == 403


# ----------------------------------------------------------------- fail closed
def test_guardrail_api_error_fails_closed_503(bedrock):
    bedrock.error = ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow"}}, "ApplyGuardrail")
    result = index.handler(_event(_b64({"messages": [{"role": "user", "content": "x"}]})), None)
    status, body = _response(result)
    assert status == 503 and body["error"]["code"] == "guardrail_unavailable"


@pytest.mark.parametrize("response", [None, [], {}, {"action": None}, {"action": "ANONYMIZED"}, {"action": "UNKNOWN"}])
def test_missing_or_unknown_guardrail_decision_fails_closed_503(bedrock, monkeypatch, response, caplog):
    monkeypatch.setattr(bedrock, "apply_guardrail", lambda **kwargs: response)
    result = index.handler(_event(_b64({"prompt": "mail a@b.c"})), None)
    status, body = _response(result)
    assert status == 503
    assert body["error"]["code"] == "guardrail_unavailable"
    assert "a@b.c" not in json.dumps(result)
    assert "a@b.c" not in caplog.text


@pytest.mark.parametrize("assessments", ["invalid", [None], [{"sensitiveInformationPolicy": {"piiEntities": [None]}}]])
def test_malformed_intervention_assessment_fails_closed_503(bedrock, monkeypatch, assessments):
    monkeypatch.setattr(bedrock, "apply_guardrail", lambda **kwargs: {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": assessments,
    })
    assert _response(index.handler(_event(_b64({"prompt": "mail a@b.c"})), None))[0] == 503


def test_missing_configuration_fails_closed_503(bedrock, monkeypatch):
    monkeypatch.delenv("GUARDRAIL_VERSION")
    result = index.handler(_event(_b64({"messages": [{"role": "user", "content": "x"}]})), None)
    assert _response(result)[0] == 503
    assert bedrock.calls == []


def test_oversized_text_fails_closed_413(bedrock):
    result = index.handler(_event(_b64({"messages": [{"role": "user", "content": "z" * 60_001}]})), None)
    assert _response(result)[0] == 413
    assert bedrock.calls == []


def test_non_json_and_non_object_bodies_are_rejected_400(bedrock):
    assert _response(index.handler(_event(_b64(b"not json")), None))[0] == 400
    assert _response(index.handler(_event(_b64([1, 2])), None))[0] == 400
    assert _response(index.handler(_event("%%%not-base64%%%"), None))[0] == 400
    assert bedrock.calls == []


# ------------------------------------------------------------------ passthrough
def test_requests_without_text_pass_through(bedrock):
    assert index.handler(_event(None, path="/inference/v1/models", method="GET"), None) == index.passthrough()
    assert index.handler(_event(_b64({"model": "m"})), None) == index.passthrough()
    assert bedrock.calls == []


def test_mcp_payload_passes_through_with_original_body(bedrock):
    event = {"interceptorInputVersion": "1.0", "mcp": {"gatewayRequest": {"body": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}}}
    result = index.handler(event, None)
    assert result["mcp"]["transformedGatewayRequest"]["body"]["method"] == "tools/list"
    assert bedrock.calls == []


def test_large_prompt_is_evaluated_in_multiple_calls(bedrock):
    text = "q" * 55_000
    result = index.handler(_event(_b64({"messages": [{"role": "user", "content": text}]})), None)
    assert result == index.passthrough()
    assert len(bedrock.calls) >= 3
    assert sum(len(c["text"]["text"]) for call in bedrock.calls for c in call["content"]) == 55_000
