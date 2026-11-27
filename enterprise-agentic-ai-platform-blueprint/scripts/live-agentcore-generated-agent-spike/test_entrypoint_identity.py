"""Reject unbound identity before token, inference, MCP or Memory clients exist."""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("identity_entrypoint_agent",
    Path(__file__).parent / "agent" / "agent.py")
agent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = agent
SPEC.loader.exec_module(agent)


class App:
    invoke = None
    def entrypoint(self, function):
        self.invoke = function
        return function


@pytest.mark.parametrize("payload", [
    None, {}, {"prompt": "synthetic"}, {"prompt": "synthetic", "actorId": ""},
    {"prompt": "synthetic", "actorId": {"id": "owner"}},
    {"prompt": "synthetic", "actorId": "default-actor\nforeign"},
    {"prompt": "x" * 8193, "actorId": "synthetic_owner"},
])
def test_invalid_identity_or_input_rejects_before_external_sinks(monkeypatch, payload):
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", types.SimpleNamespace(BedrockAgentCoreApp=App))
    calls = []
    monkeypatch.setattr(agent, "_fetch_inference_bearer", lambda: calls.append("token"))
    monkeypatch.setattr(agent, "build_production_core", lambda *a, **k: calls.append("core"))
    with pytest.raises(agent.AgentError, match="explicit actorId"):
        agent._load_entrypoint().invoke(payload)
    assert not calls


def test_real_entrypoint_passes_explicit_actor_to_core(monkeypatch):
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", types.SimpleNamespace(BedrockAgentCoreApp=App))
    for key, value in {
        "AGENTCORE_REGION": "eu-west-1",
        "AGENTCORE_TENANT_ID": "shared", "AGENTCORE_AGENT_ID": "shared",
        "AGENTCORE_ENV_NAME": "nonprod", "AGENTCORE_GUARDRAIL_ID": "reviewed-guardrail",
        "AGENTCORE_MODEL_ID": "reviewed-model", "AGENTCORE_GATEWAY_URL": "https://reviewed/mcp",
    }.items():
        monkeypatch.setenv(key, value)
    seen = []
    class Core:
        def run(self, prompt, **identity):
            seen.append((prompt, identity))
            raise agent.AgentError("test core stop")
    monkeypatch.setattr(agent, "_fetch_inference_bearer", lambda: "ephemeral-test-token")
    monkeypatch.setattr(agent, "build_production_core", lambda *a, **k: Core())
    with pytest.raises(agent.AgentError, match="test core stop"):
        agent._load_entrypoint().invoke({"prompt": "synthetic", "actorId": "synthetic_owner"})
    assert seen[0][1]["actor_id"] == "synthetic_owner"
    assert seen[0][1]["session_id"] != agent.ReferenceAgentCore._fingerprint("default-actor")[:16]
