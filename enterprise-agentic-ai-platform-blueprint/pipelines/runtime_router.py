"""IAM-invoked service router pinned to one named AgentCore endpoint.

Only trusted service callers receive InvokeFunction permission. Applications
must bind the actor/session to authenticated identity before invoking this
service; this Lambda is not an unauthenticated end-user API.
"""
import json
import math
import os
import re
import time

_client = None


def handler(event, context):
    global _client
    if not isinstance(event, dict) or set(event) - {"prompt", "actor_id", "sessionId"}:
        raise ValueError("Invalid runtime invocation")
    prompt, actor = event.get("prompt"), event.get("actor_id")
    session = event.get("sessionId")
    if (not isinstance(prompt, str) or not prompt or len(prompt.encode("utf-8")) > 8192
            or not isinstance(actor, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", actor)
            or not isinstance(session, str) or not re.fullmatch(r"[A-Za-z0-9_-]{33,128}", session)):
        raise ValueError("Invalid runtime invocation")
    if _client is None:
        import boto3
        from botocore.config import Config
        _client = boto3.client("bedrock-agentcore", config=Config(
            connect_timeout=3, read_timeout=60, retries={"total_max_attempts": 1}))
    try:
        response = _client.invoke_agent_runtime(
            agentRuntimeArn=os.environ["AGENTCORE_RUNTIME_ARN"],
            qualifier=os.environ["AGENTCORE_ENDPOINT"], runtimeSessionId=session,
            payload=json.dumps({"prompt": prompt, "actorId": actor}).encode("utf-8"),
            contentType="application/json", accept="application/json",
        )
    except Exception:
        # AWS runtime error messages may include an agent's original exception.
        raise RuntimeError("Pinned runtime invocation failed") from None
    try:
        data = response["response"].read(256 * 1024 + 1)
    finally:
        response["response"].close()
    if len(data) > 256 * 1024:
        raise ValueError("Runtime response exceeds limit")
    decoded = json.loads(data)
    if not isinstance(decoded, dict):
        raise ValueError("Runtime response is invalid")
    latency = decoded.get("inferenceFirstTokenMs")
    completed = decoded.get("stopReason") in {"done", "guardrail_intervened"}
    if (not isinstance(latency, (int, float)) or isinstance(latency, bool)
            or not math.isfinite(latency) or latency < 0):
        raise ValueError("Runtime telemetry is invalid")
    metrics = [{"Name": "CompletionFailures", "Unit": "Count"}]
    telemetry = {"FunctionName": os.environ["ROUTER_FUNCTION_NAME"],
                 "CompletionFailures": 0 if completed else 1}
    if latency > 0:
        metrics.append({"Name": "InferenceFirstTokenMs", "Unit": "Milliseconds"})
        telemetry["InferenceFirstTokenMs"] = latency
    telemetry["_aws"] = {"Timestamp": int(time.time() * 1000), "CloudWatchMetrics": [{
        "Namespace": "agenticai/runtime-canary", "Dimensions": [["FunctionName"]], "Metrics": metrics,
    }]}
    # Emit numeric telemetry only. Prompts, actor IDs, sessions and replies
    # must never become monitoring dimensions or log content.
    print(json.dumps(telemetry, separators=(",", ":")))
    return {"runtimeVersion": os.environ["AGENTCORE_VERSION"],
            "sourceRevision": os.environ["SOURCE_REVISION"], "result": decoded}
