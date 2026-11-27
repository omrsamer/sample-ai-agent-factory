"""AgentCore Gateway REQUEST interceptor: server-side Bedrock Guardrail
enforcement for the central inference Gateway.

Why this exists
---------------
The Gateway's Bedrock Mantle inference connector calls the model under the
Gateway's own role and ignores any client-supplied ``guardrail_identifier``;
``bedrock-mantle`` exposes no guardrail IAM condition key, and AgentCore
Policy guardrail providers accept only string data paths while the OpenAI
``messages`` field is a set of records (proven live 2026-09-24). This
interceptor is therefore the single enforcement point: every inference
request body is evaluated with ``bedrock:ApplyGuardrail`` against the
platform baseline guardrail BEFORE the Gateway calls the target.

Contract (HTTP/inference interceptor payload, ``interceptorInputVersion`` 1.0)
-----------------------------------------------------------------------------
* All client-supplied text is guarded, including every message role and
  top-level `system`/`instructions`. Role labels do not establish provenance.
* An operator may approve exact static system/developer prompts by SHA-256
  digest in server configuration. Only the complete matching prompt is
  exempt; appended text and user/tool/assistant turns remain guarded.
* Each guarded turn is scored on its own ApplyGuardrail call (concurrently),
  never concatenated with other turns: the prompt-attack classifier scores
  unrelated turns differently when joined (proven live 2026-09-24).
* Guardrail intervened              -> short-circuit HTTP 403 (no model call)
  This includes anonymization: flattened/chunked turns cannot be mapped
  safely back into every supported request field, so original text is refused.
* Guardrail API unavailable/error   -> short-circuit HTTP 503 (fail closed)
* Body too large to evaluate        -> short-circuit HTTP 413 (fail closed)
* Body is not a JSON object         -> short-circuit HTTP 400
* No evaluable text (GET, models)   -> pass through unchanged
* Guardrail returned NONE           -> pass through unchanged
* MCP-shaped payloads               -> pass through unchanged

The interceptor never logs or returns request text; decisions are logged with
the guardrail assessment types only. The JSON error body (``error.code``,
``error.tripped``) is the client contract: the Gateway does not propagate the
``x-agenticai-guardrail`` header from a short-circuit response (proven live
2026-09-24), so that header only aids direct invocation tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

OUTPUT_VERSION = "1.0"
# One ApplyGuardrail call covers at most this many characters (25 text units).
BATCH_CHARACTERS = 25_000
# A single content block is split above this size.
BLOCK_CHARACTERS = 20_000
# Fields that carry model input across the OpenAI-, Anthropic- and
# Responses-style request shapes served on the /inference path.
INPUT_FIELDS = ("messages", "input", "prompt")
SYSTEM_FIELDS = ("system", "instructions")
TEXT_PART_TYPES = {"text", "input_text", "output_text"}

_BEDROCK = None


class GuardrailUnavailable(Exception):
    """Raised when the guardrail decision cannot be obtained."""


def _bedrock_runtime():
    global _BEDROCK  # noqa: PLW0603 - client reuse across warm invocations
    if _BEDROCK is None:
        _BEDROCK = boto3.client(
            "bedrock-runtime",
            config=Config(
                retries={"max_attempts": 3, "mode": "standard"},
                read_timeout=10,
                connect_timeout=3,
            ),
        )
    return _BEDROCK


def settings() -> dict[str, Any]:
    identifier = os.environ.get("GUARDRAIL_IDENTIFIER", "").strip()
    version = os.environ.get("GUARDRAIL_VERSION", "").strip()
    if not identifier or not version:
        raise GuardrailUnavailable("GUARDRAIL_IDENTIFIER and GUARDRAIL_VERSION must be set")
    try:
        trusted_hashes = json.loads(os.environ.get("TRUSTED_SYSTEM_PROMPT_SHA256", "[]"))
        if (
            not isinstance(trusted_hashes, list)
            or len(trusted_hashes) > 32
            or any(not isinstance(value, str) or len(value) != 64
                   or any(char not in "0123456789abcdef" for char in value)
                   for value in trusted_hashes)
        ):
            raise ValueError("expected at most 32 lowercase SHA-256 digests")
        max_characters = int(os.environ.get("MAX_GUARDED_CHARACTERS", "200000"))
        if max_characters <= 0:
            raise ValueError("MAX_GUARDED_CHARACTERS must be positive")
    except (ValueError, TypeError) as exc:
        raise GuardrailUnavailable("Invalid server guardrail configuration") from exc
    return {
        "identifier": identifier,
        "version": version,
        "max_characters": max_characters,
        "trusted_system_prompt_hashes": frozenset(trusted_hashes),
        "blocked_message": os.environ.get(
            "BLOCKED_MESSAGE",
            "Your input violates our AI usage policy and cannot be processed.",
        ),
    }


# --------------------------------------------------------------------------- #
# Interceptor payload helpers
# --------------------------------------------------------------------------- #
def passthrough() -> dict[str, Any]:
    return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}


def mcp_passthrough(event: dict[str, Any]) -> dict[str, Any]:
    request = (event.get("mcp") or {}).get("gatewayRequest") or {}
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayRequest": {"body": request.get("body", {})}},
    }


def short_circuit(status: int, code: str, message: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"message": message, "type": code, "code": code}
    if extra:
        error.update(extra)
    body = base64.b64encode(json.dumps({"error": error}).encode("utf-8")).decode("ascii")
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "http": {
            "transformedGatewayResponse": {
                "statusCode": status,
                "contentType": "application/json",
                "headers": {"x-agenticai-guardrail": code},
                "body": body,
            }
        },
    }


def decode_body(encoded: str | None) -> Any:
    """Return the parsed JSON body, ``None`` for an empty body.

    Raises ``ValueError`` when the body is present but is not JSON.
    """
    if not encoded:
        return None
    raw = base64.b64decode(encoded, validate=True)
    if not raw.strip():
        return None
    return json.loads(raw)


# --------------------------------------------------------------------------- #
# Text extraction
# --------------------------------------------------------------------------- #
def _texts_from_content(content: Any) -> Iterable[str]:
    if isinstance(content, str):
        if content:
            yield content
        return
    if isinstance(content, list):
        for part in content:
            yield from _texts_from_content(part)
        return
    if isinstance(content, dict):
        if content.get("type") in TEXT_PART_TYPES and isinstance(content.get("text"), str):
            if content["text"]:
                yield content["text"]
        elif content.get("type") in {"thinking", "refusal"}:
            field = content["type"]
            if isinstance(content.get(field), str) and content[field]:
                yield content[field]
        elif "content" in content:
            yield from _texts_from_content(content["content"])
        elif content.get("type") == "function_call_output":
            yield from _texts_from_content(content.get("output"))
        elif content.get("type") == "function_call" and isinstance(content.get("arguments"), str):
            yield content["arguments"]
        elif content.get("type") == "tool_use" and "input" in content:
            yield json.dumps(content["input"], ensure_ascii=True, sort_keys=True)


def _approved_system_prompt(text: str, trusted_hashes: frozenset[str]) -> bool:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() in trusted_hashes


def _texts_from_turns(value: Any, trusted_hashes: frozenset[str]) -> Iterable[str]:
    """One string per complete turn; client role labels alone never exempt it."""
    if isinstance(value, str):
        if value:
            yield value
        return
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and "role" in item:
                turn = "\n".join(_texts_from_content(item.get("content")))
                role = item.get("role")
                if turn and not (
                    isinstance(role, str) and role.lower() in {"system", "developer"}
                    and _approved_system_prompt(turn, trusted_hashes)
                ):
                    yield turn
                # OpenAI assistant calls can have null content and still carry
                # caller-controlled model context in function arguments.
                for field in ("tool_calls", "function_call"):
                    if isinstance(item.get(field), (dict, list)) and item[field]:
                        yield json.dumps(item[field], ensure_ascii=True, sort_keys=True)
            else:
                turn = "\n".join(_texts_from_content(item))
                if turn:
                    yield turn
        return
    if isinstance(value, dict):
        if "role" in value:
            yield from _texts_from_turns([value], trusted_hashes)
        else:
            turn = "\n".join(_texts_from_content(value))
            if turn:
                yield turn


def extract_texts(payload: dict[str, Any], trusted_hashes: frozenset[str] = frozenset()) -> list[str]:
    """Collect the guarded turns across the supported request shapes.

    Each element is one client-controlled turn. An exemption requires the
    exact complete system prompt to match operator-owned configuration.
    """
    texts: list[str] = []
    for field in INPUT_FIELDS:
        if field in payload:
            texts.extend(_texts_from_turns(payload[field], trusted_hashes))
    for field in SYSTEM_FIELDS:
        turn = "\n".join(_texts_from_content(payload.get(field)))
        if turn and not _approved_system_prompt(turn, trusted_hashes):
            texts.append(turn)
    # Function/tool descriptions and schemas are also model-visible caller
    # input. Neither an approved system prompt nor a role label exempts them.
    for field in ("tools", "functions"):
        if isinstance(payload.get(field), (dict, list)) and payload[field]:
            texts.append(json.dumps(payload[field], ensure_ascii=True, sort_keys=True))
    return texts


def split_blocks(texts: Iterable[str]) -> list[str]:
    blocks: list[str] = []
    for text in texts:
        for start in range(0, len(text), BLOCK_CHARACTERS):
            blocks.append(text[start : start + BLOCK_CHARACTERS])
    return blocks


def turn_batches(turn: str) -> Iterable[list[str]]:
    """Content blocks for ONE turn, grouped under the per-call budget."""
    batch: list[str] = []
    size = 0
    for block in split_blocks([turn]):
        if batch and size + len(block) > BATCH_CHARACTERS:
            yield batch
            batch, size = [], 0
        batch.append(block)
        size += len(block)
    if batch:
        yield batch


# --------------------------------------------------------------------------- #
# Guardrail evaluation
# --------------------------------------------------------------------------- #
def blocked_types(assessments: Iterable[dict[str, Any]]) -> list[str]:
    """Names of every assessment entry whose action is BLOCKED (never matches)."""
    tripped: list[str] = []
    for assessment in assessments or []:
        for policy in (
            ("contentPolicy", "filters", "type"),
            ("topicPolicy", "topics", "name"),
            ("wordPolicy", "customWords", "match"),
            ("wordPolicy", "managedWordLists", "type"),
            ("sensitiveInformationPolicy", "piiEntities", "type"),
            ("sensitiveInformationPolicy", "regexes", "name"),
            ("contextualGroundingPolicy", "filters", "type"),
        ):
            section, key, label = policy
            for entry in (assessment.get(section) or {}).get(key) or []:
                if entry.get("action") == "BLOCKED":
                    name = entry.get(label) if label != "match" else "CUSTOM_WORD"
                    tripped.append(f"{section}.{name}")
    return sorted(set(tripped))


def evaluate_turn(turn: str, cfg: dict[str, Any]) -> list[str]:
    """Tripped assessment types for ONE untrusted turn (empty = allowed)."""
    tripped: list[str] = []
    for batch in turn_batches(turn):
        try:
            response = _bedrock_runtime().apply_guardrail(
                guardrailIdentifier=cfg["identifier"],
                guardrailVersion=cfg["version"],
                source="INPUT",
                content=[{"text": {"text": block}} for block in batch],
            )
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailUnavailable(str(exc)[:300]) from exc
        action = response.get("action") if isinstance(response, dict) else None
        if action == "GUARDRAIL_INTERVENED":
            try:
                types = blocked_types(response.get("assessments") or [])
            except (AttributeError, TypeError) as exc:
                raise GuardrailUnavailable("Invalid guardrail assessment response") from exc
            # Extracted turns may combine fields or serialize tool objects, and
            # are then chunked without a reversible field-to-output mapping.
            # Anonymized output therefore cannot authorize the original body.
            tripped.extend(types or ["guardrail.INTERVENTION"])
        elif action != "NONE":
            raise GuardrailUnavailable("Invalid guardrail decision response")
    return tripped


def apply_guardrail(turns: list[str], cfg: dict[str, Any]) -> tuple[bool, list[str]]:
    """Evaluate every untrusted turn on its own; return (blocked, tripped).

    Turns are scored separately -- the way a Converse loop would have scored
    each input as it arrived -- because the prompt-attack classifier scores
    the concatenation of unrelated turns differently from each turn alone
    (live 2026-09-24: a benign user request plus a benign tool result scored
    PROMPT_ATTACK LOW only when evaluated together).
    """
    tripped: list[str] = []
    if len(turns) == 1:
        tripped = evaluate_turn(turns[0], cfg)
    else:
        with ThreadPoolExecutor(max_workers=min(8, len(turns))) as pool:
            for result in pool.map(lambda turn: evaluate_turn(turn, cfg), turns):
                tripped.extend(result)
    return (len(tripped) > 0, sorted(set(tripped)))


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #
def _request_id(context: Any) -> str:
    try:
        return context.client_context.custom.get("REQUEST_ID", "")  # type: ignore[union-attr]
    except AttributeError:
        return ""


def _log(decision: str, **fields: Any) -> None:
    LOGGER.info(json.dumps({"decision": decision, **fields}, default=str))


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if "mcp" in event and "http" not in event:
        return mcp_passthrough(event)
    http = event.get("http") or {}
    request = http.get("gatewayRequest") or {}
    if http.get("gatewayResponse") is not None and not request:
        return passthrough()  # RESPONSE interception is not configured.

    path = request.get("path", "")
    method = request.get("httpMethod", "")
    rid = _request_id(context)

    try:
        cfg = settings()
    except GuardrailUnavailable as exc:
        _log("fail_closed_misconfigured", path=path, requestId=rid, reason=str(exc))
        return short_circuit(503, "guardrail_unavailable", "Guardrail enforcement is not configured.")

    try:
        payload = decode_body(request.get("body"))
    except (ValueError, TypeError) as exc:
        _log("rejected_invalid_body", path=path, requestId=rid, reason=type(exc).__name__)
        return short_circuit(400, "invalid_request_error", "Request body must be a JSON object.")

    if payload is None:
        return passthrough()
    if not isinstance(payload, dict):
        _log("rejected_invalid_body", path=path, requestId=rid, reason="not_an_object")
        return short_circuit(400, "invalid_request_error", "Request body must be a JSON object.")

    turns = extract_texts(payload, cfg["trusted_system_prompt_hashes"])
    total = sum(len(turn) for turn in turns)
    if total == 0:
        _log("passthrough_no_text", path=path, method=method, requestId=rid)
        return passthrough()
    if total > cfg["max_characters"]:
        _log("fail_closed_too_large", path=path, requestId=rid, characters=total)
        return short_circuit(
            413,
            "guarded_input_too_large",
            f"Request text exceeds the {cfg['max_characters']} character guardrail evaluation limit.",
        )

    try:
        blocked, tripped = apply_guardrail(turns, cfg)
    except GuardrailUnavailable as exc:
        _log("fail_closed_guardrail_error", path=path, requestId=rid, reason=str(exc))
        return short_circuit(503, "guardrail_unavailable", "Guardrail evaluation is unavailable; request refused.")

    if blocked:
        _log("blocked", path=path, requestId=rid, characters=total, tripped=tripped,
             guardrail=cfg["identifier"], version=cfg["version"])
        return short_circuit(
            403,
            "guardrail_intervened",
            cfg["blocked_message"],
            {
                "guardrail": {"id": cfg["identifier"], "version": cfg["version"]},
                "tripped": tripped,
            },
        )
    _log("allowed", path=path, requestId=rid, characters=total, turns=len(turns))
    return passthrough()
