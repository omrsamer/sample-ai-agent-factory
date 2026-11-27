# SPDX-License-Identifier: Apache-2.0
# Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
"""Response models that keep the console's existing wire shapes.

Field names and meanings follow the console front end's client types. Fields
marked "portal addition" are additive: they carry blueprint facts the original
shapes have no place for and can be ignored by a client that does not know them.
Everything here is a read model; the Agent Factory Portal has no write path.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# --- Current user ------------------------------------------------------------


class UserInfo(BaseModel):
    email: str
    role: str  # "admin" | "operator" | "viewer"
    role_level: int
    can_deploy: bool = False
    oid: str | None = None
    name: str | None = None
    tenants: list[dict[str, Any]] = Field(default_factory=list)
    # portal additions
    portal_role: str
    groups: list[str] = Field(default_factory=list)
    identity_provider: str
    read_only: bool = True


# --- Agents ------------------------------------------------------------------


class AgentGovernance(BaseModel):
    """Portal addition: the blueprint governance document behind a registered agent."""

    tenant_id: str | None = None
    agent_id: str | None = None
    application_id: str | None = None
    environment: str | None = None
    owner_group: str | None = None
    contact: str | None = None
    business_purpose: str | None = None
    risk_class: str | None = None
    data_classification: str | None = None
    cost_centre: str | None = None
    framework: str | None = None
    golden_path: dict[str, str] | None = None
    runtime_arn: str | None = None
    gateway_arn: str | None = None
    memory_id: str | None = None
    subscribed_tool_ids: list[str] = Field(default_factory=list)
    policy_engine_arn: str | None = None
    policy_engine_mode: str | None = None
    source_revision: str | None = None
    evaluation: dict[str, Any] | None = None
    record_version: str | None = None


class Agent(BaseModel):
    id: str
    name: str
    purpose: str | None = None
    sponsor_oid: str | None = None
    sponsor_email: str | None = None
    business_unit: str | None = None
    region: str | None = None
    data_classification: str | None = None
    platform: str | None = "aws_bedrock"
    framework: str | None = None
    mcp_server_ids: list[str] = Field(default_factory=list)
    declared_mcp_server_ids: list[str] = Field(default_factory=list)
    origin: str = "Deployed"  # "Deployed" | "Registered"
    identity_status: str = "none"
    # "proposed" | "pending_approval" | "approved" | "rejected" | "deprecated", plus the
    # portal value "discovered" for a runtime that no registry record references yet.
    lifecycle_state: str
    endpoint_url: str | None = None
    auth_type: str = "none"
    agent_arn: str | None = None
    agent_arns: dict[str, str] | None = None
    trace_delivery: str | None = "auto"
    tenant_id: str | None = None
    published: bool = False
    created_at: str
    updated_at: str
    created_by: str | None = None
    # portal additions
    registration: Literal["registered", "discovered"] = "registered"
    registry_status: str | None = None
    environment: str | None = None
    account_id: str | None = None
    runtime_status: str | None = None
    governance: AgentGovernance | None = None


class RuntimeStatus(BaseModel):
    agent_id: str
    stage: str
    status: str  # "ready" | "creating" | "updating" | "failed" | "not_deployed" | "unknown"
    runtime_arn: str | None = None
    image_tag: str | None = None
    checked_at: str
    detail: str | None = None


class Deployment(BaseModel):
    id: str
    repo_id: str = ""
    agent_id: str | None = None
    mcp_server_id: str | None = None
    stage: str
    seq_key: str
    image_tag: str
    source_sha: str | None = None
    build_id: str | None = None
    outcome: str  # "started" | "succeeded" | "failed"
    actor: str | None = None
    actor_kind: str | None = None
    started_at: str
    completed_at: str | None = None
    error: str | None = None


# --- Traces and metrics ------------------------------------------------------


class TraceRow(BaseModel):
    id: str
    timestamp: str | None = None
    name: str | None = None
    user_id: str | None = None
    latency_ms: float | None = None
    cost_usd: float = 0.0
    # portal additions
    status: str | None = None
    session_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


class TracePage(BaseModel):
    data: list[TraceRow] = Field(default_factory=list)
    total: int = 0
    warnings: list[str] = Field(default_factory=list)  # portal addition


class MetricTotals(BaseModel):
    traces: int = 0
    cost_usd: float = 0.0
    tokens: int = 0


class DailyMetric(BaseModel):
    date: str
    traces: int = 0
    cost_usd: float = 0.0
    tokens: int = 0
    errors: int = 0  # portal addition


class ModelMetric(BaseModel):
    model: str
    cost_usd: float = 0.0
    tokens: int = 0


class UserMetric(BaseModel):
    user_id: str
    cost_usd: float = 0.0
    traces: int = 0


class RuntimeMetrics(BaseModel):
    """Portal addition: Amazon CloudWatch runtime metrics for the selected window."""

    invocations: int = 0
    system_errors: int = 0
    user_errors: int = 0
    throttles: int = 0
    latency_avg_ms: float | None = None


class AgentMetrics(BaseModel):
    totals: MetricTotals = Field(default_factory=MetricTotals)
    daily: list[DailyMetric] = Field(default_factory=list)
    by_model: list[ModelMetric] = Field(default_factory=list)
    by_user: list[UserMetric] = Field(default_factory=list)
    # portal additions
    runtime: RuntimeMetrics = Field(default_factory=RuntimeMetrics)
    cost_available: bool = False
    warnings: list[str] = Field(default_factory=list)


class AgentMetricRow(BaseModel):
    agent_id: str
    agent_name: str
    tenant_id: str | None = None
    totals: MetricTotals = Field(default_factory=MetricTotals)


class ScopeMetrics(AgentMetrics):
    by_agent: list[AgentMetricRow] = Field(default_factory=list)


class ObservabilitySettings(BaseModel):
    langfuse_host: str | None = None
    configured: bool = True
    # portal additions
    backend: str = "cloudwatch"
    traces_log_group: str = "aws/spans"
    metrics_namespace: str = "AWS/Bedrock-AgentCore"


# --- Release evidence (the console's evaluation-run shape) ---------------------


class EvalGate(BaseModel):
    passed: bool
    reasons: list[str] = Field(default_factory=list)


class PipelineEvidence(BaseModel):
    """Portal addition: the pipeline execution a run row was derived from."""

    pipeline_name: str
    execution_id: str
    status: str
    source_revision: str | None = None
    source_summary: str | None = None
    trigger_type: str | None = None
    evaluation_gate_status: str | None = None
    evaluation_gate_summary: str | None = None
    evaluation_gate_started_at: str | None = None
    evaluation_gate_finished_at: str | None = None


class EvalRun(BaseModel):
    run_id: str
    repo_id: str = ""
    agent_id: str
    project_id: str = ""
    stage: str
    git_sha: str | None = None
    item_count: int | None = None
    digest: str | None = None
    build_tag: str | None = None
    trigger: str = "auto"
    started_by: str = "pipeline"
    started_at: str
    finished_at: str | None = None
    status: str  # "running" | "passed" | "failed" | "error"
    config: dict[str, Any] = Field(
        default_factory=lambda: {
            "version": 1,
            "dataset": "",
            "checks": {"tools": "off", "args": "off", "no_error": False},
            "judges": [],
            "gate": {"checks": "all_pass", "judge_min_mean": 0},
        }
    )
    summary: dict[str, Any] | None = None
    gate: EvalGate | None = None
    regressions: list[str] = Field(default_factory=list)
    pipeline: PipelineEvidence | None = None  # portal addition


class EvalRuns(BaseModel):
    runs: list[EvalRun] = Field(default_factory=list)
    overrides: list[dict[str, Any]] = Field(default_factory=list)
    current_digest: str | None = None
    current_build_tag: str | None = None
    current_run: EvalRun | None = None
    warnings: list[str] = Field(default_factory=list)  # portal addition


# --- MCP servers (Workstream Tool Gateways) ----------------------------------


class McpTool(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    # portal additions
    tool_id: str | None = None
    target_name: str | None = None
    target_type: str | None = None
    target_status: str | None = None
    registered: bool = False
    owner: str | None = None
    cost_centre: str | None = None
    status: str | None = None
    version: str | None = None


class McpServer(BaseModel):
    id: str
    name: str
    description: str | None = None
    kind: str = "gateway"
    owner_oid: str | None = None
    owner_email: str | None = None
    business_unit: str | None = None
    region: str | None = None
    data_classification: str | None = None
    endpoint_url: str | None = None
    version: str = "1"
    available_tools: list[McpTool] = Field(default_factory=list)
    gateway_arn: str | None = None
    cedar_policy_engine_id: str | None = None
    cedar_policy_engine_arn: str | None = None
    cedar_enforcement_mode: str = "none"  # "none" | "log_only" | "enforce"
    gateway_id: str | None = None
    gateway_url: str | None = None
    runtime_arn: str | None = None
    identity_status: str = "none"
    lifecycle_state: str = "approved"
    tenant_id: str | None = None
    published: bool = False
    shared: bool = False
    created_at: str
    updated_at: str
    created_by: str | None = None
    # portal additions
    gateway_status: str | None = None
    authorizer_type: str | None = None
    environment: str | None = None
    account_id: str | None = None
    agent_id: str | None = None


class CedarPolicyRow(BaseModel):
    policy_id: str
    user_oid: str | None = None
    user_label: str | None = None
    tool: str | None = None
    effect: str  # "allow" | "deny"
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    managed: bool = False
    cedar_text: str
    kind: str | None = None
    agent_app_id: str | None = None
    # portal additions
    name: str | None = None
    status: str | None = None
    editable: bool = False


class CedarPolicySet(BaseModel):
    enforcement_mode: str = "none"
    engine_id: str | None = None
    policies: list[CedarPolicyRow] = Field(default_factory=list)
    editable: bool = False  # portal addition
    warnings: list[str] = Field(default_factory=list)  # portal addition


class PolicyEnforcement(BaseModel):
    enforcement_mode: str = "none"
    engine_id: str | None = None  # portal addition


# --- Grants (derived, read-only) ---------------------------------------------


class Grant(BaseModel):
    assignment_id: str
    principal_id: str
    principal_display: str
    principal_type: str = "ServicePrincipal"
    role: str = "Invoker"
    # portal additions
    source: str | None = None
    tool_ids: list[str] = Field(default_factory=list)
    derived: bool = True


class AgentMcpGrant(BaseModel):
    mcp_id: str
    mcp_name: str
    role: str = "Invoker"
    assignment_id: str
    # portal additions
    source: str | None = None
    tool_ids: list[str] = Field(default_factory=list)
    derived: bool = True


# --- Governance graph --------------------------------------------------------


class GraphNode(BaseModel):
    type: Literal["user", "group", "agent", "mcp"]
    id: str  # "<type>:<entity-id>"
    label: str
    ref_id: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: Literal["access", "can_call"]
    role: str
    has_policy: bool = False


class GovernanceGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class PrincipalDetail(BaseModel):
    id: str
    display_name: str
    kind: Literal["user", "group"]
    user_principal_name: str | None = None
    mail: str | None = None
    job_title: str | None = None
    group_names: list[str] = Field(default_factory=list)


# --- Guardrails --------------------------------------------------------------


class GuardrailTemplate(BaseModel):
    template_id: str
    name: str
    description: str | None = None
    status: str  # "draft" | "creating" | "active" | "updating" | "failed" | "deleting" | "deleted"
    guardrail_id: str | None = None
    guardrail_arn: str | None = None
    guardrail_version: str | None = None
    content_filters: list[dict[str, Any]] = Field(default_factory=list)
    denied_topics: list[dict[str, Any]] = Field(default_factory=list)
    pii_entities: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_regexes: list[dict[str, Any]] = Field(default_factory=list)
    word_filter: dict[str, Any] | None = None
    contextual_grounding: dict[str, Any] | None = None
    status_history: list[dict[str, Any]] = Field(default_factory=list)
    created_by: str | None = None
    created_at: str
    updated_at: str
    read_only: bool = True  # portal addition
