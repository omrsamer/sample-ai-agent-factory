# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Response models for the endpoints that are new in the Agent Factory Portal."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from portal_api.containment_timing import CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS

HealthState = Literal["healthy", "needs_attention", "critical", "no_data"]


class CellHealth(BaseModel):
    tenant_id: str
    agent_id: str
    environment: str
    account_alias: str
    region: str
    state: HealthState
    alarms_in_alarm: int = 0
    reachable: bool = True
    omni_url: str | None = None  # the cell account's CloudWatch Omni domain, to link out to
    alarms_total: int = 0
    # Agent.id of the agent deployed in this cell, when one is known; use it to link to the agent.
    agent_ref: str | None = None
    detail: str | None = None


class FleetTotals(BaseModel):
    cells: int = 0
    healthy: int = 0
    needs_attention: int = 0
    critical: int = 0
    no_data: int = 0
    unreachable: int = 0
    alarms_in_alarm: int = 0


class FleetHealth(BaseModel):
    checked_at: str
    cells: list[CellHealth] = Field(default_factory=list)
    totals: FleetTotals = Field(default_factory=FleetTotals)


class AgentAttention(BaseModel):
    agent_id: str
    name: str
    risk_level: str
    flags: list[str] = Field(default_factory=list)  # the names of the flags that are true
    reasons: list[dict[str, str]] = Field(default_factory=list)  # code, severity, detail


class FleetSummary(BaseModel):
    """Counts across the whole inventory, for the fleet overview."""

    generated_at: str
    agents_total: int = 0
    by_inventory_state: dict[str, int] = Field(default_factory=dict)
    by_lifecycle: dict[str, int] = Field(default_factory=dict)
    by_risk_level: dict[str, int] = Field(default_factory=dict)
    # Per flag: how many agents have it set, and for how many it is not known.
    flags: dict[str, int] = Field(default_factory=dict)
    flags_unknown: dict[str, int] = Field(default_factory=dict)
    gateways_total: int = 0
    gateways_by_policy_mode: dict[str, int] = Field(default_factory=dict)
    # "ok", "disabled" (no discovery registry configured) or the error code when it could not be read.
    organization_registry: str = "disabled"
    # The review attestations in the audit trail: "ok", "disabled" (no audit table configured) or the
    # error code when they could not be read. Then every review date is the registration's own.
    review_attestations: str = "disabled"
    unreachable_cells: int = 0
    inactive_days: int = 30
    # CloudWatch Omni domains of the configured cells, to link out to. omni_url is set when there is exactly one.
    omni_url: str | None = None
    omni_domains: list[OmniDomain] = Field(default_factory=list)
    # The agents at risk level high or critical, most severe first, at most 20.
    needs_attention: list[AgentAttention] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class OmniDomain(BaseModel):
    account_alias: str
    region: str | None = None
    url: str | None = None


class ObservedService(BaseModel):
    """An agent CloudWatch Omni observes in telemetry."""

    name: str
    node_type: str  # SERVICE | RESOURCE
    category: str | None = None  # always GEN_AI_AGENT: only agents are listed
    resource_id: str | None = None  # the Runtime ARN and the endpoint it was called through
    runtime_arn: str | None = None  # the Runtime ARN alone, when the resource id holds one
    region: str | None = None
    last_observed_at: str | None = None  # null when the node reports no observation time
    signals: list[str] = Field(default_factory=list)  # LOGS, METRICS, TRACES, CONFIG
    registered: bool = False  # the resource is a registered agent's Runtime
    detected: bool = False  # the resource is a Runtime that a detection source found
    matched_agent_id: str | None = None  # the id of that agent in /agents, to link to
    # The matched agent's inventory state, or "observed_only": seen in telemetry, not registered, not detected.
    inventory_state: str = "observed_only"
    omni_region: str | None = None  # the Region of the Omni domain that observed it
    account_alias: str | None = None  # the account that domain belongs to


class ObservedServices(BaseModel):
    checked_at: str
    window_hours: int
    services: list[ObservedService] = Field(default_factory=list)
    omni_url: str | None = None
    # The Omni domains that were read: "Observed by CloudWatch Omni in <region> of <account_alias>".
    domains: list[OmniDomain] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CatalogModel(BaseModel):
    model_id: str
    provider: str
    regions: list[str] = Field(default_factory=list)
    status: str


class CatalogTool(BaseModel):
    tool_id: str
    name: str
    description: str | None = None
    owner: str | None = None
    cost_centre: str | None = None
    status: str
    version: str | None = None
    target_arn: str | None = None


# --- Registrations (agent governance records) and their audit trail -------------


class GoldenPathInput(BaseModel):
    model_config = {"extra": "forbid"}

    name: str
    version: str


class EvaluationInput(BaseModel):
    model_config = {"extra": "forbid"}

    verdict: str
    run_id: str | None = None
    completed_at: str | None = None


class RegistrationInput(BaseModel):
    """Request body of create and update: the governance document's fields in snake_case.

    Types only; lengths, patterns and enumerations are checked against the
    canonical JSON schema after the body is turned into a document.
    """

    model_config = {"extra": "forbid"}

    tenant_id: str
    agent_id: str
    environment: str
    owner_group: str
    business_purpose: str
    risk_class: str
    data_classification: str
    cost_centre: str
    application_id: str | None = None
    contact: str | None = None
    sponsor: str | None = None
    review_by: str | None = None
    framework: str | None = None
    golden_path: GoldenPathInput | None = None
    runtime_arn: str | None = None
    gateway_arn: str | None = None
    memory_id: str | None = None
    subscribed_tool_ids: list[str] | None = None
    policy_engine_arn: str | None = None
    policy_engine_mode: str | None = None
    source_revision: str | None = None
    evaluation: EvaluationInput | None = None
    record_version: str | None = None


class DecisionInput(BaseModel):
    """Request body of approve and reject."""

    model_config = {"extra": "forbid"}

    reason: str = Field(min_length=1, max_length=1000)
    # Optional guard: the decision is refused (409) if the record's document changed since it was read.
    document_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class RetireInput(BaseModel):
    """Request body of retire."""

    model_config = {"extra": "forbid"}

    reason: str = Field(min_length=1, max_length=1000)


class ReviewInput(BaseModel):
    """Request body of a review attestation."""

    model_config = {"extra": "forbid"}

    reason: str = Field(min_length=1, max_length=1000)
    # After today (UTC) and at most 366 days ahead; checked when the request is decided.
    next_review_by: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class Registration(BaseModel):
    record_id: str
    name: str
    status: str  # native registry status
    # The same status in the agent lifecycle vocabulary: proposed | pending_approval | approved |
    # rejected | deprecated. A retired registration is DEPRECATED and "deprecated".
    lifecycle_state: str = "proposed"
    status_reason: str | None = None
    record_version: str | None = None
    tenant_id: str | None = None
    agent_id: str | None = None
    environment: str | None = None
    document: dict[str, object]  # the governance document, snake_case keys
    document_sha256: str
    created_at: str | None = None
    updated_at: str | None = None


class RegistrationDetail(Registration):
    """One registration with who created, submitted and decided it, read from the audit trail.

    The people fields are null when the audit trail has no such event (for
    example a record published by a pipeline) or is not configured.
    """

    created_by: str | None = None
    created_by_label: str | None = None
    # Set while the record is PENDING_APPROVAL, APPROVED or REJECTED.
    submitted_by: str | None = None
    submitted_by_label: str | None = None
    submitted_at: str | None = None
    submitted_by_me: bool = False
    # Set while the record is APPROVED or REJECTED.
    decision: str | None = None  # "approve" | "reject"
    decided_by_label: str | None = None
    decided_at: str | None = None
    decision_reason: str | None = None  # the approver's full reason
    # The document as it was when last approved through the portal (snake_case), for a diff. Null when never.
    previous_approved: dict[str, object] | None = None
    # The latest attestation made through the portal: a review, or an approval of a document that
    # names a review date. Null when there is none.
    last_reviewed_at: str | None = None
    last_reviewed_by: str | None = None  # the reviewer's or approver's label
    # When the registration must be reviewed next: the latest attestation's date, else document.review_by.
    effective_review_by: str | None = None


class AuditEvent(BaseModel):
    event_id: str
    request_id: str
    at: str
    phase: str  # "intent" | "result"
    action: str  # create | update | submit | delete | approve | reject | retire | review; contain | release | sweep
    outcome: str  # allowed | denied | failed | unchanged; a sweep can also be skipped
    reason: str
    actor_subject: str
    actor_label: str
    actor_role: str
    tenant_id: str | None = None
    record_id: str | None = None
    record_name: str | None = None
    document_sha256: str | None = None
    status_before: str | None = None
    status_after: str | None = None
    # A review, and the result of an approval that recorded a review date: that date, YYYY-MM-DD.
    next_review_by: str | None = None
    # The result event of a review, or of an approval that recorded a review date: the time of the
    # attestation it wrote (the same value as last_reviewed_at).
    attested_at: str | None = None
    # Containment events only.
    agent_id: str | None = None
    runtime_arn: str | None = None
    sessions_found: int | None = None
    sessions_stopped: int | None = None
    sessions_failed: int | None = None
    # The result of a contain: how many background sweeps it scheduled.
    sweeps_scheduled: int | None = None
    # A background sweep (action "sweep"): which one it is (1, 2 or 3), how many sessions had
    # already ended, and how long the sweep took.
    sweep: int | None = None
    sessions_not_active: int | None = None
    duration_ms: int | None = None
    # For example why sessions could not be listed; on a retirement, what retirement means; on an
    # approval, that its review date could not be recorded.
    detail: str | None = None


class RegistrationHistory(BaseModel):
    record_id: str
    # The newest events of the record's history, newest first: at most 200.
    events: list[AuditEvent] = Field(default_factory=list)
    events_truncated: bool = False  # the history holds older events that are not listed


class ActionResult(BaseModel):
    action: str
    outcome: str = "allowed"  # "unchanged" when there was nothing to change (retiring a retired record)
    reason: str
    request_id: str
    registration: Registration | None = None  # null after a delete
    # False when the action was performed but its result event could not be written.
    audit_complete: bool = True


# --- Containment -------------------------------------------------------------------


class ContainmentInput(BaseModel):
    """Request body of contain and release."""

    model_config = {"extra": "forbid"}

    reason: str = Field(min_length=1, max_length=1000)
    # Needed only for an agent that has no registration when more than one cell account can be contained.
    # It must be the Runtime's ARN exactly as the portal writes it: another spelling of the partition,
    # the Region or the account is refused (422). ASCII digits only: ``\d`` would accept others.
    runtime_arn: str | None = Field(
        default=None,
        pattern=r"^arn:aws[a-z-]{0,10}:bedrock-agentcore:[a-z0-9-]{1,30}:[0-9]{12}:runtime/[A-Za-z0-9_-]{1,100}$",
    )


class SessionsStopped(BaseModel):
    # "ok"; "ok; <what was incomplete>"; or "sessions could not be listed (<why>)" when no source could be read.
    discovery: str
    # Where the sessions were found, before de-duplication: the Runtime's spans and its session log streams.
    sources: dict[str, int] = Field(default_factory=lambda: {"spans": 0, "log_streams": 0})
    found: int = 0
    stopped: int = 0
    not_active: int = 0  # unknown or already ended: no stop was needed
    failed: int = 0
    not_attempted: int = 0  # the time budget ran out first
    stop_errors: list[str] = Field(default_factory=list)  # error codes of the stops that failed


class ContainmentStep(BaseModel):
    id: str  # policy | verify | sessions
    label: str
    status: str  # done | unchanged | partial | failed | skipped
    detail: str | None = None


class ContainmentResult(BaseModel):
    action: str  # contain | release
    outcome: str  # allowed | unchanged
    reason: str
    request_id: str
    agent_id: str
    runtime_arn: str
    state: str  # contained | not_contained, verified by reading the policy back
    changed: bool
    # Contain only: a statement with the portal's identifier that the portal had not written was
    # in the policy (it did not deny invocation) and was replaced by the portal's own.
    replaced_foreign_statement: bool = False
    policy_deleted: bool = False  # release only: the policy held nothing else, so it was deleted
    other_statements_kept: int = 0
    sessions: SessionsStopped | None = None  # contain only
    # What was done, step by step. partial is true when a step did not complete.
    steps: list[ContainmentStep] = Field(default_factory=list)
    partial: bool = False
    denied_actions: list[str] = Field(default_factory=list)  # contain: the invoke actions the statement denies
    # How long this change can take to apply everywhere: about a minute for contain, several
    # minutes for release (the service applies a policy change host by host).
    enforcement_delay_seconds: int = CONTAIN_DELAY_SECONDS
    # Contain only: the background sweeps that were scheduled, as seconds from now. Empty when
    # background sweeps are not configured, or could not be scheduled (a step then says why).
    sweeps_scheduled_in_seconds: list[int] = Field(default_factory=list)
    # Contain only, with outcome "unchanged": set when the agent was contained a moment ago and
    # this request therefore did nothing (no session was stopped, nothing was scheduled). It says
    # in how many seconds to ask again: when a contain does its work again, or, while a background
    # sweep has yet to report, the earliest that can be.
    retry_after_seconds: int | None = None
    audit_complete: bool = True


class ContainmentSweeps(BaseModel):
    """The background sweeps of the containment that holds."""

    scheduled: int = 0
    done: int = 0  # how many of them have run, whatever their outcome


class ContainmentView(BaseModel):
    agent_id: str
    state: str  # contained | not_contained | unknown
    runtime_arn: str | None = None
    enabled: bool = False  # the agent's cell has a containment role, so the actions can work
    contained_by: str | None = None
    contained_by_label: str | None = None
    contained_at: str | None = None
    reason: str | None = None
    contained_by_me: bool = False  # the caller contained it and therefore cannot release it
    # Why the state is unknown (for example no reader in the agent's account). Also set when the
    # state is not_contained although a statement with the portal's identifier is in the policy:
    # that statement does not deny invocation, and a contain replaces it.
    detail: str | None = None
    partial: bool = False  # the containment that holds did not stop every session it found
    # How long a contain, and a release, can take to apply everywhere.
    enforcement_delay_seconds: int = CONTAIN_DELAY_SECONDS
    release_delay_seconds: int = RELEASE_DELAY_SECONDS
    # Background sweeps after the contain, and since when the agent is known to be quiet: the end
    # of the first sweep that started after every host applies the deny, listed every session and
    # left none running. Null until such a sweep has run.
    sweeps: ContainmentSweeps = Field(default_factory=ContainmentSweeps)
    quiet_at: str | None = None
    # The newest events of the Runtime's containment history, newest first: at most 200.
    events: list[AuditEvent] = Field(default_factory=list)
    events_truncated: bool = False  # the history holds older events that are not listed
