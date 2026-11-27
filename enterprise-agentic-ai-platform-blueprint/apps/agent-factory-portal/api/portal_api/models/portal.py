# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Response models for the endpoints that are new in the Agent Factory Portal."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

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


class Registration(BaseModel):
    record_id: str
    name: str
    status: str  # native registry status
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


class AuditEvent(BaseModel):
    event_id: str
    request_id: str
    at: str
    phase: str  # "intent" | "result"
    action: str  # create | update | submit | delete | approve | reject
    outcome: str  # allowed | denied | failed
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


class RegistrationHistory(BaseModel):
    record_id: str
    events: list[AuditEvent] = Field(default_factory=list)


class ActionResult(BaseModel):
    action: str
    outcome: str = "allowed"
    reason: str
    request_id: str
    registration: Registration | None = None  # null after a delete
    # False when the action was performed but its result event could not be written.
    audit_complete: bool = True
