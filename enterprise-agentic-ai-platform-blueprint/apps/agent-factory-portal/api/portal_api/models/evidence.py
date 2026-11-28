# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The evidence document of one agent: what an auditor is given about it, in one file.

Every section is always present. A section the portal could not fill is empty
or null, and ``limitations`` says what could not be read and why.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from portal_api.containment_timing import CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS, delay_words
from portal_api.models.portal import AuditEvent
from portal_api.models.wire import AgentFlags, RiskReason

SCHEMA_VERSION = "agenticai.agent-evidence/1.0"


def timing_sentence(contain_seconds: int, release_seconds: int) -> str:
    """The two enforcement delays in words, for a reader who does not know the field names."""
    return (
        f"A contain is enforced everywhere within {delay_words(contain_seconds)}. "
        f"After a release some calls can still be refused for {delay_words(release_seconds)} "
        "while the change spreads."
    )


class EvidenceAuthor(BaseModel):
    label: str  # the caller's name, else email, else subject id
    role: str  # the caller's portal role


class EvidenceAgent(BaseModel):
    id: str
    name: str
    tenant_id: str | None = None
    environment: str | None = None
    # The configured alias of the agent's account, else a masked label; never the full account id.
    account_alias: str | None = None
    region: str | None = None
    runtime_arn: str | None = None
    lifecycle_state: str
    inventory_state: str
    detection_sources: list[str] = Field(default_factory=list)
    reader_status: str
    inbound_authorizer: str | None = None  # AWS_IAM | CUSTOM_JWT; null when not known


class EvidenceRegistration(BaseModel):
    record_id: str
    record_name: str | None = None
    status: str
    status_reason: str | None = None
    record_version: str | None = None
    document: dict[str, Any]  # the governance document exactly as stored in the registry
    document_sha256: str  # the same value as document_sha256 on the audit events
    created_at: str | None = None
    updated_at: str | None = None


class EvidenceReview(BaseModel):
    kind: str = "review"  # review: a review attestation; approval: the approval of a document with a review date
    at: str
    reviewed_by: str  # subject id
    reviewed_by_label: str
    reviewed_by_role: str | None = None
    next_review_by: str
    reason: str | None = None
    request_id: str | None = None  # the same id as the review's events in decisions


class EvidenceReviews(BaseModel):
    effective_review_by: str | None = None
    # Where the date comes from: the latest attestation (a review, or an approval), else the
    # registration's own document. attestation | approval | registration | none
    source: str = "none"
    registration_review_by: str | None = None  # review_by of the registration's own document
    overdue: bool | None = None  # null for an agent with no registration
    # Oldest first: the attestations that the registration's own events name (those among
    # ``decisions``), and the latest one the inventory holds, each once.
    attestations: list[EvidenceReview] = Field(default_factory=list)


class EvidenceContainment(BaseModel):
    state: str = "unknown"  # contained | not_contained | unknown
    # Why the state is unknown. Also set when the state is not_contained although a statement with
    # the portal's identifier is in the policy: it is not the statement the portal writes, and it
    # may or may not deny invocation.
    detail: str | None = None
    # The incident record (who contained the agent, why, and the events) is shown only to a caller
    # whose role can contain or release, as in the containment view. For anyone else this is
    # false, those fields are null or empty, and limitations says so.
    details_shown: bool = True
    contained_by: str | None = None
    contained_by_label: str | None = None
    contained_at: str | None = None
    reason: str | None = None
    partial: bool = False  # the containment that holds did not stop every session it found
    # Background sweeps after the contain, and since when the agent is known to be quiet: the end
    # of the first sweep that started after every host applies the deny, listed every session and
    # left none running.
    sweeps_scheduled: int = 0
    sweeps_done: int = 0
    quiet_at: str | None = None
    # The state is what the Runtime's resource policy says. The service applies a change to that
    # policy host by host, so calls follow a contain, and a release, only after these delays.
    enforcement_delay_seconds: int = CONTAIN_DELAY_SECONDS  # how long a contain can take to apply everywhere
    release_delay_seconds: int = RELEASE_DELAY_SECONDS  # how long a release can take to apply everywhere
    timing: str = Field(default_factory=lambda: timing_sentence(CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS))
    # The newest events of the Runtime's containment history, at most 200, oldest first.
    events: list[AuditEvent] = Field(default_factory=list)
    events_truncated: bool = False  # the history holds older events that are not listed


class EvidenceRisk(BaseModel):
    level: str
    reasons: list[RiskReason] = Field(default_factory=list)
    flags: AgentFlags
    # True for a retired registration with no Runtime known: no risk rule applies, and the flags
    # unmanaged, ownerless, review_overdue and inactive are null because they do not apply.
    obligations_closed: bool = False
    assessed_at: str  # the moment the agent, registration, reviews and risk sections describe


class EvidencePolicy(BaseModel):
    policy_id: str
    name: str | None = None
    status: str | None = None
    effect: str  # allow | deny
    sha256: str  # of this policy's Cedar statement exactly as deployed


class EvidenceGatewayPolicy(BaseModel):
    gateway_id: str
    gateway_name: str | None = None
    link_source: str  # how the agent is linked to the gateway: registry | runtime_env | tags
    policy_mode: str | None = None  # enforce | log_only | none; null when the gateway could not be read
    policy_count: int | None = None  # null when the policies could not be read
    # SHA-256 of the Cedar statements as deployed, in ascending policy id order, each followed by a
    # newline. Null when there is no policy or the policies could not be read. Never the text.
    cedar_sha256: str | None = None
    policies: list[EvidencePolicy] = Field(default_factory=list)  # ascending policy id


class EvidenceRelease(BaseModel):
    pipeline_name: str | None = None
    execution_id: str
    status: str  # the pipeline execution's status
    evaluation_gate_result: str  # passed | failed | running | error (the gate did not run)
    evaluation_gate_status: str | None = None  # the gate action's own status; null when it did not run
    evaluation_gate_summary: str | None = None
    source_revision: str | None = None
    started_at: str
    finished_at: str | None = None


class AgentEvidence(BaseModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: str
    generated_by: EvidenceAuthor
    portal_environment: str
    agent: EvidenceAgent
    registration: EvidenceRegistration | None = None  # null for an agent with no registration
    # The newest events of the registration's history, at most 200, oldest first.
    decisions: list[AuditEvent] = Field(default_factory=list)
    decisions_truncated: bool = False  # the history holds older events that are not listed
    reviews: EvidenceReviews = Field(default_factory=EvidenceReviews)
    containment: EvidenceContainment = Field(default_factory=EvidenceContainment)
    risk: EvidenceRisk
    policy: list[EvidenceGatewayPolicy] = Field(default_factory=list)
    release: EvidenceRelease | None = None  # null when the agent's cell names no pipeline
    limitations: list[str] = Field(default_factory=list)
