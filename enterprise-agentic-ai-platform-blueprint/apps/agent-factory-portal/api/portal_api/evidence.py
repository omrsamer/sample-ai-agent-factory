# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Assembling the evidence document of one agent. Pure: no AWS calls, no clock.

``build`` takes an inventory entry that is already built and assessed, plus
the events and reads the service fetched for it, and returns the document.

What the document never holds: a value of a Runtime environment variable, a
role's external id, a token, the text of a Cedar policy, or an account id
outside an ARN. Nothing here reads any of them: the entry carries only facts
derived from them (for example whether a guardrail is named).
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable
from dataclasses import dataclass

from portal_api import registrations, reviews
from portal_api.authorities import CONTAIN_ROLES, RELEASE_ROLES
from portal_api.mappers.agents import AgentEntry, GatewayLink
from portal_api.mappers.common import iso, parse_instant, text
from portal_api.mappers.mcp import GatewayEntry
from portal_api.models.evidence import (
    AgentEvidence,
    EvidenceAgent,
    EvidenceAuthor,
    EvidenceContainment,
    EvidenceGatewayPolicy,
    EvidencePolicy,
    EvidenceRegistration,
    EvidenceRelease,
    EvidenceReview,
    EvidenceReviews,
    EvidenceRisk,
    timing_sentence,
)
from portal_api.models.portal import AuditEvent, ContainmentView
from portal_api.models.wire import CedarPolicySet, EvalRun
from portal_api.reviews import Attestation

# Said only when the inventory could not be brought up to date: the service loads it again when an
# event is newer than it (``PortalService.evidence``), and this is what remains when that failed.
STALE = (
    "An action recorded after the inventory was assessed ({assessed_at}) is listed with the events "
    "but is not yet reflected in the agent, registration, reviews and risk sections."
)

# The incident record of a containment is for the roles that can contain or release, as in the
# containment view (``PortalService.containment_view``).
WITHHELD = (
    "The incident record of the containment (who contained the agent, why, and the events) is "
    f"limited to the {', '.join(sorted(CONTAIN_ROLES | RELEASE_ROLES))} roles."
)

_UNSAFE_IN_FILE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class GatewayPolicies:
    """One Tool Gateway the agent is linked to, and what could be read about it."""

    link: GatewayLink
    gateway: GatewayEntry | None = None  # None when the gateway is not in the inventory
    policies: CedarPolicySet | None = None  # None when its policies could not be read


def file_name(agent_name: str, agent_id: str, date: dt.date) -> str:
    """``agent-evidence-<agent name>-<UTC date>.json``, safe to put in a response header."""
    for candidate in (agent_name, agent_id):
        safe = _UNSAFE_IN_FILE_NAME.sub("-", candidate).strip("-.")[:64].strip("-.")
        if safe:
            return f"agent-evidence-{safe}-{date.isoformat()}.json"
    return f"agent-evidence-agent-{date.isoformat()}.json"


def changes_inventory(event: AuditEvent) -> bool:
    """Whether an event records something that the agent, registration, reviews or risk sections show.

    Those sections come from the inventory. Only a decision that was carried
    out can make an inventory out of date: a result that is ``allowed`` or
    ``unchanged``. A refusal and a failure changed nothing, an intent is not
    yet a result, and a background sweep stops sessions, which no section
    shows.
    """
    return event.phase == "result" and event.outcome in ("allowed", "unchanged") and event.action != "sweep"


def _oldest_first(events: Iterable[AuditEvent]) -> list[AuditEvent]:
    return sorted(events, key=lambda e: (e.at, e.event_id))


def _agent(entry: AgentEntry) -> EvidenceAgent:
    agent = entry.agent
    masked = f"account-{agent.account_id[-4:]}" if agent.account_id else None
    return EvidenceAgent(
        id=agent.id,
        name=agent.name,
        tenant_id=agent.tenant_id,
        environment=agent.environment,
        account_alias=agent.account_alias or masked,
        region=agent.region,
        runtime_arn=entry.runtime_arn,
        lifecycle_state=agent.lifecycle_state,
        inventory_state=agent.inventory_state,
        detection_sources=list(agent.detection_sources),
        reader_status=agent.reader_status,
        inbound_authorizer=agent.inbound_authorizer,
    )


def _registration(entry: AgentEntry) -> EvidenceRegistration | None:
    record = entry.record
    document = registrations.agent_document(record) if record is not None else None
    if record is None or document is None:
        return None
    return EvidenceRegistration(
        record_id=str(record["recordId"]),
        record_name=text(record.get("name")),
        status=str(record.get("status") or "UNKNOWN"),
        status_reason=text(record.get("statusReason")),
        record_version=text(record.get("recordVersion")) or text(document.get("recordVersion")),
        document=document,
        document_sha256=registrations.sha256(registrations.canonical(document)),
        created_at=iso(record.get("createdAt")),
        updated_at=iso(record.get("updatedAt")),
    )


def _reviews(entry: AgentEntry, attestations: Iterable[Attestation], registered: bool) -> EvidenceReviews:
    if not registered:
        return EvidenceReviews()
    newest_first = sorted(attestations, key=lambda a: a.at, reverse=True)
    governance = entry.agent.governance
    registration_review_by = governance.review_by if governance else None
    effective = reviews.effective(registration_review_by, newest_first[0] if newest_first else None)
    return EvidenceReviews(
        effective_review_by=effective.review_by,
        source=effective.source,
        registration_review_by=registration_review_by,
        overdue=entry.agent.flags.review_overdue,
        attestations=[
            EvidenceReview(
                kind=a.kind,
                at=a.at,
                reviewed_by=a.reviewed_by,
                reviewed_by_label=a.reviewed_by_label,
                reviewed_by_role=a.reviewed_by_role,
                next_review_by=a.next_review_by,
                reason=a.reason,
                request_id=a.request_id,
            )
            for a in reversed(newest_first)
        ],
    )


def _containment(view: ContainmentView | None, details: bool) -> EvidenceContainment:
    if view is None:
        return EvidenceContainment(details_shown=details)
    section = EvidenceContainment(
        state=view.state,
        detail=view.detail,
        details_shown=details,
        contained_at=view.contained_at,
        partial=view.partial,
        sweeps_scheduled=view.sweeps.scheduled,
        sweeps_done=view.sweeps.done,
        quiet_at=view.quiet_at,
        enforcement_delay_seconds=view.enforcement_delay_seconds,
        release_delay_seconds=view.release_delay_seconds,
        timing=timing_sentence(view.enforcement_delay_seconds, view.release_delay_seconds),
    )
    if details:
        # The service already leaves these out of the view for other roles; this keeps the rule
        # true of the document whatever view it is given.
        section.contained_by, section.contained_by_label = view.contained_by, view.contained_by_label
        section.reason = view.reason
        section.events = _oldest_first(view.events)
        section.events_truncated = view.events_truncated
    return section


def gateway_policy(item: GatewayPolicies) -> EvidenceGatewayPolicy:
    """One gateway's policy facts: the mode, the number of policies and their hashes, never the text."""
    result = EvidenceGatewayPolicy(gateway_id=item.link.gateway_id, link_source=item.link.source)
    if item.gateway is None:
        return result
    result.gateway_name = item.gateway.server.name
    # A gateway that no reader read has no known mode: null, never "none".
    result.policy_mode = item.gateway.enforcement_mode if item.gateway.read else None
    if item.policies is None:
        return result
    rows = sorted(item.policies.policies, key=lambda p: p.policy_id)
    result.policy_count = len(rows)
    result.policies = [
        EvidencePolicy(
            policy_id=p.policy_id,
            name=p.name,
            status=p.status,
            effect=p.effect,
            sha256=registrations.sha256(p.cedar_text),
        )
        for p in rows
    ]
    if rows:
        result.cedar_sha256 = registrations.sha256("".join(f"{p.cedar_text}\n" for p in rows))
    return result


def _release(run: EvalRun | None) -> EvidenceRelease | None:
    if run is None:
        return None
    pipeline = run.pipeline
    return EvidenceRelease(
        pipeline_name=pipeline.pipeline_name if pipeline else None,
        execution_id=run.run_id,
        status=pipeline.status if pipeline else run.status,
        evaluation_gate_result=run.status,
        evaluation_gate_status=pipeline.evaluation_gate_status if pipeline else None,
        evaluation_gate_summary=pipeline.evaluation_gate_summary if pipeline else None,
        source_revision=run.git_sha,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


def build(
    *,
    entry: AgentEntry,
    generated_at: str,
    generated_by_label: str,
    generated_by_role: str,
    portal_environment: str,
    assessed_at: str,
    decisions: Iterable[AuditEvent] = (),
    decisions_truncated: bool = False,
    attestations: Iterable[Attestation] = (),
    containment: ContainmentView | None = None,
    containment_details: bool = True,
    gateways: Iterable[GatewayPolicies] = (),
    release: EvalRun | None = None,
    limitations: Iterable[str] = (),
) -> AgentEvidence:
    """The evidence document of ``entry``. Every section is present; ``limitations`` says what is missing."""
    registration = _registration(entry)
    ordered = _oldest_first(decisions)
    held = _containment(containment, containment_details)
    notes = list(dict.fromkeys(limitations))
    if not containment_details:
        notes.append(WITHHELD)
    assessed = parse_instant(assessed_at)
    if assessed is not None:
        # The events are read when the document is made; the rest comes from the inventory.
        later = [
            e
            for e in (*ordered, *held.events)
            if changes_inventory(e) and (at := parse_instant(e.at)) is not None and at > assessed
        ]
        if later:
            notes.append(STALE.format(assessed_at=assessed_at))
    agent = entry.agent
    return AgentEvidence(
        generated_at=generated_at,
        generated_by=EvidenceAuthor(label=generated_by_label, role=generated_by_role),
        portal_environment=portal_environment,
        agent=_agent(entry),
        registration=registration,
        decisions=ordered,
        decisions_truncated=decisions_truncated,
        reviews=_reviews(entry, attestations, registration is not None),
        containment=held,
        risk=EvidenceRisk(
            level=agent.risk.level,
            reasons=list(agent.risk.reasons),
            flags=agent.flags.model_copy(),
            obligations_closed=agent.obligations_closed,
            assessed_at=assessed_at,
        ),
        policy=[gateway_policy(item) for item in gateways],
        release=_release(release),
        limitations=notes,
    )
