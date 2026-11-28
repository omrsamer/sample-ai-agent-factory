# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The evidence document of one agent: the pure assembly, and the download through the handler."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from typing import Any

import pytest
from botocore.exceptions import ClientError
from mangum import Mangum

from portal_api import deps, registrations
from portal_api import evidence as evidence_builder
from portal_api.actions import audit_writer
from portal_api.app import create_app
from portal_api.aws import agentcore, registry
from portal_api.aws import audit as audit_reader
from portal_api.config import load_settings
from portal_api.containment_timing import CONTAIN_DELAY_SECONDS, RELEASE_DELAY_SECONDS, delay_words
from portal_api.mappers import agents as agent_mapper
from portal_api.mappers import mcp as mcp_mapper
from portal_api.mappers.agents import AgentEntry, GatewayLink
from portal_api.models.evidence import SCHEMA_VERSION, AgentEvidence
from portal_api.models.portal import AuditEvent, ContainmentView
from portal_api.models.wire import (
    AgentRisk,
    CedarPolicyRow,
    CedarPolicySet,
    EvalRun,
    PipelineEvidence,
    RiskReason,
)
from portal_api.reviews import Attestation
from tests import test_api
from tests.conftest import (
    BASE_ENV,
    CELL_ACCOUNT,
    GATEWAY_ARN,
    GATEWAY_URL,
    OTHER_ACCOUNT,
    PLATFORM_ACCOUNT,
    RUNTIME_ARN,
    FakeClient,
    FakeClients,
    agent_document,
    agent_record,
    gateway_bundle,
    make_service,
    runtime_bundle,
    tool_record,
)
from tests.fakes import FakeDynamo
from tests.test_api import PLATFORM_CLAIMS, VIEWER_CLAIMS, event, raw

# The read API's fake backend and its caller, shared with the endpoint tests.
backend = test_api.backend
call = test_api.call

TABLE = BASE_ENV["PORTAL_AUDIT_TABLE"]
GATEWAY_ID = GATEWAY_ARN.rsplit("/", 1)[-1]
ASSESSED = "2026-06-01T12:00:00Z"
SECTIONS = {
    "schema_version",
    "generated_at",
    "generated_by",
    "portal_environment",
    "agent",
    "registration",
    "decisions",
    "decisions_truncated",
    "reviews",
    "containment",
    "risk",
    "policy",
    "release",
    "limitations",
}


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- inputs for the pure assembly ------------------------------------------------------------


def registered_entry(**overrides: Any) -> AgentEntry:
    """An inventory entry built by the mappers alone, the way the service leaves it after assessment."""
    cell = load_settings(BASE_ENV).cells[0]
    runtime = agent_mapper.runtime_from_bundle(runtime_bundle(), cell)
    entry = agent_mapper.registered_agent(agent_record(**overrides), runtime, cell)
    entry.agent.reader_status = "ok"
    entry.agent.flags.unmanaged = False
    entry.agent.flags.review_overdue = False
    entry.agent.risk = AgentRisk(
        level="medium",
        reasons=[
            RiskReason(code="DATA_CONFIDENTIAL", severity="medium", detail="The agent handles confidential data.")
        ],
    )
    return entry


def detected_entry() -> AgentEntry:
    cell = load_settings(BASE_ENV).cells[0]
    entry = agent_mapper.discovered_agent(agent_mapper.runtime_from_bundle(runtime_bundle(tags={}), cell))
    entry.agent.flags.unmanaged = True
    entry.agent.risk = AgentRisk(
        level="high",
        reasons=[RiskReason(code="UNREGISTERED", severity="high", detail="The agent has no registration.")],
    )
    return entry


def audit_event(action: str, at: str, phase: str = "result", outcome: str = "allowed", **extra: Any) -> AuditEvent:
    values = {
        "event_id": f"{action}-{phase}-{at}",
        "request_id": f"req-{action}-{at[:19]}",
        "at": at,
        "phase": phase,
        "action": action,
        "outcome": outcome,
        "reason": f"{action} reason",
        "actor_subject": "ann-1",
        "actor_label": "Ann Approver",
        "actor_role": "approver",
        "tenant_id": "ws1",
        "record_id": "recAgent0001",
        "record_name": "agent-ws1-travel-agent-nonprod",
    }
    return AuditEvent(**{**values, **extra})


def attestation(at: str, next_review_by: str, who: str = "Ann Approver", kind: str = "review") -> Attestation:
    return Attestation(
        record_id="recAgent0001",
        at=at,
        next_review_by=next_review_by,
        reviewed_by="ann-1",
        reviewed_by_label=who,
        reviewed_by_role="approver",
        reason="Reviewed with the owner.",
        request_id="req-review",
        kind=kind,
    )


PERMIT = "permit(principal, action, resource);"
FORBID = '@id("no-delete")\nforbid(principal, action == Action::"delete", resource);'


def gateway_policies(
    statements: dict[str, str] | None = None, mode: str = "ENFORCE"
) -> evidence_builder.GatewayPolicies:
    cell = load_settings(BASE_ENV).cells[0]
    gateway = mcp_mapper.gateway_entry(gateway_bundle(mode), cell, {})
    rows = [
        CedarPolicyRow(
            policy_id=policy_id,
            effect="deny" if text.lstrip().startswith(("forbid", "@")) else "allow",
            cedar_text=text,
            name=f"policy_{policy_id}",
            status="ACTIVE",
        )
        for policy_id, text in (statements if statements is not None else {"p2": FORBID, "p1": PERMIT}).items()
    ]
    return evidence_builder.GatewayPolicies(
        link=GatewayLink(GATEWAY_ID, GATEWAY_ARN, "registry", ("tool-echo",)),
        gateway=gateway,
        policies=CedarPolicySet(enforcement_mode=gateway.enforcement_mode, policies=rows),
    )


def release_run() -> EvalRun:
    return EvalRun(
        run_id="exec-1",
        agent_id="recAgent0001",
        stage="nonprod",
        git_sha="rev-1",
        started_at="2026-05-30T08:00:00Z",
        finished_at="2026-05-30T08:20:00Z",
        status="passed",
        pipeline=PipelineEvidence(
            pipeline_name="agenticai-workload-ws1-travel-agent",
            execution_id="exec-1",
            status="Succeeded",
            source_revision="rev-1",
            evaluation_gate_status="Succeeded",
            evaluation_gate_summary="All checks passed.",
        ),
    )


def build(entry: AgentEntry | None = None, **parts: Any) -> AgentEvidence:
    defaults: dict[str, Any] = {
        "entry": entry or registered_entry(),
        "generated_at": "2026-06-01T12:00:05Z",
        "generated_by_label": "Vera Viewer",
        "generated_by_role": "readonly",
        "portal_environment": "nonprod",
        "assessed_at": ASSESSED,
    }
    return evidence_builder.build(**{**defaults, **parts})


# --- the pure assembly -------------------------------------------------------------------------


def test_a_full_document_for_a_registered_agent():
    decisions = [
        audit_event("approve", "2026-02-01T10:00:00.000002Z", document_sha256="a" * 64, status_after="APPROVED"),
        audit_event("create", "2026-01-10T09:00:00.000001Z", status_after="DRAFT"),
        audit_event("approve", "2026-02-01T10:00:00.000001Z", phase="intent"),
        audit_event("submit", "2026-01-11T09:00:00.000001Z", actor_subject="dev-1", actor_label="dev@example.com"),
    ]
    contained = ContainmentView(
        agent_id="recAgent0001",
        state="contained",
        runtime_arn=RUNTIME_ARN,
        contained_by="sec-1",
        contained_by_label="Sam Security",
        contained_at="2026-05-01T08:00:00.000001Z",
        reason="Suspicious calls.",
        contained_by_me=True,
        events=[
            audit_event("contain", "2026-05-01T08:00:01.000001Z", agent_id="recAgent0001", sessions_found=3),
            audit_event("contain", "2026-05-01T08:00:00.000001Z", phase="intent", agent_id="recAgent0001"),
        ],
    )
    document = build(
        decisions=decisions,
        attestations=[
            attestation("2026-05-20T10:00:00.000001Z", "2027-05-20"),
            attestation("2026-01-20T10:00:00.000001Z", "2026-07-20", who="Earlier Reviewer", kind="approval"),
        ],
        containment=contained,
        gateways=[gateway_policies()],
        release=release_run(),
        limitations=["One thing could not be read.", "One thing could not be read."],
    )
    body = json.loads(document.model_dump_json())
    assert set(body) == SECTIONS
    assert body["schema_version"] == SCHEMA_VERSION == "agenticai.agent-evidence/1.0"
    assert body["generated_at"] == "2026-06-01T12:00:05Z" and body["portal_environment"] == "nonprod"
    assert body["generated_by"] == {"label": "Vera Viewer", "role": "readonly"}

    assert body["agent"] == {
        "id": "recAgent0001",
        "name": "travel-agent",
        "tenant_id": "ws1",
        "environment": "nonprod",
        "account_alias": "account-4444",  # no alias is configured, so the account is masked
        "region": "eu-west-1",
        "runtime_arn": RUNTIME_ARN,
        "lifecycle_state": "approved",
        "inventory_state": "registered_and_detected",
        "detection_sources": ["cell_reader"],
        "reader_status": "ok",
        "inbound_authorizer": None,
    }

    # The governance document exactly as stored, with the hash the approval events carry.
    stored = agent_document()
    assert body["registration"] == {
        "record_id": "recAgent0001",
        "record_name": "agent-ws1-travel-agent-nonprod",
        "status": "APPROVED",
        "status_reason": None,
        "record_version": "1.0.0",
        "document": stored,
        "document_sha256": registrations.sha256(registrations.canonical(stored)),
        "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T14:00:00Z",
    }

    # Decisions and containment events oldest first: who, role, action, outcome, reason, when.
    assert [(e["action"], e["phase"]) for e in body["decisions"]] == [
        ("create", "result"),
        ("submit", "result"),
        ("approve", "intent"),
        ("approve", "result"),
    ]
    first = body["decisions"][0]
    assert {"actor_label", "actor_subject", "actor_role", "action", "outcome", "reason", "at"} <= set(first)
    assert body["decisions"][1]["actor_label"] == "dev@example.com"
    assert body["decisions"][3]["document_sha256"] == "a" * 64

    assert body["reviews"] == {
        "effective_review_by": "2027-05-20",
        "source": "attestation",
        "registration_review_by": "2099-12-31",
        "overdue": False,
        "attestations": [
            {
                "kind": "approval",
                "at": "2026-01-20T10:00:00.000001Z",
                "reviewed_by": "ann-1",
                "reviewed_by_label": "Earlier Reviewer",
                "reviewed_by_role": "approver",
                "next_review_by": "2026-07-20",
                "reason": "Reviewed with the owner.",
                "request_id": "req-review",
            },
            {
                "kind": "review",
                "at": "2026-05-20T10:00:00.000001Z",
                "reviewed_by": "ann-1",
                "reviewed_by_label": "Ann Approver",
                "reviewed_by_role": "approver",
                "next_review_by": "2027-05-20",
                "reason": "Reviewed with the owner.",
                "request_id": "req-review",
            },
        ],
    }

    held = body["containment"]
    assert (held["state"], held["contained_by_label"], held["contained_at"], held["reason"], held["partial"]) == (
        "contained",
        "Sam Security",
        "2026-05-01T08:00:00.000001Z",
        "Suspicious calls.",
        False,
    )
    assert [(e["phase"], e["sessions_found"]) for e in held["events"]] == [("intent", None), ("result", 3)]
    assert "contained_by_me" not in held  # that is about the caller, not about the agent
    # A change to the policy is not enforced at once: the section states both delays.
    assert (held["enforcement_delay_seconds"], held["release_delay_seconds"]) == (
        CONTAIN_DELAY_SECONDS,
        RELEASE_DELAY_SECONDS,
    )
    assert held["timing"] == (
        f"A contain is enforced everywhere within {delay_words(CONTAIN_DELAY_SECONDS)}. "
        f"After a release some calls can still be refused for {delay_words(RELEASE_DELAY_SECONDS)} "
        "while the change spreads."
    )

    assert body["risk"] == {
        "level": "medium",
        "reasons": [
            {"code": "DATA_CONFIDENTIAL", "severity": "medium", "detail": "The agent handles confidential data."}
        ],
        "flags": {
            "unmanaged": False,
            "ownerless": None,
            "review_overdue": False,
            "inactive": None,
            "contained": None,
        },
        "obligations_closed": False,
        "assessed_at": ASSESSED,
    }

    assert body["release"] == {
        "pipeline_name": "agenticai-workload-ws1-travel-agent",
        "execution_id": "exec-1",
        "status": "Succeeded",
        "evaluation_gate_result": "passed",
        "evaluation_gate_status": "Succeeded",
        "evaluation_gate_summary": "All checks passed.",
        "source_revision": "rev-1",
        "started_at": "2026-05-30T08:00:00Z",
        "finished_at": "2026-05-30T08:20:00Z",
    }
    assert body["limitations"] == ["One thing could not be read."]  # said once


def test_the_policy_section_holds_hashes_and_never_the_cedar_text():
    document = build(gateways=[gateway_policies()])
    (policy,) = json.loads(document.model_dump_json())["policy"]
    assert policy == {
        "gateway_id": GATEWAY_ID,
        "gateway_name": "ws1-tools",
        "link_source": "registry",
        "policy_mode": "enforce",
        "policy_count": 2,
        # Reproducible: the statements as deployed, in policy id order, each followed by a newline.
        "cedar_sha256": sha(f"{PERMIT}\n{FORBID}\n"),
        "policies": [
            {"policy_id": "p1", "name": "policy_p1", "status": "ACTIVE", "effect": "allow", "sha256": sha(PERMIT)},
            {"policy_id": "p2", "name": "policy_p2", "status": "ACTIVE", "effect": "deny", "sha256": sha(FORBID)},
        ],
    }
    text = document.model_dump_json()
    assert "permit(" not in text and "forbid(" not in text and "no-delete" not in text
    # The Tool Gateway's address is the value of a Runtime environment variable: it is not in the document.
    assert GATEWAY_URL not in text and "amazonaws.com" not in text


def test_a_changed_policy_changes_the_hash():
    before = evidence_builder.gateway_policy(gateway_policies({"p1": PERMIT}))
    after = evidence_builder.gateway_policy(gateway_policies({"p1": PERMIT + " "}))
    reordered = evidence_builder.gateway_policy(gateway_policies({"p2": FORBID, "p1": PERMIT}))
    same = evidence_builder.gateway_policy(gateway_policies({"p1": PERMIT, "p2": FORBID}))
    assert before.cedar_sha256 != after.cedar_sha256
    assert reordered.cedar_sha256 == same.cedar_sha256  # the order the service lists them in does not matter


def test_policy_facts_that_could_not_be_read_are_null_not_zero():
    link = GatewayLink("gw-unknown-0000000000", None, "registry")
    unknown = evidence_builder.gateway_policy(evidence_builder.GatewayPolicies(link=link))
    assert unknown.model_dump() == {
        "gateway_id": "gw-unknown-0000000000",
        "gateway_name": None,
        "link_source": "registry",
        "policy_mode": None,
        "policy_count": None,
        "cedar_sha256": None,
        "policies": [],
    }
    readable = gateway_policies()
    unread = evidence_builder.gateway_policy(
        evidence_builder.GatewayPolicies(link=readable.link, gateway=readable.gateway, policies=None)
    )
    assert (unread.gateway_name, unread.policy_mode, unread.policy_count, unread.cedar_sha256) == (
        "ws1-tools",
        "enforce",
        None,
        None,
    )
    # An engine that holds no policy: a count of zero, and nothing to hash.
    empty = evidence_builder.gateway_policy(gateway_policies({}))
    assert (empty.policy_count, empty.cedar_sha256, empty.policies) == (0, None, [])
    # A gateway with no policy engine.
    none = evidence_builder.gateway_policy(gateway_policies({}, mode=""))
    assert none.policy_mode == "none"


def test_every_section_is_present_for_an_agent_with_no_registration():
    body = json.loads(build(detected_entry()).model_dump_json())
    assert set(body) == SECTIONS
    assert body["registration"] is None and body["release"] is None
    assert body["decisions"] == [] and body["policy"] == [] and body["limitations"] == []
    assert body["reviews"] == {
        "effective_review_by": None,
        "source": "none",
        "registration_review_by": None,
        "overdue": None,
        "attestations": [],
    }
    assert body["containment"] == {
        "state": "unknown",
        "detail": None,
        "details_shown": True,
        "contained_by": None,
        "contained_by_label": None,
        "contained_at": None,
        "reason": None,
        "partial": False,
        "sweeps_scheduled": 0,
        "sweeps_done": 0,
        "quiet_at": None,
        "enforcement_delay_seconds": CONTAIN_DELAY_SECONDS,
        "release_delay_seconds": RELEASE_DELAY_SECONDS,
        "timing": body["containment"]["timing"],
        "events": [],
        "events_truncated": False,
    }
    assert body["decisions_truncated"] is False
    assert delay_words(CONTAIN_DELAY_SECONDS) in body["containment"]["timing"]
    assert delay_words(RELEASE_DELAY_SECONDS) in body["containment"]["timing"]
    assert (body["agent"]["inventory_state"], body["agent"]["lifecycle_state"]) == ("detected_only", "discovered")
    assert body["risk"]["level"] == "high" and body["risk"]["reasons"][0]["code"] == "UNREGISTERED"


def test_who_contained_an_agent_and_why_is_withheld_from_a_role_that_cannot_contain_or_release():
    view = ContainmentView(
        agent_id="recAgent0001",
        state="contained",
        runtime_arn=RUNTIME_ARN,
        contained_by="sec-1",
        contained_by_label="Sam Security",
        contained_at="2026-05-01T08:00:00.000001Z",
        reason="Suspicious calls from a partner network.",
        partial=True,
        events=[audit_event("contain", "2026-05-01T08:00:01.000001Z", agent_id="recAgent0001", sessions_found=3)],
    )
    shown = build(containment=view).containment
    assert shown.details_shown is True and shown.contained_by_label == "Sam Security" and len(shown.events) == 1

    document = build(containment=view, containment_details=False)
    held = document.containment
    # The state, when it began, whether sessions were left and the delays stay; the person, the
    # reason and the events do not.
    assert (held.state, held.contained_at, held.partial, held.details_shown) == (
        "contained",
        "2026-05-01T08:00:00.000001Z",
        True,
        False,
    )
    assert (held.contained_by, held.contained_by_label, held.reason, held.events) == (None, None, None, [])
    assert held.enforcement_delay_seconds == CONTAIN_DELAY_SECONDS and held.timing
    assert document.limitations == [evidence_builder.WITHHELD]
    assert evidence_builder.WITHHELD == (
        "The incident record of the containment (who contained the agent, why, and the events) is "
        "limited to the platform, security, sre roles."
    )
    text = document.model_dump_json()
    assert "Sam Security" not in text and "sec-1" not in text and "partner network" not in text
    # A withheld event cannot make the document claim that something is not yet reflected.
    late = ContainmentView(
        agent_id="a", state="contained", events=[audit_event("contain", "2030-01-01T00:00:00.000000Z")]
    )
    assert build(containment=late, containment_details=False).limitations == [evidence_builder.WITHHELD]


def test_the_containment_section_states_the_delays_the_view_reports():
    """The figures are the ones the containment view carries, not a copy kept here."""
    view = ContainmentView(agent_id="a", state="contained", enforcement_delay_seconds=45, release_delay_seconds=600)
    held = build(containment=view).containment
    assert (held.enforcement_delay_seconds, held.release_delay_seconds) == (45, 600)
    assert held.timing == (
        "A contain is enforced everywhere within about 45 seconds. "
        "After a release some calls can still be refused for about 10 minutes while the change spreads."
    )


def test_an_attestation_is_not_attributed_to_an_agent_with_no_registration():
    body = build(detected_entry(), attestations=[attestation("2026-05-20T10:00:00.000001Z", "2027-05-20")])
    assert body.reviews.attestations == [] and body.reviews.effective_review_by is None


def test_without_an_attestation_the_registrations_own_date_is_the_effective_one():
    reviews = build().reviews
    assert (reviews.effective_review_by, reviews.source, reviews.registration_review_by) == (
        "2099-12-31",
        "registration",
        "2099-12-31",
    )
    none = build(registered_entry(reviewBy=None)).reviews
    assert (none.effective_review_by, none.source, none.registration_review_by) == (None, "none", None)


def test_the_source_says_whether_the_date_comes_from_a_review_an_approval_or_the_registration():
    approved = build(attestations=[attestation("2026-05-20T10:00:00.000001Z", "2027-05-20", kind="approval")]).reviews
    assert (approved.effective_review_by, approved.source) == ("2027-05-20", "approval")
    assert [a.kind for a in approved.attestations] == ["approval"]
    # A later review after an approval: the review decides, and both are listed oldest first.
    both = build(
        attestations=[
            attestation("2026-06-01T10:00:00.000001Z", "2027-06-01"),
            attestation("2026-05-20T10:00:00.000001Z", "2027-05-20", kind="approval"),
        ]
    ).reviews
    assert (both.effective_review_by, both.source) == ("2027-06-01", "attestation")
    assert [a.kind for a in both.attestations] == ["approval", "review"]


def test_a_configured_account_alias_is_used_instead_of_the_masked_account():
    entry = registered_entry()
    entry.agent.account_alias = "workload-nonprod"
    assert build(entry).agent.account_alias == "workload-nonprod"
    entry.agent.account_alias, entry.agent.account_id = None, None
    assert build(entry).agent.account_alias is None


@pytest.mark.parametrize(
    ("event_at", "stale"),
    [
        ("2026-06-01T11:59:59.999999Z", False),
        ("2026-06-01T12:00:00.000000Z", False),  # the same instant as the assessment
        ("2026-06-01T12:00:00.000001Z", True),
        ("2026-06-02T00:00:00.000000Z", True),
    ],
)
def test_an_event_newer_than_the_assessment_is_pointed_out(event_at, stale):
    for parts in (
        {"decisions": [audit_event("review", event_at)]},
        {"containment": ContainmentView(agent_id="a", state="contained", events=[audit_event("contain", event_at)])},
    ):
        notes = build(**parts).limitations
        assert (notes == [evidence_builder.STALE.format(assessed_at=ASSESSED)]) is stale
        assert stale or notes == []


def test_an_unreadable_assessment_time_adds_no_note():
    assert build(assessed_at="", decisions=[audit_event("review", "2030-01-01T00:00:00.000000Z")]).limitations == []


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("travel-agent", "agent-evidence-travel-agent-2026-06-01.json"),
        ("travel_agent.v2", "agent-evidence-travel_agent.v2-2026-06-01.json"),
        ('evil"\r\nSet-Cookie: x=1', "agent-evidence-evil-Set-Cookie-x-1-2026-06-01.json"),
        ("../../etc/passwd", "agent-evidence-etc-passwd-2026-06-01.json"),
        ("Zoë's agent", "agent-evidence-Zo-s-agent-2026-06-01.json"),
        ("a" * 200, f"agent-evidence-{'a' * 64}-2026-06-01.json"),
        ("///", "agent-evidence-recAgent0001-2026-06-01.json"),  # nothing usable: the id is used
        ("", "agent-evidence-recAgent0001-2026-06-01.json"),
    ],
)
def test_the_file_name_is_safe_in_a_header(name, expected):
    produced = evidence_builder.file_name(name, "recAgent0001", dt.date(2026, 6, 1))
    assert produced == expected
    assert re.fullmatch(r"agent-evidence-[A-Za-z0-9._-]+-\d{4}-\d{2}-\d{2}\.json", produced)
    assert evidence_builder.file_name("", "", dt.date(2026, 6, 1)) == "agent-evidence-agent-2026-06-01.json"


# --- the download through the handler ------------------------------------------------------------


def evidence(backend_: Any, agent_id: str = "recAgent0001", claims: dict | None = PLATFORM_CLAIMS):
    status, body, headers = raw(backend_, f"/agents/{agent_id}/evidence", claims=claims)
    try:
        return status, json.loads(body), headers
    except ValueError:
        return status, body, headers


def test_the_evidence_is_a_json_download(backend):
    status, body, headers = evidence(backend)
    assert status == 200
    today = dt.datetime.now(dt.UTC).date().isoformat()
    assert headers["content-type"] == "application/json"
    assert headers["content-disposition"] == f'attachment; filename="agent-evidence-travel-agent-{today}.json"'
    assert headers["cache-control"] == "no-store"
    assert set(body) == SECTIONS and body["schema_version"] == SCHEMA_VERSION
    assert body["generated_by"] == {"label": "admin@example.com", "role": "platform"}
    assert body["portal_environment"] == "nonprod"
    assert body["agent"]["id"] == "recAgent0001" and body["agent"]["runtime_arn"] == RUNTIME_ARN
    assert body["agent"]["reader_status"] == "ok"
    assert body["registration"]["document"] == agent_document()
    assert body["registration"]["status"] == "APPROVED"
    assert body["decisions"] == [] and body["reviews"]["attestations"] == []
    assert body["reviews"]["effective_review_by"] == "2099-12-31" and body["reviews"]["source"] == "registration"
    assert body["containment"]["state"] == "not_contained" and body["containment"]["events"] == []
    assert (body["containment"]["enforcement_delay_seconds"], body["containment"]["release_delay_seconds"]) == (
        CONTAIN_DELAY_SECONDS,
        RELEASE_DELAY_SECONDS,
    )
    assert delay_words(RELEASE_DELAY_SECONDS) in body["containment"]["timing"]
    assert body["risk"]["level"] in ("low", "medium", "high", "critical") and body["risk"]["assessed_at"]
    assert set(body["risk"]["flags"]) == {"unmanaged", "ownerless", "review_overdue", "inactive", "contained"}
    (policy,) = body["policy"]
    assert (policy["gateway_id"], policy["gateway_name"], policy["policy_mode"], policy["policy_count"]) == (
        GATEWAY_ID,
        "ws1-tools",
        "log_only",
        1,
    )
    assert policy["cedar_sha256"] == sha("permit(principal, action, resource);\n")
    assert body["release"]["execution_id"] == "exec-1" and body["release"]["status"] == "Succeeded"
    assert body["release"]["evaluation_gate_result"] == "passed"
    assert body["release"]["pipeline_name"] == "agenticai-workload-ws1-travel-agent"
    assert body["limitations"] == []


def test_the_evidence_is_open_to_every_mapped_role_and_to_no_one_else(backend):
    status, body, _ = evidence(backend, claims=VIEWER_CLAIMS)
    assert status == 200 and body["generated_by"] == {"label": "viewer@example.com", "role": "readonly"}
    assert evidence(backend, claims=None)[0] == 401
    assert evidence(backend, claims={"sub": "x", "cognito:groups": "[strangers]"})[0] == 403
    assert evidence(backend, "recMissing00")[:2] == (404, {"detail": "Agent not found"})
    assert raw(backend, "/agents/bad%20id/evidence")[0] == 422


@pytest.mark.parametrize(
    ("groups", "role", "shown"),
    [
        ("[viewers]", "readonly", False),
        ("[devs]", "developer", False),
        ("[approvers]", "approver", False),
        ("[sre-team]", "sre", True),
        ("[sec]", "security", True),
        ("[platform-admins]", "platform", True),
    ],
)
def test_containment_details_in_the_evidence_follow_the_callers_role(backend, groups, role, shown):
    _, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    for phase in ("intent", "result"):
        audit_writer.put_event(
            table,
            TABLE,
            audit_reader.containment_key(RUNTIME_ARN),  # the history belongs to the Runtime
            audit_event(
                "contain",
                f"2026-01-14T09:00:0{1 if phase == 'result' else 0}.000001Z",
                phase,
                agent_id="recAgent0001",
                actor_label="Sam Security",
                actor_subject="sec-1",
                reason="Suspicious calls.",
            ),
        )
    status, body, _ = evidence(backend, claims={"sub": "u-1", "cognito:groups": groups})
    assert status == 200 and body["generated_by"]["role"] == role
    held = body["containment"]
    assert held["details_shown"] is shown and held["state"] == "not_contained"
    assert (len(held["events"]) == 2) is shown
    assert ("Sam Security" in json.dumps(body)) is shown
    assert (evidence_builder.WITHHELD in body["limitations"]) is (not shown)
    # The registration's own decisions are not containment details: every role sees them.
    assert body["decisions"] == [] and body["registration"]["status"] == "APPROVED"


def test_the_evidence_file_name_is_readable_by_a_cross_origin_script(backend):
    service, _ = backend
    app = create_app()
    app.dependency_overrides[deps.get_service] = lambda: service
    request = event(
        "/agents/recAgent0001/evidence", "GET", PLATFORM_CLAIMS, headers={"origin": "https://portal.example.com"}
    )
    headers = {k.lower(): v for k, v in Mangum(app, lifespan="off")(request, None)["headers"].items()}
    assert headers["access-control-allow-origin"] == "https://portal.example.com"
    assert "content-disposition" in headers["access-control-expose-headers"].lower()


def test_the_evidence_cannot_be_requested_with_another_method(call):
    assert call("/agents/recAgent0001/evidence", method="POST")[0] == 405


def test_evidence_for_an_agent_with_no_registration(backend):
    status, body, headers = evidence(backend, "orphan_agent-ZyXwVu9876")
    assert status == 200 and "agent-evidence-orphan_agent-" in headers["content-disposition"]
    assert body["registration"] is None and body["decisions"] == [] and body["release"] is None
    assert body["reviews"]["overdue"] is None and body["reviews"]["source"] == "none"
    assert body["agent"]["inventory_state"] == "detected_only"
    # It is linked to the gateway through the address in its configuration; only the gateway's id is shown.
    assert [(p["gateway_id"], p["link_source"]) for p in body["policy"]] == [(GATEWAY_ID, "runtime_env")]
    assert body["limitations"] == ["This agent does not belong to a configured cell, so it has no pipeline."]


def test_decisions_reviews_and_containment_events_come_from_the_audit_trail(backend):
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]

    def put(partition: str, action: str, at: str, phase: str = "result", **extra: Any) -> None:
        audit_writer.put_event(table, TABLE, partition, audit_event(action, at, phase, **extra))

    put("RECORD#NAME#agent-ws1-travel-agent-nonprod", "create", "2026-01-10T09:00:00.000001Z", record_id=None)
    put("RECORD#recAgent0001", "submit", "2026-01-11T09:00:00.000001Z")
    put("RECORD#recAgent0001", "approve", "2026-01-12T09:00:00.000001Z")
    put("RECORD#recAgent0001", "review", "2026-01-13T09:00:00.000002Z", next_review_by="2027-01-13")
    put("RECORD#recOther00001", "approve", "2026-01-12T09:00:00.000001Z", record_id="recOther00001")
    put(audit_reader.containment_key(RUNTIME_ARN), "contain", "2026-01-14T09:00:00.000001Z", agent_id="recAgent0001")
    # An event filed under the agent's id, as before the history followed the Runtime, is not read.
    put("CONTAINMENT#recAgent0001", "contain", "2026-01-10T09:00:00.000001Z", agent_id="recAgent0001")
    audit_writer.put_attestation(
        table,
        TABLE,
        at="2026-01-13T09:00:00.000001Z",
        record_id="recAgent0001",
        next_review_by="2027-01-13",
        reviewed_by="ann-1",
        reviewed_by_label="Ann Approver",
        reviewed_by_role="approver",
        reason="Reviewed.",
        request_id="req-review",
    )
    service.cache.clear()
    status, body, _ = evidence(backend)
    assert status == 200
    assert [e["action"] for e in body["decisions"]] == ["create", "submit", "approve", "review"]
    assert body["decisions"][-1]["next_review_by"] == "2027-01-13"
    assert body["reviews"]["effective_review_by"] == "2027-01-13" and body["reviews"]["source"] == "attestation"
    assert [a["reviewed_by_label"] for a in body["reviews"]["attestations"]] == ["Ann Approver"]
    assert [e["action"] for e in body["containment"]["events"]] == ["contain"]
    # The policy is not contained (the fake Runtime has no policy), so nobody is named as holding it.
    assert body["containment"]["state"] == "not_contained" and body["containment"]["contained_by"] is None
    # The effective date is the one the agent list shows.
    agent = service.agent("recAgent0001").agent
    assert (agent.review_by, agent.last_reviewed_by) == ("2027-01-13", "Ann Approver")


def test_whatever_cannot_be_read_is_left_empty_and_named(backend, monkeypatch):
    service, clients = backend
    service.inventory()  # assessed while everything was readable
    denied = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "Operation")
    clients.clients[("platform", "dynamodb")].fail_query = True
    clients.clients[("platform", "codepipeline")].responses["list_pipeline_executions"] = denied
    control = clients.clients[(CELL_ACCOUNT, "bedrock-agentcore-control")]
    control.responses["get_resource_policy"] = denied
    monkeypatch.setattr(agentcore, "list_policies", lambda client, engine_id: (_ for _ in ()).throw(denied))
    status, body, _ = evidence(backend)
    assert status == 200 and set(body) == SECTIONS
    assert body["decisions"] == [] and body["release"] is None
    assert (body["containment"]["state"], body["containment"]["events"]) == ("unknown", [])
    (policy,) = body["policy"]
    assert (policy["policy_mode"], policy["policy_count"], policy["cedar_sha256"]) == ("log_only", None, None)
    assert body["limitations"] == [
        "The registration's audit events could not be read (InternalServerError).",
        "The Runtime's resource policy could not be read.",
        "The containment events could not be read (InternalServerError).",
        f"The policies of Tool Gateway {GATEWAY_ID} could not be read (AccessDeniedException).",
        "The pipeline executions could not be read (AccessDeniedException).",
    ]
    # What the inventory already held is still there.
    assert body["registration"]["document"] == agent_document() and body["risk"]["assessed_at"]


def test_unreadable_attestations_are_named_in_the_evidence(backend):
    service, clients = backend
    clients.clients[("platform", "dynamodb")].fail_query = True
    service.cache.clear()
    body = evidence(backend)[1]
    assert body["reviews"]["effective_review_by"] == "2099-12-31" and body["reviews"]["source"] == "registration"
    assert body["limitations"][:2] == [
        "The registration's audit events could not be read (InternalServerError).",
        "Review attestations could not be read (InternalServerError), "
        "so every review date shown is the registration's own.",
    ]


def test_without_an_audit_table_the_document_says_so(backend, monkeypatch):
    service, clients = backend
    monkeypatch.delenv("PORTAL_AUDIT_TABLE")
    from portal_api.config import get_settings

    bare = make_service(get_settings(), clients)
    document = bare.evidence("recAgent0001", _principal())
    assert document.decisions == [] and document.containment.events == []
    assert document.containment.state == "not_contained"
    assert document.limitations == [
        "No audit table is configured for the read API, so decisions, review attestations "
        "and containment events are not available.",
        evidence_builder.WITHHELD,  # the caller here is a reader
    ]
    assert document.containment.details_shown is False
    assert clients.clients[("platform", "dynamodb")].calls == []


def test_a_gateway_outside_the_readable_cells_is_named(backend, monkeypatch):
    service, _ = backend
    elsewhere = f"arn:aws:bedrock-agentcore:eu-west-1:{OTHER_ACCOUNT}:gateway/far-tools-zyxwvutsrq"
    monkeypatch.setattr(
        registry,
        "list_records",
        lambda client, registry_id: [tool_record("tool-echo"), agent_record(gatewayArn=elsewhere)],
    )
    service.cache.clear()
    body = evidence(backend)[1]
    assert body["policy"] == [
        {
            "gateway_id": "far-tools-zyxwvutsrq",
            "gateway_name": None,
            "link_source": "registry",
            "policy_mode": None,
            "policy_count": None,
            "cedar_sha256": None,
            "policies": [],
        }
    ]
    assert body["limitations"] == [
        "Tool Gateway far-tools-zyxwvutsrq was not found in a cell the portal can read, "
        "so its policy mode and policies are not known."
    ]


def test_an_agent_with_no_reader_gets_a_document_that_says_what_is_missing(backend, monkeypatch):
    service, _ = backend
    outside = "arn:aws:bedrock-agentcore:eu-west-1:888888888888:runtime/far_agent-QwErTy5678"
    monkeypatch.setattr(
        registry,
        "list_records",
        lambda client, registry_id: [agent_record(runtimeArn=outside, gatewayArn=None, tenantId="ws9")],
    )
    service.cache.clear()
    status, body, _ = evidence(backend)
    assert status == 200
    assert (body["agent"]["reader_status"], body["agent"]["inventory_state"]) == ("none", "registered_only")
    assert body["agent"]["account_alias"] == "account-8888" and body["agent"]["runtime_arn"] == outside
    assert body["containment"]["state"] == "unknown" and body["policy"] == [] and body["release"] is None
    assert body["limitations"] == [
        "There is no reader in this agent's account, so its containment state cannot be read.",
        "This agent does not belong to a configured cell, so it has no pipeline.",
    ]


def _principal():
    from portal_api.identity.provider import Principal

    return Principal(subject="user-9", email=None, display_name="Vera Viewer", groups=("viewers",), role="readonly")


# --- what the document must never hold ---------------------------------------------------------------

ENVIRONMENT = {
    "AGENTCORE_GATEWAY_URL": GATEWAY_URL,
    "AGENTCORE_INFERENCE_GATEWAY_URL": "https://inference.internal.example.com/v1/models",
    "AGENTCORE_GUARDRAIL_ID": "gr-7f3a9c1d2e",
    "AGENTCORE_MEMORY_ID": "mem-from-environment-9c1d",
    "DB_PASSWORD": "hunter2-do-not-leak",
    "API_KEY": "key-value-do-not-leak-either",
}
EXTERNAL_ID = "portal-ext-id"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.caller-token-payload.signature-marker"  # noqa: S105 - a marker, not a credential


@pytest.fixture
def live_shaped(monkeypatch: pytest.MonkeyPatch):
    """A service whose Runtime is read through the real reading code, environment variables included."""
    monkeypatch.setattr(
        registry, "list_records", lambda client, registry_id: [tool_record("tool-echo"), agent_record()]
    )
    monkeypatch.setattr(agentcore, "list_gateways", lambda client: [gateway_bundle("ENFORCE")])
    runtime_id = RUNTIME_ARN.rsplit("/", 1)[-1]
    control = FakeClient(
        {
            "list_agent_runtimes": [
                {
                    "agentRuntimes": [
                        {"agentRuntimeArn": RUNTIME_ARN, "agentRuntimeId": runtime_id, "status": "READY"},
                    ]
                }
            ],
            "get_agent_runtime": {
                "environmentVariables": dict(ENVIRONMENT),
                "authorizerConfiguration": {"customJWTAuthorizer": {"discoveryUrl": "https://idp.example.com"}},
            },
            "get_resource_policy": {},
            "list_tags_for_resource": {
                "tags": {"tenant-id": "ws1", "agent-id": "travel-agent", "environment": "nonprod"}
            },
            "list_policies": [
                {"policies": [{"policyId": "p1", "name": "allow", "definition": {"cedar": {"statement": PERMIT}}}]}
            ],
        }
    )
    table = FakeDynamo()
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "AssumeRole")
    clients = FakeClients(
        {
            ("platform", "agent-registry-control"): FakeClient(),
            ("platform", "dynamodb"): table,
            ("platform", "codepipeline"): FakeClient({"list_pipeline_executions": {"pipelineExecutionSummaries": []}}),
            (CELL_ACCOUNT, "bedrock-agentcore-control"): control,
            (CELL_ACCOUNT, "cloudwatch"): FakeClient({"describe_alarms": [{"MetricAlarms": []}]}),
            (OTHER_ACCOUNT, "bedrock-agentcore-control"): denied,
            (OTHER_ACCOUNT, "cloudwatch"): denied,
        }
    )
    audit_writer.put_event(
        table,
        TABLE,
        audit_reader.containment_key(RUNTIME_ARN),  # the history belongs to the Runtime
        audit_event("contain", "2026-01-14T09:00:00.000001Z", agent_id="recAgent0001", runtime_arn=RUNTIME_ARN),
    )
    return make_service(load_settings(BASE_ENV), clients), control


def test_the_document_holds_no_environment_value_no_external_id_and_no_token(live_shaped):
    service, control = live_shaped
    app = create_app()
    app.dependency_overrides[deps.get_service] = lambda: service
    request = event(
        "/agents/recAgent0001/evidence", "GET", PLATFORM_CLAIMS, headers={"authorization": f"Bearer {TOKEN}"}
    )
    response = Mangum(app, lifespan="off")(request, None)
    assert response["statusCode"] == 200
    text = response["body"]
    body = json.loads(text)

    # The Runtime really was read with its environment, and what was derived from it is in the document.
    assert ("get_agent_runtime", {"agentRuntimeId": RUNTIME_ARN.rsplit("/", 1)[-1]}) in control.calls
    assert body["agent"]["inbound_authorizer"] == "CUSTOM_JWT"
    assert "GUARDRAIL_NOT_CONFIGURED" not in {r["code"] for r in body["risk"]["reasons"]}
    assert body["policy"][0]["gateway_id"] == GATEWAY_ID and body["policy"][0]["policy_count"] == 1
    assert body["containment"]["events"][0]["runtime_arn"] == RUNTIME_ARN

    haystack = text + json.dumps(dict(response["headers"]))
    for name, value in ENVIRONMENT.items():
        assert value not in haystack, f"the value of {name} is in the evidence"
    assert EXTERNAL_ID not in haystack
    assert TOKEN not in haystack and "Bearer" not in haystack and TOKEN.split(".")[1] not in haystack
    # Nor the roles the portal assumes, nor the text of a policy.
    assert "agenticai-portal-reader" not in haystack and "agenticai-portal-containment" not in haystack
    assert "permit(" not in haystack

    # No account id outside an ARN.
    outside_arns = re.sub(r'arn:aws[a-z-]*:[^"\s]*', "", haystack)
    for account in (CELL_ACCOUNT, OTHER_ACCOUNT, PLATFORM_ACCOUNT):
        assert account not in outside_arns
    assert body["agent"]["account_alias"] == f"account-{CELL_ACCOUNT[-4:]}"


def test_the_evidence_model_has_no_field_for_configuration_values():
    """A guard on the shape: nothing in the document is named after a place a secret could come from."""

    def names(schema: Any) -> set[str]:
        found: set[str] = set()
        if isinstance(schema, dict):
            for key, value in schema.items():
                if key == "properties" and isinstance(value, dict):
                    found.update(value)
                found |= names(value)
        elif isinstance(schema, list):
            for item in schema:
                found |= names(item)
        return found

    fields = names(AgentEvidence.model_json_schema())
    forbidden = (
        "environment_variable",
        "env_var",
        "secret",
        "token",
        "password",
        "credential",
        "external_id",
        "role_arn",
        "cedar_text",
        "endpoint_url",
        "gateway_url",
    )
    assert not [name for name in fields if any(word in name.lower() for word in forbidden)], sorted(fields)


# --- a decision taken a moment before the document is made ---------------------------------------


def registry_holds(monkeypatch: pytest.MonkeyPatch, *records: dict[str, Any]) -> list[str]:
    """Make the registry answer with these records from now on. Returns the list of its reads."""
    reads: list[str] = []

    def list_records(client: Any, registry_id: str) -> list[dict[str, Any]]:
        reads.append(registry_id)
        return list(records)

    monkeypatch.setattr(registry, "list_records", list_records)
    return reads


def decided(table: Any, action: str, status_after: str, **extra: Any) -> str:
    """Write the result event of a decision taken now, as the action functions do."""
    at = audit_writer.now_stamp()
    partition = extra.pop("partition", "RECORD#recAgent0001")
    audit_writer.put_event(table, TABLE, partition, audit_event(action, at, status_after=status_after, **extra))
    return at


def stale_notes(body: dict[str, Any]) -> list[str]:
    return [note for note in body["limitations"] if "not yet reflected" in note]


def test_a_decision_after_the_cached_assessment_is_reflected_in_every_section(backend, monkeypatch):
    """An auditor's document must not list an approval and still call the registration pending."""
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("PENDING_APPROVAL"))
    service.cache.clear()
    before = evidence(backend)[1]
    assert before["registration"]["status"] == "PENDING_APPROVAL" and before["decisions"] == []
    assert before["reviews"]["source"] == "registration" and stale_notes(before) == []

    # The registration is approved, reviewed and retired. The inventory in the cache is from before.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    decided(table, "approve", "APPROVED")
    decided(table, "review", "APPROVED", next_review_by="2027-06-01")
    audit_writer.put_attestation(
        table,
        TABLE,
        at=audit_writer.now_stamp(),
        record_id="recAgent0001",
        next_review_by="2027-06-01",
        reviewed_by="ann-1",
        reviewed_by_label="ann@example.com",
        reviewed_by_role="approver",
        reason="Reviewed.",
        request_id="req-review",
    )
    retired_at = decided(table, "retire", "DEPRECATED")

    status, body, _ = evidence(backend)
    assert status == 200
    assert [e["action"] for e in body["decisions"]] == ["approve", "review", "retire"]
    # Every section that comes from the inventory reflects them.
    assert body["registration"]["status"] == "DEPRECATED"
    assert body["agent"]["lifecycle_state"] == "deprecated"
    assert (body["reviews"]["effective_review_by"], body["reviews"]["source"]) == ("2027-06-01", "attestation")
    assert [a["reviewed_by_label"] for a in body["reviews"]["attestations"]] == ["ann@example.com"]
    assert "REGISTRATION_DEPRECATED" in [reason["code"] for reason in body["risk"]["reasons"]]
    # The inventory was loaded again, once, after the last event: nothing lags, and nothing says so.
    assert stale_notes(body) == [] and len(reads) == 1
    assert body["risk"]["assessed_at"] > retired_at > before["risk"]["assessed_at"]
    # The fresh inventory is the cached one now: the next document and the agent list need no load.
    assert evidence(backend)[1]["registration"]["status"] == "DEPRECATED"
    assert service.agent("recAgent0001").agent.lifecycle_state == "deprecated"
    assert len(reads) == 1


def test_a_reload_that_fails_keeps_the_sections_it_had_and_says_so(backend, monkeypatch):
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("PENDING_APPROVAL"))
    service.cache.clear()
    before = evidence(backend)[1]
    decided(table, "approve", "APPROVED")

    def unavailable(client: Any, registry_id: str) -> list[dict[str, Any]]:
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "x"}}, "ListRegistryRecords")

    monkeypatch.setattr(registry, "list_records", unavailable)
    status, body, _ = evidence(backend)
    assert status == 200
    # The decision is listed, the sections are the ones it had, and the document says that they lag.
    assert [e["action"] for e in body["decisions"]] == ["approve"]
    assert body["registration"]["status"] == "PENDING_APPROVAL"
    assert body["risk"]["assessed_at"] == before["risk"]["assessed_at"]
    assert stale_notes(body) == [evidence_builder.STALE.format(assessed_at=before["risk"]["assessed_at"])]
    # The inventory that was cached is still there for everyone else.
    assert service.agent("recAgent0001").agent.registry_status == "PENDING_APPROVAL"

    # A document asked for at once does not try again: the inventory is loaded for a document at
    # most once in 15 seconds, and an attempt that failed counts. It says that it lags.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    at_once = evidence(backend)[1]
    assert at_once["registration"]["status"] == "PENDING_APPROVAL" and len(stale_notes(at_once)) == 1
    assert reads == []
    # After that time the next document tries again, and this time the registry answers.
    later = service._clock() + 15
    monkeypatch.setattr(service, "_clock", lambda: later)
    after = evidence(backend)[1]
    assert after["registration"]["status"] == "APPROVED" and stale_notes(after) == [] and len(reads) == 1


NOTHING_CHANGED = {
    "a refusal": {"action": "approve", "outcome": "denied"},
    "a refused update": {"action": "update", "outcome": "denied"},
    "a failure": {"action": "approve", "outcome": "failed"},
    "an intent": {"action": "approve", "phase": "intent"},
    "a background sweep": {"action": "sweep", "partition": audit_reader.containment_key(RUNTIME_ARN)},
    "a sweep that was skipped": {
        "action": "sweep",
        "outcome": "skipped",
        "partition": audit_reader.containment_key(RUNTIME_ARN),
    },
    "a refused release": {
        "action": "release",
        "outcome": "denied",
        "partition": audit_reader.containment_key(RUNTIME_ARN),
    },
}


@pytest.mark.parametrize("event", NOTHING_CHANGED.values(), ids=NOTHING_CHANGED.keys())
def test_an_event_that_changed_nothing_does_not_load_the_inventory_again(backend, monkeypatch, event):
    """The attack: keep writing events (refusals, or let sweeps run) while someone asks for evidence.

    Every document then loaded the whole inventory again, which reads every cell.
    """
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("PENDING_APPROVAL"))
    service.cache.clear()
    before = evidence(backend)[1]
    loaded = len(reads)

    extra = {name: value for name, value in event.items() if name != "action"}
    for _ in range(5):
        decided(table, event["action"], "PENDING_APPROVAL", **extra)
        after = evidence(backend)[1]
    assert len(reads) == loaded  # not once
    assert after["risk"]["assessed_at"] == before["risk"]["assessed_at"]
    # And nothing lags: the event is listed, and there was nothing in it for the other sections to reflect.
    assert stale_notes(after) == []
    listed = after["containment"]["events"] if "partition" in event else after["decisions"]
    assert len([e for e in listed if e["action"] == event["action"]]) == 5


@pytest.mark.parametrize("outcome", ["allowed", "unchanged"])
def test_a_decision_that_was_carried_out_does(backend, monkeypatch, outcome):
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("PENDING_APPROVAL"))
    service.cache.clear()
    evidence(backend)
    loaded = len(reads)
    decided(table, "retire", "DEPRECATED", outcome=outcome)
    evidence(backend)
    assert len(reads) == loaded + 1


def test_the_inventory_is_loaded_again_for_a_document_at_most_once_in_fifteen_seconds(backend, monkeypatch):
    """Loading it reads every cell. However many documents are asked for, and whatever was decided meanwhile."""
    from portal_api import service as service_module

    assert service_module.DECISION_RELOAD_SECONDS == 15
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    now = [1_000.0]
    monkeypatch.setattr(service, "_clock", lambda: now[0])
    registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("PENDING_APPROVAL"))
    service.cache.clear()
    assert evidence(backend)[1]["registration"]["status"] == "PENDING_APPROVAL"

    # A decision: the first document after it loads the inventory again.
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    decided(table, "approve", "APPROVED")
    first = evidence(backend)[1]
    assert first["registration"]["status"] == "APPROVED" and stale_notes(first) == [] and len(reads) == 1

    # Another decision a moment later. The documents asked for in the next fifteen seconds do not
    # load it again: they list the decision and say that the other sections lag.
    registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("DEPRECATED"))
    decided(table, "retire", "DEPRECATED")
    for seconds in (0.0, 5.0, 14.9):
        now[0] = 1_000.0 + seconds
        lagging = evidence(backend)[1]
        assert lagging["registration"]["status"] == "APPROVED" and len(stale_notes(lagging)) == 1
        assert [e["action"] for e in lagging["decisions"]][-1] == "retire"
    assert reads == []
    # After that the next document does, and is whole again.
    now[0] = 1_015.0
    whole = evidence(backend)[1]
    assert whole["registration"]["status"] == "DEPRECATED" and stale_notes(whole) == [] and len(reads) == 1
    # ... and that one counts too.
    decided(table, "review", "DEPRECATED")
    now[0] = 1_020.0
    assert len(stale_notes(evidence(backend)[1])) == 1 and len(reads) == 1


@pytest.mark.parametrize("claims", [PLATFORM_CLAIMS, VIEWER_CLAIMS])
def test_a_containment_action_after_the_assessment_is_reflected_whoever_asks(backend, claims):
    """The reader of the document may not be shown the containment events; the flags follow them all the same."""
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    control = clients.clients[(CELL_ACCOUNT, "bedrock-agentcore-control")]
    control.runtimes[0]["detail"]["contained"] = False
    service.cache.clear()
    before = evidence(backend, claims=claims)[1]
    assert before["risk"]["flags"]["contained"] is False

    control.runtimes[0]["detail"]["contained"] = True  # what the next read of the Runtime's policy finds
    decided(table, "contain", "contained", partition=audit_reader.containment_key(RUNTIME_ARN), agent_id="recAgent0001")
    body = evidence(backend, claims=claims)[1]
    assert body["risk"]["flags"]["contained"] is True and stale_notes(body) == []
    assert body["risk"]["assessed_at"] > before["risk"]["assessed_at"]
    shown = claims is PLATFORM_CLAIMS
    assert [e["action"] for e in body["containment"]["events"]] == (["contain"] if shown else [])


def test_nothing_is_loaded_again_when_nothing_was_recorded_since(backend, monkeypatch):
    service, clients = backend
    table = clients.clients[("platform", "dynamodb")]
    # A decision that the inventory already reflects: recorded before it was assessed.
    decided(table, "approve", "APPROVED")
    reads = registry_holds(monkeypatch, tool_record("tool-echo"), agent_record("APPROVED"))
    service.cache.clear()
    first = evidence(backend)[1]
    assert [e["action"] for e in first["decisions"]] == ["approve"] and stale_notes(first) == []
    second = evidence(backend)[1]
    assert len(reads) == 1 and second["risk"]["assessed_at"] == first["risk"]["assessed_at"]


def test_the_inventory_describes_the_moment_before_its_own_reads(backend, monkeypatch):
    """What was recorded before ``assessed_at`` is in the inventory: the registry is read after it, and afresh."""
    from portal_api.mappers.common import now_precise, parse_instant

    service, _ = backend
    read_at: list[str] = []

    def list_records(client: Any, registry_id: str) -> list[dict[str, Any]]:
        read_at.append(now_precise())
        return [tool_record("tool-echo"), agent_record("APPROVED" if len(read_at) < 3 else "DEPRECATED")]

    monkeypatch.setattr(registry, "list_records", list_records)
    service.cache.clear()
    inventory = service.inventory()
    assert len(read_at) == 1 and inventory.assessed_at <= read_at[0]
    assert parse_instant(inventory.assessed_at).microsecond or "." in inventory.assessed_at  # to the microsecond
    # The tool catalogue reads the registry into the cache at some other moment.
    service.cache.clear()
    assert service.catalog_tools() and len(read_at) == 2
    # An inventory loaded after that does not build on those cached records: it reads the registry itself.
    later = service.inventory()
    assert len(read_at) == 3 and later.assessed_at <= read_at[2]
    assert service.agent("recAgent0001").agent.registry_status == "DEPRECATED"
    # And what it read serves the catalogue from the cache afterwards.
    assert service.catalog_tools() and len(read_at) == 3


def test_a_cached_value_can_be_loaded_again_and_a_failed_load_keeps_it():
    from portal_api.aws.cache import TTLCache

    cache = TTLCache()
    assert cache.get_or_load("k", 30, lambda: "first") == "first"
    assert cache.get_or_load("k", 30, lambda: "second") == "first"
    assert cache.get_or_load("k", 30, lambda: "second", refresh=True) == "second"
    assert cache.get_or_load("k", 30, lambda: "third") == "second"

    def fails() -> str:
        raise RuntimeError("unavailable")

    with pytest.raises(RuntimeError):
        cache.get_or_load("k", 30, fails, refresh=True)
    assert cache.get_or_load("k", 30, lambda: "fourth") == "second"


def test_the_documents_say_that_a_decision_is_never_listed_without_being_reflected():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    readme = " ".join((root / "README.md").read_text().split())
    assert "the inventory is loaded again once, past the cache" in readme
    assert "it never lists an approval and still calls the registration pending" in readme
    contract = " ".join((root / "ACTIONS_CONTRACT.md").read_text().split())
    assert "the inventory is loaded again before the document is built" in contract
    assert "when that load failed or was not done for that reason" in contract
    # What counts as a decision, and how often the inventory is loaded for a document.
    for document in (readme, contract):
        assert "(`allowed` or `unchanged`" in document
        assert "at most once in 15 seconds" in document
    assert "A refusal, a failure, an intent and a background sweep change nothing there" in readme
