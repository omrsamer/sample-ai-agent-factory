# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Release evidence: Workload pipeline executions as the console's evaluation-run shape."""

from __future__ import annotations

from typing import Any

from portal_api.mappers.common import EPOCH_ISO, iso, text
from portal_api.models.wire import EvalGate, EvalRun, EvalRuns, PipelineEvidence

_GATE_STATUS = {"Succeeded": "passed", "Failed": "failed", "InProgress": "running", "Abandoned": "error"}


def run_status(pipeline_status: str, gate_status: str | None) -> str:
    """running | passed | failed | error.

    The EvaluationGate action decides when it ran. When it did not, an
    execution still in progress is ``running`` and anything else is ``error``:
    the gate was never reached, so there is no verdict to report.
    """
    if gate_status is not None:
        return _GATE_STATUS.get(gate_status, "error")
    return "running" if pipeline_status in ("InProgress", "Stopping") else "error"


def eval_run(agent_id: str, stage: str, pipeline_name: str, item: dict[str, Any]) -> EvalRun:
    execution = item["execution"]
    gate = item.get("gate")
    pipeline_status = str(execution.get("status") or "Unknown")
    gate_status = text(gate.get("status")) if gate else None
    status = run_status(pipeline_status, gate_status)
    revisions = execution.get("sourceRevisions") or []
    revision = revisions[0] if revisions else {}
    gate_output = ((gate or {}).get("output") or {}).get("executionResult") or {}
    terminal = pipeline_status not in ("InProgress", "Stopping")

    if gate_status is None:
        reasons = [f"The evaluation gate did not run in this execution (pipeline status {pipeline_status})."]
    else:
        reasons = [f"Evaluation gate {gate_status}."]
        summary = text(gate_output.get("externalExecutionSummary"))
        if summary:
            reasons.append(summary[:500])

    return EvalRun(
        run_id=str(execution["pipelineExecutionId"]),
        agent_id=agent_id,
        stage=stage,
        git_sha=text(revision.get("revisionId")),
        started_at=iso(execution.get("startTime")) or EPOCH_ISO,
        finished_at=iso(execution.get("lastUpdateTime")) if terminal else None,
        status=status,
        gate=None if status == "running" else EvalGate(passed=status == "passed", reasons=reasons),
        pipeline=PipelineEvidence(
            pipeline_name=pipeline_name,
            execution_id=str(execution["pipelineExecutionId"]),
            status=pipeline_status,
            source_revision=text(revision.get("revisionId")),
            source_summary=text(revision.get("revisionSummary")),
            trigger_type=text((execution.get("trigger") or {}).get("triggerType")),
            evaluation_gate_status=gate_status,
            evaluation_gate_summary=(text(gate_output.get("externalExecutionSummary")) or "")[:500] or None,
            evaluation_gate_started_at=iso((gate or {}).get("startTime")),
            evaluation_gate_finished_at=iso((gate or {}).get("lastUpdateTime")),
        ),
    )


def eval_runs(agent_id: str, stage: str, pipeline_name: str, items: list[dict[str, Any]]) -> EvalRuns:
    runs = [eval_run(agent_id, stage, pipeline_name, item) for item in items]
    runs.sort(key=lambda r: r.started_at, reverse=True)
    current = runs[0] if runs else None
    return EvalRuns(runs=runs, current_build_tag=current.git_sha if current else None, current_run=current)
