# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS CodePipeline reads for release evidence (platform account, the function's own role)."""

from __future__ import annotations

from typing import Any

from portal_api.aws.parallel import pmap

EVALUATION_GATE_ACTION = "EvaluationGate"


def recent_executions(client: Any, pipeline_name: str, limit: int = 10) -> list[dict[str, Any]]:
    """The newest executions of a pipeline, each with its EvaluationGate action when it ran.

    Returns ``{"execution": summary, "gate": action execution detail or None}``.
    """
    response = client.list_pipeline_executions(pipelineName=pipeline_name, maxResults=limit)
    summaries = response.get("pipelineExecutionSummaries") or []

    def gate_for(summary: dict[str, Any]) -> dict[str, Any] | None:
        paginator = client.get_paginator("list_action_executions")
        pages = paginator.paginate(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": summary["pipelineExecutionId"]}
        )
        for page in pages:
            for action in page.get("actionExecutionDetails") or []:
                if action.get("actionName") == EVALUATION_GATE_ACTION:
                    return action
        return None

    gates = pmap(gate_for, summaries, max_workers=4)
    return [
        {"execution": summary, "gate": None if isinstance(gate, BaseException) else gate}
        for summary, gate in zip(summaries, gates, strict=True)
    ]
