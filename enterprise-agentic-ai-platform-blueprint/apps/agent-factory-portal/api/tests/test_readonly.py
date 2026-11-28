# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Each role's code calls exactly the AWS operations IAM_ACTIONS.md lists for it.

The read API calls no mutating operation and does not import the action code.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "portal_api"
ACTIONS = PACKAGE / "actions"

READ_FILES = sorted(p for p in PACKAGE.rglob("*.py") if ACTIONS not in p.parents)
SHARED_ACTION_FILES = [
    ACTIONS / "engine.py",
    ACTIONS / "audit_writer.py",
    ACTIONS / "authority.py",
    ACTIONS / "app.py",
    ACTIONS / "lifecycle_rules.py",  # pure; both functions refuse a change to a retired record
    ACTIONS / "reference_rules.py",  # pure; both refuse a registration that names another tenant's resources
]
REGISTRAR_FILES = [ACTIONS / "registrar.py", ACTIONS / "registrar_flow.py", *SHARED_ACTION_FILES]
# Only the approver flow reads the audit trail (to find the submitter). Retire and review are
# served by the approver function too, and add no operation to it.
APPROVER_FILES = [
    ACTIONS / "approver.py",
    ACTIONS / "approver_flow.py",
    ACTIONS / "lifecycle_flow.py",
    PACKAGE / "aws" / "audit.py",
    *SHARED_ACTION_FILES,
]

# boto3 operation -> IAM action(s)
READ_OPERATIONS = {
    "assume_role": {"sts:AssumeRole"},
    "list_registry_records": {"agent-registry:ListRegistryRecords"},
    "get_registry_record": {"agent-registry:GetRegistryRecord"},
    "list_pipeline_executions": {"codepipeline:ListPipelineExecutions"},
    "list_action_executions": {"codepipeline:ListActionExecutions"},
    "list_guardrails": {"bedrock:ListGuardrails"},
    "get_guardrail": {"bedrock:GetGuardrail"},
    "list_tags_for_resource": {"bedrock:ListTagsForResource", "bedrock-agentcore:ListTagsForResource"},
    "list_agent_runtimes": {"bedrock-agentcore:ListAgentRuntimes"},
    "get_agent_runtime": {"bedrock-agentcore:GetAgentRuntime"},
    "list_agent_runtime_versions": {"bedrock-agentcore:ListAgentRuntimeVersions"},
    "list_gateways": {"bedrock-agentcore:ListGateways"},
    "get_gateway": {"bedrock-agentcore:GetGateway"},
    "list_gateway_targets": {"bedrock-agentcore:ListGatewayTargets"},
    "get_gateway_target": {"bedrock-agentcore:GetGatewayTarget"},
    "list_policies": {"bedrock-agentcore:ListPolicies"},
    "get_policy": {"bedrock-agentcore:GetPolicy"},
    "get_resource_policy": {"bedrock-agentcore:GetResourcePolicy"},
    "describe_alarms": {"cloudwatch:DescribeAlarms"},
    "describe_alarm_history": {"cloudwatch:DescribeAlarmHistory"},
    "get_metric_data": {"cloudwatch:GetMetricData"},
    "start_query": {"logs:StartQuery"},
    "get_query_results": {"logs:GetQueryResults"},
    "query": {"dynamodb:Query"},
    "get_context_graph": {"cloudwatch:GetContextGraph"},
}
REGISTRAR_OPERATIONS = {
    "list_registry_records": {"agent-registry:ListRegistryRecords"},
    "get_registry_record": {"agent-registry:GetRegistryRecord"},
    "create_registry_record": {"agent-registry:CreateRegistryRecord"},
    "update_registry_record": {"agent-registry:UpdateRegistryRecord"},
    "submit_registry_record_for_approval": {"agent-registry:SubmitRegistryRecordForApproval"},
    "delete_registry_record": {"agent-registry:DeleteRegistryRecord"},
    "put_item": {"dynamodb:PutItem"},
}
APPROVER_OPERATIONS = {
    "get_registry_record": {"agent-registry:GetRegistryRecord"},
    "update_registry_record_status": {"agent-registry:UpdateRegistryRecordStatus"},
    "query": {"dynamodb:Query"},
    "put_item": {"dynamodb:PutItem"},
}

CONTAINMENT_FILES = [
    ACTIONS / "containment.py",
    ACTIONS / "containment_flow.py",
    ACTIONS / "containment_rules.py",
    ACTIONS / "sweep_queue.py",  # the contain leaves messages for the sweeper
    ACTIONS / "audit_writer.py",
    PACKAGE / "aws" / "audit.py",
    PACKAGE / "aws" / "logs.py",
    PACKAGE / "aws" / "session.py",
    PACKAGE / "containment_policy.py",
]
# With the function's own role, and with the cell's containment role.
CONTAINMENT_FUNCTION_OPERATIONS = {
    "assume_role": {"sts:AssumeRole"},
    "get_registry_record": {"agent-registry:GetRegistryRecord"},
    "query": {"dynamodb:Query"},
    "put_item": {"dynamodb:PutItem"},
    "send_message": {"sqs:SendMessage"},
}
# The sweeper function runs under the containment function's role and uses a part of the above.
SWEEPER_FILE = ACTIONS / "sweeper.py"
SWEEPER_USES_OF_CONTAINMENT = {"get_policy", "discover_sessions", "stop_session", "SessionStop", "Session"}
CONTAINMENT_CELL_OPERATIONS = {
    "get_resource_policy": {"bedrock-agentcore:GetResourcePolicy"},
    "put_resource_policy": {"bedrock-agentcore:PutResourcePolicy"},
    "delete_resource_policy": {"bedrock-agentcore:DeleteResourcePolicy"},
    "stop_runtime_session": {"bedrock-agentcore:StopRuntimeSession"},
    "list_agent_runtime_endpoints": {"bedrock-agentcore:ListAgentRuntimeEndpoints"},
    # In an account that several tenants share: the Runtime's own tenant-id tag.
    "list_tags_for_resource": {"bedrock-agentcore:ListTagsForResource"},
    "start_query": {"logs:StartQuery"},
    "get_query_results": {"logs:GetQueryResults"},
    "describe_log_streams": {"logs:DescribeLogStreams"},
}

MUTATING = re.compile(
    r"^(create|update|delete|put|tag|untag|start|stop|submit|invoke|attach|detach|register|deregister|"
    r"associate|disassociate|set|modify|remove|add|enable|disable|cancel|approve|reject|batch|transact)_"
)
# start_query starts a read-only Logs Insights query.
READ_ONLY_EXCEPTIONS = {"start_query"}
CALL = re.compile(r"\bclient\.([a-z_]+)\(")
PAGINATED = re.compile(r"""(?:paginate\(\s*[a-z_.()"\s]*?,|get_paginator\()\s*"([a-z_]+)\"""")
OTHER_CALL = re.compile(r"\.(assume_role)\(")


def operations(files: list[Path]) -> set[str]:
    found: set[str] = set()
    for path in files:
        text = path.read_text()
        found.update(m for m in CALL.findall(text) if m != "get_paginator")
        found.update(PAGINATED.findall(text))
        found.update(OTHER_CALL.findall(text))
    return found


def documented(section: str) -> set[str]:
    """IAM actions in the table rows of one numbered section of IAM_ACTIONS.md."""
    text = (ROOT / "IAM_ACTIONS.md").read_text()
    body = re.split(r"^## \d+\. ", text, flags=re.M)
    match = next(part for part in body if part.startswith(section))
    rows = [line for line in match.splitlines() if line.startswith("| `")]
    return {action for row in rows for action in re.findall(r"`([a-z-]+:[A-Za-z]+)`", row.split("|")[1])}


def actions_of(mapping: dict[str, set[str]]) -> set[str]:
    return {action for actions in mapping.values() for action in actions}


def test_read_api_calls_only_its_allow_listed_operations():
    assert operations(READ_FILES) == set(READ_OPERATIONS)


def test_read_api_calls_no_mutating_operation():
    mutating = {op for op in operations(READ_FILES) if MUTATING.match(op)} - READ_ONLY_EXCEPTIONS
    assert mutating == set()


def test_registrar_calls_only_its_allow_listed_operations():
    assert operations(REGISTRAR_FILES) == set(REGISTRAR_OPERATIONS)
    assert "update_registry_record_status" not in operations(REGISTRAR_FILES)


def test_approver_calls_only_its_allow_listed_operations():
    found = operations(APPROVER_FILES)
    assert found == set(APPROVER_OPERATIONS)
    assert not found & {
        "create_registry_record",
        "update_registry_record",
        "delete_registry_record",
        "submit_registry_record_for_approval",
    }


def test_retire_and_review_add_no_operation_to_any_role():
    """Wave 2 needs no new IAM action: the lifecycle code calls nothing of its own."""
    lifecycle = [ACTIONS / "lifecycle_flow.py", ACTIONS / "lifecycle_rules.py", PACKAGE / "reviews.py"]
    assert operations(lifecycle) == set()
    # The evidence document is assembled without any call, from what the read API already reads.
    assert operations([PACKAGE / "evidence.py", PACKAGE / "models" / "evidence.py"]) == set()
    # Every action file belongs to a role's list, so none escapes the checks above.
    listed = {*REGISTRAR_FILES, *APPROVER_FILES, *CONTAINMENT_FILES, SWEEPER_FILE}
    assert {p for p in ACTIONS.glob("*.py") if p.name != "__init__.py"} <= listed


def test_the_lifecycle_rules_are_pure():
    for path in (ACTIONS / "lifecycle_rules.py", PACKAGE / "reviews.py", PACKAGE / "evidence.py"):
        text = path.read_text()
        assert "boto" not in text and "client" not in text.replace("ClientError", ""), path.name


def test_containment_calls_only_its_allow_listed_operations():
    found = operations(CONTAINMENT_FILES)
    assert found == set(CONTAINMENT_FUNCTION_OPERATIONS) | set(CONTAINMENT_CELL_OPERATIONS)
    # It never changes a registry record, and never invokes or deletes a Runtime.
    assert not found & set(REGISTRAR_OPERATIONS) - {"get_registry_record", "put_item"}
    assert not {op for op in found if op.startswith(("invoke_", "delete_agent", "update_agent", "create_"))}
    # It reads the names of log streams, never a log event.
    assert not found & {"get_log_events", "filter_log_events", "get_log_record"}


def test_the_sweeper_only_reads_the_policy_and_stops_sessions():
    """It runs under the containment role, but its code reaches for a small part of what that role can do."""
    source = SWEEPER_FILE.read_text()
    # It makes no SDK call of its own: everything goes through the containment module and the audit writer.
    assert operations([SWEEPER_FILE]) == set()
    used = set(re.findall(r"\bcontainment\.([A-Za-z_]+)", source))
    assert used == SWEEPER_USES_OF_CONTAINMENT
    # So it can never write or delete a resource policy, read the registry, or send a queue message.
    assert not used & {"put_policy", "delete_policy", "get_record", "stop_sessions"}
    assert "sweep_queue" not in source and "query_events" not in source and "query_items" not in source
    # Of the audit table it uses three things, all under the Runtime's own key: the history read
    # back to the contain a message names, the claim of the sweep, and the sweep's one event, which
    # goes into the range of the events that cannot change who holds the containment. Who holds it
    # is the history's to say (``audit.History``): the sweeper never works that out from events itself.
    assert set(re.findall(r"\baudit_reader\.([A-Za-z_]+)", source)) == {
        "read_for_sweep",
        "History",
        "containment_key",
        "OTHER_PREFIX",
    }
    assert "prefix=audit_reader.OTHER_PREFIX" in source and "EVENT_PREFIX" not in source
    assert set(re.findall(r"\baudit_writer\.([A-Za-z_]+)", source)) == {"claim_sweep", "put_event", "now_stamp"}
    assert source.count("containment_key(") == 1  # the one place a key is made: the sweep's own event
    # The queue send is the containment function's, and its one operation is documented for that role.
    assert operations([ACTIONS / "sweep_queue.py"]) == {"send_message"}
    assert "sqs:SendMessage" in documented("Containment function role")
    section = (ROOT / "IAM_ACTIONS.md").read_text().split("## 7. Sweeper function", 1)[1].split("\n## ", 1)[0]
    for needed in ("sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sweep_handler.handler"):
        assert needed in section, needed


def test_only_the_containment_code_changes_a_resource_policy():
    writers = {"put_resource_policy", "delete_resource_policy", "stop_runtime_session"}
    for files in (READ_FILES, REGISTRAR_FILES, APPROVER_FILES):
        assert not operations([f for f in files if f not in CONTAINMENT_FILES or f in READ_FILES]) & writers


def test_no_action_code_can_rewrite_the_audit_trail():
    everything = operations(sorted(PACKAGE.rglob("*.py")))
    assert not everything & {"update_item", "delete_item", "batch_write_item", "transact_write_items", "delete_table"}
    writer = (ACTIONS / "audit_writer.py").read_text()
    assert 'ConditionExpression="attribute_not_exists(pk)"' in writer


def test_iam_actions_document_matches_the_code_per_role():
    read_platform = documented("Read role")
    cell_reader = documented("Cell reader role")
    assert read_platform | cell_reader == actions_of(READ_OPERATIONS)
    in_cells_only = {a for a in read_platform if a.startswith(("bedrock-agentcore:", "cloudwatch:", "logs:"))}
    assert in_cells_only == {"cloudwatch:GetContextGraph"}  # the only CloudWatch read made in the platform account
    assert {a.split(":")[0] for a in cell_reader} == {"bedrock-agentcore", "cloudwatch", "logs"}
    assert documented("Registrar role") == actions_of(REGISTRAR_OPERATIONS)
    assert documented("Approver role") == actions_of(APPROVER_OPERATIONS)
    assert documented("Containment function role") == actions_of(CONTAINMENT_FUNCTION_OPERATIONS)
    assert documented("Cell containment role") == actions_of(CONTAINMENT_CELL_OPERATIONS)


def test_read_role_document_has_no_mutating_action():
    for action in documented("Read role") | documented("Cell reader role"):
        name = action.split(":")[1]
        assert name.startswith(("List", "Get", "Describe", "Query", "AssumeRole")) or action == "logs:StartQuery", (
            action
        )


def test_read_routes_register_get_only():
    from portal_api.app import create_app

    methods: set[str] = set()

    def walk(routes):
        for route in routes:
            methods.update(getattr(route, "methods", None) or set())
            inner = getattr(route, "routes", None) or getattr(getattr(route, "router", None), "routes", None)
            if inner:
                walk(inner)

    walk(create_app().routes)
    assert methods <= {"GET", "HEAD"}


def test_read_handler_does_not_import_the_action_code():
    script = (
        "import sys, handler\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('portal_api.actions'))\n"
        "assert not loaded, loaded\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
