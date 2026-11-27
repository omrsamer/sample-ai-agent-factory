# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Read-only orchestration: AWS reads, merged and mapped for the routes.

Nothing in this module (or anything it calls) creates, updates or deletes an
AWS resource. Workstream cells are changed only by their pipelines.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from portal_api import registrations as registration_helpers
from portal_api.aws import agentcore, cloudwatch, guardrails, logs, pipelines, registry
from portal_api.aws import audit as audit_reader
from portal_api.aws.cache import TTLCache
from portal_api.aws.parallel import pmap
from portal_api.aws.session import AwsClients, error_code
from portal_api.config import Cell, ConfigError, Settings
from portal_api.mappers import agents as agent_mapper
from portal_api.mappers import graph as graph_mapper
from portal_api.mappers import guardrails as guardrail_mapper
from portal_api.mappers import health as health_mapper
from portal_api.mappers import mcp as mcp_mapper
from portal_api.mappers import observability as observability_mapper
from portal_api.mappers import registry as registry_mapper
from portal_api.mappers import release as release_mapper
from portal_api.mappers.agents import AgentEntry, Runtime
from portal_api.mappers.common import arn_parts, arn_resource_id, now_iso
from portal_api.mappers.mcp import GatewayEntry
from portal_api.models.portal import (
    CatalogModel,
    CatalogTool,
    FleetHealth,
    Registration,
    RegistrationDetail,
    RegistrationHistory,
)
from portal_api.models.wire import (
    AgentMcpGrant,
    AgentMetricRow,
    AgentMetrics,
    CedarPolicySet,
    Deployment,
    EvalRuns,
    GovernanceGraph,
    Grant,
    GuardrailTemplate,
    MetricTotals,
    PrincipalDetail,
    RuntimeStatus,
    ScopeMetrics,
    TracePage,
)

logger = logging.getLogger(__name__)

MAX_HISTORY_CHECKS_PER_CELL = 25
MAX_WINDOW = dt.timedelta(days=31)


def _day_bounds(start: dt.datetime, end: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    """Whole UTC days covering the window, so daily metric buckets line up with calendar dates."""
    floor = start.replace(hour=0, minute=0, second=0, microsecond=0)
    ceiling = end.replace(hour=0, minute=0, second=0, microsecond=0)
    if ceiling < end:
        ceiling += dt.timedelta(days=1)
    return floor, ceiling


class NotFound(Exception):
    """The requested entity does not exist (HTTP 404)."""


class Forbidden(Exception):
    """The caller's role does not allow the request (HTTP 403)."""


class BadRequest(Exception):
    """A request parameter is invalid (HTTP 400)."""


@dataclass
class Inventory:
    agents: list[AgentEntry] = field(default_factory=list)
    gateways: list[GatewayEntry] = field(default_factory=list)
    unreachable: dict[tuple[Any, ...], str] = field(default_factory=dict)

    def gateway_index(self) -> dict[str, GatewayEntry]:
        return {g.server.id: g for g in self.gateways}


def _cell_for_tags(cells: list[Cell], tags: dict[str, str]) -> Cell | None:
    identity = (
        tags.get(agent_mapper.TAG_TENANT),
        tags.get(agent_mapper.TAG_AGENT),
        tags.get(agent_mapper.TAG_ENVIRONMENT),
    )
    for cell in cells:
        if (cell.tenant_id, cell.agent_id, cell.environment) == identity:
            return cell
    return None


class PortalService:
    def __init__(self, settings: Settings, clients: AwsClients | None = None, cache: TTLCache | None = None) -> None:
        self.settings = settings
        self.clients = clients or AwsClients(home_region=settings.registry_region)
        self.cache = cache or TTLCache()

    # --- cached reads --------------------------------------------------------

    def _cached(self, key: Any, loader: Any) -> Any:
        return self.cache.get_or_load(key, self.settings.cache_ttl_seconds, loader)

    def _registry_client(self) -> Any:
        return self.clients.platform("agent-registry-control", self.settings.registry_region)

    def records(self) -> list[dict[str, Any]]:
        """Records of the platform registry (``PORTAL_REGISTRY_ID``): the tool records."""

        def load() -> list[dict[str, Any]]:
            return registry.list_records(self._registry_client(), self.settings.registry_id)

        return self._cached(("registry-records", self.settings.registry_id), load)

    def agent_registry_records(self) -> list[dict[str, Any]]:
        """Records of the registry that holds agent governance records.

        That is ``PORTAL_AGENT_REGISTRY_ID`` when set. Otherwise one registry holds both
        kinds of record and this is the same (cached) list as ``records()``.
        """
        registry_id = self.settings.effective_agent_registry_id
        if registry_id == self.settings.registry_id:
            return self.records()

        def load() -> list[dict[str, Any]]:
            return registry.list_records(self._registry_client(), registry_id)

        return self._cached(("registry-records", registry_id), load)

    def _scopes(self) -> dict[tuple[Any, ...], list[Cell]]:
        scopes: dict[tuple[Any, ...], list[Cell]] = {}
        for cell in self.settings.cells:
            scopes.setdefault(cell.scope, []).append(cell)
        return scopes

    def inventory(self) -> Inventory:
        return self._cached("inventory", self._load_inventory)

    def _load_inventory(self) -> Inventory:
        tool_index = registry_mapper.tool_index(self.records())
        agent_records = registry_mapper.agent_records(self.agent_registry_records())
        scopes = self._scopes()

        def discover(cells: list[Cell]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            client = self.clients.cell(cells[0], "bedrock-agentcore-control")
            return agentcore.list_runtimes(client), agentcore.list_gateways(client)

        inventory = Inventory()
        runtimes: dict[str, Runtime] = {}
        runtime_cells: dict[str, Cell | None] = {}
        scope_items = list(scopes.items())
        for (scope, cells), result in zip(scope_items, pmap(discover, [c for _, c in scope_items]), strict=True):
            if isinstance(result, BaseException):
                code = error_code(result)
                logger.warning("Cell account %s in %s could not be read: %s", scope[0], scope[1], code)
                inventory.unreachable[scope] = code
                continue
            runtime_bundles, gateway_bundles = result
            for bundle in runtime_bundles:
                matched = _cell_for_tags(cells, bundle.get("tags") or {})
                runtime = agent_mapper.runtime_from_bundle(bundle, matched or cells[0])
                runtimes[runtime.arn] = runtime
                runtime_cells[runtime.arn] = matched
            for bundle in gateway_bundles:
                matched = _cell_for_tags(cells, bundle.get("tags") or {})
                inventory.gateways.append(mcp_mapper.gateway_entry(bundle, matched or cells[0], tool_index))

        referenced: set[str] = set()
        for record in agent_records:
            governance = registry_mapper.agent_governance(record)
            runtime = runtimes.get(governance.runtime_arn or "")
            if runtime:
                referenced.add(runtime.arn)
            cell = self.settings.cell_for(governance.tenant_id, governance.agent_id, governance.environment)
            inventory.agents.append(
                agent_mapper.registered_agent(record, runtime, cell, self._access_cell(governance.runtime_arn))
            )
        for arn, runtime in runtimes.items():
            if arn in referenced:
                continue
            entry = agent_mapper.discovered_agent(runtime, runtime_cells.get(arn))
            entry.links = graph_mapper.derive_links(entry, inventory.gateways)
            entry.agent.mcp_server_ids = [link.gateway_id for link in entry.links]
            inventory.agents.append(entry)

        inventory.agents.sort(key=lambda e: (e.agent.name.lower(), e.agent.id))
        inventory.gateways.sort(key=lambda g: (g.server.name.lower(), g.server.id))
        return inventory

    def _access_cell(self, arn: str | None) -> Cell | None:
        """A configured cell whose reader role covers the account and Region of ``arn``."""
        parts = arn_parts(arn)
        if not parts:
            return None
        for cell in self.settings.cells:
            if (cell.account_id, cell.region) == (parts["account"], parts["region"]):
                return cell
        return None

    # --- agents --------------------------------------------------------------

    def agents(self) -> list[AgentEntry]:
        return self.inventory().agents

    def agent(self, agent_id: str) -> AgentEntry:
        for entry in self.inventory().agents:
            if entry.agent.id == agent_id:
                return entry
        raise NotFound("Agent not found")

    def runtime_status(self, agent_id: str, stage: str | None = None) -> RuntimeStatus:
        entry = self.agent(agent_id)
        if stage and stage != (entry.agent.environment or "unknown"):
            # The agent owns no runtime in that environment; never answer with another one's reading.
            return RuntimeStatus(agent_id=entry.agent.id, stage=stage, status="not_deployed", checked_at=now_iso())
        cell = entry.access_cell
        reachable = cell is not None and cell.scope not in self.inventory().unreachable
        return agent_mapper.runtime_status(entry, reachable)

    def deployments(self, agent_id: str, limit: int, stage: str | None = None) -> list[Deployment]:
        entry = self.agent(agent_id)
        if stage and stage != (entry.agent.environment or "unknown"):
            return []
        runtime_id = arn_resource_id(entry.runtime_arn)
        if not runtime_id or entry.access_cell is None:
            return []
        cell = entry.access_cell

        def load() -> list[dict[str, Any]]:
            client = self.clients.cell(cell, "bedrock-agentcore-control")
            return agentcore.list_runtime_versions(client, runtime_id)

        versions = self._cached(("runtime-versions", cell.scope, runtime_id), load)
        return agent_mapper.deployments(entry, versions, limit)

    def agent_mcp_grants(self, agent_id: str) -> list[AgentMcpGrant]:
        return graph_mapper.agent_mcp_grants(self.agent(agent_id), self.inventory().gateway_index())

    # --- traces and metrics --------------------------------------------------

    def traces(self, agent_id: str, page: int, limit: int, hours: int) -> TracePage:
        entry = self.agent(agent_id)
        if not entry.runtime_arn or entry.access_cell is None:
            return TracePage(warnings=["This agent has no runtime in a configured cell."])
        end = dt.datetime.now(dt.UTC)
        start = end - dt.timedelta(hours=hours)
        fetch = min(page * limit, logs.MAX_TRACE_ROWS)
        query = logs.traces_query(entry.runtime_arn, fetch)
        client = self.clients.cell(entry.access_cell, "logs")
        results, warnings = logs.run_queries(client, {"traces": query}, int(start.timestamp()), int(end.timestamp()))
        rows = [r for r in (observability_mapper.trace_row(row) for row in results["traces"]) if r is not None]
        if page * limit > logs.MAX_TRACE_ROWS:
            warnings.append(f"Only the newest {logs.MAX_TRACE_ROWS} traces in the window are available.")
        return TracePage(data=rows[(page - 1) * limit : page * limit], total=len(rows), warnings=warnings)

    @staticmethod
    def window(date_from: str | None, date_to: str | None) -> tuple[dt.datetime, dt.datetime]:
        def parse(value: str, label: str) -> dt.datetime:
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise BadRequest(f"{label} is not an ISO-8601 date") from exc
            return parsed.replace(tzinfo=dt.UTC) if parsed.tzinfo is None else parsed.astimezone(dt.UTC)

        end = parse(date_to, "date_to") if date_to else dt.datetime.now(dt.UTC)
        if date_to and len(date_to) <= 10:
            end += dt.timedelta(days=1)  # a bare date means through the end of that day
        end = min(end, dt.datetime.now(dt.UTC))
        start = parse(date_from, "date_from") if date_from else end - dt.timedelta(days=7)
        if start >= end:
            raise BadRequest("date_from must be before date_to")
        if end - start > MAX_WINDOW:
            raise BadRequest("The date range may not exceed 31 days")
        return start, end

    def agent_metrics(self, agent_id: str, date_from: str | None, date_to: str | None) -> AgentMetrics:
        entry = self.agent(agent_id)
        start, end = self.window(date_from, date_to)
        if not entry.runtime_arn or entry.access_cell is None:
            return observability_mapper.agent_metrics(
                {}, "m", start, end, warnings=["This agent has no runtime in a configured cell."]
            )
        cell, arn = entry.access_cell, entry.runtime_arn
        warnings: list[str] = []
        series: dict[str, dict[str, float]] = {}
        try:
            series = cloudwatch.get_metric_data(
                self.clients.cell(cell, "cloudwatch"),
                cloudwatch.runtime_metric_queries(arn, "m", 86400),
                *_day_bounds(start, end),
            )
        except logs.UnsafeQueryValue:
            raise
        except Exception as exc:  # noqa: BLE001 - reported as a warning
            logger.warning("Runtime metrics could not be read: %s", error_code(exc))
            warnings.append(f"Runtime metrics could not be read ({error_code(exc)}).")
        results, query_warnings = logs.run_queries(
            self.clients.cell(cell, "logs"),
            {
                "tokens_by_day": logs.tokens_by_day_query(arn),
                "tokens_by_model": logs.tokens_by_model_query(arn),
                "traces_by_user": logs.traces_by_user_query(arn),
            },
            int(start.timestamp()),
            int(end.timestamp()),
        )
        return observability_mapper.agent_metrics(
            series,
            "m",
            start,
            end,
            token_days=results["tokens_by_day"],
            token_models=results["tokens_by_model"],
            user_rows=results["traces_by_user"],
            warnings=warnings + query_warnings,
        )

    def scope_metrics(self, date_from: str | None, date_to: str | None) -> ScopeMetrics:
        """Fleet metrics: one GetMetricData call and one spans query per cell account."""
        start, end = self.window(date_from, date_to)
        by_scope: dict[tuple[Any, ...], list[AgentEntry]] = {}
        for entry in self.agents():
            if entry.runtime_arn and entry.access_cell is not None:
                by_scope.setdefault(entry.access_cell.scope, []).append(entry)

        def load(entries: list[AgentEntry]) -> tuple[list[AgentMetrics], list[str]]:
            cell = entries[0].access_cell
            if cell is None:
                return [], []
            queries: list[dict[str, Any]] = []
            for index, entry in enumerate(entries):
                queries.extend(cloudwatch.runtime_metric_queries(entry.runtime_arn or "", f"r{index}", 86400))
            series = cloudwatch.get_metric_data(
                self.clients.cell(cell, "cloudwatch"), queries, *_day_bounds(start, end)
            )
            results, warnings = logs.run_queries(
                self.clients.cell(cell, "logs"),
                {"tokens_by_runtime": logs.TOKENS_BY_RUNTIME_QUERY},
                int(start.timestamp()),
                int(end.timestamp()),
                max_wait_seconds=8.0,
            )
            metrics = []
            for index, entry in enumerate(entries):
                item = observability_mapper.agent_metrics(series, f"r{index}", start, end)
                prefix = f"{entry.runtime_arn}/"
                item.totals.tokens = sum(
                    int(float(row.get("tokens") or 0))
                    for row in results["tokens_by_runtime"]
                    if (row.get("resource_id") or "").startswith(prefix)
                )
                metrics.append(item)
            return metrics, warnings

        result = ScopeMetrics()
        daily: dict[str, Any] = {}
        groups = list(by_scope.values())
        for entries, loaded in zip(groups, pmap(load, groups), strict=True):
            if isinstance(loaded, logs.UnsafeQueryValue):
                raise loaded
            if isinstance(loaded, BaseException):
                logger.warning("Fleet metrics could not be read for one cell account: %s", error_code(loaded))
                result.warnings.append(f"Metrics could not be read for one cell account ({error_code(loaded)}).")
                continue
            metrics, warnings = loaded
            result.warnings.extend(warnings)
            for entry, item in zip(entries, metrics, strict=True):
                result.by_agent.append(
                    AgentMetricRow(
                        agent_id=entry.agent.id,
                        agent_name=entry.agent.name,
                        tenant_id=entry.agent.tenant_id,
                        totals=MetricTotals(traces=item.totals.traces, tokens=item.totals.tokens),
                    )
                )
                result.totals.traces += item.totals.traces
                result.totals.tokens += item.totals.tokens
                for field_name in ("invocations", "system_errors", "user_errors", "throttles"):
                    setattr(
                        result.runtime,
                        field_name,
                        getattr(result.runtime, field_name) + getattr(item.runtime, field_name),
                    )
                for day in item.daily:
                    if day.date in daily:
                        daily[day.date].traces += day.traces
                        daily[day.date].errors += day.errors
                    else:
                        daily[day.date] = day.model_copy()
        result.daily = [daily[key] for key in sorted(daily)]
        result.by_agent.sort(key=lambda row: row.totals.traces, reverse=True)
        return result

    # --- release evidence ----------------------------------------------------

    def eval_runs(self, agent_id: str) -> EvalRuns:
        entry = self.agent(agent_id)
        cell = entry.cell
        if cell is None:
            return EvalRuns(warnings=["This agent does not belong to a configured cell, so it has no pipeline."])
        if not cell.pipeline_name:
            return EvalRuns(warnings=["No pipeline name is configured for this agent's cell."])
        pipeline_name = cell.pipeline_name

        def load() -> list[dict[str, Any]]:
            client = self.clients.platform("codepipeline", self.settings.registry_region)
            return pipelines.recent_executions(client, pipeline_name)

        items = self._cached(("pipeline-executions", pipeline_name), load)
        return release_mapper.eval_runs(entry.agent.id, cell.environment, pipeline_name, items)

    # --- MCP servers (Tool Gateways) ----------------------------------------

    def gateways(self) -> list[GatewayEntry]:
        return self.inventory().gateways

    def gateway(self, gateway_id: str) -> GatewayEntry:
        for entry in self.inventory().gateways:
            if entry.server.id == gateway_id:
                return entry
        raise NotFound("MCP server not found")

    def policies(self, gateway_id: str) -> CedarPolicySet:
        entry = self.gateway(gateway_id)
        engine = arn_parts(entry.policy_engine_arn)
        if not engine:
            return mcp_mapper.policy_set(entry, [])
        if (engine["account"], engine["region"]) != (entry.cell.account_id, entry.cell.region):
            return mcp_mapper.policy_set(
                entry, [], ["The policy engine is outside this gateway's cell, so its policies are not shown."]
            )
        engine_id = engine["resource_id"]
        cell = entry.cell

        def load() -> list[dict[str, Any]]:
            return agentcore.list_policies(self.clients.cell(cell, "bedrock-agentcore-control"), engine_id)

        return mcp_mapper.policy_set(entry, self._cached(("policies", cell.scope, engine_id), load))

    def mcp_grants(self, gateway_id: str) -> list[Grant]:
        self.gateway(gateway_id)
        return graph_mapper.mcp_grants(gateway_id, self.agents())

    # --- governance graph ----------------------------------------------------

    def graph(self) -> GovernanceGraph:
        inventory = self.inventory()
        return graph_mapper.build_graph(inventory.agents, inventory.gateways)

    def principal(self, principal_id: str) -> PrincipalDetail:
        detail = graph_mapper.owner_group_detail(principal_id, self.agents())
        if detail is None:
            raise NotFound("Principal not found")
        return detail

    # --- guardrails ----------------------------------------------------------

    def _guardrail_summaries(self) -> list[dict[str, Any]]:
        def load() -> list[dict[str, Any]]:
            client = self.clients.platform("bedrock", self.settings.registry_region)
            return guardrails.list_tagged(client, self.settings.guardrail_tag_key, self.settings.guardrail_tag_value)

        return self._cached("guardrails", load)

    def guardrails(self, status: str | None = None) -> list[GuardrailTemplate]:
        templates = [guardrail_mapper.from_summary(s) for s in self._guardrail_summaries()]
        if status:
            templates = [t for t in templates if t.status == status]
        return sorted(templates, key=lambda t: t.name.lower())

    def guardrail(self, guardrail_id: str) -> GuardrailTemplate:
        if not any(s["id"] == guardrail_id for s in self._guardrail_summaries()):
            raise NotFound("Guardrail not found")

        def load() -> dict[str, Any]:
            return guardrails.get(self.clients.platform("bedrock", self.settings.registry_region), guardrail_id)

        return guardrail_mapper.from_detail(self._cached(("guardrail", guardrail_id), load))

    # --- fleet health --------------------------------------------------------

    def fleet_health(self) -> FleetHealth:
        return self._cached("fleet-health", self._load_fleet_health)

    def fleet_health_with_agents(self) -> FleetHealth:
        """Fleet health with each cell's ``agent_ref`` filled in when the inventory can be read.

        Best effort: health is still returned if the registry or a cell cannot be read.
        """
        fleet = self.fleet_health().model_copy(deep=True)
        try:
            refs = {entry.cell.key: entry.agent.id for entry in reversed(self.agents()) if entry.cell is not None}
        except Exception as exc:  # noqa: BLE001 - enrichment only
            logger.warning("Agents could not be read for fleet health links: %s", error_code(exc))
            return fleet
        for cell in fleet.cells:
            cell.agent_ref = refs.get(f"{cell.tenant_id}/{cell.agent_id}/{cell.environment}")
        return fleet

    def _load_fleet_health(self) -> FleetHealth:
        now = dt.datetime.now(dt.UTC)
        since = now - dt.timedelta(hours=24)

        def check(cell: Cell) -> Any:
            client = self.clients.cell(cell, "cloudwatch")
            alarms = cloudwatch.describe_alarms(client, cell.effective_alarm_prefix)
            states = [str(alarm.get("StateValue")) for alarm in alarms]
            entered = False
            if health_mapper.ALARM not in states:
                # Only an alarm whose state changed inside the window can have been in ALARM in it.
                recent = [
                    alarm
                    for alarm in alarms
                    if (changed := alarm.get("StateTransitionedTimestamp") or alarm.get("StateUpdatedTimestamp"))
                    and changed >= since
                ]
                for alarm in recent[:MAX_HISTORY_CHECKS_PER_CELL]:
                    if cloudwatch.entered_alarm_since(client, alarm["AlarmName"], since, now):
                        entered = True
                        break
            return health_mapper.cell_health(cell, states, entered)

        cells = list(self.settings.cells)
        results = []
        for cell, result in zip(cells, pmap(check, cells), strict=True):
            if isinstance(result, BaseException):
                code = error_code(result)
                logger.warning("Cell %s could not be checked: %s", cell.key, code)
                results.append(health_mapper.unreachable(cell, f"Cell could not be read ({code})."))
            else:
                results.append(result)
        return health_mapper.fleet(now_iso(), results)

    # --- registrations -------------------------------------------------------

    def registrations(self, status: str | None = None, tenant_id: str | None = None) -> list[Registration]:
        """Agent governance records, read fresh so the list reflects an action that just completed."""
        result = []
        for record in registry.list_records(self._registry_client(), self.settings.effective_agent_registry_id):
            document = registration_helpers.agent_document(record)
            if document is None:
                continue
            item = registration_helpers.to_registration(record, document)
            if status and item.status != status:
                continue
            if tenant_id and item.tenant_id != tenant_id:
                continue
            result.append(item)
        return sorted(result, key=lambda r: (r.updated_at or "", r.name), reverse=True)

    def registration(self, record_id: str, caller_subject: str) -> RegistrationDetail:
        """One agent governance record, with who created, submitted and decided it."""
        try:
            record = self._registry_client().get_registry_record(
                registryId=self.settings.effective_agent_registry_id, recordId=record_id
            )
        except ClientError as exc:
            if error_code(exc) == "ResourceNotFoundException":
                raise NotFound("Registration not found") from exc
            raise
        document = registration_helpers.agent_document(record)
        if document is None:
            raise NotFound("Registration not found")
        detail = RegistrationDetail(**registration_helpers.to_registration(record, document).model_dump())
        if not self.settings.audit_table:
            return detail
        dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
        items = audit_reader.query_items(dynamodb, self.settings.audit_table, audit_reader.record_key(record_id))
        events = [audit_reader.from_item(item) for item in items]
        approved = audit_reader.last_approved_document(items)
        if approved:
            detail.previous_approved = registration_helpers.snake_document(approved)
        done = [e for e in events if e.phase == "result" and e.outcome == "allowed"]  # newest first
        created = next((e for e in reversed(done) if e.action == "create"), None)
        if created:
            detail.created_by, detail.created_by_label = created.actor_subject, created.actor_label
        if detail.status in ("PENDING_APPROVAL", "APPROVED", "REJECTED"):
            submitted = audit_reader.submitter(events)
            if submitted:
                detail.submitted_by, detail.submitted_by_label = submitted.actor_subject, submitted.actor_label
                detail.submitted_at = submitted.at
                detail.submitted_by_me = submitted.actor_subject == caller_subject
        if detail.status in ("APPROVED", "REJECTED"):
            decided = next((e for e in done if e.action in ("approve", "reject")), None)
            if decided:
                detail.decision, detail.decided_by_label = decided.action, decided.actor_label
                detail.decided_at, detail.decision_reason = decided.at, decided.reason
        return detail

    def registration_history(self, record_id: str) -> RegistrationHistory:
        """The audit trail of one record, newest first. Works for a deleted record too."""
        table = self.settings.audit_table
        if not table:
            raise ConfigError("PORTAL_AUDIT_TABLE is not set")
        dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
        events = audit_reader.query_events(dynamodb, table, audit_reader.record_key(record_id))
        # Decisions taken before the record had an id (its creation) are filed under its name.
        names = {event.record_name for event in events if event.record_name}
        for name in sorted(names):
            events.extend(
                event
                for event in audit_reader.query_events(dynamodb, table, audit_reader.name_key(name))
                if event.record_id in (None, record_id)
            )
        if not events:
            raise NotFound("No history for this registration")
        events.sort(key=lambda e: (e.at, e.event_id), reverse=True)
        return RegistrationHistory(record_id=record_id, events=events)

    # --- catalogue -----------------------------------------------------------

    def catalog_models(self) -> list[CatalogModel]:
        return [
            CatalogModel(model_id=m.model_id, provider=m.provider, regions=list(m.regions), status=m.status)
            for m in self.settings.model_allowlist
        ]

    def catalog_tools(self) -> list[CatalogTool]:
        tools = [registry_mapper.catalog_tool(r) for r in registry_mapper.tool_records(self.records())]
        return sorted(tools, key=lambda t: t.tool_id)
