# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Read-only orchestration: AWS reads, merged and mapped for the routes.

Nothing in this module (or anything it calls) creates, updates or deletes an
AWS resource. Workstream cells are changed only by their pipelines.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field, replace
from typing import Any

from botocore.exceptions import ClientError

from portal_api import registrations as registration_helpers
from portal_api import risk
from portal_api.aws import agentcore, cloudwatch, guardrails, logs, omni, pipelines, registry
from portal_api.aws import audit as audit_reader
from portal_api.aws.cache import TTLCache
from portal_api.aws.parallel import pmap
from portal_api.aws.session import AwsClients, error_code
from portal_api.config import Cell, ConfigError, Settings
from portal_api.mappers import agents as agent_mapper
from portal_api.mappers import discovery as discovery_mapper
from portal_api.mappers import graph as graph_mapper
from portal_api.mappers import guardrails as guardrail_mapper
from portal_api.mappers import health as health_mapper
from portal_api.mappers import mcp as mcp_mapper
from portal_api.mappers import observability as observability_mapper
from portal_api.mappers import omni as omni_mapper
from portal_api.mappers import registry as registry_mapper
from portal_api.mappers import release as release_mapper
from portal_api.mappers.agents import AgentEntry, Runtime
from portal_api.mappers.common import arn_parts, arn_resource_id, now_iso
from portal_api.mappers.mcp import GatewayEntry
from portal_api.models.portal import (
    AgentAttention,
    CatalogModel,
    CatalogTool,
    ContainmentView,
    FleetHealth,
    FleetSummary,
    ObservedServices,
    OmniDomain,
    Registration,
    RegistrationDetail,
    RegistrationHistory,
)
from portal_api.models.wire import (
    AgentMcpGrant,
    AgentMetricRow,
    AgentMetrics,
    AgentRisk,
    CedarPolicySet,
    Deployment,
    EvalRuns,
    GovernanceGraph,
    Grant,
    GuardrailTemplate,
    MetricTotals,
    PrincipalDetail,
    RiskReason,
    RuntimeStatus,
    ScopeMetrics,
    TracePage,
)

logger = logging.getLogger(__name__)

MAX_HISTORY_CHECKS_PER_CELL = 25
FLAG_NAMES = ("unmanaged", "ownerless", "review_overdue", "inactive", "contained")
NO_RUNTIME = "This agent has no Runtime."
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
    # "disabled" (no discovery registry configured), "ok", or the error code when it could not be read.
    discovery: str = "disabled"

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

        def discover(
            cells: list[Cell],
        ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str | None] | None]:
            client = self.clients.cell(cells[0], "bedrock-agentcore-control")
            runtime_bundles, gateway_bundles = agentcore.list_runtimes(client), agentcore.list_gateways(client)
            # One metric request per cell account for all of its Runtimes, never one per agent.
            activity: dict[str, str | None] | None = None
            try:
                activity = cloudwatch.runtime_activity(
                    self.clients.cell(cells[0], "cloudwatch"),
                    [bundle["summary"]["agentRuntimeArn"] for bundle in runtime_bundles],
                    self.settings.inactive_days,
                )
            except Exception as exc:  # noqa: BLE001 - activity is then unknown, not an error
                logger.warning("Runtime activity could not be read: %s", error_code(exc))
            return runtime_bundles, gateway_bundles, activity

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
            runtime_bundles, gateway_bundles, activity = result
            for bundle in runtime_bundles:
                matched = _cell_for_tags(cells, bundle.get("tags") or {})
                runtime = agent_mapper.runtime_from_bundle(bundle, matched or cells[0])
                if activity is not None and runtime.arn in activity:
                    runtime = replace(runtime, activity_known=True, last_invoked_on=activity[runtime.arn])
                runtimes[runtime.arn] = runtime
                runtime_cells[runtime.arn] = matched
            for bundle in gateway_bundles:
                matched = _cell_for_tags(cells, bundle.get("tags") or {})
                inventory.gateways.append(mcp_mapper.gateway_entry(bundle, matched or cells[0], tool_index))

        # The organization-scoped discovery registry: a Runtime seen by both sources is one agent.
        gateway_arns: set[str] = set()
        for detection in self._detections(inventory, set(runtimes)):
            if detection.kind == "gateway":
                gateway_arns.add(detection.arn)
            elif detection.arn in runtimes:
                runtimes[detection.arn] = agent_mapper.with_source(
                    runtimes[detection.arn], agent_mapper.SOURCE_ORGANIZATION_REGISTRY, detection.authorizer_type
                )
            else:
                runtimes[detection.arn] = agent_mapper.runtime_from_detection(detection)
                runtime_cells[detection.arn] = None
        for gateway in inventory.gateways:
            gateway.server.detection_sources = sorted(
                {agent_mapper.SOURCE_CELL_READER}
                | ({agent_mapper.SOURCE_ORGANIZATION_REGISTRY} if gateway.arn in gateway_arns else set())
            )

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
        self._assess(inventory)
        return inventory

    def _cell_states(self) -> dict[str, str]:
        """Fleet-health state per cell key, for the cells that could be read."""
        try:
            fleet = self.fleet_health()
        except Exception as exc:  # noqa: BLE001 - health is then unknown for every agent
            logger.warning("Fleet health could not be read for risk: %s", error_code(exc))
            return {}
        return {f"{c.tenant_id}/{c.agent_id}/{c.environment}": c.state for c in fleet.cells if c.reachable}

    def _assess(self, inventory: Inventory) -> None:
        """Set every agent's flags and risk from the facts gathered for the inventory."""
        gateways = inventory.gateway_index()
        cell_states = self._cell_states()
        today = dt.datetime.now(dt.UTC).date().isoformat()
        aliases = {c.account_id: c.account_alias for c in self.settings.cells if c.account_alias}
        roster = self.settings.owner_groups
        for entry in inventory.agents:
            agent, runtime, governance = entry.agent, entry.runtime, entry.agent.governance
            registered = agent.registration == "registered"
            omni_cell = entry.cell or entry.access_cell
            agent.omni_url = omni_cell.omni_domain_url if omni_cell else None
            agent.account_alias = aliases.get(agent.account_id or "")
            if entry.access_cell is None:
                agent.reader_status = "none"
            else:
                agent.reader_status = "unreachable" if entry.access_cell.scope in inventory.unreachable else "ok"
            flags = agent.flags
            flags.unmanaged = not (registered and agent.lifecycle_state == "approved")
            # The accountable owner of an agent is its owner group. Sponsor and contact are optional
            # and only produce a low nudge when both are absent.
            group_missing: bool | None = None
            group_in_roster: bool | None = None
            sponsor_missing: bool | None = None
            if registered and governance is not None:
                owner_group = (governance.owner_group or "").strip()
                group_missing = not owner_group
                if roster is not None and not group_missing:
                    group_in_roster = owner_group in roster
                flags.ownerless = group_missing or group_in_roster is False
                sponsor_missing = not governance.sponsor and not governance.contact
                flags.review_overdue = bool(governance.review_by and governance.review_by < today)
            if runtime is not None:
                flags.contained = runtime.contained
                if runtime.activity_known:
                    flags.inactive = runtime.last_invoked_on is None
                    agent.last_invoked_on = runtime.last_invoked_on

            modes = [gateways[link.gateway_id].enforcement_mode for link in entry.links if link.gateway_id in gateways]
            verdict = (governance.evaluation or {}).get("verdict") if governance else None
            facts = risk.RiskFacts(
                risk_class=governance.risk_class if governance else None,
                data_classification=governance.data_classification if governance else None,
                registered=registered,
                registry_status=(agent.registry_status or "").upper() or None if registered else None,
                runtime_known=runtime is not None,
                owner_group_missing=group_missing,
                owner_group_in_roster=group_in_roster,
                sponsor_missing=sponsor_missing,
                review_overdue=flags.review_overdue,
                inactive=flags.inactive,
                gateway_policy_mode=risk.weakest_policy_mode(modes),
                guardrail_configured=runtime.guardrail_configured if runtime else None,
                authorizer_type=runtime.authorizer_type if runtime else None,
                # A registered agent with no recorded verdict has not been evaluated.
                evaluation_verdict=verdict or ("not_run" if registered else None),
                cell_health_state=cell_states.get(entry.cell.key) if entry.cell else None,
            )
            assessed = risk.assess(facts)
            agent.risk = AgentRisk(
                level=assessed.level,
                reasons=[RiskReason(code=r.code, severity=r.severity, detail=r.detail) for r in assessed.reasons],
            )

    def _detections(self, inventory: Inventory, known_runtime_arns: set[str]) -> list[discovery_mapper.Detection]:
        """What the discovery registry detected. Its absence or failure never fails the inventory."""
        registry_id = self.settings.discovery_registry_id
        if not registry_id:
            return []
        try:
            client = self._registry_client()
            summaries = registry.list_summaries(client, registry_id)
            found = discovery_mapper.detections(summaries)
            # Summaries name the source. The authorizer of a Runtime that no cell reader saw is in
            # the full record, so only those are fetched.
            wanted = [
                d.record_id
                for d in found
                if d.kind == "runtime" and d.arn not in known_runtime_arns and d.record_id and d.authorizer_type is None
            ]
            if wanted:
                detailed = {
                    d.arn: d
                    for d in discovery_mapper.detections(
                        list(registry.get_records(client, registry_id, wanted).values())
                    )
                }
                found = [detailed.get(d.arn, d) for d in found]
            inventory.discovery = "ok"
            return found
        except Exception as exc:  # noqa: BLE001 - the cell readers still cover the configured cells
            inventory.discovery = error_code(exc)
            logger.warning("Discovery registry could not be read: %s", inventory.discovery)
            return []

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

    def containment_view(self, agent_id: str, caller_subject: str) -> ContainmentView:
        """Whether the agent's Runtime is contained (read fresh through the cell reader), by whom, and the events."""
        entry = self.agent(agent_id)
        cell = entry.access_cell
        view = ContainmentView(
            agent_id=entry.agent.id,
            state="unknown",
            runtime_arn=entry.runtime_arn,
            enabled=bool(
                entry.runtime_arn
                and any(
                    c.containment_role_arn
                    for c in self.settings.cells
                    if (c.account_id, c.region) == (entry.agent.account_id, entry.agent.region)
                )
            ),
        )
        if not entry.runtime_arn:
            view.detail = NO_RUNTIME
        elif cell is None:
            view.detail = agent_mapper.NO_READER.format(what="its containment state")
        else:
            state = agentcore.contained(self.clients.cell(cell, "bedrock-agentcore-control"), entry.runtime_arn)
            view.state = "unknown" if state is None else ("contained" if state else "not_contained")
            if state is None:
                view.detail = "The Runtime's resource policy could not be read."
        if self.settings.audit_table:
            dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
            view.events = audit_reader.query_events(
                dynamodb, self.settings.audit_table, audit_reader.containment_key(entry.agent.id)
            )
            holder = audit_reader.container(view.events)
            if holder is not None and view.state != "not_contained":
                view.contained_by, view.contained_by_label = holder.actor_subject, holder.actor_label
                view.contained_at, view.reason = holder.at, holder.reason
                view.contained_by_me = holder.actor_subject == caller_subject
                result = next(
                    (e for e in view.events if e.request_id == holder.request_id and e.phase == "result"), None
                )
                # Partial: sessions were left running, or their discovery was not clean.
                view.partial = result is None or bool(result.sessions_failed) or result.detail not in (None, "ok")
        return view

    # --- traces and metrics --------------------------------------------------

    def traces(self, agent_id: str, page: int, limit: int, hours: int) -> TracePage:
        entry = self.agent(agent_id)
        if not entry.runtime_arn:
            return TracePage(warnings=[NO_RUNTIME])
        if entry.access_cell is None:
            return TracePage(warnings=[agent_mapper.NO_READER.format(what="its traces")])
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
            why = NO_RUNTIME if not entry.runtime_arn else agent_mapper.NO_READER.format(what="its metrics")
            return observability_mapper.agent_metrics({}, "m", start, end, warnings=[why])
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

    # --- fleet summary and export --------------------------------------------

    def fleet_summary(self) -> FleetSummary:
        inventory = self.inventory()
        summary = FleetSummary(
            generated_at=now_iso(),
            agents_total=len(inventory.agents),
            by_inventory_state=dict.fromkeys(
                (agent_mapper.REGISTERED_AND_DETECTED, agent_mapper.REGISTERED_ONLY, agent_mapper.DETECTED_ONLY), 0
            ),
            by_risk_level=dict.fromkeys(risk.SEVERITIES, 0),
            flags=dict.fromkeys(FLAG_NAMES, 0),
            flags_unknown=dict.fromkeys(FLAG_NAMES, 0),
            gateways_total=len(inventory.gateways),
            gateways_by_policy_mode=dict.fromkeys(("enforce", "log_only", "none"), 0),
            organization_registry=inventory.discovery,
            unreachable_cells=len(inventory.unreachable),
            inactive_days=self.settings.inactive_days,
        )
        for entry in inventory.agents:
            agent = entry.agent
            summary.by_inventory_state[agent.inventory_state] = (
                summary.by_inventory_state.get(agent.inventory_state, 0) + 1
            )
            summary.by_lifecycle[agent.lifecycle_state] = summary.by_lifecycle.get(agent.lifecycle_state, 0) + 1
            summary.by_risk_level[agent.risk.level] = summary.by_risk_level.get(agent.risk.level, 0) + 1
            for name in FLAG_NAMES:
                value = getattr(agent.flags, name)
                if value is True:
                    summary.flags[name] += 1
                elif value is None:
                    summary.flags_unknown[name] += 1
        for gateway in inventory.gateways:
            mode = gateway.enforcement_mode
            summary.gateways_by_policy_mode[mode] = summary.gateways_by_policy_mode.get(mode, 0) + 1
        seen: set[str] = set()
        for cell in self.settings.cells:
            if cell.omni_domain_url and cell.omni_domain_url not in seen:
                seen.add(cell.omni_domain_url)
                summary.omni_domains.append(
                    OmniDomain(
                        account_alias=cell.account_alias or f"account-{cell.account_id[-4:]}",
                        region=cell.omni_region,
                        url=cell.omni_domain_url,
                    )
                )
        summary.omni_url = summary.omni_domains[0].url if len(summary.omni_domains) == 1 else None
        urgent = [e.agent for e in inventory.agents if e.agent.risk.level in ("critical", "high")]
        urgent.sort(key=lambda a: (-risk.SEVERITIES.index(a.risk.level), -len(a.risk.reasons), a.name.lower(), a.id))
        summary.needs_attention = [
            AgentAttention(
                agent_id=agent.id,
                name=agent.name,
                risk_level=agent.risk.level,
                flags=[name for name in FLAG_NAMES if getattr(agent.flags, name) is True],
                reasons=[reason.model_dump() for reason in agent.risk.reasons],
            )
            for agent in urgent[:20]
        ]
        if inventory.unreachable:
            summary.warnings.append(f"{len(inventory.unreachable)} cell account(s) could not be read.")
        if inventory.discovery not in ("ok", "disabled"):
            summary.warnings.append(f"The organization registry could not be read ({inventory.discovery}).")
        return summary

    # --- CloudWatch Omni hand-off ------------------------------------------------

    def observed_services(self, cell_key: str | None, own_account_id: str | None, hours: int) -> ObservedServices:
        """Agents the Omni Context Graph observes in telemetry, for the cells in the portal's own account.

        The graph is read with the function's own role (a same-account SigV4
        call needs only the IAM action, no Omni access grant). An Omni domain
        sees its own Region, so what it reports can be an agent that is
        neither registered nor detected: ``inventory_state`` is then
        ``observed_only``. Cells in other accounts are skipped with a warning.
        """
        end = dt.datetime.now(dt.UTC)
        start = end - dt.timedelta(hours=hours)
        result = ObservedServices(checked_at=now_iso(), window_hours=hours)
        cells = list(self.settings.cells)
        if cell_key:
            cells = [c for c in cells if c.key == cell_key or c.key.rsplit("/", 1)[0] == cell_key]
            if not cells:
                raise NotFound("Cell not found")
        known = {
            entry.runtime_arn: omni_mapper.KnownAgent(
                agent_id=entry.agent.id,
                registered=entry.agent.registration == "registered",
                detected=entry.runtime is not None,
                inventory_state=entry.agent.inventory_state,
            )
            for entry in self.inventory().agents
            if entry.runtime_arn
        }
        by_account: dict[str, list[Cell]] = {}
        for cell in cells:
            by_account.setdefault(cell.account_id, []).append(cell)
        for account_id, account_cells in by_account.items():
            alias = next((c.account_alias for c in account_cells if c.account_alias), f"account-{account_id[-4:]}")
            if own_account_id is None or account_id != own_account_id:
                result.warnings.append(f"{alias}: skipped, Omni is read only in the portal's own account.")
                continue
            regions = list(dict.fromkeys(c.omni_region for c in account_cells if c.omni_region))
            if not regions:
                result.warnings.append(f"{alias}: no Omni Region is configured for this account's cells.")
                continue
            for region in regions:
                url = next(
                    (c.omni_domain_url for c in account_cells if c.omni_region == region and c.omni_domain_url), None
                )
                domain = OmniDomain(account_alias=alias, region=region, url=url)
                try:
                    client = self.clients.platform("cloudwatchomni", region)
                    found, truncated = omni.agent_nodes(client, account_id, start, end)
                except Exception as exc:  # noqa: BLE001 - reported per account, never fatal
                    logger.warning("Omni Context Graph could not be read: %s", error_code(exc))
                    result.warnings.append(
                        f"{alias}: the Omni Context Graph in {region} could not be read ({error_code(exc)})."
                    )
                    continue
                result.domains.append(domain)
                result.omni_url = result.omni_url or url
                result.services.extend(omni_mapper.observed_services(found, known, domain))
                if truncated:
                    result.warnings.append(f"{alias}: only the first {omni.MAX_NODES} agents in {region} are listed.")
        result.services.sort(key=lambda s: (s.last_observed_at or "", s.name), reverse=True)
        return result

    def export_rows(self) -> list[dict[str, Any]]:
        """One row per agent, for the inventory export. No raw account id outside an ARN."""
        rows = []
        for entry in self.agents():
            agent, governance = entry.agent, entry.agent.governance
            cell = entry.cell or entry.access_cell
            if cell is not None and cell.account_alias:
                alias = cell.account_alias
            else:
                alias = f"account-{agent.account_id[-4:]}" if agent.account_id else ""
            rows.append(
                {
                    "agent_id": agent.id,
                    "name": agent.name,
                    "record_name": agent.record_name,
                    "tenant_id": agent.tenant_id,
                    "environment": agent.environment,
                    "owner_group": governance.owner_group if governance else None,
                    "sponsor": governance.sponsor if governance else None,
                    "contact": governance.contact if governance else None,
                    "risk_class": governance.risk_class if governance else None,
                    "data_classification": governance.data_classification if governance else None,
                    "inventory_state": agent.inventory_state,
                    "detection_sources": list(agent.detection_sources),
                    "lifecycle_state": agent.lifecycle_state,
                    **{name: getattr(agent.flags, name) for name in FLAG_NAMES},
                    "risk_level": agent.risk.level,
                    "risk_reasons": [reason.code for reason in agent.risk.reasons],
                    "runtime_arn": agent.agent_arn,
                    "account_alias": alias,
                    "region": agent.region,
                    "updated_at": agent.updated_at,
                }
            )
        return rows

    # --- catalogue -----------------------------------------------------------

    def catalog_models(self) -> list[CatalogModel]:
        return [
            CatalogModel(model_id=m.model_id, provider=m.provider, regions=list(m.regions), status=m.status)
            for m in self.settings.model_allowlist
        ]

    def catalog_tools(self) -> list[CatalogTool]:
        tools = [registry_mapper.catalog_tool(r) for r in registry_mapper.tool_records(self.records())]
        return sorted(tools, key=lambda t: t.tool_id)
