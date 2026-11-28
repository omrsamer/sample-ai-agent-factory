# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Read-only orchestration: AWS reads, merged and mapped for the routes.

Nothing in this module (or anything it calls) creates, updates or deletes an
AWS resource. Workstream cells are changed only by their pipelines.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any

from botocore.exceptions import ClientError

from portal_api import arns, authorities, containment_policy, containment_timing, reviews, risk, sweeps
from portal_api import evidence as evidence_builder
from portal_api import registrations as registration_helpers
from portal_api.aws import agentcore, cloudwatch, guardrails, logs, omni, pipelines, registry
from portal_api.aws import audit as audit_reader
from portal_api.aws.cache import TTLCache
from portal_api.aws.parallel import pmap
from portal_api.aws.session import SESSION_READER, AwsClients, error_code
from portal_api.config import Cell, ConfigError, Settings
from portal_api.identity.provider import Principal
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
from portal_api.mappers.common import arn_parts, arn_resource_id, now_iso, now_precise, parse_instant
from portal_api.mappers.mcp import GatewayEntry
from portal_api.models.evidence import AgentEvidence
from portal_api.models.portal import (
    AgentAttention,
    AuditEvent,
    CatalogModel,
    CatalogTool,
    ContainmentSweeps,
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
# The portal reads a Runtime's policy and its containment history only under the ARN it builds
# itself from the cell's configuration. A registration can spell the same Runtime another way.
NOT_CANONICAL = (
    "The registration names its Runtime by an ARN whose partition is not the one of the Runtime's cell, "
    "so its containment state was not read."
)
HOLDER_NOT_FOUND = (
    f"Who contained the agent could not be established: the Runtime's history holds more than "
    f"{audit_reader.MAX_DECISION_EVENTS} events since its last contain or release."
)
OLDER_EVENTS = "The {what} holds more events than the {limit} newest, which are the ones listed here."
MAX_WINDOW = dt.timedelta(days=31)
# The evidence document and the single-agent read load the inventory again when a decision about
# the agent is newer than the cached one. Loading it reads every cell, so between them they do it
# no more often than this in one execution environment.
DECISION_RELOAD_SECONDS = 15.0
# How many of a history's newest events the single-agent read looks at to tell whether something
# was decided since the inventory was assessed, in one request. The newest event alone would not
# say: a refusal, an intent or a background sweep can have followed the decision.
DECISION_CHECK_EVENTS = 20


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
    # Review attestations by record id, newest first, and how reading them went: "disabled" (no
    # audit table configured), "ok", or the error code when they could not be read.
    attestations: dict[str, list[reviews.Attestation]] = field(default_factory=dict)
    review_attestations: str = "disabled"
    attestations_truncated: bool = False
    # The moment this inventory describes, to the microsecond: taken before anything was read for
    # it. What the audit trail recorded before it is reflected in the agents' registration,
    # reviews, flags and risk; an event later than it may not be.
    assessed_at: str = ""

    def gateway_index(self) -> dict[str, GatewayEntry]:
        """The gateways by id. A gateway that a reader read is never replaced by one that was only detected."""
        index: dict[str, GatewayEntry] = {}
        for gateway in self.gateways:
            current = index.get(gateway.server.id)
            if current is None or (gateway.read and not current.read):
                index[gateway.server.id] = gateway
        return index


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
    def __init__(
        self,
        settings: Settings,
        clients: AwsClients | None = None,
        cache: TTLCache | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.clients = clients or AwsClients(home_region=settings.registry_region, session_name=SESSION_READER)
        self.cache = cache or TTLCache()
        # Cache keys that are being loaded again whatever is cached (see ``_reading_afresh``).
        self._afresh: frozenset[Any] = frozenset()
        self._clock = clock
        # When a decision last made a request load the inventory again (see ``_may_reload``).
        self._reloaded_at: float | None = None

    # --- cached reads --------------------------------------------------------

    def _cached(self, key: Any, loader: Any) -> Any:
        return self.cache.get_or_load(key, self.settings.cache_ttl_seconds, loader, refresh=key in self._afresh)

    @contextmanager
    def _reading_afresh(self, *keys: Any) -> Iterator[None]:
        """Inside this block these cache keys are loaded again and the new values replace the cached ones."""
        before = self._afresh
        self._afresh = before | frozenset(keys)
        try:
            yield
        finally:
            self._afresh = before

    def _registry_keys(self) -> tuple[Any, ...]:
        return (
            ("registry-records", self.settings.registry_id),
            ("registry-records", self.settings.effective_agent_registry_id),
        )

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
        # Taken before anything is read, and the registry is read now and not from the cache: so
        # whatever was decided before this moment is in the inventory, and an event later than it
        # may not be. The evidence document relies on that.
        assessed_at = now_precise()
        with self._reading_afresh(*self._registry_keys()):
            records = self.records()
            # One registry can hold both kinds of record: it is then read once, not twice.
            separate = self.settings.effective_agent_registry_id != self.settings.registry_id
            agent_registry_records = self.agent_registry_records() if separate else records
        tool_index = registry_mapper.tool_index(records)
        agent_records = registry_mapper.agent_records(agent_registry_records)
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

        inventory = Inventory(assessed_at=assessed_at)
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

        # The organization-scoped discovery registry: a Runtime seen by both sources is one agent,
        # and a gateway seen by both is one gateway. A gateway that only the registry detected is
        # listed too, with what the detection says and nothing more.
        gateway_arns: set[str] = set()
        read_gateway_arns = {gateway.arn for gateway in inventory.gateways}
        # Ids already listed. A detection is keyed by an ARN that whoever registered it wrote: one
        # that carries the id of a listed gateway under another ARN must not take its place, in
        # the list or under ``/mcp-servers/{id}``. What a reader read stands.
        listed_gateway_ids = {gateway.server.id for gateway in inventory.gateways}
        for detection in self._detections(inventory, set(runtimes), read_gateway_arns):
            if detection.kind == "gateway":
                gateway_arns.add(detection.arn)
                gateway_id = arn_resource_id(detection.arn) or detection.arn
                if detection.arn not in read_gateway_arns and gateway_id not in listed_gateway_ids:
                    listed_gateway_ids.add(gateway_id)
                    inventory.gateways.append(
                        mcp_mapper.gateway_from_detection(
                            detection, self._gateway_reader_status(detection.arn, inventory)
                        )
                    )
            elif detection.arn in runtimes:
                runtimes[detection.arn] = agent_mapper.with_source(
                    runtimes[detection.arn], agent_mapper.SOURCE_ORGANIZATION_REGISTRY, detection.authorizer_type
                )
            else:
                runtimes[detection.arn] = agent_mapper.runtime_from_detection(detection)
                runtime_cells[detection.arn] = None
        aliases = {c.account_id: c.account_alias for c in self.settings.cells if c.account_alias}
        for gateway in inventory.gateways:
            gateway.server.account_alias = aliases.get(gateway.server.account_id or "")
            if gateway.read:
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
        self._load_attestations(inventory)
        self._assess(inventory)
        return inventory

    def _load_attestations(self, inventory: Inventory) -> None:
        """The latest review attestation of every record, without a query per agent.

        A failure never fails the inventory. When they cannot be read, each
        agent's review date is its registration's own and the fleet summary
        carries a warning.
        """
        table = self.settings.audit_table
        if not table:
            return
        try:
            dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
            found, inventory.attestations_truncated = audit_reader.query_attestations(dynamodb, table)
        except Exception as exc:  # noqa: BLE001 - the registrations' own dates are used instead
            inventory.review_attestations = error_code(exc)
            logger.warning("Review attestations could not be read: %s", inventory.review_attestations)
            return
        inventory.attestations = reviews.by_record(found)
        inventory.review_attestations = "ok"

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
        today = dt.datetime.now(dt.UTC).date()
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
                # An attestation for a record that no longer exists is never looked up, so it is ignored.
                attested = (inventory.attestations.get(agent.id) or [None])[0]
                agent.review_by = reviews.effective(governance.review_by, attested).review_by
                if attested is not None:
                    agent.last_reviewed_at, agent.last_reviewed_by = attested.at, attested.reviewed_by_label
                retired = (agent.registry_status or "").upper() == "DEPRECATED"
                flags.review_overdue = reviews.overdue(agent.review_by, today, retired=retired)
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
                runtime_reader_unreachable=agent.reader_status == "unreachable",
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
            # A retired registration with nothing deployed: no rule applied (``risk.closed``), and
            # the flags about it do not apply either. That is not "unknown", and the fleet summary
            # counts it as neither.
            agent.obligations_closed = risk.closed(facts)
            if agent.obligations_closed:
                flags.unmanaged = flags.ownerless = flags.review_overdue = flags.inactive = None

    def _gateway_reader_status(self, arn: str, inventory: Inventory) -> str:
        """Why no reader read a detected gateway: no reader there, a reader that failed, or one that did not list it."""
        cell = self._access_cell(arn)
        if cell is None:
            return mcp_mapper.READER_NONE
        return mcp_mapper.READER_UNREACHABLE if cell.scope in inventory.unreachable else mcp_mapper.READER_NOT_LISTED

    def _detections(
        self, inventory: Inventory, known_runtime_arns: set[str], known_gateway_arns: set[str] = frozenset()
    ) -> list[discovery_mapper.Detection]:
        """What the discovery registry detected. Its absence or failure never fails the inventory."""
        registry_id = self.settings.discovery_registry_id
        if not registry_id:
            return []
        try:
            client = self._registry_client()
            summaries = registry.list_summaries(client, registry_id)
            found = discovery_mapper.detections(summaries)
            # Summaries name the source. The authorizer (and, for a gateway, the protocol) of a
            # resource that no cell reader saw is in the full record, so only those are fetched.
            known = {"runtime": known_runtime_arns, "gateway": known_gateway_arns}
            wanted = [
                d.record_id for d in found if d.arn not in known[d.kind] and d.record_id and d.authorizer_type is None
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

    def agent_current(self, agent_id: str) -> AgentEntry:
        """The agent for its own page: as the inventory has it, unless something was decided about it since.

        The list of agents is served from the inventory as it was last
        assessed, and for up to the cache's lifetime that is behind what
        was decided a moment ago. A person who has just retired a
        registration or contained an agent opens the agent's page and must
        not be shown the state from before. So this read asks the audit
        trail first: the newest events of the agent's registration and of
        its Runtime's containment, one request each. When one of them is a
        decision that was carried out (``evidence.changes_inventory``) and
        is newer than the inventory, the inventory is loaded again, once,
        and the answer comes from that. An id the inventory does not hold
        yet is asked about in the same way when it is a registration's.

        The load reads every cell, so it shares the limit of the evidence
        document: at most one in ``DECISION_RELOAD_SECONDS`` per execution
        environment. Inside that time the trail is not asked at all, and
        the answer is the cached one, as it is when the trail cannot be
        read or the load fails.
        """
        inventory = self.inventory()
        entry = self._entry_of(inventory, agent_id)
        if self._reload_allowed() and self._decided_since(inventory, entry, agent_id) and self._may_reload():
            fresh = self._inventory_afresh()
            if fresh is not None:
                # Also when the agent is gone from it: a registration that was deleted, for example.
                entry = self._entry_of(fresh, agent_id)
        if entry is None:
            raise NotFound("Agent not found")
        return entry

    def _decided_since(self, inventory: Inventory, entry: AgentEntry | None, agent_id: str) -> bool:
        """Whether the audit trail holds a decision about this agent that is newer than the inventory.

        One request for each of the agent's histories, for its newest
        ``DECISION_CHECK_EVENTS`` events: never a read of a history. A
        history that cannot be read says nothing, and the answer is then
        the cached one.
        """
        table = self.settings.audit_table
        if not table:
            return False
        keys: list[str] = []
        if entry is None:
            # Not in the inventory (yet): only a registration's own id names a history.
            if registration_helpers.RECORD_ID.fullmatch(agent_id):
                keys.append(audit_reader.record_key(agent_id))
        else:
            if entry.record is not None:
                keys.append(audit_reader.record_key(entry.agent.id))
            runtime_arn = self._canonical_runtime_arn(entry)
            if runtime_arn:
                keys.append(audit_reader.containment_key(runtime_arn))
        if not keys:
            return False
        dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
        for key in keys:
            try:
                events = audit_reader.latest(dynamodb, table, key, DECISION_CHECK_EVENTS)
            except Exception as exc:  # noqa: BLE001 - the cached answer is still an answer
                logger.warning("The newest events of a history could not be read: %s", error_code(exc))
                continue
            if self._recorded_after(inventory.assessed_at, events):
                return True
        return False

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

    def containment_view(self, agent_id: str, caller_subject: str, caller_role: str = "") -> ContainmentView:
        """Whether the agent's Runtime is contained (read fresh through the cell reader), by whom, and the events.

        Who contained it, why, and the history of attempts are an incident
        record: they are returned only to a caller whose role can contain or
        release. Every other mapped role gets the state, when it was
        contained, and whether the caller is the one who cannot release it.
        """
        entry = self.agent(agent_id)
        view = self._containment_state(entry)
        runtime_arn = self._canonical_runtime_arn(entry)
        if self.settings.audit_table and runtime_arn:
            self._containment_history(view, runtime_arn, caller_subject, caller_role, self.settings.audit_table)
        return view

    @staticmethod
    def _canonical_runtime_arn(entry: AgentEntry) -> str | None:
        """The agent's Runtime ARN when it is the one the portal builds for the Runtime's cell, else ``None``.

        A history exists only under that ARN: the functions that write one
        build it the same way (``portal_api/arns.py``). ``None`` for an agent
        with no Runtime, for a Runtime in an account with no cell, and for a
        registration that spells the ARN another way.
        """
        return arns.canonical_in(entry.access_cell, entry.runtime_arn)

    def _containment_state(self, entry: AgentEntry) -> ContainmentView:
        """The containment state of the agent's Runtime, read fresh through the cell reader. No events."""
        cell = entry.access_cell
        runtime_arn = self._canonical_runtime_arn(entry)
        view = ContainmentView(
            agent_id=entry.agent.id,
            state="unknown",
            runtime_arn=entry.runtime_arn,
            enforcement_delay_seconds=containment_timing.CONTAIN_DELAY_SECONDS,
            release_delay_seconds=containment_timing.RELEASE_DELAY_SECONDS,
            # The actions can work: the Runtime is named by the ARN the portal builds for its cell
            # (the containment function refuses any other), and a cell there has a containment role.
            enabled=bool(
                runtime_arn
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
        elif runtime_arn is None:
            view.detail = NOT_CANONICAL
        else:
            state = agentcore.containment_state(self.clients.cell(cell, "bedrock-agentcore-control"), runtime_arn)
            if state is None:
                view.detail = "The Runtime's resource policy could not be read."
            elif state == containment_policy.CONTAINED:
                view.state = "contained"
            else:
                view.state = "not_contained"
                if state == containment_policy.FOREIGN:
                    # A statement that only carries the portal's Sid is not containment, and says so.
                    view.detail = containment_policy.FOREIGN_STATEMENT
        return view

    def _containment_history(
        self, view: ContainmentView, runtime_arn: str, caller_subject: str, caller_role: str, table: str
    ) -> list[AuditEvent]:
        """Add to ``view`` what the audit trail says about the containment of this Runtime.

        Who contained it, why, and the events are put in the view only for a caller whose role
        can contain or release; see ``containment_view``. The events are returned whatever the
        role, for the caller's own use (the evidence document checks how recent they are).
        """
        dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
        # The history belongs to the Runtime, whatever id the agent is listed under. Who holds the
        # containment is read from the events that can settle it, back to the one that does; the
        # sweeps and repeated contains since are read back to the time of that event, and both
        # far enough to show the newest events: never to the end for its own sake.
        history = audit_reader.read_history(dynamodb, table, runtime_arn, at_least=audit_reader.MAX_VIEW_EVENTS)
        events = history.events
        incident_reader = caller_role in (authorities.CONTAIN_ROLES | authorities.RELEASE_ROLES)
        settled = history.settled
        holder = history.holder.event if settled else None
        if not settled and view.state == "contained":
            view.detail = HOLDER_NOT_FOUND
        if holder is not None and view.state != "not_contained":
            view.contained_at = holder.at
            view.contained_by_me = holder.actor_subject == caller_subject
            # The result of the contain itself. Its sweeps carry the same request id and say nothing
            # about the request: ``partial`` describes the request and does not change afterwards.
            result = next(
                (
                    e
                    for e in events
                    if e.request_id == holder.request_id and e.phase == "result" and e.action == holder.action
                ),
                None,
            )
            # Partial: sessions were left running, or their discovery was not clean.
            view.partial = result is None or bool(result.sessions_failed) or result.detail not in (None, "ok")
            if incident_reader:
                view.contained_by, view.contained_by_label = holder.actor_subject, holder.actor_label
                view.reason = holder.reason
        # The background sweeps are part of the state, like ``partial``: every role sees how many
        # were scheduled and have run, and since when the agent is known to be quiet.
        # Everything the summary counts is newer than the event that began the containment, so the
        # events read back to that event are all it needs.
        swept = sweeps.summary(events, view.contained_at, containment_timing.CONTAIN_DELAY_SECONDS)
        view.sweeps = ContainmentSweeps(scheduled=swept.scheduled, done=swept.done)
        view.quiet_at = swept.quiet_at
        shown = events[: audit_reader.MAX_VIEW_EVENTS]
        if incident_reader:
            view.events = shown
            view.events_truncated = len(events) > len(shown)
        return shown

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
        return self._eval_runs(self.agent(agent_id))

    def _eval_runs(self, entry: AgentEntry) -> EvalRuns:
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
        return self._policies(self.gateway(gateway_id))

    def _policies(self, entry: GatewayEntry) -> CedarPolicySet:
        if entry.cell is None:
            # Known from the organization registry only: no policy is claimed, and none is denied.
            return mcp_mapper.policy_set(
                entry, [], [entry.server.detail or mcp_mapper.NOT_READ[mcp_mapper.READER_NONE]]
            )
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
        if not self.gateway(gateway_id).read:
            return []  # who can call a gateway that no reader read is not known
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
        registration_review_by = registry_mapper.agent_governance(record).review_by
        detail.effective_review_by = registration_review_by
        if not self.settings.audit_table:
            return detail
        dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
        # The newest part of the record's history, bounded: who submitted, decided and reviewed it
        # last are among its newest events.
        key = audit_reader.record_key(record_id)
        trail = audit_reader.read_back(dynamodb, self.settings.audit_table, key)
        items, events = trail.items, trail.events
        # Read from the record's own events, so an attestation shows here as soon as it is made.
        reviewed = audit_reader.last_review(events)
        if reviewed is not None:
            detail.last_reviewed_at, detail.last_reviewed_by = reviewed.at, reviewed.reviewed_by_label
            detail.effective_review_by = reviews.effective(registration_review_by, reviewed).review_by
        approved = audit_reader.last_approved_document(items)
        if approved:
            detail.previous_approved = registration_helpers.snake_document(approved)
        done = [e for e in events if e.phase == "result" and e.outcome == "allowed"]  # newest first
        oldest = done
        if not trail.ended:
            # The creation is the oldest event of a record. In a history longer than was read it
            # is looked up from the other end.
            first = audit_reader.read_back(
                dynamodb, self.settings.audit_table, key, max_events=5, page_size=5, oldest_first=True
            )
            oldest = [e for e in reversed(first.events) if e.phase == "result" and e.outcome == "allowed"]
        created = next((e for e in reversed(oldest) if e.action == "create"), None)
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
        events, truncated = self._record_events(table, record_id)
        if not events:
            raise NotFound("No history for this registration")
        return RegistrationHistory(record_id=record_id, events=events, events_truncated=truncated)

    def _record_events(self, table: str, record_id: str) -> tuple[list[AuditEvent], bool]:
        """The newest audit events of one record, newest first, and whether older ones were left out.

        At most ``audit.MAX_VIEW_EVENTS`` are returned, from at most that many
        read of the record's own history and of the history filed under its
        name: the newest of the two together are among the newest of each.
        """
        limit = audit_reader.MAX_VIEW_EVENTS
        dynamodb = self.clients.platform("dynamodb", self.settings.registry_region)
        events, truncated = audit_reader.newest(dynamodb, table, audit_reader.record_key(record_id), limit)
        # Decisions taken before the record had an id (its creation) are filed under its name.
        names = {event.record_name for event in events if event.record_name}
        for name in sorted(names):
            named, cut = audit_reader.newest(dynamodb, table, audit_reader.name_key(name), limit)
            truncated = truncated or cut
            events.extend(event for event in named if event.record_id in (None, record_id))
        events.sort(key=lambda e: (e.at, e.event_id), reverse=True)
        return events[:limit], truncated or len(events) > limit

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
            # "unknown": gateways that no reader read. They are not counted as having no policy engine.
            gateways_by_policy_mode=dict.fromkeys(("enforce", "log_only", "none", mcp_mapper.UNKNOWN_MODE), 0),
            organization_registry=inventory.discovery,
            review_attestations=inventory.review_attestations,
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
            if agent.obligations_closed:
                continue  # its flags do not apply: neither set nor unknown
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
        summary.warnings.extend(self._review_warnings(inventory))
        return summary

    @staticmethod
    def _review_warnings(inventory: Inventory) -> list[str]:
        """What to say when the review attestations could not be read, or not all of them."""
        warnings = []
        if inventory.review_attestations not in ("ok", "disabled"):
            warnings.append(
                f"Review attestations could not be read ({inventory.review_attestations}), "
                "so every review date shown is the registration's own."
            )
        if inventory.attestations_truncated:
            warnings.append(
                "Not every review attestation was read. For an agent whose latest attestation was "
                "left out, the review date shown is an earlier one or the registration's own."
            )
        return warnings

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
                    "review_by": agent.review_by,
                    "last_reviewed_at": agent.last_reviewed_at,
                }
            )
        return rows

    # --- evidence document ---------------------------------------------------

    def evidence(self, agent_id: str, principal: Principal) -> AgentEvidence:
        """One document about one agent, for an auditor. Read-only, and it never fails on a missing part.

        The agent, registration, reviews and risk come from the inventory as it
        was assessed. The audit events, the containment state, the gateways'
        policies and the latest pipeline execution are read for the document.
        Whatever cannot be read is left empty and named in ``limitations``.
        """
        # One inventory for the whole document, so its sections describe the same moment.
        inventory = self.inventory()
        entry = self._entry_of(inventory, agent_id)
        if entry is None:
            raise NotFound("Agent not found")
        limitations: list[str] = []
        table = self.settings.audit_table

        decisions: list[AuditEvent] = []
        decisions_truncated = False
        if not table:
            limitations.append(
                "No audit table is configured for the read API, so decisions, review attestations "
                "and containment events are not available."
            )
        elif entry.record is not None:
            try:
                decisions, decisions_truncated = self._record_events(table, entry.agent.id)
            except Exception as exc:  # noqa: BLE001 - named in the document instead
                logger.warning("Evidence: the registration's events could not be read: %s", error_code(exc))
                limitations.append(f"The registration's audit events could not be read ({error_code(exc)}).")
            if decisions_truncated:
                limitations.append(
                    OLDER_EVENTS.format(what="registration's history", limit=audit_reader.MAX_VIEW_EVENTS)
                )
        after_decisions = len(limitations)  # where the notes about the reviews go, once the inventory is settled

        containment: ContainmentView | None = None
        containment_events: list[AuditEvent] = []
        try:
            containment = self._containment_state(entry)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Evidence: the containment state could not be read: %s", error_code(exc))
            limitations.append(f"The containment state could not be read ({error_code(exc)}).")
        else:
            if containment.state == "unknown" and entry.runtime_arn and containment.detail:
                limitations.append(containment.detail)
            runtime_arn = self._canonical_runtime_arn(entry)
            if table and runtime_arn:
                try:
                    containment_events = self._containment_history(
                        containment, runtime_arn, principal.subject, principal.role, table
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Evidence: the containment events could not be read: %s", error_code(exc))
                    limitations.append(f"The containment events could not be read ({error_code(exc)}).")
                else:
                    if containment.detail == HOLDER_NOT_FOUND:
                        limitations.append(HOLDER_NOT_FOUND)
                    if containment.events_truncated:
                        limitations.append(
                            OLDER_EVENTS.format(what="containment history", limit=audit_reader.MAX_VIEW_EVENTS)
                        )

        # Something was decided after the cached inventory was assessed (a moment ago, typically).
        # The document must not list an approval and still call the registration pending, so the
        # inventory is loaded again, once. If that fails, or the agent is no longer in it, the
        # sections stay as they were and the document says that they lag (``build``).
        #
        # Only an event that can change what the inventory shows counts (``changes_inventory``):
        # a refusal, an intent and a background sweep change nothing. And the load reads every
        # cell, so it happens at most once in ``DECISION_RELOAD_SECONDS`` per execution
        # environment, however many documents are asked for: otherwise the document says that it lags.
        if self._recorded_after(inventory.assessed_at, decisions, containment_events) and self._may_reload():
            fresh = self._inventory_afresh()
            fresh_entry = self._entry_of(fresh, agent_id) if fresh is not None else None
            if fresh is not None and fresh_entry is not None:
                inventory, entry = fresh, fresh_entry
        limitations[after_decisions:after_decisions] = self._review_warnings(inventory)

        index = inventory.gateway_index()
        gateways: list[evidence_builder.GatewayPolicies] = []
        for link in entry.links:
            gateway = index.get(link.gateway_id)
            policies = None
            if gateway is None:
                limitations.append(
                    f"Tool Gateway {link.gateway_id} was not found in a cell the portal can read, "
                    "so its policy mode and policies are not known."
                )
            else:
                try:
                    policies = self._policies(gateway)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Evidence: a gateway's policies could not be read: %s", error_code(exc))
                    limitations.append(
                        f"The policies of Tool Gateway {link.gateway_id} could not be read ({error_code(exc)})."
                    )
                else:
                    if policies.warnings:
                        limitations.extend(f"Tool Gateway {link.gateway_id}: {w}" for w in policies.warnings)
                        policies = None
            gateways.append(evidence_builder.GatewayPolicies(link=link, gateway=gateway, policies=policies))

        release = None
        try:
            runs = self._eval_runs(entry)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Evidence: the pipeline executions could not be read: %s", error_code(exc))
            limitations.append(f"The pipeline executions could not be read ({error_code(exc)}).")
        else:
            release = runs.current_run
            limitations.extend(runs.warnings)
            if release is None and not runs.warnings:
                limitations.append("The pipeline of this agent's cell has no execution to show.")

        # The review date comes from the inventory, like the sections beside it. What is listed is
        # every attestation that was read for this record: the ones among its events above, where
        # the history of attestations is kept, and what the inventory holds (the latest).
        known = inventory.attestations.get(entry.agent.id, []) if entry.record is not None else []
        return evidence_builder.build(
            entry=entry,
            generated_at=now_iso(),
            generated_by_label=principal.label,
            generated_by_role=principal.role,
            portal_environment=self.settings.env,
            assessed_at=inventory.assessed_at,
            decisions=decisions,
            decisions_truncated=decisions_truncated,
            attestations=reviews.merged(known, audit_reader.attestations_in(decisions)),
            latest_attestation=known[0] if known else None,
            containment=containment,
            containment_details=principal.role in (authorities.CONTAIN_ROLES | authorities.RELEASE_ROLES),
            gateways=gateways,
            release=release,
            limitations=limitations,
        )

    @staticmethod
    def _entry_of(inventory: Inventory, agent_id: str) -> AgentEntry | None:
        return next((e for e in inventory.agents if e.agent.id == agent_id), None)

    @staticmethod
    def _recorded_after(assessed_at: str, *event_lists: Iterable[AuditEvent]) -> bool:
        """Whether any of these events was recorded after the moment the inventory describes."""
        assessed = parse_instant(assessed_at)
        if assessed is None:
            return False
        return any(
            evidence_builder.changes_inventory(event) and (at := parse_instant(event.at)) is not None and at > assessed
            for events in event_lists
            for event in events
        )

    def _reload_allowed(self) -> bool:
        """Whether a decision may make a request load the inventory again now. Asking counts for nothing."""
        return self._reloaded_at is None or self._clock() - self._reloaded_at >= DECISION_RELOAD_SECONDS

    def _may_reload(self) -> bool:
        """Whether this request may load the inventory again now. Saying yes counts as doing it.

        One limit for the evidence document and the single-agent read: the
        load is the same, and so is what it costs.
        """
        if not self._reload_allowed():
            return False
        self._reloaded_at = self._clock()
        return True

    def _inventory_afresh(self) -> Inventory | None:
        """The inventory loaded again now, whatever is cached. ``None`` when that fails.

        The fresh inventory replaces the cached one, so the next request is
        served from it. When the load fails the cached one stays.
        """
        try:
            with self._reading_afresh("inventory"):
                return self.inventory()
        except Exception as exc:  # noqa: BLE001 - the caller keeps what it had and says that it lags
            logger.warning("The inventory could not be loaded again: %s", error_code(exc))
            return None

    # --- catalogue -----------------------------------------------------------

    def catalog_models(self) -> list[CatalogModel]:
        return [
            CatalogModel(model_id=m.model_id, provider=m.provider, regions=list(m.regions), status=m.status)
            for m in self.settings.model_allowlist
        ]

    def catalog_tools(self) -> list[CatalogTool]:
        tools = [registry_mapper.catalog_tool(r) for r in registry_mapper.tool_records(self.records())]
        return sorted(tools, key=lambda t: t.tool_id)
