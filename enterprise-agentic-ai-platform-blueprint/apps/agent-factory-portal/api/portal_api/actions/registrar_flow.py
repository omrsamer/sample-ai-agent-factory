# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Registrar actions: create, update, submit and delete an agent governance record."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from portal_api import registrations
from portal_api.actions import audit_writer, authority, registrar
from portal_api.actions.engine import ActionEngine, ActionError, Target
from portal_api.aws.session import error_code
from portal_api.models.portal import ActionResult, Registration, RegistrationInput

# Statuses in which the registry accepts each action (observed against a live registry).
UPDATABLE = frozenset({"DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED"})


def _registration(record: dict[str, Any]) -> Registration:
    document = registrations.agent_document(record)
    if document is None:
        raise ActionError(404, "Registration not found")
    return registrations.to_registration(record, document)


def _document(body: RegistrationInput, version: str) -> dict[str, Any]:
    try:
        return registrations.build_document(body, version)
    except registrations.DocumentError as exc:
        raise ActionError(422, exc.errors()) from exc


def _load(engine: ActionEngine, action: str, record_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The settled record and its governance document, or 404.

    A caller without the registrar authority is refused before the record is
    read, so the answer does not reveal whether the record exists.
    """
    if not authority.has_authority(engine.principal, action):
        target = Target(action=action, tenant_id=authority.NO_TENANT, record_name="", record_id=record_id)
        engine.authorize(target, {"recordId": record_id}, None)
    try:
        record = registrar.wait_until_settled(engine.registry, engine.settings.registry_id, record_id)
    except ClientError as exc:
        if error_code(exc) == "ResourceNotFoundException":
            raise ActionError(404, "Registration not found") from exc
        raise ActionError(502, f"An AWS service call failed ({error_code(exc)})") from exc
    document = registrations.agent_document(record)
    if document is None:
        # Not an agent governance record: the portal does not touch it.
        raise ActionError(404, "Registration not found")
    return record, document


def _target(action: str, record: dict[str, Any], document: dict[str, Any]) -> Target:
    return Target(
        action=action,
        tenant_id=str(document.get("tenantId")),
        record_name=str(record.get("name")),
        record_id=str(record["recordId"]),
        status_before=str(record.get("status")),
        document_sha256=registrations.sha256(registrations.canonical(document)),
    )


def _state(record: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    return {
        "recordId": record["recordId"],
        "tenantId": document.get("tenantId"),
        "status": record.get("status"),
        "references": authority.approved_references(document),
    }


def _content(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "recordVersion"}


def _in_transition(engine: ActionEngine, target: Target) -> None:
    if target.status_before in registrar.TRANSITIONAL:
        raise engine.deny(target, 409, f"The record is still {target.status_before}; try again shortly")


def create(engine: ActionEngine, body: RegistrationInput) -> ActionResult:
    version = body.record_version or "1.0.0"
    if registrations.parse_version(version) is None:
        raise ActionError(
            422,
            registrations.DocumentError(
                "document.recordVersion must be a semantic version such as 1.0.0", "document.recordVersion"
            ).errors(),
        )
    document = _document(body, version)
    name = registrations.record_name(document["tenantId"], document["agentId"], document["environment"])
    target = Target(
        action="create",
        tenant_id=document["tenantId"],
        record_name=name,
        document_sha256=registrations.sha256(registrations.canonical(document)),
    )
    allow_reason = engine.authorize(target, {"tenantId": document["tenantId"]}, None)
    if registrar.find_by_name(engine.registry, engine.settings.registry_id, name):
        raise engine.deny(target, 409, f"A record named {name} already exists")

    token_seed = audit_writer.new_request_id()

    def call() -> dict[str, Any]:
        record_id = registrar.create_record(engine.registry, engine.settings.registry_id, document, token_seed)
        return registrar.wait_until_settled(engine.registry, engine.settings.registry_id, record_id)

    return engine.perform(target, allow_reason, call, _registration)


def update(engine: ActionEngine, record_id: str, body: RegistrationInput) -> ActionResult:
    record, current = _load(engine, "update", record_id)
    if not authority.holds_tenant(engine.principal, engine.settings, str(current.get("tenantId"))):
        # Refuse a caller who does not hold the record's tenant before telling it anything about the record.
        engine.authorize(_target("update", record, current), {"recordId": record_id}, _state(record, current))
    for field, value in (("tenantId", body.tenant_id), ("agentId", body.agent_id), ("environment", body.environment)):
        if value != current.get(field):
            raise ActionError(
                422,
                registrations.DocumentError(
                    f"document.{field} cannot be changed; register a new record instead", f"document.{field}"
                ).errors(),
            )
    try:
        version = registrations.next_version(
            current.get("recordVersion") or record.get("recordVersion"), body.record_version
        )
    except registrations.DocumentError as exc:
        raise ActionError(422, exc.errors()) from exc
    document = _document(body, version)
    target = _target("update", record, current)
    target.document_sha256 = registrations.sha256(registrations.canonical(document))
    request = {
        "recordId": record_id,
        "tenantId": document["tenantId"],
        "proposedReferences": authority.approved_references(document),
    }
    allow_reason = engine.authorize(target, request, _state(record, current))
    _in_transition(engine, target)
    if target.status_before not in UPDATABLE:
        raise engine.deny(target, 409, f"A record in status {target.status_before} cannot be updated")
    if _content(document) == _content(current):
        # The registry returns any updated record to DRAFT, so an update that changes nothing is refused.
        raise engine.deny(target, 409, "The record already holds this document")

    def call() -> dict[str, Any]:
        registrar.update_record(engine.registry, engine.settings.registry_id, record_id, document)
        return registrar.wait_until_settled(engine.registry, engine.settings.registry_id, record_id)

    return engine.perform(target, allow_reason, call, _registration)


def submit(engine: ActionEngine, record_id: str) -> ActionResult:
    record, document = _load(engine, "submit", record_id)
    target = _target("submit", record, document)
    engine.authorize(target, {"recordId": record_id, "tenantId": target.tenant_id}, _state(record, document))
    _in_transition(engine, target)
    if target.status_before == "PENDING_APPROVAL":
        raise engine.deny(target, 409, "The record is already submitted for approval")
    if target.status_before == "REJECTED":
        raise engine.deny(target, 409, "A rejected record must be updated before it is submitted again")
    if target.status_before != "DRAFT":
        raise engine.deny(target, 409, f"A record in status {target.status_before} cannot be submitted")

    def call() -> dict[str, Any]:
        registrar.submit_record(engine.registry, engine.settings.registry_id, record_id)
        return registrar.get_record(engine.registry, engine.settings.registry_id, record_id)

    return engine.perform(target, "registrar submit of a record for approval", call, _registration)


def delete(engine: ActionEngine, record_id: str) -> ActionResult:
    record, document = _load(engine, "delete", record_id)
    target = _target("delete", record, document)
    allow_reason = engine.authorize(
        target, {"recordId": record_id, "tenantId": target.tenant_id}, _state(record, document)
    )
    _in_transition(engine, target)
    if target.status_before == "APPROVED":
        raise engine.deny(target, 409, "An approved record cannot be deleted")

    def call() -> None:
        registrar.delete_record(engine.registry, engine.settings.registry_id, record_id)

    return engine.perform(target, allow_reason, call, _registration)
