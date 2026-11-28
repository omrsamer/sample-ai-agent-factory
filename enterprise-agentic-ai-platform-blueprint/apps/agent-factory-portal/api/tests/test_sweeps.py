# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Background sweeps of a contained Runtime: the messages, the sweeper function, and how they read back."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from portal_api import containment_policy, containment_timing, sweeps
from portal_api.actions import app as actions_app
from portal_api.actions import audit_writer, containment, containment_flow, sweep_queue, sweeper
from portal_api.aws import audit as audit_reader
from portal_api.aws import logs
from portal_api.config import ConfigError, load_action_settings, load_sweeper_settings
from portal_api.models.portal import AuditEvent
from portal_api.sweeps import InvalidMessage, SweepMessage
from tests import test_containment
from tests.conftest import BASE_ENV, CELL_ACCOUNT, CELLS, ORPHAN_RUNTIME_ARN, OTHER_ACCOUNT, RUNTIME_ARN
from tests.fakes import client_error
from tests.test_containment import (
    ORPHAN_ID,
    PAT,
    RUNTIME_ID,
    SEC,
    SRE,
    VIEW,
    FakeCell,
    World,
    log_group,
    session_row,
    session_stream,
    sid,
)

read = test_containment.read  # the read API over the same cell, record and audit table

QUEUE_URL = "https://sqs.eu-west-1.amazonaws.com/111111111111/agenticai-portal-nonprod-sweeps"
REQUEST_ID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
RECORD_ID = "rec000000001"
SWEEPER_ENV = {**BASE_ENV, "PORTAL_ACTION_ROLE": "sweeper"}
KEY = audit_reader.containment_key(RUNTIME_ARN)


# --- the delays and the rate (one place) -------------------------------------------------------


def test_the_three_sweep_delays_and_the_stop_rate():
    first, second, third = containment_timing.SWEEP_DELAYS_SECONDS
    assert (first, second, third) == (0, 120, 900)
    # The second sweep must come after every host applies the deny.
    assert second > containment_timing.CONTAIN_DELAY_SECONDS
    # The third is the longest delay a queue message can have.
    assert second < third <= 900
    assert containment_timing.SWEEP_STOPS_PER_SECOND == 20
    assert sweeps.SWEEP_NUMBERS == (1, 2, 3) and len(containment_timing.SWEEP_DELAYS_SECONDS) == 3


def test_the_first_sweep_is_scheduled_only_when_it_is_needed():
    assert sweeps.sweeps_to_schedule(first_needed=True) == (1, 2, 3)
    assert sweeps.sweeps_to_schedule(first_needed=False) == (2, 3)


# --- the message --------------------------------------------------------------------------------


def message(**changes: Any) -> SweepMessage:
    values = {"sweep": 2, "runtime_arn": RUNTIME_ARN, "agent_id": RECORD_ID, "request_id": REQUEST_ID}
    return SweepMessage(**{**values, **changes})


def body(**changes: Any) -> str:
    """A message body with some fields changed; a value of ``...`` removes the field."""
    data = json.loads(sweeps.encode(message()))
    for name, value in changes.items():
        if value is ...:
            data.pop(name)
        else:
            data[name] = value
    return json.dumps(data)


def test_a_message_round_trips_and_holds_only_what_the_sweeper_needs():
    encoded = sweeps.encode(message())
    assert sweeps.decode(encoded) == message()
    assert json.loads(encoded) == {
        "version": 1,
        "kind": "containment_sweep",
        "sweep": 2,
        "runtime_arn": RUNTIME_ARN,
        "agent_id": RECORD_ID,
        "request_id": REQUEST_ID,
    }
    assert message().runtime_id == RUNTIME_ID
    # An agent with no registration is addressed by its Runtime id.
    unregistered = message(agent_id=RUNTIME_ID)
    assert sweeps.decode(sweeps.encode(unregistered)) == unregistered


def test_the_longest_message_fits_and_the_queue_request_matches_the_service_model():
    import boto3
    from botocore.stub import Stubber

    name = "a" * 100 + "-" + "B" * 20
    longest = message(
        sweep=3, runtime_arn=f"arn:aws-us-gov:bedrock-agentcore:{'r' * 30}:111111111111:runtime/{name}", agent_id=name
    )
    encoded = sweeps.encode(longest)
    assert sweeps.decode(encoded) == longest and len(encoded) < sweeps.MAX_BODY_CHARACTERS // 2

    client = boto3.client("sqs", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test")
    with Stubber(client) as stub:
        for delay in containment_timing.SWEEP_DELAYS_SECONDS:
            stub.add_response(
                "send_message",
                {"MessageId": "m-1", "MD5OfMessageBody": "0" * 32},
                {"QueueUrl": QUEUE_URL, "MessageBody": encoded, "DelaySeconds": delay},
            )
            sweep_queue.send(client, QUEUE_URL, encoded, delay)
        stub.assert_no_pending_responses()


def test_the_runtime_pattern_is_the_one_the_containment_function_accepts():
    from portal_api import arns

    # One pattern for both, so a message cannot name a Runtime in a shape the contain would not accept.
    assert sweeps.RUNTIME_ARN is arns.RUNTIME_ARN
    assert containment_flow.arns is arns


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (None, "not a short text"),
        (b"bytes", "not a short text"),
        ({"sweep": 2}, "not a short text"),
        ("x" * 2049, "not a short text"),
        ("not json", "not JSON"),
        ("[1, 2]", "not a JSON object"),
        ("{}", "runtime_arn is not a Runtime ARN"),
        (body(runtime_arn=None), "runtime_arn is not a Runtime ARN"),
        (body(runtime_arn="arn:aws:bedrock-agentcore:eu-west-1:444444444444:runtime/*"), "not a Runtime ARN"),
        (body(runtime_arn=RUNTIME_ARN + " "), "not a Runtime ARN"),
        (body(runtime_arn=RUNTIME_ARN.replace("runtime/", "gateway/")), "not a Runtime ARN"),
        (body(runtime_arn=[RUNTIME_ARN]), "not a Runtime ARN"),
        (body(request_id=...), "exactly the expected fields"),
        (body(extra="x"), "exactly the expected fields"),
        (body(role_arn="arn:aws:iam::999999999999:role/other"), "exactly the expected fields"),
        (body(version=2), "version or kind"),
        (body(version=True), "version or kind"),
        (body(kind="release"), "version or kind"),
        (body(sweep=0), "sweep is not 1, 2 or 3"),
        (body(sweep=4), "sweep is not 1, 2 or 3"),
        (body(sweep="2"), "sweep is not 1, 2 or 3"),
        (body(sweep=True), "sweep is not 1, 2 or 3"),
        (body(sweep=2.5), "sweep is not 1, 2 or 3"),
        (body(agent_id="other_agent-ZyXwVu9876"), "agent_id is neither"),  # another Runtime's id
        (body(agent_id="short"), "agent_id is neither"),
        (body(agent_id=None), "agent_id is neither"),
        (body(request_id="not-a-request-id"), "request_id is not a request id"),
        (body(request_id=REQUEST_ID.upper()), "request_id is not a request id"),
        (body(request_id=5), "request_id is not a request id"),
    ],
)
def test_a_message_is_untrusted_input(raw, reason):
    with pytest.raises(InvalidMessage) as refused:
        sweeps.decode(raw)
    assert reason in refused.value.reason
    # The refusal carries the sweeper's own words and nothing the message said, not even its Runtime.
    assert vars(refused.value) == {"reason": refused.value.reason}
    assert RUNTIME_ARN not in refused.value.reason


# --- scheduling: the contain leaves the messages --------------------------------------------------


class FakeQueue:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.fail_on: set[int] = set()  # 1-based send numbers that fail
        self.sends = 0

    def send_message(self, QueueUrl: str, MessageBody: str, DelaySeconds: int) -> dict[str, Any]:  # noqa: N803
        self.sends += 1
        if self.sends in self.fail_on:
            raise client_error("AccessDenied", "SendMessage")
        self.messages.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody, "DelaySeconds": DelaySeconds})
        return {"MessageId": f"m-{self.sends}"}

    def sweeps(self) -> list[tuple[int, int]]:
        """(sweep number, delay in seconds) of every message, in the order sent."""
        return [(json.loads(m["MessageBody"])["sweep"], m["DelaySeconds"]) for m in self.messages]


class SweepWorld(World):
    """The containment function with a sweep queue configured."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PORTAL_SWEEP_QUEUE_URL", QUEUE_URL)
        super().__init__(monkeypatch)
        self.queue = FakeQueue()
        self.queue_regions: list[str] = []

        def client(service: str, region: str) -> Any:
            assert service == "sqs", service  # every other client is replaced by a fake
            self.queue_regions.append(region)
            return self.queue

        monkeypatch.setattr(actions_app, "_client", client)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SweepWorld:
    return SweepWorld(monkeypatch)


def background_step(response: dict[str, Any]) -> dict[str, Any] | None:
    return next((step for step in response["steps"] if step["id"] == "background"), None)


def test_without_a_queue_a_contain_is_what_it_was(monkeypatch):
    plain = World(monkeypatch)  # PORTAL_SWEEP_QUEUE_URL is not set
    monkeypatch.setattr(actions_app, "_client", lambda service, region: pytest.fail("no client may be made"))
    plain.cell.streams[log_group()] = [session_stream("a")]
    code, response = plain.post("contain")
    assert code == 200
    assert [step["id"] for step in response["steps"]] == ["policy", "verify", "sessions"]
    assert response["sweeps_scheduled_in_seconds"] == [] and response["partial"] is False
    assert "background" not in response["reason"].lower()
    result = [e for e in plain.dynamo.events() if e["phase"] == "result"][-1]
    assert "sweeps_scheduled" not in result


def test_a_complete_contain_needs_no_sweep_now_and_schedules_the_two_later_ones(world):
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    code, response = world.post("contain")
    assert code == 200 and response["sessions"]["stopped"] == 2 and response["partial"] is False
    assert world.queue.sweeps() == [(2, 120), (3, 900)]
    assert {m["QueueUrl"] for m in world.queue.messages} == {QUEUE_URL}
    assert world.queue_regions == ["eu-west-1"]  # the client is made for the queue's own Region
    for sent in world.queue.messages:
        decoded = sweeps.decode(sent["MessageBody"])
        # The Runtime is the identity of what is swept; the request id ties the sweep to this contain.
        assert (decoded.runtime_arn, decoded.agent_id, decoded.request_id) == (
            RUNTIME_ARN,
            world.record_id,
            response["request_id"],
        )
    step = background_step(response)
    assert step == {
        "id": "background",
        "label": "Stop remaining sessions in the background",
        "status": "scheduled",
        "detail": (
            "No background sweep is needed now. Later sweeps are scheduled in about 2 minutes and in about 15 minutes."
        ),
    }
    assert [s["id"] for s in response["steps"]] == ["policy", "verify", "sessions", "background"]
    assert response["sweeps_scheduled_in_seconds"] == [120, 900]
    # The history explains why there is one sweep fewer.
    result = [e for e in world.dynamo.events() if e["phase"] == "result"][-1]
    assert "No background sweep is needed now." in result["reason"] and result["sweeps_scheduled"] == "2"
    assert response["reason"].endswith(step["detail"] + "]")


def test_a_contain_with_no_session_at_all_also_needs_no_sweep_now(world):
    code, response = world.post("contain")
    assert code == 200 and response["sessions"]["found"] == 0
    assert world.queue.sweeps() == [(2, 120), (3, 900)]


def test_a_contain_that_left_something_undone_schedules_a_sweep_now(world):
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    world.cell.stop_errors[sid("b")] = "ThrottlingException"
    code, response = world.post("contain")
    assert code == 200 and response["partial"] is True and response["sessions"]["failed"] == 1
    assert world.queue.sweeps() == [(1, 0), (2, 120), (3, 900)]
    step = background_step(response)
    assert step["status"] == "scheduled"
    assert step["detail"] == "Background sweeps are scheduled: now, in about 2 minutes and in about 15 minutes."
    assert response["sweeps_scheduled_in_seconds"] == [0, 120, 900]
    assert [e for e in world.dynamo.events() if e["phase"] == "result"][-1]["sweeps_scheduled"] == "3"


def test_a_contain_whose_session_list_was_cut_schedules_a_sweep_now_which_stops_the_rest(world, monkeypatch):
    monkeypatch.setattr(containment, "MAX_STREAM_PAGES", 2)  # the request reads two pages of two
    world.cell.stream_page_size = 2
    world.cell.streams[log_group()] = [session_stream(f"s{i}", minutes_ago=1 + i) for i in range(7)]
    code, response = world.post("contain")
    assert code == 200 and response["partial"] is True and response["sessions"]["stopped"] == 4
    assert "more sessions may be running" in response["sessions"]["discovery"]
    assert world.queue.sweeps() == [(1, 0), (2, 120), (3, 900)]
    # The sweep has no page limit: it reads all four pages and stops the three sessions the request never saw.
    world.cell.stop_errors = {sid(f"s{i}"): "ResourceNotFoundException" for i in range(4)}  # those have ended
    run = Run(world)
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "allowed"
    assert sorted(s for s, _ in world.cell.stopped[4:]) == [sid("s4"), sid("s5"), sid("s6")]
    (event,) = run.sweep_events()
    assert (event["sweep"], event["sessions_found"], event["sessions_stopped"], event["sessions_not_active"]) == (
        "1",
        "7",
        "3",
        "4",
    )
    assert event["detail"] == "ok" and len(world.cell.stream_requests) == 2 + 4


def later(monkeypatch: pytest.MonkeyPatch, minutes: float) -> None:
    """From now on the containment function decides as if this many minutes had passed."""
    moment = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=minutes)
    monkeypatch.setattr(containment_flow, "_now", lambda: moment)


@pytest.mark.parametrize(
    ("fail_on", "scheduled", "said"),
    [
        ({1}, [], "0 of 2 were. Contain again to schedule them."),
        ({2}, [120], "1 of 2 were. Contain again in about 15 minutes to schedule them."),
    ],
)
def test_a_contain_still_succeeds_when_the_sweeps_cannot_be_scheduled(world, monkeypatch, fail_on, scheduled, said):
    world.queue.fail_on = fail_on
    code, response = world.post("contain")
    assert code == 200 and response["state"] == "contained"  # the deny statement holds either way
    step = background_step(response)
    assert step["status"] == "failed"
    assert step["detail"] == f"Background sweeps could not be scheduled (AccessDenied): {said}"
    assert response["partial"] is True and response["sweeps_scheduled_in_seconds"] == scheduled
    result = [e for e in world.dynamo.events() if e["phase"] == "result"][-1]
    assert result.get("sweeps_scheduled") == (str(len(scheduled)) if scheduled else None)
    world.queue.fail_on = set()
    if scheduled:
        # One sweep is on its way, so a contain repeated now adds nothing; once that sweep has run
        # and the pause is over, containing again schedules the rest.
        assert world.post("contain", claims=PAT)[1]["retry_after_seconds"] is not None
        assert Run(world).handle(world.queue.messages[0]["MessageBody"]) == "allowed"
        later(monkeypatch, 16)
    # Containing again schedules them.
    code, again = world.post("contain", claims=PAT)
    assert code == 200 and again["outcome"] == "unchanged" and again["retry_after_seconds"] is None
    assert background_step(again)["status"] == "scheduled" and again["sweeps_scheduled_in_seconds"] == [120, 900]


def test_a_release_schedules_nothing_and_cancels_nothing(world):
    assert world.post("contain", claims=SEC)[0] == 200
    queued = len(world.queue.messages)
    code, response = world.post("release", claims=PAT)
    assert code == 200 and background_step(response) is None
    assert response["sweeps_scheduled_in_seconds"] == []
    assert len(world.queue.messages) == queued  # the messages stay; the sweeper will skip them


def test_an_agent_with_no_registration_is_swept_by_its_runtime(world):
    code, response = world.post("contain", agent_id=ORPHAN_ID, claims=SEC)
    assert code == 200
    decoded = sweeps.decode(world.queue.messages[0]["MessageBody"])
    assert (decoded.runtime_arn, decoded.agent_id) == (ORPHAN_RUNTIME_ARN, ORPHAN_ID)


def test_the_queue_setting_belongs_to_the_containment_function_and_is_validated():
    env = {**BASE_ENV, "PORTAL_ACTION_ROLE": "containment"}
    assert load_action_settings(env).sweep_queue_url is None
    assert load_action_settings({**env, "PORTAL_SWEEP_QUEUE_URL": ""}).sweep_queue_url is None
    assert load_action_settings({**env, "PORTAL_SWEEP_QUEUE_URL": QUEUE_URL}).sweep_queue_url == QUEUE_URL
    for role in ("registrar", "approver"):
        other = {**BASE_ENV, "PORTAL_ACTION_ROLE": role, "PORTAL_SWEEP_QUEUE_URL": QUEUE_URL}
        assert load_action_settings(other).sweep_queue_url is None
    assert load_action_settings(env).sweep_queue_error is None
    assert load_action_settings({**env, "PORTAL_SWEEP_QUEUE_URL": QUEUE_URL}).sweep_queue_error is None
    # A value that is not a queue address is not a configuration error: the function still loads,
    # without a queue, and remembers why.
    for malformed in (
        "sweeps",
        "http://sqs.eu-west-1.amazonaws.com/111111111111/q",
        QUEUE_URL + "?x=1",
        QUEUE_URL + "/x",
    ):
        settings = load_action_settings({**env, "PORTAL_SWEEP_QUEUE_URL": malformed})
        assert settings.sweep_queue_url is None
        assert settings.sweep_queue_error == "the setting PORTAL_SWEEP_QUEUE_URL is not an Amazon SQS queue address"
        # The other two functions do not read the setting at all.
        other = load_action_settings({**env, "PORTAL_ACTION_ROLE": "approver", "PORTAL_SWEEP_QUEUE_URL": malformed})
        assert (other.sweep_queue_url, other.sweep_queue_error) == (None, None)
    assert sweep_queue.region_of(QUEUE_URL) == "eu-west-1" and sweep_queue.region_of("nonsense") is None


def test_a_malformed_queue_setting_does_not_stop_a_contain_or_a_release(world, monkeypatch, caplog):
    """The queue is an addition to containment: a mistake in its setting must not take the emergency action away."""
    monkeypatch.setenv("PORTAL_SWEEP_QUEUE_URL", "not-a-queue")
    world.cell.streams[log_group()] = [session_stream("a")]
    with caplog.at_level("ERROR", logger="portal_api.actions.containment_flow"):
        code, response = world.post("contain", claims=SEC)
    assert code == 200 and response["state"] == "contained" and response["sessions"]["stopped"] == 1
    assert RUNTIME_ARN in world.cell.policies
    # The step fails and names the setting; the result is partial; nothing was sent.
    assert background_step(response) == {
        "id": "background",
        "label": "Stop remaining sessions in the background",
        "status": "failed",
        "detail": (
            "Background sweeps could not be scheduled: the setting PORTAL_SWEEP_QUEUE_URL is not an Amazon SQS "
            "queue address. Contain again once it is corrected."
        ),
    }
    assert response["partial"] is True and response["sweeps_scheduled_in_seconds"] == []
    assert world.queue.messages == [] and world.queue_regions == []
    assert response["reason"].endswith("Contain again once it is corrected.]")
    result = [e for e in world.dynamo.events() if e["phase"] == "result"][-1]
    assert "sweeps_scheduled" not in result and "PORTAL_SWEEP_QUEUE_URL" in result["reason"]
    # The function says so at error level.
    assert any(
        record.levelname == "ERROR" and "PORTAL_SWEEP_QUEUE_URL" in record.getMessage() for record in caplog.records
    )
    # A release is not touched by the setting at all.
    code, released = world.post("release", claims=PAT)
    assert code == 200 and released["state"] == "not_contained" and background_step(released) is None
    # Corrected, the next contain schedules its sweeps.
    monkeypatch.setenv("PORTAL_SWEEP_QUEUE_URL", QUEUE_URL)
    code, again = world.post("contain", claims=SEC)
    assert code == 200 and background_step(again)["status"] == "scheduled" and again["partial"] is False


# --- the sweeper ---------------------------------------------------------------------------------


class Time:
    """A clock the test moves: sleeping advances it."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def time_of_day() -> dt.datetime:
    """The time of day as the events of a test are stamped with it (a test can set that clock)."""
    return dt.datetime.fromisoformat(audit_writer.now_stamp().replace("Z", "+00:00"))


def at(moment: dt.datetime) -> str:
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


class Run:
    """A sweeper over the world's cell and audit table.

    Its time of day runs ``minutes_later`` ahead of the test's: twenty
    minutes unless a test says otherwise, so that every sweep of a contain
    made a moment ago is due.
    """

    def __init__(
        self, world: World, env: dict[str, str] | None = None, *, minutes_later: float = 20.0, **options: Any
    ) -> None:
        self.world = world
        self.time = Time()
        self.started = self.time.now
        self.budget = 900.0
        self.minutes_later = minutes_later
        self.sweeper = sweeper.Sweeper(
            load_sweeper_settings(env or SWEEPER_ENV),
            world.assumed,
            world.dynamo,
            sleep=self.time.sleep,
            clock=self.time.clock,
            now=self.now,
            **options,
        )

    def now(self) -> dt.datetime:
        return time_of_day() + dt.timedelta(minutes=self.minutes_later)

    def remaining(self) -> float:
        return self.budget - (self.time.now - self.started)

    def handle(self, raw: Any) -> str:
        return self.sweeper.handle(raw, self.remaining)

    def sweep_events(self, key: str = KEY) -> list[dict[str, str]]:
        return [e for e in self.world.dynamo.events() if e["pk"] == key and e["action"] == "sweep"]


def on_record(
    world: World,
    request_id: str = REQUEST_ID,
    *,
    arn: str = RUNTIME_ARN,
    minutes_ago: float = 40.0,
    outcome: str = "allowed",
    scheduled: int | None = 3,
    result: bool = True,
    intent: bool = True,
    subject: str = "sec-1",
    action: str = "contain",
    numbers: str | None = ...,  # type: ignore[assignment]
    agent_id: str = RECORD_ID,
    prefix: str | None = None,
) -> str:
    """Put a contain into the Runtime's history, as the containment function writes one. Returns its request id.

    Its intent, and one second later its result with the sweeps it
    scheduled: all three when it scheduled three, the second and third when
    it scheduled two (``numbers`` says otherwise; ``None`` is a result
    written before results listed their sweeps). Forty minutes ago unless a
    test says otherwise: old enough that its sweeps are due and that it
    holds no later contain back. The events go straight into the table, so
    the table's count of writes stays the sweeper's own.

    They go into the range the function writes them into: a contain that
    changed nothing (``unchanged``) among the events that cannot change who
    holds the containment, every other among those that can. ``prefix``
    says otherwise: ``EVENT#`` for a history written before there were two
    ranges.
    """
    if prefix is None:
        prefix = audit_reader.OTHER_PREFIX if outcome == "unchanged" else audit_reader.EVENT_PREFIX
    if numbers is ...:
        numbers = {3: "1,2,3", 2: "2,3", 1: "2"}.get(scheduled or 0)
    began = time_of_day() - dt.timedelta(minutes=minutes_ago)
    common = {
        "request_id": request_id,
        "action": action,
        "actor_subject": subject,
        "actor_label": f"{subject}@example.com",
        "actor_role": "security",
        "tenant_id": "ws1",
        "agent_id": agent_id,
        "runtime_arn": arn,
    }
    written = []
    if intent:
        written.append(
            AuditEvent(
                event_id=f"intent-{request_id}", at=at(began), phase="intent", outcome="allowed", reason="x", **common
            )
        )
    if result:
        counts = {"sessions_found": 0, "sessions_stopped": 0, "sessions_failed": 0} if action == "contain" else {}
        written.append(
            AuditEvent(
                event_id=f"result-{request_id}",
                at=at(began + dt.timedelta(seconds=1)),
                phase="result",
                outcome=outcome,
                reason="x",
                sweeps_scheduled=scheduled if action == "contain" else None,
                sweeps_scheduled_numbers=numbers if action == "contain" else None,
                **counts,
                **common,
            )
        )
    key = audit_reader.containment_key(arn)
    for event in written:
        item = {"pk": {"S": key}, "sk": {"S": audit_reader.event_sort_key(event, prefix)}}
        item.update({name: {"S": str(value)} for name, value in event.model_dump().items() if value not in (None, "")})
        world.dynamo.items[(key, item["sk"]["S"])] = item
    return request_id


def contained(world: World, arn: str = RUNTIME_ARN, **contain: Any) -> str:
    """Contain the Runtime as a contain does, and return the contain's request id.

    The portal's statement goes into the Runtime's policy and the contain
    into its history (``on_record``), so that a sweep message with that
    request id belongs to a contain on record.
    """
    world.cell.policies[arn] = containment_policy.with_containment(None, arn, containment_policy.ALL_INVOKE_ACTIONS)
    return on_record(world, arn=arn, **contain)


def again(world: World, *, minutes_ago: float = 35.0, **contain: Any) -> str:
    """One more contain of the contained Runtime on record (``unchanged``), with sweeps of its own."""
    request_id = f"{len(world.dynamo.items):08x}-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
    return on_record(world, request_id, minutes_ago=minutes_ago, outcome="unchanged", subject="pat-1", **contain)


def test_a_sweep_stops_the_sessions_and_writes_one_event(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b"), session_stream("c")]
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert sorted(world.cell.stopped) == sorted((sid(n), "DEFAULT") for n in "abc")
    (event,) = run.sweep_events()
    assert event == {
        "pk": KEY,  # the Runtime's containment history
        "sk": event["sk"],
        "event_id": event["event_id"],
        "request_id": REQUEST_ID,  # the contain's request id
        "at": event["at"],
        "phase": "result",
        "action": "sweep",
        "outcome": "allowed",
        "reason": (
            "Background sweep 2: 3 session(s) found, 3 stopped, 0 had already ended. No session was left running."
        ),
        "actor_subject": "agent-factory-portal",
        "actor_label": "Agent Factory Portal (background sweep)",
        "actor_role": "system",
        "tenant_id": "ws1",
        "agent_id": RECORD_ID,
        "runtime_arn": RUNTIME_ARN,
        "status_before": "contained",
        "status_after": "contained",
        "sessions_found": "3",
        "sessions_stopped": "3",
        "sessions_not_active": "0",
        "sessions_failed": "0",
        "sweep": "2",
        "duration_ms": event["duration_ms"],
        "detail": "ok",
    }
    assert int(event["duration_ms"]) >= 0
    # Beside the event, one item that is not an event: the claim that makes this sweep run once.
    (claim,) = world.dynamo.claims()
    assert claim == {
        "pk": KEY,
        "sk": f"SWEEP#{REQUEST_ID}#2",
        "kind": "sweep_claim",
        "claim_id": claim["claim_id"],  # which attempt wrote it
        "at": claim["at"],
        "request_id": REQUEST_ID,
        "sweep": "2",
        "runtime_arn": RUNTIME_ARN,
    }
    assert claim["at"] <= event["at"]  # claimed before anything was done in the cell
    # It used the cell's containment role with the cell's external id, never a role from the message.
    assert {(role, external) for role, external, _, _ in world.cell.assumed} == {
        (test_containment.CONTAINMENT_ROLE, "portal-ext-id")
    }
    # It read the policy and stopped sessions; it never wrote or deleted a policy.
    assert not {"put_resource_policy", "delete_resource_policy"} & set(world.cell.calls)


def test_a_sweep_that_finds_nothing_running_says_the_agent_was_quiet(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    world.cell.stop_errors = {sid("a"): "ResourceNotFoundException", sid("b"): "ResourceNotFoundException"}
    run = Run(world)
    assert run.handle(sweeps.encode(message(sweep=3))) == "allowed"
    (event,) = run.sweep_events()
    assert (event["sessions_found"], event["sessions_stopped"], event["sessions_not_active"]) == ("2", "0", "2")
    assert event["reason"] == (
        "Background sweep 3: 2 session(s) found, 0 stopped, 2 had already ended. No session was running."
    )
    # No session of the window at all is quiet too.
    world.cell.streams.clear()
    assert run.handle(sweeps.encode(message(sweep=3, request_id=again(world)))) == "allowed"
    assert run.sweep_events()[-1]["reason"] == (
        "Background sweep 3 found no session of the lookback window. No session was running."
    )


def test_a_sweep_has_no_limit_on_the_number_of_sessions_and_keeps_to_its_rate(world):
    total = 2_500
    assert total > logs.MAX_SESSIONS  # the request's limit is far below what is there
    world.cell.streams[log_group()] = [session_stream(f"s{i:05d}", minutes_ago=1 + i / 10) for i in range(total)]
    contained(world)
    run = Run(world)
    stopped_at_each_pause: list[int] = []
    sleep = run.time.sleep
    run.sweeper.sleep = lambda seconds: (stopped_at_each_pause.append(len(world.cell.stopped)), sleep(seconds))[1]
    assert run.handle(sweeps.encode(message(sweep=1))) == "allowed"

    assert len(world.cell.stopped) == total  # every page was read: 50 pages of 50
    assert len(world.cell.stream_requests) == total // world.cell.stream_page_size
    (event,) = run.sweep_events()
    assert (event["sessions_found"], event["sessions_stopped"], event["detail"]) == (str(total), str(total), "ok")
    # Most recent first.
    assert world.cell.stopped[0][0] in {sid(f"s{i:05d}") for i in range(20)}
    # At most 20 stops in any one second, and one batch a second.
    per_slot = [b - a for a, b in zip([0, *stopped_at_each_pause], stopped_at_each_pause, strict=False)]
    assert max(per_slot) == 20 and len(stopped_at_each_pause) == total // 20 - 1
    assert all(pause == pytest.approx(1.0) for pause in run.time.sleeps)
    # How long it took is in the event, so the rate per thousand sessions can be measured.
    assert int(event["duration_ms"]) == pytest.approx((total // 20 - 1) * 1000, abs=5)


def test_a_sweep_stops_nothing_when_the_agent_was_released_meanwhile(world):
    world.cell.streams[log_group()] = [session_stream("a")]
    on_record(world)  # the contain is on record; its statement is not in the policy any more
    run = Run(world)
    # Released: the policy is gone.
    assert run.handle(sweeps.encode(message())) == "skipped"
    # Released, with other statements still in the policy.
    world.cell.policies[RUNTIME_ARN] = json.dumps(
        {"Version": "2012-10-17", "Statement": test_containment.OTHER_STATEMENTS}
    )
    assert run.handle(sweeps.encode(message(sweep=3))) == "skipped"

    assert world.cell.stopped == []
    assert "describe_log_streams" not in world.cell.calls and "stop_runtime_session" not in world.cell.calls
    first, second = run.sweep_events()
    assert (first["outcome"], first["status_before"], first["status_after"]) == (
        "skipped",
        "not_contained",
        "not_contained",
    )
    assert first["reason"] == "Background sweep 2 stopped nothing: the Runtime is no longer contained."
    assert second["sweep"] == "3" and "sessions_found" not in first


def test_a_release_between_the_contain_and_its_sweeps_makes_them_harmless(world):
    world.cell.streams[log_group()] = [session_stream("a")]
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.streams[log_group()].append(session_stream("started-after-the-release"))
    assert world.post("release", claims=PAT)[0] == 200
    stopped_by_the_contain = list(world.cell.stopped)
    run = Run(world)
    outcomes = [run.handle(sent["MessageBody"]) for sent in world.queue.messages]
    assert outcomes == ["skipped", "skipped"]
    assert world.cell.stopped == stopped_by_the_contain  # the new session of the released agent is untouched
    assert [e["outcome"] for e in run.sweep_events()] == ["skipped", "skipped"]


def test_a_release_while_a_sweep_runs_ends_the_sweep(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream(f"s{i:03d}", minutes_ago=1 + i / 10) for i in range(300)]
    run = Run(world, stops_per_second=5)  # sixty seconds of stops
    sleep = run.time.sleep

    def release_after_ten_seconds(seconds: float) -> None:
        sleep(seconds)
        if run.time.now - run.started >= 10:
            world.cell.policies.clear()  # the agent is released while the sweep runs

    run.sweeper.sleep = release_after_ten_seconds
    assert run.handle(sweeps.encode(message())) == "skipped"
    # It read the policy again after half a minute, saw the release, and stopped there.
    assert world.cell.calls.count("get_resource_policy") == 2
    assert len(world.cell.stopped) == 5 * int(sweeper.RECHECK_SECONDS) == 150
    (event,) = run.sweep_events()
    assert (event["outcome"], event["status_before"], event["status_after"]) == (
        "skipped",
        "contained",
        "not_contained",
    )
    assert (event["sessions_found"], event["sessions_stopped"], event["sessions_failed"]) == ("300", "150", "0")
    assert event["reason"] == (
        "Background sweep 2 ended early: the Runtime was released while the sweep ran. "
        "150 session(s) had been stopped, 0 had already ended and 150 were left as they were."
    )


def test_a_sweep_goes_on_when_the_policy_cannot_be_read_again(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream(f"s{i:03d}", minutes_ago=1 + i / 10) for i in range(200)]
    run = Run(world, stops_per_second=5)  # forty seconds of stops
    assert sweeper.RECHECK_SECONDS == 30
    sleep = run.time.sleep

    def break_the_next_read(seconds: float) -> None:
        sleep(seconds)
        if "get_resource_policy" not in world.cell.fail and world.cell.calls.count("get_resource_policy") == 1:
            world.cell.fail["get_resource_policy"] = "ThrottlingException"

    run.sweeper.sleep = break_the_next_read
    # It was contained when the sweep began, and nothing says it was released.
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert len(world.cell.stopped) == 200 and world.cell.calls.count("get_resource_policy") == 2


def test_a_short_sweep_reads_the_policy_once(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream(f"s{i:03d}") for i in range(50)]
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert world.cell.calls.count("get_resource_policy") == 1


def test_a_sweep_that_cannot_read_the_policy_stops_nothing(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    world.cell.fail["get_resource_policy"] = "AccessDeniedException"
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "failed"
    assert world.cell.stopped == []
    (event,) = run.sweep_events()
    assert (event["outcome"], event["status_after"]) == ("failed", "unknown")
    assert "could not be read (AccessDeniedException)" in event["reason"]


def test_a_sweep_that_cannot_list_sessions_is_recorded_as_failed(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    world.cell.fail["describe_log_streams"] = "AccessDeniedException"
    world.cell.fail["start_query"] = "AccessDeniedException"
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "failed"
    (event,) = run.sweep_events()
    assert event["outcome"] == "failed" and event["detail"].startswith("sessions could not be listed (")
    assert "sessions_found" not in event and world.cell.stopped == []


def test_a_sweep_that_cannot_stop_everything_is_recorded_as_failed(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b"), session_stream("c")]
    world.cell.stop_errors = {sid("b"): "AccessDeniedException", sid("c"): "ResourceNotFoundException"}
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "failed"
    (event,) = run.sweep_events()
    assert (event["sessions_found"], event["sessions_stopped"], event["sessions_not_active"]) == ("3", "1", "1")
    assert event["sessions_failed"] == "1"
    assert event["reason"] == (
        "Background sweep 2: 3 session(s) found, 1 stopped, 1 had already ended, "
        "1 could not be stopped (AccessDeniedException)."
    )


class FlakyCell(FakeCell):
    """A cell whose stops are pushed back a number of times before they succeed, or whose stream listing breaks."""

    def __init__(self) -> None:
        super().__init__()
        self.push_back: dict[str, list[str]] = {}
        self.fail_stream_request: int | None = None  # the 1-based request for stream names that is refused

    def describe_log_streams(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail_stream_request == len(self.stream_requests) + 1:
            self.stream_requests.append(kwargs)
            raise client_error("ThrottlingException", "DescribeLogStreams")
        return super().describe_log_streams(**kwargs)

    def stop_runtime_session(self, runtimeSessionId: str, agentRuntimeArn: str, qualifier: str) -> dict[str, Any]:  # noqa: N803
        codes = self.push_back.get(runtimeSessionId)
        if codes:
            self.calls.append("stop_runtime_session")
            raise client_error(codes.pop(0), "StopRuntimeSession")
        return super().stop_runtime_session(runtimeSessionId, agentRuntimeArn, qualifier)


def flaky(world: World) -> FlakyCell:
    cell = FlakyCell()
    world.cell = world.assumed.cell = cell
    return cell


class ExpiringClients:
    """Hands out clients whose credentials end, as an assumed role's do, and new ones near that end."""

    LIFETIME, MARGIN = 60.0, 20.0

    def __init__(self, cell: FakeCell, clock: Any) -> None:
        self.cell, self.clock = cell, clock
        self.issued: list[float] = []

    def assumed(
        self, role_arn: str, external_id: str | None, region: str, service: str, session_policy: str | None = None
    ) -> Any:
        now = self.clock()
        if not self.issued or now >= self.issued[-1] + self.LIFETIME - self.MARGIN:
            self.issued.append(now)
        return _Expiring(self.cell, self.issued[-1] + self.LIFETIME, self.clock)


class _Expiring:
    def __init__(self, cell: FakeCell, expires: float, clock: Any) -> None:
        self._cell, self._expires, self._clock = cell, expires, clock

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._cell, name)

        def call(*args: Any, **kwargs: Any) -> Any:
            if self._clock() >= self._expires:
                raise client_error("ExpiredTokenException", name)
            return target(*args, **kwargs)

        return call


def test_a_sweep_that_outlasts_its_credentials_gets_new_ones(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream(f"s{i:03d}", minutes_ago=1 + i / 10) for i in range(500)]
    run = Run(world, stops_per_second=5)  # a hundred seconds of stops, with credentials that last sixty
    clients = ExpiringClients(world.cell, run.time.clock)
    run.sweeper.clients = clients
    assert run.handle(sweeps.encode(message())) == "allowed"
    (event,) = run.sweep_events()
    assert (event["sessions_stopped"], event["sessions_failed"]) == ("500", "0")
    assert len(clients.issued) >= 2  # the role was assumed again part way


def test_a_stop_the_service_pushes_back_is_tried_again_with_a_longer_pause(world):
    cell = flaky(world)
    contained(world)
    cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    cell.push_back[sid("a")] = ["ThrottlingException", "ServiceQuotaExceededException"]
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert sorted(cell.stopped) == [(sid("a"), "DEFAULT"), (sid("b"), "DEFAULT")]
    (event,) = run.sweep_events()
    assert (event["sessions_stopped"], event["sessions_failed"]) == ("2", "0")
    # Each batch that was pushed back is followed by a longer pause: one second, then two.
    assert [round(pause) for pause in run.time.sleeps] == [2, 3]


def test_a_stop_that_keeps_being_pushed_back_is_given_up_as_failed(world):
    cell = flaky(world)
    contained(world)
    cell.streams[log_group()] = [session_stream("a")]
    cell.push_back[sid("a")] = ["ThrottlingException"] * 10
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "failed"
    (event,) = run.sweep_events()
    assert (event["sessions_stopped"], event["sessions_failed"]) == ("0", "1")
    assert "1 could not be stopped (ThrottlingException)" in event["reason"]
    assert cell.calls.count("stop_runtime_session") == 1 + sweeper.MAX_RETRIES_PER_SESSION


def test_a_sweep_stops_when_the_functions_time_runs_out_and_says_what_is_left(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream(f"s{i:03d}", minutes_ago=1 + i / 10) for i in range(100)]
    run = Run(world)
    run.budget = sweeper.RESERVE_SECONDS + 2.5  # room for three batches of 20
    assert run.handle(sweeps.encode(message())) == "failed"
    (event,) = run.sweep_events()
    assert (event["sessions_found"], event["sessions_stopped"], event["sessions_failed"]) == ("100", "60", "40")
    assert event["reason"].endswith("40 were not attempted before the function's time ran out.")
    assert len(world.cell.stopped) == 60


def test_a_sweep_that_runs_out_of_time_while_listing_never_reads_as_complete(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream(f"s{i:03d}", minutes_ago=1 + i / 10) for i in range(120)]
    run = Run(world)

    def remaining() -> float:
        # Time is short after the second page of stream names.
        return 900.0 if len(world.cell.stream_requests) < 2 else sweeper.RESERVE_SECONDS - 1

    assert run.sweeper.handle(sweeps.encode(message()), remaining) == "failed"
    (event,) = run.sweep_events()
    assert event["sessions_found"] == "100" and len(world.cell.stream_requests) == 2
    assert event["detail"] == (
        "ok; not every session could be listed in the time the sweep had, so more sessions may be running"
    )
    assert "Session discovery was incomplete" in event["reason"]
    assert event["sessions_failed"] == "100" and world.cell.stopped == []  # no time was left to stop them


def test_a_sweep_whose_stream_listing_breaks_part_way_stops_what_it_has_listed(world):
    cell = flaky(world)
    contained(world)
    cell.streams[log_group()] = [session_stream(f"s{i:03d}", minutes_ago=1 + i / 10) for i in range(120)]
    cell.fail_stream_request = 3
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "failed"  # not complete, so never proof of quiet
    assert len(cell.stopped) == 100  # the two pages it read
    (event,) = run.sweep_events()
    assert (event["sessions_found"], event["sessions_stopped"], event["sessions_failed"]) == ("100", "100", "0")
    assert event["detail"] == (
        "ok; log streams could not be listed to the end (ThrottlingException), so more sessions may be running"
    )
    # A request keeps the rule it had: a source that breaks is a source that failed.
    cell.stream_requests.clear()
    cell.fail_stream_request = 3
    found = containment.discover_sessions(cell, cell, RUNTIME_ARN)
    assert (found.failed, found.sessions) == (True, [])


def test_a_sweep_asks_the_spans_for_more_sessions_than_a_request_and_says_when_that_was_not_all(world, monkeypatch):
    assert (logs.MAX_SESSIONS, logs.MAX_SWEEP_SESSIONS) == (1000, 10_000)
    contained(world)
    world.cell.sessions = [session_row(sid(f"span{i}")) for i in range(3)]
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert world.cell.query["queryString"].endswith("| limit 10000")
    assert world.post("contain")[0] == 200
    assert world.cell.query["queryString"].endswith("| limit 1000")  # a request asks as before

    # As many rows as the query may return: there may be more, so the sweep is not complete.
    monkeypatch.setattr(logs, "MAX_SWEEP_SESSIONS", 3)
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "failed"  # a sweep of that request
    event = run.sweep_events()[-1]
    assert event["detail"] == (
        "ok; the spans query returned as many sessions as it may (3), so more sessions may be running"
    )
    assert event["sessions_found"] == "3" and event["sessions_failed"] == "0"


@pytest.mark.parametrize("status", ["Timeout", "Failed", "Cancelled"])
def test_a_spans_query_that_did_not_finish_is_never_read_as_complete_by_a_sweep(world, status):
    contained(world)
    world.cell.sessions = [session_row(sid("partial"))]
    world.cell.query_status = status
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "failed"
    (event,) = run.sweep_events()
    assert world.cell.stopped == [(sid("partial"), "DEFAULT")]  # what it did return is stopped
    assert event["detail"] == (
        f"ok; the spans query did not finish (query ended with status {status}), so more sessions may be running"
    )
    assert event["reason"].endswith(
        f"Session discovery was incomplete: the spans query did not finish (query ended with status {status}), "
        "so more sessions may be running."
    )


def test_a_sweep_waits_longer_for_the_spans_than_a_request_but_never_past_its_own_time(world, monkeypatch):
    waits: list[float] = []
    real = logs.run_queries

    def run_queries(*args: Any, **kwargs: Any) -> Any:
        waits.append(kwargs["max_wait_seconds"])
        return real(*args, **kwargs)

    monkeypatch.setattr(logs, "run_queries", run_queries)
    contained(world)
    run = Run(world)
    assert run.handle(sweeps.encode(message())) == "allowed"
    run.budget = sweeper.RESERVE_SECONDS + 12
    run.started = run.time.now
    assert run.handle(sweeps.encode(message(request_id=again(world)))) == "allowed"
    assert world.post("contain")[0] == 200
    assert waits == [sweeper.SPANS_WAIT_SECONDS, 12.0, containment.SPANS_WAIT_SECONDS] == [60.0, 12.0, 8.0]


def test_spans_are_read_only_when_the_cell_opts_in(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("in-logs")]
    world.cell.sessions = [session_row(sid("in-spans"))]
    run = Run(world)  # the test cell sets containmentSpans
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert sorted(s for s, _ in world.cell.stopped) == sorted([sid("in-logs"), sid("in-spans")])
    assert "start_query" in world.cell.calls

    world.cell.calls.clear()
    world.cell.stopped.clear()
    without = [{k: v for k, v in CELLS[0].items() if k != "containmentSpans"}, CELLS[1]]
    quiet = Run(world, {**SWEEPER_ENV, "PORTAL_CELLS": json.dumps(without)})
    assert quiet.handle(sweeps.encode(message(request_id=again(world)))) == "allowed"
    assert [s for s, _ in world.cell.stopped] == [sid("in-logs")]
    assert "start_query" not in world.cell.calls and "get_query_results" not in world.cell.calls


# --- a message the sweeper cannot validate ---------------------------------------------------------


@pytest.mark.parametrize("raw", [None, "junk", "{}", "[]", body(runtime_arn="arn:aws:iam::111111111111:role/x")])
def test_a_message_with_no_usable_runtime_is_logged_and_dropped(world, raw):
    contained(world)
    before = dict(world.dynamo.items)
    run = Run(world)
    assert run.handle(raw) == "invalid"  # it returns, so the message is deleted and never retried
    assert world.dynamo.items == before and world.dynamo.calls == []  # nothing read, nothing written
    assert world.cell.calls == [] and world.cell.assumed == []


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (body(sweep=7), "sweep is not 1, 2 or 3"),
        (body(agent_id="other_agent-ZyXwVu9876"), "agent_id is neither a registration id nor this Runtime's id"),
        (body(extra="x"), "the body does not hold exactly the expected fields"),
        (body(request_id="'; drop table --"), "request_id is not a request id"),
    ],
)
def test_an_invalid_message_for_a_known_runtime_is_logged_and_neither_recorded_nor_run(world, raw, reason, caplog):
    """Whoever can invoke the function could otherwise add an event to that Runtime's history with every message."""
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    before = dict(world.dynamo.items)
    run = Run(world)
    with caplog.at_level("ERROR", logger="portal_api.actions.sweeper"):
        for _ in range(50):
            assert run.handle(raw) == "invalid"
    assert world.cell.calls == [] and world.cell.stopped == []  # nothing was read or stopped in the cell
    # Not one event, however often it is sent, and the table was not even asked.
    assert world.dynamo.items == before and world.dynamo.calls == [] and run.sweep_events() == []
    # The function's log says why, in the sweeper's own words. Nothing the message said is in it.
    assert caplog.messages == [f"Sweep message refused, nothing written: {reason}"] * 50
    assert "drop table" not in caplog.text and RUNTIME_ARN not in caplog.text


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:bedrock-agentcore:eu-west-1:888888888888:runtime/far_agent-QwErTy5678",  # no cell there
        f"arn:aws:bedrock-agentcore:us-east-1:{CELL_ACCOUNT}:runtime/travel_agent-AbCdEf1234",  # another Region
        f"arn:aws:bedrock-agentcore:eu-west-1:{OTHER_ACCOUNT}:runtime/claims_agent-QqQqQq1111",  # no containment role
    ],
)
def test_a_runtime_outside_the_cells_that_opted_in_is_never_swept_or_recorded(world, arn):
    world.cell.policies[arn] = containment_policy.with_containment(None, arn, containment_policy.ALL_INVOKE_ACTIONS)
    run = Run(world)
    for raw in (
        sweeps.encode(message(runtime_arn=arn, agent_id=arn.rsplit("/", 1)[-1])),
        body(runtime_arn=arn, sweep=9),
    ):
        assert run.handle(raw) == "invalid"
    # Not even an audit event: its key would be whatever the sender chose.
    assert world.dynamo.items == {} and world.cell.assumed == [] and world.cell.calls == []


def test_a_sweep_that_cannot_be_recorded_comes_back_and_is_not_run_a_second_time(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    world.dynamo.fail_put_numbers = {2}  # the claim is written, the event is not
    run = Run(world)
    with pytest.raises(sweeper.SweepNotRecorded):
        run.handle(sweeps.encode(message()))
    assert world.cell.stopped == [(sid("a"), "DEFAULT")] and run.sweep_events() == []
    # Delivered again, it is not run again: the claim says that this sweep was started. It fails,
    # so the message ends in the dead-letter queue, where it is noticed.
    world.cell.calls.clear()
    for _ in range(3):
        with pytest.raises(sweeper.SweepNotFinished):
            run.handle(sweeps.encode(message()))
    assert world.cell.calls == [] and run.sweep_events() == [] and len(world.dynamo.claims()) == 1


def test_a_sweep_that_cannot_be_claimed_comes_back_and_is_run_then(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    world.dynamo.fail_put_numbers = {1}  # the claim itself cannot be written
    run = Run(world)
    with pytest.raises(sweeper.SweepNotVerified):
        run.handle(sweeps.encode(message()))
    # Nothing was done in the cell and nothing is in the table: it is not known whether it may run.
    assert world.cell.calls == [] and world.dynamo.claims() == [] and run.sweep_events() == []
    # Delivered again, it is run.
    assert run.handle(sweeps.encode(message())) == "allowed"
    assert world.cell.stopped == [(sid("a"), "DEFAULT")] and len(run.sweep_events()) == 1


def test_a_history_that_cannot_be_read_stops_the_sweep_and_the_message_comes_back(world):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    world.dynamo.fail_query = True
    run = Run(world)
    with pytest.raises(sweeper.SweepNotVerified):
        run.handle(sweeps.encode(message()))
    assert world.cell.calls == [] and world.dynamo.claims() == [] and run.sweep_events() == []
    world.dynamo.fail_query = False
    assert run.handle(sweeps.encode(message())) == "allowed"


# --- the function's entry point ------------------------------------------------------------------


class Context:
    def get_remaining_time_in_millis(self) -> int:
        return 900_000


@pytest.fixture
def entry(world, monkeypatch):
    """The sweeper function's handler over the world's cell and audit table."""

    class Clients:
        def __init__(self, home_region: str, session_name: str) -> None:
            # The sweeper assumes a cell's role under a name of its own, so the cell's trail tells
            # its calls from the containment function's.
            assert (home_region, session_name) == ("eu-west-1", "portal-sweeper")

        def platform(self, service: str, region: str) -> Any:
            assert (service, region) == ("dynamodb", "eu-west-1")
            return world.dynamo

        def assumed(self, *args: Any, **kwargs: Any) -> Any:
            return world.assumed.assumed(*args, **kwargs)

    monkeypatch.setattr(sweeper, "AwsClients", Clients)
    monkeypatch.setattr(sweeper, "_clients", None)
    monkeypatch.setenv("PORTAL_ACTION_ROLE", "sweeper")
    import sweep_handler

    return sweep_handler.handler


def test_the_function_runs_the_one_message_it_is_handed(world, entry):
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    assert entry({"Records": [{"eventSource": "aws:sqs", "body": sweeps.encode(message())}]}, Context()) == {
        "handled": 1
    }
    assert world.cell.stopped == [(sid("a"), "DEFAULT")]
    assert [e["outcome"] for e in world.dynamo.events() if e.get("action") == "sweep"] == ["allowed"]
    # One record that is not a message is one invalid message: handled, and nothing run.
    for odd in ({"body": "junk"}, {}, "not a record", None):
        assert entry({"Records": [odd]}, Context()) == {"handled": 1}
    assert len(world.cell.stopped) == 1


def test_an_invocation_with_any_other_number_of_records_runs_nothing(world, entry, caplog):
    """The queue hands over one message at a time. Several records would share one invocation's
    time: a long sweep of one Runtime put first would leave a due sweep of another none."""
    contained(world)
    world.cell.streams[log_group()] = [session_stream("a")]
    before = dict(world.dynamo.items)
    due = {"eventSource": "aws:sqs", "body": sweeps.encode(message())}
    with caplog.at_level("ERROR", logger="portal_api.actions.sweeper"):
        assert entry({"Records": [due, due]}, Context()) == {"handled": 0}
        assert entry({"Records": [{"body": "junk"}, due]}, Context()) == {"handled": 0}
        # Whoever can invoke the function chooses the event: anything else is nothing to do either.
        for odd in ({}, {"Records": []}, {"Records": "junk"}, {"Records": {"body": "x"}}, None, "junk", []):
            assert entry(odd, Context()) == {"handled": 0}
    # Nothing was read, claimed, written or stopped, and the function's log says why.
    assert world.cell.calls == [] and world.cell.stopped == []
    assert world.dynamo.items == before and world.dynamo.calls == []
    assert caplog.messages[:2] == ["Sweeper invoked with 2 records, not exactly one: nothing was run"] * 2
    assert "Sweeper invoked with no records, not exactly one: nothing was run" in caplog.messages
    # The same message alone is run.
    assert entry({"Records": [due]}, Context()) == {"handled": 1}
    assert world.cell.stopped == [(sid("a"), "DEFAULT")]


@pytest.mark.parametrize("role", ["containment", "registrar", "", None])
def test_a_mis_wired_sweeper_does_nothing_and_fails_so_that_it_is_noticed(world, entry, monkeypatch, role):
    if role is None:
        monkeypatch.delenv("PORTAL_ACTION_ROLE")
    else:
        monkeypatch.setenv("PORTAL_ACTION_ROLE", role)
    contained(world)
    before = dict(world.dynamo.items)
    with pytest.raises(ConfigError, match="PORTAL_ACTION_ROLE"):
        entry({"Records": [{"body": sweeps.encode(message())}]}, Context())
    assert world.cell.calls == [] and world.dynamo.items == before and world.dynamo.calls == []


def test_the_sweeper_needs_only_its_own_settings():
    env = {
        "PORTAL_ACTION_ROLE": "sweeper",
        "PORTAL_ENV": "nonprod",
        "PORTAL_REGISTRY_REGION": "eu-west-1",
        "PORTAL_CELLS": BASE_ENV["PORTAL_CELLS"],
        "PORTAL_AUDIT_TABLE": BASE_ENV["PORTAL_AUDIT_TABLE"],
    }
    settings = load_sweeper_settings(env)
    assert (settings.env, settings.registry_region, len(settings.cells)) == ("nonprod", "eu-west-1", 2)
    for missing in ("PORTAL_ENV", "PORTAL_REGISTRY_REGION", "PORTAL_CELLS", "PORTAL_AUDIT_TABLE"):
        with pytest.raises(ConfigError, match=missing):
            load_sweeper_settings({k: v for k, v in env.items() if k != missing})


# --- sweeps and the two-person rule ----------------------------------------------------------------


def test_a_sweep_never_counts_as_a_contain_or_a_release(world):
    world.cell.streams[log_group()] = [session_stream("a")]
    assert world.post("contain", claims=SEC)[0] == 200
    run = Run(world)
    for sent in world.queue.messages:
        assert run.handle(sent["MessageBody"]) == "allowed"
    history = audit_reader.read_history(world.dynamo, BASE_ENV["PORTAL_AUDIT_TABLE"], RUNTIME_ARN)
    events = history.events
    assert [e.action for e in events][:2] == ["sweep", "sweep"]
    holder = history.holder.event
    assert holder is not None and (holder.action, holder.actor_subject) == ("contain", "sec-1")
    # The sweeps are not among the events a release reads to find that person: the contain's two are.
    assert [(e["action"], e["phase"]) for e in world.dynamo.settling()] == [
        ("contain", "intent"),
        ("contain", "result"),
    ]
    assert [e["action"] for e in world.dynamo.others()] == ["sweep", "sweep"]
    # A history written before there were two ranges holds them together, and reads the same.
    assert audit_reader.container(events) == holder
    # The person who contained it still cannot release it; another person can.
    code, response = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in response["detail"]
    assert world.post("release", claims=PAT)[0] == 200


def test_a_contain_whose_result_was_lost_still_has_its_holder_after_its_sweeps(world, read):
    """A sweep carries its contain's request id. It must not be taken for that contain's result."""
    world.cell.streams[log_group()] = [session_stream("a")]
    world.dynamo.fail_put_numbers = {2}  # the intent is written, the result is not
    code, response = world.post("contain", claims=SEC)
    assert code == 200 and response["audit_complete"] is False
    assert world.queue.sweeps() == [(2, 120), (3, 900)]  # scheduled before the write that failed
    assert [(e["action"], e["phase"]) for e in world.dynamo.events()] == [("contain", "intent")]

    run = Run(world)
    for sent in world.queue.messages:
        assert run.handle(sent["MessageBody"]) == "allowed"
    history = audit_reader.read_history(world.dynamo, BASE_ENV["PORTAL_AUDIT_TABLE"], RUNTIME_ARN)
    events = history.events
    assert [(e.action, e.phase) for e in events] == [("sweep", "result"), ("sweep", "result"), ("contain", "intent")]
    assert {e.request_id for e in events} == {response["request_id"]}
    # The intent names the holder, as it did before any sweep ran.
    holder = history.holder.event
    assert holder is not None and (holder.action, holder.phase, holder.actor_subject) == ("contain", "intent", "sec-1")
    assert [(e["action"], e["phase"]) for e in world.dynamo.settling()] == [("contain", "intent")]
    # A history written before there were two ranges holds the sweeps beside it, and reads the same.
    assert audit_reader.container(events) == holder == audit_reader.container(events[2:])

    view = read(world.record_id, SEC)[1]
    assert (view["state"], view["contained_by_me"], view["contained_by"]) == ("contained", True, "sec-1")
    assert view["contained_at"] == holder.at
    assert view["partial"] is True  # the request's own result is not known, whatever the sweeps found
    # So the two-person rule still holds for the person who contained it.
    code, refused = world.post("release", claims=SEC)
    assert code == 403 and "CON-03-N" in refused["detail"]
    assert world.post("release", claims=PAT)[0] == 200


def test_partial_describes_the_contain_request_whatever_its_sweeps_find(world, read, monkeypatch):
    clock = {"t": 0.0}
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: stamp(clock["t"]))
    # A contain that left a session running is partial, and stays so after a sweep that found nothing wrong.
    world.cell.streams[log_group()] = [session_stream("a"), session_stream("b")]
    world.cell.stop_errors[sid("b")] = "AccessDeniedException"
    assert world.post("contain", claims=SEC)[1]["partial"] is True
    assert read(world.record_id)[1]["partial"] is True
    world.cell.stop_errors.clear()
    run = Run(world)
    clock["t"] = 125.0
    second = next(m["MessageBody"] for m in world.queue.messages if json.loads(m["MessageBody"])["sweep"] == 2)
    assert run.handle(second) == "allowed"
    view = read(world.record_id)[1]
    assert view["partial"] is True and view["quiet_at"] == stamp(125)  # the later, stronger statement says the rest

    clock["t"] = 200.0
    assert world.post("release", claims=PAT)[0] == 200
    world.queue.messages.clear()
    # A clean contain is not partial, and a sweep that fails later does not make it so.
    clock["t"] = 300.0
    assert world.post("contain", claims=SEC)[1]["partial"] is False
    world.cell.stop_errors[sid("a")] = "AccessDeniedException"
    clock["t"] = 425.0
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "failed"
    view = read(world.record_id)[1]
    assert (view["partial"], view["quiet_at"], view["sweeps"]) == (False, None, {"scheduled": 2, "done": 1})


# --- reading the sweeps back -----------------------------------------------------------------------

T0 = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)


def stamp(seconds: float) -> str:
    return (T0 + dt.timedelta(seconds=seconds)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def event_at(seconds: float, action: str = "sweep", outcome: str = "allowed", **extra: Any) -> AuditEvent:
    values = {
        "event_id": f"{action}-{seconds}",
        "request_id": REQUEST_ID,
        "at": stamp(seconds),
        "phase": "result",
        "action": action,
        "outcome": outcome,
        "reason": "x",
        "actor_subject": "s",
        "actor_label": "l",
        "actor_role": "r",
    }
    return AuditEvent(**{**values, **extra})


def summarise(*events: AuditEvent, contained_at: str | None = stamp(0)) -> sweeps.SweepSummary:
    return sweeps.summary(events, contained_at, containment_timing.CONTAIN_DELAY_SECONDS)


def test_quiet_is_the_first_complete_sweep_that_started_after_every_host_applies_the_deny():
    contain = event_at(0, "contain", sweeps_scheduled=3)
    early = event_at(8, duration_ms=3_000, sweep=1)  # complete, but hosts may still start sessions
    second = event_at(125, duration_ms=4_000, sweep=2)  # started at 121 s
    third = event_at(905, duration_ms=2_000, sweep=3)
    assert summarise(contain, early) == sweeps.SweepSummary(scheduled=3, done=1, quiet_at=None)
    assert summarise(third, contain, second, early) == sweeps.SweepSummary(scheduled=3, done=3, quiet_at=stamp(125))
    # A sweep that ended after the delay but started before it proves nothing.
    straddling = event_at(95, duration_ms=10_000, sweep=1)
    assert summarise(contain, straddling).quiet_at is None
    assert summarise(contain, event_at(90, duration_ms=0)).quiet_at == stamp(90)


@pytest.mark.parametrize("outcome", ["failed", "skipped"])
def test_a_sweep_that_did_not_finish_or_was_skipped_is_not_proof_of_quiet(outcome):
    contain = event_at(0, "contain", sweeps_scheduled=2)
    result = summarise(contain, event_at(125, outcome=outcome, sweep=2))
    assert result == sweeps.SweepSummary(scheduled=2, done=1, quiet_at=None)
    # The next complete one is.
    assert summarise(contain, event_at(125, outcome=outcome), event_at(905)).quiet_at == stamp(905)


def test_only_the_containment_that_holds_is_counted():
    earlier = [event_at(-5_000, "contain", sweeps_scheduled=3), event_at(-4_800), event_at(-4_000)]
    current = [event_at(0, "contain", sweeps_scheduled=2), event_at(130, sweep=2)]
    assert summarise(*earlier, *current) == sweeps.SweepSummary(scheduled=2, done=1, quiet_at=stamp(130))
    # Containing again schedules more; they count for the containment that still holds.
    again = event_at(300, "contain", outcome="unchanged", sweeps_scheduled=3)
    assert summarise(*current, again, event_at(302, sweep=1)) == sweeps.SweepSummary(5, 2, stamp(130))
    # Nothing holds: nothing to report.
    assert summarise(*current, contained_at=None) == sweeps.SweepSummary()
    assert summarise(*current, contained_at="not a time") == sweeps.SweepSummary()
    # An intent says nothing about what was scheduled, and a contain without sweeps counts as none.
    assert summarise(event_at(0, "contain", phase="intent", sweeps_scheduled=3), event_at(1, "contain")).scheduled == 0


OTHER_REQUEST = "ffffffff-4e5f-4a6b-8c7d-9e0f1a2b3c4d"


def test_a_sweep_counts_once_and_only_for_the_containment_that_scheduled_it():
    contain = event_at(0, "contain", sweeps_scheduled=2)
    second = event_at(125, sweep=2)
    # A history written before the sweeper claimed its sweeps can hold two events for one sweep.
    assert summarise(contain, second, event_at(140, sweep=2)) == sweeps.SweepSummary(2, 1, stamp(125))
    # A sweep that an earlier containment scheduled runs during this one: it is not one of this
    # containment's sweeps, but what it found is as true as any other sweep's.
    old = event_at(100, sweep=3, request_id=OTHER_REQUEST)
    assert summarise(contain, old) == sweeps.SweepSummary(2, 0, stamp(100))
    assert summarise(contain, old, second) == sweeps.SweepSummary(2, 1, stamp(100))
    # The record of a message that was not valid (such a history can hold one too) is no sweep at all.
    invalid = event_at(130, outcome="failed", request_id=OTHER_REQUEST)
    assert summarise(contain, invalid) == sweeps.SweepSummary(2, 0, None)
    # Never more done than scheduled, whatever a message claimed.
    forged = [event_at(100 + n, sweep=n) for n in (1, 2, 3)]
    assert summarise(contain, *forged).done == 2
    # A first sweep can leave its event a moment before the contain's own result is written.
    assert summarise(contain, event_at(-0.5, outcome="failed", sweep=1), second) == sweeps.SweepSummary(
        2, 2, stamp(125)
    )
    # A contain that scheduled nothing (no queue, or the queue refused) has no sweeps to count.
    assert summarise(event_at(0, "contain"), second) == sweeps.SweepSummary(0, 0, stamp(125))


def test_the_view_shows_the_sweeps_and_when_the_agent_was_quiet(world, read, monkeypatch):
    world.cell.streams[log_group()] = [session_stream("a")]
    clock = {"t": 0.0}
    monkeypatch.setattr(audit_writer, "now_stamp", lambda: stamp(clock["t"]))
    assert world.post("contain", claims=SEC)[0] == 200
    view = read(world.record_id)[1]
    assert (view["sweeps"], view["quiet_at"]) == ({"scheduled": 2, "done": 0}, None)

    run = Run(world)
    clock["t"] = 121.0
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "allowed"
    # Every role sees the counts and the time; only the roles that can act see the events.
    view = read(world.record_id, VIEW)[1]
    assert (view["sweeps"], view["quiet_at"], view["events"]) == ({"scheduled": 2, "done": 1}, stamp(121), [])
    clock["t"] = 901.0
    assert run.handle(world.queue.messages[1]["MessageBody"]) == "allowed"
    full = read(world.record_id, SRE)[1]
    assert (full["sweeps"], full["quiet_at"]) == ({"scheduled": 2, "done": 2}, stamp(121))
    assert [(e["action"], e["sweep"], e["outcome"]) for e in full["events"][:2]] == [
        ("sweep", 3, "allowed"),
        ("sweep", 2, "allowed"),
    ]
    assert full["events"][0]["actor_label"] == "Agent Factory Portal (background sweep)"
    assert full["contained_by"] == "sec-1"  # the sweeps did not change who holds the containment

    clock["t"] = 950.0
    assert world.post("release", claims=PAT)[0] == 200
    released = read(world.record_id, SRE)[1]
    assert (released["state"], released["sweeps"], released["quiet_at"]) == (
        "not_contained",
        {"scheduled": 0, "done": 0},
        None,
    )


def test_a_sweep_right_after_the_contain_is_not_yet_proof_of_quiet(world, read):
    world.cell.streams[log_group()] = [session_stream("a")]
    world.cell.stop_errors[sid("a")] = "ThrottlingException"  # the request leaves it, so sweep 1 is scheduled
    assert world.post("contain", claims=SEC)[0] == 200
    world.cell.stop_errors.clear()
    run = Run(world)
    assert run.handle(world.queue.messages[0]["MessageBody"]) == "allowed"  # sweep 1, seconds after the contain
    view = read(world.record_id)[1]
    assert (view["sweeps"], view["quiet_at"]) == ({"scheduled": 3, "done": 1}, None)


# --- the documents say what the code does ------------------------------------------------------------


def test_the_contract_and_the_readme_state_what_the_code_does():
    from pathlib import Path

    from portal_api.models.portal import ContainmentResult, ContainmentStep, ContainmentSweeps, ContainmentView

    root = Path(__file__).resolve().parent.parent
    contract = " ".join((root / "CONTAINMENT_CONTRACT.md").read_text().split())
    _, second, third = containment_timing.SWEEP_DELAYS_SECONDS
    assert f"| 2 | {second} seconds after the contain |" in contract
    assert f"| 3 | {third} seconds after the contain |" in contract
    assert f"at no more than {containment_timing.SWEEP_STOPS_PER_SECOND} stops per second" in contract
    assert (
        f"started at least {containment_timing.CONTAIN_DELAY_SECONDS} seconds after the containment began" in contract
    )
    assert f"up to {logs.MAX_SWEEP_SESSIONS:,} sessions from that source" in contract
    assert f"reads the policy again every {sweeper.RECHECK_SECONDS:g} seconds" in contract
    # What one sweep can reach: the rate times the time it has.
    reach = containment_timing.SWEEP_STOPS_PER_SECOND * (900 - sweeper.RESERVE_SECONDS)
    assert "that is about 17,000 sessions" in contract and 17_000 <= reach < 18_000
    for model in (ContainmentResult, ContainmentStep, ContainmentView, ContainmentSweeps):
        for name in model.model_fields:
            assert name in contract, name
    for value in (sweeps.ACTOR_SUBJECT, sweeps.ACTOR_LABEL, sweeps.ACTOR_ROLE, "skipped", "background"):
        assert f"`{value}`" in contract, value
    for literal in ('| "background";', '| "scheduled";'):  # in the step's type
        assert literal in contract, literal
    for name in ("sweep", "sessions_not_active", "duration_ms", "sweeps_scheduled"):
        assert f"`{name}`" in contract, name

    readme = " ".join((root / "README.md").read_text().split())
    for said in (
        "`sweep_handler.handler`",
        "`PORTAL_SWEEP_QUEUE_URL`",
        f"after {second} seconds",
        f"after {third} seconds",
        f"no more than {containment_timing.SWEEP_STOPS_PER_SECOND} per second",
        "timeout 900 seconds",
        f"reads the policy again every {sweeper.RECHECK_SECONDS:g} seconds",
        f"keeps the last {sweeper.RESERVE_SECONDS:g} seconds",
    ):
        assert said in readme, said
    evidence = " ".join((root / "ACTIONS_CONTRACT.md").read_text().split())
    for name in ("sweeps_scheduled: number;", "sweeps_done: number;", "quiet_at: string | null;"):
        assert name in evidence, name
    # What was decided and measured after the sweeper first ran live.
    for said in (
        "containmentSpans?",
        "every sweep calls stop once for every session of the lookback window, ended or not",
        "does not stop the function, unlike every other malformed setting",
    ):
        assert said in readme, said
    assert "a sweep calls stop for every session of the last eight hours, ended or not" in contract
    assert "names the setting, and a release is not affected at all" in contract
    iam = " ".join((root / "IAM_ACTIONS.md").read_text().split())
    assert "`OnlyTheContainmentRoleHandlesMessages`" in iam and "a second layer, not a replacement" in iam
    for action in ("SendMessage", "ReceiveMessage", "DeleteMessage", "ChangeMessageVisibility", "PurgeQueue"):
        assert f"`sqs:{action}`" in iam, action


def test_the_sweeper_loads_no_route_code_and_none_of_the_action_flows():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    code = "import sweep_handler, sys; print(' '.join(sorted(sys.modules)))"
    loaded = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True, check=False)  # noqa: S603
    assert loaded.returncode == 0, loaded.stderr
    modules = set(loaded.stdout.split())
    assert "portal_api.actions.sweeper" in modules
    # It serves no route, takes no decision about a person, and reads no registry.
    for absent in (
        "fastapi",
        "mangum",
        "portal_api.actions.app",
        "portal_api.actions.containment_flow",
        "portal_api.actions.engine",
        "portal_api.service",
        "portal_api.identity",
    ):
        assert absent not in modules, absent
