"""Alarm pipeline handler: end to end with a fake DevOps Agent client."""

from __future__ import annotations

import datetime as dt
import json
import logging
import urllib.parse
from typing import Any

import pytest
from botocore.exceptions import ClientError

from alarm_pipeline import handler as pipeline
from alarm_pipeline.routing import Router

PAYLOAD = {
    "sensor": "CPU Load",
    "device": "prod-web-01",
    "status": "Down",
    "message": "Connection failed",
    "datetime": "2026-08-21 14:05:00",
    "priority": "4",
    "group": "Production",
    "probe": "Local Probe",
    "sensorId": "2001",
    "deviceId": "1001",
}


class FakeAgentClient:
    """Records CreateBacklogTask calls and honours the idempotency token."""

    def __init__(self, *, fail_with: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_with = fail_with
        self._by_token: dict[str, str] = {}

    def create_backlog_task(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.fail_with is not None:
            raise self.fail_with

        token = kwargs.get("clientToken")
        if token and token in self._by_token:
            # Idempotent replay: the original task is returned.
            return {"taskId": self._by_token[token]}

        task_id = f"task-{len(self._by_token) + 1}"
        if token:
            self._by_token[token] = task_id
        return {"taskId": task_id}


def event(payload: dict[str, Any] | None = None, *, url_encoded: bool = False) -> dict[str, Any]:
    body = json.dumps(payload if payload is not None else PAYLOAD)
    if url_encoded:
        return {
            "body": urllib.parse.quote(body),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        }
    return {"body": body, "headers": {"Content-Type": "application/json"}}


class FakeSqsClient:
    """Records SendMessage calls, so a park can be asserted rather than assumed."""

    def __init__(self, *, fail_with: Exception | None = None) -> None:
        self.messages: list[dict[str, Any]] = []
        self.fail_with = fail_with

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail_with is not None:
            raise self.fail_with
        self.messages.append(kwargs)
        return {"MessageId": f"msg-{len(self.messages)}"}

    def parked(self) -> list[dict[str, Any]]:
        """The decoded bodies of everything parked."""
        return [json.loads(m["MessageBody"]) for m in self.messages]


@pytest.fixture
def dlq(monkeypatch: pytest.MonkeyPatch) -> FakeSqsClient:
    """Install a fake SQS client and configure the queue URL.

    ALARM_DLQ_URL is set here because ``_park_alarm`` no-ops without it. A test that
    forgot to set it would pass while asserting nothing, so the unconfigured case has
    its own explicit test rather than being the accidental default.
    """
    client = FakeSqsClient()
    monkeypatch.setattr(pipeline, "_sqs_client", client)
    monkeypatch.setenv("ALARM_DLQ_URL", "https://sqs.ap-southeast-2.amazonaws.com/111122223333/dlq")
    return client


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch, dlq: FakeSqsClient) -> FakeAgentClient:
    """Install a fake DevOps Agent client and a single-mode router."""
    client = FakeAgentClient()
    monkeypatch.setattr(pipeline, "_router", Router(agent_space_id="as-test"))
    monkeypatch.setattr(pipeline, "_agent_clients", {})
    monkeypatch.setattr(pipeline, "_agent_client", lambda target: client)
    monkeypatch.setenv("AGENT_REGION", "ap-southeast-2")
    monkeypatch.setenv("DEDUP_WINDOW_MINUTES", "30")
    return client


def body_of(response: dict[str, Any]) -> dict[str, Any]:
    return json.loads(response["body"])


# --- Happy path -------------------------------------------------------------


class TestSuccess:
    def test_creates_an_investigation(self, agent: FakeAgentClient) -> None:
        response = pipeline.handler(event(), None)
        assert response["statusCode"] == 200
        assert body_of(response)["created"] is True
        assert len(agent.calls) == 1

        call = agent.calls[0]
        assert call["agentSpaceId"] == "as-test"
        assert call["taskType"] == "INVESTIGATION"
        assert "prod-web-01" in call["title"]

    def test_handles_the_url_encoded_form_prtg_actually_sends(self, agent: FakeAgentClient) -> None:
        response = pipeline.handler(event(url_encoded=True), None)
        assert response["statusCode"] == 200
        assert len(agent.calls) == 1

    def test_priority_is_derived_not_hardcoded(self, agent: FakeAgentClient) -> None:
        pipeline.handler(event({**PAYLOAD, "priority": "5"}), None)
        pipeline.handler(event({**PAYLOAD, "priority": "1", "status": "Warning", "sensorId": "3"}), None)
        priorities = [c["priority"] for c in agent.calls]
        assert priorities[0] == "CRITICAL"
        assert priorities[1] == "MINIMAL"

    def test_description_includes_prtg_ids_for_the_mcp_tools(self, agent: FakeAgentClient) -> None:
        pipeline.handler(event(), None)
        assert "sensor id 2001" in agent.calls[0]["description"]

    def test_response_carries_a_correlation_id(self, agent: FakeAgentClient) -> None:
        assert "correlationId" in body_of(pipeline.handler(event(), None))


# --- Deduplication ----------------------------------------------------------


class TestDeduplication:
    def test_repeated_alarm_creates_only_one_task(self, agent: FakeAgentClient) -> None:
        """The reference implementation had no deduplication and pushed the problem
        onto PRTG's notification triggers."""
        first = pipeline.handler(event(), None)
        second = pipeline.handler(event(), None)

        assert first["statusCode"] == 200
        assert second["statusCode"] == 200
        # Both calls are made, but the same token means one task exists.
        assert len(agent.calls) == 2
        assert agent.calls[0]["clientToken"] == agent.calls[1]["clientToken"]
        assert body_of(first)["taskId"] == body_of(second)["taskId"]

    def test_a_different_sensor_is_not_deduplicated(self, agent: FakeAgentClient) -> None:
        pipeline.handler(event(), None)
        pipeline.handler(event({**PAYLOAD, "sensorId": "9999"}), None)
        assert agent.calls[0]["clientToken"] != agent.calls[1]["clientToken"]

    def test_deduplication_can_be_disabled(
        self, agent: FakeAgentClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DEDUP_WINDOW_MINUTES", "0")
        pipeline.handler(event(), None)
        assert "clientToken" not in agent.calls[0]

    def test_a_new_investigation_is_not_reported_as_deduplicated(self, agent: FakeAgentClient) -> None:
        """``deduplicated`` says whether this alarm was suppressed, not whether the
        feature is enabled.

        It was reported as ``bool(clientToken)``, so every successful creation came back
        ``deduplicated=true`` -- including the first alarm a brand-new sensor ever sends.
        That made the field useless for the one thing it exists to say, and actively
        misleading next to the conflict path, which returns the same value for a genuine
        suppression. Caught on a live deployment: a first-time sensor returned
        ``created=true`` and ``deduplicated=true`` together.
        """
        response = pipeline.handler(event(), None)
        body = body_of(response)

        assert body["created"] is True
        assert body["deduplicated"] is False, "nothing was suppressed; this is new work"

    def test_an_idempotent_replay_is_reported_as_deduplicated(
        self, agent: FakeAgentClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A replay returns the original task, so the age of ``createdAt`` is the signal.

        Kept as a heuristic because the API does not flag a replay. Note the real service
        more often raises ConflictException instead of replaying, because a repeat
        notification's body has changed -- so this path is the documented contract and
        the conflict path is the common one.
        """
        old = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
        monkeypatch.setattr(agent, "create_backlog_task", lambda **kw: {"taskId": "task-1", "createdAt": old})

        body = body_of(pipeline.handler(event(), None))

        assert body["taskId"] == "task-1"
        assert body["deduplicated"] is True


# --- Test notifications -----------------------------------------------------


class TestTestNotifications:
    def test_prtg_test_notification_is_acknowledged_without_creating_a_task(
        self, agent: FakeAgentClient
    ) -> None:
        """PRTG does not substitute placeholders for a test, so there is no real
        data to investigate. 200 still confirms connectivity end to end, which is
        why the operator pressed the button."""
        body = {k: f"%{k.lower()}" for k in PAYLOAD}
        response = pipeline.handler(event(body), None)

        assert response["statusCode"] == 200
        assert body_of(response)["created"] is False
        assert "test notification" in body_of(response)["reason"]
        assert agent.calls == []

    def test_test_notifications_can_be_turned_into_tasks(
        self, agent: FakeAgentClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SKIP_TEST_NOTIFICATIONS", "false")
        body = {k: f"%{k.lower()}" for k in PAYLOAD}
        response = pipeline.handler(event(body), None)
        assert body_of(response)["created"] is True
        assert agent.calls[0]["priority"] == "MINIMAL"


# --- Failure handling -------------------------------------------------------


class TestFailureHandling:
    def test_malformed_body_is_a_400_so_prtg_does_not_retry_forever(self, agent: FakeAgentClient) -> None:
        response = pipeline.handler({"body": "", "headers": {}}, None)
        assert response["statusCode"] == 400
        assert agent.calls == []

    def test_rejection_message_helps_fix_the_notification_template(self, agent: FakeAgentClient) -> None:
        response = pipeline.handler({"body": json.dumps({"nope": 1}), "headers": {}}, None)
        assert "%sensor" in body_of(response)["message"]

    def test_routing_failure_returns_500_and_creates_nothing(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient
    ) -> None:
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        response = pipeline.handler(event(), None)
        assert response["statusCode"] == 500
        assert agent.calls == []

    def test_api_failure_is_parked_and_then_propagates(
        self, monkeypatch: pytest.MonkeyPatch, dlq: FakeSqsClient
    ) -> None:
        """A swallowed failure here is a lost incident. It must surface.

        It re-raises *after* parking rather than instead of it. The raise is what
        reaches PRTG's notification log, the API's 5xx metric and the function's error
        metric; the park is what makes the alarm replayable. Neither substitutes for
        the other.
        """
        failing = FakeAgentClient(fail_with=RuntimeError("ThrottlingException"))
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id="as-test"))
        monkeypatch.setattr(pipeline, "_agent_client", lambda target: failing)

        with pytest.raises(RuntimeError):
            pipeline.handler(event(), None)

        assert len(dlq.messages) == 1
        assert dlq.parked()[0]["reason"] == "investigation_creation_failed"

    def test_error_response_to_prtg_reveals_no_internal_detail(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient
    ) -> None:
        """The response body is written into PRTG's notification log, which is not
        the place for an Agent Space ID or a role ARN."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        response = pipeline.handler(event(), None)
        rendered = json.dumps(body_of(response))
        assert "as-test" not in rendered
        assert "arn:aws" not in rendered
        assert "sqs." not in rendered, "the queue URL carries the account ID"
        assert "correlationId" in rendered


# --- Parking to the dead-letter queue ---------------------------------------


class TestParkingFailedAlarms:
    """Failed alarms are written to the DLQ by this function, explicitly.

    Lambda's ``dead_letter_queue`` and ``retry_attempts`` settings apply only to
    *asynchronous* invocations. The only caller is API Gateway's proxy integration,
    which is synchronous, so relying on them yields a queue that can never receive a
    message and an alarm on that queue that can never fire. That failure mode is
    invisible: it looks exactly like nothing going wrong.

    So the queue is written to with an explicit SendMessage, and these tests are what
    keep it that way.
    """

    def test_a_routing_failure_is_parked(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """The most recoverable failure in the function: the alarm is fine, the
        routing table is wrong. Fix the table and a redrive succeeds."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        response = pipeline.handler(event(), None)

        assert response["statusCode"] == 500
        assert len(dlq.messages) == 1
        assert dlq.parked()[0]["reason"] == "routing_failed"

    def test_a_repeat_notification_is_suppressed_not_failed(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """The deduplication feature used to turn its own success case into a failure.

        The token is narrow on purpose -- sensor, device, state, time bucket -- so a
        sensor that stays Down yields one investigation instead of one per polling
        interval. But PRTG's payload moves on between those notifications: lastValue,
        downtime, uptime, elapsedLastUp and message all change, and all of them feed the
        description. So the repeat arrives with the same token and a different body, and
        CreateBacklogTask rejects it with ConflictException.

        Treated as an error that produced a 5xx to PRTG, a firing error alarm and a
        dead-letter message -- for the exact case deduplication exists to swallow. Since
        repeat notifications are the common case for a sensor that is still down, this hit
        almost every one of them.

        Reproduced against the deployed function by re-sending one sensor with only
        lastValue and downtime changed.
        """
        conflict = ClientError(
            {"Error": {"Code": "ConflictException", "Message": "Conflicting idempotency request"}},
            "CreateBacklogTask",
        )
        agent.fail_with = conflict

        response = pipeline.handler(event(), None)
        body = json.loads(response["body"])

        assert response["statusCode"] == 200, "a suppressed duplicate is not a failure"
        assert body["created"] is False
        assert body["deduplicated"] is True
        assert body["taskId"] is None, "no lookup by client token exists, so none is invented"
        assert dlq.messages == [], "nothing to park: the investigation already exists"

    def test_a_conflict_without_a_token_still_fails(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """With deduplication off there is no token, so a conflict is a real anomaly.

        Swallowing it would hide a genuine API problem behind a feature that is not even
        enabled.
        """
        monkeypatch.setenv("DEDUP_WINDOW_MINUTES", "0")
        agent.fail_with = ClientError(
            {"Error": {"Code": "ConflictException", "Message": "Conflicting idempotency request"}},
            "CreateBacklogTask",
        )

        with pytest.raises(ClientError):
            pipeline.handler(event(), None)
        assert len(dlq.messages) == 1
        assert dlq.parked()[0]["reason"] == "investigation_creation_failed"

    def test_other_api_errors_are_still_failures(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """Only ConflictException is benign. Matched on the error code, so a different
        one must not be swept up with it."""
        agent.fail_with = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "CreateBacklogTask"
        )

        with pytest.raises(ClientError):
            pipeline.handler(event(), None)
        assert len(dlq.messages) == 1

    def test_an_alarm_is_parked_rather_than_lost_when_time_runs_short(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """The failure mode that defeated every other safeguard in this function.

        An unreachable dependency used to consume the whole invocation -- the client
        allowed four attempts at connect 5 + read 20, a 100s worst case against a 30s
        timeout -- and a sandbox timeout *kills the process* rather than raising. So the
        except block never ran, nothing was parked, the queue stayed empty, and
        PrtgAlarmsLost could not fire either because its metric filter needs a log event a
        dead process cannot emit. Three separate deployments lost alarms exactly this way,
        with the last log line pointing at credentials rather than the network.

        Now the call is not started unless there is time left to recover from it.
        """

        class NearlyOutOfTime:
            def get_remaining_time_in_millis(self) -> int:
                return 2_000  # less than the 8s park reserve

        response = pipeline.handler(event(), NearlyOutOfTime())

        assert response["statusCode"] == 500
        assert len(dlq.messages) == 1
        parked = dlq.parked()[0]
        assert parked["reason"] == "insufficient_time_remaining"
        # The alarm itself is intact and replayable, which is the whole point.
        assert parked["originalEvent"]
        assert parked["clientToken"]
        # And the call really was not attempted.
        assert agent.calls == []

    def test_plenty_of_time_proceeds_normally(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        class PlentyOfTime:
            def get_remaining_time_in_millis(self) -> int:
                return 29_000

        response = pipeline.handler(event(), PlentyOfTime())

        assert response["statusCode"] == 200
        assert dlq.messages == []
        assert len(agent.calls) == 1

    def test_a_context_without_a_clock_does_not_block_the_call(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """The check must degrade to "proceed", never to "park everything".

        Every other test in this file passes ``None`` as the context, so getting this
        backwards would park every alarm in the suite rather than fail one assertion.
        """
        assert pipeline.handler(event(), None)["statusCode"] == 200
        assert dlq.messages == []

    def test_the_retry_budget_leaves_room_to_park(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bounding the budget is what makes the deadline check reachable at all.

        Asserted arithmetically rather than by timing: the worst case across all attempts
        has to fit inside the function timeout with the park reserve still unspent.
        """
        monkeypatch.setenv("FUNCTION_TIMEOUT_SECONDS", "30")
        budget = pipeline._agent_call_budget_seconds()
        assert budget == 30 - pipeline._PARK_RESERVE_SECONDS

        per_attempt = budget / pipeline._AGENT_MAX_ATTEMPTS
        worst_case = pipeline._AGENT_MAX_ATTEMPTS * per_attempt
        assert worst_case <= 30 - pipeline._PARK_RESERVE_SECONDS

    def test_an_absent_or_unparseable_timeout_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FUNCTION_TIMEOUT_SECONDS", raising=False)
        assert pipeline._function_timeout_seconds() == 30.0
        monkeypatch.setenv("FUNCTION_TIMEOUT_SECONDS", "not-a-number")
        assert pipeline._function_timeout_seconds() == 30.0
        monkeypatch.setenv("FUNCTION_TIMEOUT_SECONDS", "0")
        assert pipeline._function_timeout_seconds() == 30.0

    def test_the_parked_message_can_be_replayed_verbatim(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """The whole point of parking. ``originalEvent`` is fed straight back to the
        handler, so a redrive needs no reconstruction of the PRTG payload."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        pipeline.handler(event(), None)
        parked = dlq.parked()[0]

        # Routing now works, as it would after an operator fixed the table.
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id="as-test"))
        replayed = pipeline.handler(parked["originalEvent"], None)

        assert replayed["statusCode"] == 200
        assert body_of(replayed)["created"] is True
        assert "prod-web-01" in agent.calls[0]["title"]

    def test_the_url_encoded_form_survives_a_replay(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """PRTG sends percent-encoded JSON under a form content type. Dropping the
        content type would make the replay undecodable, so it is carried."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        pipeline.handler(event(url_encoded=True), None)
        parked = dlq.parked()[0]
        assert "form-urlencoded" in parked["originalEvent"]["headers"]["Content-Type"]

        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id="as-test"))
        assert pipeline.handler(parked["originalEvent"], None)["statusCode"] == 200

    def test_the_parked_message_carries_the_deduplication_token(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """Captured at park time, not recomputed at redrive time.

        The token embeds a wall-clock bucket, so recomputing it during a redrive lands
        in a different bucket and creates a second investigation for the same alarm.
        Carrying it makes a redrive deduplicate against whatever the failed attempt
        managed to create.
        """
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        pipeline.handler(event(), None)

        token = dlq.parked()[0]["clientToken"]
        assert token
        # The same value the successful path would have used for this alarm.
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id="as-test"))
        pipeline.handler(event(), None)
        assert agent.calls[0]["clientToken"] == token

    def test_the_parked_message_names_the_failing_stage_and_invocation(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """Triage should not begin with a log search."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        response = pipeline.handler(event(), None)
        parked = dlq.parked()[0]

        assert parked["reason"] == "routing_failed"
        assert parked["detail"]
        assert parked["correlationId"] == body_of(response)["correlationId"]
        assert parked["schemaVersion"] == pipeline.PARKED_SCHEMA_VERSION
        assert parked["alarm"]["sensorId"] == "2001"

    def test_a_test_notification_is_never_parked(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """A parked message exists to be replayed, and replaying a test notification
        could only ever produce an investigation about a sensor called '%sensor'.

        Exercised with SKIP_TEST_NOTIFICATIONS=false, which is the only way a test
        notification reaches the failure paths at all.
        """
        monkeypatch.setenv("SKIP_TEST_NOTIFICATIONS", "false")
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))

        response = pipeline.handler(event({k: f"%{k.lower()}" for k in PAYLOAD}), None)

        assert response["statusCode"] == 500, "the failure is still reported"
        assert dlq.messages == [], "but nothing replayable was stored"

    def test_a_malformed_payload_is_not_parked(self, agent: FakeAgentClient, dlq: FakeSqsClient) -> None:
        """A 400 means the bytes are wrong. Redriving them can never succeed, so
        storing them would only fill the queue with work that cannot be done."""
        assert pipeline.handler({"body": "", "headers": {}}, None)["statusCode"] == 400
        assert dlq.messages == []

    def test_a_successful_alarm_parks_nothing(self, agent: FakeAgentClient, dlq: FakeSqsClient) -> None:
        assert pipeline.handler(event(), None)["statusCode"] == 200
        assert dlq.messages == []

    def test_an_unconfigured_queue_does_not_break_the_failure_path(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """Without ALARM_DLQ_URL the alarm is only in the logs, which is worse but
        must not turn a diagnosable routing failure into an SQS traceback."""
        monkeypatch.delenv("ALARM_DLQ_URL", raising=False)
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))

        response = pipeline.handler(event(), None)

        assert response["statusCode"] == 500
        assert dlq.messages == []

    def test_a_failing_park_does_not_mask_the_original_error(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient
    ) -> None:
        """If SendMessage itself fails, the alarm really is lost. The original
        diagnosis must still be what surfaces, not an SQS error from the handler."""
        monkeypatch.setattr(pipeline, "_sqs_client", FakeSqsClient(fail_with=RuntimeError("AccessDenied")))
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))

        response = pipeline.handler(event(), None)
        assert response["statusCode"] == 500
        assert "CloudWatch" in body_of(response)["message"]

    def test_losing_an_alarm_is_logged_under_its_own_event(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, caplog
    ) -> None:
        """``alarm_park_failed`` is the one event meaning an alarm is gone. A metric
        filter alarms on it, so the name is a contract."""
        monkeypatch.setattr(pipeline, "_sqs_client", FakeSqsClient(fail_with=RuntimeError("AccessDenied")))
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))

        with caplog.at_level(logging.ERROR):
            pipeline.handler(event(), None)

        assert "alarm_park_failed" in caplog.text

    def test_parking_is_logged_under_its_own_event(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient, caplog
    ) -> None:
        """``alarm_parked`` drives the PrtgAlarmsParked metric filter."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))

        with caplog.at_level(logging.ERROR):
            pipeline.handler(event(), None)

        assert "alarm_parked" in caplog.text

    def test_the_parked_message_carries_no_credential(
        self, monkeypatch: pytest.MonkeyPatch, agent: FakeAgentClient, dlq: FakeSqsClient
    ) -> None:
        """The queue is SSE-SQS, not a customer-managed key, on the stated grounds
        that it holds no credential. That has to stay true."""
        monkeypatch.setattr(pipeline, "_router", Router(agent_space_id=None))
        pipeline.handler(event(), None)

        rendered = json.dumps(dlq.parked()[0]).lower()
        for forbidden in ("passhash", "apitoken", "prtg_api_key", "password", "secretaccesskey"):
            assert forbidden not in rendered
