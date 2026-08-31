"""Lambda entry point for the alarm pipeline: the PRTG → agent direction.

Receives a PRTG notification through API Gateway and creates an investigation task
in a DevOps Agent Agent Space.

    PRTG ──► API Gateway ──► this function ──► aidevops:CreateBacklogTask

Two properties matter more than the mechanics.

**Every failure here is a potentially missed incident.** Unlike the MCP tool
function, where a failure degrades an investigation, a failure here means no
investigation exists at all. So this function reports failure loudly and writes the
alarm to a dead-letter queue itself, in ``_park_alarm``, before returning.

That last part is deliberate and worth understanding. Lambda's own
``DeadLetterConfig`` and ``retry_attempts`` apply *only to asynchronous
invocations*. API Gateway's proxy integration is synchronous, so a pipeline that
relies on them has a dead-letter queue that can never receive a message, and an
alarm on that queue that can never fire - which reads as "no failures" rather than
"no detection". Parking is therefore an explicit ``SendMessage`` on the failure
path.

**Responses to PRTG say as little as possible.** PRTG's notification log is visible
to anyone with PRTG access, and the response body would be written into it. Detail
goes to CloudWatch under a correlation ID instead.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from .payload import (
    PayloadError,
    PrtgAlarm,
    deduplication_token,
    header,
    parse_alarm,
    resolve_priority,
)
from .routing import Router, RoutingError, Target

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

#: Reused across invocations in a warm environment.
_router: Router | None = None
_agent_clients: dict[str, Any] = {}
_sqs_client: Any = None

#: Shape of the dead-letter message. Bumped if a field is removed or reinterpreted,
#: so a consumer written against an older pipeline can tell.
PARKED_SCHEMA_VERSION = 1

#: Seconds held back from the DevOps Agent call so that a failure can still be parked.
#:
#: Sized against the SQS client in ``_get_sqs``: two attempts at connect 1 + read 3 is a
#: worst case of 8 s. If SQS is unreachable too the park fails anyway, and that is what
#: ``alarm_park_failed`` and the ``PrtgAlarmsLost`` alarm exist to report -- the point here
#: is that the *attempt* always happens.
_PARK_RESERVE_SECONDS = 8.0

#: Attempts allowed for ``CreateBacklogTask``. Deliberately small: the budget it has to fit
#: inside is the function timeout minus the park reserve, and more attempts buy retries at
#: the cost of making each one too short to succeed on a slow path.
_AGENT_MAX_ATTEMPTS = 2

#: Assumed function timeout when the stack has not said otherwise. Matches the
#: ``pipeline_lambda.timeout_seconds`` default.
_DEFAULT_FUNCTION_TIMEOUT_SECONDS = 30.0


def _get_router() -> Router:
    global _router  # noqa: PLW0603 - deliberate warm-start cache
    if _router is None:
        _router = Router()
    return _router


# --- Responses --------------------------------------------------------------


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _accepted(correlation_id: str, detail: dict[str, Any]) -> dict[str, Any]:
    return _response(200, {"status": "accepted", "correlationId": correlation_id, **detail})


def _rejected(correlation_id: str, message: str) -> dict[str, Any]:
    """A 400: the request will never succeed, so PRTG should not retry it."""
    return _response(400, {"status": "rejected", "correlationId": correlation_id, "message": message})


def _failed(correlation_id: str) -> dict[str, Any]:
    """A 500 with no detail.

    Deliberately opaque. The body would be recorded in PRTG's notification log,
    which is not the right place for an IAM role ARN or an Agent Space ID. The
    correlation ID is enough to find the full detail in CloudWatch.
    """
    return _response(
        500,
        {
            "status": "error",
            "correlationId": correlation_id,
            "message": "Could not create the investigation. See CloudWatch Logs for this correlationId.",
        },
    )


# --- Entry point ------------------------------------------------------------


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Handle one PRTG notification."""
    correlation_id = uuid.uuid4().hex[:12]
    started = time.monotonic()

    try:
        alarm = parse_alarm(event)
    except PayloadError as exc:
        logger.warning(
            json.dumps(
                {
                    "event": "payload_rejected",
                    "correlationId": correlation_id,
                    "detail": str(exc),
                    # Truncated and only on rejection, to help diagnose a malformed
                    # notification template without logging every alarm body.
                    "bodyPreview": str(event.get("body") or "")[:200],
                }
            )
        )
        return _rejected(correlation_id, str(exc))

    log_base = {
        "correlationId": correlation_id,
        "sensor": alarm.sensor,
        "device": alarm.device,
        # Logged so an operator can tie a log line to an AWS resource without
        # opening the task. It is an address PRTG already holds, not a secret.
        "host": alarm.host,
        "status": alarm.status,
        "group": alarm.group,
        "probe": alarm.probe,
        "isTest": alarm.is_test,
    }
    logger.info(json.dumps({"event": "alarm_received", **log_base}))

    # A test notification is acknowledged but not turned into an investigation.
    # PRTG does not substitute placeholders for tests, so the payload carries no
    # real data and an investigation from it would waste an operator's attention.
    # Returning 200 lets the operator confirm connectivity end to end, which is the
    # actual purpose of pressing the test button.
    if alarm.is_test and _skip_test_notifications():
        logger.info(json.dumps({"event": "test_notification_acknowledged", **log_base}))
        return _accepted(
            correlation_id,
            {
                "created": False,
                "reason": (
                    "PRTG test notification recognised. Connectivity, authentication and payload "
                    "parsing all worked. No investigation was created because PRTG does not "
                    "substitute placeholders for test notifications."
                ),
            },
        )

    try:
        target = _get_router().resolve(alarm)
    except RoutingError as exc:
        # Logged with the stable event name the routing-failure alarm matches on.
        logger.error(json.dumps({"event": "routing_failed", "detail": str(exc), **log_base}))
        # Parked because this is the most recoverable failure in the function: the
        # alarm is well-formed and the configuration is wrong. The routing table is
        # re-read on a TTL, so once an operator fixes the entry a redrive succeeds
        # with no redeployment.
        _park_alarm(
            event,
            alarm,
            reason="routing_failed",
            detail=str(exc),
            correlation_id=correlation_id,
            log_base=log_base,
        )
        return _failed(correlation_id)

    logger.info(
        json.dumps(
            {
                "event": "route_resolved",
                "agentSpaceId": target.agent_space_id,
                "targetAccount": target.account_id,
                "matchedBy": target.matched_by,
                "matchedValue": target.matched_value,
                **log_base,
            }
        )
    )

    # Do not start a call there is no time to finish, or to recover from.
    #
    # The client's retry budget is bounded (see `_agent_client`), but earlier steps spend
    # time too -- a fan-out routing lookup reads an SSM parameter -- so the bound alone
    # does not guarantee headroom by the time we get here. Without this check a slow route
    # resolution can leave the creation call straddling the deadline, and a sandbox timeout
    # kills the process rather than raising, so the park below never runs and the alarm is
    # lost silently. Parking now, while there is still time, keeps it recoverable.
    remaining = _remaining_seconds(context)
    if remaining is not None and remaining < _PARK_RESERVE_SECONDS:
        detail = (
            f"Only {remaining:.1f}s of the invocation remained, which is less than the "
            f"{_PARK_RESERVE_SECONDS:.0f}s reserved for parking, so creating the investigation "
            "was not attempted. The alarm is preserved and a redrive will retry it. Recurring "
            "here means an earlier step is slow: check the routing parameter lookup for "
            "fan-out, or raise pipeline_lambda.timeout_seconds."
        )
        logger.error(json.dumps({"event": "investigation_creation_skipped", "detail": detail, **log_base}))
        _park_alarm(
            event,
            alarm,
            reason="insufficient_time_remaining",
            detail=detail,
            correlation_id=correlation_id,
            log_base=log_base,
        )
        return _failed(correlation_id)

    try:
        result = _create_investigation(alarm, target, correlation_id=correlation_id, log_base=log_base)
    except Exception as exc:  # noqa: BLE001 - parked and re-raised, never swallowed
        logger.exception(
            json.dumps({"event": "investigation_creation_failed", "detail": str(exc)[:500], **log_base})
        )
        _park_alarm(
            event,
            alarm,
            reason="investigation_creation_failed",
            detail=str(exc),
            correlation_id=correlation_id,
            log_base=log_base,
        )
        # Re-raised after parking, so the failure stays visible in three places that
        # a parked message alone would not reach: PRTG's notification log, the API's
        # 5xx metric, and the function's error metric. API Gateway surfaces an
        # unhandled error as 502, not the 500 returned elsewhere in this function.
        raise

    logger.info(
        json.dumps(
            {
                # A suppressed duplicate is not a creation, and logging it as one would
                # make the dashboard's investigation count disagree with the Agent Space.
                "event": (
                    "investigation_created" if result.get("created", True) else "investigation_suppressed"
                ),
                "taskId": result.get("taskId"),
                "priority": result.get("priority"),
                "durationMs": int((time.monotonic() - started) * 1000),
                **log_base,
            }
        )
    )
    # `result` may carry created=False, which overrides the default here.
    return _accepted(correlation_id, {"created": True, **result})


# --- Investigation creation -------------------------------------------------


def _create_investigation(
    alarm: PrtgAlarm,
    target: Target,
    *,
    correlation_id: str,
    log_base: dict[str, Any],
) -> dict[str, Any]:
    """Create the backlog task, deduplicating with an idempotency token."""
    client = _agent_client(target)

    priority = resolve_priority(alarm)
    window = _dedup_window_minutes()
    token = deduplication_token(alarm, window_minutes=window)

    request: dict[str, Any] = {
        "agentSpaceId": target.agent_space_id,
        "title": alarm.title(),
        "description": alarm.description(),
        "priority": priority,
        "taskType": "INVESTIGATION",
    }
    if token:
        # Server-side deduplication: the same token inside the window returns the
        # original task instead of creating a second one.
        request["clientToken"] = token

    try:
        response = client.create_backlog_task(**request)
    except Exception as exc:  # noqa: BLE001 - inspected, then re-raised unless it is a conflict
        if token and _is_idempotency_conflict(exc):
            # The token matched an existing task, but the request body did not. That is
            # not a failure -- it is the duplicate this token exists to suppress.
            #
            # It happens on almost every repeat notification. The token is deliberately
            # narrow (sensor, device, state, time bucket) so that a sensor which stays
            # Down produces one investigation rather than one per polling interval. But
            # PRTG's payload moves on between those notifications: lastValue, downtime,
            # uptime, elapsedLastUp and message all change, and every one of them feeds
            # the description. So the second notification arrives with the same token and
            # a different body, and CreateBacklogTask rejects it as a conflicting
            # idempotency request.
            #
            # Treated as an error, that turned the feature inside out: the benign case
            # deduplication is *for* became a 5xx to PRTG, a firing error alarm, and a
            # dead-letter message -- for an alarm that was supposed to be silently
            # suppressed. Reproduced by sending the same sensor twice with only lastValue
            # and downtime changed, which is what a still-Down sensor looks like.
            #
            # The task id is not recoverable here: there is no lookup by client token, and
            # searching for it would be racy and expensive for no benefit. Suppression is
            # reported without one rather than guessed at.
            logger.info(
                json.dumps(
                    {
                        "event": "duplicate_suppressed",
                        "taskId": None,
                        "windowMinutes": window,
                        "detail": (
                            "An investigation already exists for this sensor and state in this "
                            "window. PRTG re-sent the alarm with updated values, so the request "
                            "body differed from the original while the deduplication token did not."
                        ),
                        **log_base,
                    }
                )
            )
            return {
                "taskId": None,
                "agentSpaceId": target.agent_space_id,
                "priority": priority,
                "deduplicated": True,
                "created": False,
            }
        raise

    task_id = response.get("taskId") or response.get("task", {}).get("taskId")

    # An idempotent replay returns the original task, so an unchanged creation
    # timestamp is the signal that this alarm was suppressed as a duplicate. Logged
    # under the event name the dashboard's duplicate metric matches.
    created_now = response.get("createdAt")
    replayed = bool(token and created_now and _looks_like_replay(response))
    if replayed:
        logger.info(
            json.dumps(
                {"event": "duplicate_suppressed", "taskId": task_id, "windowMinutes": window, **log_base}
            )
        )

    return {
        "taskId": task_id or "unknown",
        "agentSpaceId": target.agent_space_id,
        "priority": priority,
        # Whether this alarm was suppressed, not whether deduplication was switched on.
        # Reporting `bool(token)` here meant every successful creation came back
        # deduplicated=true, including a brand-new sensor's first alarm -- so the field
        # could not distinguish a suppressed duplicate from fresh work, which is the one
        # thing it exists to say. On this path it is the replay heuristic; on the conflict
        # path above it is certain.
        "deduplicated": replayed,
    }


def _function_timeout_seconds() -> float:
    """The function's configured timeout, which the stack passes in.

    Read from the environment rather than from the Lambda context because the client
    built from it is cached across invocations, so the value has to be the *static*
    timeout and not whatever happened to be left on one particular call.
    """
    raw = os.environ.get("FUNCTION_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw else _DEFAULT_FUNCTION_TIMEOUT_SECONDS
    except ValueError:
        value = _DEFAULT_FUNCTION_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_FUNCTION_TIMEOUT_SECONDS


def _agent_call_budget_seconds() -> float:
    """How long ``CreateBacklogTask`` may take in total, leaving room to park.

    Floored at 6 s so an unusually short configured timeout still produces a client that
    can plausibly succeed, rather than one guaranteed to fail on connect.
    """
    return max(6.0, _function_timeout_seconds() - _PARK_RESERVE_SECONDS)


def _remaining_seconds(context: Any) -> float | None:
    """Seconds left in this invocation, or ``None`` when the runtime does not say.

    ``None`` rather than an assumed value: guessing here would either park alarms that
    had plenty of time or skip the check that exists to protect them.
    """
    getter = getattr(context, "get_remaining_time_in_millis", None)
    if not callable(getter):
        return None
    try:
        return float(getter()) / 1000.0
    except Exception:  # noqa: BLE001 - a broken context must not break alarm handling
        return None


def _get_sqs() -> Any:
    """Return the SQS client used to park alarms, creating it on first use.

    Configured more tightly than ``_agent_client``. A park runs inside an
    invocation that has *already* failed, with the function timeout still running,
    so spending the remaining budget on retries is how a parked alarm becomes a lost
    one plus a timeout.

    The worst case here -- two attempts at connect 1 + read 3, so 8 s -- is what
    ``_PARK_RESERVE_SECONDS`` is sized against. Changing one means changing the other.
    """
    global _sqs_client  # noqa: PLW0603 - deliberate warm-start cache
    if _sqs_client is None:
        import boto3
        from botocore.config import Config

        _sqs_client = boto3.client(
            "sqs",
            config=Config(
                retries={"max_attempts": 2, "mode": "standard"},
                connect_timeout=1,
                read_timeout=3,
            ),
        )
    return _sqs_client


def _park_alarm(
    event: dict[str, Any],
    alarm: PrtgAlarm,
    *,
    reason: str,
    detail: str,
    correlation_id: str,
    log_base: dict[str, Any],
) -> None:
    """Write an alarm that produced no investigation to the dead-letter queue.

    Called from the failure paths, and it must never raise: it runs inside an
    ``except`` block, and an exception here would replace a specific diagnosis with
    a traceback from the error handler.

    The message carries enough to redrive without re-deriving anything:

    * ``originalEvent`` - body and content type, the two things ``parse_alarm``
      reads. A consumer can hand this straight back to the handler.
    * ``clientToken`` - the deduplication token as computed *now*. It is captured at
      park time rather than left to the redrive because the token embeds a wall-clock
      bucket (see ``deduplication_token``); recomputing it later lands in a different
      bucket and creates a second investigation for the same alarm. A redrive that
      passes this token through dedupes correctly against anything the original
      attempt managed to create.
    * ``reason`` and ``detail`` - which stage failed and why, so triage does not
      start with a log search.

    Test notifications are never parked. A parked message exists to be replayed, and
    PRTG does not substitute placeholders for a test, so replaying one could only
    ever produce an investigation about a sensor literally named ``%sensor``. The
    failure still surfaces through the stage's own log event, the function's error
    metric, and the API's 5xx metric.
    """
    if alarm.is_test:
        logger.info(json.dumps({"event": "park_skipped_for_test_notification", **log_base}))
        return

    queue_url = os.environ.get("ALARM_DLQ_URL")
    if not queue_url:
        # Not fatal, but it does mean this alarm is only in the logs. Warned rather
        # than raised, because the caller is already handling a failure and losing
        # its diagnosis to this one would be worse.
        logger.warning(
            json.dumps(
                {
                    "event": "alarm_park_unconfigured",
                    "message": (
                        "ALARM_DLQ_URL is not set, so this alarm was not preserved for replay. "
                        "The CDK stack sets it; a hand-built function must too."
                    ),
                    **log_base,
                }
            )
        )
        return

    body = {
        "schemaVersion": PARKED_SCHEMA_VERSION,
        "reason": reason,
        "detail": detail[:500],
        "correlationId": correlation_id,
        "parkedAt": time.time(),
        "clientToken": deduplication_token(alarm, window_minutes=_dedup_window_minutes()),
        # A summary for triaging the queue by eye. A redrive uses ``originalEvent``,
        # so this does not need to be exhaustive - but it does need ``host``, which
        # is the only field here that identifies anything outside PRTG.
        "alarm": {
            "sensor": alarm.sensor,
            "device": alarm.device,
            "host": alarm.host,
            "status": alarm.status,
            "sensorId": alarm.sensor_id,
            "deviceId": alarm.device_id,
            "group": alarm.group,
            "probe": alarm.probe,
        },
        "originalEvent": {
            "body": event.get("body"),
            # Only the content type is carried forward. It is the one header
            # ``parse_alarm`` reads, and the rest of what API Gateway attaches
            # (forwarded addresses, user agent) is noise in a replay.
            "headers": {"Content-Type": header(event, "content-type") or "application/json"},
        },
    }

    try:
        response = _get_sqs().send_message(QueueUrl=queue_url, MessageBody=json.dumps(body))
    except Exception as exc:  # noqa: BLE001 - logged; must not mask the original failure
        # The loudest failure in the function, and the one case where an alarm is
        # genuinely lost: processing failed and preserving it failed too.
        logger.error(
            json.dumps(
                {
                    "event": "alarm_park_failed",
                    "reason": reason,
                    "detail": str(exc)[:500],
                    **log_base,
                }
            )
        )
        return

    logger.error(
        json.dumps(
            {
                "event": "alarm_parked",
                "reason": reason,
                "messageId": response.get("MessageId"),
                **log_base,
            }
        )
    )


def _agent_client(target: Target) -> Any:
    """Return a DevOps Agent client for the target, assuming a role if needed.

    Clients are cached per target for the life of the execution environment. The
    assumed-role credential is not refreshed here because the function's lifetime is
    far shorter than the session, and boto3 raises clearly if it ever expires.
    """
    cache_key = target.role_arn or "local"
    if cache_key in _agent_clients:
        return _agent_clients[cache_key]

    import boto3
    from botocore.config import Config

    # Retries matter more here than for the MCP tools: a dropped alarm is a missed
    # incident, whereas a dropped tool call is a slightly thinner investigation. But the
    # retry budget has to fit inside the invocation, and it did not.
    #
    # Four attempts at connect 5 + read 20 is a worst case of 100 s against a 30 s
    # function timeout. So an unreachable endpoint consumed the entire invocation and the
    # sandbox was killed mid-call -- which is not merely a slow failure, it is a *lost
    # alarm*: a timeout terminates the process rather than raising, so the except block
    # below never runs and `_park_alarm` never gets the chance to preserve anything. The
    # dead-letter queue stayed empty and `PrtgAlarmsLost` could not fire, because its
    # metric filter needs a log event a dead process cannot emit.
    #
    # Observed exactly that way three times before the missing VPC endpoint was found.
    # Bounding the budget does not depend on that diagnosis: any unreachable dependency
    # fails the same way, so this is worth keeping regardless.
    #
    # Two attempts rather than four, sized so the worst case leaves `_PARK_RESERVE_SECONDS`
    # for the park that follows a failure.
    budget = _agent_call_budget_seconds()
    per_attempt = budget / _AGENT_MAX_ATTEMPTS
    boto_config = Config(
        # "standard" rather than "adaptive": adaptive adds client-side throttling delays
        # that are not counted in the timeouts above, so the worst case stops being
        # predictable -- which is the property this whole calculation depends on.
        retries={"max_attempts": _AGENT_MAX_ATTEMPTS, "mode": "standard"},
        connect_timeout=min(3.0, per_attempt / 3),
        read_timeout=per_attempt - min(3.0, per_attempt / 3),
    )
    region = os.environ.get("AGENT_REGION") or os.environ["AWS_REGION"]

    # Unset means "use the SDK default", which is right whenever this function has a
    # route to the internet. In a fully-private deployment it is not: the DevOps Agent
    # interface endpoint publishes private DNS for cp.aidevops.<region>.api.aws, while
    # boto3 defaults to aidevops.<region>.amazonaws.com. Those are different domains, so
    # unlike every other endpoint this stack creates, private DNS does not intercept the
    # call -- the endpoint alone changes nothing, and the request goes to a name with no
    # answer inside the VPC and hangs until the sandbox is killed.
    endpoint_url = os.environ.get("DEVOPS_ENDPOINT_URL") or None

    if target.role_arn:
        sts = boto3.client("sts")
        assume_args: dict[str, Any] = {
            "RoleArn": target.role_arn,
            "RoleSessionName": f"prtg-alarm-{(target.account_id or 'x')[-4:]}",
            # Short-lived: the session only has to outlive one API call.
            "DurationSeconds": 900,
        }
        external_id = os.environ.get("EXTERNAL_ID")
        if external_id:
            # Required by the target account's trust policy. Guards against the
            # confused-deputy problem.
            assume_args["ExternalId"] = external_id

        credentials = sts.assume_role(**assume_args)["Credentials"]
        client = boto3.client(
            "devops-agent",
            region_name=region,
            endpoint_url=endpoint_url,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            config=boto_config,
        )
    else:
        client = boto3.client(
            "devops-agent", region_name=region, endpoint_url=endpoint_url, config=boto_config
        )

    _agent_clients[cache_key] = client
    return client


def _is_idempotency_conflict(exc: Exception) -> bool:
    """Whether ``exc`` is CreateBacklogTask rejecting a reused client token.

    Matched on the error code from the response rather than on an exception class, so
    that botocore does not have to be imported at module scope -- and so a change in
    which botocore exception subclass is raised does not quietly turn suppressed
    duplicates back into dead-letter messages.
    """
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    return response.get("Error", {}).get("Code") == "ConflictException"


def _looks_like_replay(response: dict[str, Any]) -> bool:
    """Heuristically decide whether an idempotent replay returned an existing task.

    The API does not flag a replay explicitly, so this is best effort and is used
    only for a metric, never for control flow.
    """
    created = response.get("createdAt")
    if created is None:
        return False
    try:
        # createdAt may be a datetime or an ISO string depending on the SDK path.
        epoch = created.timestamp() if hasattr(created, "timestamp") else None
    except Exception:  # noqa: BLE001
        return False
    if epoch is None:
        return False
    # More than 30 seconds old means it was created by an earlier invocation.
    return (time.time() - epoch) > 30


# --- Configuration ----------------------------------------------------------


def _dedup_window_minutes() -> int:
    try:
        return int(os.environ.get("DEDUP_WINDOW_MINUTES", "30"))
    except ValueError:
        return 30


def _skip_test_notifications() -> bool:
    return (os.environ.get("SKIP_TEST_NOTIFICATIONS", "true").strip().lower()) in (
        "1",
        "true",
        "yes",
        "on",
    )
