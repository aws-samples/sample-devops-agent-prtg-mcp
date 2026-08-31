"""Lambda entry point for the PRTG MCP tools, invoked by AgentCore Gateway.

Invocation contract
-------------------
AgentCore Gateway invokes this function once per tool call. The two halves of the
call arrive by different routes, which is unusual enough to be worth stating
plainly because it is the most common source of confusion when extending this:

* **The tool name** arrives in the client context, as
  ``context.client_context.custom["bedrockAgentCoreToolName"]``, formatted
  ``<targetName>___<toolName>`` with three underscores.
* **The arguments** arrive as the entire event payload. The event is *not* a
  wrapper object with an ``arguments`` key; it *is* the arguments.

So an empty ``event`` is normal for a no-argument tool such as
``get_server_status``, and a handler that looks for ``event["name"]`` will always
see ``None`` and report every tool as unknown.

The response shape is MCP's: a ``content`` list of typed parts, plus ``isError``.

This function has no dependencies outside the Lambda runtime's own boto3 and
urllib3, so it needs no packaged layer and no vendored wheels.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from collections.abc import Callable
from typing import Any

from . import tools as tool_specs
from .prtg_client import (
    SEARCH_COLUMNS,
    STATUS_CODES,
    PrtgAuthError,
    PrtgClient,
    PrtgError,
    install_log_scrubbing,
    redact,
)

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# The Lambda runtime installs its log handler during initialisation, so this runs
# after it exists and can attach to it. urllib3 logs the request URL on every retry,
# and PRTG carries the credential in that URL.
install_log_scrubbing()

#: Separator Gateway uses between target name and tool name.
_TOOL_NAME_SEPARATOR = "___"

#: Reused across invocations in a warm environment so the connection pool and the
#: cached credential survive between tool calls.
_client: PrtgClient | None = None


def _get_client() -> PrtgClient:
    global _client  # noqa: PLW0603 - deliberate warm-start cache
    if _client is None:
        _client = PrtgClient()
    return _client


# --- Tool implementations ---------------------------------------------------
#
# One function per entry in tools.TOOL_SPECS. Signatures use the same parameter
# names as the published schema, since the agent's arguments are passed through
# as keyword arguments.


def get_sensors(
    client: PrtgClient,
    *,
    id: int | None = None,  # noqa: A002 - name is fixed by the published schema
    status: str | None = None,
    tags: str | None = None,
    text_filter: str | None = None,
    count: int = tool_specs.DEFAULT_COUNT,
) -> Any:
    return client.table(
        "sensors",
        count=count,
        object_id=id,
        status_filter=STATUS_CODES.get(status) if status else None,
        tags=tags,
        name_filter=text_filter,
    )


def get_sensor_details(client: PrtgClient, *, id: int) -> Any:  # noqa: A002
    return client.request("/api/getsensordetails.json", {"id": int(id)})


def get_channels(client: PrtgClient, *, id: int) -> Any:  # noqa: A002
    return client.table("channels", count=tool_specs.MAX_COUNT, object_id=id, no_raw=True)


def get_devices(
    client: PrtgClient,
    *,
    id: int | None = None,  # noqa: A002
    text_filter: str | None = None,
    count: int = tool_specs.DEFAULT_COUNT,
) -> Any:
    return client.table("devices", count=count, object_id=id, name_filter=text_filter)


def get_groups(
    client: PrtgClient,
    *,
    id: int | None = None,  # noqa: A002
    count: int = tool_specs.DEFAULT_COUNT,
) -> Any:
    return client.table("groups", count=count, object_id=id)


def get_sensor_history(
    client: PrtgClient,
    *,
    id: int,  # noqa: A002
    sdate: str,
    edate: str,
    avg: int = 0,
    count: int = tool_specs.DEFAULT_COUNT,
) -> Any:
    return client.request(
        "/api/historicdata.json",
        {
            "id": int(id),
            "sdate": sdate,
            "edate": edate,
            "avg": int(avg),
            "count": max(1, min(int(count), tool_specs.MAX_COUNT)),
            "sortby": "-datetime",
        },
    )


def get_server_status(client: PrtgClient) -> Any:
    """Return PRTG health, falling back to a computed summary on older versions.

    ``/api/getstatus.htm`` is not available on every PRTG version and licence. The
    fallback derives the same counts from the sensor table. Unlike the reference
    implementation, which requested 50,000 rows to do this, the fallback asks only
    for the status column and stays within the normal page limit - an approximate
    count from a bounded query is far more useful than an exact one that times
    out or exhausts memory.

    The fallback is attempted **only when PRTG actually answered**. It exists for the
    case where the endpoint is missing, which arrives as an HTTP status; it cannot help
    when PRTG is unreachable, because a connection failure on the primary request is
    guaranteed to repeat on the fallback. Retrying it anyway is not merely wasteful, it
    loses the diagnosis: each request path spends ``connect_timeout`` times
    ``1 + max_retries`` -- 15 s at the defaults -- so the two together reach the 30 s
    default Lambda timeout exactly. The function computed a precise, actionable error
    and was then killed before it could return it, so the agent saw an unhandled
    invocation error instead. Observed against a genuinely unreachable PRTG: every other
    tool returned its error in 20 s, while this one timed out. It is also the tool most
    likely to be called first, as a health check.

    ``PrtgError.status`` is the discriminator. It is set only where PRTG returned an
    HTTP response; connection and TLS failures leave it ``None``.
    """
    try:
        return client.request("/api/getstatus.htm", {"id": 0})
    except PrtgAuthError:
        raise
    except PrtgError as exc:
        if exc.status is None:
            raise
        logger.info(
            json.dumps(
                {
                    "event": "getstatus_unavailable_using_fallback",
                    "detail": redact(exc.message)[:300],
                }
            )
        )
        data = client.table("sensors", count=tool_specs.MAX_COUNT, columns="objid,status", no_raw=False)
        sensors = data.get("sensors", []) if isinstance(data, dict) else []
        counts: dict[str, int] = {}
        for name, codes in STATUS_CODES.items():
            counts[name] = sum(1 for s in sensors if s.get("status_raw") in codes)
        return {
            "sensor_summary": {"total": len(sensors), **counts},
            "note": (
                f"Derived from a sample of up to {tool_specs.MAX_COUNT} sensors because this PRTG "
                "instance does not expose /api/getstatus.htm. Counts are approximate if the "
                "instance has more sensors than that."
            ),
        }


def get_messages(
    client: PrtgClient,
    *,
    id: int | None = None,  # noqa: A002
    count: int = tool_specs.DEFAULT_COUNT,
    date_range: str | None = None,
) -> Any:
    return client.table(
        "messages",
        count=count,
        object_id=id,
        date_range=date_range,
        sort_by="-datetime",
    )


def search(
    client: PrtgClient,
    *,
    query: str,
    type: str = "sensors",  # noqa: A002 - name is fixed by the published schema
    count: int = tool_specs.DEFAULT_COUNT,
) -> Any:
    return client.table(
        type,
        count=count,
        name_filter=query,
        columns=SEARCH_COLUMNS.get(type, SEARCH_COLUMNS["sensors"]),
    )


#: Dispatch table. Keys must exactly match ``tools.TOOL_SPECS`` names; the
#: contract test enforces this in both directions.
TOOL_IMPLEMENTATIONS: dict[str, Callable[..., Any]] = {
    "get_sensors": get_sensors,
    "get_sensor_details": get_sensor_details,
    "get_channels": get_channels,
    "get_devices": get_devices,
    "get_groups": get_groups,
    "get_sensor_history": get_sensor_history,
    "get_server_status": get_server_status,
    "get_messages": get_messages,
    "search": search,
}


# --- Argument validation ----------------------------------------------------


class ValidationError(Exception):
    """The agent's arguments did not satisfy the tool's published schema."""


def validate_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Check arguments against the tool's schema and coerce simple types.

    Implemented directly against the subset of JSON Schema used in ``tools.py``
    rather than pulling in a validation library, which keeps the deployment
    package free of external dependencies.

    Validating here matters for more than hygiene. The agent is a language model
    constructing calls from a text schema, so it will occasionally pass a string
    where an integer belongs or invent a plausible-sounding enum value. Rejecting
    that with a specific message lets the agent correct itself on the next turn.
    Passing it through to PRTG, which ignores parameters it does not understand,
    would instead return data that looks like an answer but was never filtered as
    intended.

    Returns:
        The validated arguments, with numeric strings coerced to numbers.

    Raises:
        ValidationError: with a message written for the agent to act on.
    """
    schema = tool_specs.input_schema_for(tool_name)
    properties: dict[str, Any] = schema.get("properties", {})
    required: list[str] = schema.get("required", [])

    unknown = set(arguments) - set(properties)
    if unknown:
        raise ValidationError(
            f"Unknown parameter(s) for {tool_name}: {', '.join(sorted(unknown))}. "
            f"Accepted parameters: {', '.join(sorted(properties)) or 'none'}."
        )

    missing = [key for key in required if arguments.get(key) is None]
    if missing:
        raise ValidationError(f"Missing required parameter(s) for {tool_name}: {', '.join(missing)}.")

    validated: dict[str, Any] = {}
    for key, value in arguments.items():
        validated[key] = _validate_value(tool_name, key, value, properties[key])
    return validated


def _validate_value(tool_name: str, key: str, value: Any, spec: dict[str, Any]) -> Any:
    expected = spec.get("type")

    if expected == "integer":
        if isinstance(value, bool):
            raise ValidationError(f"Parameter '{key}' of {tool_name} must be an integer, not a boolean.")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be an integer; received {value!r}."
            ) from exc
        if "minimum" in spec and value < spec["minimum"]:
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be at least {spec['minimum']}; received {value}."
            )
        if "maximum" in spec and value > spec["maximum"]:
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be at most {spec['maximum']}; received {value}. "
                "Request a smaller page, or narrow the query with a filter."
            )
        return value

    if expected == "string":
        if not isinstance(value, str):
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be a string; received {type(value).__name__}."
            )
        if "enum" in spec and value not in spec["enum"]:
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be one of: {', '.join(spec['enum'])}; "
                f"received {value!r}."
            )
        if "minLength" in spec and len(value) < spec["minLength"]:
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be at least {spec['minLength']} character(s)."
            )
        if "maxLength" in spec and len(value) > spec["maxLength"]:
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} must be at most {spec['maxLength']} characters; "
                f"received {len(value)}."
            )
        if "pattern" in spec and not re.match(spec["pattern"], value):
            raise ValidationError(
                f"Parameter '{key}' of {tool_name} is malformed. {spec.get('description', '')}".strip()
            )
        return value

    return value


# --- Response envelopes -----------------------------------------------------


def _ok(payload: Any) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False, default=str)}],
        "isError": False,
    }


def _error(message: str, *, correlation_id: str) -> dict[str, Any]:
    """Build an error response that is safe to place in the agent's context.

    The correlation ID is echoed so an operator can join what the agent reports
    back to the CloudWatch log entry holding the full detail.
    """
    return {
        "content": [{"type": "text", "text": f"{message} (correlationId: {correlation_id})"}],
        "isError": True,
    }


# --- Entry point ------------------------------------------------------------


def extract_tool_name(context: Any) -> str | None:
    """Pull the tool name out of the Lambda client context.

    Gateway sends ``<targetName>___<toolName>``. The target name is stripped so a
    deployment is free to rename its Gateway target without the handler caring.
    """
    client_context = getattr(context, "client_context", None)
    custom = getattr(client_context, "custom", None) if client_context else None
    if not custom:
        return None

    raw = custom.get("bedrockAgentCoreToolName") or ""
    if not raw:
        return None
    if _TOOL_NAME_SEPARATOR in raw:
        return raw.split(_TOOL_NAME_SEPARATOR, 1)[1]
    return raw


def handler(event: Any, context: Any) -> dict[str, Any]:  # noqa: PLR0911 - each return is a distinct error envelope
    """Serve one MCP tool call.

    Always returns an MCP response envelope. Raising out of this function would
    make Gateway report a generic target failure, which tells the agent nothing it
    can act on; a structured ``isError`` response lets it correct course or move
    on to a different tool.
    """
    correlation_id = uuid.uuid4().hex[:12]
    started = time.monotonic()

    tool_name = extract_tool_name(context)
    arguments = {k: v for k, v in (event or {}).items() if v is not None} if isinstance(event, dict) else {}

    log_base = {"correlationId": correlation_id, "tool": tool_name, "argumentKeys": sorted(arguments)}
    logger.info(json.dumps({"event": "tool_invoked", **log_base}))

    if not tool_name or tool_name not in TOOL_IMPLEMENTATIONS:
        logger.warning(json.dumps({"event": "unknown_tool", **log_base}))
        return _error(
            f"Unknown tool {tool_name!r}. Available tools: {', '.join(tool_specs.tool_names())}.",
            correlation_id=correlation_id,
        )

    try:
        validated = validate_arguments(tool_name, arguments)
    except ValidationError as exc:
        logger.warning(json.dumps({"event": "invalid_arguments", "detail": str(exc), **log_base}))
        return _error(str(exc), correlation_id=correlation_id)

    try:
        result = TOOL_IMPLEMENTATIONS[tool_name](_get_client(), **validated)
    except PrtgAuthError as exc:
        logger.error(json.dumps({"event": "prtg_auth_failed", "detail": exc.message, **log_base}))
        return _error(exc.message, correlation_id=correlation_id)
    except PrtgError as exc:
        logger.error(json.dumps({"event": "prtg_request_failed", "detail": exc.message, **log_base}))
        return _error(exc.message, correlation_id=correlation_id)
    except TypeError as exc:
        # A signature mismatch between the schema and the implementation. The
        # contract test should prevent this from ever reaching production.
        logger.exception(json.dumps({"event": "tool_signature_mismatch", **log_base}))
        return _error(
            f"Tool {tool_name} could not be called with the supplied arguments: {redact(exc)}",
            correlation_id=correlation_id,
        )
    except Exception as exc:  # noqa: BLE001 - nothing may escape this handler
        # Log the traceback for operators, but return only a scrubbed summary: an
        # unexpected exception's text can carry the request URL and therefore the
        # PRTG credential, and this return value goes into the model's context.
        logger.exception(json.dumps({"event": "tool_unhandled_error", **log_base}))
        return _error(
            f"{tool_name} failed unexpectedly: {type(exc).__name__}. See CloudWatch Logs for detail.",
            correlation_id=correlation_id,
        )

    elapsed_ms = int((time.monotonic() - started) * 1000)
    logger.info(json.dumps({"event": "tool_succeeded", "durationMs": elapsed_ms, **log_base}))
    return _ok(result)
