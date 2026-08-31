"""PRTG MCP tool definitions - the single source of truth for the tool surface.

This module is deliberately dependency-free (standard library only) because it is
imported from two places that must never disagree:

1. The Lambda handler (``handler.py``), which builds its dispatch table from
   ``TOOL_SPECS`` and refuses to serve a tool that is not declared here.
2. The CDK stack, which converts ``TOOL_SPECS`` into the AgentCore Gateway target
   tool schema at synthesis time.

If the schema advertised to the agent and the schema the handler enforces drift
apart, the agent constructs calls that fail at runtime - a class of bug that is
tedious to diagnose because the failure surfaces inside an investigation rather
than at deploy time. Deriving both from this module makes that drift impossible,
and ``tests/unit/test_tool_contract.py`` asserts it.

Every tool here is READ-ONLY. All of them issue HTTP GET requests against PRTG's
read APIs, and none accepts a parameter that can influence the request
destination. That property is what makes this integration safe to expose to an
autonomous agent; see ``docs/security.md``. Do not add a mutating tool.
"""

from __future__ import annotations

from typing import Any, Final

# --- Shared constraints -----------------------------------------------------
#
# The upstream reference implementation defaulted to count=500 and, in one
# fallback path, requested 50,000 rows. Unbounded result sets are a problem in
# three ways: PRTG spends real CPU building them, the Lambda can exhaust memory
# assembling the JSON, and the agent pays for every token of a payload it mostly
# discards. Bounding the parameter in the published schema means the agent asks
# for sane page sizes in the first place, rather than being corrected afterwards.

MAX_COUNT: Final[int] = 5_000
DEFAULT_COUNT: Final[int] = 100

#: PRTG object IDs are positive integers.
_OBJECT_ID: Final[dict[str, Any]] = {
    "type": "integer",
    "minimum": 1,
    "description": "PRTG object ID (objid). Obtain it from get_sensors, get_devices, get_groups or search.",
}

_COUNT: Final[dict[str, Any]] = {
    "type": "integer",
    "minimum": 1,
    "maximum": MAX_COUNT,
    "default": DEFAULT_COUNT,
    "description": f"Maximum rows to return (1-{MAX_COUNT}). Prefer a small value and narrow with filters.",
}

#: Human-readable sensor states, mapped to PRTG's numeric status codes in
#: ``prtg_client.STATUS_CODES``. Exposing words rather than the raw integers
#: means the agent does not have to know that "down" is 5 and "paused" is a set
#: of four different codes.
SENSOR_STATUSES: Final[tuple[str, ...]] = (
    "up",
    "down",
    "warning",
    "paused",
    "unknown",
    "unusual",
    "down_acknowledged",
    "down_partial",
)

#: PRTG's historic-data endpoints expect this timestamp layout.
PRTG_DATETIME_PATTERN: Final[str] = r"^\d{4}-\d{2}-\d{2}(-\d{2}-\d{2}-\d{2})?$"
PRTG_DATETIME_HINT: Final[str] = "PRTG timestamp, 'YYYY-MM-DD-HH-MM-SS' or 'YYYY-MM-DD'."

SEARCH_OBJECT_TYPES: Final[tuple[str, ...]] = ("sensors", "devices", "groups")

#: Relative windows PRTG accepts for the system log.
MESSAGE_DATE_RANGES: Final[tuple[str, ...]] = (
    "today",
    "yesterday",
    "7days",
    "30days",
    "6months",
    "12months",
)


def _schema(
    properties: dict[str, Any] | None = None,
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build a JSON Schema object, rejecting undeclared properties.

    ``additionalProperties: False`` is set on every tool. It gives the agent a
    fast, explicit failure when it invents a parameter, instead of PRTG silently
    ignoring the unknown key and returning a result that looks plausible but was
    never actually filtered the way the agent intended. Silently-wrong data is
    considerably worse than an error during an incident investigation.
    """
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


# --- Tool specifications ----------------------------------------------------
#
# Descriptions are written for the agent, not for a human reader. They say when
# to reach for the tool, because the agent chooses between nine of them with no
# context beyond this text. Vague descriptions produce poor tool selection.

TOOL_SPECS: Final[tuple[dict[str, Any], ...]] = (
    {
        "name": "get_sensors",
        "description": (
            "List PRTG sensors, optionally filtered by state, tag, or name substring. "
            "Start here when investigating an alert to find what else is unhealthy: "
            "call with status='down' to see everything currently failing. Returns "
            "state, last value, last check time, and how long a sensor has been down."
        ),
        "input_schema": _schema(
            {
                "id": {
                    **_OBJECT_ID,
                    "description": "Limit results to descendants of this group, device or probe ID. Omit to search everything.",
                },
                "status": {
                    "type": "string",
                    "enum": list(SENSOR_STATUSES),
                    # The valid values are repeated in the description because
                    # AgentCore Gateway strips `enum` when it republishes this
                    # schema over MCP. The description is preserved, so it is the
                    # only channel that actually reaches the agent. See
                    # docs/architecture.md#what-the-gateway-preserves.
                    "description": (
                        "Return only sensors in this state. One of: " + ", ".join(SENSOR_STATUSES) + "."
                    ),
                },
                "tags": {
                    "type": "string",
                    "maxLength": 200,
                    "description": (
                        "Comma-separated PRTG tags, up to 200 characters. Matches sensors carrying "
                        "any of them."
                    ),
                },
                "text_filter": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "Case-insensitive substring match on the sensor name.",
                },
                "count": _COUNT,
            }
        ),
    },
    {
        "name": "get_sensor_details",
        "description": (
            "Get the full configuration and current state of one sensor, including its "
            "status message, uptime/downtime totals, and parent device. Use after "
            "get_sensors or search has identified a specific sensor worth examining."
        ),
        "input_schema": _schema({"id": _OBJECT_ID}, required=["id"]),
    },
    {
        "name": "get_channels",
        "description": (
            "List the data channels of one sensor with their current, minimum and maximum "
            "values. Use this to see the actual measurements behind a sensor's state - "
            "for example which specific disk or interface on a multi-channel sensor is "
            "the one breaching its threshold."
        ),
        "input_schema": _schema({"id": _OBJECT_ID}, required=["id"]),
    },
    {
        "name": "get_devices",
        "description": (
            "List monitored devices with their hostname/IP, group, location, and a count "
            "of sensors in each state. Use it to judge whether a problem is confined to "
            "one sensor or the whole device is affected, and to map a PRTG device to the "
            "host it monitors so findings can be correlated with AWS resources."
        ),
        "input_schema": _schema(
            {
                "id": {
                    **_OBJECT_ID,
                    "description": "Limit results to devices under this group or probe ID.",
                },
                "text_filter": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "Case-insensitive substring match on the device name.",
                },
                "count": _COUNT,
            }
        ),
    },
    {
        "name": "get_groups",
        "description": (
            "List PRTG groups with aggregate sensor counts per state. Use it to "
            "understand the monitoring hierarchy, or to see whether an incident spans a "
            "whole group such as a site or an environment."
        ),
        "input_schema": _schema(
            {
                "id": {**_OBJECT_ID, "description": "Limit results to subgroups of this group or probe ID."},
                "count": _COUNT,
            }
        ),
    },
    {
        "name": "get_sensor_history",
        "description": (
            "Get historic readings for one sensor over a time range. This is the tool for "
            "establishing when a problem began and whether it was gradual or sudden, and "
            "for distinguishing a genuine change from normal variation. Use the 'avg' "
            "parameter to downsample long ranges instead of requesting raw data."
        ),
        "input_schema": _schema(
            {
                "id": _OBJECT_ID,
                "sdate": {
                    "type": "string",
                    "pattern": PRTG_DATETIME_PATTERN,
                    "description": f"Range start. {PRTG_DATETIME_HINT}",
                },
                "edate": {
                    "type": "string",
                    "pattern": PRTG_DATETIME_PATTERN,
                    "description": f"Range end. {PRTG_DATETIME_HINT}",
                },
                "avg": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 86_400,
                    "default": 0,
                    "description": (
                        "Averaging interval in seconds, 0 to 86400; 0 returns raw readings. Use "
                        "300 or 3600 for multi-day ranges to keep the response small."
                    ),
                },
                "count": _COUNT,
            },
            required=["id", "sdate", "edate"],
        ),
    },
    {
        "name": "get_server_status",
        "description": (
            "Get overall PRTG health and a count of sensors in each state. Use it first to "
            "establish whether an alert is an isolated fault or part of something "
            "widespread, and to confirm PRTG itself is healthy before trusting its data."
        ),
        "input_schema": _schema(),
    },
    {
        "name": "get_messages",
        "description": (
            "Read PRTG's system log, newest first. Use it to build a timeline around an "
            "incident and to catch state changes that no longer show in current status, "
            "such as a sensor that flapped and recovered."
        ),
        "input_schema": _schema(
            {
                "id": {**_OBJECT_ID, "description": "Limit to log entries for this object and its children."},
                "count": _COUNT,
                "date_range": {
                    "type": "string",
                    "enum": list(MESSAGE_DATE_RANGES),
                    # Values restated for the same reason as `status`.
                    "description": (
                        "Relative time window for log entries. One of: "
                        + ", ".join(MESSAGE_DATE_RANGES)
                        + "."
                    ),
                },
            }
        ),
    },
    {
        "name": "search",
        "description": (
            "Find PRTG objects by name substring when the numeric ID is unknown. This is "
            "the usual entry point when an alert names a host or service: search for that "
            "name to get the IDs the other tools need."
        ),
        "input_schema": _schema(
            {
                "query": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                    "description": "Case-insensitive substring to match against object names.",
                },
                "type": {
                    "type": "string",
                    "enum": list(SEARCH_OBJECT_TYPES),
                    "default": "sensors",
                    # Values and default restated for the same reason as `status`.
                    "description": (
                        "Which kind of PRTG object to search. One of: "
                        + ", ".join(SEARCH_OBJECT_TYPES)
                        + ". Defaults to sensors."
                    ),
                },
                "count": _COUNT,
            },
            required=["query"],
        ),
    },
)


def tool_names() -> tuple[str, ...]:
    """Return the declared tool names, in declaration order."""
    return tuple(spec["name"] for spec in TOOL_SPECS)


def input_schema_for(name: str) -> dict[str, Any]:
    """Return the JSON Schema for one tool's input.

    Raises:
        KeyError: if ``name`` is not a declared tool.
    """
    for spec in TOOL_SPECS:
        if spec["name"] == name:
            return spec["input_schema"]
    raise KeyError(f"No such tool: {name!r}. Declared tools: {', '.join(tool_names())}")


def as_gateway_tool_schema() -> list[dict[str, Any]]:
    """Render ``TOOL_SPECS`` in the shape AgentCore Gateway expects.

    The Gateway target schema uses camelCase ``inputSchema``, while this module
    uses snake_case to stay idiomatic for the Python handler. Converting in one
    place keeps that difference from leaking into either consumer.
    """
    return [
        {
            "name": spec["name"],
            "description": spec["description"],
            "inputSchema": spec["input_schema"],
        }
        for spec in TOOL_SPECS
    ]
