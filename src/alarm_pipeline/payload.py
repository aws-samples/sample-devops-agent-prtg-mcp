"""Parsing PRTG notification payloads, and deriving priority and idempotency.

PRTG's "Execute HTTP Action" has several behaviours that are not obvious and are
not documented together anywhere. They are handled here rather than scattered
through the handler:

* The payload is sent as ``application/x-www-form-urlencoded`` even when its body
  is JSON, and the whole body is URL-encoded. It must be unquoted before parsing.
* Placeholders such as ``%sensor`` are substituted at send time, but **not** for a
  test notification, so a test arrives with literal ``%sensor`` text.
* Custom headers are not supported at all, which is why the API is protected by
  source address rather than an API key.
* The payload must be a single line. A line break inside it truncates the body,
  which surfaces as a JSON parse error on a payload that looks correct in the PRTG
  UI.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Final

#: PRTG's five-star priority to the DevOps Agent priority values.
#: CreateBacklogTask accepts CRITICAL | HIGH | MEDIUM | LOW | MINIMAL.
#:
#: The reference implementation hardcoded every investigation to HIGH, which makes
#: the field useless for triage: a link-utilisation warning and a down database
#: arrive indistinguishable, and an operator facing a backlog cannot tell which to
#: open first.
PRIORITY_BY_PRTG_STARS: Final[dict[int, str]] = {
    5: "CRITICAL",
    4: "HIGH",
    3: "MEDIUM",
    2: "LOW",
    1: "MINIMAL",
}

DEFAULT_PRIORITY: Final[str] = "MEDIUM"

#: PRTG sensor states that indicate a live failure, lowercased for comparison.
#: A sensor that is genuinely Down is escalated regardless of its configured
#: priority, because priority in PRTG describes importance of the *sensor*, not
#: severity of the current state.
_DOWN_STATES: Final[tuple[str, ...]] = ("down", "down (partial)")

#: States that are down but already being handled, so they are not escalated.
_ACKNOWLEDGED_STATES: Final[tuple[str, ...]] = ("down (acknowledged)",)

#: The four original placeholders. Every PRTG version substitutes these, which is
#: why test-notification detection is based on them alone - see ``parse_alarm``.
_CORE_FIELDS: Final[tuple[str, ...]] = ("sensor", "device", "status", "message")

#: Fields read from the PRTG payload, keyed by the PRTG placeholder that fills them.
#:
#: Only these keys are read; any other key in the body is ignored. Adding a field
#: here is therefore only half of adding it to the integration - the other half is
#: the notification template, whose canonical copy is the ``PrtgNotificationPayload``
#: stack output.
#:
#: Three groups of PRTG placeholder are deliberately *not* here:
#:
#: * ``%settings`` - resolves to miscellaneous sensor settings, which Paessler
#:   documents as including "the user name for Windows, HTTP, POP3 credentials, and
#:   so on". It would copy the credentials PRTG uses to monitor its estate into the
#:   task description, this function's log group, and the dead-letter queue.
#: * ``%history``, ``%syslogmessages``, ``%trapmessages`` and their siblings -
#:   multi-line values. The payload must be a single line, and a line break
#:   truncates the body, so one of these rejects the whole alarm. The syslog and
#:   trap ones are documented as usable only in Send Email notifications anyway.
#: * ``%summarycount`` - resolves only in summarised notifications.
#:
#: Pure aliases are also omitted: ``%prio`` (= ``%priority``), ``%server``
#: (= ``%device``), ``%lastmessage`` (= ``%message``), ``%name`` (= ``%sensor``),
#: ``%statesince`` (= ``%since``), ``%comments`` (= ``%commentssensor``).
_FIELD_PLACEHOLDERS: Final[dict[str, str]] = {
    # Core: what happened. Present in every version.
    "sensor": "%sensor",
    "device": "%device",
    "status": "%status",
    "message": "%message",
    # Identity: where it happened. `host` is the field that makes an alarm
    # correlatable with an AWS resource; the rest of these name PRTG objects.
    "host": "%host",
    "sensorId": "%sensorid",
    "deviceId": "%deviceid",
    "group": "%group",
    "groupId": "%groupid",
    "probe": "%probe",
    "probeId": "%probeid",
    "location": "%location",
    "serviceUrl": "%serviceurl",
    # Measurement: how bad, and how it is rated.
    "lastValue": "%lastvalue",
    "lastStatus": "%laststatus",
    "priority": "%priority",
    # Timeline: when it started, and what the recent history is. These let the
    # agent bound a metrics query instead of guessing a window.
    "datetime": "%datetime",
    "since": "%since",
    "lastCheck": "%lastcheck",
    "lastUp": "%lastup",
    "lastDown": "%lastdown",
    "elapsedLastUp": "%elapsed_lastup",
    "elapsedLastDown": "%elapsed_lastdown",
    "downtime": "%downtime",
    "uptime": "%uptime",
    "cumulativeSince": "%cumsince",
    # Operator-supplied context. Tags and comments are the two places an operator
    # can record an AWS instance ID, account or ARN against a PRTG object, so they
    # are the route to an exact resource identity rather than an address lookup.
    "tags": "%tags",
    "parentTags": "%parenttags",
    "commentsSensor": "%commentssensor",
    "commentsDevice": "%commentsdevice",
    "commentsGroup": "%commentsgroup",
    "commentsProbe": "%commentsprobe",
    # Deep links, so a task cites PRTG rather than describing it.
    "sensorUrl": "%linksensor",
    "deviceUrl": "%linkdevice",
    "groupUrl": "%linkgroup",
    "probeUrl": "%linkprobe",
    # Which PRTG instance this came from. Worth having under fan-out, where more
    # than one PRTG server can feed the same pipeline.
    "siteName": "%sitename",
    "nodeName": "%nodename",
    "timezone": "%timezone",
}

_TEXT_FIELDS: Final[tuple[str, ...]] = tuple(_FIELD_PLACEHOLDERS)

#: Per-field cap for values PRTG does not bound. Comments and tags are free text of
#: arbitrary length, and the description as a whole is truncated to the API limit,
#: so an unbounded field left uncapped could push the identity block off the end.
_FREE_TEXT_LIMIT: Final[int] = 600


def _clip(value: str, limit: int = _FREE_TEXT_LIMIT) -> str:
    """Collapse a value onto one line and cap its length.

    PRTG comment fields can contain newlines even though the payload itself cannot,
    because the operator typed them into a multi-line box and PRTG substitutes the
    value after the body has been parsed. Left alone they would break the
    label-per-line layout of the description.
    """
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


def payload_template() -> str:
    """Return the single-line payload PRTG's notification should be configured with.

    Derived from ``_FIELD_PLACEHOLDERS`` so there is one source of truth. The CDK
    stack emits this as the ``PrtgNotificationPayload`` output and the docs quote it;
    both previously held their own copy of the string, which is how the three drift
    apart when a field is added.

    Must stay on one line: a line break in the PRTG payload field truncates the body.
    """
    return "{" + ",".join(f'"{key}":"{ph}"' for key, ph in _FIELD_PLACEHOLDERS.items()) + "}"


def minimal_payload_template() -> str:
    """Return the smallest payload that still produces a useful investigation.

    Used in the rejection message, where the full template would be more noise than
    help: someone reading that error needs the shape, not every optional field.
    """
    keys = (
        *_CORE_FIELDS,
        "host",
        "sensorId",
        "deviceId",
        "group",
        "probe",
        "priority",
        "datetime",
    )
    return "{" + ",".join(f'"{key}":"{_FIELD_PLACEHOLDERS[key]}"' for key in keys) + "}"


class PayloadError(ValueError):
    """The notification body could not be understood."""


@dataclass(frozen=True)
class PrtgAlarm:
    """One PRTG notification, normalised."""

    sensor: str
    device: str
    status: str
    message: str

    #: IP or DNS name of the device, from ``%host`` - the address PRTG actually
    #: connects to. For a monitored EC2 instance this is normally the private IP or
    #: private DNS name, which makes it the one field in the payload that can be
    #: resolved to an AWS resource. ``device`` is only a PRTG display label and
    #: ``device_id`` is internal to PRTG; neither means anything outside it.
    host: str = ""

    sensor_id: str = ""
    device_id: str = ""
    group: str = ""
    group_id: str = ""
    probe: str = ""
    probe_id: str = ""
    location: str = ""
    service_url: str = ""

    last_value: str = ""
    last_status: str = ""
    priority: str = ""

    datetime: str = ""
    since: str = ""
    last_check: str = ""
    last_up: str = ""
    last_down: str = ""
    elapsed_last_up: str = ""
    elapsed_last_down: str = ""
    downtime: str = ""
    uptime: str = ""
    cumulative_since: str = ""

    tags: str = ""
    parent_tags: str = ""
    comments_sensor: str = ""
    comments_device: str = ""
    comments_group: str = ""
    comments_probe: str = ""

    sensor_url: str = ""
    device_url: str = ""
    group_url: str = ""
    probe_url: str = ""

    site_name: str = ""
    node_name: str = ""
    timezone: str = ""

    #: True when the payload still contains literal ``%placeholder`` text in one of
    #: the core fields, which means PRTG sent a test notification rather than a real
    #: alarm.
    is_test: bool = False

    @property
    def is_down(self) -> bool:
        return self.status.strip().lower() in _DOWN_STATES

    @property
    def is_acknowledged(self) -> bool:
        return self.status.strip().lower() in _ACKNOWLEDGED_STATES

    def title(self) -> str:
        """Investigation title.

        Leads with the device rather than the sensor: an operator scanning a
        backlog recognises the host first, and PRTG sensor names are often generic
        ("CPU Load", "Ping") and repeat across every device.
        """
        prefix = "PRTG test notification" if self.is_test else "PRTG"
        title = f"{prefix}: {self.device} - {self.sensor} is {self.status}"
        # CreateBacklogTask caps the title at 400 characters.
        return title[:400]

    def description(self) -> str:
        """Investigation description, written to be useful to the agent.

        Ordered identity, then state, then the PRTG object IDs, then everything
        softer. That order is load-bearing rather than cosmetic: the description is
        truncated to the API's limit, and several fields PRTG can supply - comments
        and tags especially - are free text with no length bound. Anything the agent
        must not lose therefore has to appear above them.

        Every section is optional, so a minimal notification template still yields a
        coherent description and a full one yields a longer one.
        """
        lines: list[str] = [f"PRTG reported a state change on {self.device}."]

        def section(heading: str, rows: list[tuple[str, str]]) -> None:
            filled = [(label, _clip(value)) for label, value in rows if value]
            if not filled:
                return
            width = max(len(label) for label, _ in filled)
            lines.extend(["", f"{heading}:"])
            lines.extend(f"  {label + ':':<{width + 1}} {value}" for label, value in filled)

        section(
            "Affected host",
            [
                ("Device", self.device),
                # Labelled 'Address' rather than 'Host' because that is what it is,
                # and because 'host' invites confusion with the device name above.
                ("Address", self.host),
                ("Location", self.location),
                ("Service URL", self.service_url),
                ("Group", self.group),
                ("Probe", self.probe),
            ],
        )

        section(
            "What happened",
            [
                ("Sensor", self.sensor),
                # %status carries the transition ("Up -> Down" on some versions),
                # while %laststatus is the current state alone. Both are shown
                # because which one is more useful depends on the PRTG version.
                ("Status", self.status),
                ("Current state", self.last_status),
                ("Message", self.message),
                ("Last value", self.last_value),
                ("PRTG priority", self.priority),
            ],
        )

        if self.sensor_id or self.device_id or self.group_id or self.probe_id:
            lines += ["", "PRTG object IDs, for use with the PRTG MCP tools:"]
            if self.sensor_id:
                lines.append(
                    f"  sensor id {self.sensor_id} - get_sensor_details, get_channels, get_sensor_history"
                )
            if self.device_id:
                lines.append(f"  device id {self.device_id} - get_devices, get_sensors")
            if self.group_id:
                lines.append(f"  group id {self.group_id} - get_groups, get_sensors")
            if self.probe_id:
                lines.append(f"  probe id {self.probe_id} - get_devices, get_sensors")

        # The explicit bridge to the AWS half of the investigation. Without it the
        # agent has a device label and a set of PRTG-internal integers, none of
        # which identify anything in AWS.
        if self.host and not self.is_test:
            lines += [
                "",
                "Identifying the AWS resource:",
                f"  '{_clip(self.host, 200)}' is the address PRTG connects to for this device. For a "
                "monitored EC2 instance it is normally the private IP or private DNS name, so it is "
                "the key for correlating this alarm with an AWS resource.",
                "  Note that a private IP is unique only within a VPC and is reassigned over time, so "
                "confirm any match against the expected account and region rather than treating an "
                "address as an identity. The tags and comments below may carry an instance ID "
                "recorded by an operator, which is exact where an address lookup is not.",
            ]

        section(
            "Timeline",
            [
                ("Event time", self.datetime),
                ("In this state since", self.since),
                ("Last check", self.last_check),
                ("Last up", self.last_up),
                ("Last down", self.last_down),
                ("Time since last up", self.elapsed_last_up),
                ("Time since last down", self.elapsed_last_down),
                ("Accumulated downtime", self.downtime),
                ("Accumulated uptime", self.uptime),
                ("Accumulating since", self.cumulative_since),
                ("PRTG timezone", self.timezone),
            ],
        )

        # Below the identity blocks: these are the unbounded fields, and each is
        # individually clipped by `section` as well.
        section(
            "Operator-supplied context",
            [
                ("Tags", self.tags),
                ("Parent object tags", self.parent_tags),
                ("Sensor comments", self.comments_sensor),
                ("Device comments", self.comments_device),
                ("Group comments", self.comments_group),
                ("Probe comments", self.comments_probe),
            ],
        )

        section(
            "In PRTG",
            [
                ("Sensor", self.sensor_url),
                ("Device", self.device_url),
                ("Group", self.group_url),
                ("Probe", self.probe_url),
                ("PRTG site", self.site_name),
                ("Cluster node", self.node_name),
            ],
        )

        if self.is_test:
            lines += [
                "",
                "NOTE: this is a PRTG test notification. PRTG does not substitute placeholders for "
                "test notifications, so the values above are literal placeholder text rather than "
                "real monitoring data. No investigation is warranted.",
            ]

        # CreateBacklogTask caps the description at 10,000 characters.
        return "\n".join(lines)[:10_000]


def parse_alarm(event: dict[str, Any]) -> PrtgAlarm:
    """Build a ``PrtgAlarm`` from an API Gateway proxy event.

    Accepts, in order of preference: a JSON body, a URL-encoded JSON body, and a
    genuine form-encoded body. Being liberal here is deliberate - PRTG's exact
    encoding varies with version and with how the notification was configured, and
    a rejected alarm is a missed incident.

    Raises:
        PayloadError: if no recognisable PRTG fields could be found.
    """
    raw = event.get("body") or ""

    if event.get("isBase64Encoded"):
        import base64

        try:
            raw = base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            raise PayloadError("Body was flagged base64 but could not be decoded.") from exc

    content_type = header(event, "content-type").lower()
    body = _extract_body(raw, content_type)

    present = {key: str(body.get(key, "") or "").strip() for key in _TEXT_FIELDS}
    if not any(present.values()):
        raise PayloadError(
            "No PRTG fields were found in the request body. The PRTG notification payload should be "
            "single-line JSON. The minimum useful form is: " + minimal_payload_template()
        )

    # PRTG substitutes placeholders only for real notifications. A body still
    # containing '%sensor' is therefore a test from the PRTG UI, and treating it as
    # a real alarm would create a meaningless investigation.
    #
    # Judged on the four core placeholders rather than on every field, because PRTG
    # leaves an *unrecognised* placeholder as literal text too. Judging the whole
    # payload would mean a single placeholder the local PRTG version does not
    # support turns every real alarm into a "test": acknowledged with 200, no
    # investigation created, and nothing recorded as an error anywhere. Basing the
    # decision on placeholders that have existed in every PRTG version removes that
    # failure mode, which is what makes it safe to send a wide payload.
    is_test = any(present[key].startswith("%") for key in _CORE_FIELDS if present[key])

    # Outside a test, an unresolved placeholder in any other field is treated as
    # absent - which is what it means. The local PRTG version does not support it,
    # so there is no value to pass on, and handing the agent the literal string
    # '%lastvalue' as though it were a measurement is worse than handing it nothing.
    if not is_test:
        present = {key: "" if value.startswith("%") else value for key, value in present.items()}

    return PrtgAlarm(
        sensor=present["sensor"] or "unknown sensor",
        device=present["device"] or "unknown device",
        status=present["status"] or "unknown",
        message=present["message"] or "(no message supplied)",
        host=present["host"],
        sensor_id=present["sensorId"],
        device_id=present["deviceId"],
        group=present["group"],
        group_id=present["groupId"],
        probe=present["probe"],
        probe_id=present["probeId"],
        location=present["location"],
        service_url=present["serviceUrl"],
        last_value=present["lastValue"],
        last_status=present["lastStatus"],
        priority=present["priority"],
        datetime=present["datetime"],
        since=present["since"],
        last_check=present["lastCheck"],
        last_up=present["lastUp"],
        last_down=present["lastDown"],
        elapsed_last_up=present["elapsedLastUp"],
        elapsed_last_down=present["elapsedLastDown"],
        downtime=present["downtime"],
        uptime=present["uptime"],
        cumulative_since=present["cumulativeSince"],
        tags=present["tags"],
        parent_tags=present["parentTags"],
        comments_sensor=present["commentsSensor"],
        comments_device=present["commentsDevice"],
        comments_group=present["commentsGroup"],
        comments_probe=present["commentsProbe"],
        sensor_url=present["sensorUrl"],
        device_url=present["deviceUrl"],
        group_url=present["groupUrl"],
        probe_url=present["probeUrl"],
        site_name=present["siteName"],
        node_name=present["nodeName"],
        timezone=present["timezone"],
        is_test=is_test,
    )


def _extract_body(raw: str, content_type: str) -> dict[str, Any]:
    """Decode the request body into a mapping, trying each plausible encoding."""
    if not raw.strip():
        raise PayloadError("The request body was empty.")

    # 1. Straight JSON.
    parsed = _try_json(raw)
    if parsed is not None:
        return parsed

    # 2. URL-encoded JSON. This is what PRTG actually sends: content type says
    #    form-encoded, but the body is a percent-encoded JSON document.
    unquoted = urllib.parse.unquote_plus(raw)
    parsed = _try_json(unquoted)
    if parsed is not None:
        return parsed

    # 3. A real form body, if PRTG was configured with individual fields.
    if "form-urlencoded" in content_type or "=" in raw:
        pairs = urllib.parse.parse_qs(raw, keep_blank_values=True)
        if pairs:
            flat = {k: v[0] for k, v in pairs.items()}
            # A single field whose value is JSON, which some configurations produce.
            if len(flat) == 1:
                only = next(iter(flat.values()))
                nested = _try_json(only)
                if nested is not None:
                    return nested
            return flat

    raise PayloadError(
        "The request body was neither JSON nor form-encoded. Check that the PRTG payload is a "
        "single line with no line breaks: a break truncates the body, which produces this error "
        "even though the payload looks correct in the PRTG interface."
    )


def _try_json(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def header(event: dict[str, Any], name: str) -> str:
    """Read a header case-insensitively; API Gateway does not normalise casing.

    Public because ``handler`` needs it too, when recording the content type on a
    parked alarm so the replay decodes the body the same way this module did.
    """
    headers = event.get("headers") or {}
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value or "")
    return ""


# --- Priority ---------------------------------------------------------------


def resolve_priority(alarm: PrtgAlarm) -> str:
    """Map a PRTG alarm to a DevOps Agent task priority.

    PRTG's priority describes how important the *sensor* is, not how bad the
    current state is, so both are considered: a low-priority sensor that is
    genuinely Down still warrants attention, and a high-priority sensor in a
    warning state does not warrant the same urgency as one that is down.

    Rules, in order:

    1. A test notification is always MINIMAL - it carries no real data.
    2. An acknowledged down state is demoted one level; somebody is already on it.
    3. A live Down state is raised to at least HIGH.
    4. Otherwise the PRTG star rating maps directly.
    """
    if alarm.is_test:
        return "MINIMAL"

    base = _priority_from_prtg_field(alarm.priority)

    if alarm.is_acknowledged:
        return _shift(base, -1)

    if alarm.is_down:
        return base if _rank(base) >= _rank("HIGH") else "HIGH"

    return base


def _priority_from_prtg_field(value: str) -> str:
    """Interpret PRTG's ``%priority`` placeholder.

    PRTG renders it as a digit on most versions and as star characters on some, so
    both are handled. An unrecognised value falls back to MEDIUM rather than
    guessing high, so a formatting change in PRTG cannot silently flood the backlog
    with critical tasks.
    """
    text = (value or "").strip()
    if not text:
        return DEFAULT_PRIORITY

    digits = "".join(c for c in text if c.isdigit())
    if digits:
        try:
            return PRIORITY_BY_PRTG_STARS.get(int(digits[0]), DEFAULT_PRIORITY)
        except ValueError:
            return DEFAULT_PRIORITY

    stars = text.count("★") or text.count("*")
    if stars:
        return PRIORITY_BY_PRTG_STARS.get(min(stars, 5), DEFAULT_PRIORITY)

    return DEFAULT_PRIORITY


_ORDER: Final[tuple[str, ...]] = ("MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _rank(priority: str) -> int:
    try:
        return _ORDER.index(priority)
    except ValueError:
        return _ORDER.index(DEFAULT_PRIORITY)


def _shift(priority: str, delta: int) -> str:
    index = max(0, min(len(_ORDER) - 1, _rank(priority) + delta))
    return _ORDER[index]


# --- Idempotency ------------------------------------------------------------


def deduplication_token(alarm: PrtgAlarm, *, window_minutes: int, now: float | None = None) -> str | None:
    """Build a ``clientToken`` that suppresses duplicate investigations.

    ``CreateBacklogTask`` accepts a client token for idempotent creation, so
    repeated calls carrying the same token return the original task instead of
    creating another. Deriving the token from the alarm's identity plus a time
    bucket gives deduplication for free, server-side.

    This replaces the reference implementation's approach, which had no
    deduplication and pushed the problem onto PRTG by asking operators to add a
    second notification trigger with repeat suppression. That works only if every
    trigger is configured correctly on every group, forever.

    Args:
        alarm: The alarm.
        window_minutes: Suppression window. ``0`` disables deduplication.
        now: Override for the current time, for testing.

    Returns:
        A token, or ``None`` when deduplication is disabled.

    Note:
        Buckets are fixed rather than sliding, so two alarms falling either side of
        a boundary can both create a task. A sliding window would need external
        state; the trade is deliberate, and worst case is one duplicate rather than
        one every polling interval.
    """
    if window_minutes <= 0:
        return None

    timestamp = time.time() if now is None else now
    bucket = int(timestamp // (window_minutes * 60))

    # Identity is the sensor and the state it entered. A sensor moving Down ->
    # Up -> Down inside one window is deliberately treated as the same event:
    # flapping should produce one investigation, not many.
    identity = "|".join(
        (
            alarm.sensor_id or alarm.sensor,
            alarm.device_id or alarm.device,
            alarm.status.strip().lower(),
            str(bucket),
        )
    )
    # CreateBacklogTask limits clientToken length; a hex digest is well inside it
    # and contains only safe characters.
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:64]
