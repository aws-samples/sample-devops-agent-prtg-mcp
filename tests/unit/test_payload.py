"""PRTG payload parsing, priority mapping, and deduplication tokens.

These cover the behaviours that make the alarm pipeline more than a passthrough,
and the PRTG quirks that are easy to get wrong.
"""

from __future__ import annotations

import json
import urllib.parse

import pytest

from alarm_pipeline.payload import (
    _CORE_FIELDS,
    _FIELD_PLACEHOLDERS,
    PayloadError,
    PrtgAlarm,
    deduplication_token,
    minimal_payload_template,
    parse_alarm,
    payload_template,
    resolve_priority,
)

REAL_PAYLOAD = {
    "sensor": "CPU Load",
    "device": "prod-web-01",
    "status": "Down",
    "message": "Connection failed",
    "host": "10.0.2.45",
    "datetime": "2026-08-21 14:05:00",
    "priority": "3",
    "group": "Production",
    "probe": "Local Probe",
    "sensorId": "2001",
    "deviceId": "1001",
}


def _event(body: str, content_type: str = "application/json", **kwargs) -> dict:
    return {"body": body, "headers": {"Content-Type": content_type}, **kwargs}


def _literal_placeholders(text: str) -> list[str]:
    """Declared PRTG placeholders still present in ``text`` as literal text.

    Checked by name rather than by searching for a bare '%', because a legitimate
    value contains one: PRTG renders a percentage as "97 %".
    """
    return sorted(ph for ph in _FIELD_PLACEHOLDERS.values() if ph in text)


# --- Parsing ----------------------------------------------------------------


class TestParsing:
    def test_plain_json_body(self) -> None:
        alarm = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        assert alarm.sensor == "CPU Load"
        assert alarm.device == "prod-web-01"
        assert alarm.sensor_id == "2001"
        assert alarm.is_test is False

    def test_url_encoded_json_body(self) -> None:
        """What PRTG actually sends: form content type, percent-encoded JSON body."""
        encoded = urllib.parse.quote(json.dumps(REAL_PAYLOAD))
        alarm = parse_alarm(_event(encoded, "application/x-www-form-urlencoded"))
        assert alarm.sensor == "CPU Load"
        assert alarm.status == "Down"

    def test_genuine_form_encoded_body(self) -> None:
        body = urllib.parse.urlencode(REAL_PAYLOAD)
        alarm = parse_alarm(_event(body, "application/x-www-form-urlencoded"))
        assert alarm.device == "prod-web-01"

    def test_single_form_field_containing_json(self) -> None:
        body = urllib.parse.urlencode({"payload": json.dumps(REAL_PAYLOAD)})
        alarm = parse_alarm(_event(body, "application/x-www-form-urlencoded"))
        assert alarm.sensor == "CPU Load"

    def test_base64_encoded_body(self) -> None:
        import base64

        encoded = base64.b64encode(json.dumps(REAL_PAYLOAD).encode()).decode()
        alarm = parse_alarm(_event(encoded, isBase64Encoded=True))
        assert alarm.sensor == "CPU Load"

    def test_headers_are_matched_case_insensitively(self) -> None:
        """API Gateway does not normalise header casing."""
        event = {
            "body": urllib.parse.quote(json.dumps(REAL_PAYLOAD)),
            "headers": {"content-TYPE": "application/x-www-form-urlencoded"},
        }
        assert parse_alarm(event).sensor == "CPU Load"

    def test_missing_optional_fields_get_readable_defaults(self) -> None:
        alarm = parse_alarm(_event(json.dumps({"sensor": "Ping", "device": "db-01"})))
        assert alarm.status == "unknown"
        assert alarm.message == "(no message supplied)"
        assert alarm.group == ""

    def test_empty_body_is_rejected(self) -> None:
        with pytest.raises(PayloadError, match="empty"):
            parse_alarm(_event(""))

    def test_body_with_no_prtg_fields_is_rejected_with_the_expected_template(self) -> None:
        with pytest.raises(PayloadError) as exc:
            parse_alarm(_event(json.dumps({"unrelated": "value"})))
        # The message must show the payload PRTG should be configured with,
        # because that is the actual fix.
        assert "%sensor" in str(exc.value)

    def test_truncated_body_error_mentions_the_line_break_cause(self) -> None:
        """A line break in the PRTG payload truncates the body. It is the single
        most common configuration mistake and looks correct in the PRTG UI."""
        with pytest.raises(PayloadError) as exc:
            parse_alarm(_event('{"sensor":"CPU', "text/plain"))
        assert "single line" in str(exc.value)


class TestTestNotificationDetection:
    def test_unsubstituted_placeholders_mark_a_test_notification(self) -> None:
        """PRTG does not substitute placeholders when the test button is used."""
        body = json.dumps({k: f"%{k.lower()}" for k in REAL_PAYLOAD})
        alarm = parse_alarm(_event(body))
        assert alarm.is_test is True

    def test_a_real_alarm_is_not_flagged_as_a_test(self) -> None:
        assert parse_alarm(_event(json.dumps(REAL_PAYLOAD))).is_test is False

    def test_test_notification_description_explains_itself(self) -> None:
        body = json.dumps({k: f"%{k.lower()}" for k in REAL_PAYLOAD})
        description = parse_alarm(_event(body)).description()
        assert "test notification" in description
        assert "No investigation is warranted" in description

    def test_detection_uses_only_the_core_placeholders(self) -> None:
        """The behaviour that makes a wide payload safe to send.

        PRTG leaves an *unrecognised* placeholder as literal text, exactly as it
        does for a test notification. If detection considered every field, one
        placeholder the local PRTG version does not support would turn every real
        alarm into a "test": acknowledged with 200, no investigation, and nothing
        logged as an error.
        """
        payload = {**REAL_PAYLOAD, "tags": "%tags", "lastStatus": "%laststatus"}
        alarm = parse_alarm(_event(json.dumps(payload)))
        assert alarm.is_test is False

    @pytest.mark.parametrize("field", _CORE_FIELDS)
    def test_a_literal_placeholder_in_any_core_field_marks_a_test(self, field: str) -> None:
        payload = {**REAL_PAYLOAD, field: f"%{field}"}
        assert parse_alarm(_event(json.dumps(payload))).is_test is True

    def test_an_unresolved_optional_field_is_treated_as_absent(self) -> None:
        """Handing the agent the literal string '%lastvalue' as though it were a
        measurement is worse than handing it nothing."""
        payload = {**REAL_PAYLOAD, "lastValue": "%lastvalue", "tags": "%tags"}
        alarm = parse_alarm(_event(json.dumps(payload)))
        assert alarm.last_value == ""
        assert alarm.tags == ""

    def test_a_real_alarm_description_never_shows_a_literal_placeholder(self) -> None:
        payload = {**REAL_PAYLOAD, "commentsDevice": "%commentsdevice", "since": "%since"}
        description = parse_alarm(_event(json.dumps(payload))).description()
        assert _literal_placeholders(description) == []


# --- The payload template ---------------------------------------------------


class TestPayloadTemplate:
    """The template is the single source of truth for the PRTG notification.

    The stack output, the docs and the rejection message all derive from it, because
    a 39-field string maintained by hand in four places drifts on the first change.
    """

    def test_template_is_valid_single_line_json(self) -> None:
        template = payload_template()
        # A line break in the PRTG payload field truncates the body, which is the
        # most common configuration mistake in the whole integration.
        assert "\n" not in template
        assert "\r" not in template
        assert isinstance(json.loads(template), dict)

    def test_template_declares_exactly_the_fields_the_parser_reads(self) -> None:
        assert set(json.loads(payload_template())) == set(_FIELD_PLACEHOLDERS)

    def test_every_template_value_is_a_prtg_placeholder(self) -> None:
        for key, value in json.loads(payload_template()).items():
            assert value == _FIELD_PLACEHOLDERS[key]
            assert value.startswith("%")

    def test_template_round_trips_through_the_parser_as_a_test_notification(self) -> None:
        """Pasting the template into PRTG and pressing test must be recognised."""
        assert parse_alarm(_event(payload_template())).is_test is True

    @pytest.mark.parametrize(
        "excluded",
        [
            # Resolves to sensor settings including monitoring credentials.
            "%settings",
            # Multi-line, so it truncates the body and rejects the alarm.
            "%history",
            # Multi-line, and documented as email-only.
            "%syslogmessages",
            "%trapmessages",
            # Resolves only in summarised notifications.
            "%summarycount",
        ],
    )
    def test_unsafe_placeholders_are_not_in_the_template(self, excluded: str) -> None:
        assert excluded not in payload_template()

    def test_credential_bearing_placeholder_is_absent(self) -> None:
        """%settings would copy PRTG's monitoring credentials into the task
        description, this function's log group, and the dead-letter queue."""
        assert "settings" not in _FIELD_PLACEHOLDERS
        assert "%settings" not in payload_template()

    def test_minimal_template_is_a_subset_of_the_full_one(self) -> None:
        minimal = json.loads(minimal_payload_template())
        full = json.loads(payload_template())
        assert set(minimal) <= set(full)
        assert all(minimal[k] == full[k] for k in minimal)

    def test_the_setup_guide_quotes_the_template_verbatim(self) -> None:
        """The guide is what an operator actually copies from when they are not
        reading stack outputs. A stale copy there sends a payload the parser does
        not fully read, and nothing would report it."""
        import pathlib

        docs = pathlib.Path(__file__).resolve().parents[2] / "docs" / "prtg-setup.md"
        assert payload_template() in docs.read_text()

    def test_minimal_template_carries_the_fields_that_change_behaviour(self) -> None:
        minimal = json.loads(minimal_payload_template())
        # host identifies the AWS resource, priority drives triage, the IDs are the
        # MCP handoff. Without these the pipeline degrades in a visible way.
        for key in ("host", "priority", "sensorId", "deviceId"):
            assert key in minimal


# --- Host and AWS correlation -----------------------------------------------


class TestAwsCorrelation:
    """%host is the field that makes an alarm resolvable to an AWS resource.

    %device is a PRTG display label and %deviceid is internal to PRTG; neither
    means anything outside it.
    """

    def test_host_is_parsed(self) -> None:
        assert parse_alarm(_event(json.dumps(REAL_PAYLOAD))).host == "10.0.2.45"

    def test_description_surfaces_the_address_and_how_to_use_it(self) -> None:
        description = parse_alarm(_event(json.dumps(REAL_PAYLOAD))).description()
        assert "10.0.2.45" in description
        assert "Identifying the AWS resource" in description
        assert "private IP" in description

    def test_description_warns_that_an_address_is_not_an_identity(self) -> None:
        """A private IP is unique only within a VPC and is reassigned over time."""
        description = parse_alarm(_event(json.dumps(REAL_PAYLOAD))).description()
        assert "unique only within a VPC" in description

    def test_the_aws_block_is_omitted_when_no_host_was_sent(self) -> None:
        payload = {k: v for k, v in REAL_PAYLOAD.items() if k != "host"}
        description = parse_alarm(_event(json.dumps(payload))).description()
        assert "Identifying the AWS resource" not in description

    def test_the_aws_block_is_omitted_for_a_test_notification(self) -> None:
        body = json.dumps({k: f"%{k.lower()}" for k in REAL_PAYLOAD})
        assert "Identifying the AWS resource" not in parse_alarm(_event(body)).description()

    def test_operator_tags_and_comments_reach_the_agent(self) -> None:
        """Where an exact instance ID is recorded, rather than inferred."""
        payload = {
            **REAL_PAYLOAD,
            "parentTags": "env-prod aws-instance-i-0abc123def4567890",
            "commentsDevice": "EC2 i-0abc123def4567890, account 123456789012",
        }
        description = parse_alarm(_event(json.dumps(payload))).description()
        assert "i-0abc123def4567890" in description
        assert "123456789012" in description


# --- Title and description --------------------------------------------------


class TestPresentation:
    def test_title_leads_with_the_device(self) -> None:
        """Sensor names repeat across devices; the host is what identifies an alert."""
        title = parse_alarm(_event(json.dumps(REAL_PAYLOAD))).title()
        assert title.startswith("PRTG: prod-web-01")
        assert "CPU Load" in title
        assert "Down" in title

    def test_title_is_capped_to_the_api_limit(self) -> None:
        payload = {**REAL_PAYLOAD, "device": "d" * 600}
        assert len(parse_alarm(_event(json.dumps(payload))).title()) <= 400

    def test_description_is_capped_to_the_api_limit(self) -> None:
        payload = {**REAL_PAYLOAD, "message": "m" * 20_000}
        assert len(parse_alarm(_event(json.dumps(payload))).description()) <= 10_000

    def test_description_hands_prtg_ids_to_the_mcp_tools(self) -> None:
        """The explicit handoff between the two halves of the integration: without
        the IDs the agent must search by name before it can look anything up."""
        description = parse_alarm(_event(json.dumps(REAL_PAYLOAD))).description()
        assert "sensor id 2001" in description
        assert "get_sensor_history" in description
        assert "device id 1001" in description

    def test_unbounded_free_text_cannot_displace_the_identity_block(self) -> None:
        """Comments are operator free text with no length bound, and the description
        is truncated to the API limit. Identity must therefore sit above them."""
        payload = {
            **REAL_PAYLOAD,
            "commentsDevice": "c" * 40_000,
            "commentsGroup": "g" * 40_000,
            "tags": "t" * 40_000,
        }
        description = parse_alarm(_event(json.dumps(payload))).description()
        assert len(description) <= 10_000
        assert "10.0.2.45" in description
        assert "sensor id 2001" in description
        assert "device id 1001" in description

    def test_a_full_payload_description_stays_within_the_api_limit(self) -> None:
        payload = dict.fromkeys(_FIELD_PLACEHOLDERS, "v" * 5_000)
        payload["status"] = "Down"
        assert len(parse_alarm(_event(json.dumps(payload))).description()) <= 10_000

    def test_newlines_in_operator_comments_are_flattened(self) -> None:
        """PRTG substitutes comment values after the body has been parsed, so a
        comment typed into a multi-line box can contain newlines even though the
        payload itself cannot."""
        payload = {**REAL_PAYLOAD, "commentsDevice": "line one\nline two\r\nline three"}
        description = parse_alarm(_event(json.dumps(payload))).description()
        assert "line one line two line three" in description


# --- Priority ---------------------------------------------------------------


class TestPriority:
    @pytest.mark.parametrize(
        ("stars", "expected"),
        [("5", "CRITICAL"), ("4", "HIGH"), ("3", "MEDIUM"), ("2", "LOW"), ("1", "MINIMAL")],
    )
    def test_prtg_star_rating_maps_directly_for_non_down_states(self, stars: str, expected: str) -> None:
        alarm = PrtgAlarm(sensor="s", device="d", status="Warning", message="m", priority=stars)
        assert resolve_priority(alarm) == expected

    def test_star_characters_are_understood(self) -> None:
        """Some PRTG versions render %priority as stars rather than a digit."""
        alarm = PrtgAlarm(sensor="s", device="d", status="Warning", message="m", priority="★★★★★")
        assert resolve_priority(alarm) == "CRITICAL"

    def test_a_down_sensor_is_escalated_to_at_least_high(self) -> None:
        """PRTG priority rates the sensor's importance, not the current severity."""
        alarm = PrtgAlarm(sensor="s", device="d", status="Down", message="m", priority="1")
        assert resolve_priority(alarm) == "HIGH"

    def test_a_down_critical_sensor_stays_critical(self) -> None:
        alarm = PrtgAlarm(sensor="s", device="d", status="Down", message="m", priority="5")
        assert resolve_priority(alarm) == "CRITICAL"

    def test_an_acknowledged_down_state_is_demoted(self) -> None:
        """Somebody is already working on it."""
        alarm = PrtgAlarm(sensor="s", device="d", status="Down (Acknowledged)", message="m", priority="5")
        assert resolve_priority(alarm) == "HIGH"

    def test_a_test_notification_is_always_minimal(self) -> None:
        alarm = PrtgAlarm(sensor="s", device="d", status="Down", message="m", priority="5", is_test=True)
        assert resolve_priority(alarm) == "MINIMAL"

    def test_unrecognised_priority_falls_back_to_medium_not_high(self) -> None:
        """A formatting change in PRTG must not silently flood the backlog with
        critical tasks."""
        alarm = PrtgAlarm(sensor="s", device="d", status="Warning", message="m", priority="???")
        assert resolve_priority(alarm) == "MEDIUM"

    def test_absent_priority_falls_back_to_medium(self) -> None:
        alarm = PrtgAlarm(sensor="s", device="d", status="Warning", message="m")
        assert resolve_priority(alarm) == "MEDIUM"

    def test_priority_is_not_hardcoded(self) -> None:
        """The reference implementation set every investigation to HIGH, which makes
        the field useless for triage."""
        results = {
            resolve_priority(
                PrtgAlarm(sensor="s", device="d", status="Warning", message="m", priority=str(n))
            )
            for n in range(1, 6)
        }
        assert len(results) == 5


# --- Deduplication ----------------------------------------------------------


class TestDeduplication:
    def test_same_alarm_in_the_same_window_produces_the_same_token(self) -> None:
        alarm = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        a = deduplication_token(alarm, window_minutes=30, now=1_000_000)
        b = deduplication_token(alarm, window_minutes=30, now=1_000_060)
        assert a == b

    def test_different_windows_produce_different_tokens(self) -> None:
        alarm = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        a = deduplication_token(alarm, window_minutes=30, now=1_000_000)
        b = deduplication_token(alarm, window_minutes=30, now=1_000_000 + 1_801)
        assert a != b

    def test_different_sensors_produce_different_tokens(self) -> None:
        one = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        two = parse_alarm(_event(json.dumps({**REAL_PAYLOAD, "sensorId": "9999"})))
        assert deduplication_token(one, window_minutes=30, now=1) != deduplication_token(
            two, window_minutes=30, now=1
        )

    def test_different_states_produce_different_tokens(self) -> None:
        """Down and Up are distinct events and both deserve their own task."""
        down = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        up = parse_alarm(_event(json.dumps({**REAL_PAYLOAD, "status": "Up"})))
        assert deduplication_token(down, window_minutes=30, now=1) != deduplication_token(
            up, window_minutes=30, now=1
        )

    def test_flapping_within_a_window_is_treated_as_one_event(self) -> None:
        """A sensor going Down, Up, Down should produce one investigation, not three."""
        first = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        later = parse_alarm(_event(json.dumps({**REAL_PAYLOAD, "datetime": "2026-08-21 14:25:00"})))
        assert deduplication_token(first, window_minutes=30, now=1_000_000) == deduplication_token(
            later, window_minutes=30, now=1_000_500
        )

    def test_zero_window_disables_deduplication(self) -> None:
        alarm = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        assert deduplication_token(alarm, window_minutes=0) is None

    def test_token_is_safe_for_an_api_client_token(self) -> None:
        alarm = parse_alarm(_event(json.dumps(REAL_PAYLOAD)))
        token = deduplication_token(alarm, window_minutes=30, now=1)
        assert token is not None
        assert len(token) <= 64
        assert token.isalnum()

    def test_falls_back_to_names_when_ids_are_absent(self) -> None:
        """Not every PRTG notification template includes the ID placeholders."""
        payload = {k: v for k, v in REAL_PAYLOAD.items() if k not in ("sensorId", "deviceId")}
        alarm = parse_alarm(_event(json.dumps(payload)))
        assert deduplication_token(alarm, window_minutes=30, now=1) is not None


# --- Shipped fixtures -------------------------------------------------------


class TestShippedFixtures:
    """The files in samples/prtg-payloads/ must behave as their README claims.

    Fixtures nobody exercises drift from reality, and these are the first thing
    someone reaches for when testing a deployment.
    """

    import pathlib

    SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples" / "prtg-payloads"

    def _json_event(self, name: str) -> dict:
        return _event((self.SAMPLES / name).read_text())

    def test_sensor_down_maps_to_high_priority(self) -> None:
        alarm = parse_alarm(self._json_event("sensor-down.json"))
        assert alarm.is_down is True
        assert alarm.is_test is False
        assert resolve_priority(alarm) == "HIGH"

    def test_url_encoded_fixture_parses_to_the_same_alarm(self) -> None:
        """The form PRTG actually transmits."""
        raw = (self.SAMPLES / "sensor-down-urlencoded.txt").read_text().strip()
        encoded = parse_alarm(_event(raw, "application/x-www-form-urlencoded"))
        plain = parse_alarm(self._json_event("sensor-down.json"))
        assert encoded == plain

    def test_warning_fixture_maps_to_a_lower_priority_than_down(self) -> None:
        warning = resolve_priority(parse_alarm(self._json_event("sensor-warning.json")))
        down = resolve_priority(parse_alarm(self._json_event("sensor-down.json")))
        assert warning == "LOW"
        assert down == "HIGH"

    def test_acknowledged_fixture_is_demoted(self) -> None:
        alarm = parse_alarm(self._json_event("sensor-down-acknowledged.json"))
        assert alarm.is_acknowledged is True
        # CRITICAL sensor, but already being handled.
        assert resolve_priority(alarm) == "HIGH"

    def test_test_notification_fixture_is_detected(self) -> None:
        alarm = parse_alarm(self._json_event("test-notification.json"))
        assert alarm.is_test is True
        assert resolve_priority(alarm) == "MINIMAL"

    def test_test_notification_fixture_matches_the_template(self) -> None:
        """Generated from payload_template(), not maintained by hand. This is what
        stops it drifting when a field is added."""
        fixture = json.loads((self.SAMPLES / "test-notification.json").read_text())
        assert fixture == json.loads(payload_template())

    def test_down_fixture_carries_the_full_field_set(self) -> None:
        """The fixture someone reaches for first must exercise every field, or the
        wide payload is untested where it matters."""
        fixture = json.loads((self.SAMPLES / "sensor-down.json").read_text())
        assert set(fixture) == set(_FIELD_PLACEHOLDERS)

    def test_down_fixture_resolves_to_an_aws_correlatable_alarm(self) -> None:
        alarm = parse_alarm(self._json_event("sensor-down.json"))
        assert alarm.host == "10.0.2.45"
        assert "i-0abc123def4567890" in alarm.comments_device
        assert "Identifying the AWS resource" in alarm.description()

    def test_unresolved_placeholder_fixture_is_a_real_alarm_not_a_test(self) -> None:
        """An older PRTG resolves the core placeholders but not the newer optional
        ones. That must not suppress the investigation."""
        alarm = parse_alarm(self._json_event("unresolved-placeholders.json"))
        assert alarm.is_test is False
        assert alarm.is_down is True
        assert resolve_priority(alarm) == "HIGH"
        # The supported fields survive; the unsupported ones are dropped.
        assert alarm.host == "10.0.2.45"
        assert alarm.last_value == "97 %"
        assert alarm.tags == ""
        assert alarm.last_status == ""
        assert _literal_placeholders(alarm.description()) == []
        # The legitimate percent sign in a PRTG value survives.
        assert "97 %" in alarm.description()

    def test_truncated_fixture_is_rejected_with_the_line_break_explanation(self) -> None:
        raw = (self.SAMPLES / "truncated.txt").read_text()
        with pytest.raises(PayloadError, match="single line"):
            parse_alarm(_event(raw, "text/plain"))

    def test_every_fixture_is_documented_in_the_readme(self) -> None:
        readme = (self.SAMPLES / "README.md").read_text()
        for path in self.SAMPLES.iterdir():
            if path.name == "README.md":
                continue
            assert path.name in readme, f"{path.name} is not documented"
