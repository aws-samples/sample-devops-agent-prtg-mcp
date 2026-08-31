"""Handler behaviour: the Gateway invocation contract, validation, and error envelopes."""

from __future__ import annotations

import json

import pytest

from prtg_mcp import handler
from prtg_mcp.prtg_client import PrtgAuthError, PrtgError
from tests.unit.conftest import FAKE_PASSHASH, FakeLambdaContext, FakePool, FakeResponse


@pytest.fixture(autouse=True)
def _reset_client_cache(monkeypatch: pytest.MonkeyPatch):
    """Clear the warm-start client between tests."""
    monkeypatch.setattr(handler, "_client", None)


@pytest.fixture
def wired_client(monkeypatch: pytest.MonkeyPatch, client):
    """Install a fake-backed PrtgClient as the handler's cached client."""
    monkeypatch.setattr(handler, "_client", client)
    return client


def _text(response: dict) -> str:
    return response["content"][0]["text"]


# --- Gateway invocation contract --------------------------------------------


class TestToolNameExtraction:
    def test_strips_the_gateway_target_prefix(self) -> None:
        assert handler.extract_tool_name(FakeLambdaContext("prtg-mcp___get_sensors")) == "get_sensors"

    def test_accepts_a_bare_tool_name(self) -> None:
        assert handler.extract_tool_name(FakeLambdaContext("get_sensors")) == "get_sensors"

    def test_target_names_containing_underscores_are_handled(self) -> None:
        """Splitting must be on the first triple underscore, not the last."""
        assert (
            handler.extract_tool_name(FakeLambdaContext("my_prtg_target___get_sensor_details"))
            == "get_sensor_details"
        )

    def test_returns_none_without_a_client_context(self) -> None:
        assert handler.extract_tool_name(FakeLambdaContext(with_client_context=False)) is None

    def test_returns_none_when_the_custom_map_is_empty(self) -> None:
        assert handler.extract_tool_name(FakeLambdaContext(None)) is None


class TestDispatch:
    def test_missing_tool_name_is_reported_with_the_available_tools(self) -> None:
        response = handler.handler({}, FakeLambdaContext(None))
        assert response["isError"] is True
        assert "get_sensors" in _text(response)

    def test_unknown_tool_is_reported_with_the_available_tools(self) -> None:
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___delete_everything"))
        assert response["isError"] is True
        assert "Unknown tool" in _text(response)
        assert "get_server_status" in _text(response)

    def test_an_empty_event_is_valid_for_a_no_argument_tool(self, wired_client) -> None:
        """An empty event is normal, not an error: the event *is* the arguments."""
        wired_client._pool = FakePool([FakeResponse(200, "OK", content_type="text/plain")])
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))
        assert response["isError"] is False

    def test_a_none_event_does_not_crash(self, wired_client) -> None:
        wired_client._pool = FakePool([FakeResponse(200, "OK", content_type="text/plain")])
        response = handler.handler(None, FakeLambdaContext("prtg-mcp___get_server_status"))
        assert response["isError"] is False

    def test_arguments_come_from_the_event_body(self, wired_client) -> None:
        wired_client._pool = FakePool([FakeResponse(200, {"sensors": []})])
        handler.handler({"status": "down", "count": 5}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert wired_client._pool.last_fields["count"] == 5
        # Repeated key, not filter_status[0]. PRTG answers the indexed form with an
        # empty result and no error, so "which sensors are down" returned nothing.
        codes = [v for k, v in wired_client._pool.last_pairs if k == "filter_status"]
        assert codes == [5]  # PRTG code for "down"

    def test_explicit_nulls_are_treated_as_omitted(self, wired_client) -> None:
        """The agent often sends every declared parameter, with null for unused ones."""
        wired_client._pool = FakePool([FakeResponse(200, {"sensors": []})])
        response = handler.handler(
            {"status": None, "tags": None, "count": 10}, FakeLambdaContext("prtg-mcp___get_sensors")
        )
        assert response["isError"] is False


# --- Response envelope ------------------------------------------------------


class TestResponseEnvelope:
    def test_success_returns_mcp_content_with_json_text(self, wired_client) -> None:
        payload = {"sensors": [{"objid": 2001, "name": "CPU Load", "status": "Down"}]}
        wired_client._pool = FakePool([FakeResponse(200, payload)])
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensors"))

        assert response["isError"] is False
        assert response["content"][0]["type"] == "text"
        assert json.loads(_text(response)) == payload

    def test_errors_carry_a_correlation_id_for_log_lookup(self, wired_client) -> None:
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___nope"))
        assert "correlationId" in _text(response)

    def test_non_serialisable_values_do_not_break_the_response(self, wired_client) -> None:
        wired_client._pool = FakePool([FakeResponse(200, {"ok": True})])
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is False


# --- Argument validation ----------------------------------------------------


class TestValidation:
    def test_unknown_parameter_is_rejected_and_the_valid_ones_are_listed(self) -> None:
        response = handler.handler({"sensor_name": "web01"}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is True
        assert "sensor_name" in _text(response)
        assert "text_filter" in _text(response)  # the parameter the agent meant

    def test_missing_required_parameter_is_named(self) -> None:
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensor_details"))
        assert response["isError"] is True
        assert "id" in _text(response)

    def test_invalid_enum_value_lists_the_accepted_values(self) -> None:
        response = handler.handler({"status": "broken"}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is True
        assert "down" in _text(response)

    def test_count_above_the_maximum_is_rejected_with_guidance(self) -> None:
        response = handler.handler({"count": 100_000}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is True
        assert "narrow the query" in _text(response)

    def test_numeric_string_is_coerced(self, wired_client) -> None:
        """Language models routinely emit "2001" where an integer is expected."""
        wired_client._pool = FakePool([FakeResponse(200, {})])
        response = handler.handler({"id": "2001"}, FakeLambdaContext("prtg-mcp___get_sensor_details"))
        assert response["isError"] is False
        assert wired_client._pool.last_fields["id"] == 2001

    def test_non_numeric_id_is_rejected(self) -> None:
        response = handler.handler(
            {"id": "the web server"}, FakeLambdaContext("prtg-mcp___get_sensor_details")
        )
        assert response["isError"] is True
        assert "integer" in _text(response)

    def test_boolean_is_not_accepted_as_an_integer(self) -> None:
        response = handler.handler({"id": True}, FakeLambdaContext("prtg-mcp___get_sensor_details"))
        assert response["isError"] is True

    def test_id_below_the_minimum_is_rejected(self) -> None:
        response = handler.handler({"id": 0}, FakeLambdaContext("prtg-mcp___get_sensor_details"))
        assert response["isError"] is True
        assert "at least 1" in _text(response)

    def test_malformed_date_is_rejected(self) -> None:
        response = handler.handler(
            {"id": 1, "sdate": "last Tuesday", "edate": "2026-01-01"},
            FakeLambdaContext("prtg-mcp___get_sensor_history"),
        )
        assert response["isError"] is True
        assert "sdate" in _text(response)

    def test_well_formed_date_is_accepted(self, wired_client) -> None:
        wired_client._pool = FakePool([FakeResponse(200, {})])
        response = handler.handler(
            {"id": 1, "sdate": "2026-08-01-00-00-00", "edate": "2026-08-02-00-00-00"},
            FakeLambdaContext("prtg-mcp___get_sensor_history"),
        )
        assert response["isError"] is False

    def test_overlong_text_filter_is_rejected(self) -> None:
        response = handler.handler({"text_filter": "x" * 500}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is True


# --- Error handling ---------------------------------------------------------


class TestErrorHandling:
    def test_prtg_auth_failure_is_surfaced_with_guidance(
        self, monkeypatch: pytest.MonkeyPatch, wired_client
    ) -> None:
        def boom(*_args, **_kwargs):
            raise PrtgAuthError("PRTG rejected the credential (HTTP 401).", status=401)

        monkeypatch.setitem(handler.TOOL_IMPLEMENTATIONS, "get_sensors", boom)
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is True
        assert "401" in _text(response)

    def test_prtg_error_message_is_passed_through(
        self, monkeypatch: pytest.MonkeyPatch, wired_client
    ) -> None:
        def boom(*_args, **_kwargs):
            raise PrtgError("Could not reach PRTG; check outbound 443.")

        monkeypatch.setitem(handler.TOOL_IMPLEMENTATIONS, "get_sensors", boom)
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert "outbound 443" in _text(response)

    def test_unexpected_exception_is_summarised_not_echoed(
        self, monkeypatch: pytest.MonkeyPatch, wired_client
    ) -> None:
        """An unexpected exception's text may contain the credential.

        Only the exception *type* is returned; the traceback goes to CloudWatch.
        """

        def boom(*_args, **_kwargs):
            raise RuntimeError(f"internal failure at ?passhash={FAKE_PASSHASH}")

        monkeypatch.setitem(handler.TOOL_IMPLEMENTATIONS, "get_sensors", boom)
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensors"))

        assert response["isError"] is True
        assert FAKE_PASSHASH not in _text(response)
        assert "RuntimeError" in _text(response)
        assert "CloudWatch" in _text(response)

    def test_handler_never_raises(self, monkeypatch: pytest.MonkeyPatch, wired_client) -> None:
        """Gateway turns an exception into an opaque target failure, which the
        agent cannot act on. Everything must come back as an MCP envelope."""

        def boom(*_args, **_kwargs):
            raise BaseExceptionGroup("nested", [ValueError("a"), ValueError("b")])

        monkeypatch.setitem(handler.TOOL_IMPLEMENTATIONS, "get_sensors", boom)
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_sensors"))
        assert response["isError"] is True


# --- get_server_status fallback ---------------------------------------------


class TestServerStatusFallback:
    def test_falls_back_to_a_bounded_sensor_summary(self, wired_client) -> None:
        """Older PRTG versions do not expose /api/getstatus.htm."""
        wired_client._pool = FakePool(
            [
                FakeResponse(500, "not available", content_type="text/plain"),
                FakeResponse(
                    200,
                    {
                        "sensors": [
                            {"objid": 1, "status_raw": 3},
                            {"objid": 2, "status_raw": 5},
                            {"objid": 3, "status_raw": 5},
                            {"objid": 4, "status_raw": 8},
                        ]
                    },
                ),
            ]
        )
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))
        assert response["isError"] is False

        summary = json.loads(_text(response))["sensor_summary"]
        assert summary["total"] == 4
        assert summary["up"] == 1
        assert summary["down"] == 2
        assert summary["paused"] == 1

    def test_fallback_result_declares_that_it_is_approximate(self, wired_client) -> None:
        wired_client._pool = FakePool(
            [
                FakeResponse(500, "not available", content_type="text/plain"),
                FakeResponse(200, {"sensors": []}),
            ]
        )
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))
        assert "approximate" in json.loads(_text(response))["note"]

    def test_fallback_stays_within_the_published_page_limit(self, wired_client) -> None:
        from prtg_mcp.tools import MAX_COUNT

        wired_client._pool = FakePool(
            [
                FakeResponse(500, "not available", content_type="text/plain"),
                FakeResponse(200, {"sensors": []}),
            ]
        )
        handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))
        assert wired_client._pool.last_fields["count"] == MAX_COUNT

    def test_auth_failure_is_not_masked_by_the_fallback(self, wired_client) -> None:
        """A bad credential must not be reported as "old PRTG version"."""
        wired_client._pool = FakePool([FakeResponse(401, "denied", content_type="text/html")])
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))
        assert response["isError"] is True
        assert "credential" in _text(response)

    def test_an_unreachable_prtg_is_reported_rather_than_retried(self, wired_client) -> None:
        """The fallback must not run when PRTG never answered.

        The fallback exists for a PRTG version lacking /api/getstatus.htm, which arrives
        as an HTTP status. A connection failure on the primary request is guaranteed to
        repeat on the fallback, and attempting it anyway does more than waste time: each
        path spends connect_timeout x (1 + max_retries), 15 s at the defaults, so the two
        together reach the 30 s default Lambda timeout exactly. Observed against a
        genuinely unreachable PRTG -- every other tool returned its error in 20 s while
        this one was killed mid-fallback, so the agent got an unhandled invocation error
        instead of the diagnosis the function had already computed.
        """
        import urllib3

        wired_client._pool = FakePool(
            raises=urllib3.exceptions.MaxRetryError(pool=None, url="/api/getstatus.htm", reason=None)
        )
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))

        assert response["isError"] is True
        # The actionable message survives instead of being lost to a timeout.
        assert "Could not reach PRTG" in _text(response)
        # Exactly one request: no second path was attempted.
        assert len(wired_client._pool.requests) == 1

    def test_a_certificate_failure_is_reported_rather_than_retried(self, wired_client) -> None:
        """Same reasoning, and the message must still name TLS rather than routing."""
        import urllib3

        wired_client._pool = FakePool(raises=urllib3.exceptions.SSLError("certificate verify failed"))
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))

        assert response["isError"] is True
        assert len(wired_client._pool.requests) == 1
        assert "verify_tls" in _text(response) or "certificate" in _text(response).lower()

    def test_a_missing_endpoint_still_falls_back(self, wired_client) -> None:
        """The behaviour the fallback exists for must be unaffected by the above.

        Pinned separately because the guard is a one-line condition, and getting it
        backwards would silently disable the fallback on every PRTG version that needs
        it -- a regression no other test here would catch.
        """
        wired_client._pool = FakePool(
            [
                FakeResponse(404, "not found", content_type="text/html"),
                FakeResponse(200, {"sensors": [{"objid": 1, "status_raw": 3}]}),
            ]
        )
        response = handler.handler({}, FakeLambdaContext("prtg-mcp___get_server_status"))

        assert response["isError"] is False
        assert json.loads(_text(response))["sensor_summary"]["total"] == 1
        assert len(wired_client._pool.requests) == 2


# --- Read-only guarantee ----------------------------------------------------


class TestReadOnlyGuarantee:
    def test_every_tool_issues_only_get_requests(self, wired_client) -> None:
        """The security posture of the whole integration rests on this."""
        wired_client._pool = FakePool([FakeResponse(200, {}) for _ in range(20)])

        calls = {
            "get_sensors": {},
            "get_sensor_details": {"id": 1},
            "get_channels": {"id": 1},
            "get_devices": {},
            "get_groups": {},
            "get_sensor_history": {"id": 1, "sdate": "2026-01-01", "edate": "2026-01-02"},
            "get_messages": {},
            "search": {"query": "web"},
        }
        for tool, args in calls.items():
            handler.handler(args, FakeLambdaContext(f"prtg-mcp___{tool}"))

        assert wired_client._pool.requests, "no requests were recorded"
        methods = {r["method"] for r in wired_client._pool.requests}
        assert methods == {"GET"}, f"non-GET request issued: {methods}"

    def test_no_tool_parameter_can_change_the_request_destination(self, wired_client) -> None:
        """The PRTG endpoint is fixed at deploy time, from the secret."""
        wired_client._pool = FakePool([FakeResponse(200, {})])
        handler.handler(
            {"text_filter": "https://attacker.example/exfil"},
            FakeLambdaContext("prtg-mcp___get_sensors"),
        )
        assert wired_client._pool.requests[0]["url"].startswith("https://prtg.example.internal")
