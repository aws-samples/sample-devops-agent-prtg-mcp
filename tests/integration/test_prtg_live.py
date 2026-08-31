"""Live integration tests against a real PRTG server. Opt-in.

Skipped unless the environment names a PRTG instance, so ``make test`` and CI stay
free of external dependencies. These exist because a mocked PRTG cannot tell you
whether the API shape assumed by ``prtg_client`` matches the PRTG version in front of
you - column names, the presence of ``/api/getstatus.htm``, and the exact status
codes all vary a little across versions and licences.

Run with credentials in the environment:

    export PRTG_TEST_URL=https://prtg.example.internal
    export PRTG_TEST_USERNAME=prtg-readonly-svc
    export PRTG_TEST_PASSHASH=1234567890
    make test-integration

Or, once deployed, point at the Secrets Manager secret instead:

    export PRTG_TEST_SECRET_ARN=arn:aws:secretsmanager:...:secret:prtg-mcp/credentials-a1b2c3
    make test-integration

Use a READ-ONLY PRTG account. Everything here is a GET, but the credential is on
your machine and in your shell history while these run.

By design these assert on *shape*, not on content: a PRTG instance's sensors are
whatever they are, and a test that expects a particular device name would fail on
every installation but one.
"""

from __future__ import annotations

import json
import os

import pytest

from prtg_mcp import handler as mcp_handler
from prtg_mcp import tools
from prtg_mcp.prtg_client import STATUS_CODES, PrtgClient

pytestmark = pytest.mark.integration

#: Either credential form is enough, matching what the client accepts. An earlier
#: version required a username and passhash, so pointing these tests at an API key
#: silently skipped all of them rather than exercising that path.
_HAS_API_KEY = bool(os.environ.get("PRTG_TEST_URL") and os.environ.get("PRTG_TEST_API_KEY"))
_HAS_PASSHASH = all(
    os.environ.get(name) for name in ("PRTG_TEST_URL", "PRTG_TEST_USERNAME", "PRTG_TEST_PASSHASH")
)
_HAS_DIRECT = _HAS_API_KEY or _HAS_PASSHASH
_HAS_SECRET = bool(os.environ.get("PRTG_TEST_SECRET_ARN"))

requires_prtg = pytest.mark.skipif(
    not (_HAS_DIRECT or _HAS_SECRET),
    reason=(
        "Set PRTG_TEST_URL with either PRTG_TEST_API_KEY, or PRTG_TEST_USERNAME and "
        "PRTG_TEST_PASSHASH. Alternatively set PRTG_TEST_SECRET_ARN. Required to run the "
        "live PRTG tests."
    ),
)


@pytest.fixture(scope="module")
def client() -> PrtgClient:
    """A client pointed at the real PRTG server."""
    verify_tls = os.environ.get("PRTG_TEST_VERIFY_TLS", "true").lower() not in ("0", "false", "no")

    if _HAS_SECRET:
        return PrtgClient(
            secret_arn=os.environ["PRTG_TEST_SECRET_ARN"],
            verify_tls=verify_tls,
            ca_bundle_secret_arn=os.environ.get("PRTG_TEST_CA_BUNDLE_SECRET_ARN"),
        )

    # No secret: feed the credential through the environment path the client
    # already supports for local development.
    os.environ["PRTG_URL"] = os.environ["PRTG_TEST_URL"]
    if _HAS_API_KEY:
        os.environ["PRTG_API_KEY"] = os.environ["PRTG_TEST_API_KEY"]
        # Cleared so the run exercises key auth alone rather than silently falling
        # back if the key is rejected.
        os.environ.pop("PRTG_USERNAME", None)
        os.environ.pop("PRTG_PASSHASH", None)
    else:
        os.environ.pop("PRTG_API_KEY", None)
        os.environ["PRTG_USERNAME"] = os.environ["PRTG_TEST_USERNAME"]
        os.environ["PRTG_PASSHASH"] = os.environ["PRTG_TEST_PASSHASH"]
    return PrtgClient(secret_arn=None, verify_tls=verify_tls)


class _Context:
    """Stand-in for the Lambda context, carrying the tool name the way Gateway does."""

    def __init__(self, tool_name: str) -> None:
        self.client_context = type(
            "ClientContext", (), {"custom": {"bedrockAgentCoreToolName": f"prtg-mcp___{tool_name}"}}
        )()


def _call(tool: str, **arguments: object) -> dict:
    """Invoke a tool through the real handler, as the Gateway would."""
    return mcp_handler.handler(arguments, _Context(tool))


def _payload(response: dict) -> object:
    assert response["isError"] is False, response["content"][0]["text"]
    return json.loads(response["content"][0]["text"])


# --- Connectivity -----------------------------------------------------------


@requires_prtg
class TestConnectivity:
    def test_credential_is_accepted(self, client: PrtgClient) -> None:
        """The first thing to check. A 401 here means the passhash is wrong or the
        PRTG user is disabled; everything else will fail until this passes."""
        result = client.table("sensors", count=1)
        assert isinstance(result, dict)

    def test_tls_verification_succeeds(self, client: PrtgClient) -> None:
        """Fails if PRTG uses a self-signed certificate and no CA bundle was given.

        That is the expected failure, not a bug: supply the certificate via
        PRTG_TEST_CA_BUNDLE_SECRET_ARN, or set PRTG_TEST_VERIFY_TLS=false to confirm
        that verification is the only thing standing in the way.
        """
        if not client._verify_tls:
            pytest.skip("TLS verification is disabled for this run")
        client.table("sensors", count=1)


# --- Tools ------------------------------------------------------------------


@requires_prtg
class TestToolsAgainstLivePrtg:
    def test_every_declared_tool_is_reachable(self, client: PrtgClient, monkeypatch) -> None:
        """Calls all nine tools and reports which ones this PRTG instance rejects.

        Asserts on the set as a whole rather than failing at the first problem, so
        one run tells you everything that needs attention.
        """
        monkeypatch.setattr(mcp_handler, "_client", client)

        # A real object ID is needed for the detail tools, so find one first.
        sensors = _payload(_call("get_sensors", count=5))
        assert isinstance(sensors, dict)
        found = sensors.get("sensors") or []
        if not found:
            pytest.skip("This PRTG instance reports no sensors")
        sensor_id = found[0]["objid"]

        devices = _payload(_call("get_devices", count=5))
        device_list = devices.get("devices") or []

        calls: dict[str, dict] = {
            "get_sensors": {"count": 5},
            "get_sensor_details": {"id": sensor_id},
            "get_channels": {"id": sensor_id},
            "get_devices": {"count": 5},
            "get_groups": {"count": 5},
            "get_server_status": {},
            "get_messages": {"count": 5},
            "search": {"query": str(found[0]["name"])[:6], "count": 5},
            "get_sensor_history": {
                "id": sensor_id,
                "sdate": "2026-01-01-00-00-00",
                "edate": "2026-01-02-00-00-00",
                "avg": 3600,
                "count": 10,
            },
        }
        assert set(calls) == set(tools.tool_names()), "a declared tool is not exercised here"

        failures: dict[str, str] = {}
        for tool, arguments in calls.items():
            response = _call(tool, **arguments)
            if response["isError"]:
                failures[tool] = response["content"][0]["text"][:200]

        assert not failures, "tools failed against this PRTG instance:\n" + json.dumps(failures, indent=2)
        if device_list:
            assert "objid" in device_list[0]

    def test_status_filter_returns_only_matching_sensors(self, client: PrtgClient, monkeypatch) -> None:
        """Confirms the human-readable status words map to the right PRTG codes on
        this version."""
        monkeypatch.setattr(mcp_handler, "_client", client)
        payload = _payload(_call("get_sensors", status="up", count=20))
        sensors = payload.get("sensors") or []
        if not sensors:
            pytest.skip("No sensors are Up on this instance")
        for sensor in sensors:
            assert "up" in str(sensor.get("status", "")).lower()

    def test_server_status_returns_a_usable_summary(self, client: PrtgClient, monkeypatch) -> None:
        """Some PRTG versions do not expose /api/getstatus.htm, in which case the
        handler's fallback should still produce counts."""
        monkeypatch.setattr(mcp_handler, "_client", client)
        payload = _payload(_call("get_server_status"))
        assert payload, "get_server_status returned nothing"

    def test_invalid_object_id_produces_a_clean_error(self, client: PrtgClient, monkeypatch) -> None:
        monkeypatch.setattr(mcp_handler, "_client", client)
        response = _call("get_sensor_details", id=999_999_999)
        # Either a structured error or an empty result is acceptable; a traceback or
        # a leaked credential is not.
        text = response["content"][0]["text"]
        assert "passhash" not in text.lower()
        assert "Traceback" not in text


# --- Credential safety ------------------------------------------------------


@requires_prtg
class TestCredentialSafety:
    def test_a_wrong_credential_never_appears_in_the_error(self, client: PrtgClient) -> None:
        """The regression guard, run against the real server.

        PRTG authenticates via query parameters, for an API key exactly as for a
        passhash, and urllib3 embeds the request URL in its exception messages. This is
        the path by which a credential could reach the agent's context and the durable
        investigation record.

        The poisoned value has to be whichever form this run is using. An earlier
        version always set ``PRTG_PASSHASH``, which a key-authenticated run correctly
        ignores -- so the request succeeded and the test failed with "DID NOT RAISE"
        rather than proving anything.
        """
        from prtg_mcp.prtg_client import PrtgError

        variable = "PRTG_API_KEY" if _HAS_API_KEY else "PRTG_PASSHASH"
        sentinel = "deadbeefdeadbeef0000"
        original = os.environ.get(variable)
        os.environ[variable] = sentinel
        try:
            bad = PrtgClient(secret_arn=None, verify_tls=client._verify_tls)
            with pytest.raises(PrtgError) as exc:
                bad.table("sensors", count=1)
            assert sentinel not in str(exc.value), (
                f"the rejected {variable} appeared in the error surfaced to the agent"
            )
        finally:
            if original is not None:
                os.environ[variable] = original
            else:
                os.environ.pop(variable, None)


# --- Status filtering -------------------------------------------------------


@requires_prtg
class TestStatusFilteringIsTrustworthy:
    """The guard for the failure mode a mocked PRTG structurally cannot see.

    The client once sent ``filter_status[0]=3``. PRTG answers that with HTTP 200 and a
    ``treesize`` of 0, so every status-filtered query returned an empty list: no error,
    no warning, a well-formed result. An agent asking which sensors were down was told
    none of them were, which for an operations tool is the worst available outcome.

    The suite did not catch it. The one test that touched status filtering asked for
    sensors that were ``up`` and skipped when none came back, so a filter returning
    nothing was indistinguishable from an instance with nothing up. These assertions
    hold whatever this PRTG happens to be monitoring, which is what makes them able to
    fail when filtering breaks:

    * if any sensors exist, some status filter must match at least one of them
    * a filtered result contains only sensors carrying that status
    * the buckets partition the sensor list, so nothing is lost or double-counted

    Deliberately not asserting that a particular status is present: a healthy instance
    has nothing down, and a test demanding otherwise would fail on a working system.
    """

    #: Above any plausible sensor count for a test instance, and well under MAX_COUNT.
    _LIMIT = 500

    @staticmethod
    def _mapped_codes() -> set[int]:
        return {code for codes in STATUS_CODES.values() for code in codes}

    def _all_sensors(self, client: PrtgClient) -> dict[int, int]:
        """Every sensor, as ``objid -> status_raw``."""
        rows = client.table("sensors", count=self._LIMIT).get("sensors") or []
        return {int(r["objid"]): int(r["status_raw"]) for r in rows if "status_raw" in r}

    def _bucket(self, client: PrtgClient, status: str) -> set[int]:
        rows = client.table("sensors", count=self._LIMIT, status_filter=STATUS_CODES[status])
        return {int(r["objid"]) for r in rows.get("sensors") or []}

    def test_some_status_filter_matches_when_sensors_exist(self, client: PrtgClient) -> None:
        """The direct bug-catcher.

        Every sensor has exactly one status, so if any sensor exists then at least one
        filter has to return something. Filtering that silently matches nothing fails
        here no matter which statuses the instance happens to have.
        """
        everything = self._all_sensors(client)
        if not everything:
            pytest.skip("This PRTG instance has no sensors at all")

        matched = {status: len(self._bucket(client, status)) for status in STATUS_CODES}
        assert sum(matched.values()) > 0, (
            f"{len(everything)} sensors exist, yet every status filter returned nothing. "
            f"Status filtering is broken rather than the instance being idle. "
            f"Per-status counts: {matched}. "
            f"Statuses actually present: {sorted(set(everything.values()))}."
        )

    def test_a_filtered_result_contains_only_that_status(self, client: PrtgClient) -> None:
        """Catches the opposite failure: a filter PRTG ignores and answers in full."""
        for status, codes in STATUS_CODES.items():
            rows = client.table("sensors", count=self._LIMIT, status_filter=codes)
            for row in rows.get("sensors") or []:
                assert int(row["status_raw"]) in codes, (
                    f"filtering for {status!r} returned objid {row['objid']} with "
                    f"status_raw {row['status_raw']}, which is not in {codes}. The filter "
                    "is being ignored."
                )

    def test_the_buckets_partition_the_sensor_list(self, client: PrtgClient) -> None:
        """Nothing lost, nothing double-counted.

        A sensor missing from every bucket is only acceptable if its status is one this
        client does not map; anything else means a filter dropped it.
        """
        everything = self._all_sensors(client)
        if not everything:
            pytest.skip("This PRTG instance has no sensors at all")

        buckets = {status: self._bucket(client, status) for status in STATUS_CODES}

        names = list(buckets)
        for i, first in enumerate(names):
            for second in names[i + 1 :]:
                overlap = buckets[first] & buckets[second]
                assert not overlap, (
                    f"objids {sorted(overlap)} were returned for both {first!r} and "
                    f"{second!r}. The status code lists overlap."
                )

        union: set[int] = set().union(*buckets.values()) if buckets else set()
        unaccounted = set(everything) - union
        unmapped = self._mapped_codes()
        for objid in sorted(unaccounted):
            code = everything[objid]
            assert code not in unmapped, (
                f"objid {objid} has status_raw {code}, which STATUS_CODES maps, yet no "
                "filter returned it. A status filter is dropping sensors it should match."
            )

    def test_the_handler_reports_a_down_sensor_when_one_exists(self, client: PrtgClient, monkeypatch) -> None:
        """End to end on the question an agent actually asks.

        Skips on a healthy instance rather than demanding a fault. To exercise this
        deliberately, break something cheap -- pointing a Ping sensor at an unroutable
        address such as 192.0.2.1 is enough.
        """
        monkeypatch.setattr(mcp_handler, "_client", client)

        expected = self._bucket(client, "down")
        payload = _payload(_call("get_sensors", status="down", count=self._LIMIT))
        returned = {int(s["objid"]) for s in payload.get("sensors") or []}

        if not expected:
            assert not returned, f"nothing is down, yet the handler returned {sorted(returned)}"
            pytest.skip("Nothing is down on this instance, so there is no positive case to check")

        assert returned == expected, (
            f"the handler returned {sorted(returned)} for status='down' but the client "
            f"reports {sorted(expected)}"
        )
        for sensor in payload["sensors"]:
            assert sensor.get("name"), f"objid {sensor['objid']} came back with no name"
