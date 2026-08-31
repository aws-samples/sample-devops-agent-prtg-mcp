"""Fan-out routing: how an alarm is matched to an Agent Space."""

from __future__ import annotations

import json

import pytest

from alarm_pipeline.payload import PrtgAlarm
from alarm_pipeline.routing import Router, RoutingError

TABLE = {
    "Production": {
        "account": "222233334444",
        "agentSpaceId": "as-prod",
        "roleArn": "arn:aws:iam::222233334444:role/R",
    },
    "Local Probe": {
        "account": "333344445555",
        "agentSpaceId": "as-probe",
        "roleArn": "arn:aws:iam::333344445555:role/R",
    },
    "staging": {
        "account": "444455556666",
        "agentSpaceId": "as-stage",
        "roleArn": "arn:aws:iam::444455556666:role/R",
    },
    "DEFAULT": {
        "account": "222233334444",
        "agentSpaceId": "as-default",
        "roleArn": "arn:aws:iam::222233334444:role/R",
    },
}


class FakeSsm:
    def __init__(self, value: str, *, fail_with: Exception | None = None) -> None:
        self.value = value
        self.fail_with = fail_with
        self.calls = 0

    def get_parameter(self, *, Name: str) -> dict:  # noqa: N803 - boto3 casing
        self.calls += 1
        if self.fail_with is not None:
            raise self.fail_with
        return {"Parameter": {"Name": Name, "Value": self.value}}


def alarm(**kwargs) -> PrtgAlarm:
    base = {"sensor": "CPU Load", "device": "prod-web-01", "status": "Down", "message": "m"}
    return PrtgAlarm(**{**base, **kwargs})


def router(table: dict | None = None, **kwargs) -> Router:
    return Router(
        routing_parameter_name="/prtg/routes",
        ssm_client=FakeSsm(json.dumps(table if table is not None else TABLE)),
        **kwargs,
    )


# --- Single mode ------------------------------------------------------------


class TestSingleMode:
    def test_returns_the_configured_agent_space(self) -> None:
        target = Router(agent_space_id="as-only").resolve(alarm())
        assert target.agent_space_id == "as-only"
        assert target.is_cross_account is False

    def test_missing_configuration_is_an_error_not_a_silent_drop(self) -> None:
        with pytest.raises(RoutingError, match="nowhere to create"):
            Router(agent_space_id=None).resolve(alarm())


# --- Match precedence -------------------------------------------------------


class TestMatchPrecedence:
    def test_group_is_matched_first(self) -> None:
        target = router().resolve(alarm(group="Production", probe="Local Probe"))
        assert target.agent_space_id == "as-prod"
        assert target.matched_by == "group"

    def test_probe_is_matched_when_the_group_does_not_match(self) -> None:
        target = router().resolve(alarm(group="Unknown", probe="Local Probe"))
        assert target.agent_space_id == "as-probe"
        assert target.matched_by == "probe"

    def test_device_prefix_is_matched_last(self) -> None:
        target = router({**TABLE, "prod": {"agentSpaceId": "as-prefix"}}).resolve(alarm(device="prod-web-01"))
        assert target.agent_space_id == "as-prefix"
        assert target.matched_by == "device_prefix"

    def test_device_prefix_splits_on_hyphen_and_dot(self) -> None:
        target = router({**TABLE, "db": {"agentSpaceId": "as-db"}}).resolve(
            alarm(device="db.internal.example.com")
        )
        assert target.agent_space_id == "as-db"

    def test_falls_back_to_the_default_route(self) -> None:
        target = router().resolve(alarm(group="Nope", probe="Nope", device="nope-01"))
        assert target.agent_space_id == "as-default"
        assert target.matched_by == "default"

    def test_matching_is_case_sensitive(self) -> None:
        """PRTG names must match exactly. Silently case-folding would route alarms
        to an Agent Space the operator did not choose."""
        target = router().resolve(alarm(group="STAGING"))
        assert target.agent_space_id == "as-default"

    def test_no_match_and_no_default_is_an_error(self) -> None:
        table = {k: v for k, v in TABLE.items() if k != "DEFAULT"}
        with pytest.raises(RoutingError) as exc:
            router(table).resolve(alarm(group="Nope", probe="Nope", device="nope"))
        message = str(exc.value)
        assert "DEFAULT" in message
        assert "case-sensitive" in message
        # Lists what was configured, so the mismatch is diagnosable from the log.
        assert "Production" in message

    def test_cross_account_target_carries_its_role(self) -> None:
        target = router().resolve(alarm(group="Production"))
        assert target.is_cross_account is True
        assert target.role_arn == "arn:aws:iam::222233334444:role/R"
        assert target.account_id == "222233334444"


# --- Table loading ----------------------------------------------------------


class TestTableLoading:
    def test_table_is_cached_between_resolutions(self) -> None:
        ssm = FakeSsm(json.dumps(TABLE))
        r = Router(routing_parameter_name="/p", ssm_client=ssm, ttl_seconds=900)
        r.resolve(alarm(group="Production"))
        r.resolve(alarm(group="Production"))
        assert ssm.calls == 1

    def test_table_is_refetched_after_the_ttl(self) -> None:
        """So onboarding an account needs only an SSM edit, no deployment."""
        ssm = FakeSsm(json.dumps(TABLE))
        r = Router(routing_parameter_name="/p", ssm_client=ssm, ttl_seconds=0)
        r.resolve(alarm(group="Production"))
        r.resolve(alarm(group="Production"))
        assert ssm.calls == 2

    def test_a_stale_table_is_served_when_refresh_fails(self) -> None:
        """A transient SSM failure must not stop investigations being created."""
        ssm = FakeSsm(json.dumps(TABLE))
        r = Router(routing_parameter_name="/p", ssm_client=ssm, ttl_seconds=0)
        r.resolve(alarm(group="Production"))

        ssm.fail_with = RuntimeError("ThrottlingException")
        target = r.resolve(alarm(group="Production"))
        assert target.agent_space_id == "as-prod"

    def test_first_load_failure_is_an_error_with_guidance(self) -> None:
        r = Router(
            routing_parameter_name="/p",
            ssm_client=FakeSsm("", fail_with=RuntimeError("AccessDenied")),
        )
        with pytest.raises(RoutingError) as exc:
            r.resolve(alarm())
        assert "ssm:GetParameter" in str(exc.value)
        assert "VPC endpoint" in str(exc.value)

    def test_malformed_table_is_reported_clearly(self) -> None:
        r = Router(routing_parameter_name="/p", ssm_client=FakeSsm("not json"))
        with pytest.raises(RoutingError, match="not valid JSON"):
            r.resolve(alarm())

    def test_table_that_is_not_an_object_is_rejected(self) -> None:
        r = Router(routing_parameter_name="/p", ssm_client=FakeSsm("[1,2,3]"))
        with pytest.raises(RoutingError, match="JSON object"):
            r.resolve(alarm())

    def test_route_without_an_agent_space_is_rejected(self) -> None:
        r = router({"DEFAULT": {"account": "222233334444"}})
        with pytest.raises(RoutingError, match="agentSpaceId"):
            r.resolve(alarm())

    def test_legacy_space_key_is_accepted(self) -> None:
        """The reference implementation's routing table used "space"."""
        target = router({"DEFAULT": {"space": "as-legacy"}}).resolve(alarm())
        assert target.agent_space_id == "as-legacy"

    def test_is_fanout_reflects_configuration(self) -> None:
        assert router().is_fanout is True
        assert Router(agent_space_id="as-1").is_fanout is False
