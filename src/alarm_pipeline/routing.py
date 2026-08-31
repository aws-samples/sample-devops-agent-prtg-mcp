"""Deciding which Agent Space receives an investigation.

In ``single`` mode this is one environment variable. In ``fanout`` mode a routing
table maps PRTG groupings to Agent Spaces across accounts, and the Lambda assumes a
role in the target account before creating the task.

The routing table lives in an SSM parameter rather than an environment variable.
The reference implementation used an environment variable holding escaped JSON,
which is awkward to edit by hand, impossible to diff usefully, and runs into
Lambda's 4 KB environment limit at roughly a dozen accounts. An SSM parameter is
also editable without touching the function, so onboarding a workload account does
not require a deployment.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Final

logger = logging.getLogger(__name__)

DEFAULT_ROUTE_KEY: Final[str] = "DEFAULT"
DEFAULT_ROUTING_TTL_SECONDS: Final[int] = 300


class RoutingError(Exception):
    """No Agent Space could be determined for an alarm."""


@dataclass(frozen=True)
class Target:
    """Where an investigation should be created."""

    agent_space_id: str
    account_id: str | None = None
    role_arn: str | None = None
    #: How the route was chosen, for logging and for the investigation record.
    matched_by: str = "single"
    matched_value: str = ""

    @property
    def is_cross_account(self) -> bool:
        return self.role_arn is not None


class Router:
    """Resolves an alarm to a target Agent Space.

    The routing table is cached with a TTL so an edit to the SSM parameter takes
    effect without a deployment or a forced cold start, while a burst of alarms does
    not make one GetParameter call each.
    """

    def __init__(
        self,
        *,
        agent_space_id: str | None = None,
        routing_parameter_name: str | None = None,
        ttl_seconds: int | None = None,
        ssm_client: Any = None,
    ) -> None:
        self._agent_space_id = (
            agent_space_id if agent_space_id is not None else os.environ.get("AGENT_SPACE_ID")
        )
        self._parameter_name = (
            routing_parameter_name
            if routing_parameter_name is not None
            else os.environ.get("ROUTING_PARAMETER_NAME") or None
        )
        self._ttl = (
            ttl_seconds
            if ttl_seconds is not None
            else _env_int("ROUTING_TTL_SECONDS", DEFAULT_ROUTING_TTL_SECONDS)
        )
        self._ssm_client = ssm_client
        self._table: dict[str, dict[str, str]] | None = None
        self._table_expires_at = 0.0

    @property
    def is_fanout(self) -> bool:
        return self._parameter_name is not None

    def resolve(self, alarm: Any) -> Target:
        """Choose the target Agent Space for an alarm.

        Args:
            alarm: A ``PrtgAlarm``.

        Raises:
            RoutingError: if no route matched and no DEFAULT route exists. The
                caller must treat this as a failure rather than dropping the alarm
                silently - an alert that reaches no agent is the worst outcome
                available.
        """
        if not self.is_fanout:
            if not self._agent_space_id:
                raise RoutingError(
                    "AGENT_SPACE_ID is not set and no routing parameter is configured, so there is "
                    "nowhere to create the investigation."
                )
            return Target(agent_space_id=self._agent_space_id)

        table = self._load_table()

        # Ordered most specific to least. Group before probe because a group is the
        # narrower concept in PRTG's hierarchy, and device prefix last because it is
        # a heuristic rather than an explicit PRTG attribute.
        for matched_by, value in (
            ("group", alarm.group),
            ("probe", alarm.probe),
            ("device_prefix", _device_prefix(alarm.device)),
        ):
            if value and value in table:
                return _to_target(table[value], matched_by=matched_by, matched_value=value)

        if DEFAULT_ROUTE_KEY in table:
            return _to_target(table[DEFAULT_ROUTE_KEY], matched_by="default", matched_value=DEFAULT_ROUTE_KEY)

        raise RoutingError(
            f"No route matched group={alarm.group!r}, probe={alarm.probe!r}, "
            f"device={alarm.device!r}, and the routing table has no {DEFAULT_ROUTE_KEY} entry. "
            f"Configured routes: {', '.join(sorted(table)) or 'none'}. Note that matching is "
            "case-sensitive and must equal the PRTG name exactly."
        )

    def _load_table(self) -> dict[str, dict[str, str]]:
        """Fetch the routing table, honouring the TTL cache."""
        now = time.time()
        if self._table is not None and now < self._table_expires_at:
            return self._table

        client = self._ssm()
        try:
            response = client.get_parameter(Name=self._parameter_name)
            raw = response["Parameter"]["Value"]
        except Exception as exc:  # noqa: BLE001
            if self._table is not None:
                # Serve the stale table rather than fail. A transient SSM problem
                # should not stop investigations being created; the alternative is
                # dropping real alarms.
                logger.warning(
                    json.dumps(
                        {
                            "event": "routing_table_refresh_failed_using_stale",
                            "detail": str(exc)[:300],
                        }
                    )
                )
                self._table_expires_at = now + 30
                return self._table
            raise RoutingError(
                f"Could not read the routing table from SSM parameter {self._parameter_name!r}. "
                "Check the execution role grants ssm:GetParameter on it, and that an SSM VPC "
                f"endpoint exists if the function has no internet route. Underlying error: {exc}"
            ) from exc

        try:
            table = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RoutingError(f"The routing table in {self._parameter_name!r} is not valid JSON.") from exc

        if not isinstance(table, dict):
            raise RoutingError(
                f"The routing table in {self._parameter_name!r} must be a JSON object keyed by PRTG "
                "group, probe, or device prefix."
            )

        self._table = table
        self._table_expires_at = now + self._ttl
        logger.info(json.dumps({"event": "routing_table_loaded", "routeCount": len(table)}))
        return table

    def _ssm(self) -> Any:
        if self._ssm_client is None:
            import boto3

            self._ssm_client = boto3.client("ssm")
        return self._ssm_client


def _to_target(entry: dict[str, str], *, matched_by: str, matched_value: str) -> Target:
    agent_space_id = entry.get("agentSpaceId") or entry.get("space")
    if not agent_space_id:
        raise RoutingError(
            f"Routing entry {matched_value!r} has no agentSpaceId. Each entry needs at least "
            '{"agentSpaceId": "..."} and, for a cross-account target, "account" and "roleArn".'
        )
    return Target(
        agent_space_id=agent_space_id,
        account_id=entry.get("account"),
        role_arn=entry.get("roleArn"),
        matched_by=matched_by,
        matched_value=matched_value,
    )


def _device_prefix(device: str) -> str:
    """Take the leading token of a device name.

    ``prod-web-01.example.com`` -> ``prod``. A convention rather than a PRTG
    feature, which is why it is tried last.
    """
    if not device:
        return ""
    return device.split("-", maxsplit=1)[0].split(".", maxsplit=1)[0].strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default
