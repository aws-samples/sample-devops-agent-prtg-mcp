"""Tests for registering the MCP server with DevOps Agent from CloudFormation.

Most guides describe the console walkthrough, which leaves registration as a manual step
outside the deployment. ``AWS::DevOpsAgent::Service`` and ``AWS::DevOpsAgent::Association``
make it part of the stack. Only OAuth providers are genuinely console-only, because their
registration needs an interactive browser redirect; SigV4 has no such step.

The assertion that matters most here is the tool prefix. The Gateway exposes
``prtg-mcp___get_sensors``, not ``get_sensors``, and an allowlist of bare names matches
nothing at all. That failure is silent -- registration succeeds, association succeeds, and
the agent simply has no tools -- which is exactly the shape of bug worth pinning. Verified
against the deployed Gateway by an MCP ``tools/list`` call, which returned the nine
prefixed names plus the Gateway's own ``x_amz_bedrock_agentcore_search``.
"""

from __future__ import annotations

import os

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template
from infrastructure.config import ConfigError, load_config
from infrastructure.constructs.agent_registration import (
    MAX_TOOL_NAME_LENGTH,
    TOOL_NAME_SEPARATOR,
    AgentRegistration,
)
from infrastructure.stacks.mcp_server_stack import GATEWAY_TARGET_NAME, McpServerStack
from infrastructure.stacks.shared_stack import SharedStack

#: Any syntactically valid Agent Space ID. Supplied to the environment below rather
#: than read from it: `config/default.yaml` interpolates ${DEVOPS_AGENT_SPACE_ID} with
#: no fallback, so a test that relied on the ambient value passed only on a machine
#: where the author had exported their own, and failed on a clean clone and in CI.
AGENT_SPACE = "11111111-2222-3333-4444-555555555555"

#: Set at import, before any load_config call. test_infrastructure.py does the same.
#:
#: These are process-wide and pytest imports every test module before running any test,
#: so whatever is set here is what *other* modules synthesise `config/default.yaml`
#: with. PRTG_PRIVATE_IP therefore has to agree with DEFAULT_DEMO_PRTG_IP in app.py, or
#: the demo stack's egress cross-check trips in test_demo_prtg_stack.py - a failure with
#: no visible connection to this file. It held 10.0.1.10 while the demo default was
#: 10.0.2.50, which is the same mismatch the cross-check now exists to catch.
os.environ.setdefault("DEVOPS_AGENT_SPACE_ID", AGENT_SPACE)
os.environ.setdefault("PRTG_SOURCE_IP", "203.0.113.7")
os.environ.setdefault("PRTG_PRIVATE_IP", "10.0.2.50")


def _template(*, register: bool) -> Template:
    """Synthesise the MCP stack with registration on or off."""
    config = load_config("config/default.yaml")
    object.__setattr__(config.targeting, "register_with_agent_space", register)

    app = cdk.App()
    env = cdk.Environment(account="123456789012", region=config.region)
    shared = SharedStack(app, f"{config.name_prefix}-shared", config=config, env=env)
    stack = McpServerStack(
        app,
        f"{config.name_prefix}-mcp-server",
        config=config,
        network=shared.network,
        alarm_topic=shared.alarm_topic,
        env=env,
    )
    stack.observability.finalise()
    return Template.from_stack(stack)


# --- Opt-in behaviour -------------------------------------------------------


def test_nothing_is_registered_by_default() -> None:
    """Registration is account-level, so a second deployment would collide."""
    template = _template(register=False)
    template.resource_count_is("AWS::DevOpsAgent::Service", 0)
    template.resource_count_is("AWS::DevOpsAgent::Association", 0)


def test_enabling_it_creates_exactly_one_of_each() -> None:
    template = _template(register=True)
    template.resource_count_is("AWS::DevOpsAgent::Service", 1)
    template.resource_count_is("AWS::DevOpsAgent::Association", 1)


# --- The registration itself ------------------------------------------------


def test_it_registers_as_sigv4_against_the_gateway() -> None:
    template = _template(register=True)
    template.has_resource_properties(
        "AWS::DevOpsAgent::Service",
        {
            "ServiceType": "mcpserversigv4",
            "ServiceDetails": Match.object_like(
                {
                    "MCPServerSigV4": Match.object_like(
                        {
                            "AuthorizationConfig": Match.object_like(
                                {
                                    # The SigV4 service name of the Gateway, not the
                                    # name of this MCP server.
                                    "Service": "bedrock-agentcore",
                                    "Region": Match.any_value(),
                                    "RoleArn": Match.any_value(),
                                }
                            )
                        }
                    )
                }
            ),
        },
    )


def test_the_endpoint_and_role_are_wired_not_hardcoded(self=None) -> None:
    """Both come from the Gateway and role in this stack, so they cannot drift."""
    template = _template(register=True)
    details = next(iter(template.find_resources("AWS::DevOpsAgent::Service").values()))["Properties"][
        "ServiceDetails"
    ]["MCPServerSigV4"]

    assert "Fn::GetAtt" in details["Endpoint"], "endpoint should reference the Gateway"
    assert "Fn::GetAtt" in details["AuthorizationConfig"]["RoleArn"], "role should reference the invoker role"


def test_the_console_name_is_not_doubled() -> None:
    """``resource_name`` would produce 'prtg-mcp-prtg-mcp', which reads as a mistake."""
    template = _template(register=True)
    details = next(iter(template.find_resources("AWS::DevOpsAgent::Service").values()))["Properties"][
        "ServiceDetails"
    ]["MCPServerSigV4"]
    assert details["Name"] == "prtg-mcp"


# --- The tool allowlist -----------------------------------------------------


def test_every_tool_carries_the_gateway_target_prefix() -> None:
    """The silent failure this guards: bare names match nothing.

    The Gateway prefixes each tool with the target name, so an allowlist of
    ``get_sensors`` registers successfully and exposes no tools at all.
    """
    template = _template(register=True)
    tools = next(iter(template.find_resources("AWS::DevOpsAgent::Association").values()))["Properties"][
        "Configuration"
    ]["MCPServerSigV4"]["Tools"]

    assert tools, "the allowlist must not be empty"
    for name in tools:
        assert name.startswith(f"{GATEWAY_TARGET_NAME}{TOOL_NAME_SEPARATOR}"), (
            f"{name!r} is missing the Gateway target prefix, so it would match no tool"
        )


def test_the_allowlist_matches_the_declared_tools() -> None:
    """Derived from tools.py, so adding a tool cannot leave the allowlist behind."""
    from prtg_mcp import tools as prtg_tools

    template = _template(register=True)
    tools = next(iter(template.find_resources("AWS::DevOpsAgent::Association").values()))["Properties"][
        "Configuration"
    ]["MCPServerSigV4"]["Tools"]

    expected = {f"{GATEWAY_TARGET_NAME}{TOOL_NAME_SEPARATOR}{n}" for n in prtg_tools.tool_names()}
    assert set(tools) == expected


def test_the_association_references_the_service_it_registered() -> None:
    template = _template(register=True)
    props = next(iter(template.find_resources("AWS::DevOpsAgent::Association").values()))["Properties"]
    assert "Fn::GetAtt" in props["ServiceId"]
    # Compared against the resolved config, not AGENT_SPACE. The setdefault above only
    # applies when the variable is unset, and the Makefile, CI, and a bare `pytest` each
    # supply a different value -- asserting the literal passes in only one of the three.
    assert props["AgentSpaceId"] == load_config("config/default.yaml").targeting.agent_space_id


# --- Construct-level validation --------------------------------------------


class TestValidation:
    """Rejected at synthesis, since the service reports these late and obscurely."""

    _KWARGS = {
        "gateway_url": "https://gw.example.amazonaws.com/mcp",
        "invoker_role_arn": "arn:aws:iam::123456789012:role/invoker",
        "agent_space_id": AGENT_SPACE,
        "target_name": "prtg-mcp",
        "region": "ap-southeast-2",
    }

    def _build(self, **overrides: object) -> None:
        stack = cdk.Stack(cdk.App(), "T")
        AgentRegistration(stack, "R", **{**self._KWARGS, "tool_names": ["get_sensors"], **overrides})  # type: ignore[arg-type]

    def test_a_valid_configuration_is_accepted(self) -> None:
        self._build()

    def test_an_endpoint_without_a_path_is_refused(self) -> None:
        """DevOps Agent requires a resource path; a bare host fails service-side."""
        with pytest.raises(ValueError, match="resource path"):
            self._build(gateway_url="https://gw.example.amazonaws.com")

    def test_a_non_https_endpoint_is_refused(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            self._build(gateway_url="http://gw.example.amazonaws.com/mcp")

    def test_an_empty_tool_list_is_refused(self) -> None:
        """Registering a provider with no tools gives the agent nothing to call."""
        with pytest.raises(ValueError, match="tool_names is empty"):
            self._build(tool_names=[])

    def test_an_over_long_qualified_name_is_refused(self) -> None:
        """The prefix counts toward the 64-character service limit."""
        with pytest.raises(ValueError, match=str(MAX_TOOL_NAME_LENGTH)):
            self._build(tool_names=["x" * MAX_TOOL_NAME_LENGTH])


# --- Configuration guards ---------------------------------------------------


class TestConfigurationGuards:
    def test_fanout_with_registration_is_refused(self) -> None:
        """Association targets one Agent Space; fanout has several."""
        config = load_config("config/multi-account-fanout.yaml")
        object.__setattr__(config.targeting, "register_with_agent_space", True)
        with pytest.raises(ConfigError, match="fanout"):
            config.validate()

    def test_oidc_with_registration_is_refused(self) -> None:
        """Only SigV4 can be registered from infrastructure code."""
        config = load_config("config/default.yaml")
        object.__setattr__(config.targeting, "register_with_agent_space", True)
        object.__setattr__(config.auth, "mode", "oidc")
        with pytest.raises(ConfigError, match="Only a SigV4 Gateway"):
            config.validate()
