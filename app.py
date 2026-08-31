#!/usr/bin/env python3
"""CDK entry point.

Reads one configuration file and builds the stacks it asks for:

    config/default.yaml
      ├── <prefix>-mcp-server       agent -> PRTG (AgentCore Gateway + tool Lambda)
      └── <prefix>-alarm-pipeline   PRTG -> agent (API Gateway + pipeline Lambda)

Shared settings - region, network, secret, observability - are declared once in the
config and used by both stacks. The stacks themselves are independent
CloudFormation stacks, so either can be deployed or destroyed on its own.

Usage:
    cdk synth                                  # uses config/default.yaml
    cdk synth -c config=config/regulated-private.yaml
    cdk deploy --all -c config=config/multi-account-fanout.yaml

Configuration problems are reported here, before any resource is created, with a
message naming the field and the remedy.
"""

from __future__ import annotations

import sys
from pathlib import Path

import aws_cdk as cdk

sys.path.insert(0, str(Path(__file__).parent))

from infrastructure.config import ConfigError, PrtgMcpConfig, load_config  # noqa: E402
from infrastructure.stacks.alarm_pipeline_stack import AlarmPipelineStack  # noqa: E402
from infrastructure.stacks.demo_prtg_stack import DemoPrtgStack  # noqa: E402
from infrastructure.stacks.mcp_server_stack import McpServerStack  # noqa: E402
from infrastructure.stacks.shared_stack import SharedStack  # noqa: E402

DEFAULT_CONFIG = "config/default.yaml"

#: Where the optional demo PRTG server lands when no address is given. Inside
#: 10.0.2.0/24, the first *private* subnet the sample's own VPC creates - 10.0.0.0/24
#: and 10.0.1.0/24 are public.
#:
#: Must stay equal to the `prtg.host_cidr` fallback in config/default.yaml, since the
#: tool function's egress is scoped to that address and nothing else. DemoPrtgStack
#: refuses to synthesise when they diverge, which is how this is kept honest: they did
#: diverge (10.0.2.50 here against 10.0.1.10 there), so the documented demo one-liner
#: deployed cleanly and then timed out on every tool call.
DEFAULT_DEMO_PRTG_IP = "10.0.2.50"

#: And the optional host it monitors. Same subnet, so both pinned addresses are valid
#: in the one range the demo stack resolves to.
DEFAULT_DEMO_APP_SERVER_IP = "10.0.2.45"


def main() -> None:
    app = cdk.App()
    config_path = app.node.try_get_context("config") or DEFAULT_CONFIG

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        sys.stderr.write(f"\n{exc}\n")
        raise SystemExit(1) from None

    for warning in config.warnings:
        sys.stderr.write(f"\n[warning] {warning}\n")
    if config.warnings:
        sys.stderr.write("\n")

    env = cdk.Environment(
        account=config.account or None,
        region=config.region,
    )

    # Shared infrastructure comes first: one VPC, one set of security groups and
    # endpoints, one alarm topic. Both halves consume it.
    #
    # An earlier arrangement had each half build its own networking, which a real
    # deployment rejected outright: the security group, flow-log group and dashboard
    # names collided, and it would also have created two VPCs with two NAT gateways.
    # Synthesis could not catch that, because each template was valid on its own.
    shared = SharedStack(
        app,
        f"{config.name_prefix}-shared",
        config=config,
        env=env,
        description=(
            "PRTG MCP integration shared infrastructure: VPC, security groups, interface "
            "endpoints, alarm topic. (aws-samples)"
        ),
    )
    _tag(shared, config)

    if config.deploy_mcp_server:
        mcp_stack = McpServerStack(
            app,
            f"{config.name_prefix}-mcp-server",
            config=config,
            network=shared.network,
            alarm_topic=shared.alarm_topic,
            env=env,
            description=(
                "PRTG MCP server for AWS DevOps Agent: AgentCore Gateway exposing read-only PRTG "
                "tools. (aws-samples)"
            ),
        )
        mcp_stack.observability.finalise()
        # Explicit, so `cdk deploy --all` orders them correctly even before the
        # cross-stack references are resolved.
        mcp_stack.add_stack_dependency(shared)
        _tag(mcp_stack, config)

    if config.deploy_alarm_pipeline:
        pipeline_stack = AlarmPipelineStack(
            app,
            f"{config.name_prefix}-alarm-pipeline",
            config=config,
            network=shared.network,
            alarm_topic=shared.alarm_topic,
            env=env,
            description=(
                "PRTG alarm pipeline for AWS DevOps Agent: creates investigations from PRTG "
                "notifications. (aws-samples)"
            ),
        )
        pipeline_stack.observability.finalise()
        pipeline_stack.add_stack_dependency(shared)
        _tag(pipeline_stack, config)

    # An optional throwaway PRTG server, for evaluating the integration without one.
    # Context flags rather than configuration fields on purpose: this is a testing
    # affordance, not part of the solution, and it should not appear alongside the
    # settings that describe a real deployment.
    want_demo = _is_truthy(app.node.try_get_context("demo_prtg"))
    want_app_server = _is_truthy(app.node.try_get_context("demo_app_server"))

    if want_app_server and not want_demo:
        sys.stderr.write(
            "\ndemo_app_server=true requires demo_prtg=true. The monitored host lives in the demo "
            "stack, and on its own it would have nothing monitoring it.\n"
        )
        raise SystemExit(1)

    if want_demo:
        _add_demo_prtg(app, config=config, shared=shared, env=env, with_app_server=want_app_server)

    app.synth()


def _add_demo_prtg(
    app: cdk.App,
    *,
    config: PrtgMcpConfig,
    shared: SharedStack,
    env: cdk.Environment,
    with_app_server: bool,
) -> None:
    """Build the optional demo PRTG server, and optionally a host for it to monitor.

    Context problems are reported the same way configuration problems are: named
    field, stated remedy, before anything is created.
    """
    try:
        demo_stack = DemoPrtgStack(
            app,
            f"{config.name_prefix}-demo-prtg",
            config=config,
            network=shared.network,
            private_ip=app.node.try_get_context("prtg_private_ip") or DEFAULT_DEMO_PRTG_IP,
            subnet_id=app.node.try_get_context("prtg_subnet"),
            installer_s3_uri=app.node.try_get_context("prtg_installer_s3"),
            with_app_server=with_app_server,
            app_server_ip=(
                app.node.try_get_context("demo_app_server_ip") or DEFAULT_DEMO_APP_SERVER_IP
                if with_app_server
                else None
            ),
            env=env,
            description=(
                "DEMO ONLY, not a production topology: PRTG server on EC2 for evaluating the "
                "MCP integration. (aws-samples)"
            ),
        )
    except ValueError as exc:
        sys.stderr.write(f"\n{exc}\n")
        raise SystemExit(1) from None

    demo_stack.add_stack_dependency(shared)
    _tag(demo_stack, config)


def _is_truthy(value: object) -> bool:
    """Interpret a CDK context value as a boolean.

    ``-c demo_prtg=true`` arrives as the string ``"true"``, while the same key set in
    ``cdk.json`` arrives as a real boolean. Both have to work, and ``-c
    demo_prtg=false`` must not enable the stack just because a non-empty string is
    truthy in Python.
    """
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    return bool(value)


def _tag(stack: cdk.Stack, config: PrtgMcpConfig) -> None:
    """Apply configured tags, plus a few that aid cost attribution and audit."""
    for key, value in config.tags.items():
        cdk.Tags.of(stack).add(key, value)

    # Recorded on every resource so the deployment shape is visible in Config and
    # Cost Explorer without reading the template.
    cdk.Tags.of(stack).add("prtg-mcp:network-mode", config.network.mode)
    cdk.Tags.of(stack).add("prtg-mcp:auth-mode", config.auth.mode)
    cdk.Tags.of(stack).add("prtg-mcp:targeting-mode", config.targeting.mode)


if __name__ == "__main__":
    main()
