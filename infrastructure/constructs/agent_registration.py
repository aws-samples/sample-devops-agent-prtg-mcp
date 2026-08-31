"""Register the MCP server with AWS DevOps Agent, in CloudFormation.

The console walkthrough in most guides is not the only route. ``AWS::DevOpsAgent::Service``
registers a capability provider, and ``AWS::DevOpsAgent::Association`` attaches it to an
Agent Space with a tool allowlist. Both are available as L1 constructs in
``aws_cdk.aws_devopsagent``.

Only OAuth-based providers -- Datadog, GitHub, Slack -- are console-only, because their
registration needs an interactive browser redirect. SigV4 has no such step, so a Gateway
fronted by SigV4 can be registered entirely from infrastructure code.

Two properties of the API shape the design here:

Registration is account-level while association is per Agent Space. Two Agent Spaces
sharing one MCP server means one ``CfnService`` and two ``CfnAssociation`` resources. This
construct owns one of each, which is the single-Agent-Space case; a second Agent Space
would add an association against the same service.

Tool names are prefixed by the Gateway target. The Gateway exposes
``prtg-mcp___get_sensors``, not ``get_sensors``, and an allowlist using the bare names
matches nothing. The prefix is derived here from the same target name the Gateway is
given, so the two cannot drift.
"""

from __future__ import annotations

from aws_cdk import CfnOutput, Token
from aws_cdk import aws_devopsagent as devopsagent

from constructs import Construct

#: Separator the AgentCore Gateway puts between a target name and a tool name.
#: Three underscores, and not configurable.
TOOL_NAME_SEPARATOR = "___"

#: Ceiling on an MCP tool name, imposed by DevOps Agent. Worth checking at synthesis
#: rather than discovering when an association is rejected.
MAX_TOOL_NAME_LENGTH = 64


class AgentRegistration(Construct):
    """Registers the Gateway as a DevOps Agent capability provider and associates it.

    Attributes:
        service: The account-level registration.
        association: The binding to one Agent Space, carrying the tool allowlist.
        qualified_tool_names: Tool names as the Gateway exposes them.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        gateway_url: str,
        invoker_role_arn: str,
        agent_space_id: str,
        target_name: str,
        tool_names: list[str],
        region: str,
        service_name: str = "prtg-mcp",
        description: str = "Read-only PRTG Network Monitor tools (aws-samples)",
        **kwargs: object,
    ) -> None:
        """
        Args:
            gateway_url: The Gateway's MCP endpoint. Must include the path, because
                DevOps Agent rejects a bare host.
            invoker_role_arn: Role the agent assumes to sign requests. Must be
                trusted by ``aidevops.amazonaws.com`` and hold
                ``bedrock-agentcore:InvokeGateway`` on the Gateway.
            agent_space_id: The Agent Space to associate with. Must already exist.
            target_name: The Gateway target name, used to derive the tool prefix.
            tool_names: Unprefixed tool names, as declared in ``tools.py``.
            region: Region to sign for.
            service_name: Name shown in the DevOps Agent console.
            description: Description shown in the console.

        Raises:
            ValueError: if the endpoint has no path, no tools were given, or a
                qualified tool name would exceed the service limit.
        """
        super().__init__(scope, construct_id, **kwargs)  # type: ignore[arg-type]

        self._validate(gateway_url, tool_names, target_name)

        self.qualified_tool_names = [
            f"{target_name}{TOOL_NAME_SEPARATOR}{name}" for name in sorted(tool_names)
        ]

        self.service = devopsagent.CfnService(
            self,
            "Service",
            service_type="mcpserversigv4",
            service_details=devopsagent.CfnService.ServiceDetailsProperty(
                mcp_server_sig_v4=devopsagent.CfnService.MCPServerSigV4DetailsProperty(
                    name=service_name,
                    endpoint=gateway_url,
                    description=description,
                    authorization_config=(
                        devopsagent.CfnService.MCPServerSigV4AuthorizationConfigProperty(
                            region=region,
                            # The SigV4 service name for an AgentCore Gateway. Not the
                            # name of this MCP server.
                            service="bedrock-agentcore",
                            role_arn=invoker_role_arn,
                        )
                    ),
                )
            ),
        )

        self.association = devopsagent.CfnAssociation(
            self,
            "Association",
            agent_space_id=agent_space_id,
            service_id=self.service.attr_service_id,
            configuration=devopsagent.CfnAssociation.ServiceConfigurationProperty(
                mcp_server_sig_v4=devopsagent.CfnAssociation.MCPServerSigV4ConfigurationProperty(
                    tools=self.qualified_tool_names,
                )
            ),
        )
        # The service must exist before anything can be associated with it. Stated
        # explicitly rather than relying on the attr_service_id reference alone.
        self.association.add_dependency(self.service)

        self._emit_outputs(agent_space_id)

    # --- Validation ---------------------------------------------------------

    @staticmethod
    def _validate(gateway_url: str, tool_names: list[str], target_name: str) -> None:
        # The Gateway URL is normally a CloudFormation token, because the Gateway is
        # created in the same deployment and its hostname is not known until then. Only
        # a literal can be inspected; a token is left for the service to validate.
        if not Token.is_unresolved(gateway_url):
            if not gateway_url.startswith("https://"):
                raise ValueError(f"gateway_url must be https://, got {gateway_url!r}.")

            # DevOps Agent requires a resource path. A bare host passes the console
            # form and then fails validation, so it is caught here instead.
            path = gateway_url[len("https://") :].rstrip("/")
            if "/" not in path or not path.split("/", 1)[1]:
                raise ValueError(
                    "gateway_url must include a resource path, for example "
                    f"https://host/mcp rather than https://host. Got {gateway_url!r}."
                )

        if not tool_names:
            raise ValueError(
                "tool_names is empty. Associating no tools registers a provider the agent cannot use."
            )

        for name in tool_names:
            qualified = f"{target_name}{TOOL_NAME_SEPARATOR}{name}"
            if len(qualified) > MAX_TOOL_NAME_LENGTH:
                raise ValueError(
                    f"Tool name {qualified!r} is {len(qualified)} characters, over the "
                    f"{MAX_TOOL_NAME_LENGTH}-character limit DevOps Agent imposes. "
                    "Shorten the tool name or the Gateway target name."
                )

    # --- Outputs ------------------------------------------------------------

    def _emit_outputs(self, agent_space_id: str) -> None:
        CfnOutput(
            self,
            "RegisteredServiceId",
            description="DevOps Agent service ID for the registered PRTG MCP server.",
            value=self.service.attr_service_id,
        )
        CfnOutput(
            self,
            "AssociatedAgentSpaceId",
            description="Agent Space the PRTG tools were associated with.",
            value=agent_space_id,
        )
        CfnOutput(
            self,
            "AllowlistedTools",
            description=(
                "Tools exposed to the agent, prefixed by the Gateway target name. Bare "
                "names such as get_sensors would match nothing."
            ),
            value=",".join(self.qualified_tool_names),
        )
