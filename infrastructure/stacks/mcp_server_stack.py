"""MCP server stack: the agent → PRTG direction.

Builds an AgentCore Gateway exposing nine read-only PRTG tools, backed by a Lambda
function in a VPC. Once registered as a capability provider, the DevOps Agent can
query PRTG mid-investigation instead of working from an alarm payload alone.

    DevOps Agent ──► AgentCore Gateway ──► Lambda (VPC) ──► PRTG
                                              │
                                              └──► Secrets Manager

The tool schema advertised by the Gateway is generated from
``src/prtg_mcp/tools.py`` at synthesis time, so the schema the agent sees and the
one the handler enforces are the same object. Writing the Gateway schema by hand -
as the reference implementation did, in a separate ``create-target-config.py`` -
lets the two drift, and the resulting failures only appear mid-investigation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sns as sns

from constructs import Construct
from infrastructure.config import PrtgMcpConfig
from infrastructure.constructs.agent_registration import AgentRegistration
from infrastructure.constructs.common import retention_for
from infrastructure.constructs.network import PrtgNetwork
from infrastructure.constructs.observability import Observability
from infrastructure.constructs.prtg_secret import PrtgSecret

# The tool schema is the single source of truth shared with the Lambda. Importing
# it here is what guarantees the Gateway advertises exactly what the handler
# serves. tools.py is standard-library only, so this import is safe at synthesis.
_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from prtg_mcp import tools as prtg_tools  # noqa: E402

#: Gateway target name. The Gateway prefixes every tool with it, so
#: ``get_sensors`` is exposed as ``prtg-mcp___get_sensors``. Shared with the DevOps
#: Agent registration so the tool allowlist cannot drift from what is exposed.
GATEWAY_TARGET_NAME = "prtg-mcp"

#: Lambda runtime. Pinned rather than "latest" so a redeploy is reproducible.
LAMBDA_RUNTIME = lambda_.Runtime.PYTHON_3_13

#: Where the generated Gateway tool schema is written before being uploaded as an
#: asset. Under ``build/`` and gitignored: it is a synthesis artefact, and
#: committing it would create a second place the schema lives and therefore a way
#: for it to drift from ``tools.py``.
_SCHEMA_BUILD_PATH = Path(__file__).resolve().parents[2] / "build" / "gateway-tool-schema.json"


def write_tool_schema(path: Path | None = None) -> Path:
    """Render the Gateway tool schema from ``prtg_mcp.tools`` and return its path.

    Why a file asset rather than ``ToolSchema.from_inline``
    ------------------------------------------------------
    ``from_inline`` requires CDK's ``ToolDefinition``, which coerces each
    ``input_schema`` into a ``SchemaDefinition`` struct modelling only ``type``,
    ``description``, ``items``, ``properties`` and ``required``. It rejects
    ``enum``, ``pattern``, ``minimum``, ``maximum``, ``minLength``, ``maxLength``,
    ``default`` and ``additionalProperties`` outright, so the schema in ``tools.py``
    cannot be passed to it without being rewritten.

    ``from_local_asset`` accepts the JSON as-is, which keeps ``tools.py`` as the one
    definition of the tool surface with no hand-maintained translation layer.

    An important caveat, established by testing against a deployed Gateway
    ---------------------------------------------------------------------
    AgentCore Gateway **normalises the schema when it republishes it over MCP**. A
    ``tools/list`` response preserves only ``type``, ``description`` and
    ``required``; every constraint listed above is stripped, whichever mechanism
    supplied it.

    So this choice does not get richer constraints in front of the agent - nothing
    would. Two consequences shape the rest of the design:

    1. **Constraints are enforced, not advertised.** The handler's validator is the
       thing that actually applies them, and its rejection messages are written for
       the agent to act on.
    2. **Descriptions carry the information instead.** Since descriptions *are*
       preserved, ``tools.py`` restates valid enum values and bounds in the
       description text. That is the only channel that reaches the agent, and
       ``tests/unit/test_tool_contract.py`` asserts it stays that way.

    The file is generated rather than committed, so there is no second copy of the
    schema to drift.
    """
    target = path or _SCHEMA_BUILD_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    # sort_keys and a trailing newline keep the asset hash stable across runs, so
    # an unchanged schema does not show up as a diff in `cdk diff`.
    target.write_text(
        json.dumps(prtg_tools.as_gateway_tool_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


class McpServerStack(Stack):
    """AgentCore Gateway plus the PRTG tool Lambda.

    Attributes:
        gateway: The Gateway. Its URL is what gets registered in DevOps Agent.
        tool_function: The Lambda serving the nine tools.
        invoker_role: Role the DevOps Agent assumes to call the Gateway (SigV4 only).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: PrtgMcpConfig,
        network: PrtgNetwork,
        alarm_topic: sns.ITopic | None = None,
        **kwargs: object,
    ) -> None:
        """
        Args:
            config: The deployment configuration.
            network: Networking from ``SharedStack``. Required rather than optional:
                building it here would give each half its own VPC and NAT gateway,
                and would collide on the security group and flow-log group names.
            alarm_topic: Alarm destination from ``SharedStack``.
        """
        super().__init__(scope, construct_id, **kwargs)  # type: ignore[arg-type]
        self.config = config

        self.network = network
        self.observability = Observability(
            self,
            "Observability",
            config=config,
            alarm_topic=alarm_topic,
            # Distinct per stack: dashboard names are physical names.
            dashboard_name=f"{config.name_prefix}-mcp-server",
        )
        self.secret = PrtgSecret(self, "PrtgSecret", config=config)

        self.log_group = self._build_log_group()
        self.tool_function = self._build_tool_function()
        self.gateway = self._build_gateway()
        self._add_tool_target()
        self.invoker_role = self._build_invoker_role()
        # After the invoker role, because registration needs its ARN.
        self.registration: AgentRegistration | None = None
        self._register_with_agent_space()

        self._wire_observability()
        self._emit_outputs()

    # --- Lambda -------------------------------------------------------------

    def _build_log_group(self) -> logs.LogGroup:
        """Create the log group explicitly, so retention is a deliberate choice.

        Letting Lambda create its own log group means retention defaults to never
        expire. For logs carrying PRTG hostnames and IP addresses that is both a
        slow cost leak and an unanswered data-retention question.
        """
        return logs.LogGroup(
            self,
            "ToolFunctionLogs",
            log_group_name=f"/aws/lambda/{self.config.resource_name('mcp-tools')}",
            retention=retention_for(self.config.observability.log_retention_days),
            # DESTROY so a torn-down sample does not leave orphaned log groups
            # behind. Change to RETAIN if these logs are needed for audit.
            removal_policy=RemovalPolicy.DESTROY,
        )

    def _build_tool_function(self) -> lambda_.Function:
        """The function serving the PRTG tools."""
        lambda_config = self.config.mcp_lambda

        role = iam.Role(
            self,
            "ToolFunctionRole",
            # Named, because a cross-account secret's resource policy has to name
            # this principal and the operator applies that policy by hand. A
            # generated name would change on replacement and silently break it.
            role_name=self.config.resource_name("mcp-lambda-role"),
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="PRTG MCP tool function. Reads the PRTG credential and calls PRTG read APIs.",
        )

        # Scoped to this function's log group, rather than the AWS managed
        # AWSLambdaBasicExecutionRole which grants logs:* on all log groups.
        self.log_group.grant_write(role)

        # The function is always VPC-attached, so it always needs ENI management.
        # Granted here rather than via the AWS managed
        # AWSLambdaVPCAccessExecutionRole, which also carries logs:* on every log
        # group in the account.
        #
        # These EC2 actions do not support resource-level permissions, so "*" is
        # unavoidable; the region condition is the available narrowing.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="ManageVpcNetworkInterfaces",
                actions=[
                    "ec2:CreateNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DeleteNetworkInterface",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses",
                ],
                resources=["*"],
                conditions={"StringEquals": {"aws:RequestedRegion": self.region}},
            )
        )

        self.secret.grant_read(role)

        function = lambda_.Function(
            self,
            "ToolFunction",
            function_name=self.config.resource_name("mcp-tools"),
            runtime=LAMBDA_RUNTIME,
            # Real source files from the repository, not inline code, so the
            # handler stays diffable and reviewable like any other module.
            code=lambda_.Code.from_asset(str(_SRC)),
            handler="prtg_mcp.handler.handler",
            role=role,
            memory_size=lambda_config.memory_mb,
            timeout=Duration.seconds(lambda_config.timeout_seconds),
            vpc=self.network.vpc,
            vpc_subnets=self.network.subnet_selection,
            security_groups=[self.network.lambda_security_group],
            log_group=self.log_group,
            environment=self._function_environment(),
            reserved_concurrent_executions=lambda_config.reserved_concurrency,
            tracing=lambda_.Tracing.ACTIVE if self.config.observability.tracing else lambda_.Tracing.DISABLED,
            description=(
                "Serves read-only PRTG tools to AWS DevOps Agent via AgentCore Gateway. "
                f"Tools: {', '.join(prtg_tools.tool_names())}"
            ),
        )

        if lambda_config.provisioned_concurrency:
            # Provisioned concurrency needs a version or alias to attach to; the
            # unqualified function cannot carry it.
            alias = lambda_.Alias(
                self,
                "ToolFunctionLive",
                alias_name="live",
                version=function.current_version,
                provisioned_concurrent_executions=lambda_config.provisioned_concurrency,
            )
            self._invoke_target: lambda_.IFunction = alias
        else:
            self._invoke_target = function

        return function

    def _function_environment(self) -> dict[str, str]:
        """Environment for the tool function.

        No credential appears here. Environment variables are visible to anyone
        with ``lambda:GetFunctionConfiguration`` and are stored in the template, so
        they carry the secret's ARN and never its contents.
        """
        prtg = self.config.prtg
        return {
            **self.secret.environment,
            "PRTG_VERIFY_TLS": "true" if prtg.verify_tls else "false",
            "PRTG_CONNECT_TIMEOUT_SECONDS": str(prtg.connect_timeout_seconds),
            "PRTG_READ_TIMEOUT_SECONDS": str(prtg.read_timeout_seconds),
            "PRTG_MAX_RETRIES": str(prtg.max_retries),
            "LOG_LEVEL": "INFO",
            # Keeps the boto3 client from paying for a full credential-chain walk
            # on cold start.
            "AWS_STS_REGIONAL_ENDPOINTS": "regional",
        }

    # --- Gateway ------------------------------------------------------------

    def _build_gateway(self) -> agentcore.Gateway:
        """Create the Gateway with the configured inbound authorizer."""
        gateway_role = iam.Role(
            self,
            "GatewayRole",
            role_name=self.config.resource_name("gateway-role"),
            # Constrained to this account, so the service cannot be induced to assume
            # this role on another account's behalf -- the confused-deputy problem. Same
            # treatment the invoker role below gets.
            #
            # This previously passed `external_ids=None` with a comment claiming exactly
            # this protection. `None` is the parameter's default and applies no condition
            # at all, so the guard described here did not exist. A comment asserting an
            # absent control is worse than no comment, because it stops anyone looking --
            # and nothing asserted it either way, so it stood for as long as it did.
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com").with_conditions(
                {"StringEquals": {"aws:SourceAccount": self.account}}
            ),
            description="AgentCore Gateway role. Invokes the PRTG tool function.",
        )

        return agentcore.Gateway(
            self,
            "Gateway",
            gateway_name=self.config.resource_name("gw"),
            role=gateway_role,
            authorizer_configuration=self._build_authorizer(),
            description="Read-only PRTG Network Monitor tools for AWS DevOps Agent.",
            protocol_configuration=agentcore.McpProtocolConfiguration(
                supported_versions=[
                    agentcore.MCPProtocolVersion.MCP_2025_06_18,
                    agentcore.MCPProtocolVersion.MCP_2025_03_26,
                ],
                search_type=agentcore.McpGatewaySearchType.SEMANTIC,
                # Read by the agent when it discovers the toolset, so it is written
                # to steer tool choice rather than merely describe the server.
                instructions=(
                    "Read-only access to PRTG Network Monitor, which monitors on-premises and "
                    "cloud infrastructure. Use these tools during an investigation to correlate "
                    "PRTG's view of a host with AWS telemetry. Start with get_server_status to see "
                    "whether a problem is widespread, or search to turn a hostname from an alert "
                    "into the PRTG object IDs the other tools take. get_sensor_history establishes "
                    "when a problem began. All tools are read-only; none can change PRTG state."
                ),
            ),
            tags=dict(self.config.tags) or None,
        )

    def _build_authorizer(self) -> agentcore.IGatewayAuthorizerConfig:
        """Build the inbound authorizer for the configured auth mode.

        ``sigv4`` and the three ``oidc`` providers are the two branches. Note that
        Cognito is the only provider that creates infrastructure; ``entra`` and
        ``generic`` are configuration alone, which is why the reference material's
        separate Entra ID and "other OIDC" scenarios collapse into one code path.
        """
        auth = self.config.auth

        if auth.mode == "sigv4":
            return agentcore.GatewayAuthorizer.using_aws_iam()

        if auth.provider == "cognito":
            user_pool = cognito.UserPool(
                self,
                "UserPool",
                user_pool_name=self.config.resource_name("gateway-pool"),
                # Machine-to-machine only. The caller is the DevOps Agent service,
                # not a person, so there are no users, no sign-in flow, and no
                # password reset. Self-signup is disabled because an open pool here
                # would be pure attack surface with no purpose.
                #
                # Cognito threat protection is deliberately not enabled: it defends
                # user authentication flows against credential stuffing and
                # compromised passwords, none of which exist in a client-credentials
                # pool with zero users. Enabling it would also require the Plus
                # feature plan and its cost.
                self_sign_up_enabled=False,
                removal_policy=RemovalPolicy.DESTROY,
            )
            self._user_pool = user_pool

            scope = cognito.ResourceServerScope(
                scope_name=auth.cognito_scope_name,
                scope_description="Invoke PRTG MCP tools",
            )
            resource_server = user_pool.add_resource_server(
                "ResourceServer",
                identifier=auth.cognito_resource_server_id,
                scopes=[scope],
            )

            client = user_pool.add_client(
                "GatewayClient",
                user_pool_client_name=self.config.resource_name("agent-client"),
                generate_secret=True,
                o_auth=cognito.OAuthSettings(
                    flows=cognito.OAuthFlows(client_credentials=True),
                    scopes=[cognito.OAuthScope.resource_server(resource_server, scope)],
                ),
                # Short-lived by design: a leaked bearer token stays valid until it
                # expires, and revoking it at the provider does not invalidate it at
                # the Gateway.
                access_token_validity=Duration.hours(1),
            )

            # Cognito domain prefixes share a GLOBAL namespace across all AWS
            # accounts, so this default can collide with a stranger's and there is no
            # way to check beforehand. auth.cognito_domain_prefix overrides it.
            domain_prefix = auth.cognito_domain_prefix or (f"{self.config.name_prefix}-{self.account[:8]}")
            user_pool.add_domain(
                "GatewayDomain",
                cognito_domain=cognito.CognitoDomainOptions(domain_prefix=domain_prefix),
            )

            self._cognito_client = client
            # Retained so the token endpoint can be derived for the stack outputs.
            #
            # Gateway.token_endpoint_url is only populated when the Gateway creates
            # its own Cognito pool. Supplying an explicit authorizer - which is what
            # gives control over scopes, audiences and token lifetime - leaves it
            # None, so the output read "(not available)". The token endpoint is one of
            # three values needed to register the MCP server, so it has to be
            # constructed here instead.
            self._cognito_token_endpoint = (
                f"https://{domain_prefix}.auth.{self.region}.amazoncognito.com/oauth2/token"
            )
            return agentcore.GatewayAuthorizer.using_cognito(
                user_pool=user_pool,
                allowed_clients=[client],
                allowed_audiences=list(auth.allowed_audience) or None,
                allowed_scopes=[f"{auth.cognito_resource_server_id}/{auth.cognito_scope_name}"],
            )

        # entra / generic: the provider already exists, so nothing is created.
        #
        # `or None` on every optional list is load-bearing. An empty Python list is
        # rendered as `AllowedAudience: []`, and CloudFormation rejects that with
        # "expected minimum item count: 1" rather than treating it as absent. Passing
        # None omits the property, which is what "no audience restriction" means.
        #
        # This matters because omitting the audience is the *correct* configuration
        # for a provider that does not emit an `aud` claim in client-credentials
        # tokens - Amazon Cognito, for one. See AuthConfig.allowed_audience.
        return agentcore.GatewayAuthorizer.using_custom_jwt(
            discovery_url=auth.discovery_url,  # type: ignore[arg-type]
            allowed_audience=list(auth.allowed_audience) or None,
            allowed_clients=list(auth.allowed_clients) or None,
            allowed_scopes=list(auth.allowed_scopes) or None,
        )

    def _add_tool_target(self) -> None:
        """Attach the Lambda as a Gateway target, with the generated tool schema."""
        schema = agentcore.ToolSchema.from_local_asset(str(write_tool_schema()))

        self.target = self.gateway.add_lambda_target(
            "PrtgTools",
            gateway_target_name=GATEWAY_TARGET_NAME,
            lambda_function=self._invoke_target,
            tool_schema=schema,
            description=f"{len(prtg_tools.TOOL_SPECS)} read-only PRTG tools.",
            credential_provider_configurations=[agentcore.GatewayCredentialProvider.from_iam_role()],
        )

        # Scoped to this one function ARN. The security review's analysis of a
        # compromised Gateway account turns on this: a wildcard here would let an
        # attacker who reached the Gateway role invoke any function in the account.
        self._invoke_target.grant_invoke(self.gateway.role)  # type: ignore[arg-type]

    # --- DevOps Agent registration ------------------------------------------

    def _register_with_agent_space(self) -> None:
        """Register the Gateway as a capability provider, if the config asks for it.

        Optional because registration is account-level: a second deployment in the
        same account would collide with the existing registration, and many teams
        register once through the console and manage Agent Spaces separately.

        The tool names are derived from the same target name given to the Gateway, so
        the allowlist cannot drift from what the Gateway actually exposes. Getting this
        wrong is quiet rather than loud -- the Gateway prefixes every tool with the
        target name, so an allowlist of bare names matches nothing and the agent simply
        has no tools.
        """
        if not self.config.targeting.register_with_agent_space:
            return

        assert self.invoker_role is not None  # noqa: S101 - validated as sigv4-only
        assert self.config.targeting.agent_space_id is not None  # noqa: S101

        self.registration = AgentRegistration(
            self,
            "AgentRegistration",
            gateway_url=self.gateway.gateway_url,
            invoker_role_arn=self.invoker_role.role_arn,
            agent_space_id=self.config.targeting.agent_space_id,
            target_name=GATEWAY_TARGET_NAME,
            tool_names=list(prtg_tools.tool_names()),
            region=self.region,
            # name_prefix, not resource_name: the latter would prepend the prefix to a
            # name that already is the prefix, giving "prtg-mcp-prtg-mcp" in the console.
            service_name=self.config.name_prefix,
        )

    # --- Caller access ------------------------------------------------------

    def _build_invoker_role(self) -> iam.Role | None:
        """Role the DevOps Agent assumes to call the Gateway (SigV4 only).

        With an OIDC authorizer the agent presents a bearer token instead, so no
        role is needed.
        """
        if self.config.auth.mode != "sigv4":
            return None

        # Service principals are constrained to this account. Without the condition,
        # the AWS service could in principle be induced to assume this role on
        # another account's behalf - the confused-deputy problem. Applying it via
        # with_conditions puts it in the trust policy declaratively.
        same_account = {"StringEquals": {"aws:SourceAccount": self.account}}

        principals: list[iam.IPrincipal] = [
            iam.ServicePrincipal("aidevops.amazonaws.com").with_conditions(same_account),
            iam.ServicePrincipal("bedrock-agentcore.amazonaws.com").with_conditions(same_account),
        ]
        # Extra principals are explicit ARNs supplied by the operator, typically a
        # cross-account role. They are already specific, so no source-account
        # condition applies.
        principals.extend(iam.ArnPrincipal(arn) for arn in self.config.auth.additional_invoker_principals)

        role = iam.Role(
            self,
            "InvokerRole",
            role_name=self.config.resource_name("agent-invoker-role"),
            assumed_by=iam.CompositePrincipal(*principals),
            description="Assumed by AWS DevOps Agent to invoke the PRTG MCP Gateway.",
            # Bounds the replay window if the session credential leaks.
            max_session_duration=Duration.hours(1),
        )

        # Scoped to this Gateway's ARN. The reference granted
        # `bedrock-agentcore:*` on a wildcard ARN prefix.
        self.gateway.grant_invoke(role)

        return role

    # --- Observability ------------------------------------------------------

    def _wire_observability(self) -> None:
        self.observability.watch_mcp_lambda(self.tool_function, self.log_group)
        self.observability.watch_gateway(
            {
                "invocations": self.gateway.metric_invocations(),
                "system_errors": self.gateway.metric_system_errors(),
                "user_errors": self.gateway.metric_user_errors(),
                "throttles": self.gateway.metric_throttles(),
                "latency": self.gateway.metric_latency(),
            }
        )

    # --- Outputs ------------------------------------------------------------

    def _client_secret_command(self) -> str:
        """CLI command that prints the Cognito client secret."""
        return (
            "aws cognito-idp describe-user-pool-client "
            f"--user-pool-id {self._user_pool.user_pool_id} "
            f"--client-id {self._cognito_client.user_pool_client_id} "
            f"--region {self.region} --query UserPoolClient.ClientSecret --output text"
        )

    def _emit_outputs(self) -> None:
        """Emit exactly what is needed to register the server in DevOps Agent."""
        CfnOutput(
            self,
            "GatewayUrl",
            description="MCP endpoint URL. Register this in DevOps Agent under Capability Providers.",
            value=self.gateway.gateway_url,
        )
        CfnOutput(self, "GatewayArn", description="Gateway ARN.", value=self.gateway.gateway_arn)
        CfnOutput(
            self,
            "ToolFunctionName",
            description="Lambda serving the PRTG tools. Tail its logs to debug a tool call.",
            value=self.tool_function.function_name,
        )

        if self.config.auth.mode == "sigv4":
            assert self.invoker_role is not None  # noqa: S101
            CfnOutput(
                self,
                "RegistrationInstructions",
                description="How to register this MCP server in the AWS DevOps Agent console.",
                value=(
                    "Capability Providers > Register > MCP Server | "
                    f"Endpoint URL: (see GatewayUrl) | Auth Flow: AWS SigV4 | "
                    f"IAM Role: {self.invoker_role.role_name} | Region: {self.region} | "
                    "Service Name: bedrock-agentcore"
                ),
            )
            CfnOutput(
                self,
                "InvokerRoleArn",
                description="IAM role to supply when registering the MCP server.",
                value=self.invoker_role.role_arn,
            )
        else:
            CfnOutput(
                self,
                "RegistrationInstructions",
                description="How to register this MCP server in the AWS DevOps Agent console.",
                value=(
                    "Capability Providers > Register > MCP Server | "
                    "Endpoint URL: (see GatewayUrl) | Auth Flow: OAuth Client Credentials | "
                    "Token endpoint, client ID and scope: from your identity provider "
                    "(see TokenEndpoint / ClientId outputs when using Cognito)"
                ),
            )

        if self.config.auth.mode == "oidc" and self.config.auth.provider == "cognito":
            scope = f"{self.config.auth.cognito_resource_server_id}/{self.config.auth.cognito_scope_name}"
            CfnOutput(
                self,
                "TokenEndpoint",
                description=(
                    "OAuth2 token endpoint for the client-credentials flow. Supply this, the "
                    "client ID, the client secret and the scope when registering the MCP server."
                ),
                # Derived rather than read from gateway.token_endpoint_url, which is
                # only populated for a Gateway-managed Cognito pool.
                value=self._cognito_token_endpoint,
            )
            CfnOutput(
                self,
                "OAuthScope",
                description="Scope to request when fetching a token.",
                value=scope,
            )
            CfnOutput(
                self,
                "TokenTestCommand",
                description="Verify the OAuth flow before registering the MCP server.",
                value=(
                    f"SECRET=$({self._client_secret_command()}) && "
                    f"curl -s -X POST {self._cognito_token_endpoint} "
                    "-H 'Content-Type: application/x-www-form-urlencoded' "
                    f"-u {self._cognito_client.user_pool_client_id}:$SECRET "
                    f"-d 'grant_type=client_credentials&scope={scope}'"
                ),
            )
            CfnOutput(
                self,
                "ClientId",
                description="Cognito app client ID for DevOps Agent registration.",
                value=self._cognito_client.user_pool_client_id,
            )
            CfnOutput(
                self,
                "ClientSecretCommand",
                description=(
                    "Retrieve the client secret. Deliberately not emitted as an output, because "
                    "stack outputs are readable by anyone with describe-stacks."
                ),
                value=self._client_secret_command(),
            )

        CfnOutput(
            self,
            "ToolCount",
            description="Number of read-only PRTG tools exposed.",
            value=str(len(prtg_tools.TOOL_SPECS)),
        )
