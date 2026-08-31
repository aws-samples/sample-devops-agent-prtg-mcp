"""Alarm pipeline stack: the PRTG → agent direction.

    PRTG ──(HTTPS)──► API Gateway ──► Lambda ──► aidevops:CreateBacklogTask

Design notes worth reading before changing this.

**Access control is by source address, and that is not laziness.** PRTG's
"Execute HTTP Action" cannot send custom headers, so an API key, a bearer token and
a signed request are all unavailable. The options are a source-address allowlist on
a regional API or a private API reachable only through a VPC endpoint. Both are
supported; ``alarm_api_private`` chooses. Leaving the endpoint open is not an
option the configuration permits, because anyone who found the URL could create
investigations in the Agent Space.

**REST API rather than HTTP API.** HTTP APIs are cheaper and faster, but they do not
support resource policies, which is the mechanism that enforces both the address
allowlist and the private-endpoint restriction. At the volume of an alarm webhook
the cost difference is immaterial.

**Failures are preserved, not dropped.** A failure here means an alarm produced no
investigation, so the function writes the alarm to a dead-letter queue for replay
rather than letting it disappear into a log line. Note that the queue is written to
by the function itself, not by Lambda: ``DeadLetterConfig`` and ``retry_attempts``
apply only to asynchronous invocations, and API Gateway is synchronous, so
configuring them here would create a queue nothing could ever reach.
"""

from __future__ import annotations

import sys
from pathlib import Path

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm

from constructs import Construct
from infrastructure.config import PrtgMcpConfig
from infrastructure.constructs.common import retention_for
from infrastructure.constructs.network import PrtgNetwork
from infrastructure.constructs.observability import Observability

_SRC = Path(__file__).resolve().parents[2] / "src"

# The notification payload is the single source of truth shared with the Lambda.
# Importing it here is what guarantees the payload this stack tells an operator to
# paste into PRTG is exactly the set of fields the handler reads. payload.py is
# standard-library only, so this import is safe at synthesis.
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from alarm_pipeline import payload as alarm_payload  # noqa: E402

LAMBDA_RUNTIME = lambda_.Runtime.PYTHON_3_13

#: Path PRTG posts to.
ALARM_PATH = "prtg-alarm"
STAGE_NAME = "prod"


class AlarmPipelineStack(Stack):
    """API Gateway and Lambda that turn PRTG alarms into investigations."""

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
            network: Networking from ``SharedStack``. Required rather than optional -
                see the note in ``SharedStack``.
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
            dashboard_name=f"{config.name_prefix}-alarm-pipeline",
        )

        self.routing_parameter = self._build_routing_parameter()
        self.dead_letter_queue = self._build_dead_letter_queue()
        self.log_group = self._build_log_group()
        self.function = self._build_function()
        self.api = self._build_api()

        self._wire_observability()
        self._emit_outputs()

    # --- Routing table ------------------------------------------------------

    def _build_routing_parameter(self) -> ssm.StringParameter | None:
        """Store the fan-out routing table in SSM.

        An SSM parameter rather than a Lambda environment variable, so a workload
        account can be onboarded by editing one parameter instead of redeploying,
        and so the table is not subject to the 4 KB environment limit.
        """
        if self.config.targeting.mode != "fanout":
            return None

        import json

        return ssm.StringParameter(
            self,
            "RoutingTable",
            parameter_name=f"/{self.config.name_prefix}/routing-table",
            string_value=json.dumps(self.config.targeting.routing_table(), indent=2),
            description=(
                "Maps PRTG group, probe or device prefix to a DevOps Agent Space. Edit to onboard a "
                "workload account; the function picks up changes within ROUTING_TTL_SECONDS with no "
                "deployment."
            ),
            tier=ssm.ParameterTier.STANDARD,
        )

    # --- Reliability --------------------------------------------------------

    def _build_dead_letter_queue(self) -> sqs.Queue:
        """Queue for alarms that reached no Agent Space.

        Without this, an alarm that cannot be processed is lost, and losing an alarm
        means losing an incident. The queue makes the failure both visible and
        replayable.

        Written to by the function, not by Lambda's asynchronous retry machinery --
        see the note in the module docstring. The queue URL reaches the function
        through the ``ALARM_DLQ_URL`` environment variable, and ``SendMessage`` is
        granted in ``_build_function``.
        """
        return sqs.Queue(
            self,
            "DeadLetterQueue",
            queue_name=self.config.resource_name("alarm-dlq"),
            retention_period=Duration.days(14),
            # SSE-SQS rather than a customer-managed key: the payload holds PRTG
            # hostnames and status text, not credentials.
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

    def _build_log_group(self) -> logs.LogGroup:
        return logs.LogGroup(
            self,
            "FunctionLogs",
            log_group_name=f"/aws/lambda/{self.config.resource_name('alarm-pipeline')}",
            retention=retention_for(self.config.observability.log_retention_days),
            removal_policy=RemovalPolicy.DESTROY,
        )

    # --- Lambda -------------------------------------------------------------

    def _build_function(self) -> lambda_.Function:
        lambda_config = self.config.pipeline_lambda
        targeting = self.config.targeting

        role = iam.Role(
            self,
            "FunctionRole",
            role_name=self.config.resource_name("pipeline-lambda-role"),
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Alarm pipeline function. Creates DevOps Agent investigations from PRTG alarms.",
        )
        self.log_group.grant_write(role)

        role.add_to_policy(
            iam.PolicyStatement(
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

        self._grant_investigation_permissions(role)

        if self.routing_parameter is not None:
            self.routing_parameter.grant_read(role)

        self.dead_letter_queue.grant_send_messages(role)

        return lambda_.Function(
            self,
            "Function",
            function_name=self.config.resource_name("alarm-pipeline"),
            runtime=LAMBDA_RUNTIME,
            code=lambda_.Code.from_asset(str(_SRC)),
            handler="alarm_pipeline.handler.handler",
            role=role,
            memory_size=lambda_config.memory_mb,
            timeout=Duration.seconds(lambda_config.timeout_seconds),
            vpc=self.network.vpc,
            vpc_subnets=self.network.subnet_selection,
            security_groups=[self.network.lambda_security_group],
            log_group=self.log_group,
            reserved_concurrent_executions=lambda_config.reserved_concurrency,
            tracing=lambda_.Tracing.ACTIVE if self.config.observability.tracing else lambda_.Tracing.DISABLED,
            # Deliberately NOT dead_letter_queue= / retry_attempts=. Both configure
            # Lambda's *asynchronous* invocation behaviour, and the only caller here is
            # API Gateway's proxy integration, which is synchronous. Setting them
            # produces a queue that can never receive a message and an alarm on that
            # queue that can never fire -- indistinguishable from healthy. The function
            # writes to the queue itself instead; see _park_alarm in the handler, and
            # ALARM_DLQ_URL below.
            environment={
                "AGENT_REGION": self.region,
                "ALARM_DLQ_URL": self.dead_letter_queue.queue_url,
                "DEDUP_WINDOW_MINUTES": str(targeting.deduplication_window_minutes),
                "SKIP_TEST_NOTIFICATIONS": "true",
                "LOG_LEVEL": "INFO",
                # The handler sizes its DevOps Agent retry budget from this, holding back
                # enough of the invocation to park a failure. Passed explicitly because
                # Lambda exposes no environment variable for the configured timeout, and
                # the client is cached across invocations so it cannot be derived from the
                # remaining time on any one call.
                "FUNCTION_TIMEOUT_SECONDS": str(self.config.pipeline_lambda.timeout_seconds),
                # Set only in private mode, where the SDK's default hostname has no
                # answer inside the VPC. Absent otherwise, so the SDK resolves its own
                # endpoint and nothing here can drift from it.
                **(
                    {"DEVOPS_ENDPOINT_URL": self.config.agent_endpoint_url}
                    if self.config.agent_endpoint_url
                    else {}
                ),
                **(
                    {
                        "ROUTING_PARAMETER_NAME": self.routing_parameter.parameter_name,
                        "EXTERNAL_ID": targeting.external_id,
                    }
                    if self.routing_parameter is not None
                    else {"AGENT_SPACE_ID": targeting.agent_space_id or ""}
                ),
            },
            description="Creates AWS DevOps Agent investigations from PRTG alarm notifications.",
        )

    def _grant_investigation_permissions(self, role: iam.Role) -> None:
        """Grant task creation, either directly or by assuming a role per account.

        Note the IAM namespace: the SDK client is ``devops-agent`` but the IAM
        service prefix is ``aidevops``, and the resource is an ``agentspace``. The
        mismatch is a documented feature of the service and a reliable source of
        AccessDenied errors when guessed.
        """
        targeting = self.config.targeting

        if targeting.mode == "single":
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="CreateInvestigationInThisAccount",
                    actions=["aidevops:CreateBacklogTask"],
                    resources=[
                        f"arn:{self.partition}:aidevops:{self.region}:{self.account}"
                        f":agentspace/{targeting.agent_space_id}"
                    ],
                )
            )
            return

        # Fan-out: assume a role in each target account. Scoped either to the exact
        # role ARNs, or to the organisation, which is preferable because onboarding a
        # new account then needs no IAM change here.
        if targeting.organization_id:
            # aws:ResourceOrgID, NOT aws:PrincipalOrgID.
            #
            # This is an identity-based policy on the pipeline's own role, so
            # aws:PrincipalOrgID resolves to the organisation of the principal making the
            # request -- which is always this account's own organisation. As a condition it
            # is a tautology: it is satisfied on every call and restricts nothing, leaving
            # the account wildcard in the resource ARN to grant assume-role on that role
            # name in ANY account, inside the organisation or outside it. It also fails
            # open, so a working fan-out deployment demonstrates nothing about it.
            #
            # aws:ResourceOrgID is the organisation of the resource being accessed -- here
            # the role in the target account, which is what needs constraining. AWS
            # documents it as the key that lets a policy "apply to all resources in an
            # organization" so that "when you add and remove accounts, policies ...
            # automatically include the correct accounts", which is exactly the property
            # this branch exists to provide. sts:AssumeRole is not among the actions the
            # key does not support.
            #
            # It fails closed by design: the key is absent unless the resource-owning
            # account belongs to an organisation, and StringEquals against an absent key
            # does not match. A target account outside any organisation is therefore
            # denied rather than silently allowed.
            #
            # The role name is taken from the routes rather than hardcoded. It is
            # configurable per route (FanoutRoute.role_name), so a hardcoded name would
            # produce an AccessDenied at runtime for any route that overrides it, with
            # nothing failing at synthesis.
            role_names = sorted({route.role_name for route in targeting.routes})
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="AssumeInvestigationRoleInOrganisation",
                    actions=["sts:AssumeRole"],
                    resources=[f"arn:{self.partition}:iam::*:role/{name}" for name in role_names],
                    conditions={"StringEquals": {"aws:ResourceOrgID": targeting.organization_id}},
                )
            )
        else:
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="AssumeInvestigationRoles",
                    actions=["sts:AssumeRole"],
                    resources=sorted({route.role_arn() for route in targeting.routes}),
                )
            )

    # --- API ----------------------------------------------------------------

    def _build_api(self) -> apigateway.RestApi:
        """Create the REST API PRTG posts alarms to."""
        private = self.config.alarm_api_private

        access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogs",
            log_group_name=f"/aws/apigateway/{self.config.resource_name('alarm-api')}",
            retention=retention_for(self.config.observability.log_retention_days),
            removal_policy=RemovalPolicy.DESTROY,
        )

        api = apigateway.RestApi(
            self,
            "AlarmApi",
            rest_api_name=self.config.resource_name("alarm-api"),
            description="Receives PRTG alarm notifications and creates DevOps Agent investigations.",
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.PRIVATE if private else apigateway.EndpointType.REGIONAL],
                vpc_endpoints=[self.network.execute_api_endpoint] if private else None,  # type: ignore[list-item]
            ),
            policy=self._resource_policy(),
            deploy_options=apigateway.StageOptions(
                stage_name=STAGE_NAME,
                access_log_destination=apigateway.LogGroupLogDestination(access_log_group),
                # Includes the source IP, so a 403 from an address allowlist can be
                # diagnosed without guessing which address PRTG presented.
                access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
                logging_level=apigateway.MethodLoggingLevel.ERROR,
                metrics_enabled=True,
                # Data tracing logs full request bodies. Off: alarm bodies are not
                # sensitive, but request/response logging at this level is a habit
                # worth not forming.
                data_trace_enabled=False,
                # A bound on how much an alarm storm, or a misconfigured trigger,
                # can cost.
                throttling_rate_limit=50,
                throttling_burst_limit=100,
            ),
            cloud_watch_role=True,
        )

        resource = api.root.add_resource(ALARM_PATH)
        resource.add_method(
            "POST",
            apigateway.LambdaIntegration(self.function, proxy=True),
            # No authorizer: PRTG cannot send credentials. The resource policy is the
            # control. See the module docstring.
            authorization_type=apigateway.AuthorizationType.NONE,
        )

        return api

    def _resource_policy(self) -> iam.PolicyDocument:
        """Build the resource policy that restricts who may post alarms.

        Both branches use an explicit ``Deny``, because an ``Allow``-only policy on
        a REST API is not restrictive: anything not matched simply falls through to
        the API's default behaviour. The Deny is what actually closes the endpoint.
        """
        invoke_resource = "execute-api:/*/POST/" + ALARM_PATH

        if self.config.alarm_api_private:
            endpoint = self.network.execute_api_endpoint
            assert endpoint is not None  # noqa: S101 - guaranteed by config
            return iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        sid="AllowFromVpcEndpoint",
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=[invoke_resource],
                    ),
                    iam.PolicyStatement(
                        sid="DenyFromAnywhereElse",
                        effect=iam.Effect.DENY,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                        conditions={"StringNotEquals": {"aws:SourceVpce": endpoint.vpc_endpoint_id}},
                    ),
                ]
            )

        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    sid="AllowFromPrtgSourceAddresses",
                    effect=iam.Effect.ALLOW,
                    principals=[iam.AnyPrincipal()],
                    actions=["execute-api:Invoke"],
                    resources=[invoke_resource],
                ),
                iam.PolicyStatement(
                    sid="DenyFromAllOtherAddresses",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=["execute-api:Invoke"],
                    resources=["execute-api:/*"],
                    conditions={"NotIpAddress": {"aws:SourceIp": list(self.config.alarm_allowed_source_ips)}},
                ),
            ]
        )

    # --- Observability ------------------------------------------------------

    def _wire_observability(self) -> None:
        self.observability.watch_pipeline_lambda(
            self.function,
            self.log_group,
            fanout=self.config.targeting.mode == "fanout",
        )
        self.observability.watch_dead_letter_queue(
            self.dead_letter_queue.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(5), statistic="Maximum"
            )
        )
        self.observability.watch_api(
            {
                "count": self.api.metric_count(period=Duration.minutes(5)),
                "client_error": self.api.metric_client_error(period=Duration.minutes(5)),
                "server_error": self.api.metric_server_error(period=Duration.minutes(5)),
                "latency": self.api.metric_latency(period=Duration.minutes(5)),
            }
        )

    # --- Outputs ------------------------------------------------------------

    def _emit_outputs(self) -> None:
        webhook_url = f"{self.api.url}{ALARM_PATH}"

        CfnOutput(
            self,
            "PrtgNotificationUrl",
            description="URL for the PRTG HTTP Action notification. Method must be POST.",
            value=webhook_url,
        )

        CfnOutput(
            self,
            "PrtgNotificationPayload",
            description=(
                "Payload for the PRTG notification. MUST be a single line: a line break truncates "
                "the body and the alarm is rejected, even though it looks correct in the PRTG UI. "
                "Placeholders the local PRTG version does not support are treated as absent, so "
                "this can be pasted as-is; only the four core fields decide test detection."
            ),
            value=alarm_payload.payload_template(),
        )

        CfnOutput(
            self,
            "PrtgSniRequirement",
            # ASCII only. CloudFormation replaces non-ASCII characters in an Output's
            # value or description with '?', silently, so an em dash here would reach
            # the operator as a question mark.
            description=(
                "Enable SNI Support in the PRTG notification and set the SNI name to the API host. "
                "Without SNI the TLS handshake completes, the request never arrives, and PRTG still "
                "reports the notification as successful. This is the single most confusing failure "
                "in this integration."
            ),
            value=f"{self.api.rest_api_id}.execute-api.{self.region}.amazonaws.com",
        )

        CfnOutput(
            self,
            "DeadLetterQueueUrl",
            description="Alarms that failed every retry. Inspect and redrive after fixing the cause.",
            value=self.dead_letter_queue.queue_url,
        )

        if self.routing_parameter is not None:
            CfnOutput(
                self,
                "RoutingTableParameter",
                description=(
                    "SSM parameter holding the fan-out routing table. Edit it to onboard a workload "
                    "account; no deployment is needed."
                ),
                value=self.routing_parameter.parameter_name,
            )
            CfnOutput(
                self,
                "WorkloadAccountTrustPolicy",
                description=(
                    "Trust policy for PrtgDevOpsAgentInvestigationRole in each workload account. "
                    "Create that role with this trust policy and an inline policy allowing "
                    "aidevops:CreateBacklogTask on that account's Agent Space."
                ),
                value=(
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":'
                    f'"{self.function.role.role_arn if self.function.role else ""}"'
                    '},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":'
                    f'"{self.config.targeting.external_id}"'
                    "}}}]}"
                ),
            )

        if self.config.alarm_api_private:
            CfnOutput(
                self,
                "PrivateApiNote",
                description="This API is private.",
                # ASCII only; see the note on PrtgSniRequirement above.
                value=(
                    "Reachable only through the execute-api VPC endpoint. Three things must all be "
                    "true. (1) PRTG must be able to route to that endpoint. (2) DNS for the API "
                    "hostname must resolve to it; across VPC peering private DNS does not "
                    "propagate, so create a Route 53 private hosted zone in the PRTG VPC with "
                    "records pointing at the endpoint ENI addresses. (3) The endpoint's security "
                    "group must admit PRTG, and it is built from alarm_allowed_source_ips -- which "
                    "for a private API must hold PRTG's address on the VPC network, not the public "
                    "address it egresses as. Miss (3) and the hostname resolves correctly and the "
                    "connection is then refused, with no HTTP status and nothing in any log, "
                    "because a security group drop is silent."
                ),
            )
