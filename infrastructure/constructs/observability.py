"""Alarms, dashboard, and the notification topic.

Recommended CloudWatch alarms for an integration like this are usually published as
a table and left to the reader to create. An alarm that exists only in a table is an
alarm nobody has, so they are code here.

What is alarmed on is chosen around one question: *how would we find out this
integration had quietly stopped working?* It is a read-only monitoring
integration, so nothing breaks loudly when it fails. The agent simply stops
getting PRTG context and carries on investigating with less information, which is
strictly worse than an outage because nobody notices. Every alarm below detects a
specific way that happens:

* **Auth failures** - a rotated passhash that was never written to the secret.
  Detected by a log metric filter, because PRTG returns 401 and the Lambda then
  succeeds at returning a structured error, so no Lambda error metric fires.
* **Function errors** - a bug, a missing VPC endpoint, an IAM gap.
* **Throttling** - reserved concurrency reached, so tool calls are being dropped.
* **Gateway 5xx** - the Gateway cannot reach the target at all.
* **Duration approaching timeout** - PRTG slowing down before it starts failing.
* **Alarm-pipeline failures** - investigations are not being created from alarms.
* **Routing failures** (fan-out only) - an alarm matched no route, so it went
  nowhere.
"""

from __future__ import annotations

from aws_cdk import Duration, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions

from constructs import Construct
from infrastructure.config import PrtgMcpConfig

#: Namespace for metrics derived from log patterns.
METRIC_NAMESPACE = "PrtgMcpDevOpsAgent"


class Observability(Construct):
    """Notification topic, alarms, and an optional dashboard.

    Built incrementally: the stacks call ``watch_mcp_lambda``,
    ``watch_gateway`` and so on as they create the resources, then
    ``finalise`` renders the dashboard.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: PrtgMcpConfig,
        alarm_topic: sns.ITopic | None,
        dashboard_name: str,
    ) -> None:
        """
        Args:
            config: The deployment configuration.
            alarm_topic: Destination for alarm notifications, owned by the shared
                stack so both halves notify the same place and no name collides.
                ``None`` when no destination was configured.
            dashboard_name: Must be unique per stack. Dashboard names are physical
                names, so two stacks using the same one fail deployment with
                "already exists" - a collision that only appears when the second
                stack is deployed.
        """
        super().__init__(scope, construct_id)
        self.config = config
        self.topic = alarm_topic
        self.dashboard_name = dashboard_name
        self.alarms: list[cloudwatch.Alarm] = []
        self._widgets: list[cloudwatch.IWidget] = []

    # --- Notification topic -------------------------------------------------

    @staticmethod
    def resolve_topic(scope: Construct, config: PrtgMcpConfig) -> sns.ITopic | None:
        """Import or create the alarm topic. Called once, by the shared stack.

        Static because the topic is shared across both halves: creating it inside
        each stack's Observability construct would collide on the topic name and
        would also split notifications across two topics.
        """
        observability = config.observability

        if observability.alarm_topic_arn:
            return sns.Topic.from_topic_arn(scope, "AlarmTopic", observability.alarm_topic_arn)

        if observability.alarm_email:
            topic = sns.Topic(
                scope,
                "AlarmTopic",
                topic_name=config.resource_name("alarms"),
                display_name="PRTG MCP integration alarms",
                # SNS is encrypted with the AWS managed key by default here. A
                # customer-managed key would need a key policy allowing
                # cloudwatch.amazonaws.com to publish, which is more moving parts
                # than an alarm notification warrants.
                enforce_ssl=True,
            )
            topic.add_subscription(subscriptions.EmailSubscription(observability.alarm_email))
            return topic

        # Config already warns that alarms will notify nobody.
        return None

    def _alarm(
        self,
        construct_id: str,
        *,
        metric: cloudwatch.IMetric,
        threshold: float,
        evaluation_periods: int,
        alarm_description: str,
        comparison_operator: cloudwatch.ComparisonOperator = (
            cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        ),
        treat_missing_data: cloudwatch.TreatMissingData = cloudwatch.TreatMissingData.NOT_BREACHING,
    ) -> cloudwatch.Alarm:
        """Create an alarm and wire it to the topic."""
        alarm = cloudwatch.Alarm(
            self,
            construct_id,
            metric=metric,
            threshold=threshold,
            evaluation_periods=evaluation_periods,
            comparison_operator=comparison_operator,
            treat_missing_data=treat_missing_data,
            alarm_name=self.config.resource_name(_kebab(construct_id)),
            # The description is what an on-call engineer reads first, so it says
            # what has broken and what to do, not just which threshold tripped.
            alarm_description=alarm_description,
        )
        if self.topic is not None:
            alarm.add_alarm_action(cw_actions.SnsAction(self.topic))
        self.alarms.append(alarm)
        return alarm

    # --- MCP server ---------------------------------------------------------

    def watch_mcp_lambda(self, function: lambda_.IFunction, log_group: logs.ILogGroup) -> None:
        """Alarm on the PRTG tool function."""
        timeout = self.config.mcp_lambda.timeout_seconds

        self._alarm(
            "McpLambdaErrors",
            metric=function.metric_errors(period=Duration.minutes(5)),
            threshold=3,
            evaluation_periods=1,
            alarm_description=(
                "The PRTG MCP tool function is failing. The agent is investigating without PRTG "
                "data. Check its CloudWatch logs: the most common causes are an unpopulated or "
                "rotated credential secret, a missing VPC endpoint in a fully-private deployment, "
                "and no network route to PRTG."
            ),
        )

        self._alarm(
            "McpLambdaThrottles",
            metric=function.metric_throttles(period=Duration.minutes(5)),
            threshold=1,
            evaluation_periods=1,
            alarm_description=(
                "PRTG tool calls are being throttled, so the agent is losing data mid-"
                "investigation. Reserved concurrency has been reached. Either raise "
                "mcp_lambda.reserved_concurrency or find out why call volume is unexpectedly high - "
                "an agent retry loop is the usual reason."
            ),
        )

        self._alarm(
            "McpLambdaDurationApproachingTimeout",
            metric=function.metric_duration(period=Duration.minutes(5), statistic="p95"),
            # 80% of the configured timeout. Catches PRTG getting slower before
            # calls actually start timing out, which is the point at which there is
            # still time to act.
            threshold=timeout * 1000 * 0.8,
            evaluation_periods=2,
            alarm_description=(
                f"PRTG tool calls are taking over 80% of the {timeout}s timeout at p95. PRTG is "
                "likely under load or the network path has degraded. Left alone this becomes "
                "timeouts and lost investigation context."
            ),
        )

        # PRTG returning 401 is not a Lambda error: the function correctly returns
        # a structured MCP error, so metric_errors stays flat. Without this filter
        # a stale credential is invisible until somebody reads an investigation and
        # wonders why it has no PRTG data.
        auth_metric = self._log_metric(
            log_group,
            construct_id="PrtgAuthFailureFilter",
            metric_name="PrtgAuthFailures",
            pattern=logs.FilterPattern.literal('{ $.event = "prtg_auth_failed" }'),
        )
        self._alarm(
            "PrtgAuthFailures",
            metric=auth_metric,
            threshold=1,
            evaluation_periods=1,
            alarm_description=(
                "PRTG is rejecting the stored credential. This does NOT show up as a Lambda error, "
                "so it is invisible without this alarm. Usually the credential was rotated and the "
                "secret was not updated, or the PRTG user was disabled. Check the credentials_loaded "
                "log event for which form is in use. For an API key, confirm it still exists under "
                "Setup, Account Settings, API Keys; a deleted key cannot be recovered and must be "
                "replaced. For a passhash, regenerate it at /api/getpasshash.htm. Then write the new "
                "value to the secret."
            ),
        )

        insecure_metric = self._log_metric(
            log_group,
            construct_id="InsecureRequestFilter",
            metric_name="PrtgInsecureRequests",
            pattern=logs.FilterPattern.literal('{ $.event = "insecure_request" }'),
        )
        self._alarm(
            "PrtgTlsVerificationDisabled",
            metric=insecure_metric,
            threshold=1,
            evaluation_periods=1,
            alarm_description=(
                "PRTG requests are being made with TLS certificate verification disabled. The PRTG "
                "credential travels in the query string, so an intercepted connection exposes it. "
                "Set prtg.verify_tls to true and supply secret.ca_bundle_secret_arn with PRTG's "
                "certificate."
            ),
        )

        self._widgets.append(
            cloudwatch.GraphWidget(
                title="PRTG MCP tools - invocations and errors",
                left=[function.metric_invocations(), function.metric_errors()],
                right=[function.metric_duration(statistic="p95")],
                width=12,
            )
        )
        self._widgets.append(
            cloudwatch.GraphWidget(
                title="PRTG health signals",
                left=[auth_metric, insecure_metric],
                width=12,
            )
        )

    def watch_gateway(self, gateway_metrics: dict[str, cloudwatch.IMetric]) -> None:
        """Alarm on the AgentCore Gateway.

        Args:
            gateway_metrics: Named metrics from the Gateway L2 construct. Passed in
                rather than derived here so this construct does not need to import
                the Gateway type.
        """
        if "system_errors" in gateway_metrics:
            self._alarm(
                "GatewaySystemErrors",
                metric=gateway_metrics["system_errors"],
                threshold=3,
                evaluation_periods=1,
                alarm_description=(
                    "The AgentCore Gateway is returning 5xx. It cannot reach the PRTG tool function. "
                    "Check that the Gateway role still holds lambda:InvokeFunction on the function, "
                    "and that the Lambda resource policy still allows the Gateway."
                ),
            )

        if "throttles" in gateway_metrics:
            self._alarm(
                "GatewayThrottles",
                metric=gateway_metrics["throttles"],
                threshold=5,
                evaluation_periods=1,
                alarm_description=(
                    "The AgentCore Gateway is throttling tool calls (429), so the agent is losing "
                    "PRTG context during investigations."
                ),
            )

        widgets = [
            m for k, m in gateway_metrics.items() if k in ("invocations", "system_errors", "user_errors")
        ]
        if widgets:
            self._widgets.append(
                cloudwatch.GraphWidget(
                    title="AgentCore Gateway - traffic and errors",
                    left=widgets,
                    right=[gateway_metrics["latency"]] if "latency" in gateway_metrics else None,
                    width=12,
                )
            )

    # --- Alarm pipeline -----------------------------------------------------

    def watch_pipeline_lambda(
        self,
        function: lambda_.IFunction,
        log_group: logs.ILogGroup,
        *,
        fanout: bool,
    ) -> None:
        """Alarm on the alarm-ingestion function."""
        self._alarm(
            "PipelineLambdaErrors",
            metric=function.metric_errors(period=Duration.minutes(5)),
            threshold=1,
            # Threshold of 1, unlike the MCP function's 3. A failure here means a
            # PRTG alarm produced no investigation at all, which is a missed
            # incident rather than a degraded one.
            evaluation_periods=1,
            alarm_description=(
                "The alarm pipeline is failing, so PRTG alarms are NOT creating investigations. "
                "Every failure here is a potentially missed incident. Find the cause in the "
                "function logs by correlation ID, fix it, then redrive the dead-letter queue. "
                "Check PrtgAlarmsLost before assuming the queue holds them: a handled failure is "
                "parked there, but a timeout kills the process before it can park anything, so "
                "this alarm firing does not by itself mean the alarms were preserved."
            ),
        )

        self._alarm(
            "PipelineLambdaThrottles",
            metric=function.metric_throttles(period=Duration.minutes(5)),
            threshold=1,
            evaluation_periods=1,
            alarm_description=(
                "Alarm pipeline invocations are being throttled, so PRTG alarms are being dropped. "
                "An alarm storm is the usual cause. Raise pipeline_lambda.reserved_concurrency."
            ),
        )

        if fanout:
            routing_metric = self._log_metric(
                log_group,
                construct_id="RoutingFailureFilter",
                metric_name="PrtgRoutingFailures",
                pattern=logs.FilterPattern.literal('{ $.event = "routing_failed" }'),
            )
            self._alarm(
                "PrtgRoutingFailures",
                metric=routing_metric,
                threshold=1,
                evaluation_periods=1,
                alarm_description=(
                    "A PRTG alarm matched no route and no DEFAULT route could be applied, so it "
                    "reached no Agent Space at all. Check that the PRTG group or probe name matches "
                    "a routing entry exactly - matching is case-sensitive."
                ),
            )
            self._widgets.append(
                cloudwatch.GraphWidget(title="Alarm routing failures", left=[routing_metric], width=12)
            )

        # Alarmed separately from the queue depth. The queue metric says an alarm is
        # waiting; this one says the attempt to preserve it failed, which is the only
        # case in the pipeline where a PRTG alarm is genuinely gone. It must not be
        # inferred from the absence of queue messages, which looks identical to
        # nothing having gone wrong.
        park_failed_metric = self._log_metric(
            log_group,
            construct_id="ParkFailedFilter",
            metric_name="PrtgAlarmsLost",
            pattern=logs.FilterPattern.literal('{ $.event = "alarm_park_failed" }'),
        )
        self._alarm(
            "PrtgAlarmsLost",
            metric=park_failed_metric,
            threshold=1,
            evaluation_periods=1,
            alarm_description=(
                "A PRTG alarm could not be processed AND could not be written to the dead-letter "
                "queue, so it is lost -- no investigation, no replay. Check the function's SendMessage "
                "permission on the queue, that ALARM_DLQ_URL is set, and for network.mode private "
                "that the SQS interface endpoint exists."
            ),
        )

        parked_metric = self._log_metric(
            log_group,
            construct_id="ParkedFilter",
            metric_name="PrtgAlarmsParked",
            pattern=logs.FilterPattern.literal('{ $.event = "alarm_parked" }'),
        )

        deduped_metric = self._log_metric(
            log_group,
            construct_id="DeduplicatedFilter",
            metric_name="PrtgAlarmsDeduplicated",
            pattern=logs.FilterPattern.literal('{ $.event = "duplicate_suppressed" }'),
        )

        self._widgets.append(
            cloudwatch.GraphWidget(
                title="Alarm pipeline - invocations, errors, parked, lost, duplicates suppressed",
                left=[
                    function.metric_invocations(),
                    function.metric_errors(),
                    parked_metric,
                    park_failed_metric,
                    deduped_metric,
                ],
                width=12,
            )
        )

    def watch_dead_letter_queue(self, queue_metric: cloudwatch.IMetric) -> None:
        """Alarm when a PRTG alarm has been parked on the dead-letter queue.

        Messages arrive because the function put them there explicitly, not through
        Lambda's asynchronous retry path -- which cannot fire behind a synchronous
        API Gateway invocation. See ``_park_alarm`` in the pipeline handler.
        """
        self._alarm(
            "PipelineDeadLetterMessages",
            metric=queue_metric,
            threshold=1,
            evaluation_periods=1,
            alarm_description=(
                "A PRTG alarm reached no Agent Space and is parked on the dead-letter queue, so no "
                "investigation exists for it. Each message carries the reason, the correlation ID "
                "for the failing invocation, and the original notification. Fix the cause, then "
                "redrive the queue."
            ),
        )

    def watch_api(self, api_metrics: dict[str, cloudwatch.IMetric]) -> None:
        """Alarm on the alarm-ingestion REST API."""
        if "client_error" in api_metrics:
            self._alarm(
                "ApiClientErrors",
                metric=api_metrics["client_error"],
                threshold=5,
                evaluation_periods=1,
                alarm_description=(
                    "The alarm API is returning 4xx. Most often PRTG's source address is not in "
                    "alarm_allowed_source_ips (403), or the notification URL is wrong (404 presented "
                    "as 403 'Missing Authentication Token'). Verify the URL includes the stage and "
                    "path, and that the method is POST."
                ),
            )

        if "server_error" in api_metrics:
            self._alarm(
                "ApiServerErrors",
                metric=api_metrics["server_error"],
                threshold=1,
                evaluation_periods=1,
                alarm_description=(
                    "The alarm API is returning 5xx, so PRTG alarms are not reaching the pipeline."
                ),
            )

        graph = [m for k, m in api_metrics.items() if k in ("count", "client_error", "server_error")]
        if graph:
            self._widgets.append(
                cloudwatch.GraphWidget(title="Alarm API - requests and errors", left=graph, width=12)
            )

    # --- Helpers ------------------------------------------------------------

    def _log_metric(
        self,
        log_group: logs.ILogGroup,
        *,
        construct_id: str,
        metric_name: str,
        pattern: logs.IFilterPattern,
    ) -> cloudwatch.Metric:
        """Create a metric filter and return its metric.

        The handlers log structured JSON with a stable ``event`` field precisely so
        these filters can be exact rather than substring matches on prose. Matching
        on message text would break the first time somebody rewords a log line.
        """
        metric_filter = logs.MetricFilter(
            self,
            construct_id,
            log_group=log_group,
            filter_pattern=pattern,
            metric_namespace=METRIC_NAMESPACE,
            metric_name=metric_name,
            metric_value="1",
            default_value=0,
        )
        return metric_filter.metric(statistic="Sum", period=Duration.minutes(5))

    def finalise(self) -> cloudwatch.Dashboard | None:
        """Render the dashboard. Call after every ``watch_*``."""
        if not self.config.observability.dashboard or not self._widgets:
            return None

        dashboard = cloudwatch.Dashboard(
            self,
            "Dashboard",
            dashboard_name=self.dashboard_name,
            default_interval=Duration.hours(3),
        )

        stack = Stack.of(self)
        dashboard.add_widgets(
            cloudwatch.TextWidget(
                markdown=(
                    f"# PRTG ↔ AWS DevOps Agent integration\n\n"
                    f"**Region** {stack.region} | **Deployment** `{self.config.name_prefix}` | "
                    f"**Network** `{self.config.network.mode}` | "
                    f"**Gateway auth** `{self.config.auth.mode}` | "
                    f"**Targeting** `{self.config.targeting.mode}`\n\n"
                    "Two independent paths, and they fail independently:\n\n"
                    "- **PRTG → agent** (alarm pipeline). Failures here mean investigations are "
                    "never created - a missed incident.\n"
                    "- **agent → PRTG** (MCP tools). Failures here mean investigations run with "
                    "less context - a quieter, easier-to-miss problem."
                ),
                width=24,
                height=4,
            )
        )
        for widget in self._widgets:
            dashboard.add_widgets(widget)

        return dashboard


def _kebab(value: str) -> str:
    """``McpLambdaErrors`` -> ``mcp-lambda-errors``."""
    out: list[str] = []
    for index, char in enumerate(value):
        if char.isupper() and index > 0:
            out.append("-")
        out.append(char.lower())
    return "".join(out)
