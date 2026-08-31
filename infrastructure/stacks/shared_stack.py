"""Shared infrastructure: the VPC, security groups, endpoints, and alarm topic.

Why this stack exists
---------------------
Both halves of the integration run Lambda functions in a VPC, and both raise
CloudWatch alarms. An earlier arrangement gave each stack its own copy of that
networking, which a real deployment immediately rejected - and the failure was
worth more than the inconvenience, because it exposed two problems:

1. **Name collisions.** Security groups, the flow-log group, the dashboard, and the
   alarm topic all carry fixed physical names derived from ``name_prefix``. The
   second stack to deploy failed with "already exists". Synthesis could not catch
   this: each template was valid in isolation, and nothing compares them.

2. **Duplicated networking, which is worse.** Two VPCs, each with its own NAT
   gateway - roughly USD 64/month instead of 32 - and PRTG would need a network
   route to both. That is not a naming problem; it is the wrong architecture.

So shared infrastructure lives here, once, and the two functional halves depend on
it. They remain separate stacks and can still be deployed and destroyed
independently of each other.

On cross-stack references
-------------------------
Consuming these resources from another stack creates CloudFormation exports, and
CloudFormation will refuse to delete an export another stack still imports. That is
the correct behaviour here - you should not be able to delete the VPC out from
under a running function - but it does mean this stack must be destroyed last. The
Makefile's ``destroy`` target handles the ordering.

The "deadly embrace" risk with cross-stack references arises when two stacks
reference *each other*. Dependencies here run one way only: consumers depend on
shared, never the reverse.
"""

from __future__ import annotations

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_sns as sns

from constructs import Construct
from infrastructure.config import PrtgMcpConfig
from infrastructure.constructs.network import PrtgNetwork
from infrastructure.constructs.observability import Observability


class SharedStack(Stack):
    """VPC, security groups, interface endpoints, and the alarm notification topic.

    Attributes:
        network: Networking, consumed by both functional stacks.
        alarm_topic: Destination for alarm notifications, or ``None`` when no
            destination was configured.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: PrtgMcpConfig,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)  # type: ignore[arg-type]
        self.config = config

        self.network = PrtgNetwork(self, "Network", config=config)

        # Created here rather than in each half's Observability construct, so both
        # notify the same place and the topic name cannot collide.
        self.alarm_topic: sns.ITopic | None = Observability.resolve_topic(self, config)

        self._emit_outputs()

    def _emit_outputs(self) -> None:
        CfnOutput(
            self,
            "VpcId",
            description="VPC the integration runs in. PRTG must be routable from it.",
            value=self.network.vpc.vpc_id,
        )
        CfnOutput(
            self,
            "LambdaSecurityGroupId",
            description=(
                "Security group attached to both functions. Add this as an allowed source on "
                "PRTG's own inbound rules."
            ),
            value=self.network.lambda_security_group.security_group_id,
        )

        if self.network.endpoints:
            CfnOutput(
                self,
                "InterfaceEndpoints",
                description=(
                    "Interface VPC endpoints created for this configuration. Each one exists "
                    "because omitting it produces a specific and hard-to-diagnose failure; see "
                    "docs/deployment-matrix.md."
                ),
                value=", ".join(sorted(self.network.endpoints)),
            )

        if self.alarm_topic is not None:
            CfnOutput(
                self,
                "AlarmTopicArn",
                description="Alarms from both halves publish here.",
                value=self.alarm_topic.topic_arn,
            )
        else:
            CfnOutput(
                self,
                "AlarmTopicArn",
                description=(
                    "No alarm destination configured. Alarms exist but notify nobody, so a broken "
                    "PRTG credential would go unnoticed. Set observability.alarm_email or "
                    "alarm_topic_arn."
                ),
                value="none",
            )
