"""VPC, subnets, security groups, and interface endpoints.

This construct is where ``network.mode`` and ``prtg.reachability`` turn into real
resources. It has three jobs:

1. Resolve or create the VPC.
2. Build the two security groups, with egress narrowed to PRTG.
3. In ``private`` mode, create every interface endpoint the integration needs.

The third point is the reason this is a construct rather than a few lines inside
the stack. The endpoint list is derived from ``PrtgMcpConfig`` rather than written
out by hand, because omitting one produces a failure that is disproportionately
hard to diagnose:

* No ``secretsmanager`` endpoint - the function times out fetching the credential,
  with nothing in the logs to say why.
* No ``logs`` endpoint - the function runs correctly and writes nothing to
  CloudWatch, so it appears never to have been invoked at all.
* No ``lambda`` endpoint - the Gateway cannot invoke the function and reports a
  target failure that says nothing about networking.
* No ``sts`` endpoint - cross-account role assumption hangs until the timeout.
* No ``sqs`` endpoint - the alarm pipeline cannot park a failed alarm, so the one
  path that exists to stop an alarm being lost is itself unreachable, and it fails
  slowly, burning what is left of the invocation.

Each of those is a recurring support question for private-subnet Lambda functions,
which is a good sign they are worth designing out rather than documenting.
"""

from __future__ import annotations

from aws_cdk import RemovalPolicy, Tags
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_logs as logs

from constructs import Construct
from infrastructure.config import PrtgMcpConfig
from infrastructure.constructs.common import retention_for

#: Endpoint short name to the CDK service constant. Keyed by the same short names
#: ``PrtgMcpConfig.required_vpc_endpoints`` returns, so the two cannot disagree.
_ENDPOINT_SERVICES: dict[str, ec2.InterfaceVpcEndpointAwsService] = {
    "secretsmanager": ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
    "logs": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
    "lambda": ec2.InterfaceVpcEndpointAwsService.LAMBDA_,
    "sts": ec2.InterfaceVpcEndpointAwsService.STS,
    "sqs": ec2.InterfaceVpcEndpointAwsService.SQS,
    "cognito-idp": ec2.InterfaceVpcEndpointAwsService.COGNITO_IDP,
    "execute-api": ec2.InterfaceVpcEndpointAwsService.APIGATEWAY,
    "ssm": ec2.InterfaceVpcEndpointAwsService.SSM,
    # No InterfaceVpcEndpointAwsService constant exists for DevOps Agent, so name the
    # service directly; the constructor builds `com.amazonaws.<region>.<name>`.
    #
    # The DATA plane, despite CreateBacklogTask reading like a control-plane action. The
    # service model is what decides: CreateBacklogTask carries hostPrefix 'dp.', while
    # RegisterService and the agent-space operations carry 'cp.'. Registration is 'cp.'
    # but runs at deploy time through CloudFormation, not from inside the VPC, so only
    # the data plane is needed here.
    #
    # Creating it is not sufficient on its own: it serves names under
    # `aidevops.<region>.api.aws`, a different domain from the SDK's default endpoint, so
    # the client has to be pointed at it. See PrtgMcpConfig.agent_endpoint_url.
    "aidevops-dataplane": ec2.InterfaceVpcEndpointAwsService("aidevops-dataplane"),
}


class PrtgNetwork(Construct):
    """Networking for the PRTG integration.

    Attributes:
        vpc: The resolved or created VPC.
        subnet_selection: Subnets the Lambda functions are placed in.
        lambda_security_group: Attached to the functions. Egress is restricted.
        endpoint_security_group: Attached to interface endpoints; ``private``
            mode only, otherwise ``None``.
        endpoints: Interface endpoints by short name.
    """

    def __init__(self, scope: Construct, construct_id: str, *, config: PrtgMcpConfig) -> None:
        super().__init__(scope, construct_id)
        self.config = config

        self.vpc = self._resolve_vpc()
        self.subnet_selection = self._select_subnets()

        # Both groups are created before any rule is written, so endpoint access
        # can be expressed group-to-group rather than by CIDR. That keeps the rule
        # correct if the VPC is re-addressed, avoids admitting anything else that
        # shares the subnet, and works with a VPC imported via
        # `from_vpc_attributes`, which does not expose a CIDR at all.
        self.lambda_security_group = self._build_lambda_security_group()
        self.endpoint_security_group = self._build_endpoint_security_group()
        self._wire_egress()

        self.endpoints: dict[str, ec2.InterfaceVpcEndpoint] = self._build_endpoints()

    # --- VPC ----------------------------------------------------------------

    def _resolve_vpc(self) -> ec2.IVpc:
        """Create a VPC, or import an existing one by whichever path was configured.

        Two import paths, and the difference is not cosmetic:

        ``from_vpc_attributes`` (subnet IDs and AZs supplied)
            No lookup. Synthesis works with no AWS credentials, which is what lets
            CI verify every shipped configuration.

        ``from_lookup`` (VPC ID alone)
            A synthesis-time context lookup. Discovers subnets and AZs, but calls
            EC2 during ``cdk synth`` and so needs credentials and a concrete
            account and region. The result is cached in ``cdk.context.json``,
            which is worth committing for reproducible builds.
        """
        network = self.config.network

        if network.creates_vpc:
            return self._create_vpc()

        if network.subnet_ids:
            return ec2.Vpc.from_vpc_attributes(
                self,
                "Vpc",
                vpc_id=network.vpc_id,  # type: ignore[arg-type]
                availability_zones=list(network.availability_zones),
                private_subnet_ids=list(network.subnet_ids),
            )

        return ec2.Vpc.from_lookup(self, "Vpc", vpc_id=network.vpc_id)

    def _create_vpc(self) -> ec2.Vpc:
        """Create a VPC shaped by the egress mode.

        In ``private`` mode the subnets are ``PRIVATE_ISOLATED`` and there is no
        public subnet at all, so there is nowhere for an internet gateway to
        attach. That makes "no internet" a structural property rather than
        something enforced by a route table somebody could later change.
        """
        network = self.config.network
        private_mode = self.config.is_fully_private

        if private_mode:
            subnet_configuration = [
                ec2.SubnetConfiguration(
                    name="isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                )
            ]
            nat_gateways = 0
        else:
            subnet_configuration = [
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
            ]
            # One NAT gateway rather than one per AZ. A second costs another
            # ~USD 32/month to protect a read-only monitoring integration whose
            # unavailability degrades an investigation rather than an application.
            # Raise it if that trade does not suit you.
            nat_gateways = 1

        vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr(network.cidr),
            max_azs=network.max_azs,
            nat_gateways=nat_gateways,
            subnet_configuration=subnet_configuration,
            # Both are required for interface endpoint private DNS to resolve. In
            # private mode, without these the function cannot resolve
            # secretsmanager.<region>.amazonaws.com to the endpoint at all.
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        # Flow logs are the only way to see traffic a security group dropped.
        # Diagnosing "the Lambda cannot reach PRTG" without them is guesswork.
        #
        # The log group is created explicitly so it inherits the configured
        # retention. Left to CDK's default, the flow-log group retains for two years
        # regardless of observability.log_retention_days - a quiet inconsistency
        # that only shows up on the bill.
        flow_log_group = logs.LogGroup(
            self,
            "FlowLogGroup",
            log_group_name=f"/aws/vpc/flowlogs/{self.config.name_prefix}",
            retention=retention_for(self.config.observability.log_retention_days),
            removal_policy=RemovalPolicy.DESTROY,
        )
        ec2.FlowLog(
            self,
            "FlowLog",
            resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
            traffic_type=ec2.FlowLogTrafficType.REJECT,
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(flow_log_group),
        )

        Tags.of(vpc).add("Name", self.config.resource_name("vpc"))
        return vpc

    def _select_subnets(self) -> ec2.SubnetSelection:
        """Choose the subnets the functions run in."""
        network = self.config.network

        if network.subnet_ids:
            # Explicitly supplied, so use exactly these and nothing else.
            return ec2.SubnetSelection(
                subnets=[
                    ec2.Subnet.from_subnet_attributes(
                        self,
                        f"Subnet{index}",
                        subnet_id=subnet_id,
                        availability_zone=network.availability_zones[index],
                    )
                    for index, subnet_id in enumerate(network.subnet_ids)
                ]
            )

        if self.config.is_fully_private:
            return ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)

        return ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)

    # --- Security groups ----------------------------------------------------

    def _build_lambda_security_group(self) -> ec2.SecurityGroup:
        """Security group for the Lambda functions. Rules are added by ``_wire_egress``."""
        return ec2.SecurityGroup(
            self,
            "LambdaSecurityGroup",
            vpc=self.vpc,
            description=(
                f"{self.config.name_prefix}: PRTG MCP and alarm pipeline functions. "
                "Egress restricted to PRTG and required AWS endpoints."
            ),
            # CDK's default opens egress to everything. For a function holding a
            # monitoring credential that is more reach than it needs, so every
            # rule here is written explicitly.
            allow_all_outbound=False,
            security_group_name=self.config.resource_name("lambda-sg"),
        )

    def _build_endpoint_security_group(self) -> ec2.SecurityGroup | None:
        """Security group for the interface endpoints, if any are needed."""
        if not self.config.required_vpc_endpoints:
            return None

        group = ec2.SecurityGroup(
            self,
            "EndpointSecurityGroup",
            vpc=self.vpc,
            # CloudFormation restricts the characters allowed here; an apostrophe
            # is rejected, so this wording avoids one.
            description=(
                f"{self.config.name_prefix}: interface VPC endpoints. "
                "Ingress from the PRTG integration functions only."
            ),
            allow_all_outbound=False,
            security_group_name=self.config.resource_name("vpce-sg"),
        )

        # A private alarm API is called by PRTG, which is not in the Lambda
        # security group and may not even be in this VPC, so that one ingress path
        # is by address.
        if self.config.alarm_api_private and self.config.deploy_alarm_pipeline:
            for index, cidr in enumerate(self.config.alarm_allowed_source_ips):
                group.add_ingress_rule(
                    peer=ec2.Peer.ipv4(cidr),
                    connection=ec2.Port.tcp(443),
                    description=f"HTTPS from PRTG to the private alarm API ({index})",
                )

        return group

    def _wire_egress(self) -> None:
        """Grant the functions the egress they need, and nothing more.

        Three destinations:

        * **PRTG**, on its configured port. Narrowed to a single ``/32`` when
          ``prtg.host_cidr`` is set, which the configuration recommends.
        * **Interface endpoints**, in ``private`` mode. Expressed group-to-group,
          which also creates the matching ingress rule on the endpoint group.
        * **AWS public endpoints**, in ``nat`` mode only. AWS service endpoints
          have no stable address range worth pinning, so 443 to anywhere is as
          narrow as this gets. Choosing ``network.mode: private`` removes this
          rule entirely, which is one of the better arguments for it.
        """
        prtg = self.config.prtg

        # Guaranteed by config validation, which requires host_cidr or cidr.
        assert prtg.egress_cidr is not None  # noqa: S101

        self.lambda_security_group.add_egress_rule(
            peer=ec2.Peer.ipv4(prtg.egress_cidr),
            connection=ec2.Port.tcp(prtg.port),
            description=(
                "HTTPS to PRTG (single host)" if prtg.host_cidr else "HTTPS to PRTG (network range)"
            ),
        )

        if self.endpoint_security_group is not None:
            # allow_to writes the egress rule here and the ingress rule there, so
            # the pair cannot fall out of step.
            self.lambda_security_group.connections.allow_to(
                self.endpoint_security_group,
                ec2.Port.tcp(443),
                "HTTPS to interface VPC endpoints",
            )

        if not self.config.is_fully_private:
            self.lambda_security_group.add_egress_rule(
                peer=ec2.Peer.any_ipv4(),
                connection=ec2.Port.tcp(443),
                description="HTTPS to AWS service endpoints via NAT",
            )

    # --- Interface endpoints ------------------------------------------------

    def _build_endpoints(self) -> dict[str, ec2.InterfaceVpcEndpoint]:
        """Create the interface endpoints this configuration requires."""
        required = self.config.required_vpc_endpoints
        if not required:
            return {}

        assert self.endpoint_security_group is not None  # noqa: S101 - guaranteed above

        endpoints: dict[str, ec2.InterfaceVpcEndpoint] = {}
        for short_name in required:
            service = _ENDPOINT_SERVICES.get(short_name)
            if service is None:
                # Unreachable while config and this map stay in step; a test
                # asserts they do.
                raise ValueError(
                    f"No CDK service constant is mapped for VPC endpoint {short_name!r}. "
                    "Add it to _ENDPOINT_SERVICES in infrastructure/constructs/network.py."
                )

            endpoints[short_name] = ec2.InterfaceVpcEndpoint(
                self,
                f"Endpoint{_pascal(short_name)}",
                vpc=self.vpc,
                service=service,
                subnets=self.subnet_selection,
                security_groups=[self.endpoint_security_group],
                # Without private DNS, boto3 resolves the public hostname and the
                # call leaves the VPC - which in private mode means it fails.
                # Enabling it is what allows the Lambda source to be identical in
                # both network modes.
                private_dns_enabled=True,
                # CDK otherwise adds an ingress rule for the entire VPC CIDR.
                # Ingress is already granted group-to-group from the functions in
                # `_wire_egress`, so the implicit rule would only widen access to
                # anything else sharing the VPC. Disabling it also keeps this
                # working with a VPC imported via `from_vpc_attributes`, which
                # exposes no CIDR for CDK to reference.
                open=False,
            )

        return endpoints

    # --- Accessors ----------------------------------------------------------

    @property
    def execute_api_endpoint(self) -> ec2.InterfaceVpcEndpoint | None:
        """The ``execute-api`` endpoint, needed to build a private API's policy."""
        return self.endpoints.get("execute-api")


def _pascal(value: str) -> str:
    """``secretsmanager`` -> ``Secretsmanager``, ``execute-api`` -> ``ExecuteApi``."""
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))
