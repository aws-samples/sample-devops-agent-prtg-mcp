"""OPTIONAL demo PRTG server on EC2, with an optional host for it to monitor.

Evaluation only.

    cdk deploy -c demo_prtg=true '*-demo-prtg'
    cdk deploy -c demo_prtg=true -c demo_app_server=true '*-demo-prtg'

Off unless those context flags are set, and deliberately context flags rather than
configuration fields: this is a testing affordance for people who do not already run
PRTG, not part of the solution being demonstrated. The app server is a second flag
because it is a second Windows instance, and Windows licensing means nobody should get
one they did not ask for.

Read this before deploying it
-----------------------------
**This is not a production PRTG topology, and it should not be read as a
recommendation.** PRTG stores credentials for everything it monitors - SNMP community
strings, WMI and Windows domain accounts, SSH keys, database connection strings - and
its network position requires it to reach every monitored host. That makes a real PRTG
server a tier-0 asset deserving the same protection as a domain controller. A
single-instance EC2 box with no backup, no patching schedule and no HA is not that.

The realistic customer situation is that PRTG already runs on-premises, which is why
``prtg.reachability: remote`` exists. This stack is for the case where you want to
evaluate the integration and have no PRTG to point it at.

**Bring your own installer.** Nothing here downloads or distributes PRTG. Paessler's
licensing is not ours to redistribute, so you supply the installer yourself, either
by uploading it to S3 (see ``installer_s3_uri``) or by copying it in over an SSM
session.

What this creates
-----------------
* A Windows Server 2025 instance in a **private** subnet of the shared VPC, with no
  public IP and no key pair. Access is via SSM Session Manager only.
* A security group allowing inbound 443 **from the MCP Lambda security group alone**.
  Not from the VPC CIDR, and not from the internet.
* A fixed private IP, because the Lambda's egress is scoped to ``prtg.host_cidr`` as a
  ``/32`` and a moved address silently breaks every tool call.
* User data that opens 443 in the Windows firewall and, if given an S3 URI, stages the
  installer onto the instance.

Optionally, with ``-c demo_app_server=true``
-------------------------------------------
A second Windows instance for PRTG to monitor, so the WMI sensors have a target and the
port requirements are demonstrated rather than described.

Both firewall layers are configured, because satisfying one and not the other is the
single most common way WMI monitoring fails:

* Its security group admits WMI **from the PRTG security group alone** - TCP 135 for
  the RPC endpoint mapper, TCP 49152-65535 for the dynamically assigned port DCOM
  redirects to, TCP 445 for Remote Registry, UDP 161 for SNMP, and ICMP echo.
* Its user data enables the **built-in, service-scoped** Windows firewall rules for
  WMI, restricted to PRTG's address. Those are scoped to the ``winmgmt`` and ``rpcss``
  services rather than to a port, so the dynamic port is handled however Windows
  assigns it.

The security group still needs the full dynamic range even though the OS rules are
service-scoped, because a security group cannot match on a process.

See ``docs/network-ports.md`` for why 135 alone produces a successful logon followed by
``800706BA The RPC server is unavailable``.
"""

from __future__ import annotations

import ipaddress

from aws_cdk import CfnOutput, RemovalPolicy, Stack, Tags, Token
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam

from constructs import Construct
from infrastructure.config import PrtgMcpConfig
from infrastructure.constructs.network import PrtgNetwork

#: Windows Server 2025 English. Resolved from an SSM public parameter at deployment,
#: so synthesis stays credential-free.
#:
#: Paessler's system requirements list Server 2025 first among recommended platforms,
#: so this is supported for the core server and not only for the monitored host. The
#: firewall rule names in ``WMI_FIREWALL_RULE_NAMES`` and the RPC dynamic port range
#: below are identical on 2022 and 2025, verified on both, so moving between the two
#: does not change what has to be opened.
#:
#: One behavioural difference worth knowing: on Server 2025 the SMB *client* requires
#: signing by default, where on 2022 it did not. SMB2 and later always support signing,
#: so this negotiates rather than fails; it means traffic on port 445 is signed.
WINDOWS_VERSION = ec2.WindowsVersion.WINDOWS_SERVER_2025_ENGLISH_FULL_BASE

#: 2 vCPU / 4 GB. Comfortable for PRTG's 100-sensor free tier; the web UI is sluggish
#: on anything smaller. Windows licensing dominates the cost, not the instance size.
DEFAULT_INSTANCE_TYPE = "t3.medium"

#: PRTG's historic data grows steadily and 30 GB gets tight.
DEFAULT_VOLUME_GB = 50

#: The monitored host does no work beyond being monitored, so the smallest burstable
#: type is enough. It only has to answer WMI queries.
DEFAULT_APP_SERVER_INSTANCE_TYPE = "t3.micro"

#: Windows Server needs headroom for updates; 30 GB is the practical floor.
DEFAULT_APP_SERVER_VOLUME_GB = 30

#: Windows assigns RPC ports from this range by default on Server 2008 and later. DCOM
#: negotiates on 135 and then redirects here, so a rule for 135 alone gets you an
#: authenticated session and then a connection failure.
RPC_DYNAMIC_PORT_START = 49152
RPC_DYNAMIC_PORT_END = 65535

#: Built-in Windows firewall rules for WMI, by rule *name* rather than display name so
#: the commands work on a non-English installation. Scoped to the ``winmgmt`` and
#: ``rpcss`` services, which is what makes them immune to the dynamic-port problem.
#: Disabled on a fresh Windows Server, hence the user data.
WMI_FIREWALL_RULE_NAMES = (
    "WMI-WINMGMT-In-TCP",
    "WMI-RPCSS-In-TCP",
    "WMI-ASYNC-In-TCP",
)

#: Echo request, for PRTG's Ping sensor. Also disabled by default.
ICMP_ECHO_FIREWALL_RULE_NAME = "FPS-ICMP4-ERQ-In"


class DemoPrtgStack(Stack):
    """A throwaway PRTG server for evaluating the integration.

    Attributes:
        instance: The EC2 instance.
        security_group: PRTG's security group.
        private_ip: The pinned private address to use as ``prtg.host_cidr``.
        app_server: The optional monitored host, or ``None``.
        app_server_security_group: The monitored host's group, or ``None``.
        app_server_ip: The monitored host's pinned address, or ``None``.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: PrtgMcpConfig,
        network: PrtgNetwork,
        private_ip: str,
        subnet_id: str | None = None,
        instance_type: str = DEFAULT_INSTANCE_TYPE,
        volume_gb: int = DEFAULT_VOLUME_GB,
        installer_s3_uri: str | None = None,
        with_app_server: bool = False,
        app_server_ip: str | None = None,
        app_server_instance_type: str = DEFAULT_APP_SERVER_INSTANCE_TYPE,
        app_server_volume_gb: int = DEFAULT_APP_SERVER_VOLUME_GB,
        **kwargs: object,
    ) -> None:
        """
        Args:
            config: The deployment configuration, for naming and tags.
            network: The shared VPC. PRTG goes in a private subnet of it, so the
                Lambda can reach it without peering.
            private_ip: Fixed private address, which must match ``prtg.host_cidr``.
            subnet_id: Which private subnet to place PRTG in. Defaults to the first of
                the shared private subnets. A pinned address is only valid inside one
                subnet's range, so this and ``private_ip`` have to agree.
            instance_type: EC2 instance type.
            volume_gb: Root volume size.
            installer_s3_uri: Optional ``s3://bucket/key`` for the PRTG installer.
                When given, the instance is granted read on that object and user data
                stages it to ``C:\\Install``.
            with_app_server: Also create a Windows host for PRTG to monitor, so the
                WMI sensors have a target.
            app_server_ip: Fixed private address for that host. Required when
                ``with_app_server`` is set, and it shares PRTG's subnet.
            app_server_instance_type: EC2 instance type for the monitored host.
            app_server_volume_gb: Root volume size for the monitored host.
        """
        super().__init__(scope, construct_id, **kwargs)  # type: ignore[arg-type]
        self.config = config
        self.private_ip = _validate_ipv4(private_ip)
        self._require_address_within_lambda_egress()

        self.subnet = self._select_subnet(network, subnet_id)
        self.security_group = self._build_security_group(network)
        self.role = self._build_role(installer_s3_uri)
        self.instance = self._build_instance(
            network=network,
            instance_type=instance_type,
            volume_gb=volume_gb,
            installer_s3_uri=installer_s3_uri,
        )

        self.app_server_ip: str | None = None
        self.app_server_security_group: ec2.SecurityGroup | None = None
        self.app_server_role: iam.Role | None = None
        self.app_server: ec2.Instance | None = None

        if with_app_server:
            self.app_server_ip = self._validate_app_server_ip(app_server_ip)
            self.app_server_security_group = self._build_app_server_security_group(network)
            self.app_server_role = self._build_app_server_role()
            self.app_server = self._build_app_server(
                network=network,
                instance_type=app_server_instance_type,
                volume_gb=app_server_volume_gb,
            )

        # Built last, so ingress can be granted from whichever instance groups exist.
        self.ssm_endpoint_security_group: ec2.SecurityGroup | None = None
        self.ssm_endpoints: dict[str, ec2.InterfaceVpcEndpoint] = {}
        if config.network.mode == "private":
            self._build_ssm_endpoints(network)

        self._emit_outputs(installer_s3_uri)

    def _build_ssm_endpoints(self, network: PrtgNetwork) -> None:
        """Make these Windows hosts reachable in a VPC with no internet route.

        There is no RDP ingress anywhere in this stack, by design, so Session Manager is
        the *only* way in. In ``nat`` mode the NAT gateway carries the SSM agent's traffic
        and nothing extra is needed. In ``private`` mode there is no route at all, so
        without interface endpoints the agent never registers: the instances boot, pass
        their status checks, appear healthy, and are simply unreachable. Nothing reports
        why, because nothing failed.

        Three endpoints, and all three are required. ``ssm`` and ``ssmmessages`` carry the
        session itself; ``ec2messages`` carries Run Command. Verified empirically rather
        than from the documentation -- these exact three were enough for both hosts to
        reach ``Online`` and answer Run Command in a VPC with no NAT, no internet gateway
        and no default route.

        An S3 gateway endpoint is deliberately not added. It is needed only for S3-backed
        session output or agent auto-update from S3, neither of which this stack uses, and
        a gateway endpoint rewrites route tables for the whole VPC -- too broad a side
        effect for a testing affordance.

        These live here rather than in the shared stack's derived endpoint list for two
        reasons. They are needed by *these instances*, not by the integration, so putting
        them in ``required_vpc_endpoints`` would make every private deployment pay for
        three endpoints it never calls and would undermine the claim that the list is
        derived from what the solution needs. And keeping them here means toggling
        ``-c demo_prtg=true`` does not modify the shared stack -- which matters, because
        the demo stack imports the shared VPC, and changing that stack while an importer
        exists is exactly what fails.

        One of the three can collide with the shared stack. ``ssm`` is also in
        ``required_vpc_endpoints`` when a private deployment fans out, because the routing
        table lives in an SSM parameter. AWS permits only one interface endpoint per
        service per VPC to enable private DNS, so creating a second is rejected outright --
        and private DNS is exactly what both of them need. Whichever endpoint the shared
        stack already created is therefore reused, and these hosts are granted access to it
        instead. See ``_admit_hosts_to_shared_endpoints``.
        """
        # `ssm` is the only overlap possible: _ENDPOINT_SERVICES has no ssmmessages or
        # ec2messages entry, so the shared stack can never create those.
        already_shared = {name for name in ("ssm", "ssmmessages", "ec2messages") if name in network.endpoints}

        peers = [self.security_group]
        if self.app_server_security_group is not None:
            peers.append(self.app_server_security_group)

        if already_shared:
            self._admit_hosts_to_shared_endpoints(network, peers=peers, reused=already_shared)

        if len(already_shared) == 3:
            # Nothing left to create, so do not leave an empty security group behind.
            return

        self.ssm_endpoint_security_group = ec2.SecurityGroup(
            self,
            "SsmEndpointSecurityGroup",
            vpc=network.vpc,
            security_group_name=self.config.resource_name("demo-ssm-vpce-sg"),
            description="Session Manager interface endpoints for the demo Windows hosts",
            allow_all_outbound=False,
        )
        for peer in peers:
            self.ssm_endpoint_security_group.add_ingress_rule(
                peer=peer,
                connection=ec2.Port.tcp(443),
                description="HTTPS from a demo Windows host to the SSM endpoints",
            )

        for short_name, service in (
            ("ssm", ec2.InterfaceVpcEndpointAwsService.SSM),
            ("ssmmessages", ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES),
            ("ec2messages", ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES),
        ):
            if short_name in already_shared:
                continue
            self.ssm_endpoints[short_name] = ec2.InterfaceVpcEndpoint(
                self,
                f"SsmEndpoint{short_name.capitalize()}",
                vpc=network.vpc,
                service=service,
                subnets=network.subnet_selection,
                security_groups=[self.ssm_endpoint_security_group],
                # The agent resolves the public hostname, so without private DNS the
                # endpoint exists and is never used.
                private_dns_enabled=True,
                # Ingress is granted group-to-group above. CDK's implicit rule would open
                # the endpoint to the whole VPC CIDR, and in a shared VPC that is wider
                # than this testing affordance has any business being.
                open=False,
            )

    def _admit_hosts_to_shared_endpoints(
        self,
        network: PrtgNetwork,
        *,
        peers: list[ec2.SecurityGroup],
        reused: set[str],
    ) -> None:
        """Let the demo hosts reach an interface endpoint the shared stack already made.

        Reached only when ``required_vpc_endpoints`` and this stack want the same service.
        Today that is ``ssm`` and only when a private deployment fans out, because the
        routing table lives in an SSM parameter.

        The shared endpoint's security group admits the Lambda functions and nothing else,
        so reusing the endpoint is not enough on its own -- without this the hosts resolve
        the endpoint through private DNS and are dropped at its security group. Which is
        the same silent, flow-logs-only failure the endpoints exist to avoid, just moved.

        **The rule is created in this stack, deliberately.** The obvious spelling,
        ``peer.connections.allow_to(network.endpoint_security_group, ...)``, would put an
        ingress rule referencing this stack's security groups into the *shared* stack --
        and the demo stack already imports the shared VPC, so that makes the two stacks
        mutually dependent and CloudFormation refuses the deployment. Importing the group
        by id keeps the rule here, pointing outward only.
        """
        assert network.endpoint_security_group is not None  # noqa: S101 - endpoints exist

        # Imported by id rather than used directly, so the rule below is synthesised into
        # this stack instead of the one that owns the group.
        shared_group = ec2.SecurityGroup.from_security_group_id(
            self,
            "SharedEndpointSecurityGroup",
            network.endpoint_security_group.security_group_id,
            # Without this, CDK would also try to write egress rules onto the imported
            # group, which belongs to another stack.
            mutable=False,
        )

        for index, peer in enumerate(peers):
            ec2.CfnSecurityGroupIngress(
                self,
                f"SharedEndpointIngress{index}",
                group_id=shared_group.security_group_id,
                source_security_group_id=peer.security_group_id,
                ip_protocol="tcp",
                from_port=443,
                to_port=443,
                description=(
                    "HTTPS from a demo Windows host to the shared "
                    f"{', '.join(sorted(reused))} interface endpoint"
                ),
            )

    def _require_address_within_lambda_egress(self) -> None:
        """Refuse a PRTG address the Lambda's security group cannot reach.

        The tool function's egress is scoped to ``prtg.host_cidr`` (or ``prtg.cidr``), so
        an address outside it produces a deployment where every resource is healthy and
        every tool call times out. There is nothing in the logs to point at the security
        group, which makes it a poor thing to discover after a Windows instance has
        booted and PRTG has been installed by hand.

        Worth checking rather than documenting, because the shipped defaults themselves
        disagreed: this stack pinned PRTG at 10.0.2.50 while ``config/default.yaml``
        scoped egress to 10.0.1.10/32 -- different subnets, one public and one private, in
        the VPC the sample creates. So the documented one-liner for evaluating without a
        PRTG server produced exactly this dead end. An output already stated the two "MUST
        match"; stating it was not enough.

        Raises:
            ValueError: if the pinned address falls outside the configured egress range.
        """
        egress = self.config.prtg.egress_cidr
        if not egress:  # pragma: no cover - config validation requires one of the two
            return

        if ipaddress.ip_address(self.private_ip) in ipaddress.ip_network(egress, strict=False):
            return

        field = "prtg.host_cidr" if self.config.prtg.host_cidr else "prtg.cidr"
        raise ValueError(
            f"The demo PRTG server is pinned to {self.private_ip}, which is outside "
            f"{field}={egress!r} -- the range the tool function's egress is restricted to. "
            "Every tool call would time out while every resource looked healthy, because a "
            "security group drop is invisible outside VPC flow logs.\n"
            "     Set them to the same address, whichever way round suits you:\n"
            f"       {field}: {self.private_ip}/32          in your config file, or\n"
            f"       -c prtg_private_ip={egress.split('/')[0]}   to move the demo server instead.\n"
            "     Note the demo server needs an address inside one of this deployment's "
            "private subnets, so prefer changing the config."
        )

    def _validate_app_server_ip(self, app_server_ip: str | None) -> str:
        """Check the monitored host has a distinct pinned address.

        Raises:
            ValueError: if the address is missing, malformed, or PRTG's own.
        """
        if app_server_ip is None:
            raise ValueError(
                "demo_app_server=true requires an address for the monitored host. Pass "
                "-c demo_app_server_ip=<address> inside the same subnet as PRTG."
            )

        validated = _validate_ipv4(app_server_ip, field_name="demo_app_server_ip")
        if validated == self.private_ip:
            raise ValueError(
                f"demo_app_server_ip={validated!r} is the same address as the PRTG server. "
                "The two hosts need different addresses."
            )
        return validated

    # --- Placement ----------------------------------------------------------

    def _select_subnet(self, network: PrtgNetwork, subnet_id: str | None) -> ec2.ISubnet:
        """Resolve exactly one subnet.

        The shared selection spans two availability zones. A pinned private address
        belongs to a single subnet's range, so leaving the choice to CDK's internal
        ordering would mean the deployment succeeds or fails on an implementation
        detail. Choosing here makes it explicit and reportable in the outputs.

        Raises:
            ValueError: if ``subnet_id`` is not one of the shared private subnets.
        """
        selection = network.subnet_selection

        # The shared selection takes one of two shapes: an explicit subnet list when
        # the config named subnet ids, or a subnet type when the VPC was created here.
        # ``select_subnets`` takes keywords rather than a SubnetSelection, so unpack it.
        if selection.subnets is not None:
            available = list(selection.subnets)
        else:
            available = list(network.vpc.select_subnets(subnet_type=selection.subnet_type).subnets)

        if not available:
            raise ValueError(
                "No private subnets are available for the demo PRTG server. Check "
                "network.subnet_ids, or that the VPC has private subnets."
            )

        if subnet_id is None:
            return available[0]

        for subnet in available:
            if subnet.subnet_id == subnet_id:
                return subnet

        # When this deployment creates its own VPC, the subnet ids are unresolved
        # tokens at synthesis and listing them would print CDK internals. Only the
        # bring-your-own-VPC path has real ids to offer.
        resolved = [s.subnet_id for s in available if not Token.is_unresolved(s.subnet_id)]
        if resolved:
            raise ValueError(
                f"prtg_subnet={subnet_id!r} is not one of this deployment's private "
                f"subnets. Available: {', '.join(resolved)}."
            )
        raise ValueError(
            f"prtg_subnet={subnet_id!r} cannot be matched, because this deployment creates "
            "its own VPC and the subnet ids do not exist until it is deployed. Omit "
            "prtg_subnet to use the first private subnet, or set network.vpc_id and "
            "network.subnet_ids to place PRTG in a VPC you already have."
        )

    # --- Security group -----------------------------------------------------

    def _build_security_group(self, network: PrtgNetwork) -> ec2.SecurityGroup:
        """PRTG's own group: inbound 443 from the MCP Lambda, and nothing else."""
        group = ec2.SecurityGroup(
            self,
            "PrtgSecurityGroup",
            vpc=network.vpc,
            security_group_name=self.config.resource_name("demo-prtg-sg"),
            description=(
                f"{self.config.name_prefix}: demo PRTG server. Inbound HTTPS from the MCP tool function only."
            ),
            # Outbound is needed for SSM and Windows Update. Narrowing it would break
            # Session Manager, which is the only way into this instance.
            allow_all_outbound=True,
        )

        # Group-to-group rather than by CIDR, so this stays correct if the VPC is
        # re-addressed and admits nothing else sharing the subnet.
        group.add_ingress_rule(
            peer=network.lambda_security_group,
            connection=ec2.Port.tcp(443),
            description="HTTPS from the PRTG MCP tool function",
        )

        # Deliberately no inbound 3389. Access is via SSM Session Manager, so RDP is
        # never exposed and no key pair is needed.
        return group

    # --- IAM ----------------------------------------------------------------

    def _build_role(self, installer_s3_uri: str | None) -> iam.Role:
        """Instance profile: SSM access, plus read on the installer object if given."""
        role = iam.Role(
            self,
            "InstanceRole",
            role_name=self.config.resource_name("demo-prtg-role"),
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Demo PRTG server. SSM Session Manager access.",
            managed_policies=[
                # The minimum for Session Manager. No RDP, no key pair.
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
            ],
        )

        if installer_s3_uri:
            bucket, key = _parse_s3_uri(installer_s3_uri)
            # Scoped to the one object, not the bucket.
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="ReadPrtgInstaller",
                    actions=["s3:GetObject"],
                    resources=[f"arn:{self.partition}:s3:::{bucket}/{key}"],
                )
            )
            role.add_to_policy(
                iam.PolicyStatement(
                    sid="LocatePrtgInstallerBucket",
                    actions=["s3:GetBucketLocation"],
                    resources=[f"arn:{self.partition}:s3:::{bucket}"],
                )
            )

        return role

    # --- Instance -----------------------------------------------------------

    def _build_instance(
        self,
        *,
        network: PrtgNetwork,
        instance_type: str,
        volume_gb: int,
        installer_s3_uri: str | None,
    ) -> ec2.Instance:
        instance = ec2.Instance(
            self,
            "PrtgServer",
            instance_name=self.config.resource_name("demo-prtg"),
            instance_type=ec2.InstanceType(instance_type),
            machine_image=ec2.MachineImage.latest_windows(WINDOWS_VERSION),
            vpc=network.vpc,
            # One explicit subnet, because the pinned address below has to sit inside
            # its range.
            vpc_subnets=ec2.SubnetSelection(subnets=[self.subnet]),
            security_group=self.security_group,
            role=self.role,
            # Pinned, because the Lambda's egress is a /32. Without this, a stop/start
            # moves the address and every tool call starts timing out while the
            # security group still looks correct.
            private_ip_address=self.private_ip,
            associate_public_ip_address=False,
            # SSM only. A key pair would imply RDP, which is not exposed.
            key_pair=None,
            require_imdsv2=True,
            user_data=self._build_user_data(installer_s3_uri),
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/sda1",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_gb,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        encrypted=True,
                        delete_on_termination=True,
                    ),
                )
            ],
        )

        Tags.of(instance).add("Purpose", "PRTG MCP integration evaluation")
        Tags.of(instance).add("NotProduction", "true")
        instance.apply_removal_policy(RemovalPolicy.DESTROY)
        return instance

    def _build_user_data(self, installer_s3_uri: str | None) -> ec2.UserData:
        """Open the firewall, and stage the installer if one was supplied.

        The installer is not run unattended. PRTG's setup asks for a licence key and
        an administrator password, and a silent install that guessed at those would be
        worse than leaving it to the operator.
        """
        user_data = ec2.UserData.for_windows()
        user_data.add_commands(
            "New-Item -ItemType Directory -Force -Path C:\\Install | Out-Null",
            # The PRTG installer usually adds this rule itself, but when it does not,
            # the symptom is a Lambda timeout with a security group that looks correct.
            # Pre-creating it removes that from the list of things to check.
            (
                "New-NetFirewallRule -DisplayName 'PRTG HTTPS (inbound)' "
                "-Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow "
                "-ErrorAction SilentlyContinue | Out-Null"
            ),
        )

        if installer_s3_uri:
            bucket, key = _parse_s3_uri(installer_s3_uri)
            filename = key.rsplit("/", 1)[-1]
            user_data.add_commands(
                f"Write-Output 'Staging PRTG installer from s3://{bucket}/{key}'",
                (f"aws s3 cp s3://{bucket}/{key} C:\\Install\\{filename} --region {self.region}"),
            )

        user_data.add_commands(
            "Write-Output 'Ready. Connect with SSM Session Manager and run the installer in C:\\Install.'"
        )
        return user_data

    # --- Monitored host -----------------------------------------------------

    def _build_app_server_security_group(self, network: PrtgNetwork) -> ec2.SecurityGroup:
        """The monitored host's group: WMI and SNMP from the PRTG server alone.

        Every rule is sourced from PRTG's own security group rather than a CIDR, so
        nothing else sharing the subnet can reach it.
        """
        group = ec2.SecurityGroup(
            self,
            "AppServerSecurityGroup",
            vpc=network.vpc,
            security_group_name=self.config.resource_name("demo-app-server-sg"),
            description=(
                f"{self.config.name_prefix}: demo monitored host. Inbound WMI, SNMP and ICMP from "
                "the demo PRTG server only."
            ),
            # Outbound is needed for SSM and Windows Update. Narrowing it would break
            # Session Manager, which is the only way into this instance.
            allow_all_outbound=True,
        )

        group.add_ingress_rule(
            peer=self.security_group,
            connection=ec2.Port.tcp(135),
            description="WMI: RPC endpoint mapper (DCOM stage 1) from PRTG",
        )

        # DCOM negotiates on 135 and is then redirected to a port the OS assigns from
        # this range. Omitting it is the classic failure: authentication succeeds, the
        # target logs a successful logon, and the connection then fails with
        # 800706BA. A security group cannot match on a process, so the range has to be
        # expressed here even though the host firewall rules are service-scoped.
        group.add_ingress_rule(
            peer=self.security_group,
            connection=ec2.Port.tcp_range(RPC_DYNAMIC_PORT_START, RPC_DYNAMIC_PORT_END),
            description="WMI: RPC dynamic port range (DCOM stage 2) from PRTG",
        )

        # Reached over SMB, and needed by the PRTG sensors that read Windows
        # performance counters rather than WMI.
        group.add_ingress_rule(
            peer=self.security_group,
            connection=ec2.Port.tcp(445),
            description="SMB, for Remote Registry and performance counters, from PRTG",
        )

        # SNMP is UDP. A TCP rule on 161 looks plausible in a console and permits
        # nothing at all, which is a genuinely slow thing to notice.
        group.add_ingress_rule(
            peer=self.security_group,
            connection=ec2.Port.udp(161),
            description="SNMP from PRTG",
        )

        group.add_ingress_rule(
            peer=self.security_group,
            connection=ec2.Port.icmp_ping(),
            description="ICMP echo request, for the PRTG Ping sensor",
        )

        # Deliberately no 3389 and no WinRM. Access is via SSM Session Manager. PRTG
        # can be switched to the WSMan transport for WMI sensors, which would need
        # 5985 or 5986 added here, but the default DCOM path does not.
        return group

    def _build_app_server_role(self) -> iam.Role:
        """Instance profile for the monitored host. Session Manager only."""
        return iam.Role(
            self,
            "AppServerRole",
            role_name=self.config.resource_name("demo-app-server-role"),
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Demo monitored host. SSM Session Manager access.",
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")],
        )

    def _build_app_server(
        self,
        *,
        network: PrtgNetwork,
        instance_type: str,
        volume_gb: int,
    ) -> ec2.Instance:
        """A Windows host in PRTG's subnet, for PRTG to monitor."""
        assert self.app_server_security_group is not None  # noqa: S101 - set by the caller
        assert self.app_server_role is not None  # noqa: S101 - set by the caller

        instance = ec2.Instance(
            self,
            "AppServer",
            instance_name=self.config.resource_name("demo-app-server"),
            instance_type=ec2.InstanceType(instance_type),
            machine_image=ec2.MachineImage.latest_windows(WINDOWS_VERSION),
            vpc=network.vpc,
            # The same subnet as PRTG, so both pinned addresses sit in one range.
            vpc_subnets=ec2.SubnetSelection(subnets=[self.subnet]),
            security_group=self.app_server_security_group,
            role=self.app_server_role,
            # Pinned so the PRTG device entry stays valid across a stop/start.
            private_ip_address=self.app_server_ip,
            associate_public_ip_address=False,
            key_pair=None,
            require_imdsv2=True,
            user_data=self._build_app_server_user_data(),
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/sda1",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_gb,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        encrypted=True,
                        delete_on_termination=True,
                    ),
                )
            ],
        )

        Tags.of(instance).add("Purpose", "PRTG MCP integration evaluation - monitored host")
        Tags.of(instance).add("NotProduction", "true")
        instance.apply_removal_policy(RemovalPolicy.DESTROY)
        return instance

    def _build_app_server_user_data(self) -> ec2.UserData:
        """Open the host firewall for WMI, scoped to PRTG.

        The security group is only half of it. Windows has its own firewall, and a
        rule present in one and absent from the other fails exactly like no rule at
        all. This enables the *built-in* WMI rules, which are scoped to the
        ``winmgmt`` and ``rpcss`` services rather than to a port. That matters: a
        port-based rule has to name the RPC dynamic range, and a rule for a narrowed
        range such as 10000-10099 is only correct if the OS range was pinned to match,
        which is a separate registry change and a reboot.

        Rules are addressed by ``-Name`` rather than ``-DisplayName`` so this works on
        a non-English Windows installation.
        """
        user_data = ec2.UserData.for_windows()
        user_data.add_commands(
            f"Write-Output 'Restricting and enabling WMI firewall rules for PRTG at {self.private_ip}'"
        )

        # Scope before enabling, so the rules are never briefly open to any address.
        for rule_name in (*WMI_FIREWALL_RULE_NAMES, ICMP_ECHO_FIREWALL_RULE_NAME):
            user_data.add_commands(
                (
                    f"Set-NetFirewallRule -Name {rule_name} -RemoteAddress {self.private_ip} "
                    "-ErrorAction SilentlyContinue"
                ),
                f"Enable-NetFirewallRule -Name {rule_name} -ErrorAction SilentlyContinue",
            )

        user_data.add_commands(
            "Write-Output 'Monitored host ready. Add it to PRTG as a device at this private address.'"
        )
        return user_data

    # --- Outputs ------------------------------------------------------------

    def _emit_outputs(self, installer_s3_uri: str | None) -> None:
        CfnOutput(
            self,
            "InstanceId",
            description="Demo PRTG instance.",
            value=self.instance.instance_id,
        )
        CfnOutput(
            self,
            "PrivateIp",
            description=(
                "PRTG private address. This MUST match prtg.host_cidr in your config, "
                "because the Lambda egress rule is a /32. A mismatch produces "
                "'Could not reach PRTG' with a security group that looks correct."
            ),
            value=self.private_ip,
        )
        CfnOutput(
            self,
            "SubnetId",
            description=(
                "Subnet PRTG was placed in. The pinned private address must fall inside this subnet's range."
            ),
            value=self.subnet.subnet_id,
        )
        CfnOutput(
            self,
            "RequiredConfig",
            description="Set these in your configuration, then redeploy the MCP server stack.",
            value=(
                f"prtg.reachability=same-vpc  prtg.host_cidr={self.private_ip}/32  "
                "prtg.verify_tls=false (first pass only)"
            ),
        )
        CfnOutput(
            self,
            "ConnectCommand",
            description="Open a shell on the instance. No RDP and no key pair are configured.",
            value=f"aws ssm start-session --target {self.instance.instance_id} --region {self.region}",
        )
        if self.ssm_endpoints:
            created = ", ".join(sorted(self.ssm_endpoints))
            # Named rather than assumed: `ssm` is absent here when the shared stack
            # already created it, which happens when a private deployment fans out.
            reused = sorted({"ssm", "ssmmessages", "ec2messages"} - set(self.ssm_endpoints))
            shared_note = (
                (
                    f" The {', '.join(reused)} endpoint already existed in this VPC because the "
                    "deployment itself needs it, so it is reused and these hosts were granted "
                    "access to it -- only one endpoint per service per VPC may enable private DNS."
                )
                if reused
                else ""
            )
            CfnOutput(
                self,
                "SessionManagerAccess",
                description="How Session Manager reaches these hosts with no internet route.",
                # ASCII only; see the note on PrtgSniRequirement.
                value=(
                    f"network.mode is private, so this stack created the {created} interface "
                    f"endpoint(s).{shared_note} Session Manager is the only way in (no RDP ingress "
                    "exists) and without these the agent cannot register, so the hosts would boot, "
                    "pass their status checks and be unreachable with nothing reporting why. Allow "
                    "a few minutes after launch before the instance appears in "
                    "'aws ssm describe-instance-information'."
                ),
            )
        CfnOutput(
            self,
            "PostInstallSteps",
            description="After running the installer, in the PRTG web interface.",
            value=(
                "1. Setup > System Administration > User Interface > Web Server: enable HTTPS. "
                "2. Create a READ-ONLY user. "
                "3. Get a passhash from /api/getpasshash.htm. "
                "4. Add 2-3 sensors, or get_sensors returns an empty list. "
                "5. Write the credential to the prtg-mcp/credentials secret."
            ),
        )

        if installer_s3_uri:
            CfnOutput(
                self,
                "InstallerLocation",
                description="Staged by user data on first boot.",
                value=f"C:\\Install ({installer_s3_uri})",
            )
        else:
            CfnOutput(
                self,
                "InstallerUpload",
                description=(
                    "No installer_s3_uri was given, so nothing was staged. Upload the installer "
                    "and pass -c prtg_installer_s3=s3://bucket/key, or copy it in over SSM."
                ),
                value="aws s3 cp PRTG-Installer.exe s3://<bucket>/prtg/ --region " + self.region,
            )

        CfnOutput(
            self,
            "TlsWarning",
            description="Read before setting prtg.verify_tls to true.",
            value=(
                "PRTG ships a self-signed certificate with subject 'PRTG Demo Certificate' and a "
                "single alternative name of 'localhost', so it matches no address you would reach "
                "PRTG on. Its private key is also in every copy of the installer, so trusting it "
                "would give you encryption with no authentication. Replace it with a certificate "
                "whose key you hold, carrying a subjectAltName that matches what prtg_url uses -- "
                "an IP SAN for this instance address works and needs no DNS at all -- then put that "
                "certificate in a secret and set secret.ca_bundle_secret_arn. Verified working "
                "against this exact setup; see docs/prtg-setup.md for the procedure."
            ),
        )

        if self.app_server is not None:
            self._emit_app_server_outputs()

    def _emit_app_server_outputs(self) -> None:
        assert self.app_server is not None  # noqa: S101 - guarded by the caller
        assert self.app_server_ip is not None  # noqa: S101 - guarded by the caller

        CfnOutput(
            self,
            "AppServerInstanceId",
            description="Demo monitored host, for PRTG to point WMI sensors at.",
            value=self.app_server.instance_id,
        )
        CfnOutput(
            self,
            "AppServerPrivateIp",
            description="Add this address to PRTG as a device, then add WMI sensors to it.",
            value=self.app_server_ip,
        )
        CfnOutput(
            self,
            "AppServerConnectCommand",
            description="Open a shell on the monitored host, to set its local Administrator password.",
            value=(f"aws ssm start-session --target {self.app_server.instance_id} --region {self.region}"),
        )
        CfnOutput(
            self,
            "AppServerCredentialSetup",
            description=(
                "The step that is easy to get wrong. Both firewalls are already configured by "
                "this stack; credentials are not, and cannot be."
            ),
            value=(
                "In PRTG, on the device, set Credentials for Windows Systems. Domain or Computer "
                "Name MUST NOT be empty: use the host computer name, which you can read with "
                "'hostname' over SSM. A blank value makes PRTG fail locally with 80070005 and no "
                "logon attempt ever reaches the host. Note credentials inherit, so a probe or "
                "group override shadows anything set on Root. See docs/network-ports.md."
            ),
        )


# --- Helpers ----------------------------------------------------------------


def _validate_ipv4(value: str, *, field_name: str = "prtg_private_ip") -> str:
    """Check ``value`` is a bare IPv4 address.

    Caught here rather than by CloudFormation, because a malformed address surfaces
    several minutes into a deployment as an opaque EC2 error.

    Args:
        value: The address to check.
        field_name: The context flag to name in the error, so the message points at
            the thing the operator actually typed.

    Raises:
        ValueError: if ``value`` is not a bare IPv4 address.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        hint = ""
        if "/" in value:
            hint = " Pass a bare address, not a CIDR range."
        raise ValueError(f"{field_name}={value!r} is not a valid IP address.{hint}") from None

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError(f"{field_name}={value!r} must be IPv4.")
    return value


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    """Split ``s3://bucket/key`` into its parts.

    Raises:
        ValueError: if the URI is not a well-formed S3 object URI.
    """
    if not uri.startswith("s3://"):
        raise ValueError(f"prtg_installer_s3 must start with 's3://', got {uri!r}.")
    remainder = uri[len("s3://") :]
    if "/" not in remainder:
        raise ValueError(
            f"prtg_installer_s3 must name an object, not just a bucket, got {uri!r}. "
            "Example: s3://my-bucket/prtg/PRTG-Installer.exe"
        )
    bucket, key = remainder.split("/", 1)
    if not bucket or not key:
        raise ValueError(f"prtg_installer_s3 is malformed: {uri!r}.")
    return bucket, key
