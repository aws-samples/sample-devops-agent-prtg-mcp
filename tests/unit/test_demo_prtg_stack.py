"""Tests for the optional demo PRTG server stack.

This stack is explicitly labelled demo-only, but it still runs a Windows server that
holds monitoring credentials, so the properties asserted here are the ones whose
absence would make it genuinely dangerous rather than merely unsupported: no RDP, no
public address, no unencrypted disk, and an ingress rule that admits the tool function
and nothing else.

The pinned-address assertions matter for a different reason. The Lambda's egress is a
``/32``, so an address that drifts turns every tool call into a timeout while the
security group still reads correctly. That failure is slow to diagnose by hand, so it
is worth catching here.
"""

from __future__ import annotations

import dataclasses
import json
import os

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template
from infrastructure.config import FanoutRoute, dataclass_replace, load_config
from infrastructure.stacks.demo_prtg_stack import (
    ICMP_ECHO_FIREWALL_RULE_NAME,
    WMI_FIREWALL_RULE_NAMES,
    DemoPrtgStack,
    _parse_s3_uri,
    _validate_ipv4,
)
from infrastructure.stacks.shared_stack import SharedStack

#: Set at import, before any load_config call, as test_infrastructure.py and
#: test_agent_registration.py also do.
#:
#: Without this, the module only passes as part of the full suite, because it relies on
#: some *other* test module having set these first -- pytest imports every module before
#: running anything, so whichever one happens to set them wins. Running this file alone
#: failed with a ConfigError about DEVOPS_AGENT_SPACE_ID. setdefault so CI's own values
#: still take precedence.
os.environ.setdefault("DEVOPS_AGENT_SPACE_ID", "as-example-001")
os.environ.setdefault("PRTG_SOURCE_IP", "203.0.113.7")
os.environ.setdefault("PRTG_PRIVATE_IP", "10.0.2.50")

PRIVATE_IP = "10.0.2.50"
APP_SERVER_IP = "10.0.2.45"


def _build(
    *,
    config_path: str = "config/default.yaml",
    private_ip: str = PRIVATE_IP,
    installer_s3_uri: str | None = None,
    subnet_id: str | None = None,
    with_app_server: bool = False,
    app_server_ip: str | None = APP_SERVER_IP,
) -> tuple[Template, DemoPrtgStack]:
    """Synthesise the demo stack on top of a real shared stack."""
    config = load_config(config_path)
    app = cdk.App()
    env = cdk.Environment(account="123456789012", region=config.region)

    shared = SharedStack(app, f"{config.name_prefix}-shared", config=config, env=env)
    demo = DemoPrtgStack(
        app,
        f"{config.name_prefix}-demo-prtg",
        config=config,
        network=shared.network,
        private_ip=private_ip,
        subnet_id=subnet_id,
        installer_s3_uri=installer_s3_uri,
        with_app_server=with_app_server,
        app_server_ip=app_server_ip,
        env=env,
    )
    # Every stack must be built before any template is extracted: Template.from_stack
    # synthesises the whole app, and constructing a stack afterwards raises
    # ConstructTreeModifiedAfterSynth.
    return Template.from_stack(demo), demo


# --- Network exposure -------------------------------------------------------


def test_no_public_ip() -> None:
    """A public address would put a Windows box holding credentials on the internet."""
    template, _ = _build()
    template.has_resource_properties(
        "AWS::EC2::Instance",
        {"NetworkInterfaces": Match.array_with([Match.object_like({"AssociatePublicIpAddress": False})])},
    )


def test_no_rdp_ingress() -> None:
    """Access is via SSM Session Manager, so 3389 must never be open."""
    template, _ = _build()
    groups = template.find_resources("AWS::EC2::SecurityGroup")
    for logical_id, resource in groups.items():
        for rule in resource["Properties"].get("SecurityGroupIngress", []):
            assert rule.get("FromPort") != 3389, f"{logical_id} exposes RDP"
            assert rule.get("ToPort") != 3389, f"{logical_id} exposes RDP"


def test_ingress_is_from_lambda_group_only() -> None:
    """Exactly one inbound rule, on 443, sourced from a security group not a CIDR.

    Sourcing from the Lambda's group rather than the VPC range means nothing else
    sharing the subnet can reach PRTG.
    """
    template, _ = _build()
    ingress = template.find_resources("AWS::EC2::SecurityGroupIngress")

    prtg_rules = [
        r["Properties"]
        for r in ingress.values()
        if r["Properties"].get("FromPort") == 443 and "SourceSecurityGroupId" in r["Properties"]
    ]
    assert len(prtg_rules) == 1, f"expected one group-sourced 443 rule, got {len(prtg_rules)}"
    assert "CidrIp" not in prtg_rules[0], "PRTG ingress must not be sourced from a CIDR"


def test_no_key_pair() -> None:
    """A key pair implies RDP, which is deliberately not reachable."""
    template, _ = _build()
    instances = template.find_resources("AWS::EC2::Instance")
    for logical_id, resource in instances.items():
        assert "KeyName" not in resource["Properties"], f"{logical_id} has a key pair"


# --- Host hardening --------------------------------------------------------


def test_imdsv2_required() -> None:
    """IMDSv1 leaves role credentials reachable through SSRF in the PRTG web UI."""
    template, _ = _build()
    template.resource_count_is("AWS::EC2::LaunchTemplate", 1)
    template.has_resource_properties(
        "AWS::EC2::LaunchTemplate",
        {
            "LaunchTemplateData": Match.object_like(
                {"MetadataOptions": Match.object_like({"HttpTokens": "required"})}
            )
        },
    )


def test_root_volume_encrypted() -> None:
    """PRTG stores credentials for everything it monitors, on this disk."""
    template, _ = _build()
    template.has_resource_properties(
        "AWS::EC2::Instance",
        {
            "BlockDeviceMappings": Match.array_with(
                [Match.object_like({"Ebs": Match.object_like({"Encrypted": True})})]
            )
        },
    )


def test_instance_has_ssm_access() -> None:
    """Session Manager is the only way in, so its policy must be attached."""
    template, _ = _build()
    template.has_resource_properties(
        "AWS::IAM::Role",
        {
            "ManagedPolicyArns": Match.array_with(
                [
                    Match.object_like(
                        {
                            "Fn::Join": Match.array_with(
                                [
                                    Match.array_with(
                                        [Match.string_like_regexp(".*AmazonSSMManagedInstanceCore")]
                                    )
                                ]
                            )
                        }
                    )
                ]
            )
        },
    )


# --- Pinned address --------------------------------------------------------


def test_private_ip_is_pinned() -> None:
    """The Lambda egress is a /32, so the address must not be allowed to drift."""
    template, demo = _build()
    assert demo.private_ip == PRIVATE_IP
    template.has_resource_properties(
        "AWS::EC2::Instance",
        {"NetworkInterfaces": Match.array_with([Match.object_like({"PrivateIpAddress": PRIVATE_IP})])},
    )


def test_placed_in_exactly_one_subnet() -> None:
    """A pinned address is only valid inside one subnet's range."""
    _, demo = _build()
    assert demo.subnet is not None


@pytest.mark.parametrize("bad", ["10.0.2.50/32", "not-an-ip", "", "300.1.1.1", "::1"])
def test_invalid_private_ip_is_rejected(bad: str) -> None:
    """Rejected at synthesis, since EC2 reports this minutes into a deployment."""
    with pytest.raises(ValueError, match="prtg_private_ip"):
        _validate_ipv4(bad)


def test_cidr_gets_a_specific_hint() -> None:
    """Passing a CIDR is the likely mistake, given host_cidr sits next to it."""
    with pytest.raises(ValueError, match="bare address, not a CIDR"):
        _validate_ipv4("10.0.2.50/32")


def test_unknown_subnet_is_rejected() -> None:
    """A subnet outside the deployment would silently break the pinned address."""
    with pytest.raises(ValueError, match="prtg_subnet"):
        _build(subnet_id="subnet-does-not-exist")


# --- Session Manager reachability in a VPC with no internet route -----------


class TestSsmEndpoints:
    """These hosts have no RDP ingress, so Session Manager is the only way in.

    In `nat` mode the NAT gateway carries the agent's traffic. In `private` mode there is
    no route at all, and without interface endpoints the agent never registers: the
    instances boot, pass their status checks, look healthy and are unreachable, with
    nothing reporting why. Found the hard way -- they had to be created by hand before an
    isolated-VPC deployment could be administered at all.
    """

    PRIVATE_CONFIG = "config/regulated-private.yaml"
    PRIVATE_HOST_IP = "10.50.12.40"

    def test_private_mode_creates_the_three_session_manager_endpoints(self) -> None:
        """All three are required: ssm and ssmmessages for the session, ec2messages for
        Run Command. Two out of three leaves the host just as unreachable."""
        template, _ = _build(config_path=self.PRIVATE_CONFIG, private_ip=self.PRIVATE_HOST_IP)

        template.resource_count_is("AWS::EC2::VPCEndpoint", 3)
        services = {
            r["Properties"]["ServiceName"]
            for r in template.find_resources("AWS::EC2::VPCEndpoint").values()
            if isinstance(r["Properties"].get("ServiceName"), str)
        }
        assert {s.rsplit(".", 1)[-1] for s in services} == {"ssm", "ssmmessages", "ec2messages"}

    def test_nat_mode_creates_none(self) -> None:
        """The NAT gateway already carries it, so three endpoints would be pure cost."""
        template, _ = _build()  # config/default.yaml is nat mode
        template.resource_count_is("AWS::EC2::VPCEndpoint", 0)

    def test_private_dns_is_enabled(self) -> None:
        """The agent resolves the public hostname, so without this the endpoints exist
        and are never used."""
        template, _ = _build(config_path=self.PRIVATE_CONFIG, private_ip=self.PRIVATE_HOST_IP)
        for r in template.find_resources("AWS::EC2::VPCEndpoint").values():
            assert r["Properties"]["PrivateDnsEnabled"] is True

    def test_the_endpoints_admit_the_demo_hosts_and_not_the_whole_vpc(self) -> None:
        """CDK's implicit rule would open the endpoints to the entire VPC CIDR.

        That is wider than a testing affordance warrants, and in a VPC shared with real
        workloads it would hand every one of them a path in.
        """
        template, demo = _build(
            config_path=self.PRIVATE_CONFIG,
            private_ip=self.PRIVATE_HOST_IP,
            with_app_server=True,
            app_server_ip="10.50.12.41",
        )

        groups = template.find_resources(
            "AWS::EC2::SecurityGroup",
            Match.object_like({"Properties": {"GroupName": "prtg-mcp-demo-ssm-vpce-sg"}}),
        )
        assert len(groups) == 1

        # One rule per demo host: PRTG, and the monitored server when it exists.
        ingress = template.find_resources(
            "AWS::EC2::SecurityGroupIngress",
            Match.object_like({"Properties": {"Description": Match.string_like_regexp("SSM endpoints")}}),
        )
        assert len(ingress) == 2

        # Every one of them names a source security group rather than a range. Asserted
        # per rule rather than by scanning the group, because allow_all_outbound=False
        # makes CDK emit a placeholder 255.255.255.255/32 egress rule that a whole-group
        # search would trip over.
        for rule in ingress.values():
            props = rule["Properties"]
            assert "SourceSecurityGroupId" in props
            assert "CidrIp" not in props
            assert props["FromPort"] == 443

    def test_without_an_app_server_only_prtg_is_admitted(self) -> None:
        template, _ = _build(config_path=self.PRIVATE_CONFIG, private_ip=self.PRIVATE_HOST_IP)
        ingress = template.find_resources(
            "AWS::EC2::SecurityGroupIngress",
            Match.object_like({"Properties": {"Description": Match.string_like_regexp("SSM endpoints")}}),
        )
        assert len(ingress) == 1


class TestSsmEndpointCollisionWithFanout:
    """`private` + `fanout` makes the shared stack want `ssm` too, and two is rejected.

    AWS permits only one interface endpoint per service per VPC to enable private DNS, and
    both of these need it. So a private fan-out deployment with `-c demo_prtg=true`
    synthesised two `com.amazonaws.<region>.ssm` endpoints in one VPC and failed at deploy
    time on the second.

    Latent for a while, because no shipped config is both private and fanout --
    `multi-account-fanout.yaml` is `nat` and `regulated-private.yaml` is `single` -- so
    nothing exercised the pairing. Found by synthesising it deliberately.
    """

    @staticmethod
    def _fanout_private() -> tuple[Template, Template]:
        """Synthesise private + fanout + demo, returning the demo and shared templates."""
        base = load_config(TestSsmEndpoints.PRIVATE_CONFIG)
        config = dataclass_replace(
            base,
            targeting=dataclasses.replace(
                base.targeting,
                mode="fanout",
                agent_space_id=None,
                organization_id="o-abcdefghij",
                routes=(FanoutRoute(match="DEFAULT", account_id="222233334444", agent_space_id="as-a"),),
            ),
        )
        assert "ssm" in config.required_vpc_endpoints, "precondition: the shared stack wants ssm"

        app = cdk.App()
        env = cdk.Environment(account="123456789012", region=config.region)
        shared = SharedStack(app, f"{config.name_prefix}-shared", config=config, env=env)
        demo = DemoPrtgStack(
            app,
            f"{config.name_prefix}-demo-prtg",
            config=config,
            network=shared.network,
            private_ip=TestSsmEndpoints.PRIVATE_HOST_IP,
            with_app_server=True,
            app_server_ip="10.50.12.41",
            env=env,
        )
        return Template.from_stack(demo), Template.from_stack(shared)

    def test_the_demo_stack_does_not_duplicate_the_shared_ssm_endpoint(self) -> None:
        demo, shared = self._fanout_private()

        def services(template: Template) -> set[str]:
            return {
                r["Properties"]["ServiceName"].rsplit(".", 1)[-1]
                for r in template.find_resources("AWS::EC2::VPCEndpoint").values()
                if isinstance(r["Properties"].get("ServiceName"), str)
            }

        assert "ssm" in services(shared), "the shared stack owns it, for the routing lookup"
        assert services(demo) == {"ssmmessages", "ec2messages"}, "ssm must not be created twice"

    def test_the_demo_hosts_are_granted_access_to_the_shared_endpoint(self) -> None:
        """Reusing the endpoint is not enough: its group admits only the functions.

        Without this the hosts resolve it through private DNS and are dropped at the
        security group -- the same flow-logs-only failure the endpoints exist to prevent.
        """
        demo, _ = self._fanout_private()

        rules = demo.find_resources(
            "AWS::EC2::SecurityGroupIngress",
            Match.object_like(
                {"Properties": {"Description": Match.string_like_regexp("shared ssm interface endpoint")}}
            ),
        )
        assert len(rules) == 2, "one per demo host: PRTG and the monitored server"
        for rule in rules.values():
            props = rule["Properties"]
            assert props["FromPort"] == 443
            assert "SourceSecurityGroupId" in props
            assert "CidrIp" not in props, "must name the host group, not a range"

    def test_the_rule_lives_in_the_demo_stack_so_the_stacks_stay_acyclic(self) -> None:
        """The natural spelling creates a dependency cycle CloudFormation refuses.

        `peer.connections.allow_to(shared_group, ...)` puts an ingress rule referencing
        this stack's groups into the *shared* stack, while the demo stack already imports
        the shared VPC. Importing the group by id instead keeps the rule here and pointing
        one way only.
        """
        demo, shared = self._fanout_private()

        assert (
            shared.find_resources(
                "AWS::EC2::SecurityGroupIngress",
                Match.object_like(
                    {"Properties": {"Description": Match.string_like_regexp("demo Windows host")}}
                ),
            )
            == {}
        ), "the shared stack must not reference the demo stack"

        assert json.dumps(shared.to_json()).count("Fn::ImportValue") == 0
        assert "Fn::ImportValue" in json.dumps(demo.to_json())


def test_address_outside_the_lambda_egress_range_is_rejected() -> None:
    """The one mismatch that deploys cleanly and then fails every tool call.

    ``config/default.yaml`` scopes the tool function's egress to a single ``/32``. An
    address outside it leaves every resource healthy and every call timing out on a
    security group drop, which appears nowhere but VPC flow logs.

    This is not hypothetical: the shipped defaults disagreed. The demo server pinned
    10.0.2.50 while the config scoped egress to 10.0.1.10/32 - different subnets, one
    public and one private - so the README's own evaluation one-liner produced exactly
    this dead end. An output said the two "MUST match" and nothing enforced it.
    """
    with pytest.raises(ValueError, match="outside prtg.host_cidr"):
        _build(private_ip="10.0.3.99")


def test_the_default_demo_address_is_reachable_from_the_lambda() -> None:
    """Pins the agreement between app.py's default and the default config.

    They are edited in different files for different reasons, so nothing but a test
    keeps them together.
    """
    from app import DEFAULT_DEMO_PRTG_IP

    config = load_config("config/default.yaml")
    assert config.prtg.egress_cidr == f"{DEFAULT_DEMO_PRTG_IP}/32"
    # Synthesises rather than merely comparing strings, so the cross-check itself is
    # exercised on the happy path too.
    _build(private_ip=DEFAULT_DEMO_PRTG_IP)


# --- Installer staging -----------------------------------------------------


def test_installer_policy_is_scoped_to_one_object() -> None:
    """Read on the whole bucket would be broader than staging one file needs."""
    template, _ = _build(installer_s3_uri="s3://my-bucket/prtg/installer.exe")
    template.has_resource_properties(
        "AWS::IAM::Policy",
        {
            "PolicyDocument": Match.object_like(
                {
                    "Statement": Match.array_with(
                        [
                            Match.object_like(
                                {
                                    "Sid": "ReadPrtgInstaller",
                                    "Action": "s3:GetObject",
                                    # The partition renders as an Fn::Join, so match the
                                    # object suffix. The point of the assertion is that
                                    # it names one object and not a bucket wildcard.
                                    "Resource": Match.object_like(
                                        {
                                            "Fn::Join": Match.array_with(
                                                [Match.array_with([":s3:::my-bucket/prtg/installer.exe"])]
                                            )
                                        }
                                    ),
                                }
                            )
                        ]
                    )
                }
            )
        },
    )


def test_no_s3_policy_without_installer() -> None:
    """Nothing is granted when no installer was supplied."""
    template, _ = _build()
    policies = template.find_resources("AWS::IAM::Policy")
    for resource in policies.values():
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]:
            assert statement.get("Sid") != "ReadPrtgInstaller"


@pytest.mark.parametrize(
    "uri",
    ["my-bucket/x.exe", "s3://my-bucket", "s3://", "https://my-bucket/x.exe", "s3://my-bucket/"],
)
def test_malformed_installer_uri_is_rejected(uri: str) -> None:
    with pytest.raises(ValueError, match="prtg_installer_s3"):
        _parse_s3_uri(uri)


def test_installer_uri_parses() -> None:
    assert _parse_s3_uri("s3://bucket/prtg/PRTG.exe") == ("bucket", "prtg/PRTG.exe")


# --- Outputs ---------------------------------------------------------------


def test_outputs_are_ascii() -> None:
    """CloudFormation silently mangles non-ASCII in outputs to '?'.

    Verified during deployment: it affects both value and description, so any hint
    written with typographic punctuation arrives corrupted.
    """
    template, _ = _build()
    for name, output in template.find_outputs("*").items():
        for field in ("Value", "Description"):
            value = output.get(field)
            if isinstance(value, str):
                assert value.isascii(), f"output {name}.{field} contains non-ASCII"


def test_outputs_state_the_required_config() -> None:
    """The pinned address has to reach prtg.host_cidr or every tool call times out."""
    template, _ = _build()
    outputs = template.find_outputs("*")
    combined = " ".join(str(o.get("Value", "")) + str(o.get("Description", "")) for o in outputs.values())
    assert "host_cidr" in combined
    assert PRIVATE_IP in combined


def test_outputs_warn_about_the_certificate_name() -> None:
    """PRTG's self-signed certificate names the hostname, so verifying against the IP fails."""
    template, _ = _build()
    combined = " ".join(
        str(o.get("Value", "")) + str(o.get("Description", "")) for o in template.find_outputs("*").values()
    )
    assert "self-signed" in combined
    assert "verify_tls" in combined


# --- Framing ---------------------------------------------------------------


def test_tagged_as_not_production() -> None:
    """The topology is single-instance with no backup or patching. Say so on the resource."""
    template, _ = _build()
    template.has_resource_properties(
        "AWS::EC2::Instance",
        {"Tags": Match.array_with([Match.object_like({"Key": "NotProduction", "Value": "true"})])},
    )


# --- Monitored host: presence ----------------------------------------------


def _app_server_ingress(template: Template) -> list[dict]:
    """Standalone ingress rules belonging to the monitored host's group."""
    return [
        resource["Properties"]
        for logical_id, resource in template.find_resources("AWS::EC2::SecurityGroupIngress").items()
        if logical_id.startswith("AppServerSecurityGroup")
    ]


def test_app_server_absent_by_default() -> None:
    """A second Windows instance costs money, so it must be opt-in."""
    template, demo = _build()
    assert demo.app_server is None
    assert demo.app_server_security_group is None
    assert demo.app_server_ip is None
    template.resource_count_is("AWS::EC2::Instance", 1)
    assert _app_server_ingress(template) == []


def test_app_server_created_when_requested() -> None:
    """The whole point of the flag."""
    template, demo = _build(with_app_server=True)
    assert demo.app_server is not None
    assert demo.app_server_ip == APP_SERVER_IP
    template.resource_count_is("AWS::EC2::Instance", 2)


# --- Monitored host: the ports that actually matter -------------------------


def test_snmp_ingress_is_udp_not_tcp() -> None:
    """SNMP is UDP. A tcp/161 rule looks plausible and permits nothing at all.

    This is not hypothetical: the hand-built security group this stack replaces had
    exactly that mistake, and it is invisible until someone adds an SNMP sensor.
    """
    template, _ = _build(with_app_server=True)
    rules = _app_server_ingress(template)

    udp_161 = [r for r in rules if r.get("IpProtocol") == "udp" and r.get("FromPort") == 161]
    tcp_161 = [r for r in rules if r.get("IpProtocol") == "tcp" and r.get("FromPort") == 161]

    assert len(udp_161) == 1, "SNMP must be permitted over UDP"
    assert tcp_161 == [], "a tcp/161 rule permits nothing and implies SNMP works"


def test_rpc_dynamic_range_is_open() -> None:
    """Port 135 alone gets an authenticated session and then 800706BA.

    DCOM negotiates on 135 and is redirected to a port from the dynamic range. Opening
    only 135 produces a successful logon on the target followed by 'The RPC server is
    unavailable', which reads like a credential problem and is not one.
    """
    template, _ = _build(with_app_server=True)
    rules = _app_server_ingress(template)

    assert any(r.get("FromPort") == 135 and r.get("IpProtocol") == "tcp" for r in rules), (
        "the RPC endpoint mapper must be reachable"
    )
    assert any(
        r.get("IpProtocol") == "tcp" and r.get("FromPort") == 49152 and r.get("ToPort") == 65535
        for r in rules
    ), "the RPC dynamic range must be reachable, or WMI fails after authenticating"


def test_smb_is_open_for_performance_counters() -> None:
    """The PRTG sensors that read performance counters need Remote Registry over SMB."""
    template, _ = _build(with_app_server=True)
    rules = _app_server_ingress(template)
    assert any(r.get("FromPort") == 445 and r.get("IpProtocol") == "tcp" for r in rules)


def test_icmp_echo_is_open_for_ping_sensors() -> None:
    """A PRTG device with no reachable ICMP shows down before any sensor is added."""
    template, _ = _build(with_app_server=True)
    rules = _app_server_ingress(template)
    assert any(r.get("IpProtocol") == "icmp" and r.get("FromPort") == 8 for r in rules)


# --- Monitored host: exposure ----------------------------------------------


def test_app_server_ingress_is_from_prtg_group_only() -> None:
    """Sourcing from PRTG's group means nothing else in the subnet can reach it.

    The dynamic range is 16,000 ports wide, so the source restriction is doing more
    work here than on a single-port rule.
    """
    template, _ = _build(with_app_server=True)
    rules = _app_server_ingress(template)
    assert rules, "expected ingress rules on the monitored host"

    for rule in rules:
        assert "SourceSecurityGroupId" in rule, f"rule is not group-sourced: {rule}"
        assert "CidrIp" not in rule, f"rule admits a CIDR: {rule}"


def test_app_server_has_no_rdp_on_either_resource_type() -> None:
    """Access is via SSM. Checks standalone rules too, not just inline ones."""
    template, _ = _build(with_app_server=True)

    for resource in template.find_resources("AWS::EC2::SecurityGroupIngress").values():
        properties = resource["Properties"]
        from_port, to_port = properties.get("FromPort"), properties.get("ToPort")
        if isinstance(from_port, int) and isinstance(to_port, int):
            assert not (from_port <= 3389 <= to_port), f"3389 is reachable via {properties}"

    for resource in template.find_resources("AWS::EC2::SecurityGroup").values():
        for rule in resource["Properties"].get("SecurityGroupIngress", []) or []:
            assert rule.get("FromPort") != 3389


def test_app_server_has_no_public_ip() -> None:
    """It is a monitoring target on a private subnet, not an internet-facing host."""
    template, _ = _build(with_app_server=True)
    instances = template.find_resources("AWS::EC2::Instance")
    for logical_id, resource in instances.items():
        for interface in resource["Properties"].get("NetworkInterfaces", []):
            assert interface.get("AssociatePublicIpAddress") is False, f"{logical_id} is public"


def test_app_server_volume_encrypted() -> None:
    """Consistent with the PRTG host; an unencrypted volume would be an odd exception."""
    template, _ = _build(with_app_server=True)
    instances = template.find_resources("AWS::EC2::Instance")
    assert len(instances) == 2
    for logical_id, resource in instances.items():
        mappings = resource["Properties"].get("BlockDeviceMappings", [])
        assert mappings, f"{logical_id} has no block device mapping"
        for mapping in mappings:
            assert mapping["Ebs"]["Encrypted"] is True, f"{logical_id} volume is not encrypted"


def test_app_server_shares_the_prtg_subnet() -> None:
    """Both addresses are pinned, so they have to sit in one subnet's range."""
    template, _ = _build(with_app_server=True)
    # The VPC is created by this deployment, so SubnetId is an unresolved ref rather
    # than a string. Compare the serialised form.
    subnets = {
        json.dumps(interface.get("SubnetId"), sort_keys=True)
        for resource in template.find_resources("AWS::EC2::Instance").values()
        for interface in resource["Properties"].get("NetworkInterfaces", [])
    }
    assert len(subnets) == 1, f"instances are spread across subnets: {subnets}"


# --- Monitored host: the host firewall, which the SG does not cover ---------


def test_user_data_enables_service_scoped_wmi_rules() -> None:
    """The security group is only half of it; Windows has its own firewall.

    Service-scoped rules rather than port-scoped ones, because a port rule for a
    narrowed dynamic range is only correct if the OS range was pinned to match, which
    is a separate registry change and a reboot.
    """
    template, _ = _build(with_app_server=True)
    rendered = json.dumps(template.to_json())

    for rule_name in (*WMI_FIREWALL_RULE_NAMES, ICMP_ECHO_FIREWALL_RULE_NAME):
        assert rule_name in rendered, f"user data does not enable {rule_name}"

    assert "Enable-NetFirewallRule" in rendered
    assert "Set-NetFirewallRule" in rendered


def test_user_data_scopes_host_firewall_to_prtg() -> None:
    """Enabling the built-in rules unscoped would admit any address in the VPC."""
    template, _ = _build(with_app_server=True)
    rendered = json.dumps(template.to_json())
    assert f"-RemoteAddress {PRIVATE_IP}" in rendered


# --- Monitored host: address validation ------------------------------------


def test_app_server_requires_an_address() -> None:
    """Silently defaulting it would risk colliding with something already deployed."""
    with pytest.raises(ValueError, match="demo_app_server"):
        _build(with_app_server=True, app_server_ip=None)


def test_app_server_address_must_differ_from_prtg() -> None:
    """Two instances cannot share a private address, and EC2 says so late and opaquely."""
    with pytest.raises(ValueError, match="same address"):
        _build(with_app_server=True, app_server_ip=PRIVATE_IP)


@pytest.mark.parametrize("bad", ["10.0.2.45/32", "not-an-ip", "", "300.1.1.1", "::1"])
def test_invalid_app_server_ip_is_rejected(bad: str) -> None:
    """Named after the flag the operator typed, not the field it lands in."""
    with pytest.raises(ValueError, match="demo_app_server_ip"):
        _validate_ipv4(bad, field_name="demo_app_server_ip")


# --- Monitored host: outputs -----------------------------------------------


def test_app_server_outputs_name_the_credential_trap() -> None:
    """Both firewalls are configured by this stack. Credentials are not, and cannot be.

    An empty 'Domain or Computer Name' makes PRTG fail locally with 80070005 and never
    contact the host at all, so the output has to say so.
    """
    template, _ = _build(with_app_server=True)
    outputs = template.find_outputs("*")
    combined = " ".join(
        str(output.get("Value", "")) + str(output.get("Description", "")) for output in outputs.values()
    )
    assert "Domain or Computer" in combined
    assert "80070005" in combined
    assert APP_SERVER_IP in combined


def test_app_server_outputs_are_ascii() -> None:
    """CloudFormation silently mangles non-ASCII in outputs to '?'."""
    template, _ = _build(with_app_server=True)
    for name, output in template.find_outputs("*").items():
        for field in ("Value", "Description"):
            value = output.get(field)
            if isinstance(value, str):
                assert value.isascii(), f"output {name}.{field} contains non-ASCII"


def test_app_server_tagged_as_not_production() -> None:
    """Same framing as the PRTG host: single instance, no backup, no patching."""
    template, _ = _build(with_app_server=True)
    instances = template.find_resources("AWS::EC2::Instance")
    for logical_id, resource in instances.items():
        tags = {tag["Key"]: tag["Value"] for tag in resource["Properties"].get("Tags", [])}
        assert tags.get("NotProduction") == "true", f"{logical_id} is not marked NotProduction"
