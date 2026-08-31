"""Configuration validation.

The value of the five-knob model rests on catching mistakes here, at synthesis,
with a message naming the field and the remedy - rather than partway through a
CloudFormation deployment, or in a Lambda cold start during an incident.

Each test therefore asserts on the *content* of the message, not just that an error
was raised. A validator that fails with "invalid configuration" is barely better
than no validator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from infrastructure.config import (
    DEVOPS_AGENT_REGIONS,
    ConfigError,
    build_config,
    interpolate_environment,
    load_config,
)

VALID: dict[str, Any] = {
    "region": "ap-southeast-2",
    "targeting": {"mode": "single", "agent_space_id": "as-test-001"},
    "prtg": {"reachability": "same-vpc", "host_cidr": "10.0.1.10/32"},
    "alarm_allowed_source_ips": ["203.0.113.7/32"],
}


def cfg(**overrides: Any) -> Any:
    merged = {**VALID}
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return build_config(merged, source="<test>")


def error_from(**overrides: Any) -> str:
    with pytest.raises(ConfigError) as exc:
        cfg(**overrides)
    return str(exc.value)


# --- Baseline ---------------------------------------------------------------


def test_the_minimal_valid_configuration_validates() -> None:
    config = cfg()
    assert config.network.mode == "nat"
    assert config.auth.mode == "sigv4"
    assert config.secret.mode == "local"
    assert config.targeting.mode == "single"


def test_all_errors_are_reported_at_once() -> None:
    """Fixing five errors across five deploy attempts is a miserable afternoon."""
    message = error_from(
        region="antarctica-1",
        network={"mode": "airgapped"},
        secret={"mode": "external"},
        targeting={"mode": "single", "agent_space_id": None},
    )
    assert "1." in message and "4." in message


def test_errors_point_at_the_deployment_matrix() -> None:
    assert "docs/deployment-matrix.md" in error_from(region="antarctica-1")


# --- Region -----------------------------------------------------------------


@pytest.mark.parametrize("region", sorted(DEVOPS_AGENT_REGIONS))
def test_every_supported_region_is_accepted(region: str) -> None:
    assert cfg(region=region).region == region


def test_an_unsupported_region_lists_the_supported_ones() -> None:
    """Deploying elsewhere builds a Gateway no Agent Space can be pointed at."""
    message = error_from(region="eu-west-2")
    assert "ap-southeast-2" in message
    assert "us-east-1" in message


# --- Credentials never in configuration -------------------------------------


class TestCredentialRejection:
    @pytest.mark.parametrize(
        "payload",
        [
            {"secret": {"prtg_passhash": "abc123"}},
            {"prtg": {"password": "hunter2"}},
            {"secret": {"prtg_username": "admin"}},
            {"secret": {"prtg_api_key": "UYKEMNKFV4RQYOFVI32SX23DGKL5NQTV"}},
            {"secret": {"api_key": "UYKEMNKFV4RQYOFVI32SX23DGKL5NQTV"}},
            {"prtg": {"apitoken": "UYKEMNKFV4RQYOFVI32SX23DGKL5NQTV"}},
        ],
    )
    def test_a_credential_anywhere_in_the_file_is_rejected(self, payload: dict) -> None:
        """Config files are committed. A credential here reaches git history, every
        clone, and any CI log that echoes the file -- and scrubbing the file does not
        undo it, so rotation becomes the only remedy.

        The API key forms are covered because the key is now the *recommended*
        credential, which makes it the one most likely to be pasted into the wrong
        file. It was missing from the forbidden set at first, on the reasoning that a
        revocable credential matters less. Revocable still means live until somebody
        notices.
        """
        with pytest.raises(ConfigError) as exc:
            build_config({**VALID, **payload}, source="<test>")
        assert "must not live in configuration files" in str(exc.value)

    def test_the_rejection_shows_the_correct_way_to_store_it(self) -> None:
        with pytest.raises(ConfigError) as exc:
            build_config({**VALID, "secret": {"passhash": "x"}}, source="<test>")
        message = str(exc.value)
        assert "put-secret-value" in message
        # Shows the preferred form first, so the remedy also teaches the better habit.
        assert message.index("prtg_api_key") < message.index("prtg_passhash")

    def test_nested_credentials_are_found(self) -> None:
        with pytest.raises(ConfigError):
            build_config({**VALID, "targeting": {"routes": [{"prtg_passhash": "x"}]}}, source="<test>")


# --- Unknown keys -----------------------------------------------------------


def test_an_unknown_top_level_key_is_rejected_with_the_valid_list() -> None:
    """A typo that is silently ignored is worse than an error: the setting appears
    applied and is not."""
    with pytest.raises(ConfigError) as exc:
        build_config({**VALID, "netowrk": {}}, source="<test>")
    message = str(exc.value)
    assert "netowrk" in message
    assert "network" in message


def test_an_unknown_section_key_is_rejected() -> None:
    message = error_from(network={"moed": "nat"})
    assert "moed" in message
    assert "mode" in message


# --- Knob 1: network --------------------------------------------------------


class TestNetwork:
    def test_subnets_require_availability_zones(self) -> None:
        message = error_from(network={"vpc_id": "vpc-0abc", "subnet_ids": ["subnet-0a"]})
        assert "availability_zones is required" in message
        assert "without AWS credentials" in message

    def test_subnet_and_zone_counts_must_match(self) -> None:
        message = error_from(
            network={
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a", "subnet-0b"],
                "availability_zones": ["ap-southeast-2a"],
            }
        )
        assert "matched positionally" in message

    def test_subnets_without_a_vpc_are_rejected(self) -> None:
        assert "network.vpc_id" in error_from(network={"subnet_ids": ["subnet-0a"]})

    def test_supplying_subnets_avoids_a_context_lookup(self) -> None:
        """This is what lets CI synthesise without credentials."""
        with_subnets = cfg(
            network={
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            }
        )
        without = cfg(network={"vpc_id": "vpc-0abc"})
        assert with_subnets.network.requires_context_lookup is False
        assert without.network.requires_context_lookup is True

    def test_a_malformed_cidr_is_rejected(self) -> None:
        assert "not a valid CIDR" in error_from(network={"cidr": "10.0.0.0/64"})


class TestRequiredEndpoints:
    def test_nat_mode_needs_no_endpoints(self) -> None:
        assert cfg().required_vpc_endpoints == ()

    def test_private_mode_creates_every_endpoint_the_functions_need(self) -> None:
        """Pinned as a set, because each omission has its own failure mode and none
        of them says "missing VPC endpoint".

        ``sqs`` is the least obvious and the worst to omit: it is what the alarm
        pipeline uses to park an alarm it could not process, so without it the
        mechanism that exists to stop an alarm being lost is the one thing
        unreachable at the moment it is needed.

        ``aidevops`` was missing entirely until deployment testing found it. Three
        separate private deployments reached parsing and routing and then died on
        CreateBacklogTask, and because a Lambda timeout kills the process rather than
        raising, the dead-letter park never ran and PrtgAlarmsLost could not fire. The
        alarm was simply gone.
        """
        config = cfg(
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            }
        )
        assert set(config.required_vpc_endpoints) == {
            "secretsmanager",
            "logs",
            "lambda",
            "sts",
            "sqs",
            "aidevops-dataplane",
        }

    def test_private_mode_without_the_pipeline_omits_the_agent_endpoint(self) -> None:
        """Only the alarm pipeline calls the DevOps Agent API, so an MCP-only
        deployment should not pay for that endpoint."""
        config = cfg(
            deploy_alarm_pipeline=False,
            alarm_allowed_source_ips=[],
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            },
        )
        assert "aidevops-dataplane" not in config.required_vpc_endpoints

    def test_private_mode_with_fanout_adds_ssm(self) -> None:
        """Fan-out keeps its routing table in an SSM parameter.

        Without this endpoint the routing lookup hangs until the function times out, so
        the alarm is lost before any route is even chosen. routing.py's own error message
        tells the operator to check for an SSM endpoint, which the stack did not create.
        """
        config = cfg(
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            },
            targeting={
                "mode": "fanout",
                "agent_space_id": None,
                "routes": [{"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-a"}],
            },
        )
        assert "ssm" in config.required_vpc_endpoints

    def test_single_target_private_mode_does_not_add_ssm(self) -> None:
        config = cfg(
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            }
        )
        assert "ssm" not in config.required_vpc_endpoints


class TestAgentEndpointUrl:
    """The one endpoint whose private DNS name differs from the SDK's default.

    Every other interface endpoint this stack creates publishes private DNS for exactly
    the hostname boto3 already calls, which is why the Lambda source is identical in both
    network modes. The DevOps Agent endpoints serve names under aidevops.<region>.api.aws
    while boto3 defaults to aidevops.<region>.amazonaws.com, so creating the endpoint is
    necessary but not sufficient -- measured from inside an isolated VPC, the SDK's
    hostname had no answer at all while the endpoint's resolved to an ENI.
    """

    def test_nat_mode_uses_the_sdk_default(self) -> None:
        assert cfg().agent_endpoint_url is None

    def test_private_mode_derives_the_control_plane_endpoint(self) -> None:
        config = cfg(
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            }
        )
        assert config.agent_endpoint_url == f"https://aidevops.{config.region}.api.aws"

    def test_private_mode_without_the_pipeline_needs_no_override(self) -> None:
        config = cfg(
            deploy_alarm_pipeline=False,
            alarm_allowed_source_ips=[],
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            },
        )
        assert config.agent_endpoint_url is None

    def test_an_explicit_override_wins(self) -> None:
        """For FIPS endpoints, another partition, or a future hostname change."""
        config = cfg(targeting={"agent_endpoint_url": "https://aidevops-fips.us-east-1.api.aws"})
        assert config.agent_endpoint_url == "https://aidevops-fips.us-east-1.api.aws"

    def test_the_derived_url_carries_no_operation_prefix(self) -> None:
        """botocore prepends the operation's own hostPrefix, so ours must not include one.

        CreateBacklogTask carries hostPrefix 'dp.'. Supplying the fully-qualified
        'cp.aidevops...' name produced a live request to 'dp.cp.aidevops...' -- botocore
        had stacked its prefix on top of ours. Handing over the un-prefixed base lets it
        build 'dp.aidevops.<region>.api.aws', which is what the dataplane endpoint serves.

        Pinned because the bug is invisible in a template and only appears as a connection
        error at runtime, and because the natural instinct when reading the AWS docs -- which
        list 'cp.aidevops...' and 'dp.aidevops...' as the endpoint names -- is to paste one in.
        """
        config = cfg(
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            }
        )
        url = config.agent_endpoint_url
        assert url is not None
        host = url.removeprefix("https://")
        assert not host.startswith(("dp.", "cp."))
        assert host == f"aidevops.{config.region}.api.aws"

    def test_private_mode_with_cognito_adds_cognito_idp(self) -> None:
        """Cognito tokens are validated from inside the VPC; external providers are
        validated at the AWS service plane and need no endpoint."""
        config = cfg(
            network={
                "mode": "private",
                "vpc_id": "vpc-0abc",
                "subnet_ids": ["subnet-0a"],
                "availability_zones": ["ap-southeast-2a"],
            },
            auth={"mode": "oidc", "provider": "cognito"},
        )
        assert "cognito-idp" in config.required_vpc_endpoints

    def test_a_private_api_needs_execute_api_even_in_nat_mode(self) -> None:
        """Inbound and outbound are separate concerns. A private REST API is only
        reachable through an execute-api endpoint regardless of Lambda egress."""
        config = cfg(alarm_api_private=True)
        assert config.network.mode == "nat"
        assert config.required_vpc_endpoints == ("execute-api",)


# --- Knob 2: auth -----------------------------------------------------------


class TestAuth:
    def test_oidc_requires_a_provider(self) -> None:
        assert "auth.provider must be" in error_from(auth={"mode": "oidc"})

    def test_external_provider_requires_a_discovery_url(self) -> None:
        message = error_from(auth={"mode": "oidc", "provider": "entra"})
        assert "discovery_url is required" in message
        assert "login.microsoftonline.com" in message

    def test_discovery_url_must_end_with_the_well_known_path(self) -> None:
        message = error_from(
            auth={
                "mode": "oidc",
                "provider": "generic",
                "discovery_url": "https://idp.example.com/",
                "allowed_audience": ["a"],
                "allowed_clients": ["c"],
            }
        )
        assert "well-known/openid-configuration" in message

    def test_at_least_one_token_restriction_is_required(self) -> None:
        """With neither, the Gateway accepts any token the provider issued."""
        message = error_from(
            auth={
                "mode": "oidc",
                "provider": "entra",
                "discovery_url": "https://x/.well-known/openid-configuration",
            }
        )
        assert "allowed_audience or auth.allowed_clients is required" in message
        # The message must explain the per-provider difference, because getting this
        # wrong deploys cleanly and then returns 403 forever.
        assert "Cognito" in message
        assert "Entra" in message

    def test_allowed_clients_alone_is_accepted(self) -> None:
        """The correct configuration for a provider that omits `aud`, such as Cognito.

        Requiring an audience here would produce a deployment that succeeds and then
        rejects every call with a bare 403 - verified against a real Gateway.
        """
        config = cfg(
            auth={
                "mode": "oidc",
                "provider": "generic",
                "discovery_url": "https://x/.well-known/openid-configuration",
                "allowed_clients": ["client-id"],
            }
        )
        assert config.auth.allowed_clients == ("client-id",)
        assert config.auth.allowed_audience == ()

    def test_allowed_audience_alone_is_accepted_but_warns(self) -> None:
        """Valid for Entra ID, dangerous for a provider that omits `aud`."""
        config = cfg(
            auth={
                "mode": "oidc",
                "provider": "entra",
                "discovery_url": "https://x/.well-known/openid-configuration",
                "allowed_audience": ["api://client-id"],
            }
        )
        assert any("does not put an 'aud' claim" in w for w in config.warnings)

    def test_both_restrictions_together_do_not_warn(self) -> None:
        config = cfg(
            auth={
                "mode": "oidc",
                "provider": "entra",
                "discovery_url": "https://x/.well-known/openid-configuration",
                "allowed_audience": ["api://client-id"],
                "allowed_clients": ["client-id"],
            }
        )
        assert not any("aud" in w for w in config.warnings)

    def test_cognito_must_not_be_given_a_discovery_url(self) -> None:
        """It is created here and the URL is derived."""
        message = error_from(
            auth={
                "mode": "oidc",
                "provider": "cognito",
                "discovery_url": "https://x/.well-known/openid-configuration",
            }
        )
        assert "created by this stack" in message

    def test_oidc_fields_left_behind_on_sigv4_are_rejected(self) -> None:
        """Otherwise the config reads as though it uses the IdP while IAM is
        silently deployed."""
        message = error_from(
            auth={"mode": "sigv4", "discovery_url": "https://x/.well-known/openid-configuration"}
        )
        assert "silently deploy IAM authentication" in message


# --- Knob 3: secret ---------------------------------------------------------


class TestSecret:
    def test_external_mode_requires_an_arn(self) -> None:
        assert "secret.secret_arn is required" in error_from(secret={"mode": "external"})

    def test_a_malformed_secret_arn_is_rejected(self) -> None:
        assert "Secrets Manager ARN" in error_from(
            secret={"mode": "external", "secret_arn": "prtg-mcp/credentials"}
        )

    def test_an_arn_supplied_in_local_mode_is_rejected(self) -> None:
        """Silently ignoring it would deploy a different secret than intended."""
        message = error_from(
            secret={
                "mode": "local",
                "secret_arn": "arn:aws:secretsmanager:ap-southeast-2:111122223333:secret:x-a1b2c3",
            }
        )
        assert "would be created and the ARN ignored" in message

    def test_a_cross_account_secret_warns_about_the_kms_policy(self) -> None:
        """Granting the resource policy but not the KMS key policy is the usual
        cause of an AccessDenied that reads like an IAM problem."""
        config = cfg(
            account="111122223333",
            secret={
                "mode": "external",
                "secret_arn": "arn:aws:secretsmanager:ap-southeast-2:999988887777:secret:x-a1b2c3",
                "kms_key_arn": "arn:aws:kms:ap-southeast-2:999988887777:key/abc",
            },
        )
        assert any("KMS key policy" in w for w in config.warnings)

    def test_a_cross_account_secret_requires_the_kms_key_arn(self) -> None:
        """Omitting it deploys cleanly and then fails every credential read.

        Cross-account KMS needs the grant on both sides. The key policy is the owner's to
        apply; ``kms:Decrypt`` on the reading role is this stack's, and it cannot be added
        without knowing the key, because an imported secret does not reveal it. The
        resulting failure is ``Access to KMS is not allowed`` -- identical to a missing key
        policy, so it points at the other account. Measured against a real second account
        before this became an error.
        """
        with pytest.raises(ConfigError, match="secret.kms_key_arn is required"):
            cfg(
                account="111122223333",
                secret={
                    "mode": "external",
                    "secret_arn": "arn:aws:secretsmanager:ap-southeast-2:999988887777:secret:x-a1b2c3",
                },
            )

    def test_a_same_account_external_secret_does_not_require_it(self) -> None:
        """Same-account needs no key grant: the AWS managed key covers it, and a
        customer-managed one is reachable through the account's own key policy."""
        config = cfg(
            account="111122223333",
            secret={
                "mode": "external",
                "secret_arn": "arn:aws:secretsmanager:ap-southeast-2:111122223333:secret:x-a1b2c3",
            },
        )
        assert config.secret.kms_key_arn is None


# --- Knob 4: PRTG -----------------------------------------------------------


class TestPrtg:
    def test_an_address_is_required_so_egress_can_be_scoped(self) -> None:
        message = error_from(prtg={"reachability": "same-vpc", "host_cidr": None, "cidr": None})
        assert "scoped to PRTG rather than left open" in message

    def test_remote_reachability_mentions_the_prerequisite_link(self) -> None:
        message = error_from(prtg={"reachability": "remote", "host_cidr": None, "cidr": None})
        assert "Transit Gateway" in message

    def test_host_cidr_must_be_a_single_address(self) -> None:
        assert "single host" in error_from(prtg={"host_cidr": "10.0.0.0/24"})

    def test_disabling_tls_verification_warns(self) -> None:
        config = cfg(prtg={"verify_tls": False})
        assert any("verify_tls is false" in w for w in config.warnings)

    def test_tls_off_plus_remote_prtg_warns_about_the_flagged_combination(self) -> None:
        config = cfg(prtg={"verify_tls": False, "reachability": "remote", "host_cidr": "10.50.1.1/32"})
        assert any("security review" in w for w in config.warnings)

    def test_host_cidr_is_preferred_over_a_range(self) -> None:
        assert cfg(prtg={"host_cidr": "10.0.1.5/32"}).prtg.egress_cidr == "10.0.1.5/32"


# --- Knob 5: targeting -----------------------------------------------------


class TestTargeting:
    def test_single_mode_requires_an_agent_space(self) -> None:
        assert "agent_space_id is required" in error_from(
            targeting={"mode": "single", "agent_space_id": None}
        )

    def test_a_placeholder_agent_space_is_rejected(self) -> None:
        assert "placeholder" in error_from(
            targeting={"mode": "single", "agent_space_id": "<your-agent-space-id>"}
        )

    def test_fanout_requires_routes(self) -> None:
        assert "at least one entry" in error_from(
            targeting={"mode": "fanout", "agent_space_id": None, "routes": []}
        )

    def test_fanout_requires_a_default_route(self) -> None:
        """Without it an alarm from an unmapped group reaches no agent at all, which
        is the worst failure this system can have."""
        message = error_from(
            targeting={
                "mode": "fanout",
                "agent_space_id": None,
                "routes": [{"match": "Production", "account_id": "222233334444", "agent_space_id": "as-p"}],
            }
        )
        assert "silently never reach any agent" in message

    def test_duplicate_route_matches_are_rejected(self) -> None:
        message = error_from(
            targeting={
                "mode": "fanout",
                "agent_space_id": None,
                "routes": [
                    {"match": "Prod", "account_id": "222233334444", "agent_space_id": "as-a"},
                    {"match": "Prod", "account_id": "333344445555", "agent_space_id": "as-b"},
                    {"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-a"},
                ],
            }
        )
        assert "duplicate match values" in message

    def test_an_unquoted_account_id_is_normalised(self) -> None:
        """YAML parses a bare 12-digit ID as an int and drops any leading zero."""
        config = cfg(
            targeting={
                "mode": "fanout",
                "agent_space_id": None,
                "routes": [{"match": "DEFAULT", "account_id": 12345678901, "agent_space_id": "as-a"}],
            }
        )
        assert config.targeting.routes[0].account_id == "012345678901"

    def test_routes_supplied_in_single_mode_are_rejected(self) -> None:
        assert "would be ignored" in error_from(
            targeting={
                "mode": "single",
                "agent_space_id": "as-1",
                "routes": [{"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-a"}],
            }
        )

    def test_fanout_without_an_organisation_id_warns(self) -> None:
        config = cfg(
            targeting={
                "mode": "fanout",
                "agent_space_id": None,
                "routes": [{"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-a"}],
            }
        )
        # aws:ResourceOrgID, the organisation of the role being assumed. Not
        # aws:PrincipalOrgID, which in an identity policy is the caller's own and so
        # constrains nothing -- see test_infrastructure.py::TestTargetingIam.
        assert any("aws:ResourceOrgID" in w for w in config.warnings)

    def test_routing_table_renders_for_the_lambda(self) -> None:
        config = cfg(
            targeting={
                "mode": "fanout",
                "agent_space_id": None,
                "routes": [
                    {"match": "Prod", "account_id": "222233334444", "agent_space_id": "as-p"},
                    {"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-p"},
                ],
            }
        )
        table = config.targeting.routing_table()
        assert set(table) == {"Prod", "DEFAULT"}
        assert table["Prod"]["roleArn"].endswith("PrtgDevOpsAgentInvestigationRole")


# --- Alarm ingress ----------------------------------------------------------


class TestAlarmIngress:
    def test_a_public_api_requires_an_allowlist(self) -> None:
        """PRTG cannot send custom headers, so the source address is the only
        control available."""
        message = error_from(alarm_allowed_source_ips=[])
        assert "cannot send custom headers" in message

    def test_an_open_allowlist_is_rejected(self) -> None:
        message = error_from(alarm_allowed_source_ips=["0.0.0.0/0"])
        assert "entire internet" in message

    def test_a_private_api_needs_no_allowlist(self) -> None:
        config = cfg(alarm_api_private=True, alarm_allowed_source_ips=[])
        assert config.alarm_api_private is True

    def test_the_allowlist_is_unnecessary_when_pipeline_is_not_deployed(self) -> None:
        assert cfg(deploy_alarm_pipeline=False, alarm_allowed_source_ips=[]) is not None

    def test_a_private_api_warns_when_the_allowlist_is_not_prtgs_own_address(self) -> None:
        """The list feeds the endpoint security group, so a public address breaks it.

        With alarm_api_private the resource policy is keyed on aws:SourceVpce and the
        addresses never appear in it -- but they DO build the execute-api endpoint's
        security group ingress. Deployed with a NAT gateway's public address, which is
        correct for a *public* API, the hostname resolved to the endpoint and the
        connection was then refused: no HTTP status, no log line, because a security group
        drop is silent. Diagnosing that took a packet-level guess, so it is worth a warning.
        """
        config = cfg(
            alarm_api_private=True,
            alarm_allowed_source_ips=["203.0.113.7/32"],  # a public address
            prtg={"reachability": "same-vpc", "host_cidr": "10.0.2.50/32"},
        )
        assert any("does not contain '10.0.2.50/32'" in w for w in config.warnings)

    def test_a_private_api_is_quiet_when_the_allowlist_matches(self) -> None:
        config = cfg(
            alarm_api_private=True,
            alarm_allowed_source_ips=["10.0.2.50/32"],
            prtg={"reachability": "same-vpc", "host_cidr": "10.0.2.50/32"},
        )
        assert not any("alarm_allowed_source_ips does not contain" in w for w in config.warnings)

    def test_a_private_api_stays_quiet_when_only_a_range_is_known(self) -> None:
        """Without host_cidr there is no exact address to compare, so do not guess."""
        config = cfg(
            alarm_api_private=True,
            alarm_allowed_source_ips=["203.0.113.7/32"],
            prtg={"reachability": "remote", "cidr": "10.50.0.0/16", "host_cidr": None},
        )
        assert not any("alarm_allowed_source_ips does not contain" in w for w in config.warnings)


# --- Observability ---------------------------------------------------------


class TestObservability:
    def test_an_unsupported_retention_value_lists_the_valid_ones(self) -> None:
        message = error_from(observability={"log_retention_days": 45})
        assert "CloudWatch-supported" in message
        assert "30" in message

    def test_no_alarm_destination_warns(self) -> None:
        assert any("notify nobody" in w for w in cfg().warnings)

    def test_a_configured_email_removes_the_warning(self) -> None:
        config = cfg(observability={"alarm_email": "ops@example.com"})
        assert not any("notify nobody" in w for w in config.warnings)

    def test_long_retention_warns_about_infrastructure_detail(self) -> None:
        config = cfg(observability={"log_retention_days": 365, "alarm_email": "o@example.com"})
        assert any("retention policy" in w for w in config.warnings)


# --- Lambda sizing ---------------------------------------------------------


class TestLambdaSizing:
    def test_provisioned_concurrency_cannot_exceed_reserved(self) -> None:
        message = error_from(mcp_lambda={"reserved_concurrency": 2, "provisioned_concurrency": 5})
        assert "cannot exceed" in message

    def test_memory_bounds_are_enforced(self) -> None:
        assert "memory_mb" in error_from(mcp_lambda={"memory_mb": 64})

    def test_reserved_concurrency_defaults_to_ten(self) -> None:
        """A blast-radius limit on load reaching a production PRTG server."""
        assert cfg().mcp_lambda.reserved_concurrency == 10


# --- Nothing deployed -------------------------------------------------------


def test_deploying_neither_half_is_rejected() -> None:
    assert "would deploy nothing" in error_from(deploy_mcp_server=False, deploy_alarm_pipeline=False)


# --- Environment interpolation ---------------------------------------------


class TestInterpolation:
    def test_a_variable_is_substituted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_SPACE", "as-from-env")
        assert interpolate_environment({"a": "${MY_SPACE}"}) == {"a": "as-from-env"}

    def test_a_fallback_is_used_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MISSING_VALUE", raising=False)
        assert interpolate_environment({"a": "${MISSING_VALUE:-default}"}) == {"a": "default"}

    def test_an_empty_variable_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMPTY_VALUE", "")
        assert interpolate_environment({"a": "${EMPTY_VALUE:-fallback}"}) == {"a": "fallback"}

    def test_a_missing_variable_names_itself_and_its_location(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
        with pytest.raises(ConfigError) as exc:
            interpolate_environment({"targeting": {"agent_space_id": "${NOT_SET_ANYWHERE}"}})
        message = str(exc.value)
        assert "NOT_SET_ANYWHERE" in message
        assert "targeting.agent_space_id" in message

    def test_substitution_reaches_into_lists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IP", "198.51.100.9")
        assert interpolate_environment({"ips": ["${IP}/32"]}) == {"ips": ["198.51.100.9/32"]}

    def test_non_string_values_pass_through(self) -> None:
        assert interpolate_environment({"n": 42, "b": True, "z": None}) == {
            "n": 42,
            "b": True,
            "z": None,
        }


# --- Shipped configurations ------------------------------------------------


class TestShippedConfigurations:
    """Every configuration in config/ must load and be synthesisable offline.

    A shipped example nobody has run is an example that does not work.
    """

    CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"

    @pytest.fixture(autouse=True)
    def _example_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The identifiers the examples expect. Everything else has a fallback.
        monkeypatch.setenv("DEVOPS_AGENT_SPACE_ID", "as-example-001")
        monkeypatch.setenv("PRTG_SOURCE_IP", "203.0.113.7")

    def _configs(self) -> list[Path]:
        """The shipped examples only.

        ``config/local.*`` is gitignored scratch space for local experiments, so it is
        excluded: it is expected to contain real account IDs and VPC IDs, which is
        exactly what these tests forbid in a published example.
        """
        return sorted(p for p in self.CONFIG_DIR.glob("*.yaml") if not p.name.startswith("local."))

    def test_at_least_three_examples_are_shipped(self) -> None:
        assert len(self._configs()) >= 3

    def test_every_example_loads(self) -> None:
        for path in self._configs():
            config = load_config(path)
            assert config.region in DEVOPS_AGENT_REGIONS, path.name

    def test_no_example_requires_credentials_to_synthesise(self) -> None:
        """Otherwise CI cannot verify it."""
        for path in self._configs():
            config = load_config(path)
            assert config.network.requires_context_lookup is False, (
                f"{path.name} would need AWS credentials at synthesis; supply subnet_ids and "
                "availability_zones alongside vpc_id"
            )

    def test_no_example_contains_a_literal_account_id(self) -> None:
        """Examples must not carry anybody's real identifiers."""
        for path in self._configs():
            text = path.read_text()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or "${" in stripped:
                    continue
                import re

                assert not re.search(r"\b\d{12}\b", stripped), (
                    f"{path.name} has a bare 12-digit account ID: {stripped}"
                )

    def test_the_examples_cover_the_knobs_between_them(self) -> None:
        """The set should demonstrate both values of every knob."""
        configs = [load_config(p) for p in self._configs()]
        assert {c.network.mode for c in configs} == {"nat", "private"}
        assert {c.auth.mode for c in configs} == {"sigv4", "oidc"}
        assert {c.secret.mode for c in configs} == {"local", "external"}
        assert {c.prtg.reachability for c in configs} == {"same-vpc", "remote"}
        assert {c.targeting.mode for c in configs} == {"single", "fanout"}


def test_a_missing_config_file_lists_what_is_available() -> None:
    with pytest.raises(ConfigError) as exc:
        load_config("config/does-not-exist.yaml")
    assert "default.yaml" in str(exc.value)
