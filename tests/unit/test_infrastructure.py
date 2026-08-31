"""CDK template assertions.

These run with no AWS account and no credentials, which is the point: they let CI
verify the claims this sample makes about itself on every pull request.

Two groups matter most.

``TestSecurityPosture`` asserts the properties the security review calls for - a
Secrets Manager grant scoped to one ARN, egress narrowed to PRTG, no unrestricted
alarm ingress, Gateway invoke scoped to one function. Those are the difference
between this sample and the reference implementation it is derived from, and
without tests they would decay into aspirations.

``TestKnobIndependence`` asserts that the five configuration knobs actually are
independent, since collapsing eighteen documented scenarios into five flags is only
worth anything if changing one flag does not disturb the others.
"""

from __future__ import annotations

import json
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template
from infrastructure.config import PrtgMcpConfig, build_config
from infrastructure.stacks.alarm_pipeline_stack import AlarmPipelineStack
from infrastructure.stacks.mcp_server_stack import McpServerStack
from infrastructure.stacks.shared_stack import SharedStack

ACCOUNT = "111122223333"
REGION = "ap-southeast-2"

#: Minimal valid configuration. Individual tests override only what they exercise,
#: so each test reads as the difference from the default.
BASE: dict[str, Any] = {
    "region": REGION,
    "account": ACCOUNT,
    "targeting": {"mode": "single", "agent_space_id": "as-test-001"},
    "prtg": {"reachability": "same-vpc", "host_cidr": "10.0.1.10/32"},
    "alarm_allowed_source_ips": ["203.0.113.7/32"],
}


def config(**overrides: Any) -> PrtgMcpConfig:
    """Build a validated config from BASE plus overrides (shallow-merged per section)."""
    merged: dict[str, Any] = json.loads(json.dumps(BASE))
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return build_config(merged, source="<test>")


def templates(cfg: PrtgMcpConfig | None = None) -> dict[str, Template]:
    """Synthesise the whole app and return each stack's template by short name.

    Builds all three stacks together rather than one in isolation, because that is
    how they are deployed. A real deployment rejected an earlier arrangement in which
    each half built its own networking: the two templates were individually valid,
    and only deploying the second revealed that their physical names collided.
    Synthesising the app as a whole is what lets
    ``test_no_physical_name_collides_across_stacks`` catch that without an account.
    """
    cfg = cfg or config()
    app = cdk.App()
    env = cdk.Environment(account=ACCOUNT, region=cfg.region)

    # Every stack is constructed before any template is extracted.
    # Template.from_stack synthesises the whole app, and CDK rejects any change to
    # the construct tree afterwards with ConstructTreeModifiedAfterSynth.
    stacks: dict[str, cdk.Stack] = {}

    shared = SharedStack(app, "Shared", config=cfg, env=env)
    stacks["shared"] = shared

    if cfg.deploy_mcp_server:
        mcp = McpServerStack(
            app, "Mcp", config=cfg, network=shared.network, alarm_topic=shared.alarm_topic, env=env
        )
        mcp.observability.finalise()
        stacks["mcp"] = mcp

    if cfg.deploy_alarm_pipeline:
        pipeline = AlarmPipelineStack(
            app,
            "Pipeline",
            config=cfg,
            network=shared.network,
            alarm_topic=shared.alarm_topic,
            env=env,
        )
        pipeline.observability.finalise()
        stacks["pipeline"] = pipeline

    return {name: Template.from_stack(stack) for name, stack in stacks.items()}


def shared_template(cfg: PrtgMcpConfig | None = None) -> Template:
    return templates(cfg)["shared"]


def mcp_template(cfg: PrtgMcpConfig | None = None) -> Template:
    return templates(cfg)["mcp"]


def pipeline_template(cfg: PrtgMcpConfig | None = None) -> Template:
    return templates(cfg)["pipeline"]


def policy_statements(template: Template) -> list[dict[str, Any]]:
    """Every statement across every IAM policy in the template."""
    out: list[dict[str, Any]] = []
    for resource in template.find_resources("AWS::IAM::Policy").values():
        out.extend(resource["Properties"]["PolicyDocument"]["Statement"])
    return out


def statements_for(template: Template, action_fragment: str) -> list[dict[str, Any]]:
    matches = []
    for statement in policy_statements(template):
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else (actions or [])
        if any(action_fragment in str(a) for a in actions):
            matches.append(statement)
    return matches


# --- Security ---------------------------------------------------------------


class TestSecurityPosture:
    def test_secrets_manager_grant_is_scoped_to_one_secret(self) -> None:
        """Security review finding 3. The reference granted GetSecretValue on '*',
        so a compromise of the function exposed every secret in the account."""
        statements = statements_for(mcp_template(), "secretsmanager:GetSecretValue")
        assert statements, "no Secrets Manager grant was found"
        for statement in statements:
            resource = statement["Resource"]
            assert resource != "*", "GetSecretValue must not be granted on '*'"
            assert "*" not in json.dumps(resource) or "Ref" in json.dumps(resource)

    def test_lambda_egress_is_restricted_to_prtg(self) -> None:
        # Security groups live in the shared stack, so both halves get the same
        # narrow egress rather than each defining its own.
        template = shared_template(config(prtg={"host_cidr": "10.9.9.9/32"}))
        groups = template.find_resources("AWS::EC2::SecurityGroup")
        egress = [rule for g in groups.values() for rule in g["Properties"].get("SecurityGroupEgress", [])]
        prtg_rules = [r for r in egress if r.get("CidrIp") == "10.9.9.9/32"]
        assert prtg_rules, "no egress rule to the PRTG host was created"
        assert all(r["FromPort"] == 443 for r in prtg_rules)

    def test_fully_private_mode_creates_no_internet_egress(self) -> None:
        """The core promise of network.mode: private."""
        template = shared_template(
            config(
                network={
                    "mode": "private",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "subnet_ids": ["subnet-0a", "subnet-0b"],
                    "availability_zones": [f"{REGION}a", f"{REGION}b"],
                }
            )
        )
        for group in template.find_resources("AWS::EC2::SecurityGroup").values():
            for rule in group["Properties"].get("SecurityGroupEgress", []):
                assert rule.get("CidrIp") != "0.0.0.0/0", (
                    "a fully-private deployment must not have an egress route to the internet"
                )
        template.resource_count_is("AWS::EC2::NatGateway", 0)

    def test_gateway_invoke_grant_is_scoped_to_one_function(self) -> None:
        """A wildcard here would let a compromised Gateway role invoke any function
        in the account - the escalation path the security review describes."""
        statements = statements_for(mcp_template(), "lambda:InvokeFunction")
        assert statements
        for statement in statements:
            assert statement["Resource"] != "*"

    def test_agent_invoke_grant_is_scoped_to_one_gateway(self) -> None:
        statements = statements_for(mcp_template(), "bedrock-agentcore:")
        assert statements
        for statement in statements:
            rendered = json.dumps(statement["Resource"])
            assert rendered != '"*"'
            for action in (
                statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            ):
                assert action != "bedrock-agentcore:*", (
                    "the reference granted bedrock-agentcore:* - scope to the specific action"
                )

    def test_invoker_role_trust_is_conditioned_on_this_account(self) -> None:
        """Confused-deputy protection: the AWS service principal must not be usable
        on another account's behalf."""
        template = mcp_template()
        roles = template.find_resources("AWS::IAM::Role")
        invoker = [
            r
            for r in roles.values()
            if "aidevops.amazonaws.com" in json.dumps(r["Properties"].get("AssumeRolePolicyDocument", {}))
        ]
        assert invoker, "no DevOps Agent invoker role was found"
        rendered = json.dumps(invoker[0]["Properties"]["AssumeRolePolicyDocument"])
        assert "aws:SourceAccount" in rendered

    def test_gateway_role_trust_is_conditioned_on_this_account(self) -> None:
        """Same protection on the Gateway role, which did not have it.

        It carried ``external_ids=None`` under a comment claiming exactly this guard.
        ``None`` is the parameter's default and applies no condition, so the trust policy
        allowed ``bedrock-agentcore.amazonaws.com`` unconditionally while the code read as
        though it were constrained. Nothing asserted it either way, which is why a comment
        was able to stand in for the control for as long as it did.
        """
        template = mcp_template()
        roles = template.find_resources("AWS::IAM::Role")

        gateway = [
            r
            for r in roles.values()
            if r["Properties"].get("Description", "").startswith("AgentCore Gateway role")
        ]
        assert gateway, "no Gateway role was found"

        trust = gateway[0]["Properties"]["AssumeRolePolicyDocument"]
        statements = [
            s
            for s in trust["Statement"]
            if "bedrock-agentcore.amazonaws.com" in json.dumps(s.get("Principal", {}))
        ]
        assert statements, "the Gateway role does not trust the AgentCore service principal"

        for statement in statements:
            condition = statement.get("Condition", {})
            assert "aws:SourceAccount" in json.dumps(condition), (
                "the AgentCore service principal is trusted with no source-account "
                "condition, so it could be induced to assume this role on another "
                "account's behalf"
            )

    def test_alarm_api_denies_all_addresses_except_the_allowlist(self) -> None:
        template = pipeline_template(config(alarm_allowed_source_ips=["198.51.100.4/32"]))
        api = next(iter(template.find_resources("AWS::ApiGateway::RestApi").values()))
        policy = json.dumps(api["Properties"]["Policy"])
        assert "198.51.100.4/32" in policy
        assert "NotIpAddress" in policy
        assert '"Effect":"Deny"' in policy.replace(" ", ""), (
            "an Allow-only policy is not restrictive on a REST API; the Deny is what closes it"
        )

    def test_private_alarm_api_denies_traffic_from_other_vpc_endpoints(self) -> None:
        template = pipeline_template(
            config(
                alarm_api_private=True,
                network={
                    "mode": "private",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "subnet_ids": ["subnet-0a"],
                    "availability_zones": [f"{REGION}a"],
                },
            )
        )
        api = next(iter(template.find_resources("AWS::ApiGateway::RestApi").values()))
        policy = json.dumps(api["Properties"]["Policy"])
        assert "aws:SourceVpce" in policy
        assert "PRIVATE" in json.dumps(api["Properties"]["EndpointConfiguration"])

    def test_no_credential_appears_in_any_lambda_environment(self) -> None:
        """Environment variables are readable with GetFunctionConfiguration and are
        stored in the template, so they carry the secret's ARN and never its value."""
        for template in (mcp_template(), pipeline_template()):
            for function in template.find_resources("AWS::Lambda::Function").values():
                env = json.dumps(function["Properties"].get("Environment", {})).lower()
                for forbidden in ("passhash", "password", "prtg_username"):
                    assert forbidden not in env, f"{forbidden} must not be in a Lambda environment"

    def test_created_secret_contains_no_credential_in_the_template(self) -> None:
        """The template must not carry a credential, and must not accept one.

        The secret is created with the correct JSON shape and blank fields, so the
        Lambda's failure message names the fields to fill in. The placeholder for
        prtg_passhash is generated by Secrets Manager at creation time, so it never
        appears in the template, in CloudTrail, or in CDK context - unlike a value
        passed via configuration or a CloudFormation parameter.
        """
        template = mcp_template()
        secrets = template.find_resources("AWS::SecretsManager::Secret")
        assert secrets

        for secret in secrets.values():
            properties = secret["Properties"]
            # A literal value would be stored in the template in plain text.
            assert "SecretString" not in properties

            generator = properties.get("GenerateSecretString", {})
            seed = json.loads(generator.get("SecretStringTemplate", "{}"))
            assert seed.get("prtg_url") == "", "the template must not seed a PRTG URL"
            assert seed.get("prtg_username") == "", "the template must not seed a username"
            assert "prtg_passhash" not in seed, "a passhash must never appear in the template"
            assert generator.get("GenerateStringKey") == "prtg_passhash"

    def test_the_secret_template_is_never_changed(self) -> None:
        """Pinned exactly, because editing it destroys populated credentials.

        CloudFormation regenerates the secret whenever ``GenerateSecretString``
        changes, overwriting whatever the operator put there. Observed against a real
        deployment: adding a blank ``prtg_api_key`` to the template, purely so the field
        would show up in the console, replaced a working credential with the empty
        template on the next deploy. Every already-deployed adopter would have lost
        their PRTG credential to a change that altered no behaviour, and the breakage
        appears as "PRTG credentials are incomplete" long after the deploy responsible.

        So this asserts the exact template rather than properties of it. If a change
        here is genuinely required, it is a breaking change for every existing
        deployment and needs release notes telling operators to repopulate the secret.

        The template does not need to list every accepted field. The client reads
        ``prtg_api_key`` from whatever JSON the secret holds, whether or not it appears
        here, so new credential forms belong in the documentation instead.
        """
        template = mcp_template()
        for secret in template.find_resources("AWS::SecretsManager::Secret").values():
            generator = secret["Properties"]["GenerateSecretString"]
            assert json.loads(generator["SecretStringTemplate"]) == {
                "prtg_url": "",
                "prtg_username": "",
            }, (
                "The secret template changed. This regenerates the secret on deploy and "
                "wipes the operator's credential. See the comment in "
                "infrastructure/constructs/prtg_secret.py."
            )
            assert generator["GenerateStringKey"] == "prtg_passhash"

    def test_tls_verification_is_enabled_by_default(self) -> None:
        template = mcp_template()
        function = next(iter(template.find_resources("AWS::Lambda::Function").values()))
        assert function["Properties"]["Environment"]["Variables"]["PRTG_VERIFY_TLS"] == "true"

    def test_disabling_tls_verification_is_reflected_in_the_environment(self) -> None:
        template = mcp_template(config(prtg={"verify_tls": False}))
        function = next(iter(template.find_resources("AWS::Lambda::Function").values()))
        assert function["Properties"]["Environment"]["Variables"]["PRTG_VERIFY_TLS"] == "false"


# --- Reliability and operability -------------------------------------------


class TestReliability:
    def test_log_retention_is_always_set(self) -> None:
        """Unset retention means logs are kept forever, which is a cost leak and an
        unanswered retention question for logs holding PRTG infrastructure detail."""
        for name, template in templates().items():
            for logical_id, group in template.find_resources("AWS::Logs::LogGroup").items():
                assert "RetentionInDays" in group["Properties"], f"{name}/{logical_id}"

    def test_log_retention_honours_configuration_for_every_log_group(self) -> None:
        """Every group, not just the function's.

        CDK's VPC flow log creates its own group with a two-year default, which
        would quietly ignore the configured retention. Asserting across all groups
        catches that class of inconsistency.
        """
        found = 0
        for name, template in templates(config(observability={"log_retention_days": 7})).items():
            for logical_id, group in template.find_resources("AWS::Logs::LogGroup").items():
                found += 1
                assert group["Properties"]["RetentionInDays"] == 7, (
                    f"{name}/{logical_id} does not honour observability.log_retention_days"
                )
        assert found >= 3, "expected log groups in every stack"

    def test_pipeline_has_a_dead_letter_queue(self) -> None:
        """A failure here means an alarm produced no investigation; it must be
        replayable rather than lost."""
        pipeline_template().resource_count_is("AWS::SQS::Queue", 1)

    def test_the_pipeline_function_is_told_where_the_dead_letter_queue_is(self) -> None:
        """The function parks failed alarms itself, so it needs the queue URL.

        Without ALARM_DLQ_URL the park degrades to a log line, which is the failure
        this whole mechanism exists to avoid.
        """
        template = pipeline_template()
        function = next(iter(template.find_resources("AWS::Lambda::Function").values()))
        assert "ALARM_DLQ_URL" in function["Properties"]["Environment"]["Variables"]

    def test_the_pipeline_does_not_rely_on_asynchronous_dead_lettering(self) -> None:
        """``DeadLetterConfig`` must NOT be set on this function.

        It configures Lambda's *asynchronous* invocation path. The only caller is API
        Gateway's proxy integration, which is synchronous, so setting it yields a queue
        that can never receive a message and a CloudWatch alarm on that queue that can
        never fire -- a monitoring gap that presents as a clean bill of health.

        This asserts the absence rather than the presence, because the mistake is
        reintroduced by adding something that looks obviously correct. The queue is
        still there and still written to; see _park_alarm in the handler.
        """
        template = pipeline_template()
        function = next(iter(template.find_resources("AWS::Lambda::Function").values()))
        properties = function["Properties"]
        assert "DeadLetterConfig" not in properties, (
            "Lambda's asynchronous dead-letter path cannot fire behind a synchronous "
            "API Gateway invocation. The handler parks alarms explicitly instead."
        )

    def test_the_pipeline_may_write_to_the_dead_letter_queue(self) -> None:
        """The explicit park needs sqs:SendMessage; without it every parked alarm is
        lost at the moment it was supposed to be preserved."""
        template = pipeline_template()
        policies = template.find_resources("AWS::IAM::Policy")
        actions = [
            action
            for policy in policies.values()
            for statement in policy["Properties"]["PolicyDocument"]["Statement"]
            for action in (
                statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            )
        ]
        assert "sqs:SendMessage" in actions

    def test_reserved_concurrency_bounds_load_on_prtg(self) -> None:
        template = mcp_template()
        function = next(iter(template.find_resources("AWS::Lambda::Function").values()))
        assert function["Properties"]["ReservedConcurrentExecutions"] == 10

    def test_alarms_exist_for_both_halves(self) -> None:
        assert len(mcp_template().find_resources("AWS::CloudWatch::Alarm")) >= 5
        assert len(pipeline_template().find_resources("AWS::CloudWatch::Alarm")) >= 4

    def test_auth_failure_alarm_exists_because_it_is_otherwise_invisible(self) -> None:
        """PRTG returning 401 is not a Lambda error, so no built-in metric catches
        a credential that was rotated without updating the secret."""
        template = mcp_template()
        filters = template.find_resources("AWS::Logs::MetricFilter")
        assert any("prtg_auth_failed" in json.dumps(f["Properties"]) for f in filters.values())

    def test_alarms_notify_a_topic_when_one_is_configured(self) -> None:
        built = templates(config(observability={"alarm_email": "ops@example.com"}))
        # Created once, in the shared stack, so both halves notify the same place and
        # the topic name cannot collide.
        built["shared"].resource_count_is("AWS::SNS::Topic", 1)
        built["mcp"].resource_count_is("AWS::SNS::Topic", 0)
        built["pipeline"].resource_count_is("AWS::SNS::Topic", 0)

        for name in ("mcp", "pipeline"):
            alarms = built[name].find_resources("AWS::CloudWatch::Alarm")
            assert alarms, f"{name} has no alarms"
            for logical_id, alarm in alarms.items():
                assert alarm["Properties"].get("AlarmActions"), f"{name}/{logical_id} has no action"

    def test_every_alarm_has_a_description(self) -> None:
        """The description is what an on-call engineer reads first."""
        for template in (mcp_template(), pipeline_template()):
            for alarm in template.find_resources("AWS::CloudWatch::Alarm").values():
                description = alarm["Properties"].get("AlarmDescription", "")
                assert len(description) > 40, "alarm descriptions must say what to do"


# --- Knob independence ------------------------------------------------------


class TestKnobIndependence:
    """Each knob must change only its own resources.

    This is what justifies collapsing eighteen documented scenarios into five
    flags. If the knobs interfered, the collapse would be a simplification on paper
    only.
    """

    def test_network_knob_controls_endpoints_and_nat_only(self) -> None:
        nat = shared_template(config(network={"mode": "nat"}))
        private = shared_template(
            config(
                network={
                    "mode": "private",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "subnet_ids": ["subnet-0a"],
                    "availability_zones": [f"{REGION}a"],
                }
            )
        )
        nat.resource_count_is("AWS::EC2::VPCEndpoint", 0)
        # Asserted by service name rather than by count, so adding one produces a message
        # naming what changed. `aidevops-dataplane` is what CreateBacklogTask is served by
        # (hostPrefix 'dp.'), and without it the pipeline hangs and loses the alarm silently.
        assert {
            endpoint["Properties"]["ServiceName"].rsplit(".", 1)[-1]
            for endpoint in private.find_resources("AWS::EC2::VPCEndpoint").values()
        } == {"secretsmanager", "logs", "lambda", "sts", "sqs", "aidevops-dataplane"}

        # The Gateway and the function are unaffected by the network mode.
        for mode_config in (
            config(network={"mode": "nat"}),
            config(
                network={
                    "mode": "private",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "subnet_ids": ["subnet-0a"],
                    "availability_zones": [f"{REGION}a"],
                }
            ),
        ):
            built = templates(mode_config)
            built["mcp"].resource_count_is("AWS::BedrockAgentCore::Gateway", 1)
            built["mcp"].resource_count_is("AWS::Lambda::Function", 1)

    def test_auth_knob_controls_cognito_and_the_invoker_role_only(self) -> None:
        sigv4 = mcp_template(config(auth={"mode": "sigv4"}))
        cognito = mcp_template(config(auth={"mode": "oidc", "provider": "cognito"}))
        entra = mcp_template(
            config(
                auth={
                    "mode": "oidc",
                    "provider": "entra",
                    "discovery_url": "https://login.microsoftonline.com/t/v2.0/.well-known/openid-configuration",
                    "allowed_audience": ["api://client"],
                    "allowed_clients": ["client"],
                }
            )
        )

        sigv4.resource_count_is("AWS::Cognito::UserPool", 0)
        cognito.resource_count_is("AWS::Cognito::UserPool", 1)
        # An external provider creates nothing: this is why the reference material's
        # separate Entra ID and generic-OIDC scenarios are one code path.
        entra.resource_count_is("AWS::Cognito::UserPool", 0)

        for template in (sigv4, cognito, entra):
            template.resource_count_is("AWS::BedrockAgentCore::Gateway", 1)
            template.resource_count_is("AWS::Lambda::Function", 1)

    def test_secret_knob_controls_whether_a_secret_is_created(self) -> None:
        local = mcp_template(config(secret={"mode": "local"}))
        external = mcp_template(
            config(
                secret={
                    "mode": "external",
                    "secret_arn": f"arn:aws:secretsmanager:{REGION}:999988887777:secret:prtg-x-a1b2c3",
                    "kms_key_arn": f"arn:aws:kms:{REGION}:999988887777:key/abc-123",
                }
            )
        )
        local.resource_count_is("AWS::SecretsManager::Secret", 1)
        external.resource_count_is("AWS::SecretsManager::Secret", 0)

        for template in (local, external):
            assert statements_for(template, "secretsmanager:GetSecretValue")

    def test_cross_account_secret_emits_both_required_policies(self) -> None:
        """Granting only the resource policy produces an AccessDenied naming Secrets
        Manager and never mentioning KMS, which sends people the wrong way."""
        template = mcp_template(
            config(
                secret={
                    "mode": "external",
                    "secret_arn": f"arn:aws:secretsmanager:{REGION}:999988887777:secret:prtg-x-a1b2c3",
                    "kms_key_arn": f"arn:aws:kms:{REGION}:999988887777:key/abc-123",
                }
            )
        )
        outputs = json.dumps(template.to_json().get("Outputs", {}))
        assert "CrossAccountSecretResourcePolicy" in outputs
        assert "CrossAccountKmsKeyPolicyStatement" in outputs

    def test_targeting_knob_controls_routing_and_iam_only(self) -> None:
        single = pipeline_template(config(targeting={"mode": "single", "agent_space_id": "as-1"}))
        fanout = pipeline_template(
            config(
                targeting={
                    "mode": "fanout",
                    "agent_space_id": None,
                    "organization_id": "o-example",
                    "routes": [
                        {"match": "Production", "account_id": "222233334444", "agent_space_id": "as-p"},
                        {"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-p"},
                    ],
                }
            )
        )

        single.resource_count_is("AWS::SSM::Parameter", 0)
        fanout.resource_count_is("AWS::SSM::Parameter", 1)

        assert statements_for(single, "aidevops:CreateBacklogTask")
        assert not statements_for(single, "sts:AssumeRole")
        assert statements_for(fanout, "sts:AssumeRole")

        for template in (single, fanout):
            template.resource_count_is("AWS::Lambda::Function", 1)
            template.resource_count_is("AWS::ApiGateway::RestApi", 1)


class TestTargetingIam:
    def test_single_mode_scopes_task_creation_to_one_agent_space(self) -> None:
        template = pipeline_template(config(targeting={"agent_space_id": "as-scoped"}))
        statements = statements_for(template, "aidevops:CreateBacklogTask")
        assert statements
        rendered = json.dumps(statements[0]["Resource"])
        # The IAM namespace is aidevops even though the SDK client is devops-agent.
        assert "aidevops" in rendered
        assert "agentspace/as-scoped" in rendered

    def test_fanout_with_an_organisation_id_scopes_by_resource_org(self) -> None:
        """The account wildcard must be constrained by the TARGET's organisation.

        This asserted only that the string "aws:PrincipalOrgID" appeared somewhere in the
        condition, which it did -- and the policy still restricted nothing. The statement
        is identity-based on the pipeline's own role, so aws:PrincipalOrgID resolves to
        this account's organisation on every call and is satisfied unconditionally,
        leaving `iam::*:role/<name>` to grant assume-role in any account anywhere. The
        old assertion passed against a policy that failed open, which is the worst
        combination available: a test and a deployment both reporting success.

        aws:ResourceOrgID is the organisation of the role being assumed, so it is the key
        that actually narrows the wildcard.
        """
        template = pipeline_template(
            config(
                targeting={
                    "mode": "fanout",
                    "agent_space_id": None,
                    "organization_id": "o-example123",
                    "routes": [{"match": "DEFAULT", "account_id": "222233334444", "agent_space_id": "as-p"}],
                }
            )
        )
        statement = statements_for(template, "sts:AssumeRole")[0]
        condition = statement.get("Condition", {})

        assert condition == {"StringEquals": {"aws:ResourceOrgID": "o-example123"}}
        # Named explicitly so reintroducing the tautology fails here rather than passing.
        assert "aws:PrincipalOrgID" not in json.dumps(condition)

    def test_fanout_org_scope_covers_a_custom_role_name(self) -> None:
        """FanoutRoute.role_name is configurable, so the resource cannot be hardcoded.

        The role name was written literally into the ARN while routes may override it,
        so any route using a different name got an AccessDenied at runtime with nothing
        failing at synthesis. Never caught because the only override in the repo sets the
        name to the same string as the default.
        """
        template = pipeline_template(
            config(
                targeting={
                    "mode": "fanout",
                    "agent_space_id": None,
                    "organization_id": "o-example123",
                    "routes": [
                        {
                            "match": "Production",
                            "account_id": "222233334444",
                            "agent_space_id": "as-p",
                            "role_name": "CustomInvestigationRole",
                        },
                        {"match": "DEFAULT", "account_id": "333344445555", "agent_space_id": "as-d"},
                    ],
                }
            )
        )
        rendered = json.dumps(statements_for(template, "sts:AssumeRole")[0]["Resource"])
        assert "role/CustomInvestigationRole" in rendered
        assert "role/PrtgDevOpsAgentInvestigationRole" in rendered

    def test_fanout_without_an_organisation_id_lists_exact_role_arns(self) -> None:
        template = pipeline_template(
            config(
                targeting={
                    "mode": "fanout",
                    "agent_space_id": None,
                    "routes": [
                        {"match": "Production", "account_id": "222233334444", "agent_space_id": "as-p"},
                        {"match": "DEFAULT", "account_id": "333344445555", "agent_space_id": "as-d"},
                    ],
                }
            )
        )
        statement = statements_for(template, "sts:AssumeRole")[0]
        rendered = json.dumps(statement["Resource"])
        assert "222233334444" in rendered
        assert "333344445555" in rendered
        assert ":role/*" not in rendered


# --- Tool schema ------------------------------------------------------------


class TestToolSchema:
    def test_gateway_target_is_created_with_a_tool_schema(self) -> None:
        template = mcp_template()
        template.resource_count_is("AWS::BedrockAgentCore::GatewayTarget", 1)
        target = next(iter(template.find_resources("AWS::BedrockAgentCore::GatewayTarget").values()))
        assert "ToolSchema" in json.dumps(target["Properties"])

    def test_generated_schema_matches_the_handler_contract(self) -> None:
        """The schema uploaded to the Gateway is generated from tools.py, so it
        cannot describe a tool the handler does not implement."""
        import tempfile

        from infrastructure.stacks.mcp_server_stack import write_tool_schema

        from prtg_mcp import handler, tools

        with tempfile.TemporaryDirectory() as directory:
            path = write_tool_schema(__import__("pathlib").Path(directory) / "schema.json")
            rendered = json.loads(path.read_text())

        assert {entry["name"] for entry in rendered} == set(handler.TOOL_IMPLEMENTATIONS)
        assert {entry["name"] for entry in rendered} == set(tools.tool_names())

    def test_generated_schema_file_carries_the_full_json_schema(self) -> None:
        """The generated file keeps every constraint, which CDK's inline path cannot.

        Note what this does and does not prove. The *file* is complete, and the
        handler's validator enforces all of it. But AgentCore Gateway normalises the
        schema when it republishes it over MCP, preserving only type, description and
        required - verified against a deployed Gateway. So these constraints are
        enforced rather than advertised, and the valid values are restated in the
        description text, which is what actually reaches the agent. See
        TestConstraintsAreDiscoverable in test_tool_contract.py.
        """
        import tempfile
        from pathlib import Path

        from infrastructure.stacks.mcp_server_stack import write_tool_schema

        with tempfile.TemporaryDirectory() as directory:
            path = write_tool_schema(Path(directory) / "schema.json")
            rendered = json.loads(path.read_text())

        by_name = {entry["name"]: entry for entry in rendered}

        sensors = by_name["get_sensors"]["inputSchema"]
        assert "down" in sensors["properties"]["status"]["enum"]
        assert sensors["properties"]["count"]["maximum"] == 5000
        assert sensors["additionalProperties"] is False

        history = by_name["get_sensor_history"]["inputSchema"]
        assert "pattern" in history["properties"]["sdate"]
        assert history["required"] == ["id", "sdate", "edate"]


# --- Deployment shape -------------------------------------------------------


class TestDeploymentShape:
    def test_both_halves_can_be_deployed_independently(self) -> None:
        mcp_only = config(deploy_alarm_pipeline=False)
        pipeline_only = config(deploy_mcp_server=False)
        assert mcp_only.deploy_mcp_server and not mcp_only.deploy_alarm_pipeline
        assert pipeline_only.deploy_alarm_pipeline and not pipeline_only.deploy_mcp_server

    def test_lambda_uses_a_pinned_runtime(self) -> None:
        for template in (mcp_template(), pipeline_template()):
            for function in template.find_resources("AWS::Lambda::Function").values():
                assert function["Properties"]["Runtime"].startswith("python3.")

    def test_tracing_can_be_disabled(self) -> None:
        template = mcp_template(config(observability={"tracing": False}))
        function = next(iter(template.find_resources("AWS::Lambda::Function").values()))
        assert function["Properties"].get("TracingConfig", {}).get("Mode") != "Active"

    @pytest.mark.parametrize("concurrency", [1, 5])
    def test_provisioned_concurrency_creates_an_alias(self, concurrency: int) -> None:
        """Provisioned concurrency needs a version or alias; the unqualified
        function cannot carry it."""
        template = mcp_template(
            config(mcp_lambda={"provisioned_concurrency": concurrency, "reserved_concurrency": 10})
        )
        aliases = template.find_resources("AWS::Lambda::Alias")
        assert aliases
        alias = next(iter(aliases.values()))
        assert (
            alias["Properties"]["ProvisionedConcurrencyConfig"]["ProvisionedConcurrentExecutions"]
            == concurrency
        )


# --- Cross-stack collisions -------------------------------------------------


class TestCrossStackConsistency:
    """Properties that only hold when the stacks are considered together.

    Added after a real deployment failed. Each template was individually valid, so
    every existing test passed; the problem only appeared when the second stack was
    deployed into an account where the first had already created resources with the
    same physical names. CloudFormation reported "already exists" for a security
    group, a log group, and a dashboard.

    Worse than the naming, each half was building its own VPC and NAT gateway -
    double the cost, and PRTG would have needed a route to both. Shared
    infrastructure now lives in one stack.
    """

    #: Properties that set a *physical* name, which must therefore be unique across
    #: the whole account and region rather than merely within one stack.
    PHYSICAL_NAME_PROPERTIES = (
        "LogGroupName",
        "DashboardName",
        "TopicName",
        "GroupName",
        "FunctionName",
        "QueueName",
        "RoleName",
        "RestApiName",
        "Name",
    )

    def _physical_names(self, built: dict[str, Template]) -> dict[tuple[str, str], list[str]]:
        seen: dict[tuple[str, str], list[str]] = {}
        for stack_name, template in built.items():
            for resource in template.to_json().get("Resources", {}).values():
                properties = resource.get("Properties", {})
                for key in self.PHYSICAL_NAME_PROPERTIES:
                    value = properties.get(key)
                    if isinstance(value, str) and value:
                        seen.setdefault((resource["Type"], value), []).append(stack_name)
        return seen

    def test_no_physical_name_collides_across_stacks(self) -> None:
        """The regression guard for the deployment failure described above."""
        collisions = {
            key: stacks for key, stacks in self._physical_names(templates()).items() if len(set(stacks)) > 1
        }
        assert not collisions, "physical names reused across stacks:\n" + "\n".join(
            f"  {name} ({resource_type}) in {sorted(set(stacks))}"
            for (resource_type, name), stacks in collisions.items()
        )

    def test_no_collision_with_an_alarm_topic_configured(self) -> None:
        """The topic name is the collision that only appears once alarms are wired up,
        which is not the default configuration."""
        built = templates(config(observability={"alarm_email": "ops@example.com"}))
        collisions = {k: v for k, v in self._physical_names(built).items() if len(set(v)) > 1}
        assert not collisions, f"collisions with alarms configured: {collisions}"

    def test_no_collision_in_any_shipped_configuration(self) -> None:
        """Runs the check against every example, not just the default."""
        import os
        from pathlib import Path

        from infrastructure.config import load_config

        os.environ.setdefault("DEVOPS_AGENT_SPACE_ID", "as-example-001")
        os.environ.setdefault("PRTG_SOURCE_IP", "203.0.113.7")

        config_dir = Path(__file__).resolve().parents[2] / "config"
        for path in sorted(config_dir.glob("*.yaml")):
            built = templates(load_config(path))
            collisions = {k: v for k, v in self._physical_names(built).items() if len(set(v)) > 1}
            assert not collisions, f"{path.name}: {collisions}"

    def test_exactly_one_vpc_is_created(self) -> None:
        """Two VPCs would mean two NAT gateways and two routes to PRTG."""
        built = templates()
        total = sum(len(template.find_resources("AWS::EC2::VPC")) for template in built.values())
        assert total == 1, f"expected exactly one VPC across all stacks, found {total}"

    def test_exactly_one_nat_gateway_is_created(self) -> None:
        built = templates()
        total = sum(len(template.find_resources("AWS::EC2::NatGateway")) for template in built.values())
        assert total == 1, f"expected exactly one NAT gateway, found {total}"

    def test_networking_lives_only_in_the_shared_stack(self) -> None:
        built = templates()
        for name in ("mcp", "pipeline"):
            for resource_type in (
                "AWS::EC2::VPC",
                "AWS::EC2::NatGateway",
                "AWS::EC2::SecurityGroup",
                "AWS::EC2::VPCEndpoint",
            ):
                built[name].resource_count_is(resource_type, 0)

    def test_each_half_has_its_own_dashboard(self) -> None:
        """One dashboard each, with distinct names, rather than one shared one - the
        two halves fail differently and are read separately."""
        built = templates()
        names = set()
        for name in ("mcp", "pipeline"):
            dashboards = built[name].find_resources("AWS::CloudWatch::Dashboard")
            assert len(dashboards) == 1, f"{name} should have exactly one dashboard"
            names.add(next(iter(dashboards.values()))["Properties"]["DashboardName"])
        assert len(names) == 2, f"dashboard names must differ, got {names}"

    def test_either_half_can_be_deployed_alone(self) -> None:
        """Shared infrastructure is always built, so a single half still deploys."""
        mcp_only = templates(config(deploy_alarm_pipeline=False))
        assert set(mcp_only) == {"shared", "mcp"}
        assert len(mcp_only["shared"].find_resources("AWS::EC2::VPC")) == 1

        pipeline_only = templates(config(deploy_mcp_server=False))
        assert set(pipeline_only) == {"shared", "pipeline"}
        assert len(pipeline_only["shared"].find_resources("AWS::EC2::VPC")) == 1


class TestOutputsAreAsciiOnly:
    """CloudFormation Outputs must contain no non-ASCII characters.

    Found by deploying: CloudFormation silently replaces non-ASCII in an Output's
    value or description with ``?``. An em dash in a note about SNI reached the
    operator as "does not propagate ? create a Route 53 zone", which reads like a
    typo in the middle of the guidance that matters most.

    Only Outputs are affected. CloudWatch dashboard bodies and DevOps Agent task
    titles both preserve UTF-8 correctly, verified against the same deployment, so
    this is deliberately narrow rather than a blanket ban on the character.
    """

    def _outputs(self, built: dict[str, Template]):
        for stack_name, template in built.items():
            for key, output in template.to_json().get("Outputs", {}).items():
                yield stack_name, key, output

    def _offending(self, text: object) -> list[str]:
        if not isinstance(text, str):
            return []
        return sorted({c for c in text if ord(c) > 127})

    def test_output_values_are_ascii(self) -> None:
        problems = []
        for stack, key, output in self._outputs(templates()):
            bad = self._offending(output.get("Value"))
            if bad:
                problems.append(f"{stack}/{key} value contains {bad}")
        assert not problems, "CloudFormation would replace these with '?':\n  " + "\n  ".join(problems)

    def test_output_descriptions_are_ascii(self) -> None:
        problems = []
        for stack, key, output in self._outputs(templates()):
            bad = self._offending(output.get("Description"))
            if bad:
                problems.append(f"{stack}/{key} description contains {bad}")
        assert not problems, "CloudFormation would replace these with '?':\n  " + "\n  ".join(problems)

    def test_every_shipped_configuration_has_ascii_outputs(self) -> None:
        """Covers outputs that only appear for certain knob values, such as the
        cross-account secret policies and the private-API note."""
        import os
        from pathlib import Path

        from infrastructure.config import load_config

        os.environ.setdefault("DEVOPS_AGENT_SPACE_ID", "as-example-001")
        os.environ.setdefault("PRTG_SOURCE_IP", "203.0.113.7")

        problems = []
        config_dir = Path(__file__).resolve().parents[2] / "config"
        for path in sorted(config_dir.glob("*.yaml")):
            for stack, key, output in self._outputs(templates(load_config(path))):
                for field in ("Value", "Description"):
                    bad = self._offending(output.get(field))
                    if bad:
                        problems.append(f"{path.name}:{stack}/{key} {field.lower()} {bad}")
        assert not problems, "non-ASCII in outputs:\n  " + "\n  ".join(problems)


class TestOidcAuthorizerRendering:
    """The JWT authorizer must omit optional lists rather than send them empty.

    Both of these were found by deploying, and both had the same shape: a
    configuration that is *correct* produced a stack that either failed to deploy or
    deployed cleanly and then rejected every request.

    1. CDK renders an empty Python list as ``AllowedAudience: []``, and CloudFormation
       rejects that with "expected minimum item count: 1" rather than treating it as
       absent. Passing ``None`` omits the property.

    2. Omitting the audience is the *correct* configuration for a provider whose
       client-credentials tokens carry no ``aud`` claim. Amazon Cognito is one: its
       access tokens have ``client_id``, ``scope`` and ``sub`` but no ``aud``. A
       Gateway configured with an audience restriction rejects every such token with a
       bare 403 - verified against a real Gateway, before and after the fix.
    """

    def _authorizer(self, cfg: PrtgMcpConfig) -> dict[str, Any]:
        template = mcp_template(cfg)
        gateway = next(iter(template.find_resources("AWS::BedrockAgentCore::Gateway").values()))
        return gateway["Properties"]["AuthorizerConfiguration"]["CustomJWTAuthorizer"]

    def _oidc(self, **overrides: Any) -> PrtgMcpConfig:
        auth = {
            "mode": "oidc",
            "provider": "generic",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
        }
        auth.update(overrides)
        return config(auth=auth)

    def test_audience_is_omitted_when_not_configured(self) -> None:
        """An empty list here fails deployment outright."""
        authorizer = self._authorizer(self._oidc(allowed_clients=["client-id"]))
        assert "AllowedAudience" not in authorizer, (
            "an empty AllowedAudience is rejected by CloudFormation; omit the property instead"
        )
        assert authorizer["AllowedClients"] == ["client-id"]

    def test_clients_is_omitted_when_not_configured(self) -> None:
        authorizer = self._authorizer(self._oidc(allowed_audience=["api://client-id"]))
        assert "AllowedClients" not in authorizer
        assert authorizer["AllowedAudience"] == ["api://client-id"]

    def test_scopes_is_omitted_when_not_configured(self) -> None:
        authorizer = self._authorizer(self._oidc(allowed_clients=["client-id"]))
        assert "AllowedScopes" not in authorizer

    def test_no_authorizer_list_is_ever_rendered_empty(self) -> None:
        """Covers every optional list at once, so a new one cannot slip through."""
        for cfg in (
            self._oidc(allowed_clients=["c"]),
            self._oidc(allowed_audience=["a"]),
            self._oidc(allowed_audience=["a"], allowed_clients=["c"], allowed_scopes=["s"]),
        ):
            for key, value in self._authorizer(cfg).items():
                if isinstance(value, list):
                    assert value, f"{key} is rendered as an empty list, which CloudFormation rejects"

    def test_cognito_authorizer_does_not_set_an_audience_by_default(self) -> None:
        """Cognito omits `aud`, so a default audience would break every call."""
        authorizer = self._authorizer(config(auth={"mode": "oidc", "provider": "cognito"}))
        assert "AllowedAudience" not in authorizer

    def test_cognito_emits_a_usable_token_endpoint(self) -> None:
        """Gateway.token_endpoint_url is only populated for a Gateway-managed pool, so
        supplying an explicit authorizer left this output reading "(not available)" -
        despite the token endpoint being one of three values needed to register the
        MCP server."""
        template = mcp_template(config(auth={"mode": "oidc", "provider": "cognito"}))
        outputs = template.to_json()["Outputs"]
        assert "TokenEndpoint" in outputs
        rendered = json.dumps(outputs["TokenEndpoint"]["Value"])
        assert "not available" not in rendered
        assert "amazoncognito.com/oauth2/token" in rendered

    def test_cognito_domain_prefix_can_be_overridden(self) -> None:
        """Cognito domain prefixes are globally unique across all AWS accounts, so the
        derived default can collide with a stranger's with no way to check first."""
        template = mcp_template(
            config(auth={"mode": "oidc", "provider": "cognito", "cognito_domain_prefix": "my-own-prefix"})
        )
        domains = template.find_resources("AWS::Cognito::UserPoolDomain")
        assert domains
        assert next(iter(domains.values()))["Properties"]["Domain"] == "my-own-prefix"
