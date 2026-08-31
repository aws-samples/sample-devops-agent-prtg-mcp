"""Deployment configuration: five independent knobs, validated before synthesis.

Why this exists
---------------
This integration is conventionally documented as eighteen deployment scenarios, each
a self-contained wall of ``aws`` CLI commands with the Lambda source duplicated
verbatim. Those scenarios are not actually eighteen different architectures. They are
five independent choices:

===================  ==========================================================
Knob                 Values
===================  ==========================================================
``network.mode``     ``nat`` | ``private``
``auth.mode``        ``sigv4`` | ``oidc`` (Cognito, Entra ID, or any OIDC IdP)
``secret.mode``      ``local`` | ``external`` (same or another account)
``prtg.reachability````same-vpc`` | ``remote`` (peering / TGW / VPN / on-prem)
``targeting.mode``   ``single`` | ``fanout`` (one Agent Space or many)
===================  ==========================================================

Every conventionally documented scenario is a point in that space, and the space also
covers combinations nobody wrote down. ``docs/deployment-matrix.md`` maps the scenario
numbers onto these flags so a reader arriving with one can find their way in.

Validation philosophy
---------------------
Configuration errors are caught here, at synthesis, with a message naming the
field and what to do about it. The alternative - discovering a missing value
halfway through a CloudFormation deployment, or worse, in a Lambda cold start
during an incident - is exactly the failure mode this sample exists to remove.
``ConfigError`` messages are written for someone who has not read this file.

Secrets are never configuration
-------------------------------
No PRTG credential appears in this model, and the loader rejects any attempt to
put one in a config file. Config files get committed to git; credentials go into
Secrets Manager out of band. See ``_reject_inline_credentials``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

# --- Constants --------------------------------------------------------------

#: Regions where AWS DevOps Agent is available. Deploying the integration
#: anywhere else produces a Gateway the agent cannot be pointed at, so this is
#: checked up front rather than left to fail late.
#: Source: https://docs.aws.amazon.com/devopsagent/latest/userguide/
DEVOPS_AGENT_REGIONS: Final[frozenset[str]] = frozenset(
    {
        "us-east-1",
        "us-west-2",
        "ap-southeast-2",
        "ap-northeast-1",
        "eu-central-1",
        "eu-west-1",
    }
)

#: Interface endpoints the Lambda functions need when there is no outbound internet.
#: Omitting any one of these produces a characteristic failure:
#:   secretsmanager - the function times out fetching the credential
#:   logs           - the function runs but writes nothing to CloudWatch, which
#:                    is especially confusing because it looks like the function
#:                    is never invoked at all
#:   lambda         - the Gateway cannot invoke the function
#:   sts            - cross-account role assumption times out
#:   sqs            - the alarm pipeline cannot park a failed alarm, so the
#:                    mechanism that exists to stop an alarm being lost is the
#:                    one thing that cannot be reached when it is needed
FULLY_PRIVATE_ENDPOINTS: Final[tuple[str, ...]] = ("secretsmanager", "logs", "lambda", "sts", "sqs")

#: DevOps Agent endpoint for ``CreateBacklogTask``. Added only when the alarm pipeline is
#: deployed, since nothing else here calls the API.
#:
#: **Data plane, not control plane**, and that is not obvious from the documentation. The
#: user guide splits the endpoints into "Control Plane API Actions" (``aidevops``) and
#: "Runtime Operations" (``aidevops-dataplane``), and creating an investigation reads like
#: a control-plane action. The service model settles it: ``CreateBacklogTask`` carries
#: ``hostPrefix='dp.'``, alongside ``GetBacklogTask``, while ``RegisterService``,
#: ``CreateAgentSpace`` and ``ListAgentSpaces`` carry ``cp.``.
#:
#: Found by deploying the control-plane endpoint and watching the call fail against
#: ``dp.cp.aidevops...`` -- botocore had applied the operation's own ``dp.`` prefix on top
#: of the hostname supplied to it. That error message is what identified the plane.
#:
#: Only this endpoint is needed. Registration is a ``cp.`` operation but runs at deploy
#: time through CloudFormation, not from inside the VPC.
AGENT_DATAPLANE_ENDPOINT: Final[str] = "aidevops-dataplane"

#: Fan-out keeps its routing table in an SSM parameter, so a private deployment that
#: fans out needs to reach SSM. Missing this produced a routing lookup that hung until
#: the function timed out, which loses the alarm outright.
FANOUT_PRIVATE_ENDPOINT: Final[str] = "ssm"

NetworkMode = Literal["nat", "private"]
AuthMode = Literal["sigv4", "oidc"]
OidcProvider = Literal["cognito", "entra", "generic"]
SecretMode = Literal["local", "external"]
Reachability = Literal["same-vpc", "remote"]
TargetingMode = Literal["single", "fanout"]

_ARN_RE: Final[re.Pattern[str]] = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:.+")
_SECRET_ARN_RE: Final[re.Pattern[str]] = re.compile(
    r"^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:.+"
)
_ACCOUNT_RE: Final[re.Pattern[str]] = re.compile(r"^\d{12}$")
_AGENT_SPACE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: Values shipped in the example configs as obvious placeholders. Deploying with
#: one still in place is always a mistake, so it is rejected by name.
_PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {
        "<your-agent-space-id>",
        "<agent-space-id>",
        "REPLACE_ME",
        "changeme",
        "TODO",
        "",
    }
)


class ConfigError(ValueError):
    """A deployment configuration is invalid. The message states the remedy."""


# --- Knob 1: network egress -------------------------------------------------


@dataclass(frozen=True)
class NetworkConfig:
    """How the MCP Lambda reaches AWS APIs and PRTG.

    ``nat``
        The function sits in a private subnet with a NAT gateway default route,
        and reaches Secrets Manager over its public endpoint. Simplest to stand
        up. Around USD 32/month for the NAT gateway.

    ``private``
        No NAT gateway and no internet gateway. Every AWS API call goes through
        an interface VPC endpoint and no traffic leaves the AWS network. Required
        for regulated and air-gapped environments. Costs *more* than NAT at low
        volume, and how much more depends on the configuration, because the
        endpoint list is derived from it: five endpoints in one AZ is roughly USD
        37/month, six is USD 44 and seven is USD 51, against a NAT gateway's USD
        32. Deploying both halves means six, because the pipeline adds
        ``aidevops-dataplane``. See :meth:`required_vpc_endpoints`.

    The Lambda source is byte-identical in both modes; boto3 resolves interface
    endpoints through private DNS with no code change.
    """

    mode: NetworkMode = "nat"

    #: Existing VPC to deploy into. When omitted, a VPC is created - convenient
    #: for a demo, but most real deployments target an existing one because the
    #: route to PRTG already exists there.
    vpc_id: str | None = None

    #: Specific private subnets to place the function in.
    #:
    #: Supplying these changes *how* the VPC is resolved, not just which subnets
    #: are used, and the difference matters for CI:
    #:
    #: * ``vpc_id`` alone uses ``Vpc.from_lookup``, a synthesis-time context
    #:   lookup. It discovers subnets and AZs for you, but it calls EC2 during
    #:   ``cdk synth``, so it needs credentials and a concrete account/region.
    #: * ``vpc_id`` plus ``subnet_ids`` and ``availability_zones`` uses
    #:   ``Vpc.from_vpc_attributes``, which performs no lookup. Synthesis works
    #:   offline with no credentials at all.
    #:
    #: Pin subnets to the AZs closest to PRTG to avoid paying cross-AZ transfer
    #: on every tool call.
    subnet_ids: tuple[str, ...] = ()

    #: Availability zones for ``subnet_ids``, positionally matched. Required
    #: alongside ``subnet_ids`` because ``from_vpc_attributes`` cannot infer them
    #: without the lookup this path exists to avoid.
    availability_zones: tuple[str, ...] = ()

    #: CIDR for a newly created VPC. Ignored when ``vpc_id`` is set.
    cidr: str = "10.0.0.0/16"

    #: AZ count for a newly created VPC. Two is the minimum for a resilient
    #: deployment; one is cheaper for a demo because it halves endpoint cost.
    max_azs: int = 2

    @property
    def creates_vpc(self) -> bool:
        """True when this configuration builds a new VPC."""
        return self.vpc_id is None

    @property
    def requires_context_lookup(self) -> bool:
        """True when synthesis will call EC2 and therefore needs credentials.

        Checked by the offline synthesis test, so a config added to ``config/``
        cannot quietly break credential-free CI.
        """
        return self.vpc_id is not None and not self.subnet_ids

    def validate(self, errors: list[str]) -> None:
        if self.mode not in ("nat", "private"):
            errors.append(
                f"network.mode must be 'nat' or 'private', got {self.mode!r}. "
                "Use 'private' when the account has no outbound internet route."
            )
        if self.vpc_id and not self.vpc_id.startswith("vpc-"):
            errors.append(f"network.vpc_id must look like 'vpc-0123456789abcdef0', got {self.vpc_id!r}.")
        for subnet in self.subnet_ids:
            if not subnet.startswith("subnet-"):
                errors.append(f"network.subnet_ids entries must look like 'subnet-...', got {subnet!r}.")
        if self.subnet_ids and not self.vpc_id:
            errors.append(
                "network.subnet_ids was supplied without network.vpc_id. Subnet IDs only make "
                "sense inside an existing VPC; either add vpc_id or remove subnet_ids to have a "
                "VPC created."
            )
        if self.availability_zones and not self.subnet_ids:
            errors.append(
                "network.availability_zones was supplied without network.subnet_ids. The two are "
                "matched positionally and are only used together."
            )
        if self.subnet_ids and not self.availability_zones:
            errors.append(
                "network.availability_zones is required alongside network.subnet_ids, listing the "
                "AZ of each subnet in the same order. Supplying both avoids a synthesis-time EC2 "
                "lookup, which is what lets the stack synthesise without AWS credentials. Omit "
                "subnet_ids entirely to have the subnets discovered instead."
            )
        if (
            self.subnet_ids
            and self.availability_zones
            and len(self.subnet_ids) != len(self.availability_zones)
        ):
            errors.append(
                f"network.subnet_ids has {len(self.subnet_ids)} entries but "
                f"network.availability_zones has {len(self.availability_zones)}. They are matched "
                "positionally, so each subnet needs exactly one AZ."
            )
        if not self.vpc_id:
            _validate_cidr("network.cidr", self.cidr, errors)
            if not 1 <= self.max_azs <= 3:
                errors.append(f"network.max_azs must be between 1 and 3, got {self.max_azs}.")


# --- Knob 2: gateway inbound authentication ---------------------------------


@dataclass(frozen=True)
class AuthConfig:
    """How callers authenticate to the AgentCore Gateway.

    ``sigv4``
        IAM request signing. The DevOps Agent assumes a role that is granted
        invoke on the Gateway. No identity provider, no tokens, no rotation.
        This is the right default and covers same-account deployments.

    ``oidc``
        JWT bearer tokens from an OIDC provider. Needs exactly three values:
        a discovery URL, the allowed audience, and the allowed client IDs. The
        three ``provider`` options differ only in where those values come from,
        not in the infrastructure that gets built:

        * ``cognito`` - a user pool, resource server, app client and domain are
          created here, and the three values are derived from them.
        * ``entra`` / ``generic`` - the provider already exists (Entra ID, Okta,
          Auth0, Keycloak, Ping); supply its values and nothing is created.

    Token-based auth carries a risk IAM does not: a leaked token stays valid
    until it expires, and revoking it at the IdP does not invalidate it at the
    Gateway. Keep token lifetimes short. See ``docs/security.md``.
    """

    mode: AuthMode = "sigv4"
    provider: OidcProvider | None = None

    #: OIDC discovery document URL. Must end with the well-known path.
    discovery_url: str | None = None

    #: Audience values accepted in the token's ``aud`` claim.
    #:
    #: Only set this if your provider actually emits an ``aud`` claim in a
    #: client-credentials access token. Entra ID does; Amazon Cognito does **not**.
    #: Setting it for a provider that omits the claim means every call is rejected
    #: with a bare 403, even though the deployment succeeds. Decode a real token and
    #: look before setting this.
    allowed_audience: tuple[str, ...] = ()

    #: Client IDs permitted to call the Gateway, checked against ``client_id``.
    #: The reliable restriction when a provider omits ``aud``.
    allowed_clients: tuple[str, ...] = ()

    #: Scopes; the token must carry at least one.
    allowed_scopes: tuple[str, ...] = ()

    #: For ``provider: cognito`` - the resource server identifier that prefixes
    #: the scope, producing e.g. ``prtg-mcp-api/invoke``.
    cognito_resource_server_id: str = "prtg-mcp-api"
    cognito_scope_name: str = "invoke"

    #: Cognito hosted-domain prefix, for ``provider: cognito``.
    #:
    #: Set this if deployment fails because the generated default is taken. Cognito
    #: domain prefixes share a **global** namespace across every AWS account, not
    #: just yours, so the derived default (``<name_prefix>-<first 8 digits of the
    #: account ID>``) can in principle collide with a stranger's and there is no way
    #: to detect that in advance.
    cognito_domain_prefix: str | None = None

    #: IAM principals allowed to assume the role that invokes the Gateway
    #: (``sigv4`` only). Empty means only the DevOps Agent service principal,
    #: which is what a same-account deployment wants.
    additional_invoker_principals: tuple[str, ...] = ()

    def validate(self, errors: list[str]) -> None:  # noqa: PLR0912 - a validator is branchy by nature
        if self.mode not in ("sigv4", "oidc"):
            errors.append(f"auth.mode must be 'sigv4' or 'oidc', got {self.mode!r}.")
            return

        if self.mode == "sigv4":
            if self.discovery_url or self.allowed_audience or self.allowed_clients:
                errors.append(
                    "auth.mode is 'sigv4' but OIDC fields (discovery_url / allowed_audience / "
                    "allowed_clients) are set. Either remove them or set auth.mode to 'oidc'. "
                    "Leaving them in place would silently deploy IAM authentication while the "
                    "config reads as though it uses your identity provider."
                )
            for principal in self.additional_invoker_principals:
                if not _ARN_RE.match(principal):
                    errors.append(
                        f"auth.additional_invoker_principals entries must be IAM ARNs, got {principal!r}."
                    )
            return

        # mode == "oidc"
        if self.provider not in ("cognito", "entra", "generic"):
            errors.append(
                "auth.provider must be 'cognito', 'entra' or 'generic' when auth.mode is 'oidc', "
                f"got {self.provider!r}."
            )
            return

        if self.provider == "cognito":
            if self.discovery_url:
                errors.append(
                    "auth.discovery_url must not be set when auth.provider is 'cognito'; the user "
                    "pool is created by this stack and its discovery URL is derived automatically."
                )
            if not self.cognito_resource_server_id:
                errors.append("auth.cognito_resource_server_id must not be empty.")
            if self.cognito_domain_prefix is not None and not re.match(
                r"^[a-z0-9][a-z0-9-]{0,62}$", self.cognito_domain_prefix
            ):
                errors.append(
                    "auth.cognito_domain_prefix must be lowercase alphanumeric with hyphens, "
                    "starting with a letter or digit, up to 63 characters, got "
                    f"{self.cognito_domain_prefix!r}."
                )
            return

        # entra / generic: the IdP is external.
        if not self.discovery_url:
            errors.append(
                f"auth.discovery_url is required when auth.provider is '{self.provider}'. "
                "Entra ID: https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration"
            )
        elif not self.discovery_url.endswith("/.well-known/openid-configuration"):
            errors.append(
                "auth.discovery_url must end with '/.well-known/openid-configuration', got "
                f"{self.discovery_url!r}."
            )

        # At least one of audience or clients, not both.
        #
        # Requiring `allowed_audience` outright was wrong, and wrong in a way that
        # deploys cleanly and then fails forever: not every provider puts an `aud`
        # claim in a client-credentials access token. Amazon Cognito does not - its
        # tokens carry `client_id`, `scope` and `sub` but no `aud` - so a Gateway
        # configured with allowedAudience rejects every token with a bare 403 that
        # names nothing. Verified against a deployed Gateway.
        #
        # Microsoft Entra ID *does* emit `aud` (the API's Application ID URI), so
        # requiring it there is right. Since the provider cannot be inferred, the rule
        # is: supply at least one restriction. `allowed_clients` checks `client_id`
        # and is equally restrictive, so this keeps the endpoint from being open to
        # every token the provider issues.
        if not self.allowed_audience and not self.allowed_clients:
            errors.append(
                f"auth.allowed_audience or auth.allowed_clients is required when auth.provider is "
                f"'{self.provider}'. With neither, the Gateway accepts any token that provider "
                "issued, for any application and any client.\n"
                "     Which to use depends on what your provider puts in a client-credentials "
                "token:\n"
                "       Entra ID  - emits 'aud'; set allowed_audience to the Application ID URI "
                "(api://<client-id>), and allowed_clients as well.\n"
                "       Cognito   - emits NO 'aud' claim; set allowed_clients ONLY. Setting "
                "allowed_audience makes every call fail with 403.\n"
                "       Other     - decode a token from your provider and check for an 'aud' "
                "claim before deciding."
            )


# --- Knob 3: secret location ------------------------------------------------


@dataclass(frozen=True)
class SecretConfig:
    """Where the PRTG credential lives.

    ``local``
        This stack creates the secret. It is created **empty**: the credential is
        written afterwards with the AWS CLI, so it never passes through a config
        file, a CloudFormation parameter, or CloudTrail's record of one.

    ``external``
        The secret already exists, possibly in another account. Nothing is
        created; the execution role is granted read on that one ARN. Cross-account
        access needs **both** a Secrets Manager resource policy and a KMS key
        policy grant - supplying one and not the other is a common and confusing
        misconfiguration, so the stack emits both documents as outputs for the
        secret's owner to apply.
    """

    mode: SecretMode = "local"

    #: ARN of the existing secret. Required when ``mode`` is ``external``.
    secret_arn: str | None = None

    #: Name for the created secret (``local`` only).
    secret_name: str = "prtg-mcp/credentials"

    #: Customer-managed KMS key for the created secret. Defaults to the AWS
    #: managed key, which is adequate same-account but cannot be shared
    #: cross-account - cross-account access requires a customer-managed key.
    kms_key_arn: str | None = None

    #: Secret holding the PRTG server's certificate in PEM form, for verifying a
    #: self-signed PRTG certificate. Strongly preferred over disabling
    #: verification.
    ca_bundle_secret_arn: str | None = None

    #: How long the Lambda caches the credential. Shorter means rotation takes
    #: effect sooner; longer means fewer Secrets Manager calls.
    credential_ttl_seconds: int = 900

    def validate(self, errors: list[str]) -> None:
        if self.mode not in ("local", "external"):
            errors.append(f"secret.mode must be 'local' or 'external', got {self.mode!r}.")
            return

        if self.mode == "external":
            if not self.secret_arn:
                errors.append(
                    "secret.secret_arn is required when secret.mode is 'external'. Set "
                    "secret.mode to 'local' to have the secret created for you."
                )
            elif not _SECRET_ARN_RE.match(self.secret_arn):
                errors.append(
                    "secret.secret_arn must be a Secrets Manager ARN like "
                    "'arn:aws:secretsmanager:<region>:<account>:secret:<name>-<suffix>', got "
                    f"{self.secret_arn!r}."
                )
        elif self.secret_arn:
            errors.append(
                "secret.secret_arn was supplied but secret.mode is 'local', so a new secret "
                "would be created and the ARN ignored. Set secret.mode to 'external' to use it."
            )

        if self.ca_bundle_secret_arn and not _SECRET_ARN_RE.match(self.ca_bundle_secret_arn):
            errors.append(
                f"secret.ca_bundle_secret_arn must be a Secrets Manager ARN, got {self.ca_bundle_secret_arn!r}."
            )
        if self.kms_key_arn and not _ARN_RE.match(self.kms_key_arn):
            errors.append(f"secret.kms_key_arn must be a KMS key ARN, got {self.kms_key_arn!r}.")
        if not 0 <= self.credential_ttl_seconds <= 86_400:
            errors.append(
                f"secret.credential_ttl_seconds must be between 0 and 86400, got "
                f"{self.credential_ttl_seconds}."
            )

    def secret_account_id(self) -> str | None:
        if not self.secret_arn:
            return None
        parts = self.secret_arn.split(":")
        return parts[4] if len(parts) > 4 else None


# --- Knob 4: PRTG reachability ----------------------------------------------


@dataclass(frozen=True)
class PrtgConfig:
    """How the Lambda reaches the PRTG server, and how it trusts it.

    ``same-vpc``
        PRTG is inside the Lambda's VPC. No extra routing needed.

    ``remote``
        PRTG is in another VPC, another account, or on-premises. Supply
        ``cidr``; the security group is opened to it. The peering connection,
        Transit Gateway attachment or VPN is **not** created here - it needs
        agreement from the other side of the link, and a sample should not
        quietly reshape your network. It is a documented prerequisite.
    """

    reachability: Reachability = "same-vpc"

    #: CIDR of the network PRTG sits in. Required when ``reachability`` is
    #: ``remote``. Prefer ``host_cidr`` as well, to narrow egress to one host.
    cidr: str | None = None

    #: Single-host CIDR (``/32``) for PRTG. When set, the Lambda's egress is
    #: restricted to exactly this address on 443 - the tightest posture, and what
    #: the security review recommends.
    host_cidr: str | None = None

    #: Verify PRTG's TLS certificate. Defaults to on. PRTG frequently uses a
    #: self-signed certificate, in which case set
    #: ``secret.ca_bundle_secret_arn`` rather than turning this off.
    verify_tls: bool = True

    #: Port PRTG serves HTTPS on.
    port: int = 443

    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 20.0
    max_retries: int = 2

    def validate(self, errors: list[str], *, warnings: list[str]) -> None:
        if self.reachability not in ("same-vpc", "remote"):
            errors.append(f"prtg.reachability must be 'same-vpc' or 'remote', got {self.reachability!r}.")

        if not (self.cidr or self.host_cidr):
            # Required in both reachability modes. The alternative was to fall back
            # to the VPC CIDR for 'same-vpc', but that is unavailable when the VPC
            # is imported without a lookup, and an implicit whole-VPC egress rule
            # is worse than an explicit narrow one regardless.
            hint = (
                "Note that the peering / Transit Gateway / VPN link itself is a prerequisite this "
                "stack does not create - see docs/deployment-matrix.md."
                if self.reachability == "remote"
                else "For PRTG inside the deployment VPC, this is usually its private address as a /32."
            )
            errors.append(
                "prtg.host_cidr or prtg.cidr is required, so the function's egress can be scoped to "
                f"PRTG rather than left open. {hint}"
            )

        if self.cidr:
            _validate_cidr("prtg.cidr", self.cidr, errors)
        if self.host_cidr:
            _validate_cidr("prtg.host_cidr", self.host_cidr, errors, require_host=True)

        if not self.verify_tls:
            warnings.append(
                "prtg.verify_tls is false. PRTG's API carries the credential in the query string, "
                "so an intercepted connection exposes it. Prefer setting "
                "secret.ca_bundle_secret_arn to PRTG's certificate and leaving verification on. "
                "The Lambda will log a warning on every invocation while this is off."
            )

        if not 1 <= self.port <= 65_535:
            errors.append(f"prtg.port must be between 1 and 65535, got {self.port}.")
        if self.read_timeout_seconds <= 0 or self.connect_timeout_seconds <= 0:
            errors.append("prtg timeouts must be positive.")
        if not 0 <= self.max_retries <= 5:
            errors.append(f"prtg.max_retries must be between 0 and 5, got {self.max_retries}.")

    @property
    def egress_cidr(self) -> str | None:
        """The narrowest CIDR that still reaches PRTG."""
        return self.host_cidr or self.cidr


# --- Knob 5: agent targeting (alarm pipeline) -------------------------------


@dataclass(frozen=True)
class FanoutRoute:
    """One routing-table entry: a PRTG grouping to an Agent Space in some account."""

    #: PRTG group, probe, or device-name prefix this route matches.
    match: str
    account_id: str
    agent_space_id: str
    #: Role to assume in the target account. Defaults to the conventional name.
    role_name: str = "PrtgDevOpsAgentInvestigationRole"

    def __post_init__(self) -> None:
        # YAML parses a bare 12-digit account ID as an int, and an ID with a
        # leading zero as a *different* int. Coerce to a zero-padded string so
        # both quoted and unquoted forms behave identically, and so an ID
        # beginning with 0 is not silently truncated.
        if not isinstance(self.account_id, str):
            object.__setattr__(self, "account_id", f"{self.account_id:012d}")
        if not isinstance(self.agent_space_id, str):
            object.__setattr__(self, "agent_space_id", str(self.agent_space_id))

    def role_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"

    def validate(self, index: int, errors: list[str]) -> None:
        where = f"targeting.routes[{index}]"
        if not self.match:
            errors.append(f"{where}.match must not be empty. Use 'DEFAULT' for the fallback route.")
        if not _ACCOUNT_RE.match(self.account_id):
            errors.append(f"{where}.account_id must be 12 digits, got {self.account_id!r}.")
        _validate_agent_space(f"{where}.agent_space_id", self.agent_space_id, errors)


@dataclass(frozen=True)
class TargetingConfig:
    """Which DevOps Agent Space receives investigations from PRTG alarms.

    ``single``
        One Agent Space in this account.

    ``fanout``
        A routing table maps PRTG groupings to Agent Spaces across many accounts,
        matched in order: exact group, then probe, then device-name prefix, then
        the ``DEFAULT`` route. Adding a workload account is a routing entry plus
        one IAM role in that account - no code change.

        The routing table is stored in an SSM parameter rather than a Lambda
        environment variable. The reference implementation used an env var
        holding escaped JSON, which is awkward to edit and hits the 4 KB
        environment limit at roughly a dozen accounts.
    """

    mode: TargetingMode = "single"

    #: Agent Space in this account. Required when ``mode`` is ``single``.
    agent_space_id: str | None = None

    #: Register the MCP server as a DevOps Agent capability provider, and associate
    #: its tools with ``agent_space_id``, as part of the deployment.
    #:
    #: Off by default, for three reasons rather than caution alone. Registration is
    #: account-level, so a second deployment in the same account would collide with an
    #: existing registration. Many teams register once through the console and manage
    #: Agent Spaces separately from the servers they consume. And the tool allowlist is
    #: a decision an operator may want to make deliberately, not inherit.
    #:
    #: Requires ``mode: single`` and ``auth.mode: sigv4``. Only SigV4 can be registered
    #: from infrastructure code; OAuth providers need the console's browser redirect.
    register_with_agent_space: bool = False

    #: Routes, for ``mode: fanout``. Exactly one must have ``match: DEFAULT``.
    routes: tuple[FanoutRoute, ...] = ()

    #: ``sts:ExternalId`` required by the target accounts' trust policies.
    external_id: str = "prtg-devops-agent-integration"

    #: Restrict cross-account assumption to principals in this AWS Organization,
    #: so a new workload account does not need a policy change. Strongly
    #: recommended over a wildcard resource.
    organization_id: str | None = None

    #: Suppress duplicate investigations for the same sensor and state within
    #: this window, using CreateBacklogTask's idempotency token. The reference
    #: implementation had no deduplication and pushed the problem onto PRTG's
    #: notification triggers.
    deduplication_window_minutes: int = 30

    #: Override the DevOps Agent API endpoint the pipeline calls.
    #:
    #: Leave unset. ``network.mode: private`` derives the right value on its own --
    #: see ``PrtgMcpConfig.agent_endpoint_url`` for why an override is needed there at
    #: all. This exists for the cases derivation cannot know about: FIPS endpoints, a
    #: partition other than ``aws``, or a future hostname change.
    agent_endpoint_url: str | None = None

    def validate(self, errors: list[str]) -> None:  # noqa: PLR0912 - a validator is branchy by nature
        if self.mode not in ("single", "fanout"):
            errors.append(f"targeting.mode must be 'single' or 'fanout', got {self.mode!r}.")
            return

        if self.mode == "single":
            if not self.agent_space_id:
                errors.append(
                    "targeting.agent_space_id is required when targeting.mode is 'single'. Create an "
                    "Agent Space first (see the AWS DevOps Agent getting-started guide) and put its "
                    "ID here."
                )
            else:
                # Distinguished from "missing" on purpose: being told a value is
                # required when the file plainly contains one is confusing.
                _validate_agent_space("targeting.agent_space_id", self.agent_space_id, errors)
            if self.routes:
                errors.append(
                    "targeting.routes was supplied but targeting.mode is 'single', so the routes "
                    "would be ignored. Set targeting.mode to 'fanout' to use them."
                )
        else:
            if self.register_with_agent_space:
                errors.append(
                    "targeting.register_with_agent_space is true but targeting.mode is 'fanout'. "
                    "Registration associates the tools with one Agent Space, and fanout has "
                    "several. Register the server once, then associate it with each Agent Space "
                    "yourself."
                )
            if not self.routes:
                errors.append(
                    "targeting.routes must contain at least one entry when targeting.mode is 'fanout'."
                )
            for index, route in enumerate(self.routes):
                route.validate(index, errors)

            defaults = [r for r in self.routes if r.match == "DEFAULT"]
            if not defaults:
                errors.append(
                    "targeting.routes must include one route with match 'DEFAULT'. Without it, an "
                    "alarm from an unmapped PRTG group is dropped, which means a real alert would "
                    "silently never reach any agent."
                )
            elif len(defaults) > 1:
                errors.append("targeting.routes must contain exactly one route with match 'DEFAULT'.")

            matches = [r.match for r in self.routes]
            duplicates = {m for m in matches if matches.count(m) > 1}
            if duplicates:
                errors.append(
                    f"targeting.routes has duplicate match values: {', '.join(sorted(duplicates))}. "
                    "Each PRTG grouping must map to exactly one Agent Space."
                )

        if len(self.external_id) < 8:
            errors.append(
                "targeting.external_id should be at least 8 characters. It is a shared value that "
                "guards against the confused-deputy problem in cross-account assumption."
            )
        if not 0 <= self.deduplication_window_minutes <= 1_440:
            errors.append(
                "targeting.deduplication_window_minutes must be between 0 and 1440, got "
                f"{self.deduplication_window_minutes}."
            )

    def default_route(self) -> FanoutRoute | None:
        return next((r for r in self.routes if r.match == "DEFAULT"), None)

    def routing_table(self) -> dict[str, dict[str, str]]:
        """Render the routes as the JSON document the pipeline Lambda reads."""
        return {
            route.match: {
                "account": route.account_id,
                "agentSpaceId": route.agent_space_id,
                "roleArn": route.role_arn(),
            }
            for route in self.routes
        }


# --- Observability ----------------------------------------------------------


@dataclass(frozen=True)
class ObservabilityConfig:
    """Logging, metrics, alarms, and tracing.

    Log retention is set explicitly. Left unset, CloudWatch keeps logs forever,
    which is both a slow cost leak and, for logs that may contain infrastructure
    detail, a data-retention question nobody chose to answer.
    """

    log_retention_days: int = 30

    #: Email address subscribed to the alarm topic. A topic with no subscriber is
    #: a common way for alarms to exist but never reach anyone.
    alarm_email: str | None = None

    #: Existing SNS topic for alarms. Takes precedence over ``alarm_email``.
    alarm_topic_arn: str | None = None

    #: Build a CloudWatch dashboard covering both halves of the integration.
    dashboard: bool = True

    #: X-Ray active tracing. Useful for seeing where latency sits between
    #: Gateway, Lambda, and PRTG.
    tracing: bool = True

    def validate(self, errors: list[str], *, warnings: list[str]) -> None:
        valid_retention = {1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 3653}
        if self.log_retention_days not in valid_retention:
            errors.append(
                f"observability.log_retention_days must be a CloudWatch-supported value "
                f"({', '.join(str(v) for v in sorted(valid_retention))}), got {self.log_retention_days}."
            )
        if self.alarm_topic_arn and not _ARN_RE.match(self.alarm_topic_arn):
            errors.append(f"observability.alarm_topic_arn must be an SNS ARN, got {self.alarm_topic_arn!r}.")
        if self.alarm_email and "@" not in self.alarm_email:
            errors.append(f"observability.alarm_email does not look like an address: {self.alarm_email!r}.")
        if not self.alarm_email and not self.alarm_topic_arn:
            warnings.append(
                "No observability.alarm_email or alarm_topic_arn is set. Alarms will be created but "
                "will notify nobody, so a broken PRTG credential would go unnoticed until an "
                "investigation needed the data."
            )


# --- Lambda sizing ----------------------------------------------------------


@dataclass(frozen=True)
class LambdaConfig:
    """Function sizing. Defaults are deliberate, not arbitrary.

    256 MB is above the minimum because CPU is allocated in proportion to memory
    and these functions spend their time on TLS handshakes and JSON parsing, both
    CPU-bound. Dropping to 128 MB tends to cost more overall because the function
    runs more than twice as long.

    30 seconds accommodates a cold start inside a VPC (ENI attachment adds
    seconds) plus a PRTG query on a busy server, while staying below the
    Gateway's own patience.
    """

    memory_mb: int = 256
    timeout_seconds: int = 30

    #: Reserved concurrency, which doubles as a blast-radius limit: an agent in a
    #: retry loop cannot turn into unbounded load on PRTG.
    reserved_concurrency: int | None = 10

    #: Provisioned concurrency to hide VPC cold starts. Costs about USD 2.50 per
    #: month per unit; worth it only where first-call latency matters.
    provisioned_concurrency: int | None = None

    def validate(self, errors: list[str], *, prefix: str) -> None:
        if not 128 <= self.memory_mb <= 10_240:
            errors.append(f"{prefix}.memory_mb must be between 128 and 10240, got {self.memory_mb}.")
        if not 1 <= self.timeout_seconds <= 900:
            errors.append(f"{prefix}.timeout_seconds must be between 1 and 900, got {self.timeout_seconds}.")
        if self.reserved_concurrency is not None and self.reserved_concurrency < 1:
            errors.append(f"{prefix}.reserved_concurrency must be at least 1, or null for no reservation.")
        if self.provisioned_concurrency is not None:
            if self.provisioned_concurrency < 1:
                errors.append(f"{prefix}.provisioned_concurrency must be at least 1, or null.")
            elif (
                self.reserved_concurrency is not None
                and self.provisioned_concurrency > self.reserved_concurrency
            ):
                errors.append(
                    f"{prefix}.provisioned_concurrency ({self.provisioned_concurrency}) cannot exceed "
                    f"reserved_concurrency ({self.reserved_concurrency})."
                )


# --- Top level --------------------------------------------------------------


@dataclass(frozen=True)
class PrtgMcpConfig:
    """A complete, validated deployment configuration."""

    region: str
    account: str | None = None

    #: Prefix for resource names, so several deployments can coexist.
    name_prefix: str = "prtg-mcp"

    #: Deploy the MCP server (Gateway + Lambda + PRTG tools). This is the half
    #: that lets the agent query PRTG during an investigation.
    deploy_mcp_server: bool = True

    #: Deploy the alarm pipeline (API Gateway + Lambda + CreateBacklogTask). This
    #: is the half that starts an investigation when PRTG raises an alarm.
    deploy_alarm_pipeline: bool = True

    network: NetworkConfig = field(default_factory=NetworkConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    secret: SecretConfig = field(default_factory=SecretConfig)
    prtg: PrtgConfig = field(default_factory=PrtgConfig)
    targeting: TargetingConfig = field(default_factory=TargetingConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    mcp_lambda: LambdaConfig = field(default_factory=LambdaConfig)
    pipeline_lambda: LambdaConfig = field(default_factory=LambdaConfig)

    #: Source IPs allowed to POST alarms to the pipeline API. PRTG's HTTP action
    #: cannot send custom headers, so an API key is not an option and the source
    #: address is the available control. Required for a public endpoint.
    alarm_allowed_source_ips: tuple[str, ...] = ()

    #: Make the alarm API private, reachable only through a VPC endpoint. The
    #: right answer when PRTG has no public address.
    alarm_api_private: bool = False

    tags: dict[str, str] = field(default_factory=dict)

    #: Collected non-fatal concerns, surfaced at synthesis.
    warnings: tuple[str, ...] = ()

    def validate(self) -> PrtgMcpConfig:
        """Validate every knob and their interactions.

        Returns a copy carrying any warnings. Raises ``ConfigError`` listing all
        problems at once rather than stopping at the first - fixing five errors
        across five deploy attempts is a miserable way to spend an afternoon.
        """
        errors: list[str] = []
        warnings: list[str] = []

        if self.region not in DEVOPS_AGENT_REGIONS:
            errors.append(
                f"region {self.region!r} does not offer AWS DevOps Agent. Supported regions: "
                f"{', '.join(sorted(DEVOPS_AGENT_REGIONS))}. Deploying elsewhere would build a "
                "Gateway that no Agent Space can be pointed at."
            )
        if self.account and not _ACCOUNT_RE.match(self.account):
            errors.append(f"account must be 12 digits, got {self.account!r}.")
        if not re.match(r"^[a-z0-9][a-z0-9-]{1,30}$", self.name_prefix):
            errors.append(
                "name_prefix must be lowercase alphanumeric with hyphens, 2-31 characters, got "
                f"{self.name_prefix!r}."
            )
        if not self.deploy_mcp_server and not self.deploy_alarm_pipeline:
            errors.append(
                "Both deploy_mcp_server and deploy_alarm_pipeline are false, which would deploy "
                "nothing. Enable at least one."
            )

        self.network.validate(errors)
        self.auth.validate(errors)
        self.secret.validate(errors)
        self.prtg.validate(errors, warnings=warnings)
        self.observability.validate(errors, warnings=warnings)
        self.mcp_lambda.validate(errors, prefix="mcp_lambda")
        self.pipeline_lambda.validate(errors, prefix="pipeline_lambda")

        if self.deploy_alarm_pipeline:
            self.targeting.validate(errors)
            self._validate_alarm_ingress(errors, warnings)

        self._validate_interactions(errors, warnings)

        if errors:
            raise ConfigError(
                "Deployment configuration is invalid:\n\n"
                + "\n\n".join(f"  {index}. {message}" for index, message in enumerate(errors, 1))
                + "\n\nSee docs/deployment-matrix.md for worked examples.\n"
            )

        return dataclass_replace(self, warnings=tuple(warnings))

    def _validate_alarm_ingress(self, errors: list[str], warnings: list[str]) -> None:
        if self.alarm_api_private:
            # This used to say the IP list "adds little" alongside a private API, which is
            # true of the resource policy and wrong about reachability. A private API's
            # policy is keyed on aws:SourceVpce and never mentions the addresses -- but the
            # list is ALSO what builds the execute-api endpoint's security group ingress,
            # so it is load-bearing, and it needs a different kind of address than the
            # public case. A private API sees PRTG's private address; a public one sees
            # whatever PRTG egresses as.
            #
            # Getting it wrong is close to undiagnosable. Deployed with the NAT gateway's
            # public address, the API hostname resolved correctly to the endpoint and then
            # refused the connection, because a security group drop produces no HTTP status
            # and no log line anywhere. Worth spending a validation message on.
            # Keyed on host_cidr rather than reachability, because host_cidr is the only
            # field that states PRTG's exact address. When only prtg.cidr is set the
            # address is a range and there is nothing definite to compare against, so
            # stay quiet rather than guess.
            if (
                self.alarm_allowed_source_ips
                and self.prtg.host_cidr
                and self.prtg.host_cidr not in self.alarm_allowed_source_ips
            ):
                warnings.append(
                    "alarm_api_private is true and alarm_allowed_source_ips does not contain "
                    f"{self.prtg.host_cidr!r}, the address prtg.host_cidr says PRTG uses. For "
                    "a private API this list builds the execute-api endpoint's security group "
                    "ingress, so it must hold PRTG's address ON THE NETWORK -- not the public "
                    "address it egresses as, which is what a public API would see. The "
                    "resource policy is keyed on aws:SourceVpce and is unaffected either way, "
                    "so a wrong value here fails as a refused connection with nothing in any "
                    "log rather than as a 403."
                )
            return

        if not self.alarm_allowed_source_ips:
            errors.append(
                "alarm_allowed_source_ips must list at least one CIDR when the alarm API is public. "
                "PRTG's HTTP action cannot send custom headers, so an API key is not available and "
                "the source address is the only control. An unrestricted endpoint would let anyone "
                "create investigations in your Agent Space. Alternatively set alarm_api_private "
                "to true."
            )
        for cidr in self.alarm_allowed_source_ips:
            _validate_cidr("alarm_allowed_source_ips", cidr, errors)
            if cidr == "0.0.0.0/0":
                errors.append(
                    "alarm_allowed_source_ips contains 0.0.0.0/0, which allows the entire internet "
                    "to create investigations. Use PRTG's public address as a /32, or set "
                    "alarm_api_private to true."
                )

    def _validate_cross_account_secret(self, errors: list[str], warnings: list[str]) -> None:
        """Checks for a secret owned by a different account.

        Three grants are needed and they are split across two accounts, which is why this
        is worth its own method: a resource policy and a key policy in the owning account,
        and ``kms:Decrypt`` here. The stack emits the first two as outputs for the owner to
        apply, and applies the third itself given the key ARN.
        """
        if self.secret.mode != "external" or not self.account:
            return

        secret_account = self.secret.secret_account_id()
        if not secret_account or secret_account == self.account:
            return

        warnings.append(
            f"The PRTG secret lives in account {secret_account} while this stack deploys to "
            f"{self.account}. Cross-account access needs a resource policy on the secret AND "
            "a KMS key policy grant on its customer-managed key. Both documents are emitted "
            "as stack outputs; the secret's owner must apply them, and granting only one is "
            "the usual cause of an AccessDenied that looks like an IAM problem."
        )

        # An error, not a warning. Cross-account KMS needs the grant on both sides, and
        # this side is the one the stack can actually apply. Without the ARN, `grant_read`
        # has no key to grant on -- an imported secret does not tell CDK which key encrypts
        # it -- so the deployment succeeds and every credential read fails with "Access to
        # KMS is not allowed", which is also what a missing key policy looks like. Found
        # the hard way, against a real second account.
        if not self.secret.kms_key_arn:
            errors.append(
                "secret.kms_key_arn is required when the secret is in another account "
                f"({secret_account}). The reading role needs kms:Decrypt on the key encrypting "
                "it, and an imported secret does not reveal which key that is, so it has to be "
                "named. Without it every credential read fails with 'Access to KMS is not "
                "allowed' while the deployment itself reports success."
            )

    def _validate_interactions(self, errors: list[str], warnings: list[str]) -> None:
        """Checks that only make sense across two or more knobs."""

        # A created secret with the AWS managed key cannot be shared across
        # accounts; that needs a customer-managed key.
        self._validate_cross_account_secret(errors, warnings)

        # An audience restriction with no client restriction is the asymmetry that
        # produced a silent 403 in testing.
        if (
            self.auth.mode == "oidc"
            and self.auth.provider in ("entra", "generic")
            and self.auth.allowed_audience
            and not self.auth.allowed_clients
        ):
            warnings.append(
                "auth.allowed_audience is set but auth.allowed_clients is not. If your provider "
                "does not put an 'aud' claim in a client-credentials access token, every call will "
                "be rejected with 403 while the deployment still succeeds. Amazon Cognito omits "
                "'aud'; Entra ID includes it. Decode a real token from your provider, and prefer "
                "setting allowed_clients as well."
            )

        # Cognito plus fully-private needs one more endpoint than the other
        # combinations, because token validation happens inside the VPC.
        if self.network.mode == "private" and self.auth.mode == "oidc" and self.auth.provider == "cognito":
            warnings.append(
                "Fully-private networking with a Cognito authorizer also needs a cognito-idp "
                "interface endpoint, which this stack creates. External providers such as Entra ID "
                "do not need one, because the Gateway validates those tokens at the AWS service "
                "plane rather than from inside your VPC."
            )

        # Registration from infrastructure code needs SigV4; an OAuth provider needs a
        # browser redirect that CloudFormation cannot perform.
        if self.targeting.register_with_agent_space and self.auth.mode != "sigv4":
            errors.append(
                "targeting.register_with_agent_space is true but auth.mode is "
                f"{self.auth.mode!r}. Only a SigV4 Gateway can be registered from "
                "infrastructure code: an OAuth provider needs the interactive browser "
                "redirect the DevOps Agent console performs. Either set auth.mode to "
                "'sigv4', or register through the console and leave this false."
            )

        if self.targeting.register_with_agent_space and not self.deploy_mcp_server:
            errors.append(
                "targeting.register_with_agent_space is true but deploy_mcp_server is false. "
                "There is no Gateway to register."
            )

        # The pipeline holds back 8s of its invocation so that a failed investigation can
        # still be written to the dead-letter queue, and floors the API call budget at 6s.
        # Below roughly 20s there is not enough room for both, and the function starts
        # parking every alarm without attempting it -- safe, since nothing is lost, but
        # useless, and the cause is not obvious from the outside.
        if self.deploy_alarm_pipeline and self.pipeline_lambda.timeout_seconds < 20:
            warnings.append(
                f"pipeline_lambda.timeout_seconds is {self.pipeline_lambda.timeout_seconds}, which "
                "leaves too little room. The function reserves 8s to park a failed alarm on the "
                "dead-letter queue and needs at least 6s to attempt the investigation, so below "
                "about 20s it will park alarms without trying to create them. Nothing is lost, but "
                "no investigation is created either. Raise it to 30s or more."
            )

        if not self.prtg.verify_tls and self.prtg.reachability == "remote":
            warnings.append(
                "TLS verification is disabled and PRTG is reached across a network boundary. This is "
                "the specific combination flagged in the security review: the longer path gives more "
                "opportunity for interception, and the PRTG credential travels in the query string. "
                "Supply secret.ca_bundle_secret_arn instead."
            )

        # A private API needs somewhere for the endpoint to live.
        if self.alarm_api_private and self.deploy_alarm_pipeline and not self.network.vpc_id:
            warnings.append(
                "alarm_api_private is true and no existing VPC was supplied, so a new VPC is created "
                "for the execute-api endpoint. PRTG must be able to route to it, which usually means "
                "you want network.vpc_id set to the VPC PRTG can already reach."
            )

        # Fanout without an org ID means enumerating every account in IAM.
        if (
            self.deploy_alarm_pipeline
            and self.targeting.mode == "fanout"
            and not self.targeting.organization_id
        ):
            warnings.append(
                "targeting.mode is 'fanout' without targeting.organization_id, so the Lambda role "
                "will list each target role ARN explicitly and adding an account will require an IAM "
                "change. Setting organization_id lets the policy wildcard the account and constrain "
                "it with aws:ResourceOrgID instead, so new accounts need no policy update."
            )

        # Narrow egress is available and cheap; say so if it was skipped.
        if self.deploy_mcp_server and not self.prtg.host_cidr:
            warnings.append(
                "prtg.host_cidr is not set, so the Lambda's egress is opened to a whole CIDR rather "
                "than to the PRTG host alone. Setting it to PRTG's address as a /32 is the tightest "
                "posture and is what the security review recommends."
            )

        if self.observability.log_retention_days > 90:
            warnings.append(
                f"observability.log_retention_days is {self.observability.log_retention_days}. These "
                "logs record infrastructure names and IP addresses from PRTG; keep them only as long "
                "as your retention policy calls for."
            )

    # --- Derived values -----------------------------------------------------

    @property
    def is_fully_private(self) -> bool:
        return self.network.mode == "private"

    @property
    def agent_endpoint_url(self) -> str | None:
        """Endpoint the pipeline should call for the DevOps Agent API, or ``None``.

        ``None`` means "use the SDK default", which is correct whenever the function has
        a route to the internet.

        In ``private`` mode it is not. Every other interface endpoint this stack creates
        publishes private DNS for the same hostname the SDK already calls, so boto3 needs
        no configuration and the Lambda source is identical in both network modes. The
        DevOps Agent endpoints break that pattern: they serve names under
        ``aidevops.<region>.api.aws``, while boto3's default endpoint for ``devops-agent``
        is ``aidevops.<region>.amazonaws.com``. Different domains, so enabling private DNS
        does not intercept the SDK's call.

        Measured rather than inferred. From inside an isolated VPC with an endpoint
        present and private DNS on::

            aidevops.ap-southeast-2.amazonaws.com       -> NO ANSWER
            cp.aidevops.ap-southeast-2.api.aws          -> 10.91.0.32   (endpoint ENI)
            secretsmanager.ap-southeast-2.amazonaws.com -> 10.91.0.191  (endpoint ENI)

        The third line is the control: for an ordinary service the two names coincide. So
        the endpoint alone leaves the pipeline hanging until it times out, which is how
        this was found -- three deployments, each reaching routing and then dying silently.

        **The value deliberately carries no ``dp.`` or ``cp.`` prefix.** Each operation in
        the service model has its own ``hostPrefix``, and botocore prepends it to whatever
        endpoint it is given. Supplying the fully-qualified ``cp.aidevops...`` name
        produced a request to ``dp.cp.aidevops...``, because ``CreateBacklogTask`` adds
        ``dp.`` of its own. Handing over the un-prefixed base lets botocore build
        ``dp.aidevops.<region>.api.aws``, which is exactly what the ``aidevops-dataplane``
        endpoint serves.
        """
        if self.targeting.agent_endpoint_url:
            return self.targeting.agent_endpoint_url
        if self.is_fully_private and self.deploy_alarm_pipeline:
            # No prefix: botocore adds the operation's own. See above.
            return f"https://aidevops.{self.region}.api.aws"
        return None

    @property
    def required_vpc_endpoints(self) -> tuple[str, ...]:
        """Interface endpoints this configuration needs.

        Two independent reasons an endpoint is required, and conflating them is a
        mistake worth avoiding:

        * ``network.mode: private`` means the Lambda has no route to the internet,
          so every AWS API it calls needs an endpoint.
        * ``alarm_api_private`` means the REST API is a private API, which is
          *only* reachable through an ``execute-api`` interface endpoint. That
          holds whether or not the Lambda has NAT egress, because it concerns
          inbound traffic from PRTG rather than outbound traffic from the function.
        """
        endpoints: list[str] = []

        if self.is_fully_private:
            endpoints.extend(FULLY_PRIVATE_ENDPOINTS)
            # Cognito tokens are validated from inside the VPC, so a private
            # deployment using Cognito needs one more endpoint. External providers
            # such as Entra ID do not: the Gateway validates those at the AWS
            # service plane.
            if self.auth.mode == "oidc" and self.auth.provider == "cognito":
                endpoints.append("cognito-idp")
            if self.deploy_alarm_pipeline:
                # Without this the pipeline reaches parsing and routing, then hangs on
                # CreateBacklogTask until the sandbox is killed. The alarm is lost
                # outright: the timeout kills the process rather than raising, so the
                # dead-letter park never runs and PrtgAlarmsLost cannot fire either.
                endpoints.append(AGENT_DATAPLANE_ENDPOINT)
                if self.targeting.mode == "fanout":
                    endpoints.append(FANOUT_PRIVATE_ENDPOINT)

        if self.alarm_api_private and self.deploy_alarm_pipeline:
            endpoints.append("execute-api")

        return tuple(endpoints)

    def resource_name(self, suffix: str) -> str:
        return f"{self.name_prefix}-{suffix}"


# --- Loading ----------------------------------------------------------------


def dataclass_replace(instance: PrtgMcpConfig, **changes: Any) -> PrtgMcpConfig:
    """``dataclasses.replace`` without importing it at module scope."""
    from dataclasses import replace

    return replace(instance, **changes)


def load_config(path: str | Path) -> PrtgMcpConfig:
    """Load and validate a YAML or JSON configuration file.

    Raises:
        ConfigError: if the file is missing, malformed, contains unknown keys, or
            fails validation.
    """
    path = Path(path)
    if not path.exists():
        available = sorted(p.name for p in path.parent.glob("*.y*ml")) if path.parent.exists() else []
        raise ConfigError(
            f"Configuration file not found: {path}. "
            + (f"Available in {path.parent}: {', '.join(available)}." if available else "")
        )

    text = path.read_text(encoding="utf-8")

    try:
        if path.suffix in (".yaml", ".yml"):
            import yaml

            raw = yaml.safe_load(text) or {}
        else:
            raw = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"Could not parse {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level.")

    # Interpolation runs after parsing, on values only. Doing it on the raw text
    # would also rewrite comments, and these files document the ${VAR:-fallback}
    # syntax in their own comments.
    raw = interpolate_environment(raw, source=str(path))

    return build_config(raw, source=str(path))


#: ``${VAR}`` or ``${VAR:-fallback}`` in a configuration file.
_INTERPOLATION_RE: Final[re.Pattern[str]] = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def interpolate_environment(node: Any, *, source: str = "<config>") -> Any:
    """Substitute ``${VAR}`` and ``${VAR:-fallback}`` throughout a parsed config.

    This exists so the example configurations can be committed without carrying
    anybody's account IDs, VPC IDs, or Agent Space IDs, while remaining genuinely
    synthesisable in CI. A shipped example that has never been synthesised is an
    example nobody has tested.

    Operates on the parsed structure rather than the raw file text, so comments
    are left alone - these files document this very syntax in their comments, and
    a text-level pass would try to expand the documentation.

    Environment-supplied values are for identifiers only. Credentials still never
    belong in a configuration file, interpolated or otherwise;
    ``_reject_inline_credentials`` runs afterwards and does not care where a value
    came from.

    Raises:
        ConfigError: when a referenced variable is unset and has no fallback,
            naming every missing variable and where it was referenced.
    """
    import os

    missing: dict[str, str] = {}

    def substitute(text: str, path: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name, fallback = match.group(1), match.group(2)
            value = os.environ.get(name)
            if value:
                return value
            if fallback is not None:
                return fallback
            missing.setdefault(name, path)
            return match.group(0)

        return _INTERPOLATION_RE.sub(replace, text)

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, str):
            return substitute(value, path)
        if isinstance(value, dict):
            return {k: walk(v, f"{path}{k}." if path else f"{k}.") for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(value)]
        return value

    result = walk(node, "")

    if missing:
        raise ConfigError(
            f"{source} references environment variable(s) that are not set:\n\n"
            + "".join(
                f"  ${{{name}}}  (referenced at {location.rstrip('.') or 'top level'})\n"
                for name, location in sorted(missing.items())
            )
            + "\nEither export them:\n\n"
            + "".join(f"  export {name}=...\n" for name in sorted(missing))
            + "\nor replace the placeholder with a literal value. To supply a default inside the "
            "file, use the ${NAME:-fallback} form."
        )

    return result


def build_config(raw: dict[str, Any], *, source: str = "<dict>") -> PrtgMcpConfig:
    """Build a validated config from a plain dictionary."""
    _reject_inline_credentials(raw, source)

    known_top_level = {
        "region",
        "account",
        "name_prefix",
        "deploy_mcp_server",
        "deploy_alarm_pipeline",
        "network",
        "auth",
        "secret",
        "prtg",
        "targeting",
        "observability",
        "mcp_lambda",
        "pipeline_lambda",
        "alarm_allowed_source_ips",
        "alarm_api_private",
        "tags",
    }
    unknown = set(raw) - known_top_level
    if unknown:
        raise ConfigError(
            f"{source} has unknown top-level key(s): {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(sorted(known_top_level))}."
        )

    if "region" not in raw:
        raise ConfigError(
            f"{source} must set 'region'. AWS DevOps Agent is only available in: "
            f"{', '.join(sorted(DEVOPS_AGENT_REGIONS))}."
        )

    targeting_raw = dict(raw.get("targeting") or {})
    routes_raw = targeting_raw.pop("routes", []) or []
    routes = tuple(FanoutRoute(**_section(r, FanoutRoute, f"{source}:targeting.routes")) for r in routes_raw)

    config = PrtgMcpConfig(
        region=raw["region"],
        # Zero-padded, for the same reason as FanoutRoute.account_id: YAML turns an
        # unquoted account ID into an int and drops any leading zero.
        account=_account_or_none(raw.get("account")),
        name_prefix=raw.get("name_prefix", "prtg-mcp"),
        deploy_mcp_server=bool(raw.get("deploy_mcp_server", True)),
        deploy_alarm_pipeline=bool(raw.get("deploy_alarm_pipeline", True)),
        network=NetworkConfig(
            **_section(
                raw.get("network"),
                NetworkConfig,
                f"{source}:network",
                tuples=("subnet_ids", "availability_zones"),
            )
        ),
        auth=AuthConfig(
            **_section(
                raw.get("auth"),
                AuthConfig,
                f"{source}:auth",
                tuples=(
                    "allowed_audience",
                    "allowed_clients",
                    "allowed_scopes",
                    "additional_invoker_principals",
                ),
            )
        ),
        secret=SecretConfig(**_section(raw.get("secret"), SecretConfig, f"{source}:secret")),
        prtg=PrtgConfig(**_section(raw.get("prtg"), PrtgConfig, f"{source}:prtg")),
        targeting=TargetingConfig(
            **_section(targeting_raw, TargetingConfig, f"{source}:targeting"), routes=routes
        ),
        observability=ObservabilityConfig(
            **_section(raw.get("observability"), ObservabilityConfig, f"{source}:observability")
        ),
        mcp_lambda=LambdaConfig(**_section(raw.get("mcp_lambda"), LambdaConfig, f"{source}:mcp_lambda")),
        pipeline_lambda=LambdaConfig(
            **_section(raw.get("pipeline_lambda"), LambdaConfig, f"{source}:pipeline_lambda")
        ),
        alarm_allowed_source_ips=tuple(raw.get("alarm_allowed_source_ips") or ()),
        alarm_api_private=bool(raw.get("alarm_api_private", False)),
        tags=dict(raw.get("tags") or {}),
    )
    return config.validate()


def _section(raw: Any, cls: type, where: str, *, tuples: tuple[str, ...] = ()) -> dict[str, Any]:
    """Coerce a config sub-mapping into constructor keyword arguments."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping, got {type(raw).__name__}.")

    valid = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    unknown = set(raw) - valid
    if unknown:
        raise ConfigError(
            f"{where} has unknown key(s): {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(sorted(valid))}."
        )

    result = dict(raw)
    for key in tuples:
        if key in result and result[key] is not None:
            result[key] = tuple(result[key])
    return result


def _reject_inline_credentials(raw: dict[str, Any], source: str) -> None:
    """Refuse a config that carries a PRTG credential.

    Config files are committed to version control. A credential placed here would end
    up in git history, in every clone, and in any CI log that echoes the file. Scrubbing
    it later does not help: history keeps it, so the only remedy is rotation. The
    credential belongs in Secrets Manager, written out of band.

    ``prtg_api_key`` is in this set for the same reason as ``prtg_passhash``. It was
    missing at first, on the reasoning that a key is revocable and so matters less --
    which is wrong twice over. Revocable still means a live credential until somebody
    notices, and an operator following the recommended path now reaches for a key
    first, so the key is the value most likely to be pasted into the wrong file.
    """
    forbidden = {
        "prtg_passhash",
        "passhash",
        "prtg_password",
        "password",
        "prtg_username",
        "username",
        "prtg_api_key",
        "api_key",
        "apikey",
        "apitoken",
    }
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in forbidden:
                    found.append(f"{path}{key}")
                walk(value, f"{path}{key}.")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}].")

    walk(raw, "")
    if found:
        raise ConfigError(
            f"{source} appears to contain PRTG credentials at: {', '.join(found)}. Credentials must "
            "not live in configuration files, which are committed to version control. Set "
            "secret.mode to 'local' to have an empty secret created, then write the credential "
            "with an API key, which is the preferred form because it can be revoked on its own:"
            "\n\n"
            "  aws secretsmanager put-secret-value --secret-id <name> \\\n"
            '    --secret-string \'{"prtg_url":"https://...","prtg_api_key":"..."}\'\n\n'
            "Or, if your PRTG version has no API Keys tab:\n\n"
            "  aws secretsmanager put-secret-value --secret-id <name> \\\n"
            '    --secret-string \'{"prtg_url":"https://...","prtg_username":"...","prtg_passhash":"..."}\'\n'
        )


# --- Small helpers ----------------------------------------------------------


def _account_or_none(value: Any) -> str | None:
    """Normalise an AWS account ID to a 12-character string, or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return f"{value:012d}"
    return str(value)


def _validate_agent_space(field_name: str, value: str, errors: list[str]) -> None:
    if value in _PLACEHOLDERS:
        errors.append(
            f"{field_name} is still the placeholder {value!r}. Replace it with a real Agent Space ID."
        )
    elif not _AGENT_SPACE_RE.match(value):
        errors.append(
            f"{field_name} must be 1-128 characters of letters, digits, hyphen or underscore, got {value!r}."
        )


def _validate_cidr(field_name: str, value: str, errors: list[str], *, require_host: bool = False) -> None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        errors.append(f"{field_name} is not a valid CIDR: {value!r} ({exc}).")
        return
    if require_host and network.num_addresses != 1:
        errors.append(
            f"{field_name} must be a single host (/32 for IPv4), got {value!r} which covers "
            f"{network.num_addresses} addresses."
        )
