"""The PRTG credential: created locally, or referenced in another account.

Two things here are deliberate and worth reading before changing them.

**A created secret is created empty.** No credential is passed in from
configuration, from a CloudFormation parameter, or from a CDK context value. All
three end up somewhere durable - a git history, a CloudFormation template stored
in S3, CloudTrail's record of the API call that set the parameter - and a PRTG
passhash grants full API access to a system that itself aggregates credentials
for everything it monitors. The credential is written after deployment with a
single CLI call, and the stack emits that command as an output.

**Cross-account access emits both policies it needs, not one.** Reading a secret
in another account requires a Secrets Manager resource policy *and* a KMS key
policy grant on the customer-managed key encrypting it. The security review calls
this out as a common misconfiguration, so both documents are rendered as stack
outputs, ready to apply.

**Those two are not sufficient on their own.** Cross-account KMS needs the grant on
both sides, so the reading role also needs ``kms:Decrypt`` in its own identity policy.
That half is this stack's job, and it happens when ``secret.kms_key_arn`` names the
key -- which config validation now requires for a cross-account secret, because
without it the deployment succeeds and every credential read fails.

Two things make this hard to diagnose, and both cost time here. A missing caller-side
grant and a missing key policy produce the *same* error, ``Access to KMS is not
allowed``. And a key policy edit takes up to ~90 seconds to take effect, during which
the error is again identical. Retry before changing anything.

A missing *resource* policy is at least distinct: ``no resource-based policy allows``.
"""

from __future__ import annotations

import json

from aws_cdk import CfnOutput, RemovalPolicy, Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_secretsmanager as secretsmanager

from constructs import Construct
from infrastructure.config import PrtgMcpConfig


class PrtgSecret(Construct):
    """Resolves the PRTG credential secret for the current configuration.

    Attributes:
        secret: The secret, whether created here or imported.
        ca_bundle_secret: Optional secret holding PRTG's certificate in PEM form.

        kms_key: The key encrypting an ``external`` secret, when ``secret.kms_key_arn``
            names one. ``None`` otherwise, including in ``local`` mode where the L2
            grants decrypt itself.

    The attribute used to exist, be documented, be initialised to ``None`` and never be
    assigned -- ``_create_secret`` bound the key to a local and dropped it -- so the
    ``grant_decrypt`` call that read it was unreachable. It is now assigned for the one
    case that genuinely needs it: an imported secret encrypted with a customer-managed
    key, where the reading role must hold ``kms:Decrypt`` in its own identity policy.
    """

    def __init__(self, scope: Construct, construct_id: str, *, config: PrtgMcpConfig) -> None:
        super().__init__(scope, construct_id)
        self.config = config
        self.kms_key: kms.IKey | None = None

        if config.secret.mode == "local":
            self.secret = self._create_secret()
        else:
            self.secret = self._import_secret()

        self.ca_bundle_secret = self._import_ca_bundle()

    # --- Local secret -------------------------------------------------------

    def _create_secret(self) -> secretsmanager.ISecret:
        """Create an empty secret for the operator to populate after deployment."""
        secret_config = self.config.secret

        if secret_config.kms_key_arn:
            encryption_key: kms.IKey | None = kms.Key.from_key_arn(
                self, "SecretKey", secret_config.kms_key_arn
            )
        else:
            encryption_key = None

        secret = secretsmanager.Secret(
            self,
            "Secret",
            secret_name=secret_config.secret_name,
            description=(
                "PRTG API credential for the AWS DevOps Agent MCP integration. "
                "Populate after deployment; see the stack outputs."
            ),
            encryption_key=encryption_key,
            # The secret is created with the right *shape* but no real credential.
            #
            # The template carries two empty strings, which is not sensitive. The
            # generated placeholder for prtg_passhash is produced by Secrets Manager
            # at creation time, so it never appears in the template, in CloudTrail,
            # or in the CDK context - unlike a value passed through configuration or
            # a CloudFormation parameter, all of which are durably recorded.
            #
            # Creating it with valid JSON but blank fields is deliberate: until an
            # operator populates it, the Lambda fails with "PRTG credentials are
            # incomplete: missing prtg_url", which names exactly what to do. A secret
            # with no version at all would instead surface as a generic read failure
            # that reads like an IAM problem.
            #
            # DO NOT EDIT THIS TEMPLATE, INCLUDING TO ADD A FIELD.
            #
            # CloudFormation regenerates the secret whenever GenerateSecretString
            # changes, overwriting whatever the operator populated. Learned the hard
            # way against a real deployment: adding a blank prtg_api_key here, purely so
            # the field would be visible in the console, replaced a working credential
            # with the empty template on the next deploy. Every already-deployed adopter
            # would have lost their PRTG credential to a cosmetic change, and the
            # failure surfaces as "PRTG credentials are incomplete" well after the
            # deploy that caused it.
            #
            # The template does not need to enumerate the accepted fields. Its only job
            # is to give a fresh secret a shape that yields a useful error before it is
            # populated. The client reads prtg_api_key from whatever JSON is present,
            # whether or not it appears here, so documenting the field costs nothing and
            # changing this costs an outage.
            #
            # Pinned by test_the_secret_template_is_never_changed.
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template=json.dumps({"prtg_url": "", "prtg_username": ""}),
                generate_string_key="prtg_passhash",
                exclude_punctuation=True,
            ),
            # RETAIN, not DESTROY. Destroying the stack should not silently delete
            # a credential that may be shared with other tooling, and Secrets
            # Manager's recovery window makes accidental deletion recoverable
            # anyway. The README documents removing it explicitly during cleanup.
            removal_policy=RemovalPolicy.RETAIN,
        )

        CfnOutput(
            self,
            "PopulateSecretCommand",
            description=(
                "Run this once after deployment to store the PRTG credential. Create the API key "
                "while signed in as a READ-ONLY PRTG user, under Setup, Account Settings, API Keys, "
                "with Access Level set to Read access; a key inherits the rights of whoever created "
                "it, so one made as an administrator can read everything. The key is shown only "
                "once. If your PRTG has no API Keys tab, use PopulateSecretCommandPasshash instead."
            ),
            value=(
                f"aws secretsmanager put-secret-value --secret-id {secret_config.secret_name} "
                f"--region {self.config.region} --secret-string "
                '\'{"prtg_url":"https://<prtg-host>","prtg_api_key":"<api-key>"}\''
            ),
        )

        CfnOutput(
            self,
            "PopulateSecretCommandPasshash",
            description=(
                "Alternative to PopulateSecretCommand for PRTG versions without API keys. Generate "
                "the passhash at https://<prtg-host>/api/getpasshash.htm as a READ-ONLY user. Note "
                "a passhash cannot be revoked on its own: doing so means changing the account "
                "password, which breaks every other consumer of that account."
            ),
            value=(
                f"aws secretsmanager put-secret-value --secret-id {secret_config.secret_name} "
                f"--region {self.config.region} --secret-string "
                '\'{"prtg_url":"https://<prtg-host>","prtg_username":"<user>",'
                '"prtg_passhash":"<passhash>"}\''
            ),
        )

        return secret

    # --- Imported secret ----------------------------------------------------

    def _import_secret(self) -> secretsmanager.ISecret:
        """Import an existing secret, possibly from another account."""
        arn = self.config.secret.secret_arn
        assert arn is not None  # noqa: S101 - guaranteed by config validation

        # from_secret_complete_arn, not from_secret_name_v2: the ARN carries the
        # six-character suffix Secrets Manager appends, and generated IAM policies
        # must include it. Importing by name produces a policy resource of
        # `...:secret:name-??????` which is broader than intended and fails for a
        # cross-account secret.
        secret = secretsmanager.Secret.from_secret_complete_arn(self, "Secret", arn)

        # An imported secret does not tell CDK which key encrypts it, so `grant_read`
        # cannot add kms:Decrypt the way it does for a secret this stack creates. When the
        # key is named, grant it explicitly.
        #
        # This is required, not belt-and-braces. Cross-account KMS needs the grant on both
        # sides: the key policy in the owning account AND an identity policy here. With the
        # key policy alone, GetSecretValue fails with "Access to KMS is not allowed".
        # Measured on a live cross-account deployment, cold container both ways.
        if self.config.secret.kms_key_arn:
            self.kms_key = kms.Key.from_key_arn(self, "SecretKey", self.config.secret.kms_key_arn)

        secret_account = self.config.secret.secret_account_id()
        if secret_account and secret_account != Stack.of(self).account:
            self._emit_cross_account_policies(arn, secret_account)

        return secret

    def _emit_cross_account_policies(self, secret_arn: str, secret_account: str) -> None:
        """Render the two policies the secret's owner must apply.

        Emitted as outputs rather than applied here, because they belong to
        resources in another account that this stack has no authority over.
        Printing them removes the guesswork about what exactly to grant, and makes
        it obvious that there are two documents rather than one.
        """
        stack = Stack.of(self)
        lambda_role_arn = f"arn:aws:iam::{stack.account}:role/{self.config.resource_name('mcp-lambda-role')}"

        resource_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPrtgMcpLambdaRead",
                    "Effect": "Allow",
                    "Principal": {"AWS": lambda_role_arn},
                    "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                    "Resource": secret_arn,
                }
            ],
        }

        key_policy_statement = {
            "Sid": "AllowPrtgMcpLambdaDecrypt",
            "Effect": "Allow",
            "Principal": {"AWS": lambda_role_arn},
            "Action": ["kms:Decrypt", "kms:DescribeKey"],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:ViaService": f"secretsmanager.{self.config.region}.amazonaws.com"}
            },
        }

        CfnOutput(
            self,
            "CrossAccountSecretResourcePolicy",
            description=(
                f"STEP 1 of 2. Apply in account {secret_account}: "
                f"aws secretsmanager put-resource-policy --secret-id {secret_arn} "
                "--resource-policy file://policy.json"
            ),
            value=json.dumps(resource_policy, separators=(",", ":")),
        )

        CfnOutput(
            self,
            "CrossAccountKmsKeyPolicyStatement",
            description=(
                f"STEP 2 of 2, and the one most often missed. Add this statement to the customer-"
                f"managed KMS key encrypting the secret in account {secret_account}. Without it, "
                "GetSecretValue fails with 'AccessDeniedException: Access to KMS is not allowed'. "
                "Allow up to 90 seconds after applying it: until the key policy takes effect the "
                "error is identical, so retry before changing anything. Note the AWS managed key "
                "cannot be shared across accounts at all, so the secret must use a customer-managed "
                "key. This is only half of it: the reading role also needs kms:Decrypt in its own "
                "policy, which this stack adds when secret.kms_key_arn names the key."
            ),
            value=json.dumps(key_policy_statement, separators=(",", ":")),
        )

    # --- CA bundle ----------------------------------------------------------

    def _import_ca_bundle(self) -> secretsmanager.ISecret | None:
        """Import the secret holding PRTG's certificate, if configured.

        This is the supported way to keep TLS verification on against PRTG's
        commonly self-signed certificate, and it is strictly preferable to
        ``prtg.verify_tls: false``: PRTG's API carries the credential in the query
        string, so an intercepted connection hands it over.
        """
        arn = self.config.secret.ca_bundle_secret_arn
        if not arn:
            return None
        return secretsmanager.Secret.from_secret_complete_arn(self, "CaBundleSecret", arn)

    # --- Grants -------------------------------------------------------------

    def grant_read(self, grantee: iam.IGrantable) -> None:
        """Grant read on the credential, and on the CA bundle when present.

        Uses the L2 ``grant_read``, which scopes the policy to this secret's exact
        ARN. The reference implementation granted
        ``secretsmanager:GetSecretValue`` on ``Resource: "*"``, meaning a
        compromise of the function exposed every secret in the account - flagged
        as finding 3 in the security review.
        """
        self.secret.grant_read(grantee)
        if self.ca_bundle_secret is not None:
            self.ca_bundle_secret.grant_read(grantee)

        # Only set for an imported secret with a named key. A secret this stack creates
        # carries its own encryption_key, so grant_read above has already done this.
        if self.kms_key is not None:
            self.kms_key.grant_decrypt(grantee)

    # --- Environment --------------------------------------------------------

    @property
    def environment(self) -> dict[str, str]:
        """Environment variables the Lambda functions need to read the credential."""
        env = {
            "PRTG_SECRET_ARN": self.secret.secret_arn,
            "PRTG_CREDENTIAL_TTL_SECONDS": str(self.config.secret.credential_ttl_seconds),
        }
        if self.ca_bundle_secret is not None:
            env["PRTG_CA_BUNDLE_SECRET_ARN"] = self.ca_bundle_secret.secret_arn
        return env
