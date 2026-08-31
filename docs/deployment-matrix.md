# Deployment matrix

Five independent knobs cover every deployment shape this integration supports. This
document explains each one, and maps the eighteen scenarios this integration is
conventionally documented as onto them.

This is the **reference**. Choosing for the first time is quicker in
[`getting-started.md` step 1](getting-started.md#step-1---choose-a-deployment-shape),
which turns the choice into six questions and a starting file - come back here when
one knob needs its full story.

## The knobs

| # | Knob | Values | Default |
|---|---|---|---|
| 1 | `network.mode` | `nat`, `private` | `nat` |
| 2 | `auth.mode` (+ `auth.provider`) | `sigv4`, `oidc` (`cognito` / `entra` / `generic`) | `sigv4` |
| 3 | `secret.mode` | `local`, `external` | `local` |
| 4 | `prtg.reachability` | `same-vpc`, `remote` | `same-vpc` |
| 5 | `targeting.mode` | `single`, `fanout` | `single` |

They are genuinely independent: any combination is valid, and
`tests/unit/test_infrastructure.py::TestKnobIndependence` asserts that changing one
does not disturb the resources the others own.

---

## Knob 1 - `network.mode`

How the Lambda functions reach AWS APIs.

| | `nat` | `private` |
|---|---|---|
| Outbound internet | NAT gateway, default route | none |
| Secrets Manager reached via | public endpoint | interface VPC endpoint |
| Interface endpoints created | - | `secretsmanager`, `logs`, `lambda`, `sts`, `sqs`, and `aidevops-dataplane` with the pipeline |
| Lambda egress | PRTG + `0.0.0.0/0:443` | PRTG only |
| Monthly cost | ~$32 (NAT) | ~$7.30 per endpoint, 1 AZ - ~$44 for the six below |

The Lambda source is byte-identical in both. boto3 resolves interface endpoints
through private DNS, so no code changes.

Choose `private` when the account has no internet route, or when a compliance
requirement says traffic must not leave the AWS network. Expect it to cost a little
more than NAT, not less.

![Fully private: no NAT gateway and no internet gateway, with interface VPC endpoints for
Secrets Manager, Lambda, STS, CloudWatch Logs, SQS and the DevOps Agent data plane
carrying every AWS API call
](images/mcp-fully-private.svg)

Compare it with the `nat` shape in
[`architecture.md`](architecture.md#half-2---the-mcp-server): same Lambda, same code
path, and the only difference is what the AWS API calls travel over.

> **Deploying `private` into a VPC you already use? Read this first.** It can break
> workloads you are not touching.
>
> Every interface endpoint is created with **private DNS enabled, which is a
> VPC-wide setting**. From the moment they exist,
> `secretsmanager.<region>.amazonaws.com` and every other hostname in the list resolve to
> those endpoints for *every* resource in the VPC - not just this stack's functions. But
> the endpoint security group admits only this stack's Lambda.
>
> So any existing workload in that VPC which reaches Secrets Manager, CloudWatch Logs,
> Lambda, STS or SQS over public endpoints stops working. Its egress rules are still
> correct and its NAT route is still there; DNS simply no longer hands it a public
> address, and the endpoint drops the packet. The symptom is a hang with no diagnostic,
> in something nobody deployed.
>
> Observed exactly this way during testing: a second, unrelated deployment in the same
> VPC began timing out on Secrets Manager with nothing in its logs beyond boto3
> resolving credentials.
>
> Before deploying `private` with `network.vpc_id`, inventory what else in that VPC uses
> those services, and add their security groups to the endpoint security group. A
> VPC created by this stack is unaffected, because nothing else is in it.

**Changing `network.mode` on an existing deployment does not work in place.** Switching
between `nat` and `private` replaces the VPC, and CloudFormation refuses to delete an
export another stack still imports - so if anything consumes the shared stack's VPC (the
optional demo PRTG stack does), the update fails and rolls back with
`Cannot delete export ... as it is in use by <stack>`. Either destroy the dependent
stacks first, or deploy the new shape under a different `name_prefix`.

**The endpoint list is derived, not configured.** Omitting one produces a
disproportionately confusing failure, so the stack computes it:

| Missing endpoint | Symptom |
|---|---|
| `secretsmanager` | Function times out fetching the credential, with nothing useful logged |
| `logs` | Function runs correctly and writes nothing to CloudWatch - looks like it is never invoked |
| `lambda` | Gateway cannot invoke the function; reports a target failure that says nothing about networking |
| `sts` | Cross-account role assumption hangs until timeout |
| `sqs` | The pipeline cannot park an alarm it failed to process, so the one mechanism that stops an alarm being lost is unreachable exactly when it is needed |
| `aidevops-dataplane` | `CreateBacklogTask` hangs until the function times out. Nothing is logged after routing, and because a timeout kills the process rather than raising, the dead-letter park never runs either - the alarm is simply gone |
| `ssm` (fan-out only) | The routing lookup hangs until the function times out, so the alarm is lost before a route is even chosen |

`aidevops-dataplane` needs one thing the others do not. Every endpoint above publishes
private DNS for exactly the hostname the SDK already calls, which is why the Lambda source
is identical in both network modes. This one serves `dp.aidevops.<region>.api.aws`, while
boto3's default endpoint for `devops-agent` is `aidevops.<region>.amazonaws.com` - a
different domain, so private DNS does not intercept the call. The stack therefore also sets
`DEVOPS_ENDPOINT_URL` on the pipeline function in `private` mode, to
`https://aidevops.<region>.api.aws`.

Note that value carries **no** `dp.` or `cp.` prefix, even though the AWS documentation
lists the endpoint names with one. Each API operation has its own `hostPrefix` and botocore
prepends it, so supplying a fully-qualified name yields a request to `dp.cp.aidevops...`.
Override it with `targeting.agent_endpoint_url` only for a FIPS endpoint or a non-`aws`
partition.

Also worth knowing which plane: `CreateBacklogTask` is a **data-plane** operation
(`hostPrefix` `dp.`), despite creating an investigation sounding like control-plane work.
The control-plane endpoint `aidevops` serves `RegisterService` and the agent-space
operations, and this stack does not need it - registration runs at deploy time through
CloudFormation, not from inside the VPC.

Two endpoints are added conditionally:

- `cognito-idp` - with `network.mode: private` **and** `auth.provider: cognito`,
  because Cognito tokens are validated from inside the VPC. External providers such
  as Entra ID do not need it; the Gateway validates those at the AWS service plane.
- `execute-api` - whenever `alarm_api_private: true`, **regardless of network mode**.
  A private REST API is only reachable through that endpoint. This is an inbound
  concern, unrelated to the function's egress.

### Pointing at an existing VPC

Two paths, and the difference matters for CI:

```yaml
# Path A - VPC lookup. Discovers subnets and AZs for you.
# Calls EC2 during `cdk synth`, so it NEEDS AWS CREDENTIALS.
network:
  vpc_id: vpc-0123456789abcdef0

# Path B - explicit attributes. No lookup, synthesises offline.
network:
  vpc_id: vpc-0123456789abcdef0
  subnet_ids: [subnet-0aaa, subnet-0bbb]
  availability_zones: [eu-central-1a, eu-central-1b]   # positionally matched
```

Every shipped example uses path B, which is what lets CI verify them without an
account. Pin subnets to the AZs nearest PRTG: every tool call crosses that boundary
and cross-AZ transfer is charged.

---

## Knob 2 - `auth.mode`

How callers authenticate to the AgentCore Gateway. AgentCore supports exactly two
inbound mechanisms, so this knob is complete rather than a subset.

### `sigv4` - IAM request signing

```yaml
auth:
  mode: sigv4
```

The DevOps Agent assumes a role granted invoke on the Gateway. No identity provider,
no tokens, nothing to rotate. Correct for same-account deployments and the right
default. The stack creates the role and emits its ARN.

### `oidc` - JWT bearer tokens

Needs exactly three values: a discovery URL, the allowed audience, and the allowed
client IDs. The three providers differ **only in where those values come from** - the
infrastructure is the same.

```yaml
# Cognito - the ONLY provider that creates infrastructure.
# A user pool, resource server, app client and domain are built here and the three
# values derived. Do not set discovery_url yourself.
auth:
  mode: oidc
  provider: cognito
  cognito_resource_server_id: prtg-mcp-api
  cognito_scope_name: invoke
```

```yaml
# Entra ID - nothing is created; the app registration already exists.
auth:
  mode: oidc
  provider: entra
  discovery_url: https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration
  allowed_audience: ["api://<CLIENT_ID>"]
  allowed_clients: ["<CLIENT_ID>"]
```

```yaml
# Okta, Auth0, Keycloak, Ping, or any OIDC provider. Identical to entra.
auth:
  mode: oidc
  provider: generic
  discovery_url: https://<your-idp>/.well-known/openid-configuration
  allowed_audience: ["<audience>"]
  allowed_clients: ["<client-id>"]
```

**At least one of `allowed_audience` or `allowed_clients` is required.** With neither,
the Gateway accepts any token that provider issued, for any application and any
client. The equivalent hand-run CLI command leaves both open, because both are
optional parameters.

### Which restriction to use - read this before choosing

Whether to set `allowed_audience` depends on what your provider puts in a
**client-credentials** access token, and getting it wrong produces a deployment that
succeeds and then rejects every call with a bare 403.

| Provider | `aud` claim in a client-credentials token? | Set |
|---|---|---|
| Microsoft Entra ID | Yes - the Application ID URI | `allowed_audience` **and** `allowed_clients` |
| Amazon Cognito | **No** - only `client_id`, `scope`, `sub` | `allowed_clients` **only** |
| Okta, Auth0, Keycloak, Ping | Depends on configuration | Decode a token and look |

A Cognito client-credentials token decodes to:

```json
{
  "client_id": "7pbem4fgq397r7v3rip7ffgpif",
  "scope": "prtg-mcp-api/invoke",
  "sub": "7pbem4fgq397r7v3rip7ffgpif",
  "token_use": "access",
  "iss": "https://cognito-idp.<region>.amazonaws.com/<pool-id>"
}
```

No `aud`. So a Gateway configured with `allowed_audience` can never match, and every
request returns 403 with nothing to indicate why. Verified against a deployed Gateway.

`allowed_clients` checks `client_id` and is equally restrictive, so it is the safe
choice when in doubt. Check what your provider emits:

```bash
# Fetch a token, then decode the payload
curl -s -X POST "$TOKEN_ENDPOINT" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=$SCOPE" \
  | jq -r .access_token | cut -d. -f2 \
  | base64 -d 2>/dev/null | jq .
```

The configuration warns when `allowed_audience` is set without `allowed_clients`,
because that is the combination that fails silently.

> **Token risk.** A leaked bearer token stays valid until it expires, and revoking it
> at the identity provider does *not* invalidate it at the Gateway. Keep lifetimes
> short. IAM does not have this property, which is a reason to prefer `sigv4` where
> it is available. See [`security.md`](security.md#identity-provider-considerations).

---

## Knob 3 - `secret.mode`

### `local`

```yaml
secret:
  mode: local
  secret_name: prtg-mcp/credentials
  credential_ttl_seconds: 900
```

The stack creates the secret with the correct JSON shape and blank fields. Populate
it once after deployment; the command is emitted as a stack output.

### `external`

```yaml
secret:
  mode: external
  secret_arn: arn:aws:secretsmanager:<region>:<security-account>:secret:prtg-mcp/credentials-a1b2c3
  ca_bundle_secret_arn: arn:aws:secretsmanager:<region>:<security-account>:secret:prtg-mcp/ca-bundle-d4e5f6
  kms_key_arn: arn:aws:kms:<region>:<security-account>:key/<key-id>
```

Nothing is created; read is granted on those ARNs. `kms_key_arn` is required for a
cross-account secret and enforced at synthesis - see [the third policy](#the-third-policy)
below for what it does.

![Cross-account secret: the workload account holds the Gateway and the Lambda, and the
Lambda's GetSecretValue call crosses into a separate security account that owns the
secret](images/mcp-cross-account-secret.svg)

**Cross-account needs two policies, not one.** A Secrets Manager resource policy *and* a
KMS key policy grant. Both are emitted as stack outputs, ready to apply - look for the
output keys ending `CrossAccountSecretResourcePolicy` (step 1) and
`CrossAccountKmsKeyPolicyStatement` (step 2, the one usually missed). They carry a
construct-path prefix and a hash suffix in the deployed stack, so match on the ending
rather than the whole key.

The AWS managed key **cannot** be shared across accounts, so a cross-account secret must
use a customer-managed key.

#### The third policy

Cross-account KMS needs the grant on *both* sides, so the reading role also needs
`kms:Decrypt` in its own identity policy. Setting `secret.kms_key_arn` above makes the
stack add it.

Without it, `GetSecretValue` fails with `Access to KMS is not allowed` - the same error
as a missing key policy, which is what makes the two hard to tell apart. An imported
secret does not tell CDK which key encrypts it, so unlike a secret this stack creates,
`grant_read` cannot infer it.

A warm credential cache can mask this failure in intermittent testing: a successful call
against a warm container is not evidence the grant is unnecessary, only that it has not
yet been asked to authorise a fresh decrypt. Verify against a cold container.

> **Applied both and it still fails? Wait 90 seconds.** A KMS key policy edit is not
> immediate, and until it lands the error is indistinguishable from never having applied
> it - `Access to KMS is not allowed` at 25 seconds, working at 85, nothing changed in
> between. See [`troubleshooting.md`](troubleshooting.md).

---

## Knob 4 - `prtg.reachability`

```yaml
prtg:
  reachability: same-vpc          # PRTG is in the Lambda's VPC
  host_cidr: 10.0.1.10/32         # tightest egress; prefer this
```

```yaml
prtg:
  reachability: remote            # another VPC, account, or on-premises
  host_cidr: 10.50.12.40/32
  cidr: 10.50.0.0/16              # the wider network, for documentation
```

`host_cidr` or `cidr` is required in **both** modes, so the function's egress is
scoped to PRTG rather than left open. Prefer `host_cidr`: a single `/32` is the
tightest posture available and what the security review recommends.

![PRTG in a different network: the Lambda's HTTPS call leaves the AWS account and
crosses into the customer network over VPC peering, Transit Gateway or VPN
](images/mcp-prtg-remote.svg)

The boundary the HTTPS arrow crosses is the part this stack does not build - see the
note below.

> **`remote` does not create the network link.** VPC peering, Transit Gateway
> attachments and Site-to-Site VPN all need agreement from the other side, and a
> sample should not quietly reshape your network. Establish the link and the route
> first; this stack adds only the security group rule.

### TLS

```yaml
prtg:
  verify_tls: true                                    # the default
secret:
  ca_bundle_secret_arn: arn:aws:secretsmanager:...    # PRTG's certificate, PEM
```

PRTG very often ships a self-signed certificate. Supply it via
`ca_bundle_secret_arn` rather than turning verification off: PRTG's API carries the
credential in the query string, so an intercepted connection hands it over. Setting
`verify_tls: false` is possible, logs a warning on every invocation, and raises a
CloudWatch alarm.

---

## Knob 5 - `targeting.mode`

### `single`

```yaml
targeting:
  mode: single
  agent_space_id: as-abc123
  deduplication_window_minutes: 30
```

### `fanout`

One pipeline routing to Agent Spaces across many accounts.

```yaml
targeting:
  mode: fanout
  external_id: prtg-devops-agent-integration
  organization_id: o-exampleorgid
  routes:
    - match: Production
      account_id: "222233334444"
      agent_space_id: as-prod-001
    - match: Staging
      account_id: "333344445555"
      agent_space_id: as-staging-001
    - match: DEFAULT                    # exactly one required
      account_id: "222233334444"
      agent_space_id: as-prod-001
```

Matching order, first hit wins:

1. Exact PRTG **group** name
2. Exact PRTG **probe** name
3. **Device name prefix** - text before the first `-` or `.`
4. The **`DEFAULT`** route

Matching is **case-sensitive** and must equal the PRTG name exactly. A mismatch is
the most common reason an alarm lands in the wrong Agent Space.

The device-prefix tier compares against the *derived* prefix - the text before the
first `-` or `.` - so a route key that itself contains a dash or dot can never match.
A device named `prod-db-7` derives the prefix `prod`; a route keyed `prod-db` is
unreachable, and the alarm falls through to `DEFAULT` with the `route_resolved` log
entry showing `matchedBy: default` - which reads as a routing decision rather than a
key mistake. Key the route `prod`.

Fan-out does not require multiple accounts. Routes may target several Agent Spaces in
one account - which is also the cheapest way to evaluate it - and the code path is
identical: every route goes through `sts:AssumeRole`, so a same-account deployment
exercises the same trust policy and `sts:ExternalId` that a cross-account one relies
on.

`DEFAULT` is mandatory. Without it an alarm from an unmapped group reaches no Agent
Space at all, and a real alert silently reaching nobody is the worst failure this
system can produce.

**Setting `organization_id` is strongly recommended.** With it, the assume-role policy
wildcards the account and constrains it with `aws:ResourceOrgID`, so onboarding an
account needs no IAM change. Without it, every target role ARN is listed explicitly and
each new account is a policy update - which defeats most of the point of fan-out.

The key is `aws:ResourceOrgID`, the organisation of the *role being assumed* - not
`aws:PrincipalOrgID`, which is the organisation of the caller. In an identity-based
policy on the pipeline's own role the latter resolves to this account's own
organisation on every call, so it restricts nothing and leaves the account wildcard
wide open. It also fails open, so a fan-out deployment that works proves nothing about
it. Worth knowing if you adapt this policy: the same mistake reads as correct.

`aws:ResourceOrgID` fails closed instead. The key is absent unless the account owning
the role belongs to an organisation, and `StringEquals` against an absent key does not
match, so a target outside any organisation is denied rather than quietly allowed.

### Which way the role assumption goes

Worth stating plainly, because it is easy to picture backwards. Assumption runs **outward
from the pipeline**: the pipeline Lambda's role calls `sts:AssumeRole` (carrying the
`sts:ExternalId`) into each workload account's `PrtgDevOpsAgentInvestigationRole`, and
that role creates the investigation in its own account's Agent Space. Nothing in a
workload account can reach back.

![Role assumption runs outward: the pipeline Lambda's role assumes the
PrtgDevOpsAgentInvestigationRole in a workload account with sts:ExternalId, and that
role calls aidevops:CreateBacklogTask on its own account's Agent
Space](images/fanout-role-assumption.svg)

So there are two policies, on opposite sides, and they are not interchangeable:

- **In the workload account** - a trust policy naming the pipeline's Lambda role as
  `Principal`, plus an inline policy allowing `aidevops:CreateBacklogTask` on that
  account's own Agent Space.
- **In the pipeline account** - an identity policy allowing `sts:AssumeRole` on that role.
  Created by this stack.

Nothing assumes the pipeline's role, and DevOps Agent never calls into the pipeline
account. The pipeline pushes investigations; there is no return path.

Do not confuse this with DevOps Agent's own multi-account access, where the service assumes
roles in secondary accounts as `aidevops.amazonaws.com` so the agent can read resources
while investigating. That is a separate mechanism, configured separately, and this sample
does not touch it.

### Fan-out and the MCP tools

Routing governs where *investigations* land. Whether each space's agent can then query
PRTG is a separate, per-space setting: registering the MCP server is **account-level**,
but the tool association is **per Agent Space** - one registration, one association for
every space your routes target. `targeting.register_with_agent_space` covers only the
single-space case, so under fan-out associate the registered server with each
additional space in the DevOps Agent console (*Capability Providers*) or with the
`AssociateService` API, using the same prefixed tool names the single-space
registration uses. A space without the association still receives investigations; its
agent simply cannot query PRTG back - which quietly halves the value of the loop for
exactly the alarms routed there.

### Onboarding a workload account

1. In the workload account, create `PrtgDevOpsAgentInvestigationRole`. The trust
   policy is emitted as the `WorkloadAccountTrustPolicy` stack output. Give it an
   inline policy allowing `aidevops:CreateBacklogTask` on that account's Agent Space.
2. Add a route to `targeting.routes` and redeploy - **or** edit the SSM parameter
   named by the `RoutingTableParameter` output directly, which needs no deployment at
   all. The function picks up changes within `ROUTING_TTL_SECONDS`.
3. In PRTG, put the relevant sensors in a group matching the route key.

No Lambda change, no API Gateway change, no PRTG notification-template change.

If a route sets `role_name` to something other than the default, the pipeline's own
policy covers it automatically - the role names are read from the routes. Both sides still
have to agree on `sts:ExternalId`.

---

## Alarm ingress

Separate from the five knobs, because it concerns inbound traffic.

```yaml
alarm_api_private: false
alarm_allowed_source_ips:
  - 203.0.113.7/32          # PRTG's public address
```

```yaml
alarm_api_private: true      # PRTG has no public address
alarm_allowed_source_ips:
  - 10.50.12.40/32           # PRTG's address ON THE NETWORK, not its public one
```

The two blocks above take **different kinds of address**, and this is the easiest thing
here to get wrong. A public API sees whatever PRTG egresses as - for an instance behind a
NAT gateway, the gateway's public address. A private API sees PRTG's own address on the
network.

It matters more than it looks, because with a private API the list is not what the
resource policy uses. That policy is keyed on `aws:SourceVpce` and never mentions an
address. The list builds the **execute-api endpoint's security group ingress** instead, so
it governs whether PRTG can open a connection at all. Put a public address there and the
API hostname resolves to the endpoint correctly, then the connection is refused - no HTTP
status, nothing in any log, because a security group drop is silent. The configuration
warns when `prtg.host_cidr` is set and the list does not contain it.

PRTG's "Execute HTTP Action" **cannot send custom headers**, so an API key, a bearer
token and a signed request are all unavailable. The source address is the control
that exists. The configuration will not let you leave the endpoint open: `0.0.0.0/0`
is rejected, and an empty allowlist on a public API is an error.

A private API is reachable only through an `execute-api` interface endpoint. Note
that private DNS **does not propagate across VPC peering** - from a peered VPC you
need a Route 53 private hosted zone with records pointing at the endpoint ENI
addresses.

---

## Mapping the conventional scenarios

Deployments of this kind are usually written up as a numbered list of self-contained
scenarios - twelve for the MCP server, six for the alarm pipeline. If you arrived with
one of those numbers in hand, these tables tell you which knob values it means. If you
did not, skip to the examples below; the numbering carries no information the knobs do
not.

### MCP server (12 scenarios)

| Scenario | `network` | `auth` | `secret` | `prtg` |
|---|---|---|---|---|
| 1 - Single account, standard | `nat` | `sigv4` | `local` | `same-vpc` |
| 2 - Single account, fully private | `private` | `sigv4` | `local` | `same-vpc` |
| 3 - Cross-account secret, standard | `nat` | `sigv4` | `external` | `same-vpc` |
| 4 - Cross-account secret, fully private | `private` | `sigv4` | `external` | `same-vpc` |
| 5 - PRTG different network, standard | `nat` | `sigv4` | `local` | `remote` |
| 6 - PRTG different network, fully private | `private` | `sigv4` | `local` | `remote` |
| 7 - Multi-account, Cognito, standard | `nat` | `oidc`/`cognito` | `external` | `remote` |
| 8 - Multi-account, Cognito, fully private | `private` | `oidc`/`cognito` | `external` | `remote` |
| 9 - Multi-account, Entra ID, standard | `nat` | `oidc`/`entra` | `external` | `remote` |
| 10 - Multi-account, Entra ID, fully private | `private` | `oidc`/`entra` | `external` | `remote` |
| 11 - Multi-account, other OIDC, standard | `nat` | `oidc`/`generic` | `external` | `remote` |
| 12 - Multi-account, other OIDC, fully private | `private` | `oidc`/`generic` | `external` | `remote` |

### Alarm pipeline (6 scenarios)

| Scenario | `targeting` | `alarm_api_private` | Notes |
|---|---|---|---|
| A - Multi-agent fan-out (enterprise) | `fanout` | `true` | The recommended enterprise pattern |
| B - Public, single account | `single` | `false` | Needs `alarm_allowed_source_ips` |
| C - Private VPC, single account | `single` | `true` | |
| D - PRTG separate account | `single` | `true` | Peering is a prerequisite |
| E - Agent separate account | `fanout` | either | One route plus `DEFAULT` |
| F - All components separate | `fanout` | `true` | Peering plus cross-account assume |

Scenarios 9–12 differ from each other **only in the value of `discovery_url`**. That
is four of the twelve collapsing to one code path, which is most of why this model is
worth having.

The three both-halves examples correspond to:

- `config/default.yaml` → MCP scenario 1 + pipeline scenario B
- `config/regulated-private.yaml` → MCP scenario 10 + pipeline scenario C
- `config/multi-account-fanout.yaml` → MCP scenario 7 + pipeline scenario A, except
  that it keeps `secret: local` rather than scenario 7's `external`. The secret lives in
  the pipeline account because that is where the tool function runs; fanning out to
  several Agent Spaces does not on its own require the credential to move.

---

## Combinations outside the eighteen

Because the knobs are independent, shapes the numbered list never enumerated are
available at no extra effort.

![Combined multi-account: DevOps Agent in an ops account, Gateway and identity provider
in a platform account, the Lambda in a workload account, the secret in a security
account, and PRTG in the customer network](images/mcp-combined-multi-account.svg)

Every arrow in that diagram crosses an account or network boundary, and each crossing
is one knob value rather than a separate architecture. For example, fully private +
Entra ID + cross-account secret + remote PRTG + fan-out to five accounts:

```yaml
network:   { mode: private, vpc_id: vpc-0abc, subnet_ids: [...], availability_zones: [...] }
auth:      { mode: oidc, provider: entra, discovery_url: ..., allowed_audience: [...], allowed_clients: [...] }
secret:    { mode: external, secret_arn: ..., ca_bundle_secret_arn: ... }
prtg:      { reachability: remote, host_cidr: 10.50.12.40/32 }
targeting: { mode: fanout, organization_id: o-..., routes: [...] }
alarm_api_private: true
```

Validate any combination before deploying:

```bash
make synth CONFIG=config/your-config.yaml
```
