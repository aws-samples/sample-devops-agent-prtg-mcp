# Security

> **Disclaimer.** This document is provided for informational purposes and does not
> constitute legal, security, or professional advice. It is not a comprehensive
> security assessment, a penetration test, or a compliance audit. You are responsible
> for evaluating this sample against your own requirements, and for how you configure
> and operate it. Conduct your own assessment before production use.

---

## The property everything else rests on

**Every tool is read-only, and no tool parameter can change where a request goes.**

All nine PRTG tools issue HTTP GET requests against PRTG's read APIs. The PRTG
endpoint is fixed at deployment time, taken from Secrets Manager. There is no
parameter - no hostname, no URL, no account ID, no ARN - that a caller can use to
redirect a request somewhere else.

### Why read-only matters

An AI agent investigating an incident reads data it did not choose and cannot fully
validate: sensor names, log messages, device descriptions. Any of that could contain
text crafted to look like an instruction. This is indirect prompt injection, and the
useful way to reason about it is *way in* and *way out*:

- **Way in** - can an attacker get text in front of the model? Yes, in principle.
  Anyone who can name a PRTG object or write to a monitored log can place text where
  the agent will read it. This is true of essentially every monitoring integration
  and cannot be fully closed.
- **Way out** - can the model, once influenced, do something harmful? This is the
  half that can be closed, and closing it is what makes the *way in* tolerable.

This integration has no way out:

| Channel | Available? | Why not |
|---|---|---|
| Mutate PRTG state | No | Every tool is a GET against a read API |
| Exfiltrate to an attacker endpoint | No | The destination is fixed at deploy time |
| Encode data into a cross-account audit log | No | No cross-account calls from the tool layer |
| Execute commands or SQL | No | No such tool exists |

So the worst an injected instruction achieves is causing the agent to read *more PRTG
monitoring data* - data the agent is already authorised to read.

**If you add a tool that mutates PRTG, this analysis no longer holds.** Pausing a
sensor, acknowledging an alarm, or changing a threshold would each create a way out,
and the integration would need reassessing from scratch. That is a fork, not a
contribution - see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## Trust boundaries

```
┌─ AWS DevOps Agent ──────────┐
│  Reads PRTG data.           │   ← boundary 1: Gateway authorisation
│  Cannot invoke Lambda.      │
└──────────┬──────────────────┘
           │ SigV4 or OIDC
┌──────────▼──────────────────┐
│  AgentCore Gateway          │   ← boundary 2: Gateway → Lambda invoke
│  IS the authorisation layer │
└──────────┬──────────────────┘
           │ lambda:InvokeFunction, scoped to one function ARN
┌──────────▼──────────────────┐
│  Lambda (VPC)               │   ← boundary 3: holds the PRTG credential
│  Holds the credential       │
└──────────┬──────────────────┘
           │ HTTPS to one address
┌──────────▼──────────────────┐
│  PRTG Server                │   ← boundary 4: tier-0 asset
│  Holds credentials for      │
│  everything it monitors     │
└─────────────────────────────┘
```

Each boundary is worth thinking about separately, because the consequence of crossing
one is not the same as another.

### Boundary 1 - reaching the Gateway

An attacker here can call the tools and read monitoring data. That has real
reconnaissance value: hostnames, IP addresses, network segments, service
dependencies, which systems are currently unhealthy, and - through
`get_sensor_history` - when maintenance windows and quiet periods fall.

They cannot bypass the Gateway's own authorisation and rate limiting, and cannot
mutate anything.

Worth stating plainly, because `network.mode: private` invites the opposite
assumption: **the Gateway's URL is a public AWS endpoint in every configuration.**
`private` removes the *functions'* internet egress; it does not change the Gateway's
ingress, which stays reachable from the internet and protected by this boundary's
authentication (SigV4 or OIDC) and TLS. If your requirements rule out any public
endpoint, that means self-hosting the MCP server inside the VPC behind a DevOps
Agent [private connection](https://docs.aws.amazon.com/devopsagent/latest/userguide/configuring-integrations-and-knowledge-connecting-to-privately-hosted-tools.html)
- a different architecture this sample does not implement, and one that gives up the
Gateway's schema handling and its SigV4/OIDC authorizers.

**What this sample does:** the invoker role is granted
`bedrock-agentcore:InvokeGateway` on one Gateway ARN, not `bedrock-agentcore:*` on a
wildcard. Its trust policy is conditioned on `aws:SourceAccount`, so the AWS service
principal cannot be induced to assume it on another account's behalf. Session
duration is capped at one hour.

### Boundary 2 - reaching the Gateway's role

This one deserves more attention than boundary 1, because the Gateway *is* the
authorisation layer. An attacker with its role can invoke the Lambda directly,
bypassing Gateway authorisation, rate limiting, and the Gateway-layer audit trail
entirely.

**What this sample does:** `lambda:InvokeFunction` is scoped to exactly one function
ARN. A wildcard here is the easy mistake, and it would let that attacker invoke *any*
function in the account.

### Boundary 3 - reaching the Lambda

An attacker here obtains the PRTG credential and can call the PRTG API directly,
outside the MCP framework and its rate limiting. They also gain the function's
network position: an ENI in your private subnet.

**What this sample does:**

- `secretsmanager:GetSecretValue` is scoped to one secret ARN. A wildcard grant would
  read every secret in the account.
- Egress is restricted to PRTG's address on its port - a single `/32` when
  `prtg.host_cidr` is set. In `network.mode: private` there is no internet egress
  rule at all.
- Errors are scrubbed of the credential before they leave the function.
- Reserved concurrency bounds how much load can reach PRTG.

**What you should add for production:** Lambda code signing, to stop an attacker
replacing the function code with a version that exfiltrates every tool result or adds
a mutating tool while appearing normal to callers.

### Boundary 4 - reaching PRTG

The most serious, and largely outside this integration's control. PRTG aggregates
credentials for everything it monitors: SNMP community strings, WMI and Windows domain
accounts (often privileged), SSH keys, database connection strings. Its network
position requires broad reach. A compromised PRTG server is a pivot into the estate.

**The MCP integration does not increase the likelihood of PRTG compromise** - it
issues read-only GETs against the HTTP API. But two things follow:

- Use a **read-only PRTG account**. If the credential this integration holds is an
  administrator, a compromise at boundary 3 escalates to full PRTG administration.
- The integration creates a **new network path** to PRTG. Keep it narrow:
  `prtg.host_cidr` as a `/32`, and PRTG's own inbound rules limited to the Lambda
  security group and your administrative hosts.

Treat PRTG as tier-0. Enable its audit logging and forward it to your SIEM.

---

## What this sample fixed

Properties enforced by this sample's code and configuration, and the failure modes each
prevents, in rough order of severity.

### The credential could reach the model's context and the investigation record

PRTG authenticates with `username` and `passhash` as **query parameters**, so the
credential is part of every request URL. urllib3 embeds that URL in its exception
messages, so a handler that returns `str(exception)` directly to the caller leaks the
credential on every connection failure.

So a single connection failure - a firewall change, PRTG restarting, a routing blip -
would have written the PRTG passhash into the agent's context window, and from there
into the durable investigation record where responders and anyone with access to the
Agent Space could read it.

**Fixed by:** a two-pass scrubber (`prtg_client.redact`) applied to everything
outbound; unexpected exceptions reduced to their type plus a correlation ID, with the
traceback going only to CloudWatch; and a regression test asserting the passhash never
appears in a returned message.

The general lesson: a review focused on the tool surface may not cover error paths where
the same credential appears in exception text; both need scrubbing.

**And the first fix was incomplete.** Scrubbing what the handler returns covers the
path to the agent, but not logging done by libraries underneath it. urllib3 logs the
request URL at `WARNING` on every retry, and PRTG puts the credential in that URL, so a
deployed invocation returned a properly redacted message to the agent while writing
`username=...&passhash=<value>` into CloudWatch Logs:

```
[WARNING] Retrying (Retry(total=1, ...)) after connection broken by
'SSLError(...)': /api/table.json?...&username=<user>&passhash=<the-real-passhash>
```

Found by reading the log group after a deliberately failed call, not by any test. It
needed a real deployment: the retry only fires against a server that is reachable but
rejects the connection.

`install_log_scrubbing()` now attaches a redacting filter to the root log handlers and
to the urllib3 loggers, so the warning is still emitted -- it is useful -- but with the
credential replaced. Attached to *handlers* rather than only loggers because a filter on
a logger runs only for records logged directly through it; records from a child such as
`urllib3.connectionpool` propagate to ancestor handlers without consulting ancestor
filters. Verified against the deployed function: the retry warnings still appear, and
searching the log group for the passhash returns nothing.

The general lesson is worth stating, because it generalises past this integration: a
credential in a URL will eventually be logged by something you did not write. Scrubbing
at your own boundary is not enough when a dependency has its own.

### The credential could be supplied through the function's environment

A tempting shortcut is to resolve credentials from `PRTG_SECRET_ARN` if set, and
otherwise from `PRTG_URL`, `PRTG_USERNAME` and `PRTG_PASSHASH` environment variables.
Nothing stops a deployment taking the second path, which puts the passhash where anyone
holding
`lambda:GetFunctionConfiguration` can read it, where the console displays it, and where
infrastructure code commits it into a template.

Where a credential lives matters more here than for a typical token, because of what a
PRTG passhash is. It is a static value in the user's account settings rather than
something issued on request. It does not expire. There is one per user, so a separate
credential cannot be minted per integration. And it cannot be revoked on its own: it
derives from the password, so revoking it means changing that password and breaking
every other consumer of the account. A passhash can at least not be used to sign in to
the web interface, only to call the API.

**Fixed by:** refusing the environment path when running in Lambda, detected via
`AWS_LAMBDA_FUNCTION_NAME`. The failure names the reason and the remedy rather than
silently falling back. The fallback remains available off-Lambda, where local
development and the integration tests rely on it. A passhash left in a function's
environment is also logged as a warning even when unused, because being ignored does not
make it unreadable.

Enforced in code and asserted by `TestTheCredentialMustComeFromSecretsManagerInLambda`,
including that the deployed function refuses to start on environment credentials. A
comment saying "for local development only" is not a control; only refusing to read the
environment when `AWS_LAMBDA_FUNCTION_NAME` is set actually prevents this.

**API keys are the preferred credential, and the integration uses them.** Newer PRTG
releases offer keys alongside the passhash, and a key is a better fit for a machine
integration for exactly the reasons above: it is issued per integration rather than per
user, and deleting it revokes this integration alone instead of requiring a password
change that breaks every other consumer. Put `prtg_api_key` in the secret and it is used
in preference to any passhash also present, so migrating is a matter of adding one field.
The passhash path remains supported for versions with no API Keys tab.

Be precise about what a key does *not* buy on current PRTG, because it is easy to
overstate. Paessler's manual documents an `Authorization: Bearer` header, which would
keep the credential out of the URL entirely. Tested against 26.2.116.1542, every header
form is rejected with `401 Unsupported authorization scheme`, so the key travels as an
`apitoken` query parameter exactly as a passhash does - equally exposed to logging, and
equally dependent on the scrubber below. Nor does a key restrict what the caller can
read: a key inherits the object rights of whoever created it, so a key made by an
administrator can read the entire device tree regardless of its access level. Create it
as the read-only user. The one real gain is independent revocation.

### TLS verification was disabled

`cert_reqs="CERT_NONE"` disabled certificate validation entirely, making the
credential interceptable by anyone positioned on the path - and the credential is in
the URL. Suppressing urllib3's `InsecureRequestWarning` at the same time leaves nothing
recording that verification was off.

**Enforced by:** verification on by default, with `secret.ca_bundle_secret_arn` to
supply the certificate so verification can stay on. Disabling is possible, logs a
warning every invocation, and raises an alarm.

One caveat: PRTG ships a default certificate whose private key is in the installer, so
its key pair is identical on every installation and available to anyone. Trusting
*that* certificate as the bundle yields encryption without authentication, leaving the
interception path open while the configuration looks correct. The bundle is only worth
anything once PRTG serves a certificate whose key the operator holds. See
[`prtg-setup.md`](prtg-setup.md#replace-the-shipped-certificate-before-trusting-it).

### Secrets Manager was granted on every secret

A wildcard grant such as `secretsmanager:GetSecretValue` on `Resource: "*"` reads
every secret the account holds, not just the PRTG credential.

**Enforced by:** the CDK L2 grant, scoped to the exact secret ARN. Asserted by
`test_secrets_manager_grant_is_scoped_to_one_secret`.

### Fan-out could assume a role in any account, in any organisation

The cross-account direction is right: the pipeline's Lambda role assumes a role in each
workload account, and that role holds `aidevops:CreateBacklogTask` on its own Agent
Space. Nothing assumes the pipeline role; traffic only ever flows outward from the
pipeline.

The caller-side policy is the trap. Onboarding accounts without an IAM change per
account is tempting, and the easy way to write it is a wildcard resource fenced by a
condition:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/PRTG-CrossAccount-DevOpsAgent-Role",
  "Condition": { "StringEquals": { "aws:PrincipalOrgID": "<YOUR_ORG_ID>" } }
}
```

`aws:PrincipalOrgID` is the organisation of the principal *making* the request. This is an
identity-based policy on the pipeline's own role, so it resolves to the pipeline account's
own organisation on every call - it is satisfied unconditionally and constrains nothing.
The effective grant is `sts:AssumeRole` on that role name in **any** AWS account, inside
the organisation or outside it. The `sts:ExternalId` in the workload account's trust policy
is then the only thing standing between the pipeline role and a similarly-named role
somewhere else, and a shared secret is not an authorisation boundary.

What makes this one worth singling out is how thoroughly it hides. It reads as correct, it
passes review, it deploys cleanly, and because it fails *open* a working fan-out
deployment demonstrates nothing about it. A test asserting the string `aws:PrincipalOrgID`
appeared in the condition passed too, against a policy that restricted nothing.

**Fixed by:** `aws:ResourceOrgID`, the organisation of the role *being assumed*, which is
the side that needs constraining. AWS documents it as the key that lets a policy apply to
all resources in an organisation so that adding and removing accounts needs no policy
update - the property the wildcard was reaching for. It also fails closed: the key is
absent unless the resource-owning account belongs to an organisation, and `StringEquals`
against an absent key does not match, so a target outside any organisation is denied
rather than quietly allowed. `sts:AssumeRole` is not among the actions the key does not
support.

The role name is also derived from the configured routes rather than written into the ARN,
since `role_name` is overridable per route and a hardcoded name silently excludes any
route that overrides it.

Asserted by `test_fanout_with_an_organisation_id_scopes_by_resource_org`, which pins the
whole condition and asserts `aws:PrincipalOrgID` is *absent*, and by
`test_fanout_org_scope_covers_a_custom_role_name`.

### Everything arrived as HIGH priority

Every investigation was created with `priority="HIGH"`, making the field useless for
triage: a link-utilisation warning and a downed database were indistinguishable.

**Fixed by:** mapping PRTG's five-star rating, with a live Down state escalated to at
least HIGH and an acknowledged one demoted because somebody is already working on it.

### No deduplication

Each notification created a new investigation. The documented workaround was a second
PRTG notification trigger with repeat suppression, configured correctly on every
group, forever.

**Fixed by:** `CreateBacklogTask`'s idempotency token, derived from the sensor, its
state, and a time bucket. Server-side, so it cannot be misconfigured away.

### Log retention was unbounded

Log groups were created implicitly and never expired, holding PRTG hostnames and
addresses indefinitely.

**Fixed by:** explicit log groups with configured retention - including the VPC flow
log group, which CDK otherwise defaults to two years regardless of configuration.

---

## Identity provider considerations

With `auth.mode: oidc`, the identity provider becomes part of the trust chain, and
carries risks IAM does not.

| Risk | Severity | What to do |
|---|---|---|
| **Token replay.** A token stays valid until expiry, and revoking it at the provider does not invalidate it at the Gateway. | High | Keep token lifetimes short - one hour or less. The Cognito client this sample creates is capped at one hour. |
| **Provider compromise.** A tenant takeover or signing-key theft grants access to everything federated, including this Gateway. Outside the AWS control boundary. | Critical | Treat the provider as tier-0. Enforce MFA and conditional access on administrative accounts. |
| **No token restriction.** With neither `allowed_audience` nor `allowed_clients`, any token that provider issued is accepted, for any application and any client. | High | At least one is **required** by this sample's validation. See the note below on which. |
| **An audience restriction that can never match.** Not every provider emits an `aud` claim in a client-credentials token. Cognito does not. Configuring `allowed_audience` against such a provider rejects every call with a bare 403 - a deployment that looks healthy and works for nobody. | Medium | Use `allowed_clients` when unsure. See [`deployment-matrix.md`](deployment-matrix.md#which-restriction-to-use---read-this-before-choosing). |
| **Multi-tenant misconfiguration.** An app registration accepting tokens from any tenant would let external users in. | High | Register single-tenant. Validate the issuer and audience. |
| **Split audit trail.** Authentication events live at the provider, authorisation events in CloudTrail, with different schemas and retention. | Low | Correlate in a SIEM if you need a joined view. |

Prefer `sigv4` where it is available. It has none of these properties: no tokens, no
external trust, and revocation is immediate.

---

## Multi-account considerations

Every additional account boundary adds a place to misconfigure something.

**Cross-account secrets need two policies.** A Secrets Manager resource policy *and* a
KMS key policy grant. Both are emitted as stack outputs, and the error names whichever half
is missing - `no resource-based policy allows` for the first, `Access to KMS is not allowed`
for the second. The AWS managed key cannot be shared across accounts at all, so the secret
must use a customer-managed key. The reading role also needs `kms:Decrypt` in its own
identity policy - set `secret.kms_key_arn` to the key encrypting the secret and the stack
adds it. Two policies plus the caller-side grant; see
[`deployment-matrix.md`](deployment-matrix.md#knob-3---secretmode).

**Use exact role ARNs in trust policies,** not account-wide principals. A trust policy
allowing any principal in the agent account means any role there can invoke the
Gateway, not only the DevOps Agent.

**Set `targeting.organization_id` for fan-out,** so the assume-role policy constrains
its account wildcard with `aws:ResourceOrgID` rather than leaving it unqualified. Note
the key: `aws:ResourceOrgID` is the organisation of the role being assumed, whereas
`aws:PrincipalOrgID` is the organisation of the caller. In an identity-based policy the
second is a tautology - always satisfied, restricting nothing - and it fails open, so
neither a passing test nor a working deployment reveals the difference. See
[`deployment-matrix.md`](deployment-matrix.md#knob-5---targetingmode).

**Centralise CloudTrail.** In a fan-out deployment, the Gateway's decision to invoke,
the Lambda's execution, and the task creation are recorded in different accounts.
Without an organisation trail or Security Lake, correlating an incident means manually
joining three or four trails.

**Consider a Gateway per target.** If several MCP servers share one Gateway, a
compromise of its role reaches all of them - including any that are not read-only.

---

## Recommended hardening

Beyond what this sample configures:

| Action | Why |
|---|---|
| Enable Lambda code signing | Stops function code being replaced with a version that exfiltrates results or adds a mutating tool |
| Enable GuardDuty, including Lambda Protection | Detects credential exfiltration and unusual runtime behaviour |
| Alarm on unusual invocation patterns | Rapid enumeration or off-hours volume suggests reconnaissance rather than investigation |
| SCPs preventing trust-policy edits without approval | The trust policies are what hold the boundaries |
| Set `prtg.host_cidr` to a `/32` | Narrowest egress available |
| Use `network.mode: private` | Removes internet egress entirely, for a modest additional cost over NAT |
| Forward PRTG audit logs to your SIEM | The integration's activity is visible from the PRTG side too |
| Restrict PRTG's inbound rules to the Lambda security group | The integration adds a network path; keep it narrow |

---

## What is asserted automatically

These properties are enforced by tests in `tests/unit/test_infrastructure.py`, so they
are checked on every pull request rather than relying on review:

- `secretsmanager:GetSecretValue` is scoped to one secret ARN
- `lambda:InvokeFunction` is scoped to one function ARN
- `bedrock-agentcore` invoke is scoped to one Gateway ARN, and is not `:*`
- `aidevops:CreateBacklogTask` is scoped to one Agent Space ARN
- Fan-out `sts:AssumeRole` is constrained by `aws:ResourceOrgID`, not `aws:PrincipalOrgID`,
  and covers every role name the routes actually use
- Lambda egress reaches PRTG's address and, in `private` mode, nowhere on the internet
- The alarm API resource policy contains an explicit `Deny`
- No Lambda environment variable contains a credential
- No credential appears in the CloudFormation template
- TLS verification defaults to on
- Every log group has explicit retention
- Every tool in the published schema is implemented, and no tool is implemented that
  is not published

And in `tests/unit/test_prtg_client.py` and `test_handler.py`:

- A connection failure does not leak the credential
- An unexpected exception does not leak the credential
- A PRTG error body is scrubbed before being surfaced
- Every tool issues only GET requests
- No tool parameter can change the request destination
