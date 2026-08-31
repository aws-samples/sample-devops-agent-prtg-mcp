# Getting started

From a clean checkout to a proven loop - a PRTG alarm opening an investigation, and
the agent querying PRTG during it - in ten steps. Each step says what to do, what you
should see before moving on, and where the detail lives when something is unfamiliar.

Rough budget: about 15 minutes locally, 15–20 minutes of deployment, and 30–60
minutes across PRTG and the two integration ends. Nothing before step 5 touches AWS.

Done this before? The [README quickstart](../README.md#quickstart) is the condensed
form of the same path.

| Step | What happens | Where it runs |
|---|---|---|
| [1](#step-1---choose-a-deployment-shape) | Choose a deployment shape | this page |
| [2](#step-2---confirm-the-prerequisites) | Confirm the prerequisites | - |
| [3](#step-3---install-and-verify-locally) | Install and verify - no AWS account needed | your machine |
| [4](#step-4---prepare-prtg) | Create the read-only user and credential | PRTG |
| [5](#step-5---deploy) | Bootstrap and deploy | AWS |
| [6](#step-6---store-the-prtg-credential) | Store the PRTG credential | AWS |
| [7](#step-7---connect-the-agent) | Register the MCP server with DevOps Agent | AWS |
| [8](#step-8---connect-prtg) | Configure the alarm notification | PRTG |
| [9](#step-9---prove-the-loop) | Test end to end | both |
| [10](#step-10---before-production-or-before-leaving) | Harden, or clean up | - |

---

## Step 1 - Choose a deployment shape

One YAML file sets the whole deployment. Six questions choose your starting file:
the first picks which halves to build, the other five each set one knob, and any
combination of knob values is valid.

**1. Which halves?**

| You want | Deploy | Start from |
|---|---|---|
| The full loop: alarms open investigations, and the agent queries PRTG | both halves | [`config/default.yaml`](../config/default.yaml) |
| Only the agent gains PRTG tools - whatever pages you today keeps paging you | MCP server only | [`config/mcp-only.yaml`](../config/mcp-only.yaml) |
| Only alarms open investigations - the agent cannot query PRTG back | pipeline only | [`config/pipeline-only.yaml`](../config/pipeline-only.yaml) |

**2. May the functions have an internet route?**
Yes → `network.mode: nat` (default). No - the account has no internet route, or
traffic must stay on the AWS network → `network.mode: private`. Private costs
slightly more, not less: ~$44/month in interface endpoints against ~$32 for NAT.

**3. Is the DevOps Agent in this same account?**
Yes → `auth.mode: sigv4` (default - IAM signing, no identity provider, nothing to
rotate). No, or your organisation standardises on an identity provider →
`auth.mode: oidc` with `provider: cognito`, `entra`, or `generic` (Okta, Auth0,
Keycloak, Ping).

**4. Where should the PRTG credential live?**
This account → `secret.mode: local` (default - created empty, populated in step 6).
A central security account → `secret.mode: external`, and budget time for the two
cross-account policies in
[`deployment-matrix.md`](deployment-matrix.md#knob-3---secretmode).

**5. Where is PRTG, relative to the Lambda's VPC?**
The same VPC → `prtg.reachability: same-vpc` (default). Another VPC, another
account, or on-premises → `remote` - the peering, Transit Gateway or VPN link is a
prerequisite this stack does not create.

**6. One Agent Space, or many?**
One → `targeting.mode: single` (default). Investigations routed to Agent Spaces
across many accounts, by PRTG group → `targeting.mode: fanout`.

All defaults? Deploy `config/default.yaml` as it is. Otherwise start from the
nearest shipped file and change only the knobs that differ - each file comments on
exactly what it changes and why:

| Starting file | Shape |
|---|---|
| [`config/default.yaml`](../config/default.yaml) | Both halves, NAT, SigV4, local secret, PRTG in-VPC, one Agent Space |
| [`config/regulated-private.yaml`](../config/regulated-private.yaml) | No internet, Entra ID, secret in a security account, PRTG on-premises |
| [`config/multi-account-fanout.yaml`](../config/multi-account-fanout.yaml) | One pipeline routing to Agent Spaces in many workload accounts |
| [`config/mcp-only.yaml`](../config/mcp-only.yaml) | MCP server only, into an existing VPC |
| [`config/pipeline-only.yaml`](../config/pipeline-only.yaml) | Alarm pipeline only, into an existing VPC |

The full story of every knob - what each value builds, what it costs, and how it
fails - is [`deployment-matrix.md`](deployment-matrix.md). If you arrived holding
one of the eighteen conventionally numbered scenarios, the
[mapping tables](deployment-matrix.md#mapping-the-conventional-scenarios) translate
it into knob values.

**Before moving on:** you know which config file you are starting from. Any
combination can be validated later without deploying it:

```bash
make synth CONFIG=config/your-config.yaml
```

---

## Step 2 - Confirm the prerequisites

- [ ] **An AWS account in a supported region.** AWS DevOps Agent is available in
  `us-east-1`, `us-west-2`, `ap-southeast-2`, `ap-northeast-1`, `eu-central-1` and
  `eu-west-1` only. The configuration validates this before creating anything.
- [ ] **An Agent Space that already exists, and its ID.** This sample does not
  create one. Follow
  [Creating an Agent Space](https://docs.aws.amazon.com/devopsagent/latest/userguide/getting-started-with-aws-devops-agent-creating-an-agent-space.html)
  (console) or the
  [CLI onboarding guide](https://docs.aws.amazon.com/devopsagent/latest/userguide/getting-started-with-aws-devops-agent-cli-onboarding-guide.html)
  (about 20 minutes), and associate at least one AWS account with it - without
  that the agent has no telemetry to correlate PRTG against.
- [ ] **PRTG Network Monitor reachable over HTTPS.** The integration refuses
  `http://`. No PRTG to point at? An evaluation-only demo stack can be deployed
  alongside step 5 - see the [README](../README.md#prerequisites) for the command
  and its caveats.
- [ ] **Python 3.11+ and Node.js 22** (what CI uses; 20+ works), plus AWS
  credentials for the target account.

---

## Step 3 - Install and verify locally

```bash
git clone https://github.com/aws-samples/sample-devops-agent-prtg-mcp.git
cd sample-devops-agent-prtg-mcp
make install
make check
```

`make check` lints, runs the 522 unit tests, synthesises every shipped
configuration and scans for committed credentials - with no AWS account and no
PRTG server.

**Before moving on:** the run ends with
`All checks passed with no AWS credentials used.`

---

## Step 4 - Prepare PRTG

Three things on the PRTG side. The detail - including the traps - is in
[`prtg-setup.md`](prtg-setup.md); this is the order:

1. **Create a read-only user**
   ([§1](prtg-setup.md#1-create-a-read-only-prtg-user)). PRTG holds credentials for
   everything it monitors, so this integration gets the least privileged account
   that works. Every tool is a read, so read-only is sufficient.
2. **Create the credential** ([§2–3](prtg-setup.md#2-choose-a-credential-api-key-or-passhash)).
   Prefer an API key where your PRTG version has them - deleting one revokes this
   integration alone. **Create it signed in as the read-only user**, not as an
   administrator: a key inherits the object rights of whoever created it, so an
   admin-created key can read your whole device tree.
3. **Enable HTTPS, and replace the shipped certificate**
   ([§4](prtg-setup.md#4-enable-https)). Every copy of the PRTG installer carries
   the same default key pair, so trusting it authenticates nothing. Install a
   certificate whose key you hold, and keep `verify_tls: true`.

**Before moving on:** you hold the API key (or passhash) for step 6, and
`https://<prtg-host>` answers.

---

## Step 5 - Deploy

Set `region:` in your config file to the region of your Agent Space - the shipped
default is `ap-southeast-2`, and `make deploy` uses that field, not `AWS_REGION` or
your credential's default region.

Then set the identifiers your configuration interpolates. They are environment
variables so the file can be committed without carrying them:

```bash
export DEVOPS_AGENT_SPACE_ID=<your agent space id>
export PRTG_SOURCE_IP=<public IP of the PRTG server>   # curl https://checkip.amazonaws.com on the PRTG host
export PRTG_PRIVATE_IP=<private IP of the PRTG server>
export ALARM_EMAIL=<you@example.com>                   # optional - but an alarm topic with no subscriber notifies nobody
```

`PRTG_SOURCE_IP` feeds the alarm API's source-address allowlist - the only access
control PRTG's notifications can participate in. It must be the address PRTG
*egresses as* (behind NAT, the gateway's address). If PRTG has no public address,
a public alarm API is the wrong ingress: set `alarm_api_private: true` and list
PRTG's **private** address instead - see
[alarm ingress](deployment-matrix.md#alarm-ingress) and
[`config/regulated-private.yaml`](../config/regulated-private.yaml). Deploying
`mcp-only` uses none of this.

Then bootstrap once, and deploy:

```bash
make bootstrap                                  # once per account and region
make deploy                                     # CONFIG=config/default.yaml unless overridden
```

For the other shapes: `make deploy CONFIG=config/regulated-private.yaml`,
`make deploy-mcp CONFIG=config/mcp-only.yaml`, or
`make deploy-pipeline CONFIG=config/pipeline-only.yaml`.

**Before moving on:** CloudFormation shows `CREATE_COMPLETE` for
`prtg-mcp-shared` plus one stack per half. Everything the next three steps need is
in the stack outputs:

```bash
aws cloudformation describe-stacks --stack-name prtg-mcp-mcp-server \
  --query 'Stacks[0].Outputs' --output table --region <region>
aws cloudformation describe-stacks --stack-name prtg-mcp-alarm-pipeline \
  --query 'Stacks[0].Outputs' --output table --region <region>
```

---

## Step 6 - Store the PRTG credential

The deployment created the secret **empty**, on purpose - a credential in a config
file would reach git history and every CI log
([why](design-decisions.md#why-credentials-are-not-configuration)). Populate it once:

```bash
# With an API key - preferred
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{"prtg_url":"https://<prtg-host>","prtg_api_key":"<api-key>"}'

# Or, for older PRTG without API keys
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{"prtg_url":"https://<prtg-host>","prtg_username":"<user>","prtg_passhash":"<passhash>"}'
```

The `PopulateSecretCommand` stack output carries this command with the name and
region already filled in. If PRTG presents a self-signed certificate, store it and
set `secret.ca_bundle_secret_arn` rather than disabling verification - see
[replacing the shipped certificate](prtg-setup.md#replace-the-shipped-certificate-before-trusting-it).

**Before moving on:** invoke the tool function directly and get PRTG's own status
back. The exact command - and the three errors it can return, each naming a
different cause - is in [`prtg-setup.md` §5](prtg-setup.md#5-store-the-credential).
A reply containing a sensor count means the credential, the network path and TLS
are all correct at once.

---

## Step 7 - Connect the agent

The agent discovers the nine PRTG tools once the Gateway is registered as a
capability provider. Two ways:

**As part of the deployment** - for `auth.mode: sigv4` with
`targeting.mode: single`, set `targeting.register_with_agent_space: true` and
redeploy. Registration becomes infrastructure; no console visit. It is off by
default because registration is account-level and a second deployment into the same
account would collide - see the comment in
[`config/default.yaml`](../config/default.yaml).

**In the console** - *Capability Providers → Register → MCP Server*. The
`GatewayUrl`, `InvokerRoleArn` and `RegistrationInstructions` stack outputs are
every field the form asks for. OAuth providers must use this path; the browser
redirect cannot be automated.

**Before moving on:** the agent lists nine PRTG tools. If it does not, start at
[`troubleshooting.md`](troubleshooting.md#the-agent-has-no-prtg-tools) - the first
check is whether the Gateway target reached `READY`.

---

## Step 8 - Connect PRTG

Skip this step if you deployed `mcp-only`.

Configure the notification template and trigger in PRTG, following
[`prtg-setup.md` §6](prtg-setup.md#6-configure-the-alarm-notification). Read
[the four quirks](prtg-setup.md#the-four-quirks) first - one of them makes PRTG
report success while sending nothing at all. The template, from the stack outputs:

| Template field | Value |
|---|---|
| URL | the `PrtgNotificationUrl` output |
| HTTP Method | `POST` |
| Payload | the `PrtgNotificationPayload` output - **one line, no line breaks** |
| SNI Support | **Enabled** - without it nothing arrives and nothing errors |
| SNI Name | the `PrtgSniRequirement` output |

Then add a state trigger on the Root group, or narrower: when a sensor is **Down**
for 60 seconds, perform the notification, repeat every **0** minutes -
deduplication is handled server-side, so PRTG repeating only creates pressure.

**Before moving on:** the template is saved with SNI enabled, and the trigger is
attached.

---

## Step 9 - Prove the loop

In order, each stage building on the last:

1. **The test button.** On the notification template, press *Test*. PRTG sends
   literal placeholders; the pipeline recognises that and confirms connectivity
   without creating a meaningless investigation.

   ```bash
   aws logs tail /aws/lambda/prtg-mcp-alarm-pipeline --since 10m --region <region>
   ```

   Expect `test_notification_acknowledged`. This one step confirms DNS, TLS, SNI,
   the source-address allowlist and payload parsing together.

2. **A real alarm.** Pause a non-critical sensor, wait past the trigger delay,
   resume it. In the same log, expect `investigation_created` with a `taskId` -
   then confirm the task appears in the Agent Space, in the DevOps Agent console.
   The agent normally picks it up within seconds and completes the investigation
   in minutes.

3. **The agent querying PRTG.** Open the investigation and watch the tools being
   called:

   ```bash
   aws logs tail /aws/lambda/prtg-mcp-mcp-tools --since 10m --follow --region <region>
   ```

   Expect `tool_invoked` / `tool_succeeded` pairs - the first typically within a
   minute or two of the task being created. The agent's written conclusion is in
   the investigation view in the console.

Anything failing at any stage has a named symptom in
[`troubleshooting.md`](troubleshooting.md), which is organised by exactly these
stages - start from what you observed, not from what you deployed.

---

## Step 10 - Before production, or before leaving

Going to production:

- Read [`security.md`](security.md) - the threat model, the trust boundaries, and
  what is deliberately out of scope.
- Keep `verify_tls: true` with a certificate you installed;
  `verify_tls: false` logs a warning on every invocation and raises a CloudWatch
  alarm on purpose.
- Set `observability.alarm_email` if you skipped it - the alarms exist either way,
  but a topic with no subscriber notifies nobody.
- Scope the notification trigger to sensors where an investigation adds value -
  see [which sensors should trigger](prtg-setup.md#which-sensors-should-trigger).
- Review [`well-architected.md`](well-architected.md) for what a sample
  deliberately leaves for you to add.

Cleaning up instead:

```bash
make destroy
```

Expect 20–45 minutes, and expect to run it twice - both are normal. The reasons
(Hyperplane interface release, then a security-group race) and the two commands
that deal with them are in
[`troubleshooting.md`](troubleshooting.md#destroy-is-slow-then-fails-on-the-shared-stack).
The PRTG credential secret is retained on purpose so a redeploy does not lose it;
the destroy output prints the command that removes it too.
