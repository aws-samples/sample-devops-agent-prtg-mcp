# PRTG Network Monitor + AWS DevOps Agent

Give AWS DevOps Agent read-only access to [PRTG Network Monitor](https://www.paessler.com/prtg)
over the Model Context Protocol, and turn PRTG alarms into AI-assisted
investigations.

When a PRTG sensor goes down at 2am, the usual sequence is: someone gets paged,
logs in, opens PRTG, checks sensor history, opens the AWS console, checks
CloudWatch, and correlates the two by hand. Fifteen to thirty minutes before anyone
has a first hypothesis.

This sample closes that loop. The alarm starts an investigation immediately, and the
agent can then query PRTG itself - sensor history, device health, related sensors,
the system log - and correlate it with AWS telemetry in the same investigation.

> **This is a reference sample.** It is built to be read, adapted, and deployed into
> your own account. Read [`docs/security.md`](docs/security.md) before production use.

**Deploying for the first time?** Follow
[`docs/getting-started.md`](docs/getting-started.md) - ten steps from choosing a
deployment shape to a proven loop, with a checkpoint at each one. The
[Quickstart](#quickstart) below is the condensed form of the same path.

---

## What gets deployed

Two halves, deployable together or separately.

![End to end: a PRTG alarm POSTs to API Gateway and the pipeline Lambda creates a
deduplicated investigation task in the Agent Space; the agent then calls the nine
read-only PRTG tools through the Amazon Bedrock AgentCore Gateway into the MCP tools
Lambda, which fetches its credential from Secrets Manager and queries PRTG over
HTTPS](docs/images/architecture-end-to-end.svg)

The numbered walk-through of this picture is
[`docs/architecture.md`](docs/architecture.md#the-loop); its editable draw.io source
is beside it in [`docs/images/`](docs/images/).

Half 2 in detail, in the shape [`config/default.yaml`](config/default.yaml) deploys:

![Single account, NAT egress, IAM auth: the DevOps Agent signs a SigV4 request to an
AgentCore Gateway, which invokes a Lambda inside the VPC; the Lambda calls PRTG over
HTTPS and fetches its credential from Secrets Manager](docs/images/mcp-standard-nat.svg)

**Half 1, the alarm pipeline.** PRTG posts a notification; a Lambda turns it into an
investigation task with the sensor's PRTG object IDs attached, so the agent knows
what to look up.

**Half 2, the MCP server.** Nine read-only tools behind an Amazon Bedrock AgentCore
Gateway. The agent discovers them at runtime and calls them during an investigation.

| Tool | What the agent uses it for |
|---|---|
| `get_server_status` | Is this isolated or widespread? |
| `search` | Turn a hostname from an alert into PRTG object IDs |
| `get_sensors` | What else is failing right now |
| `get_sensor_details` | Full state of one sensor |
| `get_channels` | Which specific disk or interface breached its threshold |
| `get_devices` | Whether the whole device is affected, and which host it maps to |
| `get_groups` | Whether a site or environment is affected |
| `get_sensor_history` | When it started, and whether it was gradual or sudden |
| `get_messages` | Timeline, including flaps that have since recovered |

Everything is read-only. No tool can change PRTG state, and no tool parameter can
change where a request goes. That property is what makes this safe to hand to an
autonomous agent - see [`docs/security.md`](docs/security.md#why-read-only-matters).

---

## Prerequisites

- An AWS account in one of the six regions AWS DevOps Agent supports:
  `us-east-1`, `us-west-2`, `ap-southeast-2`, `ap-northeast-1`, `eu-central-1`,
  `eu-west-1`. The stack validates this before creating anything. See
  [Supported Regions](https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent-supported-regions.html).
- **An Agent Space that already exists**, and its ID. This sample does not create one:
  AWS publishes its own getting-started for that, and duplicating it here would only
  drift. Follow whichever suits you -
  [Creating an Agent Space](https://docs.aws.amazon.com/devopsagent/latest/userguide/getting-started-with-aws-devops-agent-creating-an-agent-space.html)
  (console, auto-creates the two required IAM roles) or the
  [CLI onboarding guide](https://docs.aws.amazon.com/devopsagent/latest/userguide/getting-started-with-aws-devops-agent-cli-onboarding-guide.html)
  (`aws devops-agent create-agent-space`, about 20 minutes). Either way, associate at
  least one AWS account with the Agent Space - without that the agent has no telemetry
  to correlate PRTG against.
- PRTG Network Monitor reachable over **HTTPS**, and a **read-only** PRTG user.
  See [`docs/prtg-setup.md`](docs/prtg-setup.md).
- Python 3.11+, Node.js 22 (what CI uses; 20+ works), and AWS credentials for the target account.

No PRTG server to point it at? There is an optional, evaluation-only demo stack, off
unless you ask for it:

```bash
cdk deploy -c demo_prtg=true '*-demo-prtg'                          # PRTG on EC2
cdk deploy -c demo_prtg=true -c demo_app_server=true '*-demo-prtg'  # plus a host to monitor
```

It is a testing affordance, not a recommended topology - a real PRTG server holds
credentials for everything it monitors and deserves rather more than a single
unpatched instance. You supply the installer; nothing here redistributes PRTG. The
monitored host exists so the WMI sensors have a target, and it comes with both firewall
layers configured. See [`docs/network-ports.md`](docs/network-ports.md).

---

## Quickstart

The quickstart deploys [`config/default.yaml`](config/default.yaml):
**both halves, in one account, in a new VPC with NAT egress, IAM (SigV4)
authentication, the PRTG credential in a Secrets Manager secret created here, PRTG
inside that VPC, and one Agent Space.** Every one of those choices is a knob in the
config file - [Choosing a deployment shape](#choosing-a-deployment-shape) below
covers the alternatives, and [`docs/deployment-matrix.md`](docs/deployment-matrix.md)
each knob in detail.

Every command, minimal commentary. For the same journey with decision help and a
verification checkpoint at each step, use
[`docs/getting-started.md`](docs/getting-started.md).

```bash
git clone https://github.com/aws-samples/sample-devops-agent-prtg-mcp.git
cd sample-devops-agent-prtg-mcp
make install
```

Verify everything before touching AWS. This needs no account and no PRTG server:

```bash
make check          # lint, 522 unit tests, synthesise every example config, secret scan
```

Then deploy. The target region is set by `region:` in the config file - the shipped
default is `ap-southeast-2`. Edit it to match your Agent Space's region before
deploying; `make deploy` ignores `AWS_REGION` and your credential's default region.

```bash
export DEVOPS_AGENT_SPACE_ID=<your agent space id>
export PRTG_SOURCE_IP=<public IP of your PRTG server>     # curl https://checkip.amazonaws.com on the PRTG host
export PRTG_PRIVATE_IP=<private IP of your PRTG server>

make bootstrap      # once per account and region
make deploy
```

Store the PRTG credential. It is deliberately not in any config file - see
[Why credentials are not configuration](docs/design-decisions.md#why-credentials-are-not-configuration):

```bash
# An API key is preferred where your PRTG version has them: deleting one revokes this
# integration alone, whereas revoking a passhash means changing the account password.
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{"prtg_url":"https://<prtg-host>","prtg_api_key":"<api-key>"}'

# Or, for older PRTG:
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{"prtg_url":"https://<prtg-host>","prtg_username":"<user>","prtg_passhash":"<passhash>"}'
```

Create the API key **while signed in as the read-only user**, not as an administrator -
a key inherits the creating account's view of the device tree, and its access level caps
only what it may *do*. See [`docs/prtg-setup.md`](docs/prtg-setup.md#creating-an-api-key).

Then finish the two ends:

1. **Register the MCP server.** Either set `targeting.register_with_agent_space: true`
   and let the deployment do it - `AWS::DevOpsAgent::Service` plus
   `AWS::DevOpsAgent::Association`, which works for SigV4 because only OAuth providers
   need the console's browser redirect - or do it by hand in the DevOps Agent console:
   *Capability Providers → Register → MCP Server*. The stack outputs `GatewayUrl`,
   `InvokerRoleArn` and
   `RegistrationInstructions` give you every field.
2. **Configure the PRTG notification.** The stack outputs `PrtgNotificationUrl`,
   `PrtgNotificationPayload` and `PrtgSniRequirement`. Follow
   [`docs/prtg-setup.md`](docs/prtg-setup.md) - there are four PRTG quirks that
   will otherwise cost you an afternoon, and one of them makes PRTG report success
   while sending nothing.

Test it end to end with the PRTG test button. The pipeline recognises a test
notification and confirms connectivity without creating a meaningless investigation.

---

## Choosing a deployment shape

This integration is conventionally documented as **eighteen deployment scenarios**,
each a self-contained wall of CLI commands. They are not eighteen architectures. They
are five independent choices, each one knob in a single configuration file -
[`docs/deployment-matrix.md`](docs/deployment-matrix.md) documents every knob in
detail:

| Knob | Values | Chooses |
|---|---|---|
| `network.mode` | `nat` \| `private` | Whether the function has any internet route |
| `auth.mode` | `sigv4` \| `oidc` | IAM signing, or JWT from Cognito / Entra ID / Okta / Auth0 / Keycloak |
| `secret.mode` | `local` \| `external` | Whether the credential lives in this account |
| `prtg.reachability` | `same-vpc` \| `remote` | Whether PRTG is across a peering, Transit Gateway or VPN |
| `targeting.mode` | `single` \| `fanout` | One Agent Space, or many across accounts |

One configuration file sets all five. Five worked examples ship - the first three build
both halves, the last two build one:

| Config | Shape |
|---|---|
| [`config/default.yaml`](config/default.yaml) | Single account, NAT egress, IAM auth. Start here. |
| [`config/regulated-private.yaml`](config/regulated-private.yaml) | No internet at all, Entra ID, secret in a security account, PRTG on-premises. |
| [`config/multi-account-fanout.yaml`](config/multi-account-fanout.yaml) | One pipeline routing to Agent Spaces in many workload accounts. |
| [`config/mcp-only.yaml`](config/mcp-only.yaml) | **You already run DevOps Agent.** Half 2 into an existing VPC: the agent gains PRTG tools, and nothing changes about how you get paged. |
| [`config/pipeline-only.yaml`](config/pipeline-only.yaml) | Half 1 into an existing VPC: PRTG alarms open investigations, but the agent cannot query PRTG back. A staging post, not a destination. |

```bash
make deploy CONFIG=config/regulated-private.yaml
make deploy-mcp CONFIG=config/mcp-only.yaml          # half 2 only
make deploy-pipeline CONFIG=config/pipeline-only.yaml # half 1 only
```

[`docs/deployment-matrix.md`](docs/deployment-matrix.md) maps each of the eighteen
conventional scenarios onto these flags, so if you arrived with a scenario number in
hand you can find your way in.

Configuration is validated before anything is created, and reports every problem at
once with the field named and the remedy stated:

```
Deployment configuration is invalid:

  1. region 'eu-west-2' does not offer AWS DevOps Agent. Supported regions: ...
  2. auth.allowed_audience is required when auth.provider is 'entra'. Without it
     the Gateway accepts tokens issued for any audience by that provider.
  3. targeting.routes must include one route with match 'DEFAULT'. Without it, an
     alarm from an unmapped PRTG group is dropped, which means a real alert would
     silently never reach any agent.
```

---

## Cost

At webhook volumes the pipeline itself is close to free; the network choice
dominates.

| Component | Monthly, low volume |
|---|---|
| Lambda, API Gateway, CloudWatch, Secrets Manager, SQS | under $1 |
| NAT gateway (`network.mode: nat`) | ~$32 |
| Interface endpoints, 1 AZ (`network.mode: private`) | ~$7.30 each: ~$37 for five, ~$44 for six |
| Provisioned concurrency, per unit (optional) | ~$2.50 |

Fully-private costs more than NAT, not less, so choose it for the posture rather than
the bill. How much more depends on the configuration: the endpoint list is derived, and
deploying both halves means six endpoints rather than five because the pipeline needs
`aidevops-dataplane`. AWS DevOps Agent and PRTG are licensed separately.

---

## Documentation

In journey order: the first four carry a deployment; the rest are there when a
specific question arrives.

| Document | Read it when |
|---|---|
| [`docs/getting-started.md`](docs/getting-started.md) | **Deploying for the first time** - the step-by-step path this table summarises |
| [`docs/deployment-matrix.md`](docs/deployment-matrix.md) | A knob needs its full story, or you arrived with one of the 18 scenario numbers |
| [`docs/prtg-setup.md`](docs/prtg-setup.md) | Configuring PRTG - read **before** the notification setup |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Something is not working |
| [`docs/security.md`](docs/security.md) | Before production. Threat model and trust boundaries |
| [`docs/architecture.md`](docs/architecture.md) | You want the request flows and trust boundaries |
| [`docs/network-ports.md`](docs/network-ports.md) | Opening ports in security groups and OS firewalls, especially for WMI |
| [`docs/design-decisions.md`](docs/design-decisions.md) | You are reviewing or adapting this, and want to know why it is shaped this way |
| [`docs/well-architected.md`](docs/well-architected.md) | Reviewing against the six pillars |

---

## Repository layout

```
config/                  Deployment configurations - one file per shape
src/prtg_mcp/            MCP server Lambda: tool schema, PRTG client, handler
src/alarm_pipeline/       Alarm pipeline Lambda: payload parsing, routing, handler
infrastructure/          CDK: config model, constructs, two stacks + an optional demo stack
tests/unit/              522 tests. No AWS account, no PRTG server.
tests/integration/       Opt-in tests against a real PRTG server
samples/prtg-payloads/   Real PRTG notification shapes, for testing
docs/                    Architecture, deployment matrix, security, operations
```

Neither Lambda has any third-party runtime dependency - boto3 and urllib3 both ship
in the managed runtime - so there is no layer to build and nothing to rebuild when a
transitive dependency gets a CVE.

---

## Cleanup

```bash
make destroy CONFIG=config/default.yaml
```

**Expect 20–45 minutes, and expect to run it twice.** Both are normal: VPC-attached
Lambda functions wait on Hyperplane network interface release, and the shared stack then
fails once on a security group those interfaces still hold. The PRTG credential secret is
retained on purpose, so a redeploy does not lose it.

The two commands you need - clearing the orphaned interfaces, and deleting the secret when
you are finished - are in
[`docs/troubleshooting.md`](docs/troubleshooting.md#destroy-is-slow-then-fails-on-the-shared-stack).

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The main constraints: the tool surface stays
read-only, IAM stays scoped to specific ARNs, and TLS verification stays on by
default.

## License

MIT-0. See [`LICENSE`](LICENSE).

PRTG Network Monitor is a product of Paessler AG. This project is not affiliated with
or endorsed by Paessler AG. See [`NOTICE`](NOTICE).
