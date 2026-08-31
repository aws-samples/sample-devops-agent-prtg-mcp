# Architecture

Two independent halves that together close the detect → investigate loop. They fail
independently and in different ways, which is the most useful thing to hold in mind
when operating them.

---

## The loop

![End to end: a PRTG alarm POSTs to API Gateway, the pipeline Lambda creates a
deduplicated investigation task in the Agent Space, the agent then calls the nine
read-only PRTG tools through the AgentCore Gateway into the MCP tools Lambda, which
fetches its credential from Secrets Manager and queries PRTG over HTTPS
](images/architecture-end-to-end.svg)


1. A PRTG sensor changes state and the notification trigger fires an HTTP POST.
2. API Gateway checks the source address (or the VPC endpoint, for a private API) and
   invokes the pipeline function.
3. The function parses the payload, derives a priority, computes an idempotency token,
   resolves the target Agent Space, and calls `aidevops:CreateBacklogTask`.
4. An operator, or the agent's own scheduling, picks up the investigation.
5. The agent discovers the PRTG toolset over MCP and calls a tool.
6. The Gateway invokes the tool function with the tool name in the client context.
7. The function reads the credential (cached), calls PRTG's read API, and returns.

Steps 1–3 are the **alarm pipeline**. Steps 5–7 are the **MCP server**. Neither
depends on the other: you can deploy either alone.

---

## Half 1 - the alarm pipeline

### Why a REST API and not an HTTP API

HTTP APIs are cheaper and faster, but they do not support resource policies. The
resource policy is what enforces both the source-address allowlist and the
private-endpoint restriction, and PRTG cannot send credentials, so it is the only
control available. At webhook volume the cost difference is immaterial.

### Why access control is by source address

PRTG's "Execute HTTP Action" cannot send custom headers. So an API key, a bearer
token, and a SigV4 signature are all unavailable. Two options remain:

- **Public regional API + address allowlist.** The resource policy denies every
  address outside `alarm_allowed_source_ips`. Note the `Deny` is what closes the
  endpoint: an `Allow`-only policy on a REST API is not restrictive.
- **Private API + VPC endpoint.** Unreachable from the internet at all. Stronger, and
  the right answer when PRTG has no public address.

The configuration will not let you leave it open. `0.0.0.0/0` is rejected, and an
empty allowlist on a public API is an error.

### Payload handling

PRTG sends `application/x-www-form-urlencoded` with a **percent-encoded JSON body** -
not form fields. A handler that trusts the content type and calls a form parser gets
one key whose name is the entire JSON document. The parser tries, in order: JSON,
URL-decoded JSON, real form fields, and a single form field whose value is JSON.

It also detects a **test notification**: PRTG does not substitute placeholders when
the test button is used, so a body still containing `%sensor` is a test. Those are
acknowledged with 200 without creating an investigation, which makes the test button
a genuine end-to-end check of DNS, TLS, SNI, the allowlist, and parsing.

### Priority

PRTG's priority rates the *sensor's importance*, not the *current severity*, so both
are considered:

| Situation | Result |
|---|---|
| Test notification | `MINIMAL` |
| Acknowledged down state | one level below the star rating - somebody is on it |
| Live `Down` state | at least `HIGH`, regardless of rating |
| Anything else | the five-star rating maps directly |
| Unrecognised priority text | `MEDIUM` - never escalate on a parsing failure |

That last row matters: a formatting change in a future PRTG version must not silently
flood the backlog with critical tasks.

### Deduplication

`CreateBacklogTask` accepts a `clientToken` for idempotent creation. The token is
`sha256(sensor id | device id | status | time bucket)`, so:

- The same sensor in the same state within the window returns the original task.
- A sensor flapping Down → Up → Down produces **one** investigation. Flapping should
  be one investigation, not many.
- Down and Up are distinct states and each gets its own task.

Buckets are fixed rather than sliding, so two alarms either side of a boundary can
both create a task. A sliding window would need external state; the trade is
deliberate and the worst case is one duplicate rather than one per poll.

### Failure handling

A failure here means an alarm produced no investigation - a missed incident, not a
degraded one. So:

- A malformed body returns **400**. It will never succeed; retrying is pointless, and
  it is not parked for the same reason.
- A routing failure returns **500**. An unexpected failure during task creation
  propagates, which API Gateway surfaces as **502**.
- Either way the alarm is first **written to the dead-letter queue by the function
  itself**, carrying the failure reason, the correlation ID, the deduplication token
  and the original notification body - enough to redrive without reconstructing
  anything.
- The DLQ retains for 14 days and raises an alarm on the first message.
- The response body to PRTG is deliberately opaque. It is written into PRTG's
  notification log, which is not the place for an Agent Space ID or a role ARN. A
  correlation ID is enough to find the detail in CloudWatch.

**Why the function writes to the queue rather than letting Lambda do it.** Lambda's
`DeadLetterConfig` and `retry_attempts` apply only to *asynchronous* invocations.
API Gateway's proxy integration is synchronous, so a pipeline configured that way has
a dead-letter queue that can never receive a message and a CloudWatch alarm on that
queue that can never fire. The failure mode is worse than having no queue: an empty
queue and a green alarm are indistinguishable from everything working.

The token is captured at park time rather than recomputed on redrive, because it
embeds a wall-clock bucket. Recomputing it later lands in a different bucket and
creates a second investigation for the same alarm.

One case remains where an alarm is genuinely lost: processing fails *and* the write to
the queue fails. That is logged as `alarm_park_failed` and has its own alarm
(`PrtgAlarmsLost`), because it must not be inferred from an empty queue.

---

## Half 2 - the MCP server

![Single account, NAT egress, IAM auth: the DevOps Agent signs a SigV4 request to an
AgentCore Gateway, which invokes a Lambda inside the VPC; the Lambda calls PRTG over
HTTPS and fetches its credential from Secrets Manager](images/mcp-standard-nat.svg)

Note the two boundaries the request crosses, because they are where this goes wrong:
the Gateway invokes the function *through* the VPC border, and the function's own
egress is scoped to PRTG. Neither is visible in a successful deployment.

### The invocation contract

Worth stating plainly, because it is the most common source of confusion when
extending this.

```python
# The tool name arrives in the CLIENT CONTEXT:
context.client_context.custom["bedrockAgentCoreToolName"]  # "prtg-mcp___get_sensors"

# The arguments arrive as the ENTIRE EVENT. The event IS the arguments -
# there is no wrapper object and no "arguments" key.
event  # {"status": "down", "count": 10}
```

Two consequences: an empty `event` is normal for `get_server_status`, and a handler
that looks for `event["name"]` will always see `None` and report every tool as
unknown.

The response is MCP's envelope:

```python
{"content": [{"type": "text", "text": "..."}], "isError": False}
```

The handler never raises. An exception would make the Gateway report a generic target
failure, which tells the agent nothing it can act on; a structured `isError` lets it
correct course or try a different tool.

### One source for the tool schema

`src/prtg_mcp/tools.py` holds `TOOL_SPECS`. Two consumers derive from it:

- The handler builds `TOOL_IMPLEMENTATIONS` and refuses any tool not declared there.
- The CDK stack generates the Gateway's advertised schema at synthesis.

A test asserts both directions, plus that every schema property maps to a keyword
parameter of the implementation and that required properties have no default. Drift
here would fail mid-investigation, which is the worst time to discover it.

**The schema is uploaded as a file asset, not inlined.** `ToolSchema.from_inline`
requires CDK's `ToolDefinition`, which coerces the input schema into a
`SchemaDefinition` struct supporting only `type`, `description`, `items`,
`properties` and `required` - so `enum`, `pattern`, `minimum`, `maximum`,
`minLength`, `maxLength`, `default` and `additionalProperties` are all rejected
outright. `from_local_asset` accepts the JSON as written, which keeps `tools.py` as
the one definition with no hand-maintained translation layer.

### What the Gateway preserves

Verified against a deployed Gateway, because it changes how the tool surface has to
be written.

**AgentCore Gateway normalises the schema when it republishes it over MCP.** A
`tools/list` response preserves only `type`, `description` and `required`. Every
other constraint is stripped, whichever mechanism supplied it:

```
declared in tools.py          reaches the agent
────────────────────────      ─────────────────
type                          yes
description                   yes
required                      yes
enum                          no
pattern                       no
minimum / maximum             no
minLength / maxLength         no
default                       no
additionalProperties          no
```

So the file-asset choice does not get richer constraints in front of the agent -
nothing would. Two consequences shape the design:

1. **Constraints are enforced, not advertised.** The handler's validator applies
   them, and its rejection messages name the parameter, the constraint, and the
   accepted values so the agent can correct itself on the next turn.
2. **Descriptions carry the information.** Descriptions *are* preserved, so
   `tools.py` restates valid enum values and numeric bounds in the description text.
   That is the only channel that reaches the agent.

What the agent actually receives for `status`, after that change:

> Return only sensors in this state. One of: up, down, warning, paused, unknown,
> unusual, down_acknowledged, down_partial.

`TestConstraintsAreDiscoverable` in `tests/unit/test_tool_contract.py` asserts every
`enum` value and every numeric ceiling appears in its own description, so the prose
and the machine-readable constraint cannot drift apart. Nothing else would fail if
somebody added an enum value and forgot the description.

### Argument validation

The handler validates against the published schema before dispatching, using a
dependency-free subset validator. Coercion is deliberate: a language model routinely
emits `"2001"` where an integer belongs, and rejecting that would waste a turn.

Rejection messages are written for the agent to act on - they name the parameter, the
constraint, and the accepted values - so it can correct itself on the next turn. The
alternative, passing unknown parameters through to PRTG, is worse than an error: PRTG
ignores what it does not understand and returns a result that looks like an answer but
was never filtered the way the agent intended.

### Credential handling

Fetched from Secrets Manager on first use and cached with a TTL, not pinned at import
time. Rotation therefore converges on its own within
`secret.credential_ttl_seconds` - no redeployment and no cold-start trick.

Nothing happens at module import. A credential problem surfaces as a normal tool error
with a usable message, rather than as a Lambda `Runtime.InitializationError`, which
reports nothing useful.

---

## Networking

### `nat`

Functions sit in a private subnet with a NAT gateway default route and reach AWS APIs
over public endpoints. Egress is restricted to PRTG plus 443 to anywhere - AWS service
endpoints have no stable address range worth pinning.

### `private`

No NAT gateway, no internet gateway. Subnets are `PRIVATE_ISOLATED`, so there is no
public subnet for an internet gateway to attach to - "no internet" is structural
rather than enforced by a route table someone could later change.

Six interface endpoints: `secretsmanager`, `logs`, `lambda`, `sts`, `sqs`,
`aidevops-dataplane` - plus `ssm` when fan-out is in use, since its routing table lives in
an SSM parameter. Egress
reaches PRTG and the endpoints, and nothing else.

Endpoints are created with `open=False` and access is granted security-group to
security-group. CDK's default adds an ingress rule for the whole VPC CIDR, which would
admit anything sharing the VPC - and would also fail for a VPC imported via
`from_vpc_attributes`, which exposes no CIDR.

VPC flow logs capture `REJECT` traffic. Diagnosing "the Lambda cannot reach PRTG"
without them is guesswork.

---

## Observability

The operating question this is built around: *how would we find out this integration
had quietly stopped working?* It is read-only, so nothing breaks loudly. The agent
simply gets less context and carries on - strictly worse than an outage, because
nobody notices.

| Alarm | Detects | Why it needs to exist |
|---|---|---|
| `PrtgAuthFailures` | Rotated passhash never written to the secret | PRTG returning 401 is **not** a Lambda error, so no built-in metric catches it |
| `McpLambdaErrors` | Bugs, missing endpoints, IAM gaps | |
| `McpLambdaThrottles` | Reserved concurrency reached; tool calls dropped | |
| `McpLambdaDurationApproachingTimeout` | PRTG slowing at p95 > 80% of timeout | Catches degradation before it becomes timeouts |
| `PrtgTlsVerificationDisabled` | Verification left off after a proof of concept | |
| `GatewaySystemErrors` / `GatewayThrottles` | Gateway cannot reach the target | |
| `PipelineLambdaErrors` | Alarms not becoming investigations | Threshold 1, not 3 - each failure is a potentially missed incident |
| `PipelineDeadLetterMessages` | An alarm exhausted its retries | |
| `PrtgRoutingFailures` | An alarm matched no route and no DEFAULT | An alert reaching nobody |
| `ApiClientErrors` / `ApiServerErrors` | Allowlist or URL problems | |

Metric filters key on a stable `event` field in structured JSON logs, not on substring
matches against prose, so rewording a log line cannot silently break an alarm.

---

## Deliberate omissions

**The Agent Space.** AWS publishes its own CDK and CloudFormation getting-started for
creating one. Duplicating it here would drift from the canonical version, so this
sample takes an existing `agentSpaceId` as input.

**Cross-account network links.** VPC peering, Transit Gateway attachments and
Site-to-Site VPN all need agreement from the other side. A sample should not quietly
reshape your network, so they are documented prerequisites and the stack adds only the
security group rule.

**Cross-account IAM roles in workload accounts.** For fan-out, the role in each target
account must be created there. The required trust policy is emitted as a stack output.

**PRTG configuration.** Nothing on the PRTG side is automated. The integration is
entirely AWS-side, which means it needs no PRTG plugin and no changes to PRTG beyond
one notification template and a read-only user.
