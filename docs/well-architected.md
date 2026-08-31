# Well-Architected review

How this sample maps to the six pillars, what it deliberately does not do, and what
you should add before production. Written honestly: a table of ticks would not be
useful to anyone.

Items marked **[test]** are asserted automatically in `tests/unit/`, so they are
verified on every pull request rather than relying on review.

---

## Operational excellence

### What the sample does

**Infrastructure as code, with configuration separated from it.** Two CDK stacks; the
deployment shape lives in one YAML file. Reviewing a change means reading the config
diff, not re-reading CLI history.

**Configuration validated before anything is created.** Every problem reported at once,
each naming the field and the remedy. The alternative - discovering a missing value
partway through a CloudFormation deployment, or in a Lambda cold start during an
incident - is what this replaces.

**Alarms as code, with actionable descriptions.** Recommended alarms for an
integration like this are usually published as a table and left to the reader to
create. An alarm that exists only in a table is an alarm nobody has, so here they are
resources, and each description says what has broken and what to do, because that is
what an on-call engineer reads first. **[test]**

**Structured logging on a stable contract.** JSON with a stable `event` field. Metric
filters key on that field, not on substring matches against prose, so rewording a log
line cannot silently break an alarm.

**A dashboard covering both halves,** with a header stating the deployed shape and
noting that the two paths fail differently.

**Verification without an AWS account.** 522 unit tests and full synthesis of every
shipped configuration, with no credentials. Every pull request checks the IAM scoping,
the schema contract, and the independence of the five knobs.

**Fixtures that are exercised.** `samples/prtg-payloads/` holds real PRTG shapes, and
tests assert each behaves as its README claims, so they cannot drift.

### Gaps

- **No canary.** Nothing proves PRTG is reachable when no alarm has fired recently. A
  scheduled `get_server_status` would close the gap; consider it if silent
  unavailability matters.
- **No automated rollback.** Deployment is `cdk deploy`. Add a pipeline with change
  sets and approvals for production.
- **No runbook automation.** Troubleshooting is documentation, not Systems Manager
  documents.
- **Registration can live outside your infrastructure code.** With
  `targeting.register_with_agent_space` off - the default, and the only option for
  OIDC or fan-out - the capability-provider registration and each Agent Space
  association are console or API state that CloudFormation does not know about.
  Record where they live, and do not later enable the flag against an account that
  already carries a registration: registration is account-level and the two collide.
- **Nothing closes the loop back to the operator.** The agent's findings live in the
  DevOps Agent console. Whoever was paged still has to go and look; forwarding the
  investigation outcome (or even just the task link) to chat or an ITSM is left to
  you.

---

## Security

Covered in depth in [`security.md`](security.md). In summary:

### What the sample does

**A read-only tool surface with a fixed destination.** No tool mutates PRTG; no
parameter can redirect a request. This is the property that makes the integration safe
to expose to an autonomous agent. **[test]**

**Least-privilege IAM, scoped to specific ARNs.** Secrets Manager to one secret,
Lambda invoke to one function, Gateway invoke to one Gateway, task creation to one
Agent Space. Two wildcards remain - EC2 ENI management and X-Ray - because neither
supports resource-level permissions; the ENI grant is region-conditioned. **[test]**

**Credentials never in configuration or templates.** The secret is created with the
right shape and blank fields; the credential is written afterwards. The loader rejects
a config file containing credential-shaped keys. **[test]**

**Credentials never in error messages.** PRTG authenticates via query parameters and
urllib3 embeds request URLs in exceptions. Without scrubbing, one connection failure
would write the passhash into the agent's context and the durable investigation
record. **[test]**

**TLS verification on by default,** with a CA bundle path for PRTG's self-signed
certificate, an explicit opt-out that warns on every invocation, and an alarm.
**[test]**

**Egress restricted to PRTG.** A single `/32` when `prtg.host_cidr` is set. In
`private` mode there is no internet egress rule at all. **[test]**

**Confused-deputy protection.** Service principals conditioned on
`aws:SourceAccount`; cross-account assumption requires `sts:ExternalId`. **[test]**

**No unauthenticated ingress possible.** PRTG cannot send credentials, so the API is
protected by source address or a private endpoint. `0.0.0.0/0` is rejected and an empty
allowlist on a public API is an error. **[test]**

### Gaps - address these for production

| Gap | Why it matters |
|---|---|
| **No Lambda code signing** | An attacker at the function could replace the code with one that exfiltrates every tool result, or adds a mutating tool while appearing normal |
| **No WAF on the alarm API** | Source-address filtering is coarse; WAF adds rate limiting and payload inspection |
| **AWS managed KMS keys by default** | Adequate same-account; a customer-managed key gives you key policy control and is *required* for cross-account secrets |
| **No automatic credential rotation** | Rotation is a documented manual step. A Secrets Manager rotation Lambda calling PRTG's `getpasshash` endpoint would automate it |
| **GuardDuty not configured** | Out of scope here, but Lambda Protection is what detects unusual runtime behaviour |
| **The Gateway endpoint is public in every network mode** | Authenticated (SigV4 or OIDC) and TLS-protected, but reachable from the internet: `network.mode: private` governs the functions' egress, not the Gateway's ingress. A posture with no public endpoint at all means self-hosting the MCP server behind a DevOps Agent private connection - a different architecture. See [`security.md`](security.md#boundary-1---reaching-the-gateway) |

---

## Reliability

### What the sample does

**A dead-letter queue on the pipeline that can actually receive a message,** with an
alarm on the first one. A failure there means an alarm produced no investigation, so it
must be replayable rather than lost. The function writes to the queue itself: Lambda's
`DeadLetterConfig` and `retry_attempts` apply only to asynchronous invocations, and
API Gateway is synchronous, so the configuration most samples ship produces a queue
nothing can reach and an alarm that can never fire - which reads as "no failures"
rather than "no detection". A test asserts `DeadLetterConfig` is *absent*, because the
mistake is reintroduced by adding something that looks obviously right. **[test]**

**A distinct alarm for the case where an alarm really is lost.** If processing fails
and the write to the queue also fails, `PrtgAlarmsLost` fires. Without it, that case
looks identical to a healthy empty queue. **[test]**

**Retries where they help, and not where they do not.** Transient states (429, 5xx) are
retried; a 401 is not, because retrying a bad credential only multiplies failed logins
and some PRTG configurations lock the account.

**Server-side idempotency.** Deduplication via `CreateBacklogTask`'s client token
cannot be misconfigured away, unlike the PRTG-side trigger arrangement it replaces.

**Graceful degradation.** `get_server_status` falls back to a bounded sensor summary on
PRTG versions lacking `/api/getstatus.htm`. A stale routing table is served if SSM is
briefly unavailable, because dropping real alarms is worse than acting on
slightly-old routing.

**No module-scope I/O.** A credential problem surfaces as a normal tool error rather
than an opaque `Runtime.InitializationError`.

**Bounded result sets.** `count` is capped in the published schema and clamped in the
client. The naive alternative - requesting tens of thousands of rows in one path - is
what makes a probe read into a memory-exhaustion event.

**A distinguished failure for "reached nobody".** Fan-out requires a `DEFAULT` route,
because an alert reaching no Agent Space is the worst outcome available.

### Gaps

- **Single region.** Both stacks are regional. PRTG is typically single-site, so this
  usually matches, but the integration is unavailable during a regional event.
- **One NAT gateway** in `nat` mode. A second doubles cost to protect a read-only
  integration whose unavailability degrades an investigation rather than an
  application. Raise it if that trade does not suit you.
- **No load testing.** Reserved concurrency bounds throughput but the ceiling has not
  been characterised against a real PRTG server.

---

## Performance efficiency

### What the sample does

**Memory sized for the actual workload.** 256 MB rather than the 128 MB minimum:
Lambda scales CPU with memory, and these functions spend their time on TLS handshakes
and JSON parsing, both CPU-bound. At 128 MB the function runs more than twice as long
and usually costs more.

**Connection and credential reuse.** The urllib3 pool and the cached credential survive
across invocations in a warm environment, so a warm tool call pays neither a TLS
handshake nor a Secrets Manager round trip.

**Explicit column selection.** PRTG returns whatever is asked for; every extra column
is tokens the agent pays to read. Search results use a narrower set than detail views.

**Provisioned concurrency available** for VPC cold starts, where ENI attachment adds
seconds. Off by default because it costs about $2.50/month per unit and only matters
where first-call latency does.

**Timeouts sized for the path.** Longer for `remote` PRTG, and a p95 alarm at 80% of
the timeout to catch degradation before it becomes failure.

### Gaps

- **No caching of PRTG responses.** An agent asking the same question twice in one
  investigation makes two calls. Deliberate: monitoring data is time-sensitive and a
  stale answer during an incident is actively misleading.
- **No pagination in the tool surface.** Tools cap results rather than offering a
  cursor. Simpler for the agent to use, at the cost of not being able to walk a very
  large estate exhaustively.

---

## Cost optimisation

### What the sample does

**Log retention always set.** Left unset, CloudWatch retains forever. This includes the
VPC flow log group, which CDK otherwise defaults to two years regardless of
configuration - a quiet inconsistency that only shows up on the bill. **[test]**

**Reserved concurrency as a cost ceiling** as well as a blast-radius limit. **[test]**

**API throttling** at 50 requests per second, bounding what an alarm storm or a
misconfigured trigger can cost.

**Serverless throughout.** No idle compute; at webhook volume the pipeline itself is
well under a dollar a month.

**Only the endpoints that are needed.** Derived from the configuration rather than
created wholesale - five in `private` mode, plus `aidevops-dataplane` with the pipeline,
and `cognito-idp`, `ssm` and `execute-api` only when the configuration calls for them.

**`private` costs more than NAT, not less.** An interface endpoint is about $7.30/month
per AZ, so five run ~$37 and the six a both-halves deployment needs run ~$44, against a
NAT gateway's ~$32. Choose `private` for the security posture and expect to pay for it.
A hardcoded total drifts as the derived list changes, so the per-endpoint rate is given
above and the arithmetic left to the reader; the count itself is derived in one place,
`required_vpc_endpoints`.

The comparison also narrows at volume: NAT charges $0.045/GB processed against an
endpoint's $0.01/GB, so a chatty deployment closes the gap.

### Gaps

- **Investigations are the expensive unit, and they are billed elsewhere.** The
  pipeline's own cost rounds to zero; every alarm that gets through it starts an AI
  investigation billed by AWS DevOps Agent. The controls that matter are the ones
  upstream of that: server-side deduplication (on by default) and scoping the PRTG
  trigger to sensors where an investigation adds value - see
  [`prtg-setup.md`](prtg-setup.md#which-sensors-should-trigger).
- **No budget or anomaly detection.** Out of scope, but worth adding.
- **Multi-AZ endpoints multiply cost.** One AZ is assumed in the figures; three
  triples the endpoint line.
- **Tracing enabled by default.** X-Ray costs a little per trace. Turn it off with
  `observability.tracing: false` once an integration is stable.
- **In `private` mode those traces go nowhere.** `observability.tracing` defaults to
  `true` and the stack creates no `xray` interface endpoint, so the X-Ray daemon cannot
  reach `xray.<region>.amazonaws.com` from an isolated VPC. Nothing fails: the function
  runs correctly, is billed for tracing, and the service map stays empty. Confirmed on a
  deployed private stack - `TracingConfig: Active`, no `xray` endpoint, no internet
  gateway and no NAT. Either set `observability.tracing: false` in `private` mode, or add
  an `xray` interface endpoint by hand (~$7.30/month). It is not created automatically
  because it would raise the cost of every private deployment for a feature many will
  turn off, but the silence is the trap and this is the note that names it.

---

## Sustainability

### What the sample does

**No polling.** Everything is event-driven. Nothing runs unless an alarm fires or the
agent asks a question.

**Right-sized rather than over-provisioned.** Memory chosen from the workload's actual
profile; provisioned concurrency off by default.

**Bounded payloads.** Capped result sets and explicit column selection mean less data
transferred, less parsed, and fewer tokens processed. Token efficiency is a real
sustainability lever in an agent workload.

**Retention limits.** Logs are not kept indefinitely by default.

**Idempotency avoids duplicated work.** A flapping sensor produces one investigation,
not one per poll - and an investigation is a substantially more expensive unit of work
than a log line.

### Gaps

- **No Graviton.** These are Python functions with no native dependencies, so
  `arm64` would work and is cheaper and more efficient. Not set because the sample
  favours the most conventional path; changing `architecture` on both functions is a
  one-line edit and a reasonable first optimisation.

---

## Summary of what to add before production

Roughly in order of value:

1. **Populate `observability.alarm_email` or `alarm_topic_arn`.** Alarms notifying
   nobody are the most likely reason a quiet failure stays quiet. The config warns
   about this.
2. **Use a read-only PRTG account.** Not optional in practice - see
   [`security.md`](security.md).
3. **Set `prtg.host_cidr` to a `/32`.** Narrowest egress available. The config warns
   when it is unset.
4. **Enable Lambda code signing.**
5. **Enable GuardDuty**, including Lambda Protection.
6. **Prefer `network.mode: private`.** No traffic leaves the AWS network, for a few
   dollars a month more than NAT.
7. **Add a canary** if silent unavailability of PRTG data would matter to you.
8. **Automate credential rotation** with a Secrets Manager rotation function.
9. **Centralise CloudTrail** if deploying fan-out across accounts.
10. **Consider `arm64`** for both functions.
