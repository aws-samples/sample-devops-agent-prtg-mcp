# Troubleshooting

Organised by symptom. Each entry names the cause rather than listing checks, because
most of these failures point somewhere other than where they originate.

## Fast triage

```bash
REGION=<region>

# Did the alarm arrive at the API?
aws logs tail /aws/apigateway/prtg-mcp-alarm-api --since 30m --region $REGION

# Was it processed into an investigation?
aws logs tail /aws/lambda/prtg-mcp-alarm-pipeline --since 30m --region $REGION

# Is the agent able to query PRTG?
aws logs tail /aws/lambda/prtg-mcp-mcp-tools --since 30m --follow --region $REGION

# Anything stuck?
aws sqs get-queue-attributes --queue-url <DeadLetterQueueUrl> \
  --attribute-names ApproximateNumberOfMessages --region $REGION
```

Logs are structured JSON with a stable `event` field. Useful ones:

| `event` | Meaning |
|---|---|
| `alarm_received` | Payload parsed |
| `investigation_created` | Task created, with `taskId` |
| `duplicate_suppressed` | Idempotency token matched an existing task |
| `test_notification_acknowledged` | PRTG test button, no task created - normal |
| `routing_failed` | No route matched and no DEFAULT - an alert reached nobody |
| `payload_rejected` | Malformed body; includes a truncated preview |
| `alarm_parked` | Failed, but preserved on the DLQ and replayable |
| `alarm_park_failed` | Failed **and** could not be preserved - the alarm is lost |
| `alarm_park_unconfigured` | `ALARM_DLQ_URL` unset, so nothing was preserved |
| `park_skipped_for_test_notification` | A test notification failed; not worth replaying |
| `tool_invoked` / `tool_succeeded` | An agent tool call |
| `prtg_auth_failed` | PRTG rejected the credential |
| `insecure_request` | TLS verification is disabled |
| `credentials_loaded` | Secret read and cached |

---

## PRTG says the notification succeeded, but nothing happened

**No API Gateway log entry, no Lambda invocation, no error anywhere.**

**Cause: SNI is not enabled in the PRTG notification.** API Gateway requires it.
Without it the TLS handshake completes, the request never arrives, and PRTG reports
success. This is the most confusing failure in the integration because every system
involved reports normality.

**Fix:** in the notification template, enable **SNI Support** and set the SNI name to
the `PrtgSniRequirement` stack output. Then test again.

---

## HTTP 403 from the alarm API

### "Missing Authentication Token"

Despite the wording this is almost never about authentication. It means the request
path matched no resource.

- The URL must include the stage and path: `.../prod/prtg-alarm`
- The method must be `POST`
- Compare against the `PrtgNotificationUrl` output exactly

```bash
curl -X POST "<PrtgNotificationUrl>" -H 'Content-Type: application/json' \
  --data @samples/prtg-payloads/sensor-down.json -i
```

### 403 with the path correct

**Cause: PRTG's source address is not in the allowlist.** The address PRTG presents
may not be the one you expect - NAT, a proxy, or a changed public IP.

Find what it actually presented:

```bash
aws logs tail /aws/apigateway/prtg-mcp-alarm-api --since 30m --region $REGION | grep '"ip"'
```

Then confirm from the PRTG host itself:

```bash
curl https://checkip.amazonaws.com
```

Update `alarm_allowed_source_ips` and redeploy. Use `/32` for a single address.

### 403 on a private API

- `aws:SourceVpce` in the resource policy must match the actual endpoint ID
- A private API is unreachable from the internet - test from inside the VPC
- Across VPC peering, private DNS does **not** propagate. You need a Route 53 private
  hosted zone in the PRTG VPC with records pointing at the endpoint ENI addresses.

---

## Alarm rejected with 400

**`payload_rejected` in the logs.** Check `bodyPreview` in that log entry.

**Most likely cause: a line break in the PRTG payload field.** It truncates the body.
The payload must be a single line - and it still looks correct in the PRTG interface,
so this is easy to stare past.

Other causes:

- Placeholders written with the wrong syntax. PRTG uses `%sensor`, not `{sensor}` or
  `$sensor`.
- A payload with no recognised PRTG fields. The rejection message includes the exact
  payload to use.

---

## Investigations created, but with no useful content

Title or description shows "unknown sensor" or "unknown device".

- **Placeholders are not being substituted.** If you pressed the test button, this is
  expected - PRTG does not substitute for tests, and the pipeline should have
  acknowledged it without creating a task. If a real alarm shows literal `%sensor`,
  check the payload syntax.
- **Missing `%sensorid` / `%deviceid`.** Optional, but without them the agent must
  search PRTG by name before it can look anything up. Add them.

---

## The agent cannot tell which AWS resource is affected

**Cause: `%host` is missing from the notification payload.**

`%device` is a PRTG display label and `%deviceid` is an integer internal to PRTG.
Neither identifies anything in AWS, so an agent given only those has nothing to look
up. `%host` is the address PRTG connects to - for a monitored EC2 instance normally the
private IP or private DNS name - and it is the field that makes the correlation
possible.

Add `"host":"%host"` to the payload, or re-copy the whole `PrtgNotificationPayload`
output. Confirm it arrived by checking the `host` field on the `alarm_received` log
entry:

```bash
aws logs tail /aws/lambda/prtg-mcp-alarm-pipeline --since 10m --region <region> \
  | grep alarm_received
```

Still ambiguous after that? An address is not an identity - a private IP is unique only
within a VPC and is reassigned over time. Record the instance ID on the PRTG device
instead, either as a tag (`%parenttags`) or in the device Comments field
(`%commentsdevice`). See
[`prtg-setup.md`](prtg-setup.md#recording-an-exact-instance-id).

Note also that the payload carries context but confers no capability: resolving an
address to an instance requires the agent to have AWS API access in the target
account. Nothing in this pipeline performs that lookup on its behalf.

---

## Real alarms are acknowledged as test notifications

Symptom: `test_notification_acknowledged` in the logs for an alarm you know was real,
HTTP 200 returned, and no investigation created.

This should no longer be reachable, and the reason is worth knowing. PRTG leaves a
placeholder it does not recognise as literal text, exactly as it does for a test
notification, so on an older PRTG a field like `%tags` (20.1.56+) arrives
indistinguishable from a test. Test detection is therefore based only on `%sensor`,
`%device`, `%status` and `%message`, which every PRTG version substitutes; any other
field arriving as a literal placeholder is treated as absent.

If you see this on a real alarm, one of those four is genuinely unsubstituted - check
the payload syntax. PRTG uses `%sensor`, not `{sensor}` or `$sensor`.

---

## Everything arrives as MEDIUM priority

**Cause: `%priority` is missing from the notification payload.** Without it the
pipeline cannot distinguish sensor importance and falls back to `MEDIUM`.

Add `"priority":"%priority"` to the payload. Note that a live `Down` state is escalated
to at least `HIGH` regardless, so if *everything* is MEDIUM the status field may also
be missing.

---

## Duplicate investigations for one incident

- **Check `targeting.deduplication_window_minutes`** - `0` disables deduplication.
- **Check the PRTG trigger's repeat interval.** Set it to 0 minutes. Deduplication is
  server-side; PRTG repeating creates pressure the idempotency window then has to
  absorb.
- **Two alarms either side of a bucket boundary** can both create a task. Buckets are
  fixed, not sliding. Widening the window reduces the chance.

---

## The agent has no PRTG tools

- Confirm the MCP server is registered: *Capability Providers → Register → MCP Server*,
  using the `GatewayUrl` and `RegistrationInstructions` outputs.
- For `sigv4`, the IAM role must be the `InvokerRoleArn` output.
- For `oidc`, the token endpoint, client ID and scope must match the provider.

Check the Gateway target reached `READY`:

```bash
aws bedrock-agentcore-control get-gateway --gateway-identifier <GatewayId> --region $REGION
```

**Target status `FAILED`** means the Gateway cannot invoke the function. Confirm the
Gateway role holds `lambda:InvokeFunction` on that exact function ARN.

---

## Tool calls fail

### "Unknown tool: None"

**Cause: the handler is not reading the client context.** The tool name arrives in
`context.client_context.custom["bedrockAgentCoreToolName"]` as
`<target>___<tool>`, and must be split on the triple underscore. If you have modified
`extract_tool_name`, this is why.

### "PRTG credentials are incomplete: missing prtg_url"

**The secret has not been populated.** Expected on a fresh deployment - the stack
creates the secret with the right shape and blank fields on purpose. Run the
`PopulateSecretCommand` output.

### "PRTG credentials are incomplete: no prtg_api_key, and ... missing"

The secret has a URL but no usable credential. Supply **either** `prtg_api_key`, **or**
both `prtg_username` and `prtg_passhash`. Half of the passhash pair is not enough. If
both forms are present the API key is used.

### "PRTG rejected the credential (HTTP 401)"

The credential is wrong, or the PRTG user is disabled or not permitted to use the API.
Which credential is in use is recorded on every cold start:

```
{"event": "credentials_loaded", "source": "secrets_manager", "auth": "api_key"}
```

**If `auth` is `api_key`:** check the key still exists under *Setup → Account Settings →
API Keys*, signed in as the user that created it. A key is displayed only once at
creation and cannot be recovered, so a lost one must be deleted and replaced.

**If `auth` is `passhash`:** regenerate it.

```
https://<prtg-host>/api/getpasshash.htm?username=<user>&password=<password>
```

Then write it to the secret. No redeployment needed either way - the cache expires
within `credential_ttl_seconds`.

### A credential works but returns fewer objects than expected

Visibility follows the **PRTG user**, not the credential type. An API key inherits the
rights of whoever created it, and its access level restricts only which *operations* are
permitted. A key created as an administrator therefore sees the whole device tree, while
one created as a read-only user sees only what that user was granted. Measured on one
instance: 13 sensors versus 4, for the same PRTG and the same tools.

If the agent cannot see something you expect, check the read-only user's group rights on
those objects rather than the credential.

The `PrtgAuthFailures` alarm exists for exactly this, because a 401 is not a Lambda
error and appears in no built-in metric.

### "TLS verification failed"

PRTG is almost certainly using a self-signed certificate. Supply it rather than
disabling verification - see
[`prtg-setup.md`](prtg-setup.md#replace-the-shipped-certificate-before-trusting-it).

### "Could not reach PRTG ... after N attempts"

In order of likelihood:

1. **PRTG is not listening on HTTPS.** The integration refuses `http://`.
2. **Security group.** Egress must allow PRTG's address on its port. Check
   `prtg.host_cidr` is right.
3. **No route.** For `reachability: remote`, the peering, Transit Gateway attachment or
   VPN is a prerequisite this stack does not create. Verify the route exists and, for
   peering, that it was *accepted* on the other side.
4. **PRTG's own firewall** is not permitting the Lambda's subnet. Note this is a
   separate layer from the security group - see [`network-ports.md`](network-ports.md).

Flow logs show what was dropped:

```bash
aws logs tail /aws/vpc/flowlogs/prtg-mcp --since 30m --region $REGION
```

### "Could not read the PRTG credential from Secrets Manager"

- **Fully private without a `secretsmanager` endpoint** - the classic case. The stack
  creates it in `private` mode; if you hand-edited the network, check it exists.
- Cross-account secret missing **either** the resource policy **or** the KMS key
  policy. Both documents are stack outputs. The two failures are easy to tell apart,
  because the error names the half that is missing:

  | Missing | Error |
  |---|---|
  | resource policy | `...is not authorized to perform: secretsmanager:GetSecretValue ... because no resource-based policy allows...` |
  | KMS key policy | `AccessDeniedException ... Access to KMS is not allowed` |

- **Applied both and it still fails? Wait 90 seconds and retry before changing anything.**
  A KMS key policy edit takes up to about a minute and a half to take effect, and until it
  does the error is identical to not having applied it. Measured on a live cross-account
  deployment: `Access to KMS is not allowed` at 25s after the edit, working at 85s, with
  nothing changed in between. This is the single most likely thing to send you chasing a
  permissions bug that does not exist.

---

## Fully private: the function runs but writes no logs

**Cause: no `logs` interface endpoint.** The function executes correctly and silently
fails to write. It looks exactly like the function is never invoked.

The stack creates it in `private` mode. If you supplied your own networking, this is
the first thing to check. `required_vpc_endpoints` in the config model is the
authoritative list.

---

## Alarms route to the wrong Agent Space

1. **Matching is case-sensitive** and must equal the PRTG name exactly. `Production`
   does not match `production`.
2. Check the log line `route_resolved` - it reports `matchedBy` and `matchedValue`, so
   you can see which rule won.
3. Precedence is group → probe → device prefix → `DEFAULT`. A group match beats a
   probe match.
4. **A device-prefix key must be the derived prefix** - the text before the first
   `-` or `.` in the device name. A key like `prod-db` can never match, because
   `prod-db-7` derives the prefix `prod`; the alarm falls through to `DEFAULT` with
   `matchedBy: default`, which looks like a routing decision rather than a key
   mistake.
5. Inspect the live table:

   ```bash
   aws ssm get-parameter --name /prtg-mcp/routing-table --region $REGION \
     --query Parameter.Value --output text | jq
   ```

   It can be edited directly; changes take effect within `ROUTING_TTL_SECONDS` with no
   deployment.

### `routing_failed`

An alarm matched nothing and there was no `DEFAULT` route, so **it reached no Agent
Space**. Add a `DEFAULT` route. Configuration validation requires one, so this only
happens if the SSM parameter was edited by hand.

### Cross-account role assumption fails

- The trust policy in the target account must name the pipeline function's role ARN
  exactly. It is emitted as the `WorkloadAccountTrustPolicy` output.
- `sts:ExternalId` must match `targeting.external_id` on both sides.
- Fully private deployments need the `sts` endpoint.

---

## Dead-letter queue has messages

Each message is an alarm that produced no investigation. The message is
self-describing, so start there rather than in the logs:

```bash
aws sqs receive-message --queue-url <DeadLetterQueueUrl> \
  --max-number-of-messages 10 --region $REGION
```

```json
{
  "schemaVersion": 1,
  "reason": "routing_failed",
  "detail": "No route matched group 'Production' and no DEFAULT route is configured.",
  "correlationId": "a1b2c3d4e5f6",
  "parkedAt": 1755772800.0,
  "clientToken": "9f2c...",
  "alarm": {"sensor": "CPU Load", "device": "prod-web-01", "status": "Down", "...": "..."},
  "originalEvent": {"body": "...", "headers": {"Content-Type": "application/json"}}
}
```

`reason` is either `routing_failed` - the alarm was fine and the routing table was
not, which is the common and easily fixed case - or `investigation_creation_failed`.
`detail` carries the underlying error. `correlationId` finds the full invocation:

```bash
aws logs filter-log-events --log-group-name /aws/lambda/prtg-mcp-alarm-pipeline \
  --filter-pattern '"a1b2c3d4e5f6"' --region $REGION
```

Fix the cause, then redrive from the SQS console. Pass `originalEvent` back to the
function unchanged - it holds the body and the content type, which is everything the
parser reads. **Carry `clientToken` through** if you replay by calling
`CreateBacklogTask` directly: it was captured when the alarm was parked, and the
token embeds a time bucket, so recomputing it produces a second investigation for the
same alarm.

Note that a **test notification is never parked**, and neither is a malformed body
(the 400 case). Replaying either could not produce a useful investigation.

### The queue is empty but alarms are failing

Check the `PrtgAlarmsLost` alarm and search for `alarm_park_failed`:

```bash
aws logs filter-log-events --log-group-name /aws/lambda/prtg-mcp-alarm-pipeline \
  --filter-pattern '"alarm_park_failed"' --region $REGION
```

That event means processing failed *and* preserving the alarm failed, which is the one
case where an alarm is genuinely gone. Causes, in order of likelihood: the execution
role lost `sqs:SendMessage`; `ALARM_DLQ_URL` is unset on the function; or, for
`network.mode: private`, the SQS interface endpoint is missing so the call cannot
leave the subnet.

If instead you see `alarm_park_unconfigured`, `ALARM_DLQ_URL` is not set at all - the
CDK stack sets it, so this points at a hand-modified function.

---

## PRTG's own WMI sensors on a monitored host are down

Not the integration, but it blocks the demo - and the error code tells you which stage
failed. Read it from `ProbeWMI.log` on the PRTG server rather than the sensor message:

```
C:\ProgramData\Paessler\PRTG Network Monitor\Logs\probe\ProbeWMI.log
```

| Error | What it means |
|---|---|
| `80070005 Access is denied`, **no logon event on the target** | The request never left PRTG. The "Domain or Computer Name" credential field is empty. |
| `80070005 Access is denied`, **a `4625` on the target** | Authentication reached the host and was rejected - wrong password, or UAC token filtering on a non-builtin local admin. |
| `800706BA The RPC server is unavailable`, **a `4624` on the target** | Authentication succeeded, then the RPC dynamic port was blocked. Port 135 is open and `49152-65535` is not. |

The distinction between the first two matters and is easy to miss: identical error code,
opposite causes. Check the target's Security log to tell them apart.

Two further traps. **Credentials inherit**, so a probe or group with its own override
shadows anything set above it - credentials saved on Root may never be used; set them on
the device to be certain. And a firewall rule for a narrowed dynamic range such as
`10000-10099` is only correct if the OS range was pinned to match, which is a separate
registry change.

Full detail, including the service-scoped firewall rules that avoid the dynamic-port
problem entirely, is in [`network-ports.md`](network-ports.md).

---

## Synthesis and deployment

### `cdk synth` fails with a cloud-assembly schema mismatch

The CDK CLI and `aws-cdk-lib` version independently, and a mismatch fails with an
opaque message. Use the pinned CLI:

```bash
npm ci
./node_modules/.bin/cdk synth        # not a globally installed cdk
```

### Synthesis wants AWS credentials

You supplied `network.vpc_id` without `subnet_ids` and `availability_zones`, which
triggers a synthesis-time EC2 lookup. Add both to synthesise offline - see
[`deployment-matrix.md`](deployment-matrix.md#pointing-at-an-existing-vpc).

### Configuration rejected

The message names the field and the remedy, and reports every problem at once. If it
mentions credentials, that is deliberate: they belong in Secrets Manager, not in a file
that gets committed.

### Region rejected

AWS DevOps Agent is available in six regions only. The error lists them.

---

## Verifying a deployment without PRTG

Invoking the function directly bypasses API Gateway, so the source-address allowlist
does not apply:

```bash
aws lambda invoke --function-name prtg-mcp-alarm-pipeline \
  --cli-binary-format raw-in-base64-out \
  --payload "$(jq -n --arg b "$(cat samples/prtg-payloads/sensor-down.json)" \
      '{body: $b, headers: {"Content-Type": "application/json"}}')" \
  --region $REGION /dev/stdout
```

And for a tool call, with the tool name in the client context as the Gateway sends it:

```bash
aws lambda invoke --function-name prtg-mcp-mcp-tools \
  --cli-binary-format raw-in-base64-out --payload '{}' \
  --client-context "$(printf '{"custom":{"bedrockAgentCoreToolName":"prtg-mcp___get_server_status"}}' | base64)" \
  --region $REGION /dev/stdout
```

`samples/prtg-payloads/` holds the other shapes, including the URL-encoded form PRTG
actually transmits.

---

## Destroy is slow, then fails on the shared stack

`make destroy` routinely takes **20–45 minutes and needs running twice**. Both are
normal, and neither indicates a problem.

### Why it is slow

The VPC-attached Lambda functions. Deleting one waits for AWS to release its Hyperplane
network interfaces, which routinely takes tens of minutes and cannot be hurried. The
AgentCore Gateway, by contrast, deletes in seconds. A stack sitting in
`DELETE_IN_PROGRESS` for half an hour is waiting, not stuck.

### Why the first run fails

A race the stack ordering cannot avoid. The function stacks report `DELETE_COMPLETE`
*before* their network interfaces are actually gone, and those interfaces still hold the
shared stack's security group - so the shared stack fails with:

```
DELETE_FAILED  ...  resource sg-0123456789abcdef0 has a dependent object
```

The error names the security group but not the interfaces holding it, which is what makes
it look like a permissions or dependency bug rather than a timing one.

Clear the orphaned interfaces, then delete the stack again:

```bash
aws ec2 describe-network-interfaces \
  --filters Name=group-id,Values=<lambda-sg-id> \
  --query 'NetworkInterfaces[?Status==`available`].NetworkInterfaceId' --output text \
  | tr '\t' '\n' | xargs -n1 -I{} aws ec2 delete-network-interface --network-interface-id {}

aws cloudformation delete-stack --stack-name <name-prefix>-shared
```

Only interfaces in `available` state are deleted, so this cannot detach anything still in
use.

### The credential secret survives on purpose

The PRTG credential secret is **retained**, so a redeploy does not lose it. Remove it
explicitly when you are finished with the integration:

```bash
aws secretsmanager delete-secret --secret-id prtg-mcp/credentials \
  --recovery-window-in-days 7 --region <region>
```
