# PRTG setup

What to configure on the PRTG side, and the quirks that will otherwise cost you an
afternoon. Read the [notification quirks](#the-four-quirks) section before you
configure the notification - one of them makes PRTG report success while sending
nothing at all.

For the ports PRTG needs - in security groups *and* in guest OS firewalls, which are
separate layers - see [`network-ports.md`](network-ports.md). WMI in particular needs
more than port 135.

---

## 1. Create a read-only PRTG user

Do this first, and do not skip it.

PRTG is not an ordinary monitored system: it stores credentials for everything it
monitors - SNMP community strings, WMI and Windows domain accounts, SSH keys,
database connection strings. Its network position requires it to reach every
monitored host. Treat it as a tier-0 asset, alongside your domain controllers and
identity systems.

The credential this integration holds should therefore be the least privileged one
that works. Every tool here issues HTTP GETs against read APIs, so a read-only user
is sufficient.

1. In PRTG: **Setup → System Administration → User Accounts → Add User**
2. Name it recognisably, for example `aws-devops-agent-readonly`
3. Set the user type to **Read-only User**
4. Add it to a user group whose access rights on the objects you want visible are
   **Read** - not Write, and not Full

If you use an administrator credential here instead, a compromise of the account
holding it escalates to full PRTG administrative access, and from there potentially
to every system PRTG monitors.

## 2. Choose a credential: API key or passhash

Recent PRTG offers **API keys** in addition to the older passhash. Prefer a key where
your version has them. The integration accepts either, and uses the key when both are
present.

The reason is revocation, not extra protection. Both authenticate as a PRTG user and
inherit that user's object rights, so neither is more privileged. But a passhash derives
from the password: revoking it means changing the account password, which breaks every
other consumer of that account. Deleting an API key revokes this integration alone. For
a credential that sits in an AWS account - possibly one the monitoring team does not own
- being able to cut off access unilaterally, without coordinating a password change, is
worth having.

Be clear about what a key does **not** give you on current PRTG. Paessler's manual
documents an `Authorization: Bearer` header, which would keep the credential out of the
URL. Tested against 26.2.116.1542, every header form is rejected with
`401 Unsupported authorization scheme`, so the key travels as an `apitoken` query
parameter exactly as a passhash does. It is equally exposed to logging, which is why the
integration scrubs both.

### Creating an API key

**Sign in as the read-only user first.** This is the step that is easy to get wrong. A
key inherits the object rights of whoever created it, and the access level caps only
*operations*. A key created while signed in as an administrator cannot write, but can
read your entire device tree. Measured on a real instance: an admin-created key returned
13 sensors where the read-only user's own credential returned 4.

1. Signed in as the read-only user, go to **Setup → Account Settings → API Keys**, or
   `https://<prtg-host>/myaccount.htm?tabid=5`
2. **Add API Key**
3. Token Type will show **Scripting**, which is what the API needs
4. Set **Access Level** to **Read access**
5. Copy the key. **It is shown once and cannot be retrieved again** - a lost key has to
   be deleted and replaced

Read access is enforced server-side, not merely advisory. A write attempt returns
`HTTP 400` with `Read-only user accounts are not allowed to access this web page`.

If your PRTG has no API Keys tab, use a passhash instead.

## 3. Generate a passhash (if you are not using an API key)

PRTG's API authenticates with a `passhash` rather than the password. Get it by
visiting, as that user:

```
https://<prtg-host>/api/getpasshash.htm?username=<user>&password=<password>
```

The response is the passhash. Note that it is **equivalent to a password** - anything
holding it has that user's full API access.

## 4. Enable HTTPS

The integration refuses a plain `http://` URL. PRTG's API sends the credential as a
query parameter, so HTTP would put it on the wire in cleartext on every call.

In PRTG: **Setup → System Administration → User Interface → Site & Server →
Web Server**, then choose an HTTPS option.

### Replace the shipped certificate before trusting it

**Do not supply PRTG's out-of-the-box certificate as the CA bundle.** PRTG is
[delivered with a default SSL certificate](https://www.paessler.com/manuals/prtg/using_your_own_ssl_certificate),
and the private key ships in the installer alongside it. On a default install you will
see:

```
Subject   CN=PRTG Demo Certificate, O=PRTG Demo Certificate   (self-signed)
SAN       DNS Name = localhost
Validity  issued 2023, expires 2033 - dates fixed at build time, not install time
```

Because every copy of the installer contains the same key pair, anyone who downloads
PRTG can present that certificate. Trusting it would give you encryption with **no
authentication**, which is exactly the interception case verification is meant to
prevent. Paessler's own note that a warning "does not mean your connection is not
secure" addresses the browser name mismatch, not this.

The `localhost` SAN also means it matches no address you would reach PRTG on - not the
IP, not the hostname, not a DNS alias.

So install a certificate whose private key you hold, then trust that one:

1. Obtain a certificate from your internal CA, or generate a self-signed one, with a
   **subject alternative name matching the hostname in `prtg_url`**. IP-only SANs work
   but tie the configuration to an address.

   For a demo or a test deployment, an IP SAN is the pragmatic choice - it removes DNS
   from the picture entirely, so nothing but the certificate itself can be wrong.
   Include both if you want to move to a name later without reissuing:

   ```bash
   cat > prtg.cnf <<'EOF'
   [req]
   distinguished_name = dn
   x509_extensions    = v3
   prompt             = no
   [dn]
   CN = prtg.internal
   [v3]
   basicConstraints = critical,CA:FALSE
   keyUsage         = critical,digitalSignature,keyEncipherment
   extendedKeyUsage = serverAuth
   subjectAltName   = @san
   [san]
   DNS.1 = prtg.internal
   IP.1  = 10.0.2.50
   EOF

   openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
     -keyout prtg.key.pk8 -out prtg.crt -config prtg.cnf
   # PRTG wants a traditional RSA key, not PKCS#8
   openssl rsa -in prtg.key.pk8 -out prtg.key -traditional
   ```
2. Install it in PRTG, replacing `prtg.crt` and `prtg.key` in the `cert` directory
   under the PRTG installation, then restart the PRTG core service. Paessler documents
   this, and ships a Certificate Importer tool for it.
3. Store the issuing CA certificate - or the certificate itself, if self-signed - as
   the bundle:

```bash
# Confirm PRTG is presenting the certificate you installed, not the shipped one
openssl s_client -connect <prtg-host>:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName

# Store the trust anchor
aws secretsmanager create-secret \
  --name prtg-mcp/ca-bundle \
  --secret-string "$(cat prtg-ca.pem)" \
  --region <region>
```

If the subject still reads `CN=PRTG Demo Certificate`, the replacement did not take
effect and there is no point continuing.

Then point the configuration at it:

```yaml
secret:
  ca_bundle_secret_arn: arn:aws:secretsmanager:<region>:<account>:secret:prtg-mcp/ca-bundle-XXXXXX
```

Disabling verification instead (`prtg.verify_tls: false`) is supported but logs a
warning on every invocation and raises an alarm, because an intercepted connection
would expose the credential.

Be clear-eyed about the interim state: until the certificate is replaced,
`verify_tls: false` and `verify_tls: true` trusting the shipped certificate offer the
same protection against an attacker on the path, which is none. The difference is that
the first is honest about it and raises an alarm. Reach for the alarm rather than a
green tick you have not earned.

## 5. Store the credential

With an API key, which is preferred:

```bash
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{
    "prtg_url": "https://<prtg-host>",
    "prtg_api_key": "<api-key>"
  }'
```

Or with a passhash:

```bash
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{
    "prtg_url": "https://<prtg-host>",
    "prtg_username": "aws-devops-agent-readonly",
    "prtg_passhash": "<passhash>"
  }'
```

If both are present the API key is used and the passhash ignored, so migrating is a
matter of adding one field. Which one is in use is recorded on every cold start as
`"auth": "api_key"` or `"auth": "passhash"` in the `credentials_loaded` log entry -
naming the mechanism only, never a value.

The function picks up a change within `secret.credential_ttl_seconds` (default 900),
so rotation needs no redeployment and no forced cold start.

Confirm it works:

```bash
aws lambda invoke --function-name prtg-mcp-mcp-tools \
  --cli-binary-format raw-in-base64-out --payload '{}' \
  --client-context "$(printf '%s' \
    '{"custom":{"bedrockAgentCoreToolName":"prtg-mcp___get_server_status"}}' | base64)" \
  --region <region> /dev/stdout
```

A successful reply is PRTG's own status JSON, including `ReadOnlyUser` and a sensor
count. If you see *"PRTG credentials are incomplete"*, the secret has not been
populated. If you see *"PRTG rejected the credential"*, the username or passhash is
wrong or the user is disabled. If you see *"Could not reach PRTG"*, the credential
was read fine and the problem is network - security group or route.

> **`--client-context` is what makes this a real test.** The tool name arrives there,
> not in the payload. Invoking with `--payload '{}'` alone returns
> `Unknown tool None` and lists the available tools - before any credential is read,
> so it confirms the function is deployed and nothing else. Any credential-related
> error from that form is from something else, not from this call.

---

## 6. Configure the alarm notification

### The four quirks

These are not documented together anywhere, and each one produces a failure that does
not point at its cause.

**1. SNI must be enabled.** Without it the TLS handshake completes, the request never
arrives, and PRTG cheerfully logs the notification as successful. This is the single
most confusing failure in the integration: PRTG says OK, API Gateway shows no
request, the Lambda is never invoked, and nothing anywhere records an error. The stack
emits the required SNI name as the `PrtgSniRequirement` output.

**2. The payload must be a single line.** A line break truncates the body. The
pipeline rejects it with a message naming this cause, but the payload still *looks*
correct in the PRTG interface, so it is easy to stare past.

**3. Custom headers are not supported.** This is why access control is by source
address rather than an API key - there is no way to send one.

**4. Placeholders are not substituted for test notifications.** Press the test button
and PRTG sends the literal text `%sensor`, `%device` and so on. The pipeline detects
this and confirms connectivity without creating a meaningless investigation, which
makes the test button genuinely useful.

### Create the notification template

**Setup → Account Settings → Notification Templates → Add Notification Template**

- **Name:** `AWS DevOps Agent - Create Investigation`
- Enable **Execute HTTP Action**

| Field | Value |
|---|---|
| URL | the `PrtgNotificationUrl` stack output |
| HTTP Method | `POST` |
| Payload | the `PrtgNotificationPayload` stack output - **one line** |
| SNI Support | **Enabled** |
| SNI Name | the `PrtgSniRequirement` stack output |

The payload, for reference. Paste it as a single line - the `PrtgNotificationPayload`
output is generated from the same source, so prefer copying that:

```json
{"sensor":"%sensor","device":"%device","status":"%status","message":"%message","host":"%host","sensorId":"%sensorid","deviceId":"%deviceid","group":"%group","groupId":"%groupid","probe":"%probe","probeId":"%probeid","location":"%location","serviceUrl":"%serviceurl","lastValue":"%lastvalue","lastStatus":"%laststatus","priority":"%priority","datetime":"%datetime","since":"%since","lastCheck":"%lastcheck","lastUp":"%lastup","lastDown":"%lastdown","elapsedLastUp":"%elapsed_lastup","elapsedLastDown":"%elapsed_lastdown","downtime":"%downtime","uptime":"%uptime","cumulativeSince":"%cumsince","tags":"%tags","parentTags":"%parenttags","commentsSensor":"%commentssensor","commentsDevice":"%commentsdevice","commentsGroup":"%commentsgroup","commentsProbe":"%commentsprobe","sensorUrl":"%linksensor","deviceUrl":"%linkdevice","groupUrl":"%linkgroup","probeUrl":"%linkprobe","siteName":"%sitename","nodeName":"%nodename","timezone":"%timezone"}
```

Paste it whole. Placeholders your PRTG version does not support are treated as absent
rather than as data, so there is no need to prune the list to match your version - see
[the note below](#unsupported-placeholders-are-safe).

What each group is for:

| Placeholders | Used for |
|---|---|
| `%sensor`, `%device`, `%status`, `%message` | Investigation title and description. **The four that matter most** - see the note below. |
| `%host` | **The address PRTG connects to, and the only field that identifies anything outside PRTG.** For a monitored EC2 instance it is normally the private IP or private DNS name, which is what makes the alarm correlatable with an AWS resource. `%device` is only a display label and `%deviceid` is internal to PRTG. |
| `%priority` | Mapped to task priority - omit it and everything arrives as MEDIUM |
| `%group`, `%probe` | Fan-out routing, and context in the description |
| `%sensorid`, `%deviceid`, `%groupid`, `%probeid` | Handed to the agent so the MCP tools can look the object up directly. Omit these and the agent has to search by name first. |
| `%lastvalue`, `%laststatus` | The measurement that actually breached. "CPU 97 %" is far more actionable than "is Down". |
| `%datetime`, `%since`, `%lastcheck`, `%lastup`, `%lastdown`, `%elapsed_lastup`, `%elapsed_lastdown`, `%downtime`, `%uptime`, `%cumsince`, `%timezone` | Timeline. Lets the agent bound a metrics query instead of guessing a window. |
| `%tags`, `%parenttags`, `%comments*` | Operator-supplied context, and the place to record an **exact** instance ID - see below |
| `%location`, `%serviceurl` | Device metadata, sometimes used to carry environment or ownership |
| `%linksensor`, `%linkdevice`, `%linkgroup`, `%linkprobe` | Deep links, so the task cites PRTG rather than describing it |
| `%sitename`, `%nodename` | Which PRTG instance sent this. Worth having under fan-out, where several can feed one pipeline. |

### Recording an exact instance ID

`%host` gives an address, and an address is not an identity: a private IP is unique
only within a VPC and gets reassigned over time. Where you want an exact answer,
record the instance ID against the PRTG device and let it travel in the payload:

- **A device tag**, picked up by `%parenttags`. For example tag the device
  `aws-instance-i-0abc123def4567890`. Needs PRTG 20.1.56 or newer.
- **The device Comments field**, picked up by `%commentsdevice`. Room for more -
  instance ID, account and region together.

Both are optional. `%host` alone is enough for the agent to attempt a lookup; these
turn a lookup into a certainty.

### Unsupported placeholders are safe

PRTG leaves a placeholder it does not recognise as literal text - exactly what it does
for a test notification. That could have been a nasty failure: one unsupported
placeholder making every real alarm look like a test, acknowledged with HTTP 200, no
investigation created, and nothing recorded as an error anywhere.

The pipeline decides on `%sensor`, `%device`, `%status` and `%message` alone, which
every PRTG version substitutes. Any other field arriving as a literal placeholder is
treated as absent. So the payload above is safe to paste whole on an older PRTG; you
simply get fewer fields in the description.

### Three placeholders deliberately excluded

Do not add these:

| Placeholder | Why not |
|---|---|
| `%settings` | Resolves to sensor settings **including credentials** - Paessler documents it as containing "the user name for Windows, HTTP, POP3 credentials, and so on". It would copy the credentials PRTG uses to monitor your estate into the task description, the pipeline's log group, and the dead-letter queue. |
| `%history`, `%syslogmessages`, `%trapmessages` and siblings | Multi-line values. A line break truncates the body, so one of these rejects the whole alarm. The syslog and trap ones are documented as usable only in Send Email notifications anyway. |
| `%summarycount` | Resolves only in summarised notifications. |

### Add the notification trigger

On the Root group, or narrower if you want a subset:

**Notification Triggers → Add State Trigger**

| Setting | Value | Why |
|---|---|---|
| When sensor is **Down** for | 60 seconds | Long enough to skip transient blips |
| Perform | `AWS DevOps Agent - Create Investigation` | |
| Repeat every | **0 minutes** | Deduplication is handled server-side; PRTG repeating would create pressure the idempotency window then has to absorb |

You do **not** need the second suppression trigger the older PRTG guides recommend.
The pipeline deduplicates using an idempotency token derived from the sensor, its
state, and a time bucket, so a flapping sensor produces one investigation rather than
one per poll. Tune the window with `targeting.deduplication_window_minutes`.

### Which sensors should trigger

Consider scoping this rather than enabling it on Root. Every triggering sensor
consumes agent investigation capacity, so the useful set is usually sensors where an
AI-assisted investigation adds something: application and service health, host
resources, connectivity to dependencies. A link-utilisation warning that resolves
itself in ninety seconds probably does not need one.

PRTG tags are a convenient way to control this - trigger only on sensors tagged, say,
`aws-investigate`.

---

## 7. Test end to end

1. **Press the test button** on the notification template. Expect HTTP 200 and, in
   the pipeline logs, `test_notification_acknowledged`. This confirms DNS, TLS, SNI,
   the source-address allowlist, and payload parsing in one step, with no
   investigation created.

2. **Trigger a real alarm.** Pause a non-critical sensor, wait past the trigger
   delay, and resume it. Then check, in order:

   ```bash
   # The alarm arrived
   aws logs tail /aws/apigateway/prtg-mcp-alarm-api --since 10m --region <region>

   # It was processed
   aws logs tail /aws/lambda/prtg-mcp-alarm-pipeline --since 10m --region <region>
   ```

   Look for `investigation_created` with a `taskId`. Then confirm the task is in the
   Agent Space, in the DevOps Agent console. The agent normally picks a task up
   within seconds and completes the investigation in minutes, not hours. (If your
   AWS CLI reports `devops-agent` as an invalid choice, it predates the service -
   update it or use the console; nothing in this integration needs that CLI.)

3. **Confirm the agent can query PRTG.** In an investigation, the agent should be
   able to call the PRTG tools. Watch them arrive:

   ```bash
   aws logs tail /aws/lambda/prtg-mcp-mcp-tools --since 10m --follow --region <region>
   ```

   Each call logs `tool_invoked` with the tool name, then `tool_succeeded` with a
   duration. The first calls typically arrive within a minute or two of the task
   being created; the agent's written findings are in the investigation view in the
   DevOps Agent console.

If any step fails, [`troubleshooting.md`](troubleshooting.md) is organised by symptom.

---

## Rotating the credential

**With an API key**, which is why keys are worth preferring. Create the replacement
before deleting the old one and there is no interruption, and nothing outside this
integration is affected:

```bash
# 1. As the read-only user: Setup > Account Settings > API Keys > Add API Key
#    Access Level: Read access. Copy the key; it is shown only once.

# 2. Update the secret
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{"prtg_url":"https://<host>","prtg_api_key":"<new-key>"}'

# 3. Once the function has picked it up, delete the old key in PRTG.
```

**With a passhash**, rotation is disruptive and worth understanding before you rely on
it. A passhash derives from the password, so there is no way to rotate it in isolation:
changing the password invalidates the credential for *every* consumer of that account,
and there is only one passhash per user, so you cannot stage a replacement first.

```bash
# 1. New passhash in PRTG (change the password, or generate a fresh hash)
#    https://<prtg-host>/api/getpasshash.htm?username=<user>&password=<new-password>

# 2. Update the secret
aws secretsmanager put-secret-value \
  --secret-id prtg-mcp/credentials \
  --region <region> \
  --secret-string '{"prtg_url":"https://<host>","prtg_username":"<user>","prtg_passhash":"<new>"}'
```

No redeployment and no cold-start trick required. The function re-reads the secret
when its cache expires. Shorten `secret.credential_ttl_seconds` if you want rotation
to take effect sooner.

The `PrtgAuthFailures` alarm fires if a rotation is missed, which is worth knowing
about because PRTG returning 401 is *not* a Lambda error and shows up in no built-in
metric.
