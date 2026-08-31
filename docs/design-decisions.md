# Design decisions worth knowing

Five choices in this sample differ from how the integration is usually written up, and
each one exists because the obvious approach failed in a way that was expensive to
diagnose. None of them is required reading to deploy - start with the
[README](../README.md) for that. Read this when you are reviewing the sample, adapting
it, or wondering why a particular thing is not simpler.

---

## Why credentials are not configuration

Config files get committed. A PRTG credential placed in one reaches git history, every
clone, and any CI log that echoes the file - and scrubbing the file later does not undo
it, because history keeps the value. Rotation becomes the only remedy. So the secret is
created with the right JSON shape but blank fields, and you write the credential
afterwards with one CLI call. The loader **rejects** a config file containing
credential-shaped keys, `prtg_api_key` among them.

A PRTG credential is not an ordinary one: PRTG stores credentials for everything it
monitors - SNMP community strings, WMI and domain accounts, SSH keys, database
connection strings. Treat PRTG as a tier-0 asset and give this integration a read-only
account.

That is also the argument for preferring an **API key** over a passhash. A passhash
derives from the account password, so revoking it means changing that password and
breaking every other consumer of the account; there is one per user, so you cannot stage
a replacement. Deleting an API key revokes this integration alone. Both forms are
supported and the key wins when both are present, so migrating is a matter of adding one
field to the secret.

See [`prtg-setup.md`](prtg-setup.md#5-store-the-credential) for the procedure.

## The tool schema has one source

`src/prtg_mcp/tools.py` defines the nine tools. The Lambda builds its dispatch table
from it, and the CDK stack generates the Gateway's advertised schema from it at
synthesis. They cannot drift, and a test asserts it in both directions.

This matters because drift here fails at the worst possible time: the agent
constructs a call from a schema the handler does not honour, mid-investigation.

## Errors never carry the credential

PRTG's API authenticates with the credential in the query string, and urllib3 puts
the request URL into its exception messages. The implementation this sample is
derived from returned `f"Error: {e}"` straight to the agent - so a single connection
failure would have written the PRTG passhash into the model's context and from there
into the durable investigation record.

Every outbound message is scrubbed, unexpected exceptions are reduced to their type
plus a correlation ID, and a test asserts the passhash never appears in a returned
message. The general lesson: an error path can leak a credential the happy path never
returns, so the scrubber has to cover exception text too.

## Duplicate alarms are handled server-side

`CreateBacklogTask` accepts an idempotency token, so the pipeline derives one from
the sensor, its state, and a time bucket. A flapping sensor produces one
investigation rather than one per poll. The alternative - asking operators to add a
second PRTG notification trigger on every group to gate duplicates - is more work per
group, forever, and depends on operators remembering to do it.

Server-side only gets you half of it, though, and the other half is not optional. A
reused token whose request body has *changed* is rejected with `ConflictException`
rather than replayed - and the body changes on nearly every repeat notification,
because `lastValue`, `downtime`, `uptime` and `message` all move between polls and all
feed the description. So the pipeline treats that specific conflict as the suppression
it is. Left as an error it inverted the feature: the duplicate deduplication exists to
swallow became a 5xx to PRTG, a firing alarm, and a dead-letter message.

## Everything CI checks runs without an AWS account

Unit tests and `cdk synth` need no credentials, so every pull request verifies the
IAM scoping, the schema contract, and the independence of the five knobs. Only
`cdk deploy` and the opt-in PRTG integration tests need real access.

The limit of that guarantee is worth stating: synthesis proves a template says what it
should, not that the deployed system behaves. A template missing a VPC endpoint is a
template that says so, and no synthesis test notices.

---

## Related

| Document | Read it when |
|---|---|
| [`architecture.md`](architecture.md) | You want the request flows and trust boundaries |
| [`security.md`](security.md) | Before production. Threat model, and what this sample fixed |
| [`well-architected.md`](well-architected.md) | Reviewing against the six pillars |
