# Sample PRTG payloads

Captured shapes of what PRTG's "Execute HTTP Action" actually sends, for testing the
alarm pipeline without waiting for a real alarm.

| File | What it represents |
|---|---|
| `sensor-down.json` | A sensor entering Down, with the full field set a current PRTG resolves. The common case. |
| `sensor-down-urlencoded.txt` | The same alarm as PRTG really transmits it: `application/x-www-form-urlencoded` with a percent-encoded JSON body. |
| `sensor-warning.json` | A warning state on a low-priority sensor, which maps to a lower task priority. Also the partial case: a template carrying only some of the optional fields. |
| `sensor-down-acknowledged.json` | An acknowledged down state, demoted because somebody is already working on it. |
| `test-notification.json` | What the PRTG test button sends. Placeholders are **not** substituted, so the pipeline acknowledges it without creating an investigation. |
| `unresolved-placeholders.json` | A **real** alarm from an older PRTG, where the core placeholders resolved but several optional ones did not. Those fields are treated as absent; the alarm is not mistaken for a test. |
| `truncated.txt` | A payload broken across lines, which is what happens when the PRTG payload field contains a line break. Rejected with a message naming the cause. |

`test-notification.json` and `sensor-down-urlencoded.txt` are generated from
`payload_template()` in `src/alarm_pipeline/payload.py` rather than maintained by hand,
and a test asserts they still match it. That is what keeps them from drifting when a
field is added.

## Why `unresolved-placeholders.json` matters

It pins the behaviour that makes a wide payload safe to send. PRTG leaves an
*unrecognised* placeholder as literal text, exactly as it does for a test
notification - so `%tags` on a PRTG older than 20.1.56 arrives looking identical to a
test. If test detection considered every field, one unsupported placeholder would turn
every real alarm into a "test": HTTP 200, no investigation created, and nothing
recorded as an error anywhere.

Detection is therefore based only on `%sensor`, `%device`, `%status` and `%message`,
which every PRTG version substitutes. Any other field arriving as a literal
placeholder is treated as absent.

## Sending one

Against a deployed public endpoint, from a host whose address is in
`alarm_allowed_source_ips`:

```bash
URL=$(aws cloudformation describe-stacks \
  --stack-name prtg-mcp-alarm-pipeline --region <region> \
  --query "Stacks[0].Outputs[?OutputKey=='PrtgNotificationUrl'].OutputValue" --output text)

curl -X POST "$URL" \
  -H 'Content-Type: application/json' \
  --data @samples/prtg-payloads/sensor-down.json
```

Invoking the function directly bypasses API Gateway, so it tests the handler without
needing the source address to match:

```bash
aws lambda invoke \
  --function-name prtg-mcp-alarm-pipeline \
  --cli-binary-format raw-in-base64-out \
  --payload "$(jq -n --arg b "$(cat samples/prtg-payloads/sensor-down.json)" \
      '{body: $b, headers: {"Content-Type": "application/json"}}')" \
  --region <region> /dev/stdout
```

## A note on the encoding

`sensor-down-urlencoded.txt` is worth understanding. PRTG sets the content type to
`application/x-www-form-urlencoded` but sends a percent-encoded JSON document as the
body, rather than form fields. A handler that trusts the content type and calls a
form parser gets a single key whose name is the entire JSON document. The pipeline
tries JSON, then URL-decoded JSON, then real form fields, and finally a single form
field whose value is JSON, in that order.
