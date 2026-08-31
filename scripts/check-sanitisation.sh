#!/usr/bin/env bash
# Reject credentials and site-specific identifiers in tracked files.
#
# Adapting this sample means putting your own PRTG passhash, API key, hostnames and
# private IP addresses somewhere. The easy mistake is to edit a tracked file, get a
# working deployment, and commit the credential along with it. Committed credentials
# survive a later cleanup, because scrubbing the working tree does not rewrite
# history -- rotation is the only real remedy. This script is the cheap guard against
# needing one.
#
# Keep your own values in .env, in Secrets Manager, or under .reference/ (gitignored).
#
# Run locally with `make check-sanitisation`. CI runs the same script.
set -uo pipefail

status=0

files=$(git ls-files -co --exclude-standard \
  | grep -vE '^\.reference/|^\.venv/|^node_modules/|^cdk\.out/|^build/|^\.kiro/' || true)

if [ -z "$files" ]; then
  echo "No files to scan."
  exit 0
fi

# Files where a credential-shaped literal is legitimate. The test suite must contain
# passhash-shaped values to assert they are scrubbed from logs and error messages and
# rejected by the config loader - those are the tests protecting the real credential.
production_files=$(printf '%s\n' "$files" | grep -vE '^tests/' || true)

report() {
  local description="$1" hits="$2"
  if [ -n "$hits" ]; then
    printf 'FAIL  %s\n' "$description"
    printf '%s\n' "$hits" | sed 's/^/        /' | head -10
    status=1
  else
    printf '  ok  %s\n' "$description"
  fi
}

scan() {
  local pattern="$1" description="$2" scope="${3:-all}" target
  target=$files
  [ "$scope" = "production" ] && target=$production_files
  report "$description" "$(printf '%s\n' "$target" | xargs -r grep -nEI "$pattern" 2>/dev/null || true)"
}

echo "Scanning $(printf '%s\n' "$files" | wc -l | tr -d ' ') tracked files"
echo

# --- Credentials ------------------------------------------------------------
scan 'prtg_passhash"?[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9]{6,}"' \
     'no literal PRTG passhash outside tests/' production
# PRTG API keys are base32 and often carry '=' padding, so the character class differs
# from the passhash rule. Added when key authentication was introduced: a new credential
# form that the gate did not know about would have passed straight through it.
scan 'prtg_api_key"?[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9=]{6,}"' \
     'no literal PRTG API key outside tests/' production
# Scoped to production for the same reason as the passhash rule: the tests must contain
# credential-shaped values in URLs in order to assert that redact() removes them.
scan '\bapitoken=[A-Za-z0-9=]{10,}' 'no PRTG API key in a URL' production
# A passhash inside a URL, which is the shape that actually leaks. The rule above only
# catches the quoted "prtg_passhash": "..." form, so a real credential reached both
# docs/security.md and a test docstring -- inside the very prose explaining how the
# leak was stopped -- while this gate reported clean. Documentation examples must use
# an obviously fake value such as 0000000000.
scan '\bpasshash=[0-9]{6,}' 'no PRTG passhash in a URL'
# Same shape with the value unquoted after a colon, as it appears in log lines.
#
# Quantifier braces are UNESCAPED. Every rule here runs through `grep -E`, where `\{`
# is a literal brace rather than a quantifier -- so this rule was written as
# `[0-9]\{8,\}` (basic-regex syntax) and therefore searched for that text literally,
# matching nothing while the gate reported `ok`.
#
# If you add a rule here, test it against a string you expect it to catch before
# trusting a green run. Do not put such a string in this file: the scan covers this
# script too, so a worked example in a comment fails the gate it documents. Use a
# character class to break up any pattern that would match itself, as the
# inclusive-language rule at the bottom does.
scan 'passhash["'"'"']?[[:space:]]*:[[:space:]]*["'"'"']?[0-9]{8,}' 'no bare passhash after a colon'
scan '\bAKIA[0-9A-Z]{16}\b' 'no AWS access key ID'
scan '(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9/+]{20,}' \
     'no AWS secret access key'
# Pattern deliberately omits the leading dashes so grep does not read it as a flag.
scan 'BEGIN [A-Z ]*PRIVATE KEY' 'no private key'

# --- Internal identifiers ---------------------------------------------------
scan '\b[a-z0-9.-]+\.(a2z\.com|amazon\.dev|corp\.amazon\.com|aws\.dev)\b' \
     'no internal-only hostname'
scan '\b(CR-[0-9]{6,}|SIM-[0-9]+)\b' 'no internal ticket or review ID'

# Individual @amazon.com addresses. The two published aws-samples contact addresses
# are expected.
report 'no individual @amazon.com address' \
  "$(printf '%s\n' "$files" | xargs -r grep -nEI '[A-Za-z0-9._%+-]+@amazon\.com' 2>/dev/null \
     | grep -vE 'opensource-codeofconduct@amazon\.com|aws-security@amazon\.com' || true)"

# --- Inclusive language -----------------------------------------------------
# One letter is a character class so this file does not match its own patterns.
scan '(white[l]ist|black[l]ist|[s]lave)' 'inclusive language'

echo
if [ "$status" -eq 0 ]; then
  echo "PASS - nothing sensitive found in tracked files."
else
  echo "FAIL - see above. Move the value to .env, Secrets Manager, or .reference/"
  echo "       (gitignored). If it is already committed, rotate it: scrubbing the"
  echo "       working tree does not remove it from history."
fi
exit "$status"
