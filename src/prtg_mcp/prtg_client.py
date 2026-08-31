"""HTTP client for the PRTG Network Monitor API.

Three concerns live here that the upstream reference implementation handled in
ways that do not hold up in production, and which are worth understanding before
changing this file.

**Credentials are cached with a TTL, not pinned at import time.** The reference
read the secret once at module scope, so a rotated credential was only picked up
by forcing a cold start (the documented workaround was to poke the function's
description to trigger one). Caching with an expiry means rotation converges on
its own within ``PRTG_CREDENTIAL_TTL_SECONDS``, and a credential revoked mid-life
stops working without an operator having to remember a trick.

**TLS certificates are verified.** The reference passed
``cert_reqs="CERT_NONE"``, which the security review flagged, and which matters
more once traffic crosses a VPC peering or Transit Gateway boundary where the
path is longer and less trusted. PRTG very often runs a self-signed certificate,
so ``PRTG_CA_BUNDLE_SECRET_ARN`` exists to supply that certificate rather than
forcing the choice between "verify against a CA PRTG was never issued by" and
"verify nothing".

**Errors are scrubbed before they are logged or returned.** PRTG's classic API
authenticates with ``username`` and ``passhash`` query parameters, so the
credential is part of every request URL. urllib3 embeds that URL in its exception
messages. The reference returned ``f"Error: {e}"`` straight to the caller, which
means a single connection failure would have written the PRTG passhash into the
agent's context window and from there into the durable investigation record. See
``redact()``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any, Final

import urllib3
from urllib3.util import Retry

logger = logging.getLogger(__name__)


class _CredentialScrubbingFilter(logging.Filter):
    """Redact credentials from log records this package does not emit.

    PRTG authenticates with query parameters, so the credential is in every request
    URL, and urllib3 logs that URL at WARNING on each retry. Scrubbing what the
    handler returns does nothing about it, because the record never passes through
    this package.

    Verified in a deployed Lambda: a certificate failure produced a correctly
    redacted message for the agent while writing
    ``username=...&passhash=<value>`` into CloudWatch Logs on the same invocation.

    Attached to handlers rather than only to loggers on purpose. A filter on a
    logger runs only for records logged directly through it; records from a child
    such as ``urllib3.connectionpool`` propagate to ancestor *handlers* without
    consulting ancestor *filters*. Handler-level attachment therefore covers every
    record that can reach CloudWatch.
    """

    def __init__(self) -> None:
        super().__init__()
        self._secrets: tuple[str, ...] = ()

    def add_secrets(self, secrets: tuple[str, ...]) -> None:
        """Register literal values to remove, in addition to pattern matching."""
        merged = set(self._secrets) | {s for s in secrets if s}
        self._secrets = tuple(merged)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken record must not break logging
            return True

        cleaned = redact(message, self._secrets)
        if cleaned != message:
            # Replace the rendered text and drop the arguments, since they are the
            # source of the unredacted values.
            record.msg = cleaned
            record.args = ()
        return True


#: One shared instance, so every install point registers the same secrets.
_SCRUBBER = _CredentialScrubbingFilter()

#: Loggers known to render request URLs, used when no handler exists yet.
_URL_LOGGING_SOURCES: Final[tuple[str, ...]] = (
    "urllib3",
    "urllib3.connectionpool",
    "urllib3.util.retry",
)


def install_log_scrubbing() -> None:
    """Attach credential scrubbing to the logging paths that reach CloudWatch.

    Idempotent, so it is safe to call from module import and from client
    construction. Both exist because the Lambda runtime installs its handler during
    initialisation, and a local caller may have none.
    """
    root = logging.getLogger()
    for handler in root.handlers:
        if _SCRUBBER not in handler.filters:
            handler.addFilter(_SCRUBBER)

    for name in _URL_LOGGING_SOURCES:
        source = logging.getLogger(name)
        if _SCRUBBER not in source.filters:
            source.addFilter(_SCRUBBER)


# --- Configuration ----------------------------------------------------------

DEFAULT_CREDENTIAL_TTL_SECONDS: Final[int] = 900
DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_READ_TIMEOUT_SECONDS: Final[float] = 20.0
DEFAULT_MAX_RETRIES: Final[int] = 2

#: Retry only on states that a later attempt could plausibly resolve. A 401 from
#: PRTG means the credential is wrong; retrying it just multiplies failed logins,
#: which on some PRTG configurations will lock the account out.
_RETRY_STATUSES: Final[tuple[int, ...]] = (429, 500, 502, 503, 504)

#: Human-readable sensor state to PRTG's numeric status codes. "paused" covers
#: four distinct codes because PRTG distinguishes paused-by-user from
#: paused-by-schedule, paused-by-dependency and paused-by-license, none of which
#: an investigating agent needs to tell apart.
STATUS_CODES: Final[dict[str, list[int]]] = {
    "up": [3],
    "down": [5],
    "warning": [4],
    "paused": [7, 8, 9, 12],
    "unknown": [1],
    "unusual": [10],
    "down_acknowledged": [13],
    "down_partial": [14],
}

#: Columns requested per table type. Named explicitly rather than requesting
#: everything: PRTG returns whatever is asked for, and every extra column is
#: tokens the agent pays to read.
TABLE_COLUMNS: Final[dict[str, str]] = {
    "sensors": (
        "objid,name,status,message,lastvalue,device,group,probe,priority,tags,"
        "type,active,downtimesince,lastcheck,parentid"
    ),
    "devices": (
        "objid,name,status,host,group,probe,upsens,downsens,warnsens,pausedsens,"
        "totalsens,location,tags,active"
    ),
    "groups": "objid,name,status,probe,upsens,downsens,warnsens,pausedsens,totalsens,active",
    "channels": "objid,name,lastvalue,minimum,maximum",
    "messages": "objid,datetime,parent,type,name,status,message",
}

#: Narrower column sets for search results, where the agent wants identification
#: rather than full detail.
SEARCH_COLUMNS: Final[dict[str, str]] = {
    "sensors": "objid,name,status,type,tags,device,group,lastvalue",
    "devices": "objid,name,status,host,group,tags",
    "groups": "objid,name,status,totalsens",
}

_REDACTION_PLACEHOLDER: Final[str] = "***REDACTED***"

#: Query parameters whose values must never reach a log or a response. Matches
#: both raw and percent-encoded forms, since the value may have been URL-encoded
#: by the time it appears inside an exception message.
_SENSITIVE_QUERY_PARAMS: Final[tuple[str, ...]] = (
    "passhash",
    "password",
    "username",
    "apitoken",
)

_SENSITIVE_PARAM_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(" + "|".join(_SENSITIVE_QUERY_PARAMS) + r")=([^&\s\"'<>]*)"
)


class PrtgError(Exception):
    """A PRTG request failed.

    Carries a caller-safe ``message`` that has already been scrubbed of
    credentials, so it is safe to surface to the agent.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


class PrtgAuthError(PrtgError):
    """PRTG rejected the credential. Not retryable."""


def redact(text: object, extra_secrets: tuple[str, ...] = ()) -> str:
    """Remove credentials from arbitrary text before it is logged or returned.

    Two passes, because either alone leaves a gap:

    1. Pattern-based, replacing the value of any sensitive query parameter. This
       catches the common case of a URL appearing inside an exception message,
       including URLs this code never constructed itself.
    2. Literal, replacing the known credential values wherever they appear. This
       catches a credential echoed back in a form the pattern would miss - for
       example a passhash reflected in a PRTG error body without its parameter
       name attached.

    Args:
        text: Any object; it is coerced with ``str()``.
        extra_secrets: Known literal secret values to remove. Short values (fewer
            than 4 characters) are skipped, because replacing every occurrence of
            a 1- or 2-character string would corrupt the message without
            protecting anything meaningful.

    Returns:
        The scrubbed string.
    """
    result = _SENSITIVE_PARAM_RE.sub(rf"\1={_REDACTION_PLACEHOLDER}", str(text))
    for secret in extra_secrets:
        if secret and len(str(secret)) >= 4:
            result = result.replace(str(secret), _REDACTION_PLACEHOLDER)
    return result


class _CachedCredentials:
    """PRTG credentials plus the wall-clock time at which they go stale.

    Either an API key or a username and passhash. Both authenticate as a PRTG user
    and are subject to that user's object rights; the difference is that a key can be
    deleted on its own, whereas revoking a passhash means changing the account
    password and breaking every other consumer of it.
    """

    __slots__ = ("url", "username", "passhash", "api_key", "expires_at")

    def __init__(
        self,
        url: str,
        expires_at: float,
        username: str = "",
        passhash: str = "",
        api_key: str = "",
    ) -> None:
        self.url = url
        self.username = username
        self.passhash = passhash
        self.api_key = api_key
        self.expires_at = expires_at

    def is_fresh(self, now: float) -> bool:
        return now < self.expires_at

    @property
    def uses_api_key(self) -> bool:
        return bool(self.api_key)

    def auth_params(self) -> list[tuple[str, str]]:
        """Authentication parameters for a request.

        PRTG 26.2 rejects every ``Authorization`` header form, including the
        ``Bearer`` scheme its own manual documents, so the key travels as a query
        parameter exactly as a passhash does. Verified against 26.2.116.1542: header
        auth returns 401 "Unsupported authorization scheme."
        """
        if self.api_key:
            return [("apitoken", self.api_key)]
        return [("username", self.username), ("passhash", self.passhash)]

    def secret_values(self) -> tuple[str, ...]:
        """Literal values that must be scrubbed from any outgoing text."""
        return tuple(v for v in (self.passhash, self.api_key, self.username) if v)


class PrtgClient:
    """Read-only client for the PRTG API.

    Construction performs no I/O. Credentials and the TLS trust store are
    resolved on first use and refreshed on expiry, so an unreachable Secrets
    Manager surfaces as a normal tool error with a usable message rather than as
    a Lambda ``Runtime.InitializationError``, which reports no useful detail and
    is a documented source of confusion for this integration.
    """

    def __init__(
        self,
        *,
        secret_arn: str | None = None,
        verify_tls: bool | None = None,
        ca_bundle_secret_arn: str | None = None,
        credential_ttl_seconds: int | None = None,
        connect_timeout: float | None = None,
        read_timeout: float | None = None,
        max_retries: int | None = None,
        secrets_client: Any = None,
    ) -> None:
        self._secret_arn = secret_arn if secret_arn is not None else os.environ.get("PRTG_SECRET_ARN")
        self._ca_bundle_secret_arn = (
            ca_bundle_secret_arn
            if ca_bundle_secret_arn is not None
            else os.environ.get("PRTG_CA_BUNDLE_SECRET_ARN") or None
        )
        self._verify_tls = _env_bool("PRTG_VERIFY_TLS", True) if verify_tls is None else verify_tls
        self._credential_ttl = (
            credential_ttl_seconds
            if credential_ttl_seconds is not None
            else _env_int("PRTG_CREDENTIAL_TTL_SECONDS", DEFAULT_CREDENTIAL_TTL_SECONDS)
        )
        self._connect_timeout = (
            connect_timeout
            if connect_timeout is not None
            else _env_float("PRTG_CONNECT_TIMEOUT_SECONDS", DEFAULT_CONNECT_TIMEOUT_SECONDS)
        )
        self._read_timeout = (
            read_timeout
            if read_timeout is not None
            else _env_float("PRTG_READ_TIMEOUT_SECONDS", DEFAULT_READ_TIMEOUT_SECONDS)
        )
        self._max_retries = (
            max_retries if max_retries is not None else _env_int("PRTG_MAX_RETRIES", DEFAULT_MAX_RETRIES)
        )

        self._secrets_client = secrets_client
        self._credentials: _CachedCredentials | None = None
        self._pool: urllib3.PoolManager | None = None
        self._ca_bundle_path: str | None = None

        # Before any request is made, so a failure on the very first call cannot log
        # the credential. Pattern matching alone already covers a URL, so this is
        # effective even though no literal values are registered yet.
        install_log_scrubbing()

        # Set but unused is still exposed: it is readable by anyone who can read the
        # function configuration, whether or not this code consults it.
        # Both credential forms, not just the passhash. An API key is revocable, which
        # makes it less bad to leak but not acceptable to leave here -- it is still a
        # live credential until somebody notices, and it is now the form an operator
        # following the recommended path is most likely to have to hand.
        leaked = sorted(
            name for name in ("PRTG_PASSHASH", "PRTG_API_KEY") if _in_lambda() and os.environ.get(name)
        )
        if leaked:
            logger.warning(
                json.dumps(
                    {
                        "event": "credential_in_function_environment",
                        "variables": leaked,
                        "message": (
                            f"{' and '.join(leaked)} set in this function's environment. Secrets "
                            "Manager takes precedence so it is not used, but it remains "
                            "readable to anyone holding lambda:GetFunctionConfiguration and "
                            "is visible in the console. Remove it from the function "
                            "configuration."
                        ),
                    }
                )
            )

        if not self._verify_tls:
            # Deliberately noisy. An operator who disabled verification during a
            # proof of concept should not be able to forget it is off, so this is
            # logged on construction and again on every request rather than once
            # at deploy time where it would scroll away.
            logger.warning(
                json.dumps(
                    {
                        "event": "tls_verification_disabled",
                        "message": (
                            "PRTG TLS certificate verification is DISABLED. Traffic to PRTG is "
                            "vulnerable to interception, which would expose the PRTG credential. "
                            "Set PRTG_VERIFY_TLS=true and supply PRTG_CA_BUNDLE_SECRET_ARN if PRTG "
                            "uses a self-signed certificate."
                        ),
                    }
                )
            )

    # --- Credential handling ------------------------------------------------

    def _boto_secrets_client(self) -> Any:
        if self._secrets_client is None:
            import boto3  # Imported lazily: keeps unit tests free of boto3/network.

            self._secrets_client = boto3.client("secretsmanager")
        return self._secrets_client

    def _load_credentials(self) -> _CachedCredentials:
        """Fetch PRTG credentials, honouring the TTL cache."""
        now = time.time()
        if self._credentials is not None and self._credentials.is_fresh(now):
            return self._credentials

        raw = self._read_credential_source()

        api_key = str(raw.get("prtg_api_key") or "").strip()
        username = str(raw.get("prtg_username") or "").strip()
        passhash = str(raw.get("prtg_passhash") or "").strip()

        # Either form is accepted, and an API key wins when both are present. Keys are
        # preferred because deleting one revokes this integration alone, whereas
        # revoking a passhash means changing the account password and breaking every
        # other consumer of it. Both resolve to a PRTG user and inherit that user's
        # object rights, so neither is more privileged by virtue of its type.
        if not raw.get("prtg_url"):
            raise PrtgError(
                "PRTG credentials are incomplete: missing prtg_url. The secret must be a "
                "JSON object with prtg_url plus either prtg_api_key, or prtg_username and "
                "prtg_passhash."
            )

        if not api_key and not (username and passhash):
            absent = []
            if not username:
                absent.append("prtg_username")
            if not passhash:
                absent.append("prtg_passhash")
            raise PrtgError(
                "PRTG credentials are incomplete: no prtg_api_key, and "
                + ", ".join(absent)
                + " missing. Supply either prtg_api_key, which is preferred because it can "
                "be revoked without changing the account password, or prtg_username with "
                "prtg_passhash."
            )

        url = str(raw["prtg_url"]).rstrip("/")
        if not url.startswith("https://"):
            # Refused rather than warned. The credential is a query parameter, so
            # plain HTTP puts it on the wire in cleartext on every single call.
            raise PrtgError(
                "prtg_url must use https://. PRTG's API sends the credential as a query "
                "parameter, so an http:// endpoint would transmit it in cleartext."
            )

        self._credentials = _CachedCredentials(
            url=url,
            username=username,
            passhash=passhash,
            api_key=api_key,
            expires_at=now + self._credential_ttl,
        )
        # Now that the literal values are known, add them to the log scrubber so a
        # credential echoed back in a form the pattern would miss is also removed.
        _SCRUBBER.add_secrets(self._credentials.secret_values())
        logger.info(
            json.dumps(
                {
                    "event": "credentials_loaded",
                    "ttl_seconds": self._credential_ttl,
                    "source": "secrets_manager" if self._secret_arn else "environment",
                    # Recorded so an operator can tell which credential is in use
                    # without reading the secret. Names the mechanism, never a value.
                    "auth": "api_key" if self._credentials.uses_api_key else "passhash",
                }
            )
        )
        return self._credentials

    def _read_credential_source(self) -> dict[str, Any]:
        """Read the raw credential document from Secrets Manager or the environment."""
        if self._secret_arn:
            try:
                response = self._boto_secrets_client().get_secret_value(SecretId=self._secret_arn)
            except Exception as exc:  # noqa: BLE001 - re-raised as a scrubbed PrtgError
                raise PrtgError(
                    "Could not read the PRTG credential from Secrets Manager. Check the Lambda "
                    "execution role grants secretsmanager:GetSecretValue on this secret, that the "
                    "secret's resource policy and KMS key policy allow this role if it lives in "
                    "another account, and that a VPC endpoint for Secrets Manager exists if the "
                    f"function has no outbound internet route. Underlying error: {redact(exc)}"
                ) from exc
            try:
                parsed = json.loads(response["SecretString"])
            except (KeyError, json.JSONDecodeError) as exc:
                raise PrtgError(
                    "The PRTG secret is not valid JSON. Expected an object with prtg_url plus "
                    "either prtg_api_key, or prtg_username and prtg_passhash."
                ) from exc
            if not isinstance(parsed, dict):
                raise PrtgError("The PRTG secret must be a JSON object, not a bare value or array.")
            return parsed

        # The environment fallback is for local development and the integration
        # tests. It is refused when running in Lambda, because a passhash in a
        # function's environment is readable by anyone holding
        # lambda:GetFunctionConfiguration, is shown in the console, and is committed
        # into the template if it was set through infrastructure code. The reference
        # implementation this sample derives from offered exactly this fallback with
        # no such guard.
        #
        # A comment saying "local development only" was already here and did not stop
        # anything, so the rule is enforced rather than described.
        if _in_lambda():
            raise PrtgError(
                "PRTG_SECRET_ARN is not set. In Lambda the credential must come from "
                "Secrets Manager: PRTG's passhash does not expire and cannot be revoked "
                "without changing the user's password, so it must not sit in the function's "
                "environment where it is visible to anyone who can read the function "
                "configuration. Set PRTG_SECRET_ARN to a secret holding "
                '{"prtg_url": ..., "prtg_api_key": ...}, or {"prtg_url": ..., '
                '"prtg_username": ..., "prtg_passhash": ...}. The CDK stacks wire this '
                "automatically."
            )

        return {
            "prtg_url": os.environ.get("PRTG_URL", ""),
            "prtg_username": os.environ.get("PRTG_USERNAME", ""),
            "prtg_passhash": os.environ.get("PRTG_PASSHASH", ""),
            "prtg_api_key": os.environ.get("PRTG_API_KEY", ""),
        }

    # --- Connection pool ----------------------------------------------------

    def _ca_bundle(self) -> str | None:
        """Materialise the custom CA bundle on local disk, if one is configured.

        urllib3 needs a filesystem path, so the PEM is written to ``/tmp`` - the
        only writable location in a Lambda execution environment. It persists for
        the life of the environment and is reused across invocations.
        """
        if not self._ca_bundle_secret_arn:
            return None
        if self._ca_bundle_path and os.path.exists(self._ca_bundle_path):
            return self._ca_bundle_path

        try:
            response = self._boto_secrets_client().get_secret_value(SecretId=self._ca_bundle_secret_arn)
            pem = response["SecretString"]
        except Exception as exc:  # noqa: BLE001
            raise PrtgError(
                "Could not read the PRTG CA bundle from Secrets Manager. Check the execution "
                f"role's access to it. Underlying error: {redact(exc)}"
            ) from exc

        if "BEGIN CERTIFICATE" not in pem:
            raise PrtgError(
                "The configured CA bundle secret does not contain a PEM certificate. It should "
                "hold the PRTG server's certificate (or its issuing CA) in PEM form, beginning "
                "with '-----BEGIN CERTIFICATE-----'."
            )

        path = "/tmp/prtg-ca-bundle.pem"  # noqa: S108 - the only writable path in Lambda
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(pem)
        self._ca_bundle_path = path
        logger.info(json.dumps({"event": "ca_bundle_loaded", "path": path}))
        return path

    def _http(self) -> urllib3.PoolManager:
        """Return the shared connection pool, creating it on first use.

        Reused across invocations in a warm execution environment, which avoids
        repeating the TLS handshake on every tool call.
        """
        if self._pool is not None:
            return self._pool

        retries = Retry(
            total=self._max_retries,
            connect=self._max_retries,
            read=self._max_retries,
            status=self._max_retries,
            backoff_factor=0.5,
            status_forcelist=list(_RETRY_STATUSES),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )

        if self._verify_tls:
            self._pool = urllib3.PoolManager(
                cert_reqs="CERT_REQUIRED",
                ca_certs=self._ca_bundle(),
                retries=retries,
            )
        else:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._pool = urllib3.PoolManager(cert_reqs="CERT_NONE", retries=retries)

        return self._pool

    # --- Requests -----------------------------------------------------------

    def request(
        self,
        endpoint: str,
        params: dict[str, Any] | Sequence[tuple[str, Any]] | None = None,
    ) -> Any:
        """Issue an authenticated GET against a PRTG API endpoint.

        Args:
            endpoint: Path beginning with ``/``, for example ``/api/table.json``.
            params: Query parameters. ``None`` values are dropped. Accepts a sequence
                of pairs as well as a mapping, because some PRTG filters take the same
                key more than once and a mapping cannot express that.

        Returns:
            Parsed JSON when PRTG returns JSON, otherwise the response body as text.

        Raises:
            PrtgAuthError: PRTG rejected the credential.
            PrtgError: any other failure. The message is safe to surface.
        """
        credentials = self._load_credentials()
        secrets = credentials.secret_values()

        if not self._verify_tls:
            logger.warning(json.dumps({"event": "insecure_request", "endpoint": endpoint}))

        # A list of pairs, not a mapping: PRTG expresses a multi-valued filter by
        # repeating the key, so the query string has to be able to carry duplicates.
        pairs = params.items() if isinstance(params, Mapping) else (params or ())
        query: list[tuple[str, Any]] = [(k, v) for k, v in pairs if v is not None]
        query.extend(credentials.auth_params())

        url = f"{credentials.url}{endpoint}"

        try:
            response = self._http().request(
                "GET",
                url,
                fields=query,
                timeout=urllib3.Timeout(connect=self._connect_timeout, read=self._read_timeout),
            )
        except urllib3.exceptions.MaxRetryError as exc:
            # The exception message contains the full request URL, and therefore
            # the credential. Never let it through unscrubbed.
            #
            # urllib3 wraps the underlying cause once retries are exhausted, so a
            # certificate failure arrives here rather than at the SSLError handler
            # below. Unwrapped explicitly, because the two remedies have nothing to do
            # with each other: sending someone to check security groups and routes when
            # the certificate is the problem costs them the afternoon the message was
            # meant to save. Observed against a real deployment, where a self-signed
            # PRTG certificate was reported as unreachable.
            if isinstance(exc.reason, urllib3.exceptions.SSLError):
                raise PrtgError(self._tls_failure_message(credentials.url, exc, secrets)) from exc

            raise PrtgError(
                f"Could not reach PRTG at {_safe_host(credentials.url)} after "
                f"{self._max_retries + 1} attempts. Check that PRTG is listening on HTTPS, that "
                "the Lambda security group allows outbound 443 to it, and that a route to the "
                f"PRTG network exists. Underlying error: {redact(exc, secrets)}"
            ) from exc
        except urllib3.exceptions.SSLError as exc:
            raise PrtgError(self._tls_failure_message(credentials.url, exc, secrets)) from exc
        except Exception as exc:  # noqa: BLE001
            raise PrtgError(f"PRTG request to {endpoint} failed: {redact(exc, secrets)}") from exc

        return self._parse(response, endpoint=endpoint, secrets=secrets, host=_safe_host(credentials.url))

    def _tls_failure_message(self, url: str, exc: Exception, secrets: tuple[str, ...]) -> str:
        """Explain a certificate failure and name the setting that resolves it.

        Shared by both paths that can raise it, so the advice cannot drift between the
        wrapped and unwrapped forms of the same failure.
        """
        remedy = (
            "Supply that certificate via PRTG_CA_BUNDLE_SECRET_ARN so it can be verified."
            if not self._ca_bundle_secret_arn
            else (
                "A CA bundle is configured, so the certificate PRTG presents is not the one it "
                "signs for. A common cause is PRTG still serving its shipped default certificate, "
                "whose subject is 'PRTG Demo Certificate' with a single alternative name of "
                "'localhost'. Another is reaching PRTG by an address the certificate does not "
                "name. Replace PRTG's certificate with one covering the host in prtg_url."
            )
        )
        return (
            f"TLS verification failed for PRTG at {_safe_host(url)}. {remedy} "
            "Setting PRTG_VERIFY_TLS=false is possible but leaves the credential, which PRTG "
            f"carries in the query string, open to interception. Underlying error: "
            f"{redact(exc, secrets)}"
        )

    def _parse(self, response: Any, *, endpoint: str, secrets: tuple[str, ...], host: str) -> Any:
        """Validate the HTTP status and decode the body."""
        status = response.status

        if status in (401, 403):
            raise PrtgAuthError(
                "PRTG rejected the credential (HTTP "
                f"{status}). Confirm the credential in the secret is current and that the PRTG "
                "user is enabled and permitted to use the API. For an API key, check it still "
                "exists under Setup, Account Settings, API Keys -- a key is shown only once at "
                "creation and cannot be recovered, so a lost one must be replaced. For a "
                "passhash, regenerate it at /api/getpasshash.htm.",
                status=status,
            )
        if status == 404:
            raise PrtgError(
                f"PRTG returned HTTP 404 for {endpoint}. The object ID may not exist, or this PRTG "
                "version may not expose that endpoint.",
                status=status,
            )
        if status >= 400:
            body = redact(_decode(response)[:500], secrets)
            raise PrtgError(f"PRTG returned HTTP {status} for {endpoint}: {body}", status=status)

        body = _decode(response)
        content_type = (response.headers.get("content-type") or "").lower()

        if "json" in content_type or endpoint.endswith(".json"):
            try:
                return json.loads(body)
            except json.JSONDecodeError as exc:
                # Usually PRTG serving an HTML error or login page with a 200.
                raise PrtgError(
                    f"PRTG returned a non-JSON body from {endpoint} at {host}. This often means the "
                    "request was redirected to a login page, which points at an authentication "
                    f"problem rather than a malformed request. First 200 characters: "
                    f"{redact(body[:200], secrets)}"
                ) from exc

        # PRTG does not always label a JSON body as JSON. /api/getstatus.htm answers
        # with Content-Type: text/html and a JSON object, verified on 26.2.116.1542.
        # Returning that as text made the handler encode a string of JSON, so the tool
        # result arrived double-encoded and the agent had to parse twice to reach any
        # field -- while every other tool returned an object.
        #
        # Sniffed rather than special-cased by endpoint, because the mislabelling is a
        # property of PRTG's responses and not of one path. Parse failure falls back to
        # text, so a genuinely non-JSON body is still returned unchanged.
        stripped = body.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return body

        return body

    # --- Table helper -------------------------------------------------------

    def table(
        self,
        content: str,
        *,
        count: int,
        object_id: int | None = None,
        status_filter: list[int] | None = None,
        tags: str | None = None,
        name_filter: str | None = None,
        date_range: str | None = None,
        sort_by: str | None = None,
        no_raw: bool = False,
        columns: str | None = None,
    ) -> Any:
        """Query PRTG's ``/api/table.json`` endpoint.

        Args:
            content: Table type - one of the keys of ``TABLE_COLUMNS``.
            count: Row limit, clamped to ``tools.MAX_COUNT``.
            object_id: Restrict to this object and its descendants.
            status_filter: PRTG numeric status codes to include.
            tags: Comma-separated tag filter.
            name_filter: Substring match on the object name.
            date_range: Relative window, for the messages table.
            sort_by: PRTG sort expression, e.g. ``-datetime`` for newest first.
            no_raw: Omit PRTG's ``*_raw`` companion fields.
            columns: Override the default column set for ``content``.
        """
        from .tools import MAX_COUNT  # Local import avoids a circular dependency.

        params: dict[str, Any] = {
            "content": content,
            "columns": columns or TABLE_COLUMNS.get(content, TABLE_COLUMNS["sensors"]),
            "count": max(1, min(int(count), MAX_COUNT)),
        }
        if object_id is not None:
            params["id"] = int(object_id)
        if tags:
            params["filter_tags"] = tags
        if name_filter:
            # @sub(...) is PRTG's substring-match filter syntax.
            params["filter_name"] = f"@sub({name_filter})"
        if date_range:
            params["filter_drel"] = date_range
        if sort_by:
            params["sortby"] = sort_by
        if no_raw:
            params["noraw"] = 1
        pairs: list[tuple[str, Any]] = list(params.items())

        if status_filter:
            # One repeated key per code, combined by PRTG as OR:
            #     filter_status=3&filter_status=4
            #
            # Not indexed keys. An earlier version sent filter_status[0]=3, which
            # PRTG accepts with HTTP 200 and a treesize of 0 -- so every status
            # query came back empty and the agent concluded nothing was wrong.
            # Verified against PRTG 26.2.116.1542: indexed 0 rows, repeated 4 rows.
            pairs.extend(("filter_status", code) for code in status_filter)

        return self.request("/api/table.json", pairs)


# --- Helpers ----------------------------------------------------------------


def _decode(response: Any) -> str:
    try:
        return response.data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _safe_host(url: str) -> str:
    """Return the host portion of a URL, discarding any credentials in it."""
    without_scheme = re.sub(r"^https?://", "", url)
    return without_scheme.split("/")[0].split("@")[-1]


def _in_lambda() -> bool:
    """Whether this is executing inside the Lambda runtime.

    ``AWS_LAMBDA_FUNCTION_NAME`` is set by the runtime and by nothing else, so it
    distinguishes a deployed function from a developer's machine. Deliberately not
    inferred from the absence of a secret ARN, since that absence is the condition
    being guarded against.
    """
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default
