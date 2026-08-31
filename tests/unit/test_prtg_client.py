"""PrtgClient behaviour: credential handling, TLS, and credential redaction."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
import urllib3

from prtg_mcp.prtg_client import (
    PrtgAuthError,
    PrtgClient,
    PrtgError,
    install_log_scrubbing,
    redact,
)
from tests.unit.conftest import (
    FAKE_PASSHASH,
    FAKE_URL,
    FAKE_USERNAME,
    FakePool,
    FakeResponse,
    FakeSecretsClient,
)

# --- Redaction --------------------------------------------------------------
#
# These are the highest-value tests in the suite. PRTG authenticates with the
# credential in the query string, urllib3 puts the request URL into its exception
# messages, and this handler's return value is placed directly into the agent's
# context and persisted in the investigation record. A regression here writes the
# PRTG passhash somewhere durable and human-readable.


class TestRedaction:
    def test_removes_passhash_from_a_query_string(self) -> None:
        text = f"Max retries exceeded with url: /api/table.json?count=100&username={FAKE_USERNAME}&passhash={FAKE_PASSHASH}"
        result = redact(text)
        assert FAKE_PASSHASH not in result
        assert FAKE_USERNAME not in result
        assert "passhash=***REDACTED***" in result

    def test_removes_password_and_apitoken_parameters(self) -> None:
        result = redact("?password=hunter2xyz&apitoken=abcd1234efgh")
        assert "hunter2xyz" not in result
        assert "abcd1234efgh" not in result

    def test_is_case_insensitive_on_the_parameter_name(self) -> None:
        assert FAKE_PASSHASH not in redact(f"PassHash={FAKE_PASSHASH}")

    def test_removes_literal_secret_values_without_a_parameter_name(self) -> None:
        """Covers a credential echoed back by PRTG without its parameter name."""
        text = f"PRTG said: login failed for hash {FAKE_PASSHASH}"
        assert FAKE_PASSHASH not in redact(text, (FAKE_PASSHASH,))

    def test_ignores_very_short_secrets(self) -> None:
        """Replacing a 2-character value everywhere would mangle the message."""
        assert redact("status is up and running", ("up",)) == "status is up and running"

    def test_accepts_non_string_input(self) -> None:
        assert redact(ValueError("boom")) == "boom"
        assert redact(None) == "None"


# --- Credential handling ----------------------------------------------------


class TestCredentials:
    def test_construction_performs_no_io(self, secrets_client: FakeSecretsClient) -> None:
        """Deferring I/O keeps a bad secret from becoming an opaque init error."""
        PrtgClient(secret_arn="prtg-secret", secrets_client=secrets_client)
        assert secrets_client.call_count == 0

    def test_credential_is_cached_between_requests(self, client: PrtgClient, secrets_client) -> None:
        client._pool = FakePool([FakeResponse(200, {"sensors": []}), FakeResponse(200, {"sensors": []})])
        client.request("/api/table.json")
        client.request("/api/table.json")
        assert secrets_client.call_count == 1

    def test_credential_is_refetched_after_the_ttl_expires(self, secrets_client: FakeSecretsClient) -> None:
        """Rotation converges on its own; no forced cold start required."""
        client = PrtgClient(
            secret_arn="prtg-secret",
            verify_tls=True,
            secrets_client=secrets_client,
            credential_ttl_seconds=0,  # expire immediately
        )
        client._pool = FakePool([FakeResponse(200, {}), FakeResponse(200, {})])
        client.request("/api/table.json")
        client.request("/api/table.json")
        assert secrets_client.call_count == 2

    def test_rejects_a_plain_http_url(self) -> None:
        secrets = FakeSecretsClient(
            {
                "s": json.dumps(
                    {
                        "prtg_url": "http://prtg.example.internal",
                        "prtg_username": "u",
                        "prtg_passhash": "hash1234",
                    }
                )
            }
        )
        client = PrtgClient(secret_arn="s", secrets_client=secrets)
        with pytest.raises(PrtgError, match="must use https"):
            client.request("/api/table.json")

    def test_reports_which_credential_keys_are_missing(self) -> None:
        secrets = FakeSecretsClient({"s": json.dumps({"prtg_url": "https://x.example"})})
        client = PrtgClient(secret_arn="s", secrets_client=secrets)
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")
        assert "prtg_username" in str(exc.value)
        assert "prtg_passhash" in str(exc.value)

    def test_reports_a_non_json_secret_clearly(self) -> None:
        secrets = FakeSecretsClient({"s": "not-json-at-all"})
        client = PrtgClient(secret_arn="s", secrets_client=secrets)
        with pytest.raises(PrtgError, match="not valid JSON"):
            client.request("/api/table.json")

    def test_secrets_manager_failure_mentions_the_likely_causes(self) -> None:
        secrets = FakeSecretsClient(fail_with=RuntimeError("AccessDeniedException"))
        client = PrtgClient(secret_arn="s", secrets_client=secrets)
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")
        message = str(exc.value)
        assert "secretsmanager:GetSecretValue" in message
        assert "VPC endpoint" in message  # the classic fully-private failure


# --- Transport --------------------------------------------------------------


class TestTransport:
    def test_credential_is_attached_to_every_request(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.request("/api/table.json", {"content": "sensors"})
        fields = client._pool.last_fields
        assert fields["username"] == FAKE_USERNAME
        assert fields["passhash"] == FAKE_PASSHASH
        assert fields["content"] == "sensors"

    def test_none_valued_parameters_are_dropped(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.request("/api/table.json", {"content": "sensors", "filter_tags": None})
        assert "filter_tags" not in client._pool.last_fields


class TestApiKeyAuthentication:
    """Either an API key or a username and passhash, with the key preferred.

    Both authenticate as a PRTG user and inherit that user's object rights, so
    neither is more privileged by virtue of its type. Verified against a live PRTG
    26.2.116.1542: a key created under the administrator returned 13 sensors while a
    passhash for a read-only user returned 4, because visibility follows the account
    rather than the credential form. Create the key as the read-only user.

    The reason to prefer a key is revocation. Deleting one revokes this integration
    alone; revoking a passhash means changing the account password, which breaks every
    other consumer of that account.

    Note what the key does *not* buy on this version. PRTG rejects every
    ``Authorization`` header form, including the ``Bearer`` scheme its own manual
    documents, returning 401 "Unsupported authorization scheme." The key therefore
    travels as a query parameter exactly as a passhash does, so it is equally exposed
    to logging and equally dependent on the scrubber.
    """

    @staticmethod
    def _secret(**fields: str) -> str:
        return json.dumps({"prtg_url": FAKE_URL, **fields})

    def _client(self, secret_body: str) -> PrtgClient:
        secrets = FakeSecretsClient({"prtg-secret": secret_body})
        client = PrtgClient(secret_arn="prtg-secret", verify_tls=True, secrets_client=secrets)
        client._pool = FakePool([FakeResponse(200, {})])
        return client

    def test_an_api_key_is_sent_as_apitoken(self) -> None:
        client = self._client(self._secret(prtg_api_key="KEY123456"))
        client.request("/api/table.json")

        sent = dict(client._pool.last_pairs)
        assert sent["apitoken"] == "KEY123456"
        assert "passhash" not in sent, "the passhash form must not be sent alongside a key"
        assert "username" not in sent

    def test_a_passhash_is_still_supported(self) -> None:
        client = self._client(self._secret(prtg_username="reader", prtg_passhash="1234567890"))
        client.request("/api/table.json")

        sent = dict(client._pool.last_pairs)
        assert sent["username"] == "reader"
        assert sent["passhash"] == "1234567890"
        assert "apitoken" not in sent

    def test_the_key_wins_when_both_are_present(self) -> None:
        """Preferring the key means an operator can migrate by adding one field."""
        client = self._client(
            self._secret(prtg_api_key="KEY123456", prtg_username="reader", prtg_passhash="1234567890")
        )
        client.request("/api/table.json")

        sent = dict(client._pool.last_pairs)
        assert sent["apitoken"] == "KEY123456"
        assert "passhash" not in sent

    def test_neither_form_present_is_refused_with_both_options_named(self) -> None:
        client = self._client(self._secret())
        with pytest.raises(PrtgError) as exc:
            client._load_credentials()

        message = str(exc.value)
        assert "prtg_api_key" in message
        assert "prtg_passhash" in message
        assert "revoked without changing the account password" in message

    def test_a_username_without_a_passhash_is_refused(self) -> None:
        """Half a passhash credential is not a credential."""
        client = self._client(self._secret(prtg_username="reader"))
        with pytest.raises(PrtgError, match="prtg_passhash"):
            client._load_credentials()

    def test_a_missing_url_is_reported_on_its_own(self) -> None:
        secrets = FakeSecretsClient({"prtg-secret": json.dumps({"prtg_api_key": "KEY123456"})})
        client = PrtgClient(secret_arn="prtg-secret", verify_tls=True, secrets_client=secrets)
        with pytest.raises(PrtgError, match="missing prtg_url"):
            client._load_credentials()

    def test_whitespace_only_values_do_not_count_as_supplied(self) -> None:
        """A field an operator has 'filled in' with a space is still empty."""
        client = self._client(self._secret(prtg_api_key="   "))
        with pytest.raises(PrtgError, match="no prtg_api_key"):
            client._load_credentials()

    def test_the_key_is_scrubbed_from_errors(self) -> None:
        """apitoken is in the sensitive-parameter list, and must stay there."""
        leaky = urllib3.exceptions.MaxRetryError(
            pool=None,  # type: ignore[arg-type]
            url="/api/table.json?apitoken=KEY123456",
            reason=urllib3.exceptions.NewConnectionError(None, "refused"),  # type: ignore[arg-type]
        )
        client = self._client(self._secret(prtg_api_key="KEY123456"))
        client._pool = FakePool(raises=leaky)

        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")
        assert "KEY123456" not in str(exc.value)

    def test_the_key_is_registered_with_the_log_scrubber(self) -> None:
        """urllib3 logs the URL on retry, so the key must be scrubbed there too."""
        client = self._client(self._secret(prtg_api_key="KEY123456"))
        client.request("/api/table.json")
        assert "KEY123456" in client._load_credentials().secret_values()

    def test_the_auth_mechanism_is_logged_but_never_the_value(self, caplog) -> None:
        client = self._client(self._secret(prtg_api_key="KEY123456"))
        with caplog.at_level(logging.INFO):
            client.request("/api/table.json")

        assert '"auth": "api_key"' in caplog.text
        assert "KEY123456" not in caplog.text

    def test_the_environment_fallback_accepts_a_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRTG_URL", FAKE_URL)
        monkeypatch.setenv("PRTG_API_KEY", "KEY123456")

        client = PrtgClient(secret_arn=None, verify_tls=True)
        client._pool = FakePool([FakeResponse(200, {})])
        client.request("/api/table.json")
        assert dict(client._pool.last_pairs)["apitoken"] == "KEY123456"


class TestTheCredentialMustComeFromSecretsManagerInLambda:
    """The environment fallback is refused in a deployed function.

    PRTG's passhash does not expire and cannot be revoked without changing the user's
    password, so where it is stored matters more than for a short-lived token. In a
    function's environment it is readable by anyone holding
    ``lambda:GetFunctionConfiguration``, shown in the console, and committed into the
    template when set through infrastructure code.

    The reference implementation this sample derives from offered exactly this
    fallback with no guard. A comment reading "local development only" was present
    here too and prevented nothing, which is why this is enforced instead.
    """

    def test_lambda_without_a_secret_arn_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "prtg-mcp-mcp-tools")
        monkeypatch.setenv("PRTG_URL", "https://prtg.example.internal")
        monkeypatch.setenv("PRTG_USERNAME", "reader")
        monkeypatch.setenv("PRTG_PASSHASH", "1234567890")

        client = PrtgClient(secret_arn=None, verify_tls=False)
        with pytest.raises(PrtgError, match="PRTG_SECRET_ARN is not set"):
            client._load_credentials()

    def test_the_refusal_explains_why_and_what_to_do(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "prtg-mcp-mcp-tools")
        client = PrtgClient(secret_arn=None, verify_tls=False)

        with pytest.raises(PrtgError) as exc:
            client._load_credentials()

        message = str(exc.value)
        assert "Secrets Manager" in message
        assert "cannot be revoked" in message, "should say why this matters, not just refuse"
        assert "prtg_passhash" in message, "should state the expected secret shape"

    def test_the_fallback_still_works_outside_lambda(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Local development and the integration tests depend on this path."""
        monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
        monkeypatch.setenv("PRTG_URL", "https://prtg.example.internal")
        monkeypatch.setenv("PRTG_USERNAME", "reader")
        monkeypatch.setenv("PRTG_PASSHASH", "1234567890")

        client = PrtgClient(secret_arn=None, verify_tls=False)
        credentials = client._load_credentials()
        assert credentials.username == "reader"
        assert credentials.url == "https://prtg.example.internal"

    def test_a_secret_arn_in_lambda_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, secrets_client: FakeSecretsClient
    ) -> None:
        """The guard must not block the supported path."""
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "prtg-mcp-mcp-tools")
        client = PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)
        assert client._load_credentials().username == FAKE_USERNAME

    def test_a_passhash_left_in_the_environment_is_flagged(
        self, monkeypatch: pytest.MonkeyPatch, secrets_client: FakeSecretsClient, caplog
    ) -> None:
        """Set but unused is still exposed, so it is worth saying so."""
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "prtg-mcp-mcp-tools")
        monkeypatch.setenv("PRTG_PASSHASH", "1234567890")

        with caplog.at_level(logging.WARNING):
            PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)

        assert "credential_in_function_environment" in caplog.text

    def test_an_api_key_left_in_the_environment_is_also_flagged(
        self, monkeypatch: pytest.MonkeyPatch, secrets_client: FakeSecretsClient, caplog
    ) -> None:
        """The warning originally covered only PRTG_PASSHASH.

        Being revocable makes a leaked key less costly to fix, not acceptable to leave
        in a place anyone with lambda:GetFunctionConfiguration can read. And since the
        key is now the recommended credential, it is the likelier of the two to be
        sitting there.
        """
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "prtg-mcp-mcp-tools")
        monkeypatch.delenv("PRTG_PASSHASH", raising=False)
        monkeypatch.setenv("PRTG_API_KEY", "KEY123456")

        with caplog.at_level(logging.WARNING):
            PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)

        assert "credential_in_function_environment" in caplog.text
        assert "PRTG_API_KEY" in caplog.text
        assert "KEY123456" not in caplog.text, "the warning must name the variable, never the value"

    def test_no_warning_when_the_environment_is_clean(
        self, monkeypatch: pytest.MonkeyPatch, secrets_client: FakeSecretsClient, caplog
    ) -> None:
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "prtg-mcp-mcp-tools")
        monkeypatch.delenv("PRTG_PASSHASH", raising=False)

        with caplog.at_level(logging.WARNING):
            PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)

        assert "credential_in_function_environment" not in caplog.text


class TestUrllib3LoggingDoesNotLeakTheCredential:
    """The credential must not reach CloudWatch via a logger outside this package.

    PRTG carries username and passhash in the query string, and urllib3 logs the
    request URL at WARNING on every retry. Scrubbing what the handler returns does
    nothing for those records, because they never pass through this package.

    Found in a deployed Lambda. A certificate failure returned a correctly redacted
    message to the agent while writing this to CloudWatch on the same invocation:

        [WARNING] Retrying (Retry(total=1, ...)) after connection broken by
        'SSLError(...)': /api/table.json?...&username=<user>&passhash=<the-real-passhash>

    The reproduction below logs through ``urllib3.connectionpool`` because that is
    where the real record originates, and because a filter on the parent
    ``urllib3`` logger would not see it -- ancestor filters are skipped during
    propagation, unlike ancestor handlers.
    """

    _URL = "/api/table.json?content=sensors&username={u}&passhash={p}"

    @pytest.fixture
    def captured(self, client: PrtgClient) -> logging.Handler:
        """A root handler carrying the scrubbing filter, as Lambda's handler does."""
        records: list[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = Capture()
        handler.records = records  # type: ignore[attr-defined]

        root = logging.getLogger()
        root.addHandler(handler)
        # Re-run installation so the filter attaches to the handler just added.
        install_log_scrubbing()
        try:
            yield handler
        finally:
            root.removeHandler(handler)

    def _load_credentials(self, client: PrtgClient) -> None:
        """Registers the literal values with the scrubber, as a real call would."""
        client._pool = FakePool([FakeResponse(200, {})])
        client.request("/api/table.json")

    def test_a_retry_warning_is_scrubbed(self, client: PrtgClient, captured: Any) -> None:
        self._load_credentials(client)
        url = self._URL.format(u=FAKE_USERNAME, p=FAKE_PASSHASH)

        logging.getLogger("urllib3.connectionpool").warning(
            "Retrying (Retry(total=1)) after connection broken by 'SSLError(...)': %s", url
        )

        emitted = " ".join(captured.records)
        assert FAKE_PASSHASH not in emitted, f"passhash reached the log: {emitted}"
        assert "***REDACTED***" in emitted

    def test_scrubbing_works_before_any_credential_is_loaded(self, client: PrtgClient, captured: Any) -> None:
        """A failure on the very first call must not leak either.

        No literal values are registered yet, so this exercises the pattern pass.
        """
        logging.getLogger("urllib3.connectionpool").warning(
            "Retrying: /api/table.json?username=someone&passhash=abcdef123456"
        )
        emitted = " ".join(captured.records)
        assert "abcdef123456" not in emitted

    def test_an_unrelated_message_is_left_alone(self, client: PrtgClient, captured: Any) -> None:
        """The filter must not mangle records that contain no credential."""
        logging.getLogger("urllib3.connectionpool").warning("Connection pool is full")
        assert "Connection pool is full" in " ".join(captured.records)

    def test_installation_is_idempotent(self, client: PrtgClient) -> None:
        """Called from both module import and client construction."""
        before = len(logging.getLogger("urllib3.connectionpool").filters)
        install_log_scrubbing()
        install_log_scrubbing()
        assert len(logging.getLogger("urllib3.connectionpool").filters) == before

    def test_an_unrenderable_record_passes_through_instead_of_raising(self, client: PrtgClient) -> None:
        """A filter that raises would break logging for the whole process.

        The filter is exercised directly with a record whose arguments do not match
        its format string, because routing one through a logger would fail in the
        handler rather than in the filter.
        """
        broken = logging.LogRecord(
            name="urllib3.connectionpool",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="two placeholders %s %s",
            args=("only-one",),
            exc_info=None,
        )

        scrubbing = next(
            f
            for f in logging.getLogger("urllib3.connectionpool").filters
            if f.__class__.__name__ == "_CredentialScrubbingFilter"
        )
        assert scrubbing.filter(broken) is True, "the record must still be emitted"


class TestTlsFailuresAreNotReportedAsConnectivityFailures:
    """A certificate problem must not be described as an unreachable host.

    urllib3 wraps the underlying cause in ``MaxRetryError`` once retries are exhausted,
    so a certificate failure never reaches the ``SSLError`` handler. Observed against a
    real deployment: a self-signed PRTG certificate produced "Could not reach PRTG ...
    check that the Lambda security group allows outbound 443 ... and that a route
    exists", which sends the operator to inspect networking that was working correctly.
    """

    @staticmethod
    def _wrapped_ssl_error() -> urllib3.exceptions.MaxRetryError:
        """What urllib3 actually raises for a bad certificate after retries."""
        return urllib3.exceptions.MaxRetryError(
            pool=None,  # type: ignore[arg-type]
            url=f"/api/table.json?username={FAKE_USERNAME}&passhash={FAKE_PASSHASH}",
            reason=urllib3.exceptions.SSLError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
            ),
        )

    def test_a_wrapped_certificate_failure_is_reported_as_tls(self, client: PrtgClient) -> None:
        client._pool = FakePool(raises=self._wrapped_ssl_error())
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")

        message = str(exc.value)
        assert "TLS verification failed" in message
        assert "security group" not in message, "still blaming the network for a certificate"
        assert "route to the PRTG network" not in message

    def test_it_names_the_setting_that_fixes_it(self, client: PrtgClient) -> None:
        client._pool = FakePool(raises=self._wrapped_ssl_error())
        with pytest.raises(PrtgError, match="PRTG_CA_BUNDLE_SECRET_ARN"):
            client.request("/api/table.json")

    def test_with_a_bundle_configured_it_points_at_the_shipped_certificate(
        self, secrets_client: FakeSecretsClient
    ) -> None:
        """Different advice when a bundle is already set: the bundle is not the gap."""
        client = PrtgClient(
            secret_arn="prtg-secret",
            ca_bundle_secret_arn="arn:aws:secretsmanager:r:1:secret:ca-x",
            verify_tls=True,
            secrets_client=secrets_client,
        )
        client._pool = FakePool(raises=self._wrapped_ssl_error())
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")

        message = str(exc.value)
        assert "PRTG Demo Certificate" in message
        assert "localhost" in message

    def test_a_genuine_connectivity_failure_still_says_so(self, client: PrtgClient) -> None:
        """The other half: a real network failure must keep the network advice."""
        client._pool = FakePool(
            raises=urllib3.exceptions.MaxRetryError(
                pool=None,  # type: ignore[arg-type]
                url="/api/table.json",
                reason=urllib3.exceptions.NewConnectionError(None, "connection refused"),  # type: ignore[arg-type]
            )
        )
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")

        message = str(exc.value)
        assert "Could not reach PRTG" in message
        assert "security group" in message
        assert "TLS verification failed" not in message

    def test_neither_message_leaks_the_credential(self, client: PrtgClient) -> None:
        """Both paths carry a urllib3 message containing the full request URL."""
        client._pool = FakePool(raises=self._wrapped_ssl_error())
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")
        assert FAKE_PASSHASH not in str(exc.value)
        assert FAKE_USERNAME not in str(exc.value)


class TestJsonBodySniffing:
    """PRTG does not always label a JSON body as JSON.

    Verified on 26.2.116.1542: ``/api/getstatus.htm`` answers with
    ``Content-Type: text/html`` and a JSON object, while ``/api/table.json`` answers
    with ``application/json``. Trusting the header alone meant ``get_server_status``
    returned text, the handler encoded that string, and the agent received JSON nested
    inside a JSON string -- needing two parses to reach ``UpSens`` when every other
    tool returned an object.
    """

    def test_json_body_labelled_text_html_is_still_parsed(self, client: PrtgClient) -> None:
        client._pool = FakePool(
            [FakeResponse(200, '{"UpSens": "4"}', content_type="text/html; charset=UTF-8")]
        )
        assert client.request("/api/getstatus.htm") == {"UpSens": "4"}

    def test_json_array_labelled_text_html_is_still_parsed(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, "[1, 2, 3]", content_type="text/html")])
        assert client.request("/api/getstatus.htm") == [1, 2, 3]

    def test_leading_whitespace_does_not_defeat_the_sniff(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, '\r\n  {"a": 1}', content_type="text/html")])
        assert client.request("/api/getstatus.htm") == {"a": 1}

    def test_genuinely_non_json_text_is_returned_unchanged(self, client: PrtgClient) -> None:
        """The sniff must not turn a plain-text endpoint into an error."""
        client._pool = FakePool([FakeResponse(200, "OK 42", content_type="text/plain")])
        assert client.request("/api/getpasshash.htm") == "OK 42"

    def test_text_that_only_looks_like_json_falls_back_to_text(self, client: PrtgClient) -> None:
        """Starts with a brace but does not parse. Returned as text, not raised."""
        client._pool = FakePool([FakeResponse(200, "{not json at all", content_type="text/html")])
        assert client.request("/api/getstatus.htm") == "{not json at all"

    def test_a_declared_json_endpoint_still_raises_on_a_login_page(self, client: PrtgClient) -> None:
        """The sniff must not weaken the existing guard for redirected-to-login."""
        client._pool = FakePool([FakeResponse(200, "<html>login</html>", content_type="application/json")])
        with pytest.raises(PrtgError, match="non-JSON body"):
            client.request("/api/table.json")


class TestStatusFilterWireFormat:
    """PRTG expresses a multi-valued status filter by repeating the key.

    This is the regression guard for a bug that only a real server exposed. The client
    used to send ``filter_status[0]=3``, which PRTG answers with HTTP 200 and a
    ``treesize`` of 0. Nothing looked wrong: no error, no warning, a well-formed empty
    result. Every status-filtered query returned nothing, so an agent asking which
    sensors were down was told none of them were.

    Measured against PRTG 26.2.116.1542 with four sensors up:

        filter_status[0]=3               0 rows
        filter_status=3                  4 rows
        filter_status=3&filter_status=4  4 rows

    A mock cannot catch this on its own, because a fake accepts whatever it is given.
    What makes the assertion possible is checking the wire format rather than the
    outcome.
    """

    def test_each_code_is_a_separate_repeated_key(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10, status_filter=[7, 8, 9, 12])

        status = [(k, v) for k, v in client._pool.last_pairs if k == "filter_status"]
        assert status == [
            ("filter_status", 7),
            ("filter_status", 8),
            ("filter_status", 9),
            ("filter_status", 12),
        ]

    def test_no_indexed_keys_are_emitted(self, client: PrtgClient) -> None:
        """The specific broken form, named so a reintroduction is unmistakable."""
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10, status_filter=[3, 5])

        keys = [k for k, _ in client._pool.last_pairs]
        assert "filter_status[0]" not in keys
        assert not any("[" in k for k in keys), f"indexed parameter reintroduced: {keys}"

    def test_single_code_still_repeats_rather_than_indexes(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10, status_filter=[3])
        assert ("filter_status", 3) in client._pool.last_pairs

    def test_absent_filter_sends_no_status_key(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10)
        assert not [k for k, _ in client._pool.last_pairs if k.startswith("filter_status")]

    def test_the_credential_is_still_attached_alongside_repeated_keys(self, client: PrtgClient) -> None:
        """Guards the pairs refactor: auth is appended after the caller's parameters."""
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10, status_filter=[3, 4])
        fields = client._pool.last_fields
        assert fields["username"] == FAKE_USERNAME
        assert fields["passhash"] == FAKE_PASSHASH

    def test_a_sequence_of_pairs_is_accepted_directly(self, client: PrtgClient) -> None:
        """``request`` takes pairs as well as a mapping, which is what makes this work."""
        client._pool = FakePool([FakeResponse(200, {})])
        client.request("/api/table.json", [("filter_status", 3), ("filter_status", 5)])
        status = [(k, v) for k, v in client._pool.last_pairs if k == "filter_status"]
        assert status == [("filter_status", 3), ("filter_status", 5)]

    def test_connection_failure_does_not_leak_the_credential(self, client: PrtgClient) -> None:
        """The regression guard for the credential-in-exception path."""
        leaky = urllib3.exceptions.MaxRetryError(
            pool=None,  # type: ignore[arg-type]
            url=f"/api/table.json?username={FAKE_USERNAME}&passhash={FAKE_PASSHASH}",
            reason=Exception("connection refused"),
        )
        client._pool = FakePool(raises=leaky)
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")

        message = exc.value.message
        assert FAKE_PASSHASH not in message
        assert FAKE_USERNAME not in message
        assert "outbound 443" in message  # actionable guidance survives

    def test_tls_failure_suggests_the_ca_bundle_option(self, client: PrtgClient) -> None:
        client._pool = FakePool(raises=urllib3.exceptions.SSLError("self-signed certificate"))
        with pytest.raises(PrtgError, match="PRTG_CA_BUNDLE_SECRET_ARN"):
            client.request("/api/table.json")

    @pytest.mark.parametrize("status", [401, 403])
    def test_auth_rejection_raises_a_distinct_non_retryable_error(
        self, client: PrtgClient, status: int
    ) -> None:
        client._pool = FakePool([FakeResponse(status, "unauthorized", content_type="text/html")])
        with pytest.raises(PrtgAuthError) as exc:
            client.request("/api/table.json")
        assert exc.value.status == status
        assert "getpasshash" in exc.value.message

    def test_html_body_on_a_200_is_reported_as_an_auth_problem(self, client: PrtgClient) -> None:
        """PRTG serves its login page with HTTP 200 when a session is not valid."""
        client._pool = FakePool([FakeResponse(200, "<html>Login</html>", content_type="text/html")])
        with pytest.raises(PrtgError, match="login page"):
            client.request("/api/table.json")

    def test_error_body_is_redacted_before_being_surfaced(self, client: PrtgClient) -> None:
        client._pool = FakePool(
            [FakeResponse(500, f"failure processing passhash={FAKE_PASSHASH}", content_type="text/plain")]
        )
        with pytest.raises(PrtgError) as exc:
            client.request("/api/table.json")
        assert FAKE_PASSHASH not in exc.value.message

    def test_non_json_endpoint_returns_text(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, "OK 42", content_type="text/plain")])
        assert client.request("/api/getstatus.htm") == "OK 42"


# --- Table helper -----------------------------------------------------------


class TestTable:
    def test_count_is_clamped_to_the_published_maximum(self, client: PrtgClient) -> None:
        from prtg_mcp.tools import MAX_COUNT

        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=999_999)
        assert client._pool.last_fields["count"] == MAX_COUNT

    def test_count_is_clamped_to_at_least_one(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=0)
        assert client._pool.last_fields["count"] == 1

    def test_status_filter_repeats_the_key_once_per_code(self, client: PrtgClient) -> None:
        """See TestStatusFilterWireFormat: the indexed form this once asserted
        returns an empty result from a real PRTG server."""
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10, status_filter=[7, 8, 9, 12])
        codes = [v for k, v in client._pool.last_pairs if k == "filter_status"]
        assert codes == [7, 8, 9, 12]

    def test_name_filter_is_wrapped_in_prtg_substring_syntax(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("sensors", count=10, name_filter="appserver")
        assert client._pool.last_fields["filter_name"] == "@sub(appserver)"

    def test_requests_an_explicit_column_set(self, client: PrtgClient) -> None:
        client._pool = FakePool([FakeResponse(200, {})])
        client.table("devices", count=10)
        assert "host" in client._pool.last_fields["columns"]


# --- TLS configuration ------------------------------------------------------


class TestTlsConfiguration:
    def test_verification_is_enabled_by_default(self, secrets_client: FakeSecretsClient) -> None:
        client = PrtgClient(secret_arn="prtg-secret", secrets_client=secrets_client)
        assert client._verify_tls is True

    def test_verification_can_be_disabled_explicitly(self, secrets_client: FakeSecretsClient) -> None:
        client = PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)
        assert client._verify_tls is False

    def test_environment_can_disable_verification(
        self, monkeypatch: pytest.MonkeyPatch, secrets_client: FakeSecretsClient
    ) -> None:
        monkeypatch.setenv("PRTG_VERIFY_TLS", "false")
        client = PrtgClient(secret_arn="prtg-secret", secrets_client=secrets_client)
        assert client._verify_tls is False

    def test_pool_requires_certificates_when_verification_is_on(
        self, secrets_client: FakeSecretsClient
    ) -> None:
        client = PrtgClient(secret_arn="prtg-secret", verify_tls=True, secrets_client=secrets_client)
        assert client._http().connection_pool_kw["cert_reqs"] == "CERT_REQUIRED"

    def test_disabling_verification_logs_a_warning_on_construction(
        self, secrets_client: FakeSecretsClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An operator must not be able to forget that verification is off."""
        with caplog.at_level("WARNING"):
            PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)
        assert "tls_verification_disabled" in caplog.text

    def test_disabling_verification_logs_a_warning_per_request(
        self, secrets_client: FakeSecretsClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = PrtgClient(secret_arn="prtg-secret", verify_tls=False, secrets_client=secrets_client)
        client._pool = FakePool([FakeResponse(200, {})])
        with caplog.at_level("WARNING"):
            client.request("/api/table.json")
        assert "insecure_request" in caplog.text

    def test_ca_bundle_must_contain_a_pem_certificate(self) -> None:
        secrets = FakeSecretsClient(
            {
                "cred": json.dumps(
                    {"prtg_url": "https://x.example", "prtg_username": "u", "prtg_passhash": "hash1234"}
                ),
                "ca": "this is not a certificate",
            }
        )
        client = PrtgClient(
            secret_arn="cred", ca_bundle_secret_arn="ca", verify_tls=True, secrets_client=secrets
        )
        with pytest.raises(PrtgError, match="PEM certificate"):
            client._http()
